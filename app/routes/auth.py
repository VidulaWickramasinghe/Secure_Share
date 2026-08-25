"""REST endpoints for account and authentication operations."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlsplit

from flask import Blueprint, current_app, g, jsonify, request

from app.models.account_action_token import (
    EMAIL_VERIFICATION,
    PASSWORD_RESET,
)
from app.models.user import serialize_timestamp
from app.rate_limits import (
    email_verification_confirm_rate_limited,
    email_verification_request_rate_limited,
    login_rate_limited,
    password_reset_confirm_rate_limited,
    password_reset_request_rate_limited,
    registration_rate_limited,
)
from app.services.account_token_service import (
    AccountTokenError,
    confirm_email_verification,
    find_user_for_password_reset,
    hash_account_token,
    reset_password_with_token,
)
from app.services.auth_service import (
    AuthServiceError,
    change_password,
    login_browser_user,
    login_user,
    logout_session,
    normalize_email_address,
    register_user,
    rotate_session_csrf,
)
from app.services.email_outbox_service import (
    enqueue_security_email,
    process_security_email_job,
)
from app.utils.security import (
    auth_required,
    clear_browser_auth_cookies,
    set_browser_auth_cookies,
    set_browser_csrf_cookie,
)


auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _json_payload() -> dict[str, Any]:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise AuthServiceError("A JSON object is required.")
    return payload


def _service_error_response(error: AuthServiceError):
    return jsonify({"error": error.message}), error.status_code


def _account_token_error_response(error: AccountTokenError):
    return jsonify({"error": error.message}), error.status_code


def _process_inline_security_email(job_id: str | None) -> None:
    """Deliver queued mail inline only for explicit local/test configuration."""

    if not job_id or not current_app.config["SECURITY_EMAIL_INLINE_DELIVERY"]:
        return
    result = process_security_email_job(job_id)
    if result is not None and result.outcome in {"retry_scheduled", "lost_lease"}:
        current_app.logger.warning(
            "A queued security email was not completed; outcome=%s.",
            result.outcome,
        )


def _normalized_origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            return None
        default_port = 443 if parsed.scheme == "https" else 80
        return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or default_port
    except (TypeError, ValueError):
        return None


def _browser_request_is_same_origin() -> bool:
    """Compare browser-controlled Origin with the configured public origin."""

    origin = request.headers.get("Origin")
    return bool(
        origin
        and _normalized_origin(origin)
        == _normalized_origin(current_app.config["PUBLIC_BASE_URL"])
    )


@auth_bp.post("/register")
@registration_rate_limited
def register():
    try:
        user, email_job = register_user(_json_payload())
    except AuthServiceError as error:
        return _service_error_response(error)
    _process_inline_security_email(email_job.id)
    return (
        jsonify(
            {
                "message": (
                    "Account created. Check your email to verify the address."
                ),
                "user": user.to_dict(),
            }
        ),
        201,
    )


@auth_bp.post("/login")
@login_rate_limited
def login():
    try:
        user, token, auth_session = login_user(_json_payload())
    except AuthServiceError as error:
        return _service_error_response(error)

    return jsonify(
        {
            "token": token,
            "token_type": "Bearer",  # nosec B105
            "expires_at": serialize_timestamp(auth_session.expires_at),
            "user": user.to_dict(),
        }
    )


@auth_bp.post("/browser-login")
@login_rate_limited
def browser_login():
    """Create an HttpOnly browser session without disclosing its credential."""

    if not _browser_request_is_same_origin():
        return (
            jsonify(
                {
                    "error": "The browser login request was not same-origin.",
                    "code": "origin_failed",
                }
            ),
            403,
        )
    try:
        user, session_token, csrf_token, auth_session = login_browser_user(
            _json_payload()
        )
    except AuthServiceError as error:
        return _service_error_response(error)

    response = jsonify(
        {
            "expires_at": serialize_timestamp(auth_session.expires_at),
            "user": user.to_dict(),
        }
    )
    return set_browser_auth_cookies(
        response,
        session_token,
        csrf_token,
        auth_session.expires_at,
    )


@auth_bp.post("/logout")
@auth_required
def logout():
    logout_session(g.auth_session)
    response = jsonify({"message": "Logged out successfully."})
    if g.auth_transport == "cookie":
        return clear_browser_auth_cookies(response)
    return response


@auth_bp.get("/me")
@auth_required
def me():
    return jsonify({"user": g.current_user.to_dict()})


@auth_bp.post("/email-verification/request")
@auth_required
@email_verification_request_rate_limited
def request_email_verification():
    """Queue a fresh challenge without exposing it to the browser response."""

    email_job = enqueue_security_email(g.current_user, EMAIL_VERIFICATION)
    _process_inline_security_email(email_job.id if email_job is not None else None)
    return (
        jsonify(
            {
                "message": (
                    "If verification is still required, a new email has been sent."
                )
            }
        ),
        202,
    )


@auth_bp.post("/email-verification/confirm")
@email_verification_confirm_rate_limited
def confirm_verification():
    try:
        confirm_email_verification(_json_payload().get("token"))
    except AuthServiceError as error:
        return _service_error_response(error)
    except AccountTokenError as error:
        return _account_token_error_response(error)
    return jsonify({"message": "Email verified successfully."})


@auth_bp.post("/password-reset/request")
@password_reset_request_rate_limited
def request_password_reset():
    """Return one generic response whether or not the account exists."""

    started_at = time.monotonic()
    try:
        payload = _json_payload()
        email = normalize_email_address(payload.get("email"))
    except AuthServiceError:
        email = None

    user = find_user_for_password_reset(email) if email is not None else None
    if user is not None:
        email_job = enqueue_security_email(user, PASSWORD_RESET)
        _process_inline_security_email(email_job.id if email_job is not None else None)
    else:
        # Perform the same protected-token primitive for unknown and malformed
        # identifiers. The API status and response body are always identical.
        hash_account_token("unknown-account-placeholder", PASSWORD_RESET)

    minimum_duration = float(
        current_app.config["PASSWORD_RESET_MINIMUM_RESPONSE_SECONDS"]
    )
    remaining_duration = minimum_duration - (time.monotonic() - started_at)
    if remaining_duration > 0:
        time.sleep(remaining_duration)

    return (
        jsonify(
            {
                "message": (
                    "If an account matches that email, password-reset "
                    "instructions have been sent."
                )
            }
        ),
        202,
    )


@auth_bp.post("/password-reset/confirm")
@password_reset_confirm_rate_limited
def confirm_password_reset():
    try:
        payload = _json_payload()
        _user, email_job = reset_password_with_token(
            payload.get("token"), payload.get("new_password")
        )
    except AuthServiceError as error:
        return _service_error_response(error)
    except AccountTokenError as error:
        return _account_token_error_response(error)

    _process_inline_security_email(email_job.id)
    return jsonify(
        {
            "message": (
                "Password reset successfully. Sign in with your new password."
            )
        }
    )


@auth_bp.get("/csrf")
@auth_required
def refresh_csrf():
    """Rotate browser CSRF state after an explicit same-origin script request."""

    if g.auth_transport != "cookie":
        return jsonify({"error": "CSRF tokens are only used by browser sessions."}), 400
    # This GET exists only to restore the readable CSRF cookie when a browser
    # still has its HttpOnly session cookie. Requiring a non-simple custom
    # header prevents cross-site forms, images, and top-level SameSite=Lax
    # navigations from rotating the token. A cross-origin script would require
    # a successful CORS preflight, which this same-origin application denies.
    if request.headers.get("X-Secure-Share-CSRF-Restore") != "1":
        return (
            jsonify(
                {
                    "error": "The CSRF refresh request was not same-origin.",
                    "code": "origin_failed",
                }
            ),
            403,
        )
    fetch_site = request.headers.get("Sec-Fetch-Site")
    if fetch_site is not None and fetch_site != "same-origin":
        return (
            jsonify(
                {
                    "error": "The CSRF refresh request was not same-origin.",
                    "code": "origin_failed",
                }
            ),
            403,
        )
    csrf_token = rotate_session_csrf(g.auth_session)
    response = jsonify({"message": "CSRF token refreshed."})
    return set_browser_csrf_cookie(response, csrf_token, g.auth_session.expires_at)


@auth_bp.route("/password", methods=["PATCH", "PUT"])
@auth_required
def update_password():
    try:
        email_job = change_password(
            g.current_user, g.auth_session, _json_payload()
        )
    except AuthServiceError as error:
        return _service_error_response(error)
    _process_inline_security_email(email_job.id)
    return jsonify({"message": "Password changed successfully."})


__all__ = ["auth_bp"]
