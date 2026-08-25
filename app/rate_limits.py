"""Fail-closed rate-limit configuration and privacy-preserving bucket keys."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable
from typing import Any, TypeVar, cast
from urllib.parse import urlsplit

from flask import Flask, Response, current_app, g, request
from limits import parse_many

from app.extensions import limiter


ViewFunction = TypeVar("ViewFunction", bound=Callable[..., Any])
_MAXIMUM_BUCKET_COMPONENT_LENGTH = 512
_PRODUCTION_STORAGE_SCHEMES = frozenset(
    {"redis", "rediss", "redis+cluster", "redis+sentinel", "redis+unix"}
)
_LIMIT_CONFIG_NAMES = (
    "LOGIN_IP_RATE_LIMIT",
    "LOGIN_FAILURE_IP_RATE_LIMIT",
    "LOGIN_FAILURE_CREDENTIAL_RATE_LIMIT",
    "REGISTRATION_IP_RATE_LIMIT",
    "ACCOUNT_ACTION_IP_RATE_LIMIT",
    "EMAIL_VERIFICATION_REQUEST_RATE_LIMIT",
    "EMAIL_VERIFICATION_CONFIRM_RATE_LIMIT",
    "PASSWORD_RESET_REQUEST_RATE_LIMIT",
    "PASSWORD_RESET_CONFIRM_RATE_LIMIT",
    "UPLOAD_IP_RATE_LIMIT",
    "UPLOAD_USER_RATE_LIMIT",
    "UPLOAD_SESSION_RATE_LIMIT",
    "DOWNLOAD_IP_RATE_LIMIT",
    "DOWNLOAD_USER_RATE_LIMIT",
    "DOWNLOAD_SESSION_RATE_LIMIT",
    "DOWNLOAD_RESOURCE_RATE_LIMIT",
)


def _secret_bytes() -> bytes:
    configured = current_app.config.get("RATE_LIMIT_KEY_SECRET")
    if isinstance(configured, bytes):
        return configured
    if isinstance(configured, str):
        return configured.encode("utf-8")
    raise RuntimeError("RATE_LIMIT_KEY_SECRET is not configured")


def _hmac_bucket(namespace: str, *components: object) -> str:
    """Return a stable digest without disclosing bucket identifiers to storage."""

    digest = hmac.new(_secret_bytes(), digestmod=hashlib.sha256)
    for component in (namespace, *components):
        encoded = str(component).encode("utf-8", errors="surrogatepass")
        digest.update(len(encoded).to_bytes(8, byteorder="big"))
        digest.update(encoded)
    return digest.hexdigest()


def _direct_remote_address() -> str:
    """Use Flask's socket peer address and deliberately ignore proxy headers."""

    return request.remote_addr or "unknown-peer"


def remote_address_rate_key() -> str:
    return _hmac_bucket("remote-address", _direct_remote_address())


def _login_identifier() -> str:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return "missing-identifier"
    value = payload.get("identifier") or payload.get("username") or payload.get("email")
    if not isinstance(value, str):
        return "missing-identifier"
    normalized = value.strip().lower()
    if len(normalized) > _MAXIMUM_BUCKET_COMPONENT_LENGTH:
        return "oversized-identifier"
    return normalized


def login_credential_rate_key() -> str:
    # This target-only bucket closes distributed guessing across rotating
    # source addresses. A separate peer-IP limit still bounds one source. The
    # target cooldown is finite and applies identically to known and unknown
    # identifiers, avoiding a permanent account-lock denial of service.
    return _hmac_bucket("login-credential", _login_identifier())


def _payload_string(field: str, *, normalize: bool = False) -> str:
    payload = request.get_json(silent=True)
    value = payload.get(field) if isinstance(payload, dict) else None
    if not isinstance(value, str):
        return f"missing-{field}"
    prepared = value.strip().lower() if normalize else value
    if len(prepared) > _MAXIMUM_BUCKET_COMPONENT_LENGTH:
        return f"oversized-{field}"
    return prepared


def _authenticated_user_id() -> object:
    user = getattr(g, "current_user", None)
    if user is None:
        raise RuntimeError(
            "Authenticated rate limits must be applied inside auth_required"
        )
    return user.id


def _authenticated_session_id() -> object:
    auth_session = getattr(g, "auth_session", None)
    if auth_session is None:
        raise RuntimeError(
            "Authenticated rate limits must be applied inside auth_required"
        )
    return auth_session.id


def user_rate_key() -> str:
    return _hmac_bucket("user", _authenticated_user_id())


def session_rate_key() -> str:
    return _hmac_bucket("session", _authenticated_session_id())


def email_verification_request_rate_key() -> str:
    return _hmac_bucket(
        "email-verification-request",
        _authenticated_user_id(),
    )


def email_verification_confirm_rate_key() -> str:
    return _hmac_bucket(
        "email-verification-confirm",
        _payload_string("token"),
    )


def password_reset_request_rate_key() -> str:
    return _hmac_bucket(
        "password-reset-request",
        _payload_string("email", normalize=True),
    )


def password_reset_confirm_rate_key() -> str:
    return _hmac_bucket(
        "password-reset-confirm",
        _payload_string("token"),
    )


def download_resource_rate_key() -> str:
    view_arguments = request.view_args or {}
    return _hmac_bucket(
        "download-resource",
        _authenticated_user_id(),
        view_arguments.get("file_id", "missing-resource"),
    )


def _configured_limit(name: str) -> Callable[[], str]:
    def provider() -> str:
        return str(current_app.config[name])

    return provider


def _failed_credentials(response: Response) -> bool:
    return response.status_code == 401


def registration_rate_limited(view: ViewFunction) -> ViewFunction:
    limited = limiter.shared_limit(
        _configured_limit("REGISTRATION_IP_RATE_LIMIT"),
        scope="registration-ip",
        key_func=remote_address_rate_key,
    )(view)
    return cast(ViewFunction, limited)


def login_rate_limited(view: ViewFunction) -> ViewFunction:
    """Apply shared broad and failed-only limits to both login transports."""

    limited = limiter.shared_limit(
        _configured_limit("LOGIN_IP_RATE_LIMIT"),
        scope="login-ip",
        key_func=remote_address_rate_key,
    )(view)
    limited = limiter.shared_limit(
        _configured_limit("LOGIN_FAILURE_IP_RATE_LIMIT"),
        scope="login-failure-ip",
        key_func=remote_address_rate_key,
        deduct_when=_failed_credentials,
    )(limited)
    limited = limiter.shared_limit(
        _configured_limit("LOGIN_FAILURE_CREDENTIAL_RATE_LIMIT"),
        scope="login-failure-credential",
        key_func=login_credential_rate_key,
        deduct_when=_failed_credentials,
    )(limited)
    return cast(ViewFunction, limited)


def _account_action_ip_limit(view: ViewFunction) -> ViewFunction:
    limited = limiter.shared_limit(
        _configured_limit("ACCOUNT_ACTION_IP_RATE_LIMIT"),
        scope="account-action-ip",
        key_func=remote_address_rate_key,
    )(view)
    return cast(ViewFunction, limited)


def email_verification_request_rate_limited(
    view: ViewFunction,
) -> ViewFunction:
    limited = limiter.shared_limit(
        _configured_limit("EMAIL_VERIFICATION_REQUEST_RATE_LIMIT"),
        scope="email-verification-request-user",
        key_func=email_verification_request_rate_key,
    )(view)
    return _account_action_ip_limit(cast(ViewFunction, limited))


def email_verification_confirm_rate_limited(
    view: ViewFunction,
) -> ViewFunction:
    limited = limiter.shared_limit(
        _configured_limit("EMAIL_VERIFICATION_CONFIRM_RATE_LIMIT"),
        scope="email-verification-confirm-token",
        key_func=email_verification_confirm_rate_key,
    )(view)
    return _account_action_ip_limit(cast(ViewFunction, limited))


def password_reset_request_rate_limited(
    view: ViewFunction,
) -> ViewFunction:
    limited = limiter.shared_limit(
        _configured_limit("PASSWORD_RESET_REQUEST_RATE_LIMIT"),
        scope="password-reset-request-email",
        key_func=password_reset_request_rate_key,
    )(view)
    return _account_action_ip_limit(cast(ViewFunction, limited))


def password_reset_confirm_rate_limited(
    view: ViewFunction,
) -> ViewFunction:
    limited = limiter.shared_limit(
        _configured_limit("PASSWORD_RESET_CONFIRM_RATE_LIMIT"),
        scope="password-reset-confirm-token",
        key_func=password_reset_confirm_rate_key,
    )(view)
    return _account_action_ip_limit(cast(ViewFunction, limited))


def upload_rate_limited(view: ViewFunction) -> ViewFunction:
    limited = limiter.shared_limit(
        _configured_limit("UPLOAD_USER_RATE_LIMIT"),
        scope="upload-user",
        key_func=user_rate_key,
    )(view)
    limited = limiter.shared_limit(
        _configured_limit("UPLOAD_SESSION_RATE_LIMIT"),
        scope="upload-session",
        key_func=session_rate_key,
    )(limited)
    return cast(ViewFunction, limited)


def upload_peer_rate_limited(view: ViewFunction) -> ViewFunction:
    """Bound upload attempts before authentication or multipart parsing."""

    return _pre_auth_peer_limit(
        view,
        config_name="UPLOAD_IP_RATE_LIMIT",
        scope="upload-ip",
    )


def download_rate_limited(view: ViewFunction) -> ViewFunction:
    limited = limiter.shared_limit(
        _configured_limit("DOWNLOAD_USER_RATE_LIMIT"),
        scope="download-user",
        key_func=user_rate_key,
    )(view)
    limited = limiter.shared_limit(
        _configured_limit("DOWNLOAD_SESSION_RATE_LIMIT"),
        scope="download-session",
        key_func=session_rate_key,
    )(limited)
    limited = limiter.shared_limit(
        _configured_limit("DOWNLOAD_RESOURCE_RATE_LIMIT"),
        scope="download-user-resource",
        key_func=download_resource_rate_key,
    )(limited)
    return cast(ViewFunction, limited)


def download_peer_rate_limited(view: ViewFunction) -> ViewFunction:
    """Bound download attempts before session lookup and authorization."""

    return _pre_auth_peer_limit(
        view,
        config_name="DOWNLOAD_IP_RATE_LIMIT",
        scope="download-ip",
    )


def _pre_auth_peer_limit(
    view: ViewFunction,
    *,
    config_name: str,
    scope: str,
) -> ViewFunction:
    """Create a limiter boundary distinct from inner authenticated limits.

    Flask-Limiter groups decorated callables by qualified name. ``auth_required``
    intentionally preserves the wrapped view's identity, so applying an outer
    limit directly would be grouped with the inner user/session limits and
    skipped by Flask-Limiter's stacked-wrapper optimization. This uniquely
    named boundary lets the peer check run before authentication while the
    returned callable retains Flask's original endpoint name.
    """

    def boundary(*args: Any, **kwargs: Any):
        return view(*args, **kwargs)

    original_name = view.__name__
    original_qualname = view.__qualname__
    boundary.__module__ = view.__module__
    boundary.__name__ = f"{original_name}__{scope.replace('-', '_')}"
    boundary.__qualname__ = f"{original_qualname}__{scope.replace('-', '_')}"
    limited = limiter.shared_limit(
        _configured_limit(config_name),
        scope=scope,
        key_func=remote_address_rate_key,
    )(boundary)
    assert limited is not None  # nosec B101 - a callable never returns None
    limited.__name__ = original_name
    limited.__qualname__ = original_qualname
    limited.__doc__ = view.__doc__
    return cast(ViewFunction, limited)


def init_rate_limiting(app: Flask) -> None:
    """Validate secure deployment settings and initialize Flask-Limiter."""

    environment = str(app.config.get("APP_ENV", "development")).strip().lower()
    storage_uri = str(app.config.get("RATELIMIT_STORAGE_URI") or "").strip()
    storage_scheme = urlsplit(storage_uri).scheme.lower()

    if not storage_uri or not storage_scheme:
        raise RuntimeError("RATELIMIT_STORAGE_URI must be configured")
    if environment == "production" and storage_scheme not in _PRODUCTION_STORAGE_SCHEMES:
        raise RuntimeError(
            "Production requires shared Redis rate-limit storage; configure "
            "RATELIMIT_STORAGE_URI"
        )
    if storage_scheme == "memory" and environment not in {"development", "test"}:
        raise RuntimeError(
            "In-memory rate-limit storage is allowed only in development and tests"
        )

    configured_secret = app.config.get("RATE_LIMIT_KEY_SECRET")
    if not configured_secret:
        if storage_scheme == "memory" and environment in {"development", "test"}:
            configured_secret = secrets.token_urlsafe(48)
            app.config["RATE_LIMIT_KEY_SECRET"] = configured_secret
        else:
            raise RuntimeError(
                "RATE_LIMIT_KEY_SECRET is required with shared rate-limit storage"
            )
    secret_bytes = (
        configured_secret
        if isinstance(configured_secret, bytes)
        else str(configured_secret).encode("utf-8")
    )
    if len(secret_bytes) < 32:
        raise RuntimeError("RATE_LIMIT_KEY_SECRET must contain at least 32 bytes")
    for other_secret_name in ("SECRET_KEY", "ACCOUNT_TOKEN_PEPPER"):
        other_secret = app.config.get(other_secret_name)
        if isinstance(other_secret, (bytes, str)):
            other_secret_bytes = (
                other_secret
                if isinstance(other_secret, bytes)
                else other_secret.encode("utf-8")
            )
            if secrets.compare_digest(secret_bytes, other_secret_bytes):
                raise RuntimeError(
                    "RATE_LIMIT_KEY_SECRET must be dedicated and must not reuse "
                    f"{other_secret_name}"
                )

    for config_name in _LIMIT_CONFIG_NAMES:
        configured_limit = app.config.get(config_name)
        try:
            parsed_limits = parse_many(str(configured_limit or ""))
        except ValueError as exc:
            raise RuntimeError(f"{config_name} is not a valid rate limit") from exc
        if not parsed_limits:
            raise RuntimeError(f"{config_name} must define at least one rate limit")

    # These settings are intentionally not operator-tunable: backend failures
    # must reject requests, never silently disable or localize enforcement.
    app.config["RATELIMIT_ENABLED"] = True
    app.config["RATELIMIT_HEADERS_ENABLED"] = True
    app.config["RATELIMIT_SWALLOW_ERRORS"] = False
    app.config["RATELIMIT_IN_MEMORY_FALLBACK_ENABLED"] = False
    app.config["RATELIMIT_IN_MEMORY_FALLBACK"] = []
    app.config["RATELIMIT_FAIL_ON_FIRST_BREACH"] = False
    limiter.init_app(app)


__all__ = [
    "download_peer_rate_limited",
    "download_rate_limited",
    "email_verification_confirm_rate_limited",
    "email_verification_request_rate_limited",
    "init_rate_limiting",
    "login_rate_limited",
    "password_reset_confirm_rate_limited",
    "password_reset_request_rate_limited",
    "registration_rate_limited",
    "remote_address_rate_key",
    "upload_peer_rate_limited",
    "upload_rate_limited",
]
