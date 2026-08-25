"""Authentication and token-security helpers."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from datetime import datetime, timezone
from functools import wraps
from typing import Any, TypeVar, cast

from flask import Response, current_app, g, jsonify, make_response, request
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.models.auth_session import AuthSession
from app.models.user import utc_now


ViewFunction = TypeVar("ViewFunction", bound=Callable[..., Any])
MAXIMUM_TOKEN_LENGTH = 512
SAFE_REQUEST_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def generate_session_token() -> str:
    """Generate a high-entropy token safe for use in an HTTP header."""

    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    """Return the fixed-size digest stored in the database."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_csrf_token() -> str:
    """Generate a high-entropy token independent of the session credential."""

    return secrets.token_urlsafe(32)


def hash_csrf_token(token: str) -> str:
    """Return the fixed-size CSRF digest stored with a browser session."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _bounded_token(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > MAXIMUM_TOKEN_LENGTH:
        return None
    return value


def _bearer_token() -> str | None:
    authorization = request.headers.get("Authorization", "")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    # Current tokens are 43 characters. The loose upper bound allows future
    # formats while preventing oversized attacker-controlled database lookups.
    return _bounded_token(parts[1])


def _browser_session_token() -> str | None:
    cookie_name = current_app.config["BROWSER_SESSION_COOKIE_NAME"]
    return _bounded_token(request.cookies.get(cookie_name))


def _session_for_token(token: str, *, browser: bool) -> AuthSession | None:
    csrf_condition = (
        AuthSession.csrf_token_hash.is_not(None)
        if browser
        else AuthSession.csrf_token_hash.is_(None)
    )
    statement = (
        select(AuthSession)
        .options(joinedload(AuthSession.user))
        .where(
            AuthSession.token_hash == hash_session_token(token),
            AuthSession.expires_at > utc_now(),
            csrf_condition,
        )
    )
    return db.session.execute(statement).scalar_one_or_none()


def _remaining_cookie_seconds(expires_at: datetime) -> int:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return max(0, int((expires_at - utc_now()).total_seconds()))


def set_browser_auth_cookies(
    response: Response,
    session_token: str,
    csrf_token: str,
    expires_at: datetime,
) -> Response:
    """Attach the browser session and its separate CSRF token securely."""

    secure = bool(current_app.config["BROWSER_COOKIE_SECURE"])
    same_site = current_app.config["BROWSER_COOKIE_SAMESITE"]
    max_age = _remaining_cookie_seconds(expires_at)
    response.set_cookie(
        current_app.config["BROWSER_SESSION_COOKIE_NAME"],
        session_token,
        max_age=max_age,
        expires=expires_at,
        secure=secure,
        httponly=True,
        samesite=same_site,
        path="/",
    )
    response.set_cookie(
        current_app.config["BROWSER_CSRF_COOKIE_NAME"],
        csrf_token,
        max_age=max_age,
        expires=expires_at,
        secure=secure,
        httponly=False,
        samesite=same_site,
        path="/",
    )
    return response


def set_browser_csrf_cookie(
    response: Response,
    csrf_token: str,
    expires_at: datetime,
) -> Response:
    """Replace only the readable CSRF cookie for an existing browser session."""

    response.set_cookie(
        current_app.config["BROWSER_CSRF_COOKIE_NAME"],
        csrf_token,
        max_age=_remaining_cookie_seconds(expires_at),
        expires=expires_at,
        secure=bool(current_app.config["BROWSER_COOKIE_SECURE"]),
        httponly=False,
        samesite=current_app.config["BROWSER_COOKIE_SAMESITE"],
        path="/",
    )
    return response


def clear_browser_auth_cookies(response: Response | tuple[Any, int]) -> Response:
    """Expire both cookies using the same scope with which they were issued."""

    prepared = make_response(response)
    cookie_options = {
        "path": "/",
        "secure": bool(current_app.config["BROWSER_COOKIE_SECURE"]),
        "samesite": current_app.config["BROWSER_COOKIE_SAMESITE"],
    }
    prepared.delete_cookie(
        current_app.config["BROWSER_SESSION_COOKIE_NAME"],
        httponly=True,
        **cookie_options,
    )
    prepared.delete_cookie(
        current_app.config["BROWSER_CSRF_COOKIE_NAME"],
        httponly=False,
        **cookie_options,
    )
    return prepared


def _valid_cookie_csrf(auth_session: AuthSession) -> bool:
    stored_hash = auth_session.csrf_token_hash
    header_token = _bounded_token(request.headers.get("X-CSRF-Token"))
    cookie_token = _bounded_token(
        request.cookies.get(current_app.config["BROWSER_CSRF_COOKIE_NAME"])
    )
    if stored_hash is None or header_token is None or cookie_token is None:
        return False
    if not secrets.compare_digest(header_token, cookie_token):
        return False
    return secrets.compare_digest(hash_csrf_token(header_token), stored_hash)


def auth_required(view: ViewFunction) -> ViewFunction:
    """Require a valid server-side bearer or browser session for a route.

    Authenticated routes can use ``g.current_user`` and ``g.auth_session``.
    Explicit bearer credentials always take precedence and never fall back to a
    cookie. Cookie-authenticated unsafe methods also require the session-bound
    CSRF cookie value in the ``X-CSRF-Token`` header.
    """

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Response | Any:
        authorization_supplied = "Authorization" in request.headers
        attempted_cookie_auth = False
        if authorization_supplied:
            token = _bearer_token()
            auth_session = (
                _session_for_token(token, browser=False) if token else None
            )
            auth_transport = "bearer"
        else:
            cookie_name = current_app.config["BROWSER_SESSION_COOKIE_NAME"]
            attempted_cookie_auth = cookie_name in request.cookies
            token = _browser_session_token()
            auth_session = (
                _session_for_token(token, browser=True) if token else None
            )
            auth_transport = "cookie"

        if auth_session is None:
            failure = (jsonify({"error": "Authentication required."}), 401)
            if attempted_cookie_auth:
                return clear_browser_auth_cookies(failure)
            return failure

        if (
            auth_transport == "cookie"
            and request.method.upper() not in SAFE_REQUEST_METHODS
            and not _valid_cookie_csrf(auth_session)
        ):
            return (
                jsonify(
                    {
                        "error": "CSRF validation failed.",
                        "code": "csrf_failed",
                    }
                ),
                403,
            )

        g.current_user = auth_session.user
        g.auth_session = auth_session
        g.auth_transport = auth_transport
        return view(*args, **kwargs)

    return cast(ViewFunction, wrapped)


__all__ = [
    "auth_required",
    "clear_browser_auth_cookies",
    "generate_csrf_token",
    "generate_session_token",
    "hash_csrf_token",
    "hash_session_token",
    "set_browser_auth_cookies",
    "set_browser_csrf_cookie",
]
