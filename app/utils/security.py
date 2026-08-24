"""Authentication and token-security helpers."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar, cast

from flask import Response, g, jsonify, request
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.models.auth_session import AuthSession
from app.models.user import utc_now


ViewFunction = TypeVar("ViewFunction", bound=Callable[..., Any])


def generate_session_token() -> str:
    """Generate a high-entropy token safe for use in an HTTP header."""

    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    """Return the fixed-size digest stored in the database."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _bearer_token() -> str | None:
    authorization = request.headers.get("Authorization", "")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1]
    # Current tokens are 43 characters. The loose upper bound allows future
    # formats while preventing oversized attacker-controlled database lookups.
    if not token or len(token) > 512:
        return None
    return token


def _session_for_token(token: str) -> AuthSession | None:
    statement = (
        select(AuthSession)
        .options(joinedload(AuthSession.user))
        .where(
            AuthSession.token_hash == hash_session_token(token),
            AuthSession.expires_at > utc_now(),
        )
    )
    return db.session.execute(statement).scalar_one_or_none()


def auth_required(view: ViewFunction) -> ViewFunction:
    """Require a valid server-side bearer session for a route.

    Authenticated routes can use ``g.current_user`` and ``g.auth_session``.
    Authentication failures deliberately share one generic response.
    """

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Response | Any:
        token = _bearer_token()
        auth_session = _session_for_token(token) if token else None
        if auth_session is None:
            return jsonify({"error": "Authentication required."}), 401

        g.current_user = auth_session.user
        g.auth_session = auth_session
        return view(*args, **kwargs)

    return cast(ViewFunction, wrapped)


__all__ = [
    "auth_required",
    "generate_session_token",
    "hash_session_token",
]
