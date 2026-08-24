"""Authentication business logic."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from flask import current_app
from sqlalchemy import delete, or_, select
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db
from app.models.auth_session import AuthSession
from app.models.user import User, utc_now
from app.utils.security import generate_session_token, hash_session_token


USERNAME_PATTERN = re.compile(r"^[a-z0-9_.-]{3,80}$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
MINIMUM_PASSWORD_LENGTH = 8
MAXIMUM_PASSWORD_LENGTH = 1024
# Used to keep failed-login password verification work similar for known and
# unknown accounts, reducing username-enumeration timing differences.
DUMMY_PASSWORD_HASH = generate_password_hash(
    "not-a-user-password", method="scrypt"
)


class AuthServiceError(Exception):
    """Expected validation or authentication failure."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _required_string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise AuthServiceError(f"{field} is required.")
    return value.strip()


def _validate_username(username: str) -> str:
    normalized = username.lower()
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise AuthServiceError(
            "username must be 3-80 characters and contain only letters, "
            "numbers, dots, underscores, or hyphens."
        )
    return normalized


def _validate_email(email: str) -> str:
    normalized = email.lower()
    if len(normalized) > 254 or not EMAIL_PATTERN.fullmatch(normalized):
        raise AuthServiceError("A valid email address is required.")
    return normalized


def _validate_password(password: object, field: str = "password") -> str:
    if not isinstance(password, str):
        raise AuthServiceError(f"{field} is required.")
    if len(password) < MINIMUM_PASSWORD_LENGTH:
        raise AuthServiceError(
            f"{field} must be at least {MINIMUM_PASSWORD_LENGTH} characters."
        )
    if len(password) > MAXIMUM_PASSWORD_LENGTH:
        raise AuthServiceError(f"{field} is too long.")
    return password


def register_user(payload: dict[str, Any]) -> User:
    username = _validate_username(_required_string(payload, "username"))
    email = _validate_email(_required_string(payload, "email"))
    password = _validate_password(payload.get("password"))

    existing = db.session.execute(
        select(User.id).where(or_(User.username == username, User.email == email))
    ).first()
    if existing is not None:
        raise AuthServiceError("Username or email is already registered.", 409)

    user = User(username=username, email=email, password_hash="")
    user.set_password(password)
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError as exc:
        # Protect against concurrent registrations racing the initial lookup.
        db.session.rollback()
        raise AuthServiceError(
            "Username or email is already registered.", 409
        ) from exc
    return user


def login_user(payload: dict[str, Any]) -> tuple[User, str, AuthSession]:
    identifier_value = (
        payload.get("identifier") or payload.get("username") or payload.get("email")
    )
    if not isinstance(identifier_value, str) or not identifier_value.strip():
        raise AuthServiceError("identifier is required.")
    password = payload.get("password")
    if not isinstance(password, str) or not password:
        raise AuthServiceError("password is required.")
    if len(password) > MAXIMUM_PASSWORD_LENGTH:
        # Keep the response indistinguishable from another invalid credential
        # while avoiding expensive hashing of attacker-controlled huge input.
        raise AuthServiceError("Invalid username/email or password.", 401)

    identifier = identifier_value.strip().lower()
    user = db.session.execute(
        select(User).where(
            or_(User.username == identifier, User.email == identifier)
        )
    ).scalar_one_or_none()

    if user is None:
        check_password_hash(DUMMY_PASSWORD_HASH, password)
        raise AuthServiceError("Invalid username/email or password.", 401)
    if not user.check_password(password):
        raise AuthServiceError("Invalid username/email or password.", 401)

    raw_token = generate_session_token()
    expires_at = utc_now() + timedelta(
        seconds=int(current_app.config["SESSION_LIFETIME_SECONDS"])
    )
    auth_session = AuthSession(
        user_id=user.id,
        token_hash=hash_session_token(raw_token),
        expires_at=expires_at,
    )
    db.session.add(auth_session)
    db.session.commit()
    return user, raw_token, auth_session


def logout_session(auth_session: AuthSession) -> None:
    db.session.delete(auth_session)
    db.session.commit()


def change_password(
    user: User,
    current_session: AuthSession,
    payload: dict[str, Any],
) -> None:
    current_password = payload.get("current_password")
    if not isinstance(current_password, str) or not current_password:
        raise AuthServiceError("current_password is required.")
    if len(current_password) > MAXIMUM_PASSWORD_LENGTH:
        raise AuthServiceError("Current password is incorrect.")
    new_password = _validate_password(payload.get("new_password"), "new_password")

    if not user.check_password(current_password):
        raise AuthServiceError("Current password is incorrect.")
    if current_password == new_password:
        raise AuthServiceError(
            "new_password must be different from the current password."
        )

    user.set_password(new_password)
    # A password change invalidates every other device while keeping the
    # request's session usable so the response can be consumed normally.
    db.session.execute(
        delete(AuthSession).where(
            AuthSession.user_id == user.id,
            AuthSession.id != current_session.id,
        )
    )
    db.session.commit()


__all__ = [
    "AuthServiceError",
    "change_password",
    "login_user",
    "logout_session",
    "register_user",
]
