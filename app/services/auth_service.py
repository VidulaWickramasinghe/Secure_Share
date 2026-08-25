"""Authentication business logic."""

from __future__ import annotations

import re
import secrets
from datetime import timedelta
from typing import Any

from flask import current_app
from sqlalchemy import delete, or_, select
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db
from app.models.account_action_token import EMAIL_VERIFICATION, PASSWORD_RESET
from app.models.auth_session import AuthSession
from app.models.security_email_job import PASSWORD_CHANGED, SecurityEmailJob
from app.models.user import User, utc_now
from app.services.email_outbox_service import (
    cancel_security_email_jobs,
    enqueue_security_email,
)
from app.services.password_policy import (
    MAXIMUM_PASSWORD_LENGTH,
    PasswordPolicyError,
    validate_new_password,
)
from app.utils.security import (
    generate_csrf_token,
    generate_session_token,
    hash_csrf_token,
    hash_session_token,
)

USERNAME_PATTERN = re.compile(r"^[a-z0-9_.-]{3,80}$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
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


def normalize_email_address(value: object) -> str:
    """Normalize an email using the same rules as registration."""

    if not isinstance(value, str) or not value.strip():
        raise AuthServiceError("A valid email address is required.")
    return _validate_email(value.strip())


def _validate_new_password(password: object, field: str = "password") -> str:
    try:
        return validate_new_password(password, field=field)
    except PasswordPolicyError as exc:
        raise AuthServiceError(exc.message) from exc


def register_user(payload: dict[str, Any]) -> tuple[User, SecurityEmailJob]:
    username = _validate_username(_required_string(payload, "username"))
    email = _validate_email(_required_string(payload, "email"))
    password = _validate_new_password(payload.get("password"))

    existing = db.session.execute(
        select(User.id).where(or_(User.username == username, User.email == email))
    ).first()
    if existing is not None:
        raise AuthServiceError(
            "Unable to create an account with those details.", 409
        )

    user = User(username=username, email=email, password_hash="")  # nosec B106
    user.set_password(password)
    try:
        db.session.add(user)
        db.session.flush()
        email_job = enqueue_security_email(
            user, EMAIL_VERIFICATION, commit=False
        )
        if email_job is None:
            raise RuntimeError("New account unexpectedly started as verified.")
        db.session.commit()
    except IntegrityError as exc:
        # Protect against concurrent registrations racing the initial lookup.
        db.session.rollback()
        raise AuthServiceError(
            "Unable to create an account with those details.", 409
        ) from exc
    return user, email_job


def _authenticate_user(payload: dict[str, Any]) -> User:
    """Verify credentials without deciding how the resulting session travels."""

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
    if len(identifier) > 254:
        check_password_hash(DUMMY_PASSWORD_HASH, password)
        raise AuthServiceError("Invalid username/email or password.", 401)
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

    # Reacquire the account under a row lock before creating the session. A
    # concurrent password reset may have changed the hash after the first
    # verification; populate_existing ensures the identity-map object refreshes
    # after waiting for that transaction. Wrong-password attempts never take
    # the row lock, avoiding an account-targeted lock amplification vector.
    verified_hash = user.password_hash
    locked_user = db.session.execute(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if locked_user is None:
        raise AuthServiceError("Invalid username/email or password.", 401)
    if (
        not secrets.compare_digest(verified_hash, locked_user.password_hash)
        and not locked_user.check_password(password)
    ):
        raise AuthServiceError("Invalid username/email or password.", 401)

    return locked_user


def _create_auth_session(
    user: User,
    *,
    csrf_token_hash: str | None = None,
) -> tuple[str, AuthSession]:
    """Create one fixed-lifetime server-side authentication session."""

    raw_token = generate_session_token()
    expires_at = utc_now() + timedelta(
        seconds=int(current_app.config["SESSION_LIFETIME_SECONDS"])
    )
    auth_session = AuthSession(
        user_id=user.id,
        token_hash=hash_session_token(raw_token),
        csrf_token_hash=csrf_token_hash,
        expires_at=expires_at,
    )
    db.session.add(auth_session)
    db.session.commit()
    return raw_token, auth_session


def login_user(payload: dict[str, Any]) -> tuple[User, str, AuthSession]:
    """Authenticate an API client and create a bearer-only session."""

    user = _authenticate_user(payload)
    raw_token, auth_session = _create_auth_session(user)
    return user, raw_token, auth_session


def login_browser_user(
    payload: dict[str, Any],
) -> tuple[User, str, str, AuthSession]:
    """Authenticate a browser and create cookie and CSRF credentials."""

    user = _authenticate_user(payload)
    raw_csrf_token = generate_csrf_token()
    raw_session_token, auth_session = _create_auth_session(
        user,
        csrf_token_hash=hash_csrf_token(raw_csrf_token),
    )
    return user, raw_session_token, raw_csrf_token, auth_session


def rotate_session_csrf(auth_session: AuthSession) -> str:
    """Replace a browser session's CSRF token and persist only its digest."""

    if auth_session.csrf_token_hash is None:
        raise AuthServiceError("CSRF tokens are only used by browser sessions.")
    raw_csrf_token = generate_csrf_token()
    auth_session.csrf_token_hash = hash_csrf_token(raw_csrf_token)
    db.session.commit()
    return raw_csrf_token


def logout_session(auth_session: AuthSession) -> None:
    db.session.delete(auth_session)
    db.session.commit()


def change_password(
    user: User,
    current_session: AuthSession,
    payload: dict[str, Any],
) -> SecurityEmailJob:
    locked_user = db.session.execute(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    if locked_user.email_verified_at is None:
        raise AuthServiceError(
            "Verify your email address before changing security settings.", 403
        )
    current_password = payload.get("current_password")
    if not isinstance(current_password, str) or not current_password:
        raise AuthServiceError("current_password is required.")
    if len(current_password) > MAXIMUM_PASSWORD_LENGTH:
        raise AuthServiceError("Current password is incorrect.")
    new_password = _validate_new_password(
        payload.get("new_password"), "new_password"
    )

    if not locked_user.check_password(current_password):
        raise AuthServiceError("Current password is incorrect.")
    if current_password == new_password:
        raise AuthServiceError(
            "new_password must be different from the current password."
        )

    locked_user.set_password(new_password)
    locked_user.password_changed_at = utc_now()
    cancel_security_email_jobs(
        locked_user, PASSWORD_RESET, commit=False
    )
    # A password change invalidates every other device while keeping the
    # request's session usable so the response can be consumed normally.
    db.session.execute(
        delete(AuthSession).where(
            AuthSession.user_id == locked_user.id,
            AuthSession.id != current_session.id,
        )
    )
    email_job = enqueue_security_email(
        locked_user, PASSWORD_CHANGED, commit=False
    )
    if email_job is None:  # pragma: no cover - this kind always creates a job
        raise RuntimeError("Password-change alert was not queued.")
    db.session.commit()
    return email_job


__all__ = [
    "AuthServiceError",
    "change_password",
    "login_browser_user",
    "login_user",
    "logout_session",
    "normalize_email_address",
    "register_user",
    "rotate_session_csrf",
]
