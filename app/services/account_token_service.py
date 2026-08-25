"""Secure email-verification and password-recovery token operations."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta

from flask import current_app
from sqlalchemy import delete, select, update

from app.extensions import db
from app.models.account_action_token import (
    AccountActionToken,
    EMAIL_VERIFICATION,
    PASSWORD_RESET,
    TOKEN_PURPOSES,
)
from app.models.auth_session import AuthSession
from app.models.security_email_job import PASSWORD_CHANGED, SecurityEmailJob
from app.models.user import User, utc_now
from app.services.password_policy import PasswordPolicyError, validate_new_password


MAXIMUM_ACTION_TOKEN_LENGTH = 512


class AccountTokenError(Exception):
    """A safe, expected account-token failure."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _pepper() -> bytes:
    value = current_app.config.get("ACCOUNT_TOKEN_PEPPER")
    if not isinstance(value, str) or len(value) < 32:
        raise RuntimeError("ACCOUNT_TOKEN_PEPPER must contain at least 32 characters.")
    return value.encode("utf-8")


def hash_account_token(raw_token: str, purpose: str) -> str:
    """Return a domain-separated HMAC without retaining the usable token."""

    if purpose not in TOKEN_PURPOSES:
        raise ValueError("Unsupported account token purpose.")
    message = f"secure-share:{purpose}\0{raw_token}".encode("utf-8")
    return hmac.new(_pepper(), message, hashlib.sha256).hexdigest()


def _token_lifetime(purpose: str) -> timedelta:
    config_key = (
        "EMAIL_VERIFICATION_TOKEN_LIFETIME_SECONDS"
        if purpose == EMAIL_VERIFICATION
        else "PASSWORD_RESET_TOKEN_LIFETIME_SECONDS"
    )
    return timedelta(seconds=int(current_app.config[config_key]))


def issue_account_token(
    user: User,
    purpose: str,
    *,
    commit: bool = True,
) -> str | None:
    """Invalidate sibling challenges and issue a new random action token."""

    if purpose not in TOKEN_PURPOSES:
        raise ValueError("Unsupported account token purpose.")

    # Serialize challenge generations for this account. Without the row lock,
    # two PostgreSQL READ COMMITTED transactions could each invalidate the old
    # generation before either inserts its replacement, leaving two usable
    # links after both commit. SQLite ignores FOR UPDATE but serializes writes.
    locked_user = db.session.execute(
        select(User).where(User.id == user.id).with_for_update()
    ).scalar_one()
    if (
        purpose == EMAIL_VERIFICATION
        and locked_user.email_verified_at is not None
    ):
        if commit:
            db.session.commit()
        return None
    now = utc_now()
    raw_token = secrets.token_urlsafe(32)
    db.session.execute(
        update(AccountActionToken)
        .where(
            AccountActionToken.user_id == locked_user.id,
            AccountActionToken.purpose == purpose,
            AccountActionToken.consumed_at.is_(None),
            AccountActionToken.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )
    record = AccountActionToken(
        user_id=locked_user.id,
        purpose=purpose,
        token_hash=hash_account_token(raw_token, purpose),
        target_email=locked_user.email,
        created_at=now,
        expires_at=now + _token_lifetime(purpose),
    )
    db.session.add(record)
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    return raw_token


def issue_email_verification_token(
    user: User,
    *,
    commit: bool = True,
) -> str | None:
    """Issue verification only while the current address remains unverified."""

    return issue_account_token(user, EMAIL_VERIFICATION, commit=commit)


def issue_password_reset_token(user: User) -> str:
    token = issue_account_token(user, PASSWORD_RESET)
    assert token is not None  # nosec B101 - only verification may return None
    return token


def _claim_token(raw_token: object, purpose: str):
    """Atomically claim a valid token and return its protected metadata."""

    if (
        not isinstance(raw_token, str)
        or not raw_token
        or len(raw_token) > MAXIMUM_ACTION_TOKEN_LENGTH
    ):
        raise AccountTokenError("The token is invalid or has expired.")

    lookup_now = utc_now()
    token_hash = hash_account_token(raw_token, purpose)
    candidate_user_id = db.session.execute(
        select(AccountActionToken.user_id).where(
            AccountActionToken.token_hash == token_hash,
            AccountActionToken.purpose == purpose,
            AccountActionToken.consumed_at.is_(None),
            AccountActionToken.invalidated_at.is_(None),
            AccountActionToken.expires_at > lookup_now,
        )
    ).scalar_one_or_none()
    if candidate_user_id is None:
        db.session.rollback()
        raise AccountTokenError("The token is invalid or has expired.")

    # Use the same user-then-token lock order as issuance. This prevents two
    # confirmations, or a confirmation and a replacement request, from
    # producing multiple usable generations or deadlocking in PostgreSQL.
    locked_user = db.session.execute(
        select(User)
        .where(User.id == candidate_user_id)
        .with_for_update()
    ).scalar_one_or_none()
    if locked_user is None:
        db.session.rollback()
        raise AccountTokenError("The token is invalid or has expired.")

    # Lock acquisition can block behind token replacement or a security
    # setting change. Re-read the clock so the authoritative claim cannot use
    # a token which expired while this transaction was waiting.
    claim_now = utc_now()
    statement = (
        update(AccountActionToken)
        .where(
            AccountActionToken.token_hash == token_hash,
            AccountActionToken.purpose == purpose,
            AccountActionToken.consumed_at.is_(None),
            AccountActionToken.invalidated_at.is_(None),
            AccountActionToken.expires_at > claim_now,
        )
        .values(consumed_at=claim_now)
        .returning(
            AccountActionToken.id,
            AccountActionToken.user_id,
            AccountActionToken.target_email,
        )
    )
    claimed = db.session.execute(
        statement.execution_options(synchronize_session=False)
    ).one_or_none()
    if claimed is None:
        db.session.rollback()
        raise AccountTokenError("The token is invalid or has expired.")
    return claimed, claim_now, locked_user


def _email_matches(current_email: str, token_email: str) -> bool:
    """Compare a token binding without rejecting valid non-ASCII addresses."""

    return secrets.compare_digest(
        current_email.encode("utf-8"), token_email.encode("utf-8")
    )


def confirm_email_verification(raw_token: object) -> User:
    """Consume one token and mark exactly its bound address verified."""

    claimed, now, user = _claim_token(raw_token, EMAIL_VERIFICATION)
    if not _email_matches(user.email, claimed.target_email):
        db.session.rollback()
        raise AccountTokenError("The token is invalid or has expired.")

    user.email_verified_at = now
    db.session.execute(
        update(AccountActionToken)
        .where(
            AccountActionToken.user_id == user.id,
            AccountActionToken.purpose == EMAIL_VERIFICATION,
            AccountActionToken.id != claimed.id,
            AccountActionToken.consumed_at.is_(None),
            AccountActionToken.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )
    db.session.commit()
    return user


def reset_password_with_token(
    raw_token: object,
    new_password: object,
) -> tuple[User, SecurityEmailJob]:
    """Consume a reset token, replace the password, and revoke all sessions."""

    claimed, now, user = _claim_token(raw_token, PASSWORD_RESET)
    if not _email_matches(user.email, claimed.target_email):
        db.session.rollback()
        raise AccountTokenError("The token is invalid or has expired.")

    try:
        password = validate_new_password(new_password, field="new_password")
    except PasswordPolicyError as exc:
        db.session.rollback()
        raise AccountTokenError(exc.message) from exc

    user.set_password(password)
    user.password_changed_at = now
    # The recovery token was delivered to the current address, so successful
    # use also proves control of that address.
    if user.email_verified_at is None:
        user.email_verified_at = now
    db.session.execute(
        update(AccountActionToken)
        .where(
            AccountActionToken.user_id == user.id,
            AccountActionToken.id != claimed.id,
            AccountActionToken.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )
    db.session.execute(delete(AuthSession).where(AuthSession.user_id == user.id))
    # Queue the mandatory security notice in the same transaction as the
    # credential change. The worker resolves the current address and never
    # persists a message body or usable action token.
    from app.services.email_outbox_service import (
        cancel_security_email_jobs,
        enqueue_security_email,
    )

    cancel_security_email_jobs(user, PASSWORD_RESET, commit=False)
    email_job = enqueue_security_email(user, PASSWORD_CHANGED, commit=False)
    if email_job is None:  # pragma: no cover - this kind always creates a job
        raise RuntimeError("Password-change alert was not queued.")
    db.session.commit()
    return user, email_job


def invalidate_password_reset_tokens(user_id: int) -> None:
    """Invalidate recovery links after an authenticated password change."""

    db.session.execute(
        update(AccountActionToken)
        .where(
            AccountActionToken.user_id == user_id,
            AccountActionToken.purpose == PASSWORD_RESET,
            AccountActionToken.consumed_at.is_(None),
            AccountActionToken.invalidated_at.is_(None),
        )
        .values(invalidated_at=utc_now())
    )


def find_user_for_password_reset(email: str) -> User | None:
    return db.session.execute(select(User).where(User.email == email)).scalar_one_or_none()


__all__ = [
    "AccountTokenError",
    "confirm_email_verification",
    "find_user_for_password_reset",
    "hash_account_token",
    "invalidate_password_reset_tokens",
    "issue_email_verification_token",
    "issue_password_reset_token",
    "reset_password_with_token",
]
