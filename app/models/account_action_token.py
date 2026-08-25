"""Digest-only tokens for email verification and account recovery."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.user import utc_now

if TYPE_CHECKING:
    from app.models.user import User


EMAIL_VERIFICATION = "email_verification"
PASSWORD_RESET = "password_reset"  # nosec B105  # pragma: allowlist secret
TOKEN_PURPOSES = (EMAIL_VERIFICATION, PASSWORD_RESET)


class AccountActionToken(db.Model):
    """One expiring, single-use account action token.

    The usable token is delivered to the account's email address and is never
    stored. Only a purpose-bound HMAC digest is persisted.
    """

    __tablename__ = "account_action_tokens"
    __table_args__ = (
        CheckConstraint(
            "purpose IN ('email_verification', 'password_reset')",
            name="ck_account_action_tokens_purpose",
        ),
        Index(
            "ix_account_action_tokens_user_purpose_state",
            "user_id",
            "purpose",
            "consumed_at",
            "invalidated_at",
            "expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    target_email: Mapped[str] = mapped_column(String(254), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    invalidated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User"] = relationship(back_populates="account_action_tokens")

    def __repr__(self) -> str:
        return (
            f"<AccountActionToken id={self.id!r} "
            f"user_id={self.user_id!r} purpose={self.purpose!r}>"
        )


__all__ = [
    "AccountActionToken",
    "EMAIL_VERIFICATION",
    "PASSWORD_RESET",
    "TOKEN_PURPOSES",
]
