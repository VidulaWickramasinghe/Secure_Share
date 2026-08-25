"""Secret-free durable jobs for security-sensitive account email."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.account_action_token import EMAIL_VERIFICATION, PASSWORD_RESET
from app.models.user import utc_now

if TYPE_CHECKING:
    from app.models.user import User


PASSWORD_CHANGED = "password_changed"  # nosec B105  # pragma: allowlist secret
SECURITY_EMAIL_KINDS = (EMAIL_VERIFICATION, PASSWORD_RESET, PASSWORD_CHANGED)


class SecurityEmailJob(db.Model):
    """A durable request to create and deliver one security email.

    A job deliberately contains no recipient snapshot, message content, raw
    action token, or other usable secret. The worker resolves the current user
    and creates any required action token only after it has claimed the job.
    """

    __tablename__ = "security_email_jobs"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('email_verification', 'password_reset', 'password_changed')",
            name="ck_security_email_jobs_kind",
        ),
        CheckConstraint(
            "attempts >= 0",
            name="ck_security_email_jobs_attempts_nonnegative",
        ),
        Index(
            "ix_security_email_jobs_pending_claim",
            "completed_at",
            "cancelled_at",
            "available_at",
            "lease_expires_at",
        ),
        Index(
            "ix_security_email_jobs_user_kind_pending",
            "user_id",
            "kind",
            "completed_at",
            "cancelled_at",
            "lease_expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempts: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="security_email_jobs")

    def __repr__(self) -> str:
        return (
            f"<SecurityEmailJob id={self.id!r} "
            f"user_id={self.user_id!r} kind={self.kind!r}>"
        )


__all__ = [
    "PASSWORD_CHANGED",
    "SECURITY_EMAIL_KINDS",
    "SecurityEmailJob",
]
