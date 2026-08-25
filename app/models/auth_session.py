"""Server-side authentication session model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.user import utc_now

if TYPE_CHECKING:
    from app.models.user import User


class AuthSession(db.Model):
    """An opaque server-side bearer or browser session.

    Only a SHA-256 digest of the token is persisted. A database disclosure
    therefore does not immediately disclose live bearer credentials.
    """

    __tablename__ = "auth_sessions"
    __table_args__ = (
        Index("ix_auth_sessions_user_expires", "user_id", "expires_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    # Bearer-only sessions leave this null. Browser sessions store a digest of
    # a separate JavaScript-readable CSRF token; the raw value is never stored.
    csrf_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    user: Mapped["User"] = relationship(back_populates="auth_sessions")

    def __repr__(self) -> str:
        return f"<AuthSession id={self.id!r} user_id={self.user_id!r}>"
