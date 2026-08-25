"""User account model."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db

if TYPE_CHECKING:
    from app.models.account_action_token import AccountActionToken
    from app.models.auth_session import AuthSession
    from app.models.security_email_job import SecurityEmailJob


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def serialize_timestamp(value: datetime) -> str:
    """Serialize SQLite and PostgreSQL timestamps consistently as UTC."""

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


class User(db.Model):
    """A registered user.

    Usernames and email addresses are normalized before persistence, making
    their unique constraints effectively case-insensitive across SQLite and
    PostgreSQL.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(
        String(80), unique=True, index=True, nullable=False
    )
    email: Mapped[str] = mapped_column(
        String(254), unique=True, index=True, nullable=False
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )

    auth_sessions: Mapped[list["AuthSession"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    account_action_tokens: Mapped[list["AccountActionToken"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    security_email_jobs: Mapped[list["SecurityEmailJob"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("username", "email")
    def _normalize_identity(self, key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string")
        return value.strip().lower()

    def set_password(self, password: str) -> None:
        """Hash a plain-text password; the input is never retained."""

        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self) -> dict[str, object]:
        """Return the public account representation."""

        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "email_verified": self.email_verified_at is not None,
            "created_at": serialize_timestamp(self.created_at),
        }

    def __repr__(self) -> str:
        return f"<User id={self.id!r} username={self.username!r}>"
