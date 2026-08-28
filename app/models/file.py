"""Database model for privately stored files."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import CheckConstraint, Index

from app.extensions import db


def _utcnow() -> datetime:
    """Return an aware UTC timestamp suitable for SQLAlchemy defaults."""

    return datetime.now(timezone.utc)


def _serialize_timestamp(value: datetime) -> str:
    """Serialize timestamps consistently, including SQLite's naive datetimes."""

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


class FileRecord(db.Model):
    """Metadata for an uploaded file whose bytes live in private storage."""

    __tablename__ = "files"
    __table_args__ = (
        CheckConstraint("file_size >= 0", name="ck_files_file_size_nonnegative"),
        Index("ix_files_owner_created_at", "owner_id", "created_at"),
    )

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(
        db.String(64),
        nullable=False,
        unique=True,
        index=True,
    )
    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    file_size = db.Column(db.BigInteger, nullable=False)
    # Retain each file's location when the deployment changes its write backend.
    storage_backend = db.Column(
        db.String(16), nullable=False, default="filesystem", server_default="filesystem"
    )
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    owner = db.relationship("User", foreign_keys=[owner_id], lazy="joined")
    permissions = db.relationship(
        "FilePermission",
        back_populates="file",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def to_dict(self) -> dict[str, object]:
        """Return API-safe metadata; the private storage name is never exposed."""

        return {
            "id": self.id,
            "original_filename": self.original_filename,
            "owner_id": self.owner_id,
            "file_size": self.file_size,
            "created_at": _serialize_timestamp(self.created_at),
        }
