"""Per-user authorization records for private files."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Index, UniqueConstraint

from app.extensions import db


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _serialize_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


class FilePermission(db.Model):
    """Explicit permission for one user to access one file."""

    __tablename__ = "file_permissions"
    __table_args__ = (
        UniqueConstraint(
            "file_id",
            "user_id",
            name="uq_file_permissions_file_user",
        ),
        Index("ix_file_permissions_user_file", "user_id", "file_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(
        db.String(36),
        db.ForeignKey("files.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    file = db.relationship("FileRecord", back_populates="permissions")
    user = db.relationship("User", foreign_keys=[user_id], lazy="joined")

    def to_dict(self, *, include_user: bool = False) -> dict[str, object]:
        result: dict[str, object] = {
            "id": self.id,
            "file_id": self.file_id,
            "user_id": self.user_id,
            "created_at": _serialize_timestamp(self.created_at),
        }
        if include_user:
            result["user"] = {
                "id": self.user.id,
                "username": self.user.username,
            }
        return result
