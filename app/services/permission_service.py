"""Owner-controlled management of per-file download permissions."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.permission import FilePermission
from app.models.user import User
from app.services.file_service import FileServiceError, get_owned_file


class PermissionValidationError(FileServiceError):
    status_code = 400
    message = "A valid user_id is required."


class PermissionTargetNotFoundError(FileServiceError):
    status_code = 404
    message = "User not found."


class PermissionAlreadyExistsError(FileServiceError):
    status_code = 409
    message = "That user is already authorized for this file."


class PermissionNotFoundError(FileServiceError):
    status_code = 404
    message = "Permission not found."


class OwnerPermissionError(FileServiceError):
    status_code = 400
    message = "The file owner already has access and cannot be authorized."


def validate_user_id(value: object) -> int:
    """Require a JSON integer ID without accepting booleans or coercing text."""

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PermissionValidationError()
    return value


def list_permissions(file_id: str, owner_id: int) -> list[FilePermission]:
    """List authorized users after proving the requester owns the file."""

    get_owned_file(file_id, owner_id)
    statement = (
        select(FilePermission)
        .where(FilePermission.file_id == file_id)
        .order_by(FilePermission.created_at, FilePermission.id)
    )
    return list(db.session.execute(statement).scalars().all())


def authorize_user(
    file_id: str,
    owner_id: int,
    target_user_id: object,
) -> FilePermission:
    """Grant explicit access; only the file owner may call this operation."""

    record = get_owned_file(file_id, owner_id)
    user_id = validate_user_id(target_user_id)
    if user_id == record.owner_id:
        raise OwnerPermissionError()

    target_user = db.session.get(User, user_id)
    if target_user is None:
        raise PermissionTargetNotFoundError()

    existing = db.session.execute(
        select(FilePermission.id).where(
            FilePermission.file_id == file_id,
            FilePermission.user_id == user_id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise PermissionAlreadyExistsError()

    permission = FilePermission(file_id=file_id, user_id=user_id)
    try:
        db.session.add(permission)
        db.session.commit()
    except IntegrityError as exc:
        # The unique constraint is the final authority under concurrent grants.
        db.session.rollback()
        duplicate = db.session.execute(
            select(FilePermission.id).where(
                FilePermission.file_id == file_id,
                FilePermission.user_id == user_id,
            )
        ).scalar_one_or_none()
        if duplicate is not None:
            raise PermissionAlreadyExistsError() from exc
        if db.session.get(User, user_id) is None:
            raise PermissionTargetNotFoundError() from exc
        raise
    return permission


def revoke_user(file_id: str, owner_id: int, target_user_id: object) -> None:
    """Remove one explicit permission; only the file owner may do so."""

    record = get_owned_file(file_id, owner_id)
    user_id = validate_user_id(target_user_id)
    if user_id == record.owner_id:
        raise OwnerPermissionError(
            "The file owner's access cannot be removed."
        )

    permission = db.session.execute(
        select(FilePermission).where(
            FilePermission.file_id == file_id,
            FilePermission.user_id == user_id,
        )
    ).scalar_one_or_none()
    if permission is None:
        raise PermissionNotFoundError()

    try:
        db.session.delete(permission)
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
