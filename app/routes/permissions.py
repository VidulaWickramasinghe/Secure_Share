"""REST endpoints for owner-managed per-file permissions."""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from app.services.file_service import FileServiceError
from app.services.permission_service import (
    authorize_user,
    list_permissions,
    revoke_user,
)
from app.utils.security import auth_required


permissions_bp = Blueprint(
    "permissions",
    __name__,
    url_prefix="/api/files",
)


@permissions_bp.errorhandler(FileServiceError)
def handle_permission_service_error(error: FileServiceError):
    return jsonify({"error": error.public_message}), error.status_code


@permissions_bp.get("/<string:file_id>/permissions")
@auth_required
def get_file_permissions(file_id: str):
    permissions = list_permissions(file_id, g.current_user.id)
    return jsonify(
        {
            "permissions": [
                permission.to_dict(include_user=True)
                for permission in permissions
            ]
        }
    )


@permissions_bp.post("/<string:file_id>/permissions")
@auth_required
def grant_file_permission(file_id: str):
    payload = request.get_json(silent=True)
    target_user_id = payload.get("user_id") if isinstance(payload, dict) else None
    permission = authorize_user(
        file_id,
        g.current_user.id,
        target_user_id,
    )
    return (
        jsonify(
            {
                "message": "Permission granted successfully.",
                "permission": permission.to_dict(include_user=True),
            }
        ),
        201,
    )


@permissions_bp.delete("/<string:file_id>/permissions/<int:user_id>")
@auth_required
def remove_file_permission(file_id: str, user_id: int):
    revoke_user(file_id, g.current_user.id, user_id)
    return jsonify({"message": "Permission removed successfully."})


__all__ = ["permissions_bp"]
