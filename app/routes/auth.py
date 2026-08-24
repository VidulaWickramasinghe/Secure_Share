"""REST endpoints for account and authentication operations."""

from __future__ import annotations

from typing import Any

from flask import Blueprint, g, jsonify, request

from app.models.user import serialize_timestamp
from app.services.auth_service import (
    AuthServiceError,
    change_password,
    login_user,
    logout_session,
    register_user,
)
from app.utils.security import auth_required


auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _json_payload() -> dict[str, Any]:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise AuthServiceError("A JSON object is required.")
    return payload


def _service_error_response(error: AuthServiceError):
    return jsonify({"error": error.message}), error.status_code


@auth_bp.post("/register")
def register():
    try:
        user = register_user(_json_payload())
    except AuthServiceError as error:
        return _service_error_response(error)
    return jsonify({"user": user.to_dict()}), 201


@auth_bp.post("/login")
def login():
    try:
        user, token, auth_session = login_user(_json_payload())
    except AuthServiceError as error:
        return _service_error_response(error)

    return jsonify(
        {
            "token": token,
            "token_type": "Bearer",
            "expires_at": serialize_timestamp(auth_session.expires_at),
            "user": user.to_dict(),
        }
    )


@auth_bp.post("/logout")
@auth_required
def logout():
    logout_session(g.auth_session)
    return jsonify({"message": "Logged out successfully."})


@auth_bp.get("/me")
@auth_required
def me():
    return jsonify({"user": g.current_user.to_dict()})


@auth_bp.route("/password", methods=["PATCH", "PUT"])
@auth_required
def update_password():
    try:
        change_password(g.current_user, g.auth_session, _json_payload())
    except AuthServiceError as error:
        return _service_error_response(error)
    return jsonify({"message": "Password changed successfully."})


__all__ = ["auth_bp"]
