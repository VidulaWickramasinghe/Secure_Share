"""REST endpoints for private file upload, discovery, and download."""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge

from app.services.file_service import (
    FileServiceError,
    delete_file,
    get_accessible_file,
    get_download,
    list_accessible_files,
    upload_file,
)
from app.utils.security import auth_required


files_bp = Blueprint("files", __name__, url_prefix="/api/files")


@files_bp.errorhandler(FileServiceError)
def handle_file_service_error(error: FileServiceError):
    return jsonify({"error": error.public_message}), error.status_code


@files_bp.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(_error: RequestEntityTooLarge):
    return jsonify({"error": "The uploaded file is too large."}), 413


@files_bp.post("")
@auth_required
def create_file():
    record = upload_file(request.files.get("file"), g.current_user)
    return (
        jsonify(
            {
                "message": "File uploaded successfully.",
                "file": record.to_dict(),
            }
        ),
        201,
    )


@files_bp.get("")
@auth_required
def list_files():
    records = list_accessible_files(g.current_user.id)
    return jsonify({"files": [record.to_dict() for record in records]})


@files_bp.get("/<string:file_id>")
@auth_required
def get_file_metadata(file_id: str):
    record = get_accessible_file(file_id, g.current_user.id)
    return jsonify({"file": record.to_dict()})


@files_bp.get("/<string:file_id>/download")
@auth_required
def download_file(file_id: str):
    record, stored_file = get_download(file_id, g.current_user.id)
    try:
        response = send_file(
            stored_file,
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=record.original_filename,
            conditional=False,
            etag=False,
            max_age=0,
        )
    except Exception:
        stored_file.close()
        raise
    response.call_on_close(stored_file.close)
    response.content_length = record.file_size
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return response


@files_bp.delete("/<string:file_id>")
@auth_required
def remove_file(file_id: str):
    delete_file(file_id, g.current_user.id)
    return jsonify({"message": "File deleted successfully."})


__all__ = ["files_bp"]
