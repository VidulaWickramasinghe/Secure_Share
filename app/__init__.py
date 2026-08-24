"""Application factory for the secure file-transfer API."""

from __future__ import annotations

import os
from pathlib import Path

import click
from flask import Flask, current_app, jsonify, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from app.config import Config
from app.extensions import db


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure a Flask application instance.

    A mapping may be supplied by tests or a WSGI host. Environment-backed
    defaults are loaded first, then the supplied mapping is applied.
    """

    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    # Flask's default development SQLite URL lives below instance_path. Flask
    # intentionally does not create this directory for us.
    Path(app.instance_path).mkdir(mode=0o700, parents=True, exist_ok=True)

    upload_folder = Path(app.config["UPLOAD_FOLDER"]).expanduser()
    if not upload_folder.is_absolute():
        upload_folder = Path(app.root_path).parent / upload_folder
    upload_folder = upload_folder.resolve()
    if app.static_folder:
        static_folder = Path(app.static_folder).resolve()
        if upload_folder == static_folder or static_folder in upload_folder.parents:
            raise RuntimeError(
                "UPLOAD_FOLDER must not be inside Flask's static directory."
            )
    upload_folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        # Existing directories ignore mkdir's mode, so tighten a checked-out or
        # pre-provisioned storage directory as well.
        upload_folder.chmod(0o700)
    app.config["UPLOAD_FOLDER"] = str(upload_folder)

    db.init_app(app)

    # Importing models before create_all is important for both the CLI and the
    # lightweight test/development setup.
    from app import models  # noqa: F401
    from app.routes.auth import auth_bp
    from app.routes.files import files_bp
    from app.routes.permissions import permissions_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(permissions_bp)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'",
        )
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

    register_error_handlers(app)
    register_cli(app)
    return app


def register_error_handlers(app: Flask) -> None:
    """Return predictable JSON errors without exposing internal details."""

    @app.errorhandler(RequestEntityTooLarge)
    def handle_too_large(_error: RequestEntityTooLarge):
        return jsonify(error="The uploaded file exceeds the size limit."), 413

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        messages = {
            400: "The request is invalid.",
            401: "Authentication is required.",
            403: "You are not authorized to perform this action.",
            404: "The requested resource was not found.",
            405: "The requested method is not allowed.",
        }
        message = messages.get(error.code, "The request could not be completed.")
        return jsonify(error=message), error.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        if current_app.config.get("TESTING"):
            raise error
        current_app.logger.exception("Unhandled application error")
        return jsonify(error="An internal server error occurred."), 500


def register_cli(app: Flask) -> None:
    """Register small database-management commands for local deployments."""

    @app.cli.command("init-db")
    def init_db_command() -> None:
        """Create all database tables."""

        db.create_all()
        click.echo("Database tables created.")
