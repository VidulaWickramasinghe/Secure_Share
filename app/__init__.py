"""Application factory for the secure file-transfer API."""

from __future__ import annotations

import os
import time
from pathlib import Path

import click
from flask import Flask, current_app, jsonify, request
from flask_limiter import RateLimitExceeded
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from app.config import Config
from app.database import (
    MIGRATIONS_DIRECTORY,
    LegacySchemaMismatch,
    initialize_database,
)
from app.extensions import db, migrate
from app.rate_limits import init_rate_limiting
from app.validation import validate_application_configuration


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure a Flask application instance.

    A mapping may be supplied by tests or a WSGI host. Environment-backed
    defaults are loaded first, then the supplied mapping is applied.
    """

    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    validate_application_configuration(app)
    init_rate_limiting(app)

    # Flask's default development SQLite URL lives below instance_path. Flask
    # intentionally does not create this directory for us.
    if (
        str(app.config["SQLALCHEMY_DATABASE_URI"]).startswith("sqlite:")
        or app.config["MAIL_BACKEND"] == "file"
    ):
        Path(app.instance_path).mkdir(mode=0o700, parents=True, exist_ok=True)

    if app.config["FILE_STORAGE_BACKEND"] == "filesystem":
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
    migrate.init_app(
        app,
        db,
        directory=str(MIGRATIONS_DIRECTORY),
        compare_type=True,
        render_as_batch=True,
    )

    # Import models before migrations or test-only metadata creation inspect
    # SQLAlchemy's model registry.
    from app import models  # noqa: F401
    from app.routes.auth import auth_bp
    from app.routes.files import files_bp
    from app.routes.internal import internal_bp
    from app.routes.permissions import permissions_bp
    from app.routes.web import web_bp

    app.register_blueprint(web_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(internal_bp)
    app.register_blueprint(permissions_bp)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        if str(current_app.config.get("APP_ENV", "")).lower() == "production":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        if request.path.startswith("/api/"):
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'",
            )
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        else:
            response.headers.setdefault(
                "Content-Security-Policy",
                "; ".join(
                    (
                        "default-src 'self'",
                        "script-src 'self'",
                        "style-src 'self'",
                        "img-src 'self' data:",
                        "font-src 'self'",
                        "connect-src 'self'",
                        "object-src 'none'",
                        "base-uri 'self'",
                        "form-action 'self'",
                        "frame-ancestors 'none'",
                    )
                ),
            )
            if request.endpoint != "static":
                response.headers["Cache-Control"] = "no-store"
        return response

    register_error_handlers(app)
    register_cli(app)
    return app


def register_error_handlers(app: Flask) -> None:
    """Return predictable JSON errors without exposing internal details."""

    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit(_error: RateLimitExceeded):
        return (
            jsonify(
                error="Too many requests. Please try again later.",
                code="rate_limit_exceeded",
            ),
            429,
        )

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
        """Safely initialize or migrate the configured database."""

        try:
            state = initialize_database()
        except LegacySchemaMismatch as exc:
            raise click.ClickException(str(exc)) from exc

        messages = {
            "fresh": "Database initialized at the latest migration.",
            "adopted": (
                "Existing baseline schema validated, adopted, and upgraded."
            ),
            "upgraded": "Database migrations applied.",
        }
        click.echo(messages[state])

    @app.cli.command("email-worker")
    @click.option(
        "--once",
        is_flag=True,
        help="Process one batch and exit instead of polling continuously.",
    )
    @click.option(
        "--batch-size",
        type=click.IntRange(min=1, max=1000),
        default=None,
        help="Maximum jobs per batch (defaults to configuration).",
    )
    @click.option(
        "--poll-seconds",
        type=click.FloatRange(min=0.1, max=300),
        default=None,
        help="Idle polling interval (defaults to configuration).",
    )
    def email_worker_command(
        once: bool,
        batch_size: int | None,
        poll_seconds: float | None,
    ) -> None:
        """Deliver queued verification, recovery, and security-alert email."""

        from app.services.email_outbox_service import (
            process_pending_security_email,
        )

        resolved_batch_size = batch_size or int(
            current_app.config["SECURITY_EMAIL_WORKER_BATCH_SIZE"]
        )
        resolved_poll_seconds = poll_seconds or float(
            current_app.config["SECURITY_EMAIL_WORKER_POLL_SECONDS"]
        )
        click.echo("Security email worker started.")
        try:
            while True:
                results = process_pending_security_email(resolved_batch_size)
                if results:
                    outcomes: dict[str, int] = {}
                    for result in results:
                        outcomes[result.outcome] = outcomes.get(result.outcome, 0) + 1
                    summary = ", ".join(
                        f"{outcome}={count}"
                        for outcome, count in sorted(outcomes.items())
                    )
                    click.echo(f"Processed {len(results)} job(s): {summary}.")
                if once:
                    break
                if len(results) < resolved_batch_size:
                    time.sleep(resolved_poll_seconds)
        except KeyboardInterrupt:
            click.echo("Security email worker stopped.")
