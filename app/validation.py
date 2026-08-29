"""Collect startup problems before initializing services or writing files."""

from __future__ import annotations

import os
from urllib.parse import urlsplit

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app.rate_limits import validate_rate_limit_configuration
from app.services.password_policy import (
    PasswordPolicyConfigurationError,
    validate_password_policy_configuration,
)
from deployment import DeploymentConfigurationError


def validate_application_configuration(app) -> None:
    config = app.config
    problems = list(config.get("CONFIGURATION_ERRORS", ()))
    environment = str(config.get("APP_ENV", "development")).strip().lower()
    if environment not in {"development", "test", "production"}:
        problems.append("APP_ENV must be development, test, or production")
    mail_backend = str(config.get("MAIL_BACKEND", "")).lower()
    if mail_backend not in {"memory", "file", "smtp", "disabled"}:
        problems.append("MAIL_BACKEND must be memory, file, smtp, or disabled")
    if config.get("SMTP_USE_SSL") and config.get("SMTP_USE_STARTTLS"):
        problems.append("SMTP_USE_SSL and SMTP_USE_STARTTLS cannot both be true")
    storage_backend = config.get("FILE_STORAGE_BACKEND")
    if storage_backend not in {"filesystem", "vercel_blob"}:
        problems.append("FILE_STORAGE_BACKEND must be filesystem or vercel_blob")
    if (
        storage_backend == "vercel_blob"
        and not str(config.get("BLOB_READ_WRITE_TOKEN") or "").strip()
    ):
        problems.append("Private Blob storage requires BLOB_READ_WRITE_TOKEN")
    cron_secret = config.get("CRON_SECRET")
    if cron_secret and (
        not isinstance(cron_secret, str)
        or len(cron_secret.strip()) < 32
        or cron_secret
        in (
            config.get("SECRET_KEY"),
            config.get("ACCOUNT_TOKEN_PEPPER"),
            config.get("RATE_LIMIT_KEY_SECRET"),
        )
    ):
        problems.append(
            "CRON_SECRET must be an independent secret of at least 32 characters"
        )
    if config["SECURITY_EMAIL_HTTP_BATCH_SIZE"] > 3:
        problems.append("SECURITY_EMAIL_HTTP_BATCH_SIZE must be between 1 and 3")

    if environment == "production":
        if config.get("BROWSER_COOKIE_SECURE") is not True:
            problems.append("Production requires BROWSER_COOKIE_SECURE=true")
        secret_key = config.get("SECRET_KEY")
        token_pepper = config.get("ACCOUNT_TOKEN_PEPPER")
        rate_key = config.get("RATE_LIMIT_KEY_SECRET")
        if not isinstance(secret_key, str) or len(secret_key.strip()) < 32:
            problems.append("Production requires a stable high-entropy SECRET_KEY")
        if (
            not isinstance(token_pepper, str)
            or len(token_pepper.strip()) < 32
            or token_pepper == secret_key
        ):
            problems.append(
                "Production requires a distinct high-entropy ACCOUNT_TOKEN_PEPPER"
            )
        if (
            not isinstance(rate_key, str)
            or len(rate_key.strip()) < 32
            or rate_key in (secret_key, token_pepper)
        ):
            problems.append(
                "Production requires a distinct high-entropy RATE_LIMIT_KEY_SECRET"
            )
        try:
            public_url = urlsplit(str(config.get("PUBLIC_BASE_URL", "")))
            valid_origin = (
                public_url.scheme == "https"
                and public_url.hostname
                and public_url.username is None
                and public_url.password is None
                and public_url.path in {"", "/"}
                and not public_url.query
                and not public_url.fragment
                and public_url.port != 0
            )
        except ValueError:
            valid_origin = False
        if not valid_origin:
            problems.append("Production requires PUBLIC_BASE_URL to be an HTTPS origin")
        else:
            config["TRUSTED_HOSTS"] = [public_url.hostname]
        if mail_backend != "smtp" or not str(config.get("SMTP_HOST") or "").strip():
            problems.append(
                "Production requires a configured SMTP mail backend (SMTP_HOST)"
            )
        if not (
            bool(config.get("SMTP_USE_SSL")) ^ bool(config.get("SMTP_USE_STARTTLS"))
        ):
            problems.append("Production SMTP requires exactly one encrypted TLS mode")
        if config.get("SECURITY_EMAIL_INLINE_DELIVERY") is not False:
            problems.append("Production requires SECURITY_EMAIL_INLINE_DELIVERY=false")
        if (
            int(config["SECURITY_EMAIL_LEASE_SECONDS"])
            < int(config["SMTP_TIMEOUT_SECONDS"]) * 10
        ):
            problems.append(
                "SECURITY_EMAIL_LEASE_SECONDS must be at least ten times "
                "SMTP_TIMEOUT_SECONDS in production"
            )
        if float(config["PASSWORD_RESET_MINIMUM_RESPONSE_SECONDS"]) < 0.25:
            problems.append(
                "Production requires PASSWORD_RESET_MINIMUM_RESPONSE_SECONDS "
                "to be at least 0.25"
            )

    try:
        validate_password_policy_configuration(app)
    except PasswordPolicyConfigurationError:
        # The original exception can contain an operator-supplied path. Logs
        # should list only the setting and its requirements, never its value.
        problems.append(
            "Production requires PASSWORD_BLOCKLIST_PATH to name a readable "
            "file containing at least 10,000 unique SHA-256 password digests"
        )
    try:
        validate_rate_limit_configuration(app)
    except RuntimeError as exc:
        problems.append(str(exc))

    if os.getenv("VERCEL") == "1":
        if environment != "production":
            problems.append(
                "Vercel requires APP_ENV=production; development/test is unsafe"
            )
        try:
            database = make_url(config.get("SQLALCHEMY_DATABASE_URI") or "")
            remote_postgres = (
                database.get_backend_name() == "postgresql" and database.host
            )
        except (ArgumentError, ValueError):
            remote_postgres = False
        if not remote_postgres:
            problems.append(
                "Vercel requires DATABASE_URL for an external PostgreSQL database"
            )
        if storage_backend != "vercel_blob":
            problems.append(
                "Vercel requires FILE_STORAGE_BACKEND=vercel_blob; "
                "UPLOAD_FOLDER and /tmp cannot persist private uploads"
            )
        if not cron_secret:
            problems.append(
                "Vercel requires CRON_SECRET for the authenticated email-worker endpoint"
            )
        if config["SECURITY_EMAIL_HTTP_BATCH_SIZE"] != 1:
            problems.append("Vercel requires SECURITY_EMAIL_HTTP_BATCH_SIZE=1")
        if config["SMTP_TIMEOUT_SECONDS"] > 10:
            problems.append("Vercel requires SMTP_TIMEOUT_SECONDS to be at most 10")
        if not 128 * 1024 <= config["MAX_CONTENT_LENGTH"] <= 4 * 1024 * 1024:
            problems.append(
                "Vercel requires MAX_CONTENT_LENGTH between 131072 and 4194304"
            )
        if not isinstance(config.get("MAX_FILE_SIZE"), int) or not (
            0 < config["MAX_FILE_SIZE"] <= config["MAX_CONTENT_LENGTH"] - 64 * 1024
        ):
            problems.append(
                "Vercel requires MAX_FILE_SIZE below the multipart request limit"
            )

    if problems:
        raise DeploymentConfigurationError(problems)
