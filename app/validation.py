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
        # This repository currently stores uploaded bytes on the filesystem.
        # Vercel's /tmp is ephemeral, not a persistent storage backend. Refuse
        # to advertise successful uploads that disappear on a later request.
        problems.append(
            "Vercel cannot persist the current UPLOAD_FOLDER filesystem backend. "
            "Implement private object storage, or host the backend on a server "
            "with a private persistent volume; /tmp is not a production fix"
        )
        problems.append(
            "Production needs a separately hosted email-worker process; "
            "Vercel does not run this repository's persistent worker"
        )

    if problems:
        raise DeploymentConfigurationError(problems)
