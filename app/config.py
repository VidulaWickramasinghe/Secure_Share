"""Application configuration loaded from environment variables."""

from __future__ import annotations

import math
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def _positive_int_from_env(name: str, default: int) -> int:
    """Read a positive integer without silently accepting unsafe values."""

    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default

    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc

    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


def _boolean_from_env(name: str, default: bool) -> bool:
    """Read an explicit boolean without treating arbitrary text as false."""

    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default

    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _nonnegative_float_from_env(name: str, default: float) -> float:
    """Read a finite, non-negative duration."""

    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        value = float(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be a finite non-negative number")
    return value


def _application_environment() -> str:
    # Empty dashboard entries are unset settings. A hosted deployment must
    # still default to production validation, never development safeguards.
    default = "production" if os.getenv("VERCEL") == "1" else "development"
    value = (os.getenv("APP_ENV") or "").strip().lower() or default
    if value not in {"development", "test", "production"}:
        raise ValueError("APP_ENV must be development, test, or production")
    return value


def _database_url() -> str:
    configured_url = os.getenv("DATABASE_URL")
    if configured_url:
        # Some platforms still provide the retired postgres:// alias. Select
        # psycopg v3 explicitly; a bare postgresql:// URL otherwise defaults to
        # the separately packaged psycopg2 driver.
        if configured_url.startswith("postgres://"):
            return configured_url.replace(
                "postgres://", "postgresql+psycopg://", 1
            )
        if configured_url.startswith("postgresql://"):
            return configured_url.replace(
                "postgresql://", "postgresql+psycopg://", 1
            )
        return configured_url

    database_path = PROJECT_ROOT / "instance" / "secure_share.db"
    return f"sqlite:///{database_path}"


APPLICATION_ENVIRONMENT = _application_environment()


class Config:
    """Default configuration suitable for local development.

    Production deployments must set ``SECRET_KEY`` and ``DATABASE_URL`` in the
    environment. Authentication tokens are random opaque values and are not
    encoded with ``SECRET_KEY``, but Flask and extensions may still use it.
    """

    # An ephemeral fallback is safe for local startup and avoids shipping a
    # shared predictable secret. Production must provide a stable SECRET_KEY.
    SECRET_KEY = os.getenv("SECRET_KEY") or (
        None if APPLICATION_ENVIRONMENT == "production" else secrets.token_hex(32)
    )
    APP_ENV = APPLICATION_ENVIRONMENT
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "").strip() or str(
        PROJECT_ROOT / "storage"
    )
    MAX_CONTENT_LENGTH = _positive_int_from_env(
        "MAX_CONTENT_LENGTH", 16 * 1024 * 1024
    )
    SESSION_LIFETIME_SECONDS = _positive_int_from_env(
        "SESSION_LIFETIME_SECONDS", 24 * 60 * 60
    )
    # Browser sessions use application-owned cookies rather than Flask's signed
    # client-side session. Production forces Secure on; the documented local
    # development environment uses HTTP and therefore disables it explicitly.
    BROWSER_SESSION_COOKIE_NAME = "secure_share_session"
    BROWSER_CSRF_COOKIE_NAME = "secure_share_csrf"
    BROWSER_COOKIE_SECURE = _boolean_from_env(
        "BROWSER_COOKIE_SECURE", APPLICATION_ENVIRONMENT == "production"
    )
    BROWSER_COOKIE_SAMESITE = "Lax"

    # Rate-limit counters are deliberately process-local only in development
    # and tests. Production validation in app.rate_limits requires Redis and a
    # stable, independently generated HMAC key.
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI") or "memory://"
    RATE_LIMIT_KEY_SECRET = os.getenv("RATE_LIMIT_KEY_SECRET") or None
    RATELIMIT_KEY_PREFIX = os.getenv("RATELIMIT_KEY_PREFIX") or "secure-share"
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_HEADER_RETRY_AFTER_VALUE = "delta-seconds"
    RATELIMIT_SWALLOW_ERRORS = False
    RATELIMIT_IN_MEMORY_FALLBACK_ENABLED = False
    RATELIMIT_FAIL_ON_FIRST_BREACH = False

    # A broad per-IP limit covers every login, while the two failed-response
    # limits impose progressively longer finite delays without locking an
    # account in the database. Authenticated file limits use HMAC-protected
    # user, session, and resource buckets.
    LOGIN_IP_RATE_LIMIT = "60 per minute; 600 per hour"
    LOGIN_FAILURE_IP_RATE_LIMIT = "10 per minute; 50 per hour"
    LOGIN_FAILURE_CREDENTIAL_RATE_LIMIT = "5 per minute; 20 per hour"
    REGISTRATION_IP_RATE_LIMIT = "10 per minute; 50 per hour"
    ACCOUNT_ACTION_IP_RATE_LIMIT = "20 per minute; 100 per hour"
    EMAIL_VERIFICATION_REQUEST_RATE_LIMIT = "3 per 15 minutes; 10 per day"
    EMAIL_VERIFICATION_CONFIRM_RATE_LIMIT = "5 per minute; 20 per hour"
    PASSWORD_RESET_REQUEST_RATE_LIMIT = (  # nosec B105
        "5 per 15 minutes; 20 per day"
    )
    PASSWORD_RESET_CONFIRM_RATE_LIMIT = (  # nosec B105
        "5 per minute; 20 per hour"
    )
    UPLOAD_IP_RATE_LIMIT = "60 per minute; 500 per hour"
    UPLOAD_USER_RATE_LIMIT = "20 per minute; 200 per hour"
    UPLOAD_SESSION_RATE_LIMIT = "15 per minute; 150 per hour"
    DOWNLOAD_IP_RATE_LIMIT = "300 per minute; 5000 per hour"
    DOWNLOAD_USER_RATE_LIMIT = "120 per minute; 2000 per hour"
    DOWNLOAD_SESSION_RATE_LIMIT = "90 per minute; 1500 per hour"
    DOWNLOAD_RESOURCE_RATE_LIMIT = "30 per minute; 300 per hour"

    # The bundled whole-password blocklist is always active. Operators may
    # extend it with an ASCII file containing one SHA-256 hex digest per line.
    PASSWORD_BLOCKLIST_PATH = os.getenv("PASSWORD_BLOCKLIST_PATH") or None

    # Account-action links contain 256 bits of randomness. Only a
    # purpose-separated HMAC digest is retained in the database. A distinct,
    # stable pepper is mandatory in production; development falls back to the
    # application secret so a fresh checkout remains easy to run.
    ACCOUNT_TOKEN_PEPPER = os.getenv("ACCOUNT_TOKEN_PEPPER") or SECRET_KEY
    EMAIL_VERIFICATION_TOKEN_LIFETIME_SECONDS = _positive_int_from_env(
        "EMAIL_VERIFICATION_TOKEN_LIFETIME_SECONDS", 24 * 60 * 60
    )
    PASSWORD_RESET_TOKEN_LIFETIME_SECONDS = _positive_int_from_env(
        "PASSWORD_RESET_TOKEN_LIFETIME_SECONDS", 60 * 60
    )
    PASSWORD_RESET_MINIMUM_RESPONSE_SECONDS = _nonnegative_float_from_env(
        "PASSWORD_RESET_MINIMUM_RESPONSE_SECONDS", 0.5
    )

    # The file backend is intentionally development-only and writes private
    # RFC 5322 messages below instance/. Production validation requires SMTP.
    PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL") or "http://127.0.0.1:5000"
    MAIL_BACKEND = os.getenv("MAIL_BACKEND", "").strip().lower() or (
        "smtp" if APPLICATION_ENVIRONMENT == "production" else "file"
    )
    MAIL_FROM_ADDRESS = os.getenv("MAIL_FROM_ADDRESS") or "no-reply@secure-share.local"
    MAIL_FILE_OUTBOX = os.getenv("MAIL_FILE_OUTBOX", "").strip() or "mail-outbox"
    SMTP_HOST = os.getenv("SMTP_HOST") or None
    SMTP_PORT = _positive_int_from_env("SMTP_PORT", 587)
    SMTP_USERNAME = os.getenv("SMTP_USERNAME") or None
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD") or None
    SMTP_USE_SSL = _boolean_from_env("SMTP_USE_SSL", False)
    SMTP_USE_STARTTLS = _boolean_from_env("SMTP_USE_STARTTLS", True)
    SMTP_TIMEOUT_SECONDS = _positive_int_from_env("SMTP_TIMEOUT_SECONDS", 10)

    # Security mail is a durable database job. Local file/memory delivery can
    # run inline for a one-process developer experience; production must turn
    # this off and run the dedicated worker so SMTP latency cannot become an
    # account-enumeration side channel in authentication requests.
    SECURITY_EMAIL_INLINE_DELIVERY = _boolean_from_env(
        "SECURITY_EMAIL_INLINE_DELIVERY",
        APPLICATION_ENVIRONMENT != "production",
    )
    SECURITY_EMAIL_LEASE_SECONDS = _positive_int_from_env(
        "SECURITY_EMAIL_LEASE_SECONDS", 300
    )
    SECURITY_EMAIL_MAX_ATTEMPTS = _positive_int_from_env(
        "SECURITY_EMAIL_MAX_ATTEMPTS", 5
    )
    SECURITY_EMAIL_RETRY_BASE_SECONDS = _positive_int_from_env(
        "SECURITY_EMAIL_RETRY_BASE_SECONDS", 30
    )
    SECURITY_EMAIL_RETRY_MAX_SECONDS = _positive_int_from_env(
        "SECURITY_EMAIL_RETRY_MAX_SECONDS", 3600
    )
    SECURITY_EMAIL_WORKER_BATCH_SIZE = _positive_int_from_env(
        "SECURITY_EMAIL_WORKER_BATCH_SIZE", 100
    )
    SECURITY_EMAIL_WORKER_POLL_SECONDS = _positive_int_from_env(
        "SECURITY_EMAIL_WORKER_POLL_SECONDS", 2
    )

    JSON_SORT_KEYS = False
