"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def _positive_int_from_env(name: str, default: int) -> int:
    """Read a positive integer without silently accepting unsafe values."""

    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc

    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
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


class Config:
    """Default configuration suitable for local development.

    Production deployments must set ``SECRET_KEY`` and ``DATABASE_URL`` in the
    environment. Authentication tokens are random opaque values and are not
    encoded with ``SECRET_KEY``, but Flask and extensions may still use it.
    """

    # An ephemeral fallback is safe for local startup and avoids shipping a
    # shared predictable secret. Production must provide a stable SECRET_KEY.
    SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", str(PROJECT_ROOT / "storage"))
    MAX_CONTENT_LENGTH = _positive_int_from_env(
        "MAX_CONTENT_LENGTH", 16 * 1024 * 1024
    )
    SESSION_LIFETIME_SECONDS = _positive_int_from_env(
        "SESSION_LIFETIME_SECONDS", 24 * 60 * 60
    )

    JSON_SORT_KEYS = False
