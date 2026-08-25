"""Flask extension instances and database connection safeguards.

Extensions are created without an application so the application-factory
pattern remains straightforward and tests can create isolated app instances.
"""

import sqlite3

from flask_limiter import Limiter
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base shared by all database models."""


db = SQLAlchemy(model_class=Base)
migrate = Migrate()


def _default_rate_limit_key() -> str:
    """Resolve the default key lazily to avoid extension import cycles."""

    from app.rate_limits import remote_address_rate_key

    return remote_address_rate_key()


limiter = Limiter(
    key_func=_default_rate_limit_key,
    default_limits=[],
    headers_enabled=True,
    strategy="fixed-window",
    swallow_errors=False,
    fail_on_first_breach=False,
    in_memory_fallback_enabled=False,
    retry_after="delta-seconds",
)


@event.listens_for(Engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
    """Make SQLite enforce the same foreign-key cascades as PostgreSQL."""

    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
