"""Flask extension instances and database connection safeguards.

Extensions are created without an application so the application-factory
pattern remains straightforward and tests can create isolated app instances.
"""

import sqlite3

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base shared by all database models."""


db = SQLAlchemy(model_class=Base)


@event.listens_for(Engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
    """Make SQLite enforce the same foreign-key cascades as PostgreSQL."""

    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
