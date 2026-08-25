"""Alembic environment integrated with the Flask application factory."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from flask import current_app
from sqlalchemy.engine import Connection


config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _database_extension():
    return current_app.extensions["migrate"]


def _database_url() -> str:
    # Alembic treats percent signs as interpolation markers in configuration.
    return str(_database_extension().db.engine.url).replace("%", "%%")


def _target_metadata():
    return _database_extension().db.metadata


def _set_sqlite_foreign_keys(connection: Connection, *, enabled: bool) -> bool:
    """Temporarily control SQLite FK actions during batch table rebuilds.

    Alembic's SQLite batch mode recreates tables. Dropping the old parent
    table while foreign-key actions are active can cascade-delete rows from
    child tables. PostgreSQL and other production databases are unaffected.
    """

    if connection.dialect.name != "sqlite":
        return False

    statement = "PRAGMA foreign_keys=ON" if enabled else "PRAGMA foreign_keys=OFF"
    connection.exec_driver_sql(statement)
    actual = connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one()
    if bool(actual) is not enabled:
        state = "enable" if enabled else "disable"
        raise RuntimeError(
            f"Could not {state} SQLite foreign-key enforcement for migrations."
        )
    return True


def _assert_sqlite_foreign_key_integrity(connection: Connection) -> None:
    """Fail a migration command if SQLite contains broken references."""

    if connection.dialect.name != "sqlite":
        return
    violation = connection.exec_driver_sql("PRAGMA foreign_key_check").first()
    if violation is not None:
        raise RuntimeError(
            "Database migration produced or retained foreign-key violations."
        )


def run_migrations_offline() -> None:
    """Run migration SQL generation without opening a database connection."""

    context.configure(
        url=_database_url(),
        target_metadata=_target_metadata(),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations using the application's configured SQLAlchemy engine."""

    extension = _database_extension()
    configure_args = dict(extension.configure_args)
    with extension.db.engine.connect() as connection:
        sqlite_foreign_keys_changed = _set_sqlite_foreign_keys(
            connection, enabled=False
        )
        migrations_succeeded = False
        try:
            context.configure(
                connection=connection,
                target_metadata=extension.db.metadata,
                **configure_args,
            )
            with context.begin_transaction():
                context.run_migrations()
            _assert_sqlite_foreign_key_integrity(connection)
            migrations_succeeded = True
        finally:
            if sqlite_foreign_keys_changed:
                # SQLite ignores attempts to change this PRAGMA inside a
                # transaction. Finish any SQLAlchemy autobegin transaction
                # before restoring enforcement on the pooled connection.
                if connection.in_transaction():
                    if migrations_succeeded:
                        connection.commit()
                    else:
                        connection.rollback()
                _set_sqlite_foreign_keys(connection, enabled=True)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
