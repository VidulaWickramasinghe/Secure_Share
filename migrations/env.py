"""Alembic environment integrated with the Flask application factory."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from flask import current_app


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
        context.configure(
            connection=connection,
            target_metadata=extension.db.metadata,
            **configure_args,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
