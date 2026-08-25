"""Database migration bootstrap and legacy-schema adoption safeguards."""

from __future__ import annotations

import re
from pathlib import Path

import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask_migrate import stamp, upgrade

from app.extensions import db


MIGRATIONS_DIRECTORY = Path(__file__).resolve().parent.parent / "migrations"
BASELINE_REVISION = "20260825_0001"
ALEMBIC_VERSION_TABLE = "alembic_version"


class LegacySchemaMismatch(RuntimeError):
    """Raised when an unversioned database is not the known legacy schema."""


def _build_baseline_metadata() -> sa.MetaData:
    """Describe the exact schema shipped before migrations were introduced.

    This intentionally remains independent of the live ORM metadata. Future
    model changes must not cause an old, valid database to be mistaken for an
    unknown schema before Alembic has a chance to apply later revisions.
    """

    metadata = sa.MetaData()
    users = sa.Table(
        "users",
        metadata,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=80), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    sa.Index("ix_users_username", users.c.username, unique=True)
    sa.Index("ix_users_email", users.c.email, unique=True)
    sa.Index("ix_users_created_at", users.c.created_at)

    auth_sessions = sa.Table(
        "auth_sessions",
        metadata,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    sa.Index("ix_auth_sessions_user_id", auth_sessions.c.user_id)
    sa.Index(
        "ix_auth_sessions_token_hash", auth_sessions.c.token_hash, unique=True
    )
    sa.Index("ix_auth_sessions_expires_at", auth_sessions.c.expires_at)
    sa.Index(
        "ix_auth_sessions_user_expires",
        auth_sessions.c.user_id,
        auth_sessions.c.expires_at,
    )

    files = sa.Table(
        "files",
        metadata,
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("stored_filename", sa.String(length=64), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "file_size >= 0", name="ck_files_file_size_nonnegative"
        ),
        sa.ForeignKeyConstraint(
            ["owner_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    sa.Index("ix_files_stored_filename", files.c.stored_filename, unique=True)
    sa.Index("ix_files_owner_created_at", files.c.owner_id, files.c.created_at)

    file_permissions = sa.Table(
        "file_permissions",
        metadata,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("file_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["file_id"], ["files.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "file_id", "user_id", name="uq_file_permissions_file_user"
        ),
    )
    sa.Index(
        "ix_file_permissions_user_file",
        file_permissions.c.user_id,
        file_permissions.c.file_id,
    )
    return metadata


BASELINE_METADATA = _build_baseline_metadata()


def _normalize_check_expression(value: object) -> str:
    """Normalize harmless quoting/whitespace differences in reflected checks."""

    expression = str(value if value is not None else "").lower().replace('"', "")
    expression = re.sub(r"\s+", "", expression)
    while expression.startswith("(") and expression.endswith(")"):
        expression = expression[1:-1]
    return expression


def _check_constraints_match(connection: sa.Connection) -> bool:
    """Supplement Alembic comparison, which does not compare every check."""

    inspector = sa.inspect(connection)
    for table in BASELINE_METADATA.sorted_tables:
        expected = {
            constraint.name: _normalize_check_expression(constraint.sqltext)
            for constraint in table.constraints
            if isinstance(constraint, sa.CheckConstraint)
        }
        reflected = {
            item.get("name"): _normalize_check_expression(item.get("sqltext"))
            for item in inspector.get_check_constraints(table.name)
        }
        if expected != reflected:
            return False
    return True


def _matches_legacy_baseline(connection: sa.Connection) -> bool:
    """Return whether an unversioned database is exactly the known baseline."""

    context = MigrationContext.configure(
        connection,
        opts={
            "compare_type": True,
            "compare_server_default": True,
            "target_metadata": BASELINE_METADATA,
        },
    )
    return not compare_metadata(context, BASELINE_METADATA) and (
        _check_constraints_match(connection)
    )


def initialize_database() -> str:
    """Upgrade a database, safely adopting the pre-migration schema if needed.

    Returns ``fresh``, ``adopted``, or ``upgraded`` for operator-facing CLI
    output. An unknown unversioned schema is never stamped or modified.
    """

    with db.engine.connect() as connection:
        table_names = set(sa.inspect(connection).get_table_names())
        if ALEMBIC_VERSION_TABLE in table_names:
            state = "upgraded"
        elif not table_names:
            state = "fresh"
        elif _matches_legacy_baseline(connection):
            state = "adopted"
        else:
            raise LegacySchemaMismatch(
                "The database has an unversioned schema that does not match "
                "the supported Secure Share baseline. Back it up and reconcile "
                "the schema before running init-db again."
            )

    directory = str(MIGRATIONS_DIRECTORY)
    if state == "adopted":
        stamp(directory=directory, revision=BASELINE_REVISION)
    upgrade(directory=directory, revision="head")
    return state
