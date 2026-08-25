"""Migration bootstrap, legacy adoption, and drift-rejection tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import sqlalchemy as sa
from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
from flask_migrate import upgrade

from app import create_app
from app.database import (
    ALEMBIC_VERSION_TABLE,
    BASELINE_METADATA,
    BASELINE_REVISION,
    MIGRATIONS_DIRECTORY,
    _matches_legacy_baseline,
)
from app.extensions import db


def _create_migration_app(tmp_path: Path):
    return create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "migration-test-only-secret",  # pragma: allowlist secret
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'migration.db'}",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
        }
    )


def _head_revision() -> str:
    config = AlembicConfig(str(MIGRATIONS_DIRECTORY / "alembic.ini"))
    config.set_main_option("script_location", str(MIGRATIONS_DIRECTORY))
    head = ScriptDirectory.from_config(config).get_current_head()
    assert head is not None
    return head


def _database_revision() -> str:
    return db.session.execute(
        sa.text("SELECT version_num FROM alembic_version")
    ).scalar_one()


def test_baseline_revision_matches_the_frozen_legacy_schema(tmp_path):
    app = _create_migration_app(tmp_path)

    with app.app_context():
        upgrade(
            directory=str(MIGRATIONS_DIRECTORY), revision=BASELINE_REVISION
        )
        with db.engine.connect() as connection:
            assert _matches_legacy_baseline(connection)
        assert _database_revision() == BASELINE_REVISION


def test_init_db_migrates_a_fresh_database_to_head(tmp_path):
    app = _create_migration_app(tmp_path)

    result = app.test_cli_runner().invoke(args=["init-db"])

    assert result.exit_code == 0, result.output
    assert "initialized" in result.output.lower()
    with app.app_context():
        table_names = set(sa.inspect(db.engine).get_table_names())
        assert table_names == set(db.metadata.tables) | {ALEMBIC_VERSION_TABLE}
        assert _database_revision() == _head_revision()


def test_init_db_adopts_exact_legacy_schema_without_losing_data(tmp_path):
    app = _create_migration_app(tmp_path)

    with app.app_context():
        BASELINE_METADATA.create_all(db.engine)
        with db.engine.begin() as connection:
            connection.execute(
                BASELINE_METADATA.tables["users"].insert().values(
                    id=41,
                    username="legacy-user",
                    email="legacy@example.com",
                    password_hash="legacy-scrypt-hash",  # pragma: allowlist secret
                    created_at=datetime.now(timezone.utc),
                )
            )

    result = app.test_cli_runner().invoke(args=["init-db"])

    assert result.exit_code == 0, result.output
    assert "validated" in result.output.lower()
    with app.app_context():
        from app.models.user import User

        preserved = db.session.execute(
            sa.select(BASELINE_METADATA.tables["users"].c.username).where(
                BASELINE_METADATA.tables["users"].c.id == 41
            )
        ).scalar_one()
        assert preserved == "legacy-user"
        legacy_user = db.session.get(User, 41)
        assert legacy_user is not None
        assert legacy_user.email_verified_at is None
        assert legacy_user.password_changed_at == legacy_user.created_at
        assert legacy_user.to_dict()["email_verified"] is False
        assert _database_revision() == _head_revision()


def test_init_db_rejects_unknown_unversioned_schema_without_stamping(tmp_path):
    app = _create_migration_app(tmp_path)

    with app.app_context():
        BASELINE_METADATA.create_all(db.engine)
        with db.engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE users ADD COLUMN unexpected_data TEXT"
            )

    result = app.test_cli_runner().invoke(args=["init-db"])

    assert result.exit_code != 0
    assert "does not match" in result.output.lower()
    with app.app_context():
        assert ALEMBIC_VERSION_TABLE not in sa.inspect(db.engine).get_table_names()
        assert "unexpected_data" in {
            item["name"] for item in sa.inspect(db.engine).get_columns("users")
        }


def test_init_db_is_idempotent_after_migration_tracking_exists(tmp_path):
    app = _create_migration_app(tmp_path)
    runner = app.test_cli_runner()

    first = runner.invoke(args=["init-db"])
    second = runner.invoke(args=["init-db"])

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert "migrations applied" in second.output.lower()
    with app.app_context():
        assert _database_revision() == _head_revision()
