"""Add session-bound CSRF digests for browser authentication.

Revision ID: 20260825_0002
Revises: 20260825_0001
Create Date: 2026-08-25
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "20260825_0002"
down_revision: str | None = "20260825_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing rows remain bearer-only. A non-null digest marks sessions that
    # may authenticate through the HttpOnly browser cookie transport.
    op.add_column(
        "auth_sessions",
        sa.Column("csrf_token_hash", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("auth_sessions", "csrf_token_hash")
