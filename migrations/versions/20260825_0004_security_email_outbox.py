"""Add a secret-free durable security-email outbox.

Revision ID: 20260825_0004
Revises: 20260825_0003
Create Date: 2026-08-25
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "20260825_0004"
down_revision: str | None = "20260825_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "security_email_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "attempts",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "kind IN ('email_verification', 'password_reset', 'password_changed')",
            name="ck_security_email_jobs_kind",
        ),
        sa.CheckConstraint(
            "attempts >= 0",
            name="ck_security_email_jobs_attempts_nonnegative",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_security_email_jobs_pending_claim",
        "security_email_jobs",
        ["completed_at", "cancelled_at", "available_at", "lease_expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_security_email_jobs_user_kind_pending",
        "security_email_jobs",
        [
            "user_id",
            "kind",
            "completed_at",
            "cancelled_at",
            "lease_expires_at",
        ],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_security_email_jobs_user_kind_pending",
        table_name="security_email_jobs",
    )
    op.drop_index(
        "ix_security_email_jobs_pending_claim",
        table_name="security_email_jobs",
    )
    op.drop_table("security_email_jobs")
