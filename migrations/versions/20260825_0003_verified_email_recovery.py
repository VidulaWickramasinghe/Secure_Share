"""Add verified email state and protected account-action tokens.

Revision ID: 20260825_0003
Revises: 20260825_0002
Create Date: 2026-08-25
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "20260825_0003"
down_revision: str | None = "20260825_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing addresses were never proven, so they intentionally remain
    # unverified. Existing FilePermission rows continue to grant access, while
    # service-layer creation of any new grant requires verification.
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True)
        )

    op.execute(
        sa.text(
            "UPDATE users SET password_changed_at = created_at"
        )
    )
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "password_changed_at",
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
        )

    op.create_table(
        "account_action_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("target_email", sa.String(length=254), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("invalidated_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "purpose IN ('email_verification', 'password_reset')",
            name="ck_account_action_tokens_purpose",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_account_action_tokens_expires_at",
        "account_action_tokens",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_account_action_tokens_token_hash",
        "account_action_tokens",
        ["token_hash"],
        unique=True,
    )
    op.create_index(
        "ix_account_action_tokens_user_id",
        "account_action_tokens",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_account_action_tokens_user_purpose_state",
        "account_action_tokens",
        [
            "user_id",
            "purpose",
            "consumed_at",
            "invalidated_at",
            "expires_at",
        ],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_account_action_tokens_user_purpose_state",
        table_name="account_action_tokens",
    )
    op.drop_index(
        "ix_account_action_tokens_user_id", table_name="account_action_tokens"
    )
    op.drop_index(
        "ix_account_action_tokens_token_hash", table_name="account_action_tokens"
    )
    op.drop_index(
        "ix_account_action_tokens_expires_at", table_name="account_action_tokens"
    )
    op.drop_table("account_action_tokens")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("password_changed_at")
        batch_op.drop_column("email_verified_at")
