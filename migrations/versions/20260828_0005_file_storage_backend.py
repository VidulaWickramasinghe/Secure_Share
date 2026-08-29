"""Record the storage backend without relocating existing private files.

Revision ID: 20260828_0005
Revises: 20260825_0004
"""

import sqlalchemy as sa
from alembic import op

revision = "20260828_0005"
down_revision = "20260825_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "files",
        sa.Column(
            "storage_backend",
            sa.String(16),
            nullable=False,
            server_default="filesystem",
        ),
    )


def downgrade() -> None:
    with op.batch_alter_table("files") as batch:
        batch.drop_column("storage_backend")
