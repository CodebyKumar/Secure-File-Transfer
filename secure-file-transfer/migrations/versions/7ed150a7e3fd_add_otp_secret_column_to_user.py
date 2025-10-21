"""Add otp_secret column to User

Revision ID: 7ed150a7e3fd
Revises: 448cca10ec5f
Create Date: 2025-10-21 19:16:45.175324

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7ed150a7e3fd"
down_revision: Union[str, Sequence[str], None] = "448cca10ec5f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("users", sa.Column("otp_secret", sa.String(length=32), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("users", "otp_secret")
