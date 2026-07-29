"""TOTP replay guard.

Revision ID: 0002_totp_replay
Revises: 0001_initial
Create Date: Phase 2

Adds ``users.totp_last_used_step``: the highest TOTP time step a user has
already spent. Without it a code stays usable for the whole skew window (~90s),
which RFC 6238 §5.2 explicitly forbids -- a code observed once could be replayed
before it expired.

Nullable with no default: NULL means "no code has been used yet", which is the
correct starting point for both existing and new accounts.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0002_totp_replay"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users", sa.Column("totp_last_used_step", sa.BigInteger(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("users", "totp_last_used_step")
