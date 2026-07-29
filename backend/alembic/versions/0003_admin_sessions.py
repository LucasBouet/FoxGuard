"""Admin sessions.

Revision ID: 0003_admin_sessions
Revises: 0002_totp_replay
Create Date: Phase 4

Until now the admin API was a single shared bearer token, so every entry in
``audit_log`` said ``admin-api`` -- including the kill switch. This table backs
real sign-in, so an action can name the person who took it.

Only the token's hash is stored. The static token remains valid for automation
and is recorded as a distinct actor.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0003_admin_sessions"
down_revision = "0002_totp_replay"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
    )
    op.create_index("ix_admin_sessions_user", "admin_sessions", ["user_id"])
    op.create_index("ix_admin_sessions_token", "admin_sessions", ["token_hash"])


def downgrade() -> None:
    op.drop_index("ix_admin_sessions_token", table_name="admin_sessions")
    op.drop_index("ix_admin_sessions_user", table_name="admin_sessions")
    op.drop_table("admin_sessions")
