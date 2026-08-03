"""Browser sessions for people reaching a published service.

Revision ID: 0007_sso
Revises: 0006_proxy
Create Date: Phase 7c

One table, no enums, no changes to anything existing.

``sso_sessions.id`` doubles as the JWT's ``jti``. That is the whole point of the
design: the cookie is a signed token the proxy verifies on its own, so this row
is never consulted on the request path -- it exists so an administrator can see
who is signed in, and so revoking a session can push one identifier into a
HAProxy map and have it take effect immediately rather than whenever the token
would have expired.

Deliberately not a reuse of ``admin_sessions``: that table's tokens open the
admin API, and a cookie handed out for reaching an internal web app must not be
mistakable for one.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0007_sso"
down_revision = "0006_proxy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sso_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_ip", postgresql.INET()),
        sa.Column("user_agent", sa.String(255)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_sso_sessions_user", "sso_sessions", ["user_id"])
    op.create_index("ix_sso_sessions_expires", "sso_sessions", ["expires_at"])


def downgrade() -> None:
    op.drop_table("sso_sessions")
