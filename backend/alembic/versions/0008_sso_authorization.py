"""Being signed in stops being the same thing as being allowed in.

Revision ID: 0008_sso_authorization
Revises: 0007_sso
Create Date: Phase 7d

Two association tables and one flag.

``user_groups`` puts people in the *same* ``groups`` table the peers use. A
group is a set of principals; splitting humans into a parallel taxonomy is how
an access model ends up with two answers to "who is in infra". It grants no
network access -- the nftables generator reads ``peer_groups`` and only that --
so this migration cannot change a single firewall rule. Worth stating plainly,
because a table called ``user_groups`` in a VPN's schema looks like it should.

``service_auth_groups`` records which of those groups an SSO authenticator
demands. A table rather than slugs in ``service_auth.config``, so that deleting
a group withdraws the requirement instead of leaving a string that a later
unrelated group with the same slug would satisfy.

``service_auth.require_admin`` defaults false, and every existing row keeps the
behaviour it had: no groups required and no admin flag means any account that
can sign in, which is exactly what SSO did before this. Nothing that works today
starts denying after this upgrade.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0008_sso_authorization"
down_revision = "0007_sso"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_groups",
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_user_groups_group", "user_groups", ["group_id"])

    op.add_column(
        "service_auth",
        sa.Column(
            "require_admin",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

    op.create_table(
        "service_auth_groups",
        sa.Column(
            "auth_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("service_auth.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    op.create_index(
        "ix_service_auth_groups_group", "service_auth_groups", ["group_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_service_auth_groups_group", table_name="service_auth_groups")
    op.drop_table("service_auth_groups")
    op.drop_column("service_auth", "require_admin")
    op.drop_index("ix_user_groups_group", table_name="user_groups")
    op.drop_table("user_groups")
