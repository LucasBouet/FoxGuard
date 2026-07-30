"""Network zones and their routed networks.

Revision ID: 0005_zones
Revises: 0004_dns
Create Date: Phase 5

A zone is a row in ``groups`` with ``kind = 'zone'`` -- the column was reserved
for this in ``0001`` precisely so it would not need a table rewrite. What is new
is what a zone *means* compared to a group:

* **A peer belongs to at most one zone** (``peers.zone_id``), while it may hold
  any number of groups. A zone is where a device sits; a group is what it does.
  Membership through ``peer_groups`` would make "this zone's routes" ambiguous
  the moment a peer was in two of them.
* **A zone owns routes** (``zone_routes``), so its address space is larger than
  the set of its members.

ACL endpoints reuse ``src_group_id`` / ``dst_group_id``: a zone *is* a groups
row, so the foreign key already points at the right table and ``src_kind``
disambiguates. The CHECK constraints are widened accordingly -- without that, a
``zone`` endpoint would be allowed to carry no reference at all.

``peers.zone_id`` is ON DELETE SET NULL and ``zone_routes.via_peer_id`` is ON
DELETE CASCADE, both chosen so that deleting something narrows access rather
than widening it: a peer whose zone is gone belongs to no zone, and a route
whose routing peer is gone stops being advertised.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0005_zones"
down_revision = "0004_dns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # A new enum value cannot be *used* in the transaction that added it, and
    # the CHECK constraints below reference 'zone'. Alembic wraps the migration
    # in one transaction, so the value is added between two explicit commits:
    # the first ends alembic's transaction, the second ends the one ALTER TYPE
    # opens. Measured -- with only the first commit, PostgreSQL rejects the
    # CHECK and rolls the whole thing back, leaving the enum unchanged.
    op.execute("COMMIT")
    op.execute("ALTER TYPE endpoint_kind ADD VALUE IF NOT EXISTS 'zone'")
    op.execute("COMMIT")

    op.add_column(
        "groups",
        sa.Column(
            "intra_zone", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column(
        "peers",
        sa.Column(
            "zone_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_peers_zone", "peers", ["zone_id"])

    op.create_table(
        "zone_routes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "zone_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cidr", sa.String(length=64), nullable=False),
        # NULL means the gateway reaches this network by itself (a LAN behind
        # it). Non-NULL means the traffic is carried by that peer.
        sa.Column(
            "via_peer_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("peers.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "extra", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("zone_id", "cidr", name="uq_zone_routes_zone_cidr"),
    )
    op.create_index("ix_zone_routes_zone", "zone_routes", ["zone_id"])

    for side in ("src", "dst"):
        op.drop_constraint(f"ck_acl_{side}_consistent", "acl_rules", type_="check")
        op.create_check_constraint(
            f"ck_acl_{side}_consistent",
            "acl_rules",
            f"({side}_kind NOT IN ('group', 'zone') OR {side}_group_id IS NOT NULL) AND "
            f"({side}_kind <> 'cidr' OR {side}_cidr IS NOT NULL)",
        )


def downgrade() -> None:
    for side in ("src", "dst"):
        op.drop_constraint(f"ck_acl_{side}_consistent", "acl_rules", type_="check")
        op.create_check_constraint(
            f"ck_acl_{side}_consistent",
            "acl_rules",
            f"({side}_kind <> 'group' OR {side}_group_id IS NOT NULL) AND "
            f"({side}_kind <> 'cidr' OR {side}_cidr IS NOT NULL)",
        )

    op.drop_index("ix_zone_routes_zone", table_name="zone_routes")
    op.drop_table("zone_routes")
    op.drop_index("ix_peers_zone", table_name="peers")
    op.drop_column("peers", "zone_id")
    op.drop_column("groups", "intra_zone")
    # The 'zone' enum value is deliberately left in place: PostgreSQL cannot
    # drop a value from an enum, and recreating the type would mean rewriting
    # every acl_rules row. A spare value nothing references is harmless.
