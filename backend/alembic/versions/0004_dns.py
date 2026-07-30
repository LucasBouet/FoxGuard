"""Internal DNS: peer names and hand-authored records.

Revision ID: 0004_dns
Revises: 0003_admin_sessions
Create Date: Phase 5

``peers.dns_label`` is materialised rather than derived at render time. Deriving
it would push collisions ("Laptop" and "laptop" both want ``laptop``) all the way
out to the resolver, where the only available answers are "refuse to render the
whole zone" or "pick one silently". Storing it means the conflict surfaces as a
409 on the request that caused it, and an administrator can override it.

The unique index is on ``lower(dns_label)`` because DNS is case-insensitive: two
labels differing only in case are the same name, and the column would otherwise
happily hold both. NULL is allowed and does not conflict with anything, so a
peer can have no name at all.
"""

from __future__ import annotations

import re
import unicodedata

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0004_dns"
down_revision = "0003_admin_sessions"
branch_labels = None
depends_on = None

_NON_LABEL = re.compile(r"[^a-z0-9]+")


def _derive(name: str) -> str | None:
    """Same rule as ``foxguard.dns.naming.derive_label``.

    Duplicated on purpose: a migration must keep producing the values it
    produced on the day it ran, and importing application code would let a later
    refactor rewrite history for anyone who migrates afterwards.
    """
    folded = unicodedata.normalize("NFKD", name)
    ascii_only = folded.encode("ascii", "ignore").decode("ascii").lower()
    label = _NON_LABEL.sub("-", ascii_only).strip("-")[:63].rstrip("-")
    return label or None


def upgrade() -> None:
    op.add_column("peers", sa.Column("dns_label", sa.String(length=63), nullable=True))

    # Backfill. Existing peers were named without any awareness of DNS, so
    # collisions are expected; they are numbered here rather than left NULL,
    # because a fleet that upgrades into a half-named zone is harder to reason
    # about than one where every device has a name it can be renamed away from.
    bind = op.get_bind()
    rows = bind.execute(
        sa.text("SELECT id, name FROM peers ORDER BY created_at, id")
    ).fetchall()
    taken: set[str] = set()
    for peer_id, name in rows:
        base = _derive(name or "") or f"peer-{str(peer_id).replace('-', '')[:12]}"
        label, suffix = base, 1
        while label in taken:
            suffix += 1
            label = f"{base[: 63 - len(str(suffix)) - 1]}-{suffix}"
        taken.add(label)
        bind.execute(
            sa.text("UPDATE peers SET dns_label = :label WHERE id = :id"),
            {"label": label, "id": peer_id},
        )

    op.create_index(
        "uq_peers_dns_label",
        "peers",
        [sa.text("lower(dns_label)")],
        unique=True,
    )

    dns_record_kind = postgresql.ENUM(
        "A", "AAAA", "CNAME", name="dns_record_kind", create_type=False
    )
    dns_record_kind.create(bind, checkfirst=True)

    op.create_table(
        "dns_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        # Relative to the configured zone, so renaming the zone does not orphan
        # every record. May carry dots: "git.services" is a legal sub-label.
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("kind", dns_record_kind, nullable=False),
        # An address for A/AAAA, another record's relative name for CNAME.
        sa.Column("value", sa.String(length=253), nullable=False),
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
    )
    op.create_index(
        "uq_dns_records_name", "dns_records", [sa.text("lower(name)")], unique=True
    )


def downgrade() -> None:
    op.drop_index("uq_dns_records_name", table_name="dns_records")
    op.drop_table("dns_records")
    postgresql.ENUM(name="dns_record_kind").drop(op.get_bind(), checkfirst=True)
    op.drop_index("uq_peers_dns_label", table_name="peers")
    op.drop_column("peers", "dns_label")
