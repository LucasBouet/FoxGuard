"""Initial Foxguard schema.

Revision ID: 0001_initial
Revises:
Create Date: Phase 1

Enum types are created explicitly (``create_type=False`` on the columns)
because several of them are used by more than one column -- ``endpoint_kind``
appears twice in ``acl_rules`` alone -- and SQLAlchemy would otherwise emit
``CREATE TYPE`` more than once.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


peer_type = postgresql.ENUM("server", "user", name="peer_type", create_type=False)
peer_state = postgresql.ENUM(
    "staging", "quarantined", "active", "disabled", "revoked",
    name="peer_state", create_type=False,
)
group_kind = postgresql.ENUM("group", "zone", name="group_kind", create_type=False)
acl_action = postgresql.ENUM("accept", "drop", "reject", name="acl_action", create_type=False)
endpoint_kind = postgresql.ENUM("any", "group", "cidr", name="endpoint_kind", create_type=False)
acl_protocol = postgresql.ENUM("any", "tcp", "udp", "icmp", name="acl_protocol", create_type=False)
auth_method = postgresql.ENUM("local", "oidc", name="auth_method", create_type=False)
session_status = postgresql.ENUM(
    "active", "expired", "revoked", name="session_status", create_type=False
)
actor_type = postgresql.ENUM(
    "admin", "user", "agent", "system", "peer", name="actor_type", create_type=False
)
ruleset_status = postgresql.ENUM(
    "pending", "applied", "failed", "superseded", name="ruleset_status", create_type=False
)

_ALL_ENUMS = (
    peer_type,
    peer_state,
    group_kind,
    acl_action,
    endpoint_kind,
    acl_protocol,
    auth_method,
    session_status,
    actor_type,
    ruleset_status,
)


def upgrade() -> None:
    bind = op.get_bind()
    for enum in _ALL_ENUMS:
        enum.create(bind, checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("email", sa.String(255)),
        sa.Column("display_name", sa.String(255)),
        sa.Column("password_hash", sa.Text()),
        sa.Column("external_idp_issuer", sa.String(255)),
        sa.Column("external_idp_subject", sa.String(255)),
        sa.Column("totp_secret", sa.Text()),
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "password_hash IS NOT NULL OR external_idp_subject IS NOT NULL",
            name="ck_users_has_credential",
        ),
        sa.UniqueConstraint(
            "external_idp_issuer", "external_idp_subject", name="uq_users_idp_subject"
        ),
    )

    op.create_table(
        "groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(24), nullable=False, unique=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("kind", group_kind, nullable=False, server_default="group"),
        sa.Column(
            "parent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="SET NULL"),
        ),
        sa.Column("internet_exit", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("session_lifetime_seconds", sa.Integer()),
        sa.Column("extra", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        # The slug becomes part of an nftables set name, hence the strict shape.
        sa.CheckConstraint("slug ~ '^[a-z0-9][a-z0-9_-]{0,23}$'", name="ck_groups_slug_format"),
        sa.CheckConstraint("id <> parent_id", name="ck_groups_no_self_parent"),
    )

    op.create_table(
        "tags",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("color", sa.String(16)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "peers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("peer_type", peer_type, nullable=False),
        sa.Column("state", peer_state, nullable=False, server_default="staging"),
        sa.Column("wg_public_key", sa.String(64), nullable=False, unique=True),
        sa.Column("wg_interface", sa.String(15), nullable=False, server_default="wg0"),
        sa.Column("tunnel_ip", postgresql.INET(), unique=True),
        sa.Column("tunnel_ip6", postgresql.INET(), unique=True),
        sa.Column(
            "owner_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("enrollment_key_hash", sa.Text()),
        sa.Column("enrollment_key_expires_at", sa.DateTime(timezone=True)),
        sa.Column("enrolled_at", sa.DateTime(timezone=True)),
        sa.Column("last_handshake_at", sa.DateTime(timezone=True)),
        sa.Column("last_authenticated_at", sa.DateTime(timezone=True)),
        sa.Column("extra", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "tunnel_ip IS NOT NULL OR tunnel_ip6 IS NOT NULL", name="ck_peers_has_address"
        ),
        sa.CheckConstraint(
            "peer_type = 'server' OR enrollment_key_hash IS NULL",
            name="ck_peers_enrollment_key_is_server_only",
        ),
    )
    op.create_index("ix_peers_state", "peers", ["state"])
    op.create_index("ix_peers_type", "peers", ["peer_type"])

    op.create_table(
        "peer_groups",
        sa.Column(
            "peer_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("peers.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "peer_tags",
        sa.Column(
            "peer_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("peers.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "tag_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tags.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    op.create_table(
        "acl_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ref", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("action", acl_action, nullable=False),
        sa.Column("src_kind", endpoint_kind, nullable=False),
        sa.Column(
            "src_group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
        ),
        sa.Column("src_cidr", sa.String(64)),
        sa.Column("dst_kind", endpoint_kind, nullable=False),
        sa.Column(
            "dst_group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
        ),
        sa.Column("dst_cidr", sa.String(64)),
        sa.Column("protocol", acl_protocol, nullable=False, server_default="any"),
        sa.Column("dst_port_start", sa.Integer()),
        sa.Column("dst_port_end", sa.Integer()),
        sa.Column("extra", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "(src_kind <> 'group' OR src_group_id IS NOT NULL) AND "
            "(src_kind <> 'cidr' OR src_cidr IS NOT NULL)",
            name="ck_acl_src_consistent",
        ),
        sa.CheckConstraint(
            "(dst_kind <> 'group' OR dst_group_id IS NOT NULL) AND "
            "(dst_kind <> 'cidr' OR dst_cidr IS NOT NULL)",
            name="ck_acl_dst_consistent",
        ),
        sa.CheckConstraint(
            "dst_port_start IS NULL OR protocol IN ('tcp', 'udp')",
            name="ck_acl_ports_need_l4",
        ),
        sa.CheckConstraint(
            "dst_port_end IS NULL OR dst_port_start IS NOT NULL",
            name="ck_acl_port_range_start",
        ),
        sa.CheckConstraint(
            "dst_port_end IS NULL OR dst_port_end >= dst_port_start",
            name="ck_acl_port_range_order",
        ),
    )
    op.create_index("ix_acl_rules_order", "acl_rules", ["priority", "id"])

    op.create_table(
        "sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "peer_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("peers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("auth_method", auth_method, nullable=False),
        sa.Column("status", session_status, nullable=False, server_default="active"),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_authenticated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("source_ip", postgresql.INET()),
    )
    op.create_index("ix_sessions_peer_status", "sessions", ["peer_id", "status"])

    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("actor_type", actor_type, nullable=False),
        sa.Column(
            "actor_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("actor_label", sa.String(128)),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("object_type", sa.String(64)),
        sa.Column("object_id", sa.String(64)),
        sa.Column("source_ip", postgresql.INET()),
        sa.Column("detail", postgresql.JSONB(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])
    op.create_index("ix_audit_log_object", "audit_log", ["object_type", "object_id"])

    op.create_table(
        "ruleset_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("status", ruleset_status, nullable=False, server_default="pending"),
        sa.Column("applied_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.Text()),
        sa.Column("generated_by", sa.String(128)),
    )
    op.create_index("ix_ruleset_versions_created_at", "ruleset_versions", ["created_at"])
    op.create_index("ix_ruleset_versions_digest", "ruleset_versions", ["digest"])


def downgrade() -> None:
    op.drop_table("ruleset_versions")
    op.drop_table("audit_log")
    op.drop_table("sessions")
    op.drop_table("acl_rules")
    op.drop_table("peer_tags")
    op.drop_table("peer_groups")
    op.drop_table("peers")
    op.drop_table("tags")
    op.drop_table("groups")
    op.drop_table("users")

    bind = op.get_bind()
    for enum in reversed(_ALL_ENUMS):
        enum.drop(bind, checkfirst=True)
