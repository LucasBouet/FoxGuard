"""Published services and the reverse proxy that fronts them.

Revision ID: 0006_proxy
Revises: 0005_zones
Create Date: Phase 6

Six tables, five new enums and **no change to any existing type**. That is
deliberate: ``0005`` had to add a value to ``endpoint_kind`` and paid for it
with the two-commit dance below, so this migration reuses ``endpoint_kind`` and
``acl_action`` exactly as they are.

The consequence, recorded here because it looks like an omission: there is no
``peer`` endpoint kind for ``service_access``. A single device is named by its
``/32``, which is what ``acl_rules`` already requires of anyone writing a
one-device rule. Adding ``peer`` would have widened a type shared with the
firewall generator, for a case the ``cidr`` kind already covers.

``services.upstream_peer_id`` is ON DELETE CASCADE rather than SET NULL: a
service is published *because* some peer can serve it, and a service whose peer
is gone would keep a listener open on a backend nothing can answer. Deleting
narrows, as everywhere else.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0006_proxy"
down_revision = "0005_zones"
branch_labels = None
depends_on = None


service_kind = postgresql.ENUM("http", "tcp", name="service_kind", create_type=False)
service_exposure = postgresql.ENUM(
    "internal", "external", "both", name="service_exposure", create_type=False
)
service_scope = postgresql.ENUM(
    "internal", "external", "both", name="service_scope", create_type=False
)
service_auth_kind = postgresql.ENUM(
    "peer_identity",
    "bearer",
    "basic",
    "foxguard_sso",
    "mtls",
    name="service_auth_kind",
    create_type=False,
)
service_filter_kind = postgresql.ENUM(
    "ip_allow",
    "ip_deny",
    "geo_allow",
    "geo_deny",
    "rate_limit",
    "waf",
    "crowdsec",
    name="service_filter_kind",
    create_type=False,
)
endpoint_kind = postgresql.ENUM(
    "any", "group", "cidr", "zone", name="endpoint_kind", create_type=False
)
acl_action = postgresql.ENUM(
    "accept", "drop", "reject", name="acl_action", create_type=False
)

_NEW_ENUMS = (
    service_kind,
    service_exposure,
    service_scope,
    service_auth_kind,
    service_filter_kind,
)


def upgrade() -> None:
    bind = op.get_bind()
    for enum in _NEW_ENUMS:
        enum.create(bind, checkfirst=True)

    op.create_table(
        "services",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(24), nullable=False, unique=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("kind", service_kind, nullable=False),
        sa.Column(
            "exposure", service_exposure, nullable=False, server_default="internal"
        ),
        sa.Column(
            "upstream_peer_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("peers.id", ondelete="CASCADE"),
        ),
        sa.Column("upstream_host", postgresql.INET(), nullable=False),
        sa.Column("upstream_port", sa.Integer(), nullable=False),
        sa.Column(
            "upstream_tls", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "upstream_tls_verify",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("internal_hostname", sa.String(255), unique=True),
        sa.Column("external_hostname", sa.String(255), unique=True),
        sa.Column("listen_port", sa.Integer()),
        sa.Column("sni_hostname", sa.String(255)),
        sa.Column(
            "health_check", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "health_check_interval", sa.Integer(), nullable=False, server_default="30"
        ),
        sa.Column(
            "extra",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "slug ~ '^[a-z0-9][a-z0-9_-]{0,23}$'", name="ck_services_slug_format"
        ),
        sa.CheckConstraint(
            "kind <> 'tcp' OR listen_port IS NOT NULL OR sni_hostname IS NOT NULL",
            name="ck_services_tcp_needs_target",
        ),
        sa.CheckConstraint(
            "listen_port IS NULL OR (listen_port BETWEEN 1 AND 65535)",
            name="ck_services_listen_port_range",
        ),
        sa.CheckConstraint(
            "upstream_port BETWEEN 1 AND 65535", name="ck_services_upstream_port_range"
        ),
        sa.CheckConstraint(
            "kind <> 'http' OR exposure = 'external' OR internal_hostname IS NOT NULL",
            name="ck_services_internal_hostname",
        ),
        sa.CheckConstraint(
            "kind <> 'http' OR exposure = 'internal' OR external_hostname IS NOT NULL",
            name="ck_services_external_hostname",
        ),
    )
    op.create_index("ix_services_peer", "services", ["upstream_peer_id"])
    # Partial, because "no dedicated port" is the normal case for HTTP services
    # and NULLs must not collide with each other.
    op.create_index(
        "uq_services_listen_port",
        "services",
        ["listen_port"],
        unique=True,
        postgresql_where=sa.text("listen_port IS NOT NULL"),
    )

    op.create_table(
        "service_auth",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "service_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("services.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", service_auth_kind, nullable=False),
        sa.Column("scope", service_scope, nullable=False, server_default="both"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("realm", sa.String(64)),
        sa.Column(
            "config",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("service_id", "kind", "scope", name="uq_service_auth_kind"),
    )
    op.create_index("ix_service_auth_service", "service_auth", ["service_id"])

    op.create_table(
        "service_filters",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "service_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("services.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", service_filter_kind, nullable=False),
        sa.Column("scope", service_scope, nullable=False, server_default="both"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column(
            "values",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("rate", sa.Integer()),
        sa.Column("period_seconds", sa.Integer()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "kind <> 'rate_limit' OR (rate IS NOT NULL AND period_seconds IS NOT NULL)",
            name="ck_service_filters_rate_complete",
        ),
    )
    op.create_index("ix_service_filters_service", "service_filters", ["service_id"])

    op.create_table(
        "service_access",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "service_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("services.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action", acl_action, nullable=False, server_default="accept"),
        sa.Column("kind", endpoint_kind, nullable=False),
        sa.Column(
            "group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
        ),
        sa.Column("cidr", sa.String(64)),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "(kind NOT IN ('group', 'zone') OR group_id IS NOT NULL) AND "
            "(kind <> 'cidr' OR cidr IS NOT NULL)",
            name="ck_service_access_consistent",
        ),
    )
    op.create_index("ix_service_access_service", "service_access", ["service_id"])

    op.create_table(
        "service_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "service_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("services.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("prefix", sa.String(12), nullable=False),
        sa.Column(
            "created_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("token_hash", name="uq_service_tokens_hash"),
    )
    op.create_index("ix_service_tokens_service", "service_tokens", ["service_id"])

    op.create_table(
        "service_accounts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "service_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("services.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("service_id", "username", name="uq_service_accounts_name"),
    )
    op.create_index("ix_service_accounts_service", "service_accounts", ["service_id"])


def downgrade() -> None:
    op.drop_table("service_accounts")
    op.drop_table("service_tokens")
    op.drop_table("service_access")
    op.drop_table("service_filters")
    op.drop_table("service_auth")
    op.drop_table("services")

    bind = op.get_bind()
    for enum in reversed(_NEW_ENUMS):
        enum.drop(bind, checkfirst=True)
