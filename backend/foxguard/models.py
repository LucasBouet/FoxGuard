"""SQLAlchemy models — the single source of truth for the dataplane.

Extensibility notes for the Phase 5 roadmap (kept cheap on purpose):

* ``groups.kind`` distinguishes ``group`` from ``zone`` and ``groups.parent_id``
  allows nesting, which is what let network zones with their own routes and
  exit nodes land in ``0005`` without a table rewrite.
* ACL endpoints are modelled as ``(kind, group_id, cidr)`` rather than a bare
  ``src_group_id``, so the ``zone`` endpoint kind cost one enum value rather
  than a migration of every rule.
* ``acl_rules.extra`` / ``groups.extra`` are JSONB escape hatches for things
  like reverse-proxy hints or CrowdSec metadata that must not shape the core
  schema today.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .dns.model import RecordKind
from .nftables.model import Action, EndpointKind, PeerState, PeerType, Protocol
from .proxy.model import (
    AuthKind as ServiceAuthKind,
)
from .proxy.model import (
    Exposure as ServiceExposure,
)
from .proxy.model import (
    FilterKind as ServiceFilterKind,
)
from .proxy.model import (
    Scope as ServiceScope,
)
from .proxy.model import (
    ServiceKind,
)


class Base(DeclarativeBase):
    pass


def _enum(enum_cls: type[Enum], name: str) -> SAEnum:
    """Native PostgreSQL enum keyed on the *values*, not the member names."""
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=True,
        values_callable=lambda cls: [member.value for member in cls],
        validate_strings=True,
    )


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


TimestampColumn = DateTime(timezone=True)


# --------------------------------------------------------------------------- #
# enums that only exist in the control plane
# --------------------------------------------------------------------------- #


class GroupKind(str, Enum):
    GROUP = "group"
    ZONE = "zone"  # reserved for Phase 5, not yet honoured by the generator


class AuthMethod(str, Enum):
    LOCAL = "local"
    OIDC = "oidc"


class ActorType(str, Enum):
    ADMIN = "admin"
    USER = "user"
    AGENT = "agent"
    SYSTEM = "system"
    PEER = "peer"


class RulesetStatus(str, Enum):
    PENDING = "pending"
    APPLIED = "applied"
    FAILED = "failed"
    SUPERSEDED = "superseded"


class SessionStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


# --------------------------------------------------------------------------- #
# core tables
# --------------------------------------------------------------------------- #


class User(Base):
    """A human. May authenticate locally, via OIDC, or both."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "password_hash IS NOT NULL OR external_idp_subject IS NOT NULL",
            name="ck_users_has_credential",
        ),
        UniqueConstraint(
            "external_idp_issuer", "external_idp_subject", name="uq_users_idp_subject"
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(255))

    # Local authentication (argon2 hash; the plaintext never touches the DB).
    password_hash: Mapped[str | None] = mapped_column(Text)
    # External IdP binding (Authentik / Keycloak / anything OIDC).
    external_idp_issuer: Mapped[str | None] = mapped_column(String(255))
    external_idp_subject: Mapped[str | None] = mapped_column(String(255))

    totp_secret: Mapped[str | None] = mapped_column(Text)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Highest TOTP time step already spent, so a code cannot be replayed while
    #: it is still inside the skew window (RFC 6238 §5.2). BigInteger because a
    #: step is a unix timestamp / 30 and would overflow int4 in 2038.
    totp_last_used_step: Mapped[int | None] = mapped_column(BigInteger)

    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(TimestampColumn)

    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    peers: Mapped[list[Peer]] = relationship(back_populates="owner")

    @property
    def available_auth_methods(self) -> list[AuthMethod]:
        methods = []
        if self.password_hash:
            methods.append(AuthMethod.LOCAL)
        if self.external_idp_subject:
            methods.append(AuthMethod.OIDC)
        return methods


class PeerGroup(Base):
    """Many-to-many between peers and groups."""

    __tablename__ = "peer_groups"

    peer_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("peers.id", ondelete="CASCADE"), primary_key=True
    )
    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )


class PeerTag(Base):
    """Free-form labels for dashboard filtering. Deliberately outside the ACL model."""

    __tablename__ = "peer_tags"

    peer_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("peers.id", ondelete="CASCADE"), primary_key=True
    )
    tag_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True
    )


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    color: Mapped[str | None] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )

    peers: Mapped[list[Peer]] = relationship(
        secondary="peer_tags", back_populates="tags"
    )


class Group(Base):
    __tablename__ = "groups"
    __table_args__ = (
        CheckConstraint(
            "slug ~ '^[a-z0-9][a-z0-9_-]{0,23}$'", name="ck_groups_slug_format"
        ),
        CheckConstraint("id <> parent_id", name="ck_groups_no_self_parent"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    #: Also the nftables set name component -- hence the strict format check.
    slug: Mapped[str] = mapped_column(String(24), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    kind: Mapped[GroupKind] = mapped_column(
        _enum(GroupKind, "group_kind"), default=GroupKind.GROUP, nullable=False
    )
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("groups.id", ondelete="SET NULL")
    )

    #: Peers in this group may reach the internet through the gateway (Phase 1
    #: answer to "exit node configurable per group").
    internet_exit: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    #: Zones only: whether members may reach each other without an explicit ACL
    #: rule. Off by default -- everywhere else in Foxguard access is denied
    #: until something grants it, and a zone is not the exception.
    intra_zone: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Session lifetime override for user peers (Phase 3). NULL -> global default.
    session_lifetime_seconds: Mapped[int | None] = mapped_column(Integer)

    extra: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    peers: Mapped[list[Peer]] = relationship(
        secondary="peer_groups", back_populates="groups"
    )
    routes: Mapped[list[ZoneRoute]] = relationship(
        back_populates="zone", cascade="all, delete-orphan", lazy="selectin"
    )


class ZoneRoute(Base):
    """A network reachable inside a zone.

    ``via_peer_id`` is the peer that carries it -- Netbird's "routing peer".
    NULL means the gateway reaches the network itself, in which case the CIDR
    only widens the zone's address set and no tunnel route is installed.

    Deleting the routing peer cascades this row away rather than leaving the
    route pointing nowhere: a network is advertised *because* some peer can
    carry it, and an orphaned route would keep widening the zone's set while
    nothing could deliver the packets.
    """

    __tablename__ = "zone_routes"
    __table_args__ = (
        UniqueConstraint("zone_id", "cidr", name="uq_zone_routes_zone_cidr"),
        Index("ix_zone_routes_zone", "zone_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    zone_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), nullable=False
    )
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    via_peer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("peers.id", ondelete="CASCADE")
    )
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    extra: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    zone: Mapped[Group] = relationship(back_populates="routes")


class Peer(Base):
    __tablename__ = "peers"
    __table_args__ = (
        CheckConstraint(
            "tunnel_ip IS NOT NULL OR tunnel_ip6 IS NOT NULL",
            name="ck_peers_has_address",
        ),
        # Enrollment keys are a server-peer mechanism; user peers authenticate
        # through the portal instead.
        CheckConstraint(
            "peer_type = 'server' OR enrollment_key_hash IS NULL",
            name="ck_peers_enrollment_key_is_server_only",
        ),
        Index("ix_peers_state", "state"),
        Index("ix_peers_type", "peer_type"),
        Index("ix_peers_zone", "zone_id"),
        # On lower(), because DNS is case-insensitive: without it the column
        # would happily hold both "Laptop" and "laptop" as distinct labels for
        # what a resolver considers one name. Mirrors migration 0004 -- the two
        # must agree, or `create_all` in tests enforces less than production.
        Index("uq_peers_dns_label", text("lower(dns_label)"), unique=True),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    peer_type: Mapped[PeerType] = mapped_column(
        _enum(PeerType, "peer_type"), nullable=False
    )
    state: Mapped[PeerState] = mapped_column(
        _enum(PeerState, "peer_state"), default=PeerState.STAGING, nullable=False
    )

    #: Public key only. Private keys are generated on the device and never leave it.
    wg_public_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    #: Which WireGuard interface this peer lives on. Single-interface today;
    #: the column exists so multi-interface / zones do not need a migration.
    wg_interface: Mapped[str] = mapped_column(
        String(15), default="wg0", nullable=False
    )
    tunnel_ip: Mapped[str | None] = mapped_column(INET, unique=True)
    tunnel_ip6: Mapped[str | None] = mapped_column(INET, unique=True)

    #: Single DNS label inside ``FOXGUARD_DNS_ZONE``. Materialised at
    #: registration rather than derived at render time, so that two peers
    #: wanting the same name is a 409 on the request that caused it instead of
    #: a zone that will not render. Uniqueness is enforced on ``lower()``,
    #: since DNS is case-insensitive (migration ``0004``).
    dns_label: Mapped[str | None] = mapped_column(String(63))

    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    #: The one zone this peer sits in, if any. A single FK rather than a second
    #: many-to-many: a zone owns routes, and "which zone's routes apply" has to
    #: have one answer. ON DELETE SET NULL, so removing a zone narrows access.
    zone_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("groups.id", ondelete="SET NULL")
    )

    #: Only the hash is stored; the plaintext is shown once at generation time.
    enrollment_key_hash: Mapped[str | None] = mapped_column(Text)
    enrollment_key_expires_at: Mapped[datetime | None] = mapped_column(TimestampColumn)
    enrolled_at: Mapped[datetime | None] = mapped_column(TimestampColumn)

    last_handshake_at: Mapped[datetime | None] = mapped_column(TimestampColumn)
    last_authenticated_at: Mapped[datetime | None] = mapped_column(TimestampColumn)

    extra: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    owner: Mapped[User | None] = relationship(back_populates="peers")
    zone: Mapped[Group | None] = relationship(foreign_keys=[zone_id], lazy="joined")
    groups: Mapped[list[Group]] = relationship(
        secondary="peer_groups", back_populates="peers", lazy="selectin"
    )
    tags: Mapped[list[Tag]] = relationship(
        secondary="peer_tags", back_populates="peers", lazy="selectin"
    )


class AclRule(Base):
    __tablename__ = "acl_rules"
    __table_args__ = (
        # 'zone' shares the group_id column: a zone *is* a groups row, so the
        # foreign key already points at the right table and the kind is what
        # says how to read it.
        CheckConstraint(
            "(src_kind NOT IN ('group', 'zone') OR src_group_id IS NOT NULL) AND "
            "(src_kind <> 'cidr' OR src_cidr IS NOT NULL)",
            name="ck_acl_src_consistent",
        ),
        CheckConstraint(
            "(dst_kind NOT IN ('group', 'zone') OR dst_group_id IS NOT NULL) AND "
            "(dst_kind <> 'cidr' OR dst_cidr IS NOT NULL)",
            name="ck_acl_dst_consistent",
        ),
        CheckConstraint(
            "dst_port_start IS NULL OR protocol IN ('tcp', 'udp')",
            name="ck_acl_ports_need_l4",
        ),
        CheckConstraint(
            "dst_port_end IS NULL OR dst_port_start IS NOT NULL",
            name="ck_acl_port_range_start",
        ),
        CheckConstraint(
            "dst_port_end IS NULL OR dst_port_end >= dst_port_start",
            name="ck_acl_port_range_order",
        ),
        Index("ix_acl_rules_order", "priority", "id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    #: Stable, human-authored identifier used in the JSON export so rules survive
    #: an export/rebuild/import round trip.
    ref: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    #: Lower runs first. Ties broken by ``ref`` so output is deterministic.
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    action: Mapped[Action] = mapped_column(_enum(Action, "acl_action"), nullable=False)

    src_kind: Mapped[EndpointKind] = mapped_column(
        _enum(EndpointKind, "endpoint_kind"), nullable=False
    )
    src_group_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE")
    )
    src_cidr: Mapped[str | None] = mapped_column(String(64))

    dst_kind: Mapped[EndpointKind] = mapped_column(
        _enum(EndpointKind, "endpoint_kind"), nullable=False
    )
    dst_group_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE")
    )
    dst_cidr: Mapped[str | None] = mapped_column(String(64))

    protocol: Mapped[Protocol] = mapped_column(
        _enum(Protocol, "acl_protocol"), default=Protocol.ANY, nullable=False
    )
    dst_port_start: Mapped[int | None] = mapped_column(Integer)
    dst_port_end: Mapped[int | None] = mapped_column(Integer)

    extra: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    src_group: Mapped[Group | None] = relationship(
        foreign_keys=[src_group_id], lazy="joined"
    )
    dst_group: Mapped[Group | None] = relationship(
        foreign_keys=[dst_group_id], lazy="joined"
    )


class DnsRecord(Base):
    """A record an administrator authored by hand.

    Peers name themselves through ``peers.dns_label``; this table is for
    everything else -- an alias for the portal, an A record for a service that
    lives on the LAN behind the gateway, a friendlier name for a server peer.

    ``name`` and (for CNAMEs) ``value`` are *relative to the zone*. Storing
    fully qualified names would orphan every row the day someone changes
    ``FOXGUARD_DNS_ZONE``.
    """

    __tablename__ = "dns_records"
    __table_args__ = (
        Index("uq_dns_records_name", text("lower(name)"), unique=True),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(253), nullable=False)
    kind: Mapped[RecordKind] = mapped_column(
        _enum(RecordKind, "dns_record_kind"), nullable=False
    )
    #: An IP address for A/AAAA, another record's relative name for CNAME.
    value: Mapped[str] = mapped_column(String(253), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    extra: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class PeerSession(Base):
    """Portal authentication session for a *user* peer.

    Server peers never get a row here: their access is bound to the enrollment
    key, not to a session that can expire.
    """

    __tablename__ = "sessions"
    __table_args__ = (Index("ix_sessions_peer_status", "peer_id", "status"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    peer_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("peers.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    auth_method: Mapped[AuthMethod] = mapped_column(
        _enum(AuthMethod, "auth_method"), nullable=False
    )
    status: Mapped[SessionStatus] = mapped_column(
        _enum(SessionStatus, "session_status"), default=SessionStatus.ACTIVE, nullable=False
    )

    authenticated_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    last_authenticated_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(TimestampColumn)
    revoked_at: Mapped[datetime | None] = mapped_column(TimestampColumn)
    source_ip: Mapped[str | None] = mapped_column(INET)


class AdminSession(Base):
    """A signed-in administrator.

    Separate from :class:`PeerSession`, which records a *peer* proving a human is
    present on a device. This one records a human operating the control plane,
    and it is what lets the audit log name a person instead of "whoever holds the
    shared token".

    Only a hash of the token is stored -- a salted SHA-256 rather than argon2,
    because the input is a 256-bit random secret with nothing to brute force,
    exactly as for enrollment keys.
    """

    __tablename__ = "admin_sessions"
    __table_args__ = (
        Index("ix_admin_sessions_user", "user_id"),
        # Every authenticated request looks a session up by hash.
        Index("ix_admin_sessions_token", "token_hash"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    #: Refreshed on use, so an idle session can be spotted and expired.
    last_seen_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(TimestampColumn, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(TimestampColumn)

    source_ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(255))

    user: Mapped[User] = relationship(lazy="joined")


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_created_at", "created_at"),
        Index("ix_audit_log_object", "object_type", "object_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )

    actor_type: Mapped[ActorType] = mapped_column(
        _enum(ActorType, "actor_type"), nullable=False
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    actor_label: Mapped[str | None] = mapped_column(String(128))

    action: Mapped[str] = mapped_column(String(64), nullable=False)
    object_type: Mapped[str | None] = mapped_column(String(64))
    object_id: Mapped[str | None] = mapped_column(String(64))
    source_ip: Mapped[str | None] = mapped_column(INET)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class RulesetVersion(Base):
    """Every ruleset ever generated, for audit and drift detection."""

    __tablename__ = "ruleset_versions"
    __table_args__ = (
        Index("ix_ruleset_versions_created_at", "created_at"),
        # store_version() and the agent's /report endpoint both look versions up
        # by digest on every reconciliation.
        Index("ix_ruleset_versions_digest", "digest"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    #: sha256 of the rendered script. Identical DB state -> identical digest.
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[RulesetStatus] = mapped_column(
        _enum(RulesetStatus, "ruleset_status"), default=RulesetStatus.PENDING, nullable=False
    )
    applied_at: Mapped[datetime | None] = mapped_column(TimestampColumn)
    error: Mapped[str | None] = mapped_column(Text)
    generated_by: Mapped[str | None] = mapped_column(String(128))


# --------------------------------------------------------------------------- #
# Phase 6: published services (reverse proxy)
# --------------------------------------------------------------------------- #


class Service(Base):
    """A service published through the gateway's reverse proxy.

    The upstream lives *behind a peer*, which is what makes this different from
    a generic proxy: ``upstream_host`` must be an address the carrying peer's
    ``AllowedIPs`` actually covers -- its own tunnel address, or a network in a
    zone it routes for. The control plane checks that before the row is ever
    written, because the alternative failure mode is a timeout, which is the
    least diagnosable thing in the system.

    ``upstream_peer_id`` is nullable for the case where the gateway hosts the
    thing itself. Deleting the peer cascades the service away rather than
    leaving it pointing nowhere: a service is published *because* some peer can
    serve it.
    """

    __tablename__ = "services"
    __table_args__ = (
        CheckConstraint(
            "slug ~ '^[a-z0-9][a-z0-9_-]{0,23}$'", name="ck_services_slug_format"
        ),
        # Plain TCP has no SNI and no Host header, so it has nothing to route on
        # but the port it arrived at.
        CheckConstraint(
            "kind <> 'tcp' OR listen_port IS NOT NULL OR sni_hostname IS NOT NULL",
            name="ck_services_tcp_needs_target",
        ),
        CheckConstraint(
            "listen_port IS NULL OR (listen_port BETWEEN 1 AND 65535)",
            name="ck_services_listen_port_range",
        ),
        CheckConstraint(
            "upstream_port BETWEEN 1 AND 65535", name="ck_services_upstream_port_range"
        ),
        # An HTTP service is routed by Host, so each door it opens needs a name.
        CheckConstraint(
            "kind <> 'http' OR exposure = 'external' OR internal_hostname IS NOT NULL",
            name="ck_services_internal_hostname",
        ),
        CheckConstraint(
            "kind <> 'http' OR exposure = 'internal' OR external_hostname IS NOT NULL",
            name="ck_services_external_hostname",
        ),
        Index("ix_services_peer", "upstream_peer_id"),
        Index(
            "uq_services_listen_port",
            "listen_port",
            unique=True,
            postgresql_where=text("listen_port IS NOT NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    #: Shares one namespace with peer labels, groups and zones -- a name that
    #: could mean two things makes an access rule ambiguous.
    slug: Mapped[str] = mapped_column(String(24), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    kind: Mapped[ServiceKind] = mapped_column(
        _enum(ServiceKind, "service_kind"), nullable=False
    )
    exposure: Mapped[ServiceExposure] = mapped_column(
        _enum(ServiceExposure, "service_exposure"),
        default=ServiceExposure.INTERNAL,
        nullable=False,
    )

    upstream_peer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("peers.id", ondelete="CASCADE")
    )
    upstream_host: Mapped[str] = mapped_column(INET, nullable=False)
    upstream_port: Mapped[int] = mapped_column(Integer, nullable=False)
    upstream_tls: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Off by default. These upstreams are appliances with self-signed
    #: certificates and the hop already runs inside WireGuard.
    upstream_tls_verify: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    internal_hostname: Mapped[str | None] = mapped_column(String(255), unique=True)
    external_hostname: Mapped[str | None] = mapped_column(String(255), unique=True)
    listen_port: Mapped[int | None] = mapped_column(Integer)
    sni_hostname: Mapped[str | None] = mapped_column(String(255))

    #: Off by default: an upstream behind a roaming laptop flaps every time the
    #: lid closes, and an aggressive check turns that into spurious 503s.
    health_check: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    health_check_interval: Mapped[int] = mapped_column(
        Integer, default=30, nullable=False
    )

    extra: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    upstream_peer: Mapped[Peer | None] = relationship(lazy="joined")
    authenticators: Mapped[list[ServiceAuth]] = relationship(
        back_populates="service", cascade="all, delete-orphan", lazy="selectin"
    )
    filters: Mapped[list[ServiceFilter]] = relationship(
        back_populates="service", cascade="all, delete-orphan", lazy="selectin"
    )
    access: Mapped[list[ServiceAccess]] = relationship(
        back_populates="service", cascade="all, delete-orphan", lazy="selectin"
    )
    tokens: Mapped[list[ServiceToken]] = relationship(
        back_populates="service", cascade="all, delete-orphan", lazy="selectin"
    )
    accounts: Mapped[list[ServiceAccount]] = relationship(
        back_populates="service", cascade="all, delete-orphan", lazy="selectin"
    )


class ServiceAuth(Base):
    """One way in. Combined with OR: any one of these is enough.

    ``scope`` exists because the same service legitimately wants different
    proof on each door -- the tunnel proves identity by itself, the internet
    proves nothing. ``peer_identity`` scoped anywhere but ``internal`` is
    refused by the validator rather than silently ignored.
    """

    __tablename__ = "service_auth"
    __table_args__ = (
        UniqueConstraint("service_id", "kind", "scope", name="uq_service_auth_kind"),
        Index("ix_service_auth_service", "service_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[ServiceAuthKind] = mapped_column(
        _enum(ServiceAuthKind, "service_auth_kind"), nullable=False
    )
    scope: Mapped[ServiceScope] = mapped_column(
        _enum(ServiceScope, "service_scope"), default=ServiceScope.BOTH, nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    #: ``basic`` only: the realm shown in the browser prompt.
    realm: Mapped[str | None] = mapped_column(String(64))
    config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )

    service: Mapped[Service] = relationship(back_populates="authenticators")


class ServiceFilter(Base):
    """A condition that must pass. Combined with AND.

    Generic ``kind`` + ``values`` on purpose: geo, WAF and CrowdSec arrive in
    later phases and should not each need a migration. The ones not implemented
    yet are accepted by the schema and refused by the validator, which is
    better than a rule that saves and quietly does nothing.
    """

    __tablename__ = "service_filters"
    __table_args__ = (
        CheckConstraint(
            "kind <> 'rate_limit' OR (rate IS NOT NULL AND period_seconds IS NOT NULL)",
            name="ck_service_filters_rate_complete",
        ),
        Index("ix_service_filters_service", "service_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[ServiceFilterKind] = mapped_column(
        _enum(ServiceFilterKind, "service_filter_kind"), nullable=False
    )
    scope: Mapped[ServiceScope] = mapped_column(
        _enum(ServiceScope, "service_scope"), default=ServiceScope.BOTH, nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    #: ``ip_allow`` / ``ip_deny``: addresses and prefixes.
    values: Mapped[dict] = mapped_column(JSONB, default=list, nullable=False)
    rate: Mapped[int | None] = mapped_column(Integer)
    period_seconds: Mapped[int | None] = mapped_column(Integer)

    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )

    service: Mapped[Service] = relationship(back_populates="filters")


class ServiceAccess(Base):
    """Who may use a service, in the ACL module's vocabulary.

    Deliberately reuses ``endpoint_kind`` and ``acl_action`` rather than
    inventing a parallel set: two access-control vocabularies that can disagree
    is how a segmentation model becomes a lie. There is no ``peer`` kind
    because there is none in ``endpoint_kind`` -- a single device is named by
    its ``/32``, exactly as the ACL rules already require.

    Set-backed rules (``group``, ``zone``) are evaluated only on the internal
    listener. A public source address cannot be a peer, so applying them
    outside would deny everyone for a reason nobody could read; external
    authorisation is the authenticators' job plus any ``cidr`` rules.
    """

    __tablename__ = "service_access"
    __table_args__ = (
        CheckConstraint(
            "(kind NOT IN ('group', 'zone') OR group_id IS NOT NULL) AND "
            "(kind <> 'cidr' OR cidr IS NOT NULL)",
            name="ck_service_access_consistent",
        ),
        Index("ix_service_access_service", "service_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), nullable=False
    )
    action: Mapped[Action] = mapped_column(
        _enum(Action, "acl_action"), default=Action.ACCEPT, nullable=False
    )
    kind: Mapped[EndpointKind] = mapped_column(
        _enum(EndpointKind, "endpoint_kind"), nullable=False
    )
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE")
    )
    cidr: Mapped[str | None] = mapped_column(String(64))
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )

    service: Mapped[Service] = relationship(back_populates="access")
    group: Mapped[Group | None] = relationship(lazy="joined")


class ServiceToken(Base):
    """A bearer token, scoped to one service.

    Stored as a salted SHA-256, not behind a KDF -- the same reasoning as
    ``admin_sessions`` and enrollment keys, and for the same reason: these are
    generated high-entropy secrets, so stretching buys nothing. ``prefix`` is
    the first characters of the plaintext, kept purely so a human can tell two
    tokens apart in a list.
    """

    __tablename__ = "service_tokens"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_service_tokens_hash"),
        Index("ix_service_tokens_service", "service_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    expires_at: Mapped[datetime | None] = mapped_column(TimestampColumn)
    revoked_at: Mapped[datetime | None] = mapped_column(TimestampColumn)
    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )

    service: Mapped[Service] = relationship(back_populates="tokens")


class ServiceAccount(Base):
    """A basic-auth service account.

    ``password_hash`` is a crypt(3) SHA-crypt string, because that is what a
    HAProxy ``userlist`` can verify. Weaker than the argon2 the ``users`` table
    uses, and acceptable only because the password here is machine-generated
    and high-entropy: human passwords stay in the database and never reach the
    gateway's disk. That is the whole reason this table exists separately from
    ``users``.
    """

    __tablename__ = "service_accounts"
    __table_args__ = (
        UniqueConstraint("service_id", "username", name="uq_service_accounts_name"),
        Index("ix_service_accounts_service", "service_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), nullable=False
    )
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(TimestampColumn)
    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )

    service: Mapped[Service] = relationship(back_populates="accounts")


class SsoSession(Base):
    """A browser session for a *person* reaching a published service.

    Deliberately a third kind of session, not a reuse of either existing one:

    * ``admin_sessions`` grants the admin API. An SSO cookie must never be
      mistakable for one, or reaching a published web app would hand the holder
      the kill switch.
    * ``sessions`` (portal) is not an HTTP session at all -- what a peer gets
      for authenticating there is *network* access, expressed in nftables. See
      ``api/routes/portal.py``.

    The cookie itself is a signed JWT the proxy verifies without asking anyone,
    so this row is not consulted on the request path. It exists for two things
    the JWT cannot do: telling an administrator who is signed in where, and
    revocation -- the ``jti`` of a revoked row is pushed into a HAProxy map, and
    that is what makes "sign this person out now" mean now rather than "within
    the token lifetime".
    """

    __tablename__ = "sso_sessions"
    __table_args__ = (
        Index("ix_sso_sessions_user", "user_id"),
        Index("ix_sso_sessions_expires", "expires_at"),
    )

    #: Also the JWT's ``jti``. One value, so a revocation entry needs no lookup.
    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    #: Where the browser was when it signed in. Read from the header the proxy
    #: sets and the caller cannot forge, never from the TCP peer -- behind the
    #: proxy that would be the gateway itself, every time.
    source_ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(255))
    expires_at: Mapped[datetime] = mapped_column(TimestampColumn, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(TimestampColumn)
    created_at: Mapped[datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )

    user: Mapped[User] = relationship(lazy="joined")
