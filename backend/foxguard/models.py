"""SQLAlchemy models — the single source of truth for the dataplane.

Extensibility notes for the Phase 5 roadmap (kept cheap on purpose):

* ``groups.kind`` already distinguishes ``group`` from ``zone`` and
  ``groups.parent_id`` allows nesting, so network zones with their own routes /
  exit nodes can land without a table rewrite.
* ACL endpoints are modelled as ``(kind, group_id, cidr)`` rather than a bare
  ``src_group_id``. Adding a ``zone`` endpoint kind is one enum value, not a
  migration of every rule.
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
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .nftables.model import Action, EndpointKind, PeerState, PeerType, Protocol


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

    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
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
    groups: Mapped[list[Group]] = relationship(
        secondary="peer_groups", back_populates="peers", lazy="selectin"
    )
    tags: Mapped[list[Tag]] = relationship(
        secondary="peer_tags", back_populates="peers", lazy="selectin"
    )


class AclRule(Base):
    __tablename__ = "acl_rules"
    __table_args__ = (
        CheckConstraint(
            "(src_kind <> 'group' OR src_group_id IS NOT NULL) AND "
            "(src_kind <> 'cidr' OR src_cidr IS NOT NULL)",
            name="ck_acl_src_consistent",
        ),
        CheckConstraint(
            "(dst_kind <> 'group' OR dst_group_id IS NOT NULL) AND "
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
