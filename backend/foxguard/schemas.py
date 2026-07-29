"""Pydantic request/response models for the admin API."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from .models import ActorType, AuthMethod, GroupKind, RulesetStatus
from .nftables import Action, EndpointKind, PeerState, PeerType, Protocol
from .services.killswitch import CONFIRMATION as KILL_SWITCH_CONFIRMATION
from .services.killswitch import KillSwitchMode

SLUG_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,23}$"
REF_PATTERN = r"^[A-Za-z0-9_.:-]{1,64}$"

Slug = Annotated[str, Field(pattern=SLUG_PATTERN, max_length=24)]
Ref = Annotated[str, Field(pattern=REF_PATTERN, max_length=64)]
Port = Annotated[int, Field(ge=1, le=65535)]

_IP_TYPES = (
    ipaddress.IPv4Address,
    ipaddress.IPv6Address,
    ipaddress.IPv4Interface,
    ipaddress.IPv6Interface,
)


def _coerce_ip(value: Any) -> Any:
    """Accept what psycopg actually hands back for a PostgreSQL ``INET`` column.

    psycopg 3 returns ``ipaddress`` objects, not strings, so a response model
    annotated ``str`` fails validation and the endpoint 500s. Serialising ORM
    rows directly is the normal case here, so the coercion belongs in the type.
    """
    if isinstance(value, _IP_TYPES):
        return str(value)
    return value


#: A string field that also accepts the ipaddress objects psycopg returns.
IpString = Annotated[str, BeforeValidator(_coerce_ip)]


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=False)


def _validate_wg_key(value: str) -> str:
    """A WireGuard public key is 32 raw bytes in standard base64 (44 chars)."""
    candidate = value.strip()
    if len(candidate) != 44:
        raise ValueError("WireGuard public key must be 44 base64 characters")
    try:
        raw = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64 in WireGuard public key: {exc}") from exc
    if len(raw) != 32:
        raise ValueError("WireGuard public key must decode to 32 bytes")
    return candidate


def _validate_cidr(value: str | None) -> str | None:
    if value is None:
        return None
    return str(ipaddress.ip_network(value, strict=False))


# --------------------------------------------------------------------------- #
# groups
# --------------------------------------------------------------------------- #


class GroupBase(ApiModel):
    name: str = Field(max_length=128)
    description: str | None = None
    kind: GroupKind = GroupKind.GROUP
    internet_exit: bool = False
    session_lifetime_seconds: int | None = Field(default=None, ge=60)


class GroupCreate(GroupBase):
    slug: Slug
    parent_id: uuid.UUID | None = None


class GroupUpdate(ApiModel):
    name: str | None = Field(default=None, max_length=128)
    description: str | None = None
    internet_exit: bool | None = None
    session_lifetime_seconds: int | None = Field(default=None, ge=60)
    parent_id: uuid.UUID | None = None


class GroupRead(GroupBase):
    id: uuid.UUID
    slug: str
    parent_id: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime


# --------------------------------------------------------------------------- #
# tags
# --------------------------------------------------------------------------- #


class TagCreate(ApiModel):
    name: str = Field(max_length=64)
    color: str | None = Field(default=None, max_length=16)


class TagRead(TagCreate):
    id: uuid.UUID


# --------------------------------------------------------------------------- #
# users
# --------------------------------------------------------------------------- #


class UserBase(ApiModel):
    username: str = Field(max_length=64, pattern=r"^[A-Za-z0-9._@-]{1,64}$")
    email: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    is_admin: bool = False
    is_active: bool = True


class UserCreate(UserBase):
    #: Optional: a user may exist with an OIDC binding only.
    password: str | None = Field(default=None, min_length=12, max_length=256)
    external_idp_issuer: str | None = None
    external_idp_subject: str | None = None

    @model_validator(mode="after")
    def _needs_a_credential(self) -> UserCreate:
        if not self.password and not self.external_idp_subject:
            raise ValueError(
                "a user needs either a password (local auth) or an "
                "external_idp_subject (OIDC)"
            )
        if self.external_idp_subject and not self.external_idp_issuer:
            raise ValueError("external_idp_subject requires external_idp_issuer")
        return self


class UserUpdate(ApiModel):
    email: str | None = None
    display_name: str | None = None
    is_admin: bool | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)
    external_idp_issuer: str | None = None
    external_idp_subject: str | None = None


class UserRead(UserBase):
    id: uuid.UUID
    totp_enabled: bool
    last_login_at: datetime | None
    created_at: datetime
    auth_methods: list[AuthMethod] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# peers
# --------------------------------------------------------------------------- #


class PeerBase(ApiModel):
    name: str = Field(max_length=128)
    description: str | None = None


class PeerCreate(PeerBase):
    peer_type: PeerType
    wg_public_key: str
    owner_user_id: uuid.UUID | None = None
    group_slugs: list[Slug] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    #: Optional fixed address. Left empty, the next free pool address is used.
    tunnel_ip: str | None = None
    tunnel_ip6: str | None = None

    @field_validator("wg_public_key")
    @classmethod
    def _check_key(cls, value: str) -> str:
        return _validate_wg_key(value)

    @model_validator(mode="after")
    def _user_peers_need_an_owner(self) -> PeerCreate:
        # The peer <-> user binding is done at registration time, never inferred
        # from the source IP at request time.
        if self.peer_type is PeerType.USER and self.owner_user_id is None:
            raise ValueError("a user peer must be bound to owner_user_id at creation")
        return self


class PeerUpdate(ApiModel):
    name: str | None = Field(default=None, max_length=128)
    description: str | None = None
    state: PeerState | None = None
    owner_user_id: uuid.UUID | None = None
    group_slugs: list[Slug] | None = None
    tags: list[str] | None = None


class PeerRead(PeerBase):
    id: uuid.UUID
    peer_type: PeerType
    state: PeerState
    wg_public_key: str
    wg_interface: str
    tunnel_ip: IpString | None
    tunnel_ip6: IpString | None
    owner_user_id: uuid.UUID | None
    group_slugs: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    enrollment_key_expires_at: datetime | None = None
    enrolled_at: datetime | None = None
    last_handshake_at: datetime | None = None
    last_authenticated_at: datetime | None = None
    created_at: datetime


class EnrollmentKeyCreate(ApiModel):
    expires_at: datetime | None = Field(
        default=None,
        description="Optional expiry; the key stops working then, even without revocation.",
    )


class EnrollmentKeyRead(ApiModel):
    peer_id: uuid.UUID
    #: Shown exactly once. Only its hash is stored.
    enrollment_key: str
    expires_at: datetime | None


# --------------------------------------------------------------------------- #
# TOTP (admin-side provisioning)
# --------------------------------------------------------------------------- #


class TotpProvisionRead(ApiModel):
    #: Shown exactly once, like an enrollment key. Scan it or lose it.
    secret: str
    provisioning_uri: str
    #: False until a correct code is presented -- provisioning does not enforce.
    enabled: bool


class TotpConfirmRequest(ApiModel):
    code: str = Field(min_length=6, max_length=10)


# --------------------------------------------------------------------------- #
# administrator sign-in
# --------------------------------------------------------------------------- #


class AdminLoginRequest(ApiModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    totp_code: str | None = Field(default=None, max_length=10)


class AdminWhoAmI(ApiModel):
    #: None when authenticated with the static machine token.
    user_id: uuid.UUID | None
    username: str
    display_name: str | None
    totp_enabled: bool
    #: "session" for a signed-in person, "token" for automation.
    via: Literal["session", "token"]


class AdminLoginResponse(ApiModel):
    #: Bearer credential, returned once. Send it as `Authorization: Bearer`.
    token: str
    expires_at: datetime
    user: AdminWhoAmI


class AdminSessionRead(ApiModel):
    id: uuid.UUID
    user_id: uuid.UUID
    username: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    source_ip: IpString | None
    user_agent: str | None
    #: True for the session making this request, so the UI can label it and
    #: warn before someone signs themselves out from a list.
    current: bool = False


class AdminOidcStartResponse(ApiModel):
    authorization_url: str
    state: str


class AdminOidcCompleteRequest(ApiModel):
    state: str
    code: str


# --------------------------------------------------------------------------- #
# enrollment (server peers, called by the device from inside the tunnel)
# --------------------------------------------------------------------------- #


class EnrollRequest(ApiModel):
    enrollment_key: str = Field(min_length=8, max_length=256)
    #: Optional cross-check. When present it must match the public key of the
    #: peer holding the source address, which catches a device that was given
    #: another machine's key by a bad provisioning script.
    wg_public_key: str | None = None


class EnrollResponse(ApiModel):
    peer_id: uuid.UUID
    name: str
    state: PeerState
    tunnel_ip: IpString | None
    tunnel_ip6: IpString | None
    group_slugs: list[str] = Field(default_factory=list)
    enrolled_at: datetime | None


# --------------------------------------------------------------------------- #
# captive portal (user peers)
# --------------------------------------------------------------------------- #


class PortalStatusRead(ApiModel):
    """What the portal UI needs to decide which form to show.

    Nothing here is a secret: it is all derived from the peer that owns the
    calling tunnel address, which already proves possession of its private key.
    """

    peer_id: uuid.UUID
    peer_name: str
    peer_type: PeerType
    state: PeerState
    authenticated: bool
    username: str | None = None
    auth_methods: list[AuthMethod] = Field(default_factory=list)
    totp_required: bool = False
    oidc_available: bool = False
    session_expires_at: datetime | None = None


class PortalLoginRequest(ApiModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    #: Required when the account has TOTP enabled, ignored otherwise.
    totp_code: str | None = Field(default=None, max_length=10)


class PortalLoginResponse(ApiModel):
    peer_id: uuid.UUID
    state: PeerState
    username: str
    auth_method: AuthMethod
    group_slugs: list[str] = Field(default_factory=list)
    session_expires_at: datetime | None = None


class PortalLogoutResponse(ApiModel):
    peer_id: uuid.UUID
    state: PeerState


class OidcStartResponse(ApiModel):
    authorization_url: str
    state: str


# --------------------------------------------------------------------------- #
# sessions (Phase 3)
# --------------------------------------------------------------------------- #


class PeerSessionRead(ApiModel):
    id: uuid.UUID
    peer_id: uuid.UUID
    peer_name: str
    user_id: uuid.UUID
    username: str
    auth_method: AuthMethod
    authenticated_at: datetime
    last_authenticated_at: datetime
    #: The stricter of the stored expiry and the one the peer's *current* groups
    #: imply, so moving a peer to a stricter group shows up here immediately.
    expires_at: datetime | None
    seconds_remaining: int | None
    source_ip: IpString | None


class ExpiredPeerRead(ApiModel):
    peer_id: uuid.UUID
    name: str
    tunnel_ip: IpString | None
    reason: str
    deadline: datetime | None


class SweepResultRead(ApiModel):
    expired: list[ExpiredPeerRead] = Field(default_factory=list)
    #: False when the sweep found nothing -- no new ruleset version is written
    #: for a no-op, which is what keeps digests stable.
    regenerated: bool
    #: False when another worker or a cron run held the advisory lock.
    ran: bool = True


# --------------------------------------------------------------------------- #
# kill switch (Phase 4)
# --------------------------------------------------------------------------- #


class KillSwitchRequest(ApiModel):
    mode: KillSwitchMode = Field(
        default=KillSwitchMode.QUARANTINE,
        description=(
            "quarantine: active peers go back to quarantine and must "
            "re-authenticate -- note a server peer re-enrolls automatically "
            "within one poll. lockdown: every peer is disabled and only an "
            "administrator can bring it back. Use lockdown for a suspected "
            "compromise."
        ),
    )
    #: Must equal the phrase for the chosen mode. Deliberately awkward: this is
    #: the one endpoint where a stray POST would take the whole fleet down.
    confirm: str

    @model_validator(mode="after")
    def _check_confirmation(self) -> KillSwitchRequest:
        expected = KILL_SWITCH_CONFIRMATION[self.mode]
        if self.confirm != expected:
            raise ValueError(
                f"confirm must be exactly {expected!r} to trigger mode {self.mode.value!r}"
            )
        return self


class AffectedPeerRead(ApiModel):
    peer_id: uuid.UUID
    name: str
    peer_type: PeerType
    previous_state: PeerState
    state: PeerState


class KillSwitchResultRead(ApiModel):
    mode: KillSwitchMode
    affected: list[AffectedPeerRead] = Field(default_factory=list)
    sessions_revoked: int
    regenerated: bool


# --------------------------------------------------------------------------- #
# dashboard (Phase 4)
# --------------------------------------------------------------------------- #


class RulesetHealth(ApiModel):
    """Whether the box is running what the database says it should."""

    digest: str
    applied_digest: str | None = None
    status: RulesetStatus | None = None
    applied_at: datetime | None = None
    #: False when the agent has not (yet) reported applying the current ruleset.
    in_sync: bool = False


class DashboardRead(ApiModel):
    peers_total: int
    peers_by_state: dict[str, int]
    peers_by_type: dict[str, int]
    active_sessions: int
    groups: int
    acl_rules: int
    acl_rules_disabled: int
    users: int
    ruleset: RulesetHealth
    recent_audit: list[AuditLogRead] = Field(default_factory=list)


class MatrixCell(ApiModel):
    """One (source, destination) pair and the rules that connect it."""

    src: str
    dst: str
    action: Action
    rule_refs: list[str] = Field(default_factory=list)


class PolicyMatrixRead(ApiModel):
    #: Group slugs plus the pseudo-endpoints `any` and any CIDR literals used.
    sources: list[str] = Field(default_factory=list)
    destinations: list[str] = Field(default_factory=list)
    cells: list[MatrixCell] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# ACL rules
# --------------------------------------------------------------------------- #


class AclEndpoint(ApiModel):
    kind: EndpointKind = EndpointKind.ANY
    group_slug: Slug | None = None
    cidr: str | None = None

    @field_validator("cidr")
    @classmethod
    def _check_cidr(cls, value: str | None) -> str | None:
        return _validate_cidr(value)

    @model_validator(mode="after")
    def _consistent(self) -> AclEndpoint:
        if self.kind is EndpointKind.GROUP and not self.group_slug:
            raise ValueError("kind=group requires group_slug")
        if self.kind is EndpointKind.CIDR and not self.cidr:
            raise ValueError("kind=cidr requires cidr")
        return self


class AclRuleBase(ApiModel):
    name: str = Field(max_length=128)
    description: str | None = None
    priority: int = Field(default=100, ge=0, le=100000)
    enabled: bool = True
    action: Action
    src: AclEndpoint
    dst: AclEndpoint
    protocol: Protocol = Protocol.ANY
    dst_port_start: Port | None = None
    dst_port_end: Port | None = None

    @model_validator(mode="after")
    def _check_ports(self) -> AclRuleBase:
        if self.dst_port_start is None and self.dst_port_end is not None:
            raise ValueError("dst_port_end requires dst_port_start")
        if self.dst_port_start is not None and self.protocol not in (
            Protocol.TCP,
            Protocol.UDP,
        ):
            raise ValueError("ports are only valid with protocol tcp or udp")
        if (
            self.dst_port_start is not None
            and self.dst_port_end is not None
            and self.dst_port_end < self.dst_port_start
        ):
            raise ValueError("dst_port_end must be >= dst_port_start")
        return self


class AclRuleCreate(AclRuleBase):
    ref: Ref


class AclRuleUpdate(ApiModel):
    name: str | None = None
    description: str | None = None
    priority: int | None = Field(default=None, ge=0, le=100000)
    enabled: bool | None = None
    action: Action | None = None
    src: AclEndpoint | None = None
    dst: AclEndpoint | None = None
    protocol: Protocol | None = None
    dst_port_start: Port | None = None
    dst_port_end: Port | None = None


class AclRuleRead(AclRuleBase):
    id: uuid.UUID
    ref: str
    created_at: datetime
    updated_at: datetime


# --------------------------------------------------------------------------- #
# policy documents (import / export)
# --------------------------------------------------------------------------- #


class PolicyGroupDocument(ApiModel):
    slug: Slug
    name: str | None = None
    description: str | None = None
    kind: GroupKind = GroupKind.GROUP
    internet_exit: bool = False
    session_lifetime_seconds: int | None = None


class PolicyRuleDocument(ApiModel):
    ref: Ref
    name: str | None = None
    description: str | None = None
    priority: int = 100
    enabled: bool = True
    action: Action
    src_kind: EndpointKind = EndpointKind.ANY
    src_group: Slug | None = None
    src_cidr: str | None = None
    dst_kind: EndpointKind = EndpointKind.ANY
    dst_group: Slug | None = None
    dst_cidr: str | None = None
    protocol: Protocol = Protocol.ANY
    dst_port_start: Port | None = None
    dst_port_end: Port | None = None

    @field_validator("src_cidr", "dst_cidr")
    @classmethod
    def _check_cidr(cls, value: str | None) -> str | None:
        return _validate_cidr(value)


class PolicyDocument(ApiModel):
    version: Literal[1] = 1
    groups: list[PolicyGroupDocument] = Field(default_factory=list)
    acl_rules: list[PolicyRuleDocument] = Field(default_factory=list)


class PolicyImportRequest(ApiModel):
    document: PolicyDocument
    dry_run: bool = Field(
        default=True,
        description="Default true: you must opt in explicitly to mutate the ACLs.",
    )
    prune: bool = Field(
        default=False,
        description="Delete groups/rules absent from the document (git-style sync).",
    )


class PolicyDiffResponse(ApiModel):
    dry_run: bool
    applied: bool
    summary: str
    groups_created: list[str]
    groups_updated: list[dict[str, Any]]
    groups_deleted: list[str]
    rules_created: list[str]
    rules_updated: list[dict[str, Any]]
    rules_deleted: list[str]
    ruleset_digest: str | None = None


# --------------------------------------------------------------------------- #
# ruleset / agent
# --------------------------------------------------------------------------- #


class RulesetPreview(ApiModel):
    digest: str
    content: str


class RulesetVersionRead(ApiModel):
    id: uuid.UUID
    digest: str
    status: RulesetStatus
    created_at: datetime
    applied_at: datetime | None
    error: str | None
    generated_by: str | None


class AgentWireGuardPeer(ApiModel):
    public_key: str
    allowed_ips: list[str]


class AgentStateResponse(ApiModel):
    """Everything the gateway agent needs for one reconciliation pass."""

    digest: str
    ruleset: str
    wg_interface: str
    wg_peers: list[AgentWireGuardPeer]


class AgentReport(ApiModel):
    digest: str
    success: bool
    error: str | None = None


class AuditLogRead(ApiModel):
    id: uuid.UUID
    created_at: datetime
    actor_type: ActorType
    actor_label: str | None
    action: str
    object_type: str | None
    object_id: str | None
    source_ip: IpString | None
    detail: dict[str, Any]
