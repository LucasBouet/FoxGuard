"""Pydantic request/response models for the admin API."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
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

from .clientconfig import AllowedIpsMode
from .dns import RecordKind, ResolverMode
from .models import (
    ActorType,
    AuthMethod,
    GroupKind,
    RulesetStatus,
    ServiceAuthKind,
    ServiceExposure,
    ServiceFilterKind,
    ServiceKind,
    ServiceScope,
)
from .nftables import Action, EndpointKind, PeerState, PeerType, Protocol
from .services.killswitch import CONFIRMATION as KILL_SWITCH_CONFIRMATION
from .services.killswitch import KillSwitchMode

SLUG_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,23}$"
REF_PATTERN = r"^[A-Za-z0-9_.:-]{1,64}$"

#: One DNS label (RFC 1123). Underscores are excluded: legal in some record
#: types, not in host names, and resolvers disagree about how strict to be.
DNS_LABEL_PATTERN = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
#: A zone-relative name, which may carry dots: ``git.services``.
DNS_NAME_PATTERN = (
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)

Slug = Annotated[str, Field(pattern=SLUG_PATTERN, max_length=24)]
Ref = Annotated[str, Field(pattern=REF_PATTERN, max_length=64)]
Port = Annotated[int, Field(ge=1, le=65535)]
DnsLabel = Annotated[str, Field(pattern=DNS_LABEL_PATTERN, max_length=63)]
DnsName = Annotated[str, Field(pattern=DNS_NAME_PATTERN, max_length=253)]

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
# zones
# --------------------------------------------------------------------------- #


class ZoneRouteBase(ApiModel):
    cidr: str = Field(max_length=64)
    #: The peer that carries this network. Omitted, the gateway is assumed to
    #: reach it directly (a LAN behind the gateway) and no tunnel route is
    #: installed for it.
    via_peer_id: uuid.UUID | None = None
    description: str | None = None
    enabled: bool = True

    @field_validator("cidr")
    @classmethod
    def _check_cidr(cls, value: str) -> str:
        network = ipaddress.ip_network(value, strict=False)
        if network.prefixlen == 0:
            raise ValueError(
                "a zone route may not be a default route: the gateway would "
                "route its own traffic into the tunnel and lose every remote "
                "session, including the one making this request"
            )
        return str(network)


class ZoneRouteCreate(ZoneRouteBase):
    pass


class ZoneRouteUpdate(ApiModel):
    via_peer_id: uuid.UUID | None = None
    description: str | None = None
    enabled: bool | None = None


class ZoneRouteRead(ZoneRouteBase):
    id: uuid.UUID
    zone_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class ZoneBase(ApiModel):
    name: str = Field(max_length=128)
    description: str | None = None
    internet_exit: bool = False
    #: Off by default. Everywhere else in Foxguard access is denied until
    #: something grants it, and a zone is not the exception.
    intra_zone: bool = False
    session_lifetime_seconds: int | None = Field(default=None, ge=60)


class ZoneCreate(ZoneBase):
    slug: Slug


class ZoneUpdate(ApiModel):
    name: str | None = Field(default=None, max_length=128)
    description: str | None = None
    internet_exit: bool | None = None
    intra_zone: bool | None = None
    session_lifetime_seconds: int | None = Field(default=None, ge=60)


class ZoneRead(ZoneBase):
    id: uuid.UUID
    slug: str
    routes: list[ZoneRouteRead] = Field(default_factory=list)
    peer_count: int = 0
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
    #: Name inside FOXGUARD_DNS_ZONE. Left empty, one is derived from ``name``;
    #: a derivation that collides is a 409, never a silent ``laptop-2``.
    dns_label: DnsLabel | None = None
    #: The one zone this peer sits in. Groups are a separate, many-valued thing.
    zone_slug: Slug | None = None

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
    dns_label: DnsLabel | None = None
    zone_slug: Slug | None = None

    @model_validator(mode="before")
    @classmethod
    def _refuse_rekeying(cls, data: Any) -> Any:
        """A key cannot be swapped on a live peer, and saying so beats ignoring it.

        Unknown fields are dropped by default, so this used to answer 200 and
        change nothing -- and re-keying is precisely what an operator reaches
        for when a device's private key is lost. Identity here *is* the key
        pair: the address, the DNS name, the group and zone membership and the
        audit trail all hang off a peer whose public key was fixed when it was
        registered. Replacing it in place would leave every one of those
        pointing at a device that can no longer prove it is the same one.
        """
        if isinstance(data, dict) and "wg_public_key" in data:
            raise ValueError(
                "a peer's public key cannot be changed: delete this peer and "
                "register it again with the new key (the dashboard's config "
                "generator does both, and makes the keypair in your browser)"
            )
        return data


class PeerRead(PeerBase):
    id: uuid.UUID
    peer_type: PeerType
    state: PeerState
    wg_public_key: str
    wg_interface: str
    tunnel_ip: IpString | None
    tunnel_ip6: IpString | None
    owner_user_id: uuid.UUID | None
    dns_label: str | None = None
    zone_slug: str | None = None
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
# DNS records
# --------------------------------------------------------------------------- #


class DnsRecordBase(ApiModel):
    #: Relative to FOXGUARD_DNS_ZONE. Storing it qualified would orphan every
    #: record the day the zone is renamed.
    name: DnsName
    kind: RecordKind
    #: An IP address for A/AAAA, another record's relative name for CNAME.
    value: str = Field(max_length=253)
    description: str | None = None
    enabled: bool = True

    @model_validator(mode="after")
    def _value_matches_the_kind(self) -> DnsRecordBase:
        if self.kind is RecordKind.CNAME:
            if not re.match(DNS_NAME_PATTERN, self.value):
                raise ValueError("a CNAME value must be a DNS name")
            return self
        address = ipaddress.ip_address(self.value)
        expected = 4 if self.kind is RecordKind.A else 6
        if address.version != expected:
            raise ValueError(f"an {self.kind.value} record needs an IPv{expected} address")
        return self


class DnsRecordCreate(DnsRecordBase):
    pass


class DnsRecordUpdate(ApiModel):
    """Every field optional, but ``kind`` and ``value`` still have to agree.

    They are re-checked in the route against the merged row rather than here:
    a PATCH carrying only ``value`` has no ``kind`` to validate it against.
    """

    name: DnsName | None = None
    kind: RecordKind | None = None
    value: str | None = Field(default=None, max_length=253)
    description: str | None = None
    enabled: bool | None = None


class DnsRecordRead(DnsRecordBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class DnsZoneRead(ApiModel):
    """What the zone currently looks like, rendered from the database."""

    enabled: bool
    zone: str
    mode: ResolverMode
    listen_addresses: list[str]
    upstreams: list[str]
    digest: str | None = None
    hosts: str | None = None
    conf: str | None = None
    #: Populated instead of the artefacts when the state cannot be rendered.
    errors: list[str] = Field(default_factory=list)
    #: Things that are not being served but do not stop the zone rendering --
    #: an alias whose target was revoked, typically.
    warnings: list[str] = Field(default_factory=list)


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
    #: Zones and groups both live in the ``groups`` table, so one column stores
    #: either. The field is separate here because the *caller* should have to
    #: say which it means: a rule reading ``zone_slug: office`` and one reading
    #: ``group_slug: office`` would otherwise be indistinguishable in an export.
    zone_slug: Slug | None = None
    cidr: str | None = None

    @field_validator("cidr")
    @classmethod
    def _check_cidr(cls, value: str | None) -> str | None:
        return _validate_cidr(value)

    @model_validator(mode="after")
    def _consistent(self) -> AclEndpoint:
        if self.kind is EndpointKind.GROUP and not self.group_slug:
            raise ValueError("kind=group requires group_slug")
        if self.kind is EndpointKind.ZONE and not self.zone_slug:
            raise ValueError("kind=zone requires zone_slug")
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


class ClientConfigProfile(ApiModel):
    """The non-secret half of a WireGuard client configuration.

    Structured rather than a rendered ``.conf`` on purpose. The file is
    assembled in the browser, where the private key was generated and where it
    stays; an endpoint that returned finished text would invite a future caller
    to POST the private key up so the server could "just do it", and that is the
    one thing this design exists to make impossible.
    """

    peer_id: uuid.UUID
    peer_name: str
    peer_state: PeerState
    #: Name inside the internal zone, when the resolver is on. Informational --
    #: the config does not contain it.
    fqdn: str | None = None

    addresses: list[str]
    dns: list[str]
    mtu: int | None = None

    server_public_key: str | None = None
    endpoint: str | None = None
    allowed_ips: list[str]
    persistent_keepalive: int

    allowed_ips_mode: AllowedIpsMode
    excluded_routes: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    #: False when something the operator has to configure is missing. The
    #: dashboard offers no download in that state.
    complete: bool


class AgentWireGuardPeer(ApiModel):
    public_key: str
    allowed_ips: list[str]


class AgentRoute(ApiModel):
    """A network the gateway must route into the tunnel.

    Only routes carried *by a peer* appear here. A zone route with no
    ``via_peer_id`` is a network the gateway already reaches on its own, and
    installing a tunnel route for it would break the path that works.
    """

    cidr: str
    #: The peer that carries it, for the agent's logs and for the audit trail.
    via_peer_id: uuid.UUID


class AgentDnsState(ApiModel):
    """The rendered zone, or nothing at all.

    Absent when DNS is disabled *or* when the current database state cannot be
    rendered into a valid zone. Both mean the same thing to the agent -- leave
    the resolver exactly as it is -- and neither may stop the ruleset in the
    same response from being applied.
    """

    digest: str
    hosts: str
    conf: str
    hosts_path: str
    conf_path: str


class AgentProxyState(ApiModel):
    """The rendered proxy configuration, or nothing at all.

    Absent when the proxy is disabled *or* when the current state cannot be
    rendered. Both mean the same thing to the agent -- leave the proxy exactly
    as it is -- and neither may stop the ruleset in the same response from
    being applied.

    ``files`` are the pattern files the configuration references, keyed by base
    name. They travel together because ``haproxy -c`` resolves ``-f`` at parse
    time: a configuration whose maps are not yet on disk does not validate.
    """

    digest: str
    conf: str
    conf_path: str
    maps_dir: str
    certs_dir: str
    runtime_socket: str
    files: dict[str, str] = Field(default_factory=dict)


class AgentStateResponse(ApiModel):
    """Everything the gateway agent needs for one reconciliation pass."""

    digest: str
    ruleset: str
    wg_interface: str
    wg_peers: list[AgentWireGuardPeer]
    routes: list[AgentRoute] = Field(default_factory=list)
    #: Carries its own digest: the ruleset digest identifies a row in
    #: ``ruleset_versions`` and must keep meaning exactly that.
    dns: AgentDnsState | None = None
    proxy: AgentProxyState | None = None


class AgentReport(ApiModel):
    digest: str
    success: bool
    error: str | None = None
    #: Reported separately so a resolver that will not reload cannot be mistaken
    #: for a ruleset that would not apply.
    dns_digest: str | None = None
    dns_error: str | None = None
    proxy_digest: str | None = None
    proxy_error: str | None = None


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


# --------------------------------------------------------------------------- #
# published services (Phase 6)
# --------------------------------------------------------------------------- #


class ServiceAuthBase(ApiModel):
    kind: ServiceAuthKind
    scope: ServiceScope = ServiceScope.BOTH
    enabled: bool = True
    priority: int = 100
    realm: str | None = Field(default=None, max_length=64)


class ServiceAuthCreate(ServiceAuthBase):
    pass


class ServiceAuthRead(ServiceAuthBase):
    id: uuid.UUID
    created_at: datetime


class ServiceFilterBase(ApiModel):
    kind: ServiceFilterKind
    scope: ServiceScope = ServiceScope.BOTH
    enabled: bool = True
    priority: int = 100
    values: list[str] = Field(default_factory=list)
    rate: int | None = Field(default=None, ge=1)
    period_seconds: int | None = Field(default=None, ge=1)

    @field_validator("values")
    @classmethod
    def _validate_values(cls, value: list[str]) -> list[str]:
        for item in value:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ValueError(f"{item!r} is not an address or prefix") from exc
        return value

    @model_validator(mode="after")
    def _rate_needs_both(self) -> ServiceFilterBase:
        if self.kind is ServiceFilterKind.RATE_LIMIT and not (
            self.rate and self.period_seconds
        ):
            raise ValueError("a rate limit needs both a rate and a period")
        if self.kind in (ServiceFilterKind.IP_ALLOW, ServiceFilterKind.IP_DENY) and not (
            self.values
        ):
            # An empty allow list denies everything, which is never what anyone
            # meant to type.
            raise ValueError(f"an {self.kind.value} filter needs at least one address")
        return self


class ServiceFilterCreate(ServiceFilterBase):
    pass


class ServiceFilterRead(ServiceFilterBase):
    id: uuid.UUID
    created_at: datetime


class ServiceAccessBase(ApiModel):
    action: Action = Action.ACCEPT
    kind: EndpointKind
    group_id: uuid.UUID | None = None
    cidr: str | None = None
    priority: int = 100

    @model_validator(mode="after")
    def _consistent(self) -> ServiceAccessBase:
        if self.kind in (EndpointKind.GROUP, EndpointKind.ZONE) and not self.group_id:
            raise ValueError(f"a {self.kind.value} endpoint needs group_id")
        if self.kind is EndpointKind.CIDR and not self.cidr:
            raise ValueError("a cidr endpoint needs cidr")
        if self.cidr:
            try:
                ipaddress.ip_network(self.cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"{self.cidr!r} is not a prefix") from exc
        return self


class ServiceAccessCreate(ServiceAccessBase):
    pass


class ServiceAccessRead(ServiceAccessBase):
    id: uuid.UUID
    group_slug: str | None = None
    created_at: datetime


class ServiceBase(ApiModel):
    slug: str = Field(pattern=SLUG_PATTERN, max_length=24)
    name: str = Field(max_length=128)
    description: str | None = None
    enabled: bool = True
    kind: ServiceKind
    exposure: ServiceExposure = ServiceExposure.INTERNAL
    upstream_peer_id: uuid.UUID | None = None
    upstream_host: str
    upstream_port: int = Field(ge=1, le=65535)
    upstream_tls: bool = False
    upstream_tls_verify: bool = False
    internal_hostname: str | None = Field(default=None, max_length=255)
    external_hostname: str | None = Field(default=None, max_length=255)
    #: Omit for a plain-TCP service and one is allocated from the configured
    #: range. Plain TCP has no SNI and no Host header, so it cannot share a port.
    listen_port: int | None = Field(default=None, ge=1, le=65535)
    sni_hostname: str | None = Field(default=None, max_length=255)
    health_check: bool = False
    health_check_interval: int = Field(default=30, ge=1)

    @field_validator("upstream_host")
    @classmethod
    def _validate_upstream(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(
                f"{value!r} is not an IP address. The upstream must be an address "
                "inside the tunnel or behind a peer's routes, not a name -- the "
                "control plane checks reachability against AllowedIPs"
            ) from exc
        return value


class ServiceCreate(ServiceBase):
    """A service and the way in, in one request.

    The policy is not optional extra: a service exposed on a listener with no
    authenticator that applies there is refused by the renderer, so creating
    the two separately would make it impossible to ever create the first one.
    Publishing a service and saying how it is guarded are one decision.
    """

    authenticators: list[ServiceAuthCreate] = Field(default_factory=list)
    filters: list[ServiceFilterCreate] = Field(default_factory=list)
    access: list[ServiceAccessCreate] = Field(default_factory=list)


class ServiceUpdate(ApiModel):
    name: str | None = Field(default=None, max_length=128)
    description: str | None = None
    enabled: bool | None = None
    exposure: ServiceExposure | None = None
    upstream_peer_id: uuid.UUID | None = None
    upstream_host: str | None = None
    upstream_port: int | None = Field(default=None, ge=1, le=65535)
    upstream_tls: bool | None = None
    upstream_tls_verify: bool | None = None
    internal_hostname: str | None = Field(default=None, max_length=255)
    external_hostname: str | None = Field(default=None, max_length=255)
    listen_port: int | None = Field(default=None, ge=1, le=65535)
    sni_hostname: str | None = Field(default=None, max_length=255)
    health_check: bool | None = None
    health_check_interval: int | None = Field(default=None, ge=1)


class ServiceRead(ServiceBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    upstream_peer_name: str | None = None
    #: Which listeners the service currently has. Differs from ``exposure``
    #: when the upstream peer is not active -- see ``services/proxy.doors_for``.
    active_doors: ServiceExposure | None = None
    authenticators: list[ServiceAuthRead] = Field(default_factory=list)
    filters: list[ServiceFilterRead] = Field(default_factory=list)
    access: list[ServiceAccessRead] = Field(default_factory=list)
    token_count: int = 0
    account_count: int = 0


class ServiceTokenCreate(ApiModel):
    name: str = Field(max_length=128)
    expires_at: datetime | None = None


class ServiceTokenRead(ApiModel):
    id: uuid.UUID
    name: str
    prefix: str
    expires_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class ServiceTokenCreated(ServiceTokenRead):
    #: The only time the plaintext exists outside the caller's memory.
    token: str


class ServiceAccountCreate(ApiModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$", max_length=64)


class ServiceAccountRead(ApiModel):
    id: uuid.UUID
    username: str
    revoked_at: datetime | None
    created_at: datetime


class ServiceAccountCreated(ServiceAccountRead):
    #: Generated, high-entropy, and shown once. That is what allows the hash on
    #: the gateway to be sha-512-crypt rather than argon2.
    password: str


class ImplicitPathRead(ApiModel):
    """A gateway-to-upstream path a published service has opened.

    Not enforced by nftables -- Foxguard creates no ``output`` chain, by design.
    Surfaced so the path is never invisible.
    """

    service: str
    source: str
    destination: str
    peer: str | None
    protocol: str
    port: int
    enforced_by: str


class SsoSessionRead(ApiModel):
    """A browser session on a published service.

    No token, not even a prefix of one: the cookie is a signed JWT the proxy
    verifies on its own, so there is nothing stored here that could be shown.
    """

    id: uuid.UUID
    username: str | None
    source_ip: str | None
    user_agent: str | None
    expires_at: datetime
    created_at: datetime


class ProxyStatusRead(ApiModel):
    enabled: bool
    domain: str | None
    internal_binds: list[str]
    external_binds: list[str]
    service_count: int
    digest: str | None
    config: str | None
    files: dict[str, str] = Field(default_factory=dict)
    implicit_paths: list[ImplicitPathRead] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
