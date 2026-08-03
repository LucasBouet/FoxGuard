"""Pure data model consumed by the nftables ruleset generator.

The generator is deliberately decoupled from the database and from the network:
:class:`RulesetSpec` is a frozen description of *what* must be enforced, and
:mod:`foxguard.nftables.generator` turns it into an ``nft`` script.

Everything that can lock you out of the gateway lives behind this boundary, so
it can be unit-tested without a database, without root, and without the ``nft``
binary being installed.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "Action",
    "Endpoint",
    "EndpointKind",
    "Family",
    "GatewayInputPolicy",
    "GatewaySpec",
    "GroupSpec",
    "PeerSpec",
    "PeerState",
    "PeerType",
    "Protocol",
    "RouteSpec",
    "RuleSpec",
    "RulesetSpec",
    "ZoneSpec",
    "FAMILIES",
]


class Family(str, Enum):
    """IP family. ``inet`` tables carry both, so most rules are emitted twice."""

    V4 = "ipv4"
    V6 = "ipv6"

    @property
    def addr_kw(self) -> str:
        """nft keyword used for address matches (``ip saddr`` / ``ip6 saddr``)."""
        return "ip" if self is Family.V4 else "ip6"

    @property
    def suffix(self) -> str:
        return "v4" if self is Family.V4 else "v6"

    @property
    def nfproto(self) -> str:
        return "ipv4" if self is Family.V4 else "ipv6"

    @property
    def set_type(self) -> str:
        return "ipv4_addr" if self is Family.V4 else "ipv6_addr"

    @property
    def version(self) -> int:
        return 4 if self is Family.V4 else 6


#: Deterministic iteration order. Never iterate over ``Family`` directly in the
#: generator: output byte-stability is a hard requirement (see idempotence).
FAMILIES: tuple[Family, ...] = (Family.V4, Family.V6)


class PeerState(str, Enum):
    """Lifecycle of a peer, as far as the *dataplane* is concerned.

    ``STAGING``     pubkey registered, enrollment key not yet presented.
    ``QUARANTINED`` known peer without a valid session (user peers).
    ``ACTIVE``      peer is a member of its groups and subject to ACL rules.
    ``DISABLED``    administratively paused; no dataplane presence at all.
    ``REVOKED``     terminal state; the WireGuard peer entry is removed too.
    """

    STAGING = "staging"
    QUARANTINED = "quarantined"
    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"

    @property
    def is_confined(self) -> bool:
        """True when the peer may only reach the portal / enrollment endpoint."""
        return self in (PeerState.STAGING, PeerState.QUARANTINED)

    @property
    def is_active(self) -> bool:
        return self is PeerState.ACTIVE


class PeerType(str, Enum):
    SERVER = "server"
    USER = "user"


class Action(str, Enum):
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"


class Protocol(str, Enum):
    ANY = "any"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"

    @property
    def supports_ports(self) -> bool:
        return self in (Protocol.TCP, Protocol.UDP)


class EndpointKind(str, Enum):
    ANY = "any"
    GROUP = "group"
    CIDR = "cidr"
    #: A whole network zone: its member peers *and* the networks routed inside
    #: it. Distinct from ``GROUP`` because the two answer different questions --
    #: a group is a set of devices, a zone is a region of the address space.
    ZONE = "zone"


class GatewayInputPolicy(str, Enum):
    """How traffic from the tunnel *to the gateway itself* is treated.

    ``OPEN`` (default) — Foxguard confines quarantined peers but expresses no
    opinion about active peers reaching gateway-local services. Any other
    nftables table on the box (host firewall) still applies, because in
    nftables a ``drop`` in *any* table wins over an ``accept`` in ours.

    ``RESTRICTED`` — active peers may only reach the portal (plus DNS/ICMP when
    enabled); everything else arriving on the tunnel interface is dropped. Use
    once you are sure your management access does not transit the tunnel.
    """

    OPEN = "open"
    RESTRICTED = "restricted"


@dataclass(frozen=True, slots=True)
class Endpoint:
    """Source or destination of an ACL rule."""

    kind: EndpointKind
    group_slug: str | None = None
    cidr: str | None = None
    zone_slug: str | None = None

    @classmethod
    def any_(cls) -> Endpoint:
        return cls(kind=EndpointKind.ANY)

    @classmethod
    def group(cls, slug: str) -> Endpoint:
        return cls(kind=EndpointKind.GROUP, group_slug=slug)

    @classmethod
    def zone(cls, slug: str) -> Endpoint:
        return cls(kind=EndpointKind.ZONE, zone_slug=slug)

    @classmethod
    def network(cls, cidr: str) -> Endpoint:
        return cls(kind=EndpointKind.CIDR, cidr=cidr)

    @property
    def family(self) -> Family | None:
        """Family this endpoint pins the rule to, or ``None`` if family-agnostic."""
        if self.kind is not EndpointKind.CIDR or self.cidr is None:
            return None
        version = ipaddress.ip_network(self.cidr, strict=False).version
        return Family.V4 if version == 4 else Family.V6

    def describe(self) -> str:
        if self.kind is EndpointKind.ANY:
            return "any"
        if self.kind is EndpointKind.GROUP:
            return f"group:{self.group_slug}"
        if self.kind is EndpointKind.ZONE:
            return f"zone:{self.zone_slug}"
        return f"cidr:{self.cidr}"


@dataclass(frozen=True, slots=True)
class GroupSpec:
    """A group of peers -- a role, not a place. Rendered as a plain address set."""

    slug: str
    internet_exit: bool = False


@dataclass(frozen=True, slots=True)
class RouteSpec:
    """A network reachable inside a zone.

    ``via_peer_id`` is the peer that routes it. ``None`` means the gateway
    reaches it directly (a LAN behind the gateway), in which case nothing needs
    to be added to anybody's ``AllowedIPs`` and no tunnel route is installed --
    the CIDR only widens the zone's address set.
    """

    cidr: str
    via_peer_id: str | None = None
    comment: str | None = None


@dataclass(frozen=True, slots=True)
class ZoneSpec:
    """A network zone: the peers assigned to it plus the networks routed in it.

    Zones are rendered as *interval* sets, unlike groups, because they hold
    prefixes as well as host addresses. A peer belongs to at most one zone --
    the segment it sits in -- while it may hold any number of groups.
    """

    slug: str
    #: Whether members may reach each other without an explicit ACL rule.
    #: Defaults to off: everywhere else in Foxguard access is denied until
    #: something grants it, and a zone should not be the one exception.
    intra_zone: bool = False
    internet_exit: bool = False
    routes: tuple[RouteSpec, ...] = ()

    def route_cidrs(self, family: Family) -> tuple[str, ...]:
        return tuple(
            route.cidr
            for route in self.routes
            if ipaddress.ip_network(route.cidr, strict=False).version == family.version
        )


@dataclass(frozen=True, slots=True)
class PeerSpec:
    id: str
    name: str
    state: PeerState
    peer_type: PeerType = PeerType.USER
    tunnel_ip: str | None = None
    tunnel_ip6: str | None = None
    group_slugs: tuple[str, ...] = ()
    #: At most one. A peer is in one place and can play several roles.
    zone_slug: str | None = None

    def addresses(self, family: Family) -> tuple[str, ...]:
        value = self.tunnel_ip if family is Family.V4 else self.tunnel_ip6
        return (value,) if value else ()


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """One ACL rule. Rendered as one nft rule *per applicable family*."""

    id: str
    priority: int
    action: Action
    src: Endpoint
    dst: Endpoint
    protocol: Protocol = Protocol.ANY
    dst_port_start: int | None = None
    dst_port_end: int | None = None
    comment: str | None = None

    @property
    def sort_key(self) -> tuple[int, str]:
        """Rule evaluation order. Ties broken by id so output is stable."""
        return (self.priority, self.id)


@dataclass(frozen=True, slots=True)
class GatewaySpec:
    """Everything about the box itself that the ruleset depends on."""

    wg_interface: str = "wg0"
    wan_interface: str | None = None
    table_name: str = "foxguard"
    portal_port: int = 8080
    #: CIDRs Foxguard considers "internal". Used to make sure an ``internet_exit``
    #: group cannot reach internal networks without an explicit ACL rule.
    internal_cidrs: tuple[str, ...] = ()
    allow_dns_in_quarantine: bool = True
    allow_icmp_to_gateway: bool = True
    gateway_input_policy: GatewayInputPolicy = GatewayInputPolicy.OPEN
    log_dropped: bool = True
    #: Ports the reverse proxy binds on the *tunnel* side. Only meaningful when
    #: ``gateway_input_policy`` is RESTRICTED, where the chain ends in a drop
    #: and a listener nobody may reach is a service that silently does not work.
    #: Peers reach the proxy through the input chain, not the forward chain --
    #: the proxy terminates the connection on the gateway itself.
    proxy_ports: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class RulesetSpec:
    gateway: GatewaySpec = field(default_factory=GatewaySpec)
    groups: tuple[GroupSpec, ...] = ()
    zones: tuple[ZoneSpec, ...] = ()
    peers: tuple[PeerSpec, ...] = ()
    rules: tuple[RuleSpec, ...] = ()

    @property
    def group_slugs(self) -> frozenset[str]:
        return frozenset(g.slug for g in self.groups)

    @property
    def zone_slugs(self) -> frozenset[str]:
        return frozenset(z.slug for z in self.zones)
