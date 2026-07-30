"""Projection of the database onto a :class:`DnsSpec`.

The DNS twin of :mod:`foxguard.services.ruleset`, and deliberately shaped the
same way: the only path from database state to a served zone is "render
everything", so the same state always yields the same bytes and drift is a
digest comparison.

One rule is specific to this module and matters more than it looks:

> **A broken zone must never break the dataplane.**

DNS records are hand-authored, so an administrator can write a CNAME loop or two
records fighting over a name. If that made ``GET /api/v1/agent/state`` fail, a
typo in a DNS record would stop the agent applying *firewall* rules -- access
control taken down by a name service. Callers therefore use
:func:`render_or_none`, which reports the failure and yields nothing, and the
mutation endpoints validate eagerly so the typo is refused at the source.

The same rule points the other way for an alias whose target *disappears*.
Revoking a peer takes its name away, and a CNAME pointing at it would otherwise
break the whole zone -- meaning the kill switch, the one action guaranteed to
only narrow access, would silently stop the fleet resolving anything.
:func:`build_spec` drops those aliases and :func:`dangling_aliases` reports
them, so the zone survives an ordinary operational event.
"""

from __future__ import annotations

import logging
from collections import OrderedDict

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..dns import (
    CnameEntry,
    DnsSpec,
    DnsValidationError,
    HostEntry,
    RecordKind,
    dns_digest,
    render_conf,
    render_hosts,
)
from ..models import DnsRecord, Peer
from ..nftables import PeerState

logger = logging.getLogger(__name__)

__all__ = [
    "NAMED_STATES",
    "build_spec",
    "dangling_aliases",
    "digest",
    "qualify",
    "render",
    "render_or_none",
    "target_exists",
]

#: States in which a peer has a name. The same set the agent keeps on the
#: WireGuard interface: a name that resolves to a device which cannot be on the
#: tunnel is a wrong answer, not a stale one. ``disabled`` and ``revoked`` peers
#: keep their address in the database and lose their name.
NAMED_STATES = (PeerState.STAGING, PeerState.QUARANTINED, PeerState.ACTIVE)


def qualify(name: str, zone: str) -> str:
    """Turn a zone-relative name into a fully qualified one."""
    trimmed = name.strip().rstrip(".").lower()
    if trimmed == zone or trimmed.endswith(f".{zone}"):
        return trimmed
    return f"{trimmed}.{zone}"


def build_spec(session: Session, settings: Settings) -> DnsSpec:
    """Build the full DNS spec from current database state."""
    zone = settings.dns_zone
    spec = settings.dns_base_spec()

    # An ordered mapping so the first name written for an address stays the
    # canonical one -- that is what dnsmasq answers reverse lookups with, and
    # the peer's own name should win over an alias someone added later.
    by_address: OrderedDict[str, list[str]] = OrderedDict()
    comments: dict[str, str] = {}

    def add(address: str, name: str, comment: str | None = None) -> None:
        names = by_address.setdefault(address, [])
        if name not in names:
            names.append(name)
        if comment and address not in comments:
            comments[address] = comment

    gateway_name = qualify(settings.dns_gateway_label, zone)
    add(settings.gateway_ip, gateway_name, "gateway")

    peers = (
        session.execute(
            select(Peer)
            .where(Peer.state.in_(NAMED_STATES), Peer.dns_label.is_not(None))
            .order_by(Peer.created_at, Peer.id)
        )
        .scalars()
        .all()
    )
    for peer in peers:
        name = qualify(peer.dns_label or "", zone)
        for address in (peer.tunnel_ip, peer.tunnel_ip6):
            if address:
                add(str(address), name, peer.peer_type.value)

    records = (
        session.execute(
            select(DnsRecord).where(DnsRecord.enabled.is_(True)).order_by(DnsRecord.name)
        )
        .scalars()
        .all()
    )
    aliases: list[CnameEntry] = []
    for record in records:
        name = qualify(record.name, zone)
        if record.kind is RecordKind.CNAME:
            aliases.append(
                CnameEntry(
                    alias=name,
                    target=qualify(record.value, zone),
                    comment=record.description,
                )
            )
        else:
            add(record.value, name, record.description)

    hosts = tuple(
        HostEntry(address=address, names=tuple(names), comment=comments.get(address))
        for address, names in by_address.items()
    )

    # An alias whose target no longer exists is dropped, not treated as an
    # error. Targets disappear through ordinary operations -- revoking a peer,
    # or the kill switch disabling the fleet -- and taking the whole zone down
    # because one alias lost its target would mean an access-control action
    # silently killing name resolution for everybody. The alias simply stops
    # resolving, which is the right answer for a device that is gone anyway.
    # ``dangling_aliases`` reports them so this is visible rather than magic,
    # and the API still refuses a CNAME to a name that never existed.
    known = {name for host in hosts for name in host.names}
    cnames = [alias for alias in aliases if alias.target in known]
    return DnsSpec(
        zone=spec.zone,
        listen_addresses=spec.listen_addresses,
        port=spec.port,
        hosts_path=spec.hosts_path,
        hosts=hosts,
        cnames=tuple(cnames),
        mode=spec.mode,
        upstreams=spec.upstreams,
        cache_size=spec.cache_size,
        reverse_pools=spec.reverse_pools,
        stop_dns_rebind=spec.stop_dns_rebind,
        log_queries=spec.log_queries,
        extra_options=spec.extra_options,
    )


def dangling_aliases(session: Session, settings: Settings) -> list[str]:
    """Aliases that are not being served because their target is gone.

    Not an error anywhere, but the administrator who created them should be
    able to find out. Reported by ``GET /api/v1/dns``.
    """
    zone = settings.dns_zone
    spec = build_spec(session, settings)
    served = {alias.alias for alias in spec.cnames}
    records = (
        session.execute(
            select(DnsRecord)
            .where(DnsRecord.enabled.is_(True), DnsRecord.kind == RecordKind.CNAME)
            .order_by(DnsRecord.name)
        )
        .scalars()
        .all()
    )
    return [
        f"{qualify(record.name, zone)} is not served: its target "
        f"{qualify(record.value, zone)} no longer exists"
        for record in records
        if qualify(record.name, zone) not in served
    ]


def target_exists(session: Session, settings: Settings, target: str) -> bool:
    """Is ``target`` a name this zone currently answers for?

    Used by the record endpoints, which refuse an alias to a name that was
    never there. Rendering alone cannot catch it any more, because a dangling
    alias is now dropped rather than rejected.
    """
    spec = build_spec(session, settings)
    wanted = qualify(target, settings.dns_zone)
    return any(wanted in host.names for host in spec.hosts)


def render(session: Session, settings: Settings) -> tuple[str, str]:
    """Render ``(hosts, conf)`` from current database state.

    Raises :class:`DnsValidationError` if the state cannot produce a safe zone.
    """
    spec = build_spec(session, settings)
    return render_hosts(spec), render_conf(spec)


def digest(hosts: str, conf: str) -> str:
    return dns_digest(hosts, conf)


def render_or_none(
    session: Session, settings: Settings
) -> tuple[str, str, str] | None:
    """``(hosts, conf, digest)``, or ``None`` when DNS is off or unrenderable.

    The failure is logged at error level and swallowed. That is the whole point
    of this function: the caller is the agent state endpoint, and a hand-authored
    DNS record must not be able to stop firewall rules reaching the kernel.
    """
    if not settings.dns_enabled:
        return None
    try:
        hosts, conf = render(session, settings)
    except DnsValidationError as exc:
        logger.error(
            "DNS zone cannot be rendered, leaving the resolver untouched: %s", exc
        )
        return None
    return hosts, conf, dns_digest(hosts, conf)
