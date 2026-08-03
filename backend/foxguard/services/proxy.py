"""Projection of the database onto a :class:`ProxySpec`.

The third instance of the pattern, after :mod:`foxguard.services.ruleset` and
:mod:`foxguard.services.dns`, and deliberately the same shape: the only path
from database state to a running proxy is "render everything", so the same
state always yields the same bytes and drift is a digest comparison.

Two rules are specific to this module.

> **A broken service must never break the dataplane.**

Services are hand-authored, so an administrator can write a policy that cannot
render. If that made ``GET /api/v1/agent/state`` fail, a typo in a proxy rule
would stop the agent applying *firewall* rules. Callers therefore use
:func:`render_or_none`, and the mutation endpoints validate eagerly so the typo
is refused at the source.

> **A door that cannot describe how it is guarded is not opened.**

Not a style preference: an authenticator list that applies to neither listener
leaves the service either wide open or wholly shut depending on how the
fallback is written. The renderer refuses it, and so does the API.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import (
    Group,
    Peer,
    Service,
    ServiceAccess,
    ZoneRoute,
)
from ..nftables import Action, EndpointKind, PeerState
from ..proxy import (
    PEER_SET,
    AccessAction,
    AccessRule,
    Account,
    Authenticator,
    AuthKind,
    Backend,
    Exposure,
    Filter,
    FilterKind,
    PeerIdentity,
    ProxySpec,
    ProxyValidationError,
    Scope,
    ServiceKind,
    SourceSet,
    proxy_digest,
    render_conf,
    render_files,
)
from ..proxy import (
    Service as ServiceSpec,
)
from . import sso as sso_service

logger = logging.getLogger(__name__)

__all__ = [
    "SERVED_STATES",
    "allocate_listen_port",
    "build_spec",
    "digest",
    "doors_for",
    "forbidden_upstream",
    "implicit_paths",
    "render",
    "render_or_none",
    "slug_conflict",
    "upstream_reachable",
]

#: The only peer state that can actually carry traffic. Narrower than the DNS
#: module's ``NAMED_STATES`` on purpose: a name for a quarantined peer is merely
#: unhelpful, but a *service* on one is a listener that authenticates callers
#: and then hands them a timeout, because the quarantine drop is evaluated
#: before the established/related accept.
SERVED_STATES = (PeerState.ACTIVE,)


def doors_for(service: Service, settings: Settings) -> Exposure | None:
    """Which listeners this service actually gets, or ``None`` for none at all.

    The kill switch has no persistent flag to read -- it is an action that moves
    peer states, not a mode the system sits in. So the setting pair
    ``proxy_killswitch_stops_{internal,external}`` is applied where the effect
    is genuinely observable: an upstream peer that is no longer ``active``,
    whether because the kill switch hit it, an administrator disabled it, or it
    was revoked.

    With the defaults, a peer going down takes its internal listener with it and
    leaves the external one answering the 503 page that names the device. That
    is the decision "the kill switch stops internal services and leaves external
    ones serving", expressed in the only terms the database can express it.
    """
    if not service.enabled:
        return None
    peer = service.upstream_peer
    if peer is None or peer.state in SERVED_STATES:
        return Exposure(service.exposure.value)

    keep_internal = service.exposure.has_internal and not settings.proxy_killswitch_stops_internal
    keep_external = service.exposure.has_external and not settings.proxy_killswitch_stops_external
    if keep_internal and keep_external:
        return Exposure.BOTH
    if keep_internal:
        return Exposure.INTERNAL
    if keep_external:
        return Exposure.EXTERNAL
    return None


def build_spec(session: Session, settings: Settings) -> ProxySpec:
    """Build the full proxy spec from current database state."""
    spec = settings.proxy_base_spec()

    peers = (
        session.execute(
            select(Peer).where(Peer.state.in_(SERVED_STATES)).order_by(Peer.created_at, Peer.id)
        )
        .scalars()
        .all()
    )
    identities: list[PeerIdentity] = []
    peer_addresses: list[str] = []
    for peer in peers:
        label = peer.dns_label or str(peer.id)[:12]
        groups = tuple(sorted(group.slug for group in peer.groups))
        for address in (peer.tunnel_ip, peer.tunnel_ip6):
            if address:
                identities.append(PeerIdentity(str(address), label, groups))
                peer_addresses.append(str(address))

    services = session.execute(select(Service).order_by(Service.slug)).scalars().all()

    # Only render the sets an access rule actually names. A HAProxy pattern file
    # per group in the database would be dozens of files nothing reads.
    wanted: set[str] = set()
    for service in services:
        for rule in service.access:
            if rule.kind in (EndpointKind.GROUP, EndpointKind.ZONE) and rule.group:
                wanted.add(rule.group.slug)

    source_sets = [
        SourceSet(PEER_SET, tuple(peer_addresses), "every peer that can be on the tunnel")
    ]
    for slug in sorted(wanted):
        group = session.execute(select(Group).where(Group.slug == slug)).scalar_one_or_none()
        if group is None:
            continue
        source_sets.append(
            SourceSet(
                _set_name(slug),
                tuple(_group_members(session, group)),
                f"{group.kind.value} {slug}",
            )
        )

    rendered: list[ServiceSpec] = []
    for service in services:
        exposure = doors_for(service, settings)
        if exposure is None:
            continue
        rendered.append(_project_service(service, exposure))

    return ProxySpec(
        domain=spec.domain,
        internal_binds=spec.internal_binds,
        external_binds=spec.external_binds,
        internal_https_port=spec.internal_https_port,
        external_http_port=spec.external_http_port,
        external_https_port=spec.external_https_port,
        certs_dir=spec.certs_dir,
        maps_dir=spec.maps_dir,
        runtime_socket=spec.runtime_socket,
        hsts_max_age=spec.hsts_max_age,
        send_group_header=spec.send_group_header,
        sso_secret=spec.sso_secret,
        sso_cookie=spec.sso_cookie,
        sso_hostname=spec.sso_hostname,
        sso_cookie_domain=spec.sso_cookie_domain,
        sso_api_port=spec.sso_api_port,
        # Only sessions that are revoked *and* not yet expired. An expired one
        # is already refused by the expiry comparison in the rendered config,
        # and keeping it would grow this map forever.
        sso_revoked=tuple(sso_service.revoked_jtis(session)),
        services=tuple(rendered),
        source_sets=tuple(source_sets),
        peers=tuple(identities),
        connect_timeout_seconds=spec.connect_timeout_seconds,
        client_timeout_seconds=spec.client_timeout_seconds,
        server_timeout_seconds=spec.server_timeout_seconds,
        tunnel_timeout_seconds=spec.tunnel_timeout_seconds,
        extra_options=spec.extra_options,
    )


def _set_name(slug: str) -> str:
    return f"grp_{slug}"


def _group_members(session: Session, group: Group) -> list[str]:
    """Addresses that count as "inside" this group or zone.

    A zone carries its routed networks as well as its member peers, matching
    what the nftables generator puts in the zone's interval set. A packet from
    a network a zone routes for *is* in that zone, and an access rule naming the
    zone should say so.
    """
    members: list[str] = []
    if group.kind.value == "zone":
        peers = (
            session.execute(
                select(Peer).where(Peer.zone_id == group.id, Peer.state.in_(SERVED_STATES))
            )
            .scalars()
            .all()
        )
        routes = (
            session.execute(
                select(ZoneRoute).where(ZoneRoute.zone_id == group.id, ZoneRoute.enabled.is_(True))
            )
            .scalars()
            .all()
        )
        members.extend(route.cidr for route in routes)
    else:
        peers = [peer for peer in group.peers if peer.state in SERVED_STATES]

    for peer in peers:
        for address in (peer.tunnel_ip, peer.tunnel_ip6):
            if address:
                members.append(str(address))
    return sorted(set(members))


def _project_service(service: Service, exposure: Exposure) -> ServiceSpec:
    peer = service.upstream_peer
    backend = Backend(
        address=str(service.upstream_host),
        port=service.upstream_port,
        tls=service.upstream_tls,
        tls_verify=service.upstream_tls_verify,
        check=service.health_check,
        check_interval_seconds=service.health_check_interval,
        peer_label=(peer.dns_label or peer.name) if peer else None,
    )

    authenticators = tuple(
        Authenticator(
            kind=AuthKind(row.kind.value),
            scope=Scope(row.scope.value),
            realm=row.realm,
        )
        for row in _enabled(service.authenticators)
    )
    filters = tuple(
        Filter(
            kind=FilterKind(row.kind.value),
            scope=Scope(row.scope.value),
            values=tuple(row.values or ()),
            rate=row.rate,
            period_seconds=row.period_seconds,
        )
        for row in _enabled(service.filters)
    )
    access = tuple(
        _project_access(row)
        for row in sorted(service.access, key=lambda r: (r.priority, str(r.id)))
    )

    return ServiceSpec(
        slug=service.slug,
        kind=ServiceKind(service.kind.value),
        exposure=exposure,
        backend=backend,
        internal_hostname=service.internal_hostname if exposure.has_internal else None,
        external_hostname=service.external_hostname if exposure.has_external else None,
        listen_port=service.listen_port,
        sni_hostname=service.sni_hostname,
        authenticators=authenticators,
        filters=filters,
        access=access,
        token_hashes=tuple(
            sorted(row.token_hash for row in service.tokens if row.revoked_at is None)
        ),
        accounts=tuple(
            Account(row.username, row.password_hash)
            for row in sorted(service.accounts, key=lambda a: a.username)
            if row.revoked_at is None
        ),
        description=service.description,
    )


def _enabled(rows: Iterable) -> list:
    return [row for row in sorted(rows, key=lambda r: (r.priority, str(r.id))) if row.enabled]


def _project_access(row: ServiceAccess) -> AccessRule:
    action = AccessAction.ALLOW if row.action is Action.ACCEPT else AccessAction.DENY
    if row.kind is EndpointKind.ANY:
        return AccessRule(action, None)
    if row.kind is EndpointKind.CIDR:
        return AccessRule(action, row.cidr)
    slug = row.group.slug if row.group else None
    return AccessRule(action, _set_name(slug) if slug else None, is_set=bool(slug))


# --------------------------------------------------------------------------- #
# validators used by the API
# --------------------------------------------------------------------------- #


def sso_hostnames(session: Session, settings: Settings) -> set[str]:
    """Host names the login page is allowed to send a browser back to.

    Only names Foxguard itself publishes. Anything else is an open redirect,
    which would turn its own sign-in page into a convincing phishing hop --
    the classic way a login flow becomes the attack.
    """
    names: set[str] = set()
    for service in session.execute(select(Service)).scalars():
        if doors_for(service, settings) is None:
            continue
        for hostname in (service.internal_hostname, service.external_hostname):
            if hostname:
                names.add(hostname.lower())
    return names


def upstream_reachable(session: Session, peer: Peer | None, host: str) -> tuple[bool, str]:
    """Is ``host`` an address the carrying peer's ``AllowedIPs`` covers?

    The single most useful validator in this module. Without it, publishing a
    service on an address nothing routes to succeeds, and the failure surfaces
    later as a timeout -- which is the least diagnosable thing in the system and
    gets blamed on the proxy.

    Reuses the Phase 5 zone work directly: a peer carries its own tunnel
    addresses plus every enabled ``zone_routes`` row that names it.
    """
    if peer is None:
        return True, ""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False, f"{host!r} is not an IP address"

    for own in (peer.tunnel_ip, peer.tunnel_ip6):
        if own and ipaddress.ip_address(str(own)) == address:
            return True, ""

    routes = (
        session.execute(
            select(ZoneRoute).where(ZoneRoute.via_peer_id == peer.id, ZoneRoute.enabled.is_(True))
        )
        .scalars()
        .all()
    )
    for route in routes:
        if address in ipaddress.ip_network(route.cidr, strict=False):
            return True, ""

    carried = ", ".join(route.cidr for route in routes) or "nothing"
    return False, (
        f"{host} is not reachable through {peer.name!r}: it carries "
        f"{peer.tunnel_ip or peer.tunnel_ip6} and routes for {carried}. "
        "Add a zone route for the network this address is in, or point the "
        "service at a peer that carries it"
    )


def forbidden_upstream(settings: Settings, host: str, port: int) -> str | None:
    """Refuse a service pointing at Foxguard's own API or portal.

    ``deps.calling_peer`` identifies portal and enrollment callers by source
    address, and ``deps.assert_no_forwarded_headers`` refuses anything carrying
    a forwarded header precisely because a proxy destroys that identity. A
    service pointing there would appear to work and then break enrollment in a
    way nobody would connect to this setting.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if str(address) != settings.gateway_ip:
        return None
    if port == settings.portal_port:
        return (
            f"{host}:{port} is Foxguard's own listener. The portal and the "
            "enrollment API identify their caller by source address, and a "
            "proxy in front of them destroys that identity -- they must be "
            "reached directly from the tunnel"
        )
    if port in (
        settings.proxy_internal_https_port,
        settings.proxy_external_https_port,
        settings.proxy_external_http_port,
    ):
        return f"{host}:{port} is the proxy's own listener: this service would forward to itself"
    return None


def slug_conflict(session: Session, slug: str, exclude: str | None = None) -> str | None:
    """Is this name already taken anywhere in the shared namespace?

    Peers, groups, zones and services share one namespace so that an access
    rule naming ``office`` is never ambiguous about what it means.
    """
    group = session.execute(select(Group).where(Group.slug == slug)).scalar_one_or_none()
    if group is not None:
        return f"{slug!r} is already a {group.kind.value}"

    peer = session.execute(select(Peer).where(Peer.dns_label == slug)).scalar_one_or_none()
    if peer is not None:
        return f"{slug!r} is already the DNS label of peer {peer.name!r}"

    other = session.execute(select(Service).where(Service.slug == slug)).scalar_one_or_none()
    if other is not None and str(other.id) != exclude:
        return f"{slug!r} is already a service"
    return None


def allocate_listen_port(session: Session, settings: Settings) -> int:
    """The next free port in the configured range.

    A database concern with a unique constraint behind it, not a runtime scan
    of what happens to be listening: two administrators publishing at the same
    moment must not be handed the same port.
    """
    taken = set(
        session.execute(select(Service.listen_port).where(Service.listen_port.is_not(None)))
        .scalars()
        .all()
    )
    for port in range(settings.proxy_tcp_port_start, settings.proxy_tcp_port_end + 1):
        if port not in taken:
            return port
    raise ProxyValidationError(
        f"no free port left in {settings.proxy_tcp_port_start}-"
        f"{settings.proxy_tcp_port_end}. Plain TCP cannot share a port, so each "
        "such service needs one of its own -- widen the range or retire a service"
    )


def implicit_paths(session: Session, settings: Settings) -> list[dict]:
    """The gateway-to-upstream paths publishing services has opened.

    These are *not* enforced by nftables and deliberately so: the proxy
    originates from the gateway, which traverses an ``output`` chain Foxguard
    does not create -- base chains are ``policy accept`` with explicit drops
    precisely so a bad ruleset cannot lock the operator out. What enforces the
    path is the proxy configuration itself, which can only ever connect to the
    declared host and port.

    They are surfaced anyway, because the one thing that must never happen is a
    published service creating a path that appears nowhere a human looks.
    """
    services = session.execute(select(Service).order_by(Service.slug)).scalars().all()
    paths = []
    for service in services:
        if doors_for(service, settings) is None:
            continue
        peer = service.upstream_peer
        paths.append(
            {
                "service": service.slug,
                "source": "gateway",
                "destination": str(service.upstream_host),
                "peer": peer.name if peer else None,
                "protocol": "tcp",
                "port": service.upstream_port,
                "enforced_by": "proxy configuration",
            }
        )
    return paths


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #


def render(session: Session, settings: Settings) -> tuple[str, dict[str, str]]:
    """Render ``(conf, files)`` from current database state.

    Raises :class:`ProxyValidationError` if the state cannot produce a safe
    configuration.
    """
    spec = build_spec(session, settings)
    return render_conf(spec), render_files(spec)


def digest(conf: str, files: dict[str, str]) -> str:
    return proxy_digest(conf, files)


def render_or_none(session: Session, settings: Settings) -> tuple[str, dict[str, str], str] | None:
    """``(conf, files, digest)``, or ``None`` when the proxy is off or unrenderable.

    The failure is logged at error level and swallowed, for the same reason
    ``dns.render_or_none`` does it: the caller is the agent state endpoint, and
    a hand-authored proxy rule must not be able to stop firewall rules reaching
    the kernel.
    """
    if not settings.proxy_enabled:
        return None
    try:
        conf, files = render(session, settings)
    except ProxyValidationError as exc:
        logger.error(
            "proxy configuration cannot be rendered, leaving the proxy untouched: %s",
            exc,
        )
        return None
    return conf, files, proxy_digest(conf, files)
