"""Project database state onto a client-configuration profile.

The same shape as ``services/dns.py`` and ``services/ruleset.py``: settings and
rows in, a frozen value object out, no side effects. What is unusual is what
comes *back* -- a profile is incomplete by design when the deployment has not
been told its own public address or key, and the warnings say which environment
variable is missing rather than leaving the operator to find out from a device
that will not connect.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..clientconfig import AllowedIpsMode, ClientProfile, compute_allowed_ips
from ..config import Settings
from ..dns.model import ResolverMode
from ..models import Group, Peer, ZoneRoute
from ..nftables import PeerState

__all__ = ["build_profile"]

#: States where a device is on the interface at all. A config for anything else
#: is still generated -- an operator preparing a disabled device for a return to
#: service should not have to guess the file -- but it says so.
_CONNECTABLE = (PeerState.STAGING, PeerState.QUARANTINED, PeerState.ACTIVE)


def _routes(session: Session) -> list[ZoneRoute]:
    return list(
        session.execute(
            select(ZoneRoute).where(ZoneRoute.enabled.is_(True)).order_by(ZoneRoute.cidr)
        )
        .scalars()
        .all()
    )


def build_profile(
    session: Session,
    settings: Settings,
    peer: Peer,
    *,
    mode: AllowedIpsMode | None = None,
    keepalive: int | None = None,
    mtu: int | None = None,
    include_dns: bool | None = None,
) -> ClientProfile:
    """Everything but the private key.

    The overrides exist because these are per-device decisions as often as
    per-deployment ones -- a phone on mobile data wants keepalive, a server on a
    static address does not -- and the alternative is the operator editing the
    file afterwards, which is how a working config becomes a broken one.
    """
    mode = mode if mode is not None else settings.client_config_allowed_ips
    warnings: list[str] = []

    addresses: list[str] = []
    if peer.tunnel_ip:
        addresses.append(f"{peer.tunnel_ip}/32")
    if peer.tunnel_ip6:
        addresses.append(f"{peer.tunnel_ip6}/128")
    if not addresses:
        warnings.append(
            "this peer has no tunnel address, so there is nothing to put on the "
            "Address line -- re-register it"
        )

    all_routes = _routes(session)
    carried = tuple(route.cidr for route in all_routes if route.via_peer_id == peer.id)
    own_zone = (
        tuple(route.cidr for route in all_routes if route.zone_id == peer.zone_id)
        if peer.zone_id
        else ()
    )
    fleet = tuple(route.cidr for route in all_routes)

    allowed_ips, excluded = compute_allowed_ips(
        mode,
        pools=settings.tunnel_pools,
        own_zone_routes=own_zone,
        fleet_routes=fleet,
        carried_by_peer=carried,
        extra=tuple(settings.client_config_extra_allowed_ips),
    )

    server_public_key = settings.wg_public_key
    if not server_public_key:
        warnings.append(
            "the gateway's own public key is not configured, so this config "
            "cannot connect -- set FOXGUARD_WG_PUBLIC_KEY to the output of "
            f"`wg show {settings.wg_interface} public-key`"
        )
    endpoint = settings.client_endpoint
    if not endpoint:
        warnings.append(
            "no public endpoint is configured, so this config cannot connect -- "
            "set FOXGUARD_WG_ENDPOINT_HOST to the address your router forwards "
            f"udp/{settings.wg_listen_port} to"
        )

    if excluded:
        warnings.append(
            f"{', '.join(excluded)} left out of AllowedIPs: this device carries "
            "those networks for a zone, and routing them into the tunnel would "
            "cut it off from the very networks it serves"
        )

    if peer.state not in _CONNECTABLE:
        warnings.append(
            f"this peer is {peer.state.value}: the gateway will not accept its "
            "handshake until that changes"
        )
    elif peer.state is not PeerState.ACTIVE:
        warnings.append(
            f"this peer is {peer.state.value}: the tunnel will come up, but it "
            "reaches only the portal until it authenticates"
        )

    if mode is AllowedIpsMode.FULL and not _has_internet_exit(session, peer):
        warnings.append(
            "full tunnel selected, but no group this peer belongs to has "
            "internet exit -- the device will send everything to the gateway "
            "and the gateway will drop it, leaving it with no internet at all"
        )

    dns = settings.client_dns if include_dns is not False else ()
    if dns and settings.dns_mode is ResolverMode.SPLIT:
        warnings.append(
            "the resolver runs in split mode, which REFUSES anything outside "
            f"{settings.dns_zone}: this device needs a second resolver of its "
            "own, or it will resolve nothing else"
        )

    fqdn = (
        f"{peer.dns_label}.{settings.dns_zone}"
        if settings.dns_enabled and peer.dns_label
        else None
    )

    return ClientProfile(
        peer_id=str(peer.id),
        peer_name=peer.name,
        peer_state=peer.state.value,
        fqdn=fqdn,
        addresses=tuple(addresses),
        dns=dns,
        mtu=mtu if mtu is not None else settings.client_config_mtu,
        server_public_key=server_public_key,
        endpoint=endpoint,
        allowed_ips=allowed_ips,
        persistent_keepalive=(
            keepalive if keepalive is not None else settings.client_config_keepalive
        ),
        allowed_ips_mode=mode,
        excluded_routes=excluded,
        warnings=tuple(warnings),
    )


def _has_internet_exit(session: Session, peer: Peer) -> bool:
    """Does anything this peer belongs to let it out to the internet?

    Zones count as well as groups: ``internet_exit`` is a column on the shared
    table and the ruleset generator honours it for both, so a check that looked
    only at groups would warn about a full-tunnel config that works perfectly.
    """
    candidates = [group.id for group in peer.groups]
    if peer.zone_id:
        candidates.append(peer.zone_id)
    if not candidates:
        return False
    return bool(
        session.execute(
            select(Group.id)
            .where(Group.id.in_(candidates), Group.internet_exit.is_(True))
            .limit(1)
        ).scalar_one_or_none()
    )
