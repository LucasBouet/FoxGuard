"""Internal API consumed by the gateway agent.

The agent is a pull client: it asks for the desired state, reconciles the box,
and reports back. It never writes to the database directly, so the same agent
binary works whether it runs on the API box or on a separate gateway.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import ActorType, Peer, RulesetStatus, RulesetVersion, ZoneRoute
from ...nftables import PeerState, ruleset_digest
from ...schemas import (
    AgentDnsState,
    AgentProxyState,
    AgentReport,
    AgentRoute,
    AgentStateResponse,
    AgentWireGuardPeer,
)
from ...services import audit
from ...services import dns as dns_service
from ...services import proxy as proxy_service
from ...services import ruleset as ruleset_service
from ..deps import client_ip, require_agent

router = APIRouter(
    prefix="/api/v1/agent", tags=["agent"], dependencies=[Depends(require_agent)]
)

#: States that keep a WireGuard peer entry on the interface. Quarantined and
#: staging peers stay connected on purpose -- that is what lets them reach the
#: portal / enrollment endpoint; confinement is enforced by nftables, not by
#: removing them from WireGuard.
_WG_PRESENT_STATES = (PeerState.STAGING, PeerState.QUARANTINED, PeerState.ACTIVE)


@router.get("/state", response_model=AgentStateResponse)
def get_state(
    session: Session = Depends(get_db), settings: Settings = Depends(get_settings)
) -> AgentStateResponse:
    """Full desired state for one reconciliation pass.

    Deliberately a full snapshot rather than a delta: the agent can be restarted,
    the gateway rebuilt, or the DB edited by hand, and the next poll still
    converges to the same state.
    """
    content = ruleset_service.render(session, settings)

    peers = (
        session.execute(
            select(Peer)
            .where(Peer.state.in_(_WG_PRESENT_STATES))
            .order_by(Peer.wg_public_key)
        )
        .scalars()
        .all()
    )

    # Networks a peer carries for a zone. They belong in that peer's AllowedIPs
    # because WireGuard's cryptokey routing is what decides which peer a packet
    # for 192.168.10.7 is encrypted to -- without it the kernel route into the
    # tunnel exists and every packet is dropped as unroutable at the wg layer.
    # Only enabled routes, and only where the zone itself still exists.
    routed: dict[uuid.UUID, list[str]] = {}
    carried = (
        session.execute(
            select(ZoneRoute)
            .where(ZoneRoute.enabled.is_(True), ZoneRoute.via_peer_id.is_not(None))
            .order_by(ZoneRoute.cidr)
        )
        .scalars()
        .all()
    )
    for route in carried:
        routed.setdefault(route.via_peer_id, []).append(route.cidr)

    # Only peers that can actually be on the interface carry anything: a route
    # whose peer is disabled or revoked would sit in the kernel table pointing
    # at a tunnel that will drop every packet.
    present = {peer.id for peer in peers}

    wg_peers = []
    for peer in peers:
        allowed: list[str] = []
        if peer.tunnel_ip:
            allowed.append(f"{peer.tunnel_ip}/32")
        if peer.tunnel_ip6:
            allowed.append(f"{peer.tunnel_ip6}/128")
        # Sorted so an unchanged fleet produces an unchanged config and
        # ``wg syncconf`` stays a no-op.
        allowed.extend(sorted(routed.get(peer.id, ())))
        if allowed:
            wg_peers.append(
                AgentWireGuardPeer(public_key=peer.wg_public_key, allowed_ips=allowed)
            )

    # Rendered last and allowed to yield nothing. A hand-authored DNS record
    # must never be able to stop firewall rules reaching the kernel, so the
    # failure is logged there and the agent simply leaves the resolver alone.
    rendered = dns_service.render_or_none(session, settings)
    dns_state = (
        AgentDnsState(
            digest=rendered[2],
            hosts=rendered[0],
            conf=rendered[1],
            hosts_path=settings.dns_hosts_path,
            conf_path=settings.dns_conf_path,
        )
        if rendered
        else None
    )

    # Same contract as the DNS block above, for the same reason: a
    # hand-authored proxy rule must not be able to stop firewall rules.
    proxied = proxy_service.render_or_none(session, settings)
    proxy_state = (
        AgentProxyState(
            digest=proxied[2],
            conf=proxied[0],
            files=proxied[1],
            conf_path=settings.proxy_conf_path,
            maps_dir=settings.proxy_maps_dir,
            certs_dir=settings.proxy_certs_dir,
            runtime_socket=settings.proxy_runtime_socket,
            geo_countries=list(proxied.geo_countries),
        )
        if proxied
        else None
    )

    return AgentStateResponse(
        digest=ruleset_digest(content),
        ruleset=content,
        wg_interface=settings.wg_interface,
        wg_peers=wg_peers,
        routes=[
            AgentRoute(cidr=route.cidr, via_peer_id=route.via_peer_id)
            for route in carried
            if route.via_peer_id in present
        ],
        dns=dns_state,
        proxy=proxy_state,
    )


@router.post("/report", status_code=204)
def report(
    payload: AgentReport, request: Request, session: Session = Depends(get_db)
) -> None:
    """Record the outcome of an apply attempt."""
    version = session.execute(
        select(RulesetVersion).where(RulesetVersion.digest == payload.digest).limit(1)
    ).scalar_one_or_none()

    if version is not None:
        if payload.success:
            ruleset_service.mark_applied(session, version)
        else:
            ruleset_service.mark_failed(session, version, payload.error or "unknown error")
    elif payload.success:
        # The agent applied a ruleset we have no record of (e.g. it was rendered
        # before a rollback). Store it so the audit trail stays complete.
        version = RulesetVersion(
            digest=payload.digest,
            content="",
            status=RulesetStatus.APPLIED,
            generated_by="agent",
        )
        session.add(version)

    audit.record(
        session,
        action="ruleset.apply" if payload.success else "ruleset.apply_failed",
        actor_type=ActorType.AGENT,
        actor_label="gateway-agent",
        object_type="ruleset_version",
        object_id=version.id if version is not None else None,
        source_ip=client_ip(request),
        detail={"digest": payload.digest, "error": payload.error},
    )

    # Its own entry rather than a field on the one above: a resolver that will
    # not reload and a ruleset that will not apply are different incidents, and
    # the audit log is where someone looks to tell them apart.
    if payload.dns_error:
        audit.record(
            session,
            action="dns.apply_failed",
            actor_type=ActorType.AGENT,
            actor_label="gateway-agent",
            object_type="dns_zone",
            source_ip=client_ip(request),
            detail={"digest": payload.dns_digest, "error": payload.dns_error},
        )
    session.commit()
