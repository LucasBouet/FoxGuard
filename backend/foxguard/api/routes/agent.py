"""Internal API consumed by the gateway agent.

The agent is a pull client: it asks for the desired state, reconciles the box,
and reports back. It never writes to the database directly, so the same agent
binary works whether it runs on the API box or on a separate gateway.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import ActorType, Peer, RulesetStatus, RulesetVersion
from ...nftables import PeerState, ruleset_digest
from ...schemas import AgentReport, AgentStateResponse, AgentWireGuardPeer
from ...services import audit
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
    wg_peers = []
    for peer in peers:
        allowed: list[str] = []
        if peer.tunnel_ip:
            allowed.append(f"{peer.tunnel_ip}/32")
        if peer.tunnel_ip6:
            allowed.append(f"{peer.tunnel_ip6}/128")
        if allowed:
            wg_peers.append(
                AgentWireGuardPeer(public_key=peer.wg_public_key, allowed_ips=allowed)
            )

    return AgentStateResponse(
        digest=ruleset_digest(content),
        ruleset=content,
        wg_interface=settings.wg_interface,
        wg_peers=wg_peers,
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
    session.commit()
