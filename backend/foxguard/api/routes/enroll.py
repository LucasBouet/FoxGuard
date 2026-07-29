"""Server-peer enrollment: the endpoint a machine calls to leave ``staging``.

This is the only route in the admin API surface with no bearer token, so its
authentication story is worth stating in full. A caller must satisfy **two**
independent checks:

1. it holds the WireGuard private key for a tunnel address Foxguard allocated
   (enforced by :func:`~foxguard.api.deps.calling_peer`, ultimately by
   WireGuard's cryptokey routing);
2. it presents that specific peer's enrollment key.

Neither alone is enough. A registered public key grants nothing until the key is
presented -- that is what ``staging`` means -- and a leaked enrollment key is
useless without the tunnel, because ``staging`` peers can reach *only* the
portal port and nothing else on the box.

The key is checked against the peer that owns the source address, never looked
up across the table. Searching for "whichever peer this key belongs to" would
let anyone inside the tunnel enroll as any peer whose key they obtained, and
would turn the endpoint into an oracle for guessing keys.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import ActorType, Peer
from ...nftables import PeerState, PeerType
from ...schemas import EnrollRequest, EnrollResponse
from ...services import audit, enrollment, peer_state
from ...services import ruleset as ruleset_service
from ...services.ratelimit import RateLimited
from ..deps import calling_peer, client_ip, enroll_limiter, rate_limited_response

router = APIRouter(prefix="/api/v1/enroll", tags=["enrollment"])


def _refused(peer: Peer, request: Request, session: Session, reason: str) -> HTTPException:
    """One opaque 403 for every failure, with the real reason in the audit log.

    The device gets no help distinguishing "wrong key" from "key expired" from
    "wrong peer type": all of those are useful to an attacker holding a stolen
    WireGuard key and nothing else, and useless to a correctly provisioned
    machine.
    """
    audit.record(
        session,
        action="peer.enroll.denied",
        actor_type=ActorType.PEER,
        actor_label=peer.name,
        object_type="peer",
        object_id=peer.id,
        source_ip=client_ip(request),
        detail={"reason": reason},
    )
    return HTTPException(status.HTTP_403_FORBIDDEN, "enrollment refused")


@router.post("", response_model=EnrollResponse)
def enroll(
    payload: EnrollRequest,
    request: Request,
    peer: Peer = Depends(calling_peer),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> EnrollResponse:
    """Present an enrollment key and move ``staging``/``quarantined`` -> ``active``."""
    limiter = enroll_limiter()
    limiter_key = f"enroll:{peer.id}"
    try:
        limiter.check(limiter_key)
    except RateLimited as exc:
        # Committed so the denial survives -- an audit trail that only exists
        # when the request succeeds is not an audit trail.
        session.commit()
        raise rate_limited_response(exc) from exc

    def refuse(reason: str) -> HTTPException:
        limiter.record_failure(limiter_key)
        exc = _refused(peer, request, session, reason)
        session.commit()
        return exc

    if peer.peer_type is not PeerType.SERVER:
        raise refuse("not a server peer")

    if payload.wg_public_key and payload.wg_public_key.strip() != peer.wg_public_key:
        raise refuse("public key does not match the peer holding this address")

    # verify_key hashes even when the stored hash is missing, so a peer that
    # never had a key costs the same time as one with a wrong key.
    if not enrollment.verify_key(payload.enrollment_key, peer.enrollment_key_hash):
        raise refuse("invalid enrollment key")

    if enrollment.is_expired(peer.enrollment_key_expires_at):
        raise refuse("enrollment key expired")

    try:
        peer_state.assert_self_service_transition(peer.state, PeerState.ACTIVE)
    except peer_state.IllegalTransition as exc:
        # A valid key must not undo `disabled` or `revoked`.
        raise refuse(f"state {peer.state.value} is not eligible") from exc

    peer.state = PeerState.ACTIVE
    peer.enrolled_at = datetime.now(UTC)
    session.flush()

    limiter.reset(limiter_key)
    audit.record(
        session,
        action="peer.enroll",
        actor_type=ActorType.PEER,
        actor_label=peer.name,
        object_type="peer",
        object_id=peer.id,
        source_ip=client_ip(request),
        detail={"groups": sorted(group.slug for group in peer.groups)},
    )
    ruleset_service.regenerate(session, settings, generated_by="peer.enroll")
    session.commit()

    return EnrollResponse(
        peer_id=peer.id,
        name=peer.name,
        state=peer.state,
        tunnel_ip=str(peer.tunnel_ip) if peer.tunnel_ip else None,
        tunnel_ip6=str(peer.tunnel_ip6) if peer.tunnel_ip6 else None,
        group_slugs=sorted(group.slug for group in peer.groups),
        enrolled_at=peer.enrolled_at,
    )
