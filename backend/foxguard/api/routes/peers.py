"""Peer CRUD plus enrollment-key lifecycle for server peers."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import Group, Peer, Tag
from ...nftables import PeerState, PeerType
from ...schemas import (
    EnrollmentKeyCreate,
    EnrollmentKeyRead,
    PeerCreate,
    PeerRead,
    PeerUpdate,
)
from ...services import audit, enrollment, ipam, peer_state, sessions
from ...services import ruleset as ruleset_service
from ..deps import audit_context, integrity_conflict, require_admin

router = APIRouter(
    prefix="/api/v1/peers", tags=["peers"], dependencies=[Depends(require_admin)]
)


def _serialise(peer: Peer) -> dict:
    return {
        "id": peer.id,
        "name": peer.name,
        "description": peer.description,
        "peer_type": peer.peer_type,
        "state": peer.state,
        "wg_public_key": peer.wg_public_key,
        "wg_interface": peer.wg_interface,
        "tunnel_ip": str(peer.tunnel_ip) if peer.tunnel_ip else None,
        "tunnel_ip6": str(peer.tunnel_ip6) if peer.tunnel_ip6 else None,
        "owner_user_id": peer.owner_user_id,
        "group_slugs": sorted(group.slug for group in peer.groups),
        "tags": sorted(tag.name for tag in peer.tags),
        "enrollment_key_expires_at": peer.enrollment_key_expires_at,
        "enrolled_at": peer.enrolled_at,
        "last_handshake_at": peer.last_handshake_at,
        "last_authenticated_at": peer.last_authenticated_at,
        "created_at": peer.created_at,
    }


def _get_or_404(session: Session, peer_id: uuid.UUID) -> Peer:
    peer = session.get(Peer, peer_id)
    if peer is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "peer not found")
    return peer


def _resolve_groups(session: Session, slugs: list[str]) -> list[Group]:
    if not slugs:
        return []
    groups = (
        session.execute(select(Group).where(Group.slug.in_(slugs))).scalars().all()
    )
    missing = sorted(set(slugs) - {group.slug for group in groups})
    if missing:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown groups: {', '.join(missing)}"
        )
    return list(groups)


def _resolve_tags(session: Session, names: list[str]) -> list[Tag]:
    tags: list[Tag] = []
    for name in dict.fromkeys(names):  # dedupe, keep order
        tag = session.execute(select(Tag).where(Tag.name == name)).scalar_one_or_none()
        if tag is None:
            tag = Tag(name=name)
            session.add(tag)
            session.flush()
        tags.append(tag)
    return tags


@router.get("", response_model=list[PeerRead])
def list_peers(
    session: Session = Depends(get_db),
    peer_type: PeerType | None = Query(default=None),
    state: PeerState | None = Query(default=None),
    tag: list[str] | None = Query(default=None, description="Repeatable; AND semantics."),
    group: str | None = Query(default=None),
) -> list[dict]:
    stmt = select(Peer)
    if peer_type is not None:
        stmt = stmt.where(Peer.peer_type == peer_type)
    if state is not None:
        stmt = stmt.where(Peer.state == state)
    if group:
        stmt = stmt.where(Peer.groups.any(Group.slug == group))
    for name in tag or []:
        stmt = stmt.where(Peer.tags.any(Tag.name == name))
    peers = session.execute(stmt.order_by(Peer.name)).scalars().unique().all()
    return [_serialise(peer) for peer in peers]


@router.post("", response_model=PeerRead, status_code=status.HTTP_201_CREATED)
def create_peer(
    payload: PeerCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Register a peer.

    New peers always land in ``staging``: a registered public key alone grants
    nothing. A server peer leaves staging by presenting its enrollment key; a
    user peer by authenticating on the portal (Phase 2).
    """
    tunnel_ip, tunnel_ip6 = payload.tunnel_ip, payload.tunnel_ip6
    if tunnel_ip is None and tunnel_ip6 is None:
        tunnel_ip, tunnel_ip6 = ipam.allocate_addresses(
            session,
            pool_v4=settings.wg_staging_pool_v4 or settings.wg_pool_v4,
            pool_v6=settings.wg_staging_pool_v6 or settings.wg_pool_v6,
            reserved=[settings.gateway_ip],
        )

    peer = Peer(
        name=payload.name,
        description=payload.description,
        peer_type=payload.peer_type,
        state=PeerState.STAGING,
        wg_public_key=payload.wg_public_key,
        wg_interface=settings.wg_interface,
        tunnel_ip=tunnel_ip,
        tunnel_ip6=tunnel_ip6,
        owner_user_id=payload.owner_user_id,
    )
    # Added to the session before the relationships are populated: _resolve_tags
    # flushes, and assigning a persistent Group to a transient Peer otherwise
    # emits "object not in session, add operation won't proceed".
    session.add(peer)
    peer.groups = _resolve_groups(session, payload.group_slugs)
    peer.tags = _resolve_tags(session, payload.tags)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(
            exc, "a peer with this public key or tunnel address already exists"
        ) from exc

    audit.record(
        session,
        action="peer.create",
        object_type="peer",
        object_id=peer.id,
        **audit_context(request),
        detail={"name": peer.name, "type": peer.peer_type.value, "ip": str(tunnel_ip)},
    )
    ruleset_service.regenerate(session, settings, generated_by="peer.create")
    session.commit()
    return _serialise(peer)


@router.get("/{peer_id}", response_model=PeerRead)
def get_peer(peer_id: uuid.UUID, session: Session = Depends(get_db)) -> dict:
    return _serialise(_get_or_404(session, peer_id))


@router.patch("/{peer_id}", response_model=PeerRead)
def update_peer(
    peer_id: uuid.UUID,
    payload: PeerUpdate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    peer = _get_or_404(session, peer_id)
    changes = payload.model_dump(exclude_unset=True)

    previous_state = peer.state
    target_state = changes.get("state")
    if target_state is not None:
        try:
            peer_state.assert_admin_transition(previous_state, target_state)
        except peer_state.IllegalTransition as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        if target_state is PeerState.ACTIVE and previous_state is not PeerState.ACTIVE:
            if peer.peer_type is PeerType.USER:
                # A user peer is `active` *because a human authenticated*, and
                # the expiry job relies on that: it reads last_authenticated_at
                # to decide whether access is still warranted. A hand-granted
                # active would have none, leaving the sweeper two bad options --
                # never expire it (a hole) or expire it on the next tick (a
                # pointless override). The portal is the only way in.
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "a user peer becomes active by authenticating on the portal; "
                    "an administrator can only quarantine, disable or revoke it",
                )
            # For a server peer this is legitimate -- provisioning may not be
            # automated yet -- but it still bypasses proof of possession, so it
            # gets its own audit action instead of hiding inside "peer.update".
            audit.record(
                session,
                action="peer.state.override",
                object_type="peer",
                object_id=peer.id,
                **audit_context(request),
                detail={"from": previous_state.value, "to": target_state.value},
            )
    if "group_slugs" in changes:
        peer.groups = _resolve_groups(session, changes.pop("group_slugs") or [])
    if "tags" in changes:
        peer.tags = _resolve_tags(session, changes.pop("tags") or [])
    for key, value in changes.items():
        setattr(peer, key, value)

    # Losing `active` ends the session that granted it; leaving the row behind
    # would make the Phase 3 expiry job and the dashboard disagree about who is
    # authenticated.
    if previous_state is PeerState.ACTIVE and peer.state is not PeerState.ACTIVE:
        sessions.revoke_sessions(session, peer)
    session.flush()

    audit.record(
        session,
        action="peer.update",
        object_type="peer",
        object_id=peer.id,
        **audit_context(request),
        detail={"changes": list(payload.model_dump(exclude_unset=True))},
    )
    ruleset_service.regenerate(session, settings, generated_by="peer.update")
    session.commit()
    return _serialise(peer)


@router.delete("/{peer_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_peer(
    peer_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    peer = _get_or_404(session, peer_id)
    name = peer.name
    session.delete(peer)
    session.flush()

    audit.record(
        session,
        action="peer.delete",
        object_type="peer",
        object_id=peer_id,
        **audit_context(request),
        detail={"name": name},
    )
    ruleset_service.regenerate(session, settings, generated_by="peer.delete")
    session.commit()


# --------------------------------------------------------------------------- #
# enrollment keys (server peers only)
# --------------------------------------------------------------------------- #


@router.post(
    "/{peer_id}/enrollment-key",
    response_model=EnrollmentKeyRead,
    status_code=status.HTTP_201_CREATED,
)
def create_enrollment_key(
    peer_id: uuid.UUID,
    payload: EnrollmentKeyCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> EnrollmentKeyRead:
    """Generate a fresh enrollment key. Returned once, stored only as a hash.

    Generating a new key invalidates the previous one for that peer.
    """
    peer = _get_or_404(session, peer_id)
    if peer.peer_type is not PeerType.SERVER:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "enrollment keys are for server peers; user peers authenticate on the portal",
        )
    if payload.expires_at is not None:
        expires_at = payload.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= datetime.now(UTC):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "expires_at is in the past"
            )
    else:
        expires_at = None

    key = enrollment.generate_key(settings.enrollment_key_bytes)
    peer.enrollment_key_hash = enrollment.hash_key(key)
    peer.enrollment_key_expires_at = expires_at
    session.flush()

    audit.record(
        session,
        action="peer.enrollment_key.create",
        object_type="peer",
        object_id=peer.id,
        **audit_context(request),
        detail={"expires_at": expires_at.isoformat() if expires_at else None},
    )
    session.commit()
    return EnrollmentKeyRead(
        peer_id=peer.id, enrollment_key=key, expires_at=expires_at
    )


@router.delete(
    "/{peer_id}/enrollment-key", response_model=PeerRead, status_code=status.HTTP_200_OK
)
def revoke_enrollment_key(
    peer_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    quarantine: bool = Query(
        default=True,
        description="Also push the peer back to quarantine (revocation takes effect now).",
    ),
    session_settings: Settings = Depends(get_settings),
) -> dict:
    """Invalidate the key and, by default, cut the peer's access immediately."""
    peer = _get_or_404(session, peer_id)
    peer.enrollment_key_hash = None
    peer.enrollment_key_expires_at = None
    if quarantine and peer.state is not PeerState.REVOKED:
        # Skipped for a revoked peer rather than refused: the caller asked to
        # invalidate a key, and that part succeeds. Moving `revoked` back to
        # `quarantined` would put it back in the dataplane, which is the one
        # thing revocation is supposed to prevent.
        peer.state = PeerState.QUARANTINED
    session.flush()

    audit.record(
        session,
        action="peer.enrollment_key.revoke",
        object_type="peer",
        object_id=peer.id,
        **audit_context(request),
        detail={"quarantined": quarantine},
    )
    ruleset_service.regenerate(
        session, session_settings, generated_by="peer.enrollment_key.revoke"
    )
    session.commit()
    return _serialise(peer)
