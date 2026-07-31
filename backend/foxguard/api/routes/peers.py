"""Peer CRUD plus enrollment-key lifecycle for server peers."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...clientconfig import AllowedIpsMode
from ...config import Settings, get_settings
from ...db import get_db
from ...dns import derive_label, fallback_label
from ...models import Group, GroupKind, Peer, Tag
from ...nftables import PeerState, PeerType
from ...schemas import (
    ClientConfigProfile,
    EnrollmentKeyCreate,
    EnrollmentKeyRead,
    PeerCreate,
    PeerRead,
    PeerUpdate,
)
from ...services import audit, clientconfig, enrollment, ipam, peer_state, sessions
from ..deps import (
    audit_context,
    integrity_conflict,
    regenerate_or_422,
    require_admin,
)

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
        "dns_label": peer.dns_label,
        "zone_slug": peer.zone.slug if peer.zone else None,
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
    # Attaching a zone as a group would put the peer in the group set, which for
    # a zone is never rendered -- the peer would appear assigned in the API and
    # be absent from the dataplane.
    zones = sorted(g.slug for g in groups if g.kind is GroupKind.ZONE)
    if zones:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{', '.join(zones)} are zones, not groups: use zone_slug "
            "(a peer belongs to at most one zone)",
        )
    return list(groups)


def _resolve_zone(session: Session, slug: str | None) -> Group | None:
    if not slug:
        return None
    zone = session.execute(
        select(Group).where(Group.slug == slug)
    ).scalar_one_or_none()
    if zone is None or zone.kind is not GroupKind.ZONE:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown zone {slug!r}")
    return zone


def _dns_label(payload_label: str | None, name: str, peer_id: uuid.UUID) -> str:
    """The DNS label a peer gets, chosen once and stored.

    Deriving this at render time instead would push every collision out to the
    resolver, where the only options are refusing to serve the zone at all or
    picking a winner nobody chose. Stored, a clash is a 409 on the request that
    caused it -- and the caller can pass ``dns_label`` to settle it.
    """
    return payload_label or derive_label(name) or fallback_label(str(peer_id))


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
        id=uuid.uuid4(),
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
    # The id is assigned above rather than left to the column default because
    # the fallback label is derived from it, and a peer whose name yields no
    # usable label still needs one before the insert.
    peer.dns_label = _dns_label(payload.dns_label, payload.name, peer.id)
    # Added to the session before the relationships are populated: _resolve_tags
    # flushes, and assigning a persistent Group to a transient Peer otherwise
    # emits "object not in session, add operation won't proceed".
    session.add(peer)
    peer.groups = _resolve_groups(session, payload.group_slugs)
    peer.zone = _resolve_zone(session, payload.zone_slug)
    peer.tags = _resolve_tags(session, payload.tags)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(
            exc,
            "a peer with this public key, tunnel address or DNS label already "
            "exists (pass dns_label to choose a different name)",
        ) from exc

    audit.record(
        session,
        action="peer.create",
        object_type="peer",
        object_id=peer.id,
        **audit_context(request),
        detail={"name": peer.name, "type": peer.peer_type.value, "ip": str(tunnel_ip)},
    )
    regenerate_or_422(session, settings, "peer.create")
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
    if "zone_slug" in changes:
        # Explicit null clears the assignment, which narrows access -- so unlike
        # `state`, it needs no transition guard.
        peer.zone = _resolve_zone(session, changes.pop("zone_slug"))
    if "tags" in changes:
        peer.tags = _resolve_tags(session, changes.pop("tags") or [])
    for key, value in changes.items():
        setattr(peer, key, value)

    # Losing `active` ends the session that granted it; leaving the row behind
    # would make the Phase 3 expiry job and the dashboard disagree about who is
    # authenticated.
    if previous_state is PeerState.ACTIVE and peer.state is not PeerState.ACTIVE:
        sessions.revoke_sessions(session, peer)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(exc, "another peer already has that DNS label") from exc

    audit.record(
        session,
        action="peer.update",
        object_type="peer",
        object_id=peer.id,
        **audit_context(request),
        detail={"changes": list(payload.model_dump(exclude_unset=True))},
    )
    regenerate_or_422(session, settings, "peer.update")
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
    regenerate_or_422(session, settings, "peer.delete")
    session.commit()


# --------------------------------------------------------------------------- #
# client configuration
# --------------------------------------------------------------------------- #


@router.get("/{peer_id}/config-profile", response_model=ClientConfigProfile)
def get_config_profile(
    peer_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    allowed_ips: AllowedIpsMode | None = Query(
        default=None, description="Overrides FOXGUARD_CLIENT_CONFIG_ALLOWED_IPS."
    ),
    keepalive: int | None = Query(default=None, ge=0, le=65535),
    mtu: int | None = Query(default=None, ge=576, le=9000),
    dns: bool | None = Query(
        default=None, description="False omits the DNS line even when the resolver is on."
    ),
) -> ClientConfigProfile:
    """Everything a client config needs except the private key.

    **No secret is returned and none is accepted.** The browser generates the
    keypair, sends the public half through ``POST /peers``, and assembles the
    file locally; this endpoint only tells it what to put around the key. That
    is also why reading a profile is audited: it is the moment a device becomes
    provisionable, and the audit log is where "who set this laptop up" is
    answered.
    """
    peer = _get_or_404(session, peer_id)
    profile = clientconfig.build_profile(
        session,
        settings,
        peer,
        mode=allowed_ips,
        keepalive=keepalive,
        mtu=mtu,
        include_dns=dns,
    )

    audit.record(
        session,
        action="peer.config_profile.read",
        object_type="peer",
        object_id=peer.id,
        **audit_context(request),
        detail={"allowed_ips_mode": profile.allowed_ips_mode.value},
    )
    session.commit()

    return ClientConfigProfile(
        peer_id=peer.id,
        peer_name=profile.peer_name,
        peer_state=peer.state,
        fqdn=profile.fqdn,
        addresses=list(profile.addresses),
        dns=list(profile.dns),
        mtu=profile.mtu,
        server_public_key=profile.server_public_key,
        endpoint=profile.endpoint,
        allowed_ips=list(profile.allowed_ips),
        persistent_keepalive=profile.persistent_keepalive,
        allowed_ips_mode=profile.allowed_ips_mode,
        excluded_routes=list(profile.excluded_routes),
        warnings=list(profile.warnings),
        complete=profile.complete,
    )


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
    regenerate_or_422(session, session_settings, "peer.enrollment_key.revoke")
    session.commit()
    return _serialise(peer)
