"""Network zones and the networks routed inside them.

A zone is a ``groups`` row with ``kind = 'zone'``, but it is a different thing
from a group and gets its own endpoints for that reason: it owns routes, a peer
belongs to at most one, and ``/api/v1/groups`` deliberately does not list them.
Sharing one endpoint would let a zone be attached to a peer as a group, which
would silently drop its routes.

Like the ACL routes, every mutation regenerates the ruleset before the
transaction commits, so a zone that cannot be expressed in nftables -- a route
that is a default route, a slug colliding with a group -- is a 422 rather than
a row that breaks the next agent poll.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ...config import Settings, get_settings
from ...db import get_db
from ...models import Group, GroupKind, Peer, ZoneRoute
from ...schemas import (
    ZoneCreate,
    ZoneRead,
    ZoneRouteCreate,
    ZoneRouteRead,
    ZoneRouteUpdate,
    ZoneUpdate,
)
from ...services import audit
from ..deps import (
    audit_context,
    integrity_conflict,
    regenerate_or_422,
    require_admin,
)

router = APIRouter(
    prefix="/api/v1/zones", tags=["zones"], dependencies=[Depends(require_admin)]
)


def _get_or_404(session: Session, zone_id: uuid.UUID) -> Group:
    zone = session.get(Group, zone_id)
    if zone is None or zone.kind is not GroupKind.ZONE:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "zone not found")
    return zone


def _serialise(session: Session, zone: Group) -> dict:
    peer_count = session.execute(
        select(func.count()).select_from(Peer).where(Peer.zone_id == zone.id)
    ).scalar_one()
    return {
        "id": zone.id,
        "slug": zone.slug,
        "name": zone.name,
        "description": zone.description,
        "internet_exit": zone.internet_exit,
        "intra_zone": zone.intra_zone,
        "session_lifetime_seconds": zone.session_lifetime_seconds,
        "routes": sorted(zone.routes, key=lambda r: r.cidr),
        "peer_count": peer_count,
        "created_at": zone.created_at,
        "updated_at": zone.updated_at,
    }


# --------------------------------------------------------------------------- #
# zones
# --------------------------------------------------------------------------- #


@router.get("", response_model=list[ZoneRead])
def list_zones(session: Session = Depends(get_db)) -> list[dict]:
    zones = (
        session.execute(
            select(Group)
            .options(selectinload(Group.routes))
            .where(Group.kind == GroupKind.ZONE)
            .order_by(Group.slug)
        )
        .scalars()
        .all()
    )
    return [_serialise(session, zone) for zone in zones]


@router.post("", response_model=ZoneRead, status_code=status.HTTP_201_CREATED)
def create_zone(
    payload: ZoneCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    zone = Group(kind=GroupKind.ZONE, **payload.model_dump())
    session.add(zone)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(
            exc,
            f"slug {payload.slug!r} is already taken (groups and zones share one "
            "namespace, so an ACL rule naming it is never ambiguous)",
        ) from exc

    audit.record(
        session,
        action="zone.create",
        object_type="zone",
        object_id=zone.id,
        **audit_context(request),
        detail={"slug": zone.slug},
    )
    regenerate_or_422(session, settings, "zone.create")
    session.commit()
    return _serialise(session, zone)


@router.get("/{zone_id}", response_model=ZoneRead)
def get_zone(zone_id: uuid.UUID, session: Session = Depends(get_db)) -> dict:
    return _serialise(session, _get_or_404(session, zone_id))


@router.patch("/{zone_id}", response_model=ZoneRead)
def update_zone(
    zone_id: uuid.UUID,
    payload: ZoneUpdate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    zone = _get_or_404(session, zone_id)
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(zone, key, value)
    session.flush()

    audit.record(
        session,
        action="zone.update",
        object_type="zone",
        object_id=zone.id,
        **audit_context(request),
        detail={"slug": zone.slug, "changes": list(changes)},
    )
    regenerate_or_422(session, settings, "zone.update")
    session.commit()
    return _serialise(session, zone)


@router.delete("/{zone_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_zone(
    zone_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    """Delete a zone. Its routes go with it and its peers become unassigned.

    Both directions narrow access rather than widening it, which is the only
    acceptable behaviour for a delete in an access-control system: a peer with
    no zone reaches nothing through one.
    """
    zone = _get_or_404(session, zone_id)
    slug = zone.slug
    session.delete(zone)
    session.flush()

    audit.record(
        session,
        action="zone.delete",
        object_type="zone",
        object_id=zone_id,
        **audit_context(request),
        detail={"slug": slug},
    )
    regenerate_or_422(session, settings, "zone.delete")
    session.commit()


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #


@router.get("/{zone_id}/routes", response_model=list[ZoneRouteRead])
def list_routes(zone_id: uuid.UUID, session: Session = Depends(get_db)) -> list[ZoneRoute]:
    zone = _get_or_404(session, zone_id)
    return sorted(zone.routes, key=lambda r: r.cidr)


@router.post(
    "/{zone_id}/routes", response_model=ZoneRouteRead, status_code=status.HTTP_201_CREATED
)
def create_route(
    zone_id: uuid.UUID,
    payload: ZoneRouteCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ZoneRoute:
    zone = _get_or_404(session, zone_id)
    if payload.via_peer_id is not None and session.get(Peer, payload.via_peer_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unknown via_peer_id")

    # Appended to the relationship, not inserted by foreign key. ``Group.routes``
    # is already loaded on this object (lazy="selectin" in _get_or_404), so a
    # bare INSERT leaves the collection stale -- and ``_regenerate_or_422`` below
    # would then validate a zone that does not contain the route being added.
    # Measured: the validator saw [] while the row was in the table, so a route
    # the generator rejects was committed anyway and every later regeneration
    # failed. The relationship keeps the object graph and the table in step.
    route = ZoneRoute(**payload.model_dump())
    zone.routes.append(route)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(
            exc, f"{payload.cidr} is already routed in zone {zone.slug!r}"
        ) from exc

    audit.record(
        session,
        action="zone.route.create",
        object_type="zone",
        object_id=zone.id,
        **audit_context(request),
        detail={"cidr": route.cidr, "via_peer_id": str(route.via_peer_id or "")},
    )
    regenerate_or_422(session, settings, "zone.route.create")
    session.commit()
    return route


@router.patch("/{zone_id}/routes/{route_id}", response_model=ZoneRouteRead)
def update_route(
    zone_id: uuid.UUID,
    route_id: uuid.UUID,
    payload: ZoneRouteUpdate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ZoneRoute:
    zone = _get_or_404(session, zone_id)
    route = session.get(ZoneRoute, route_id)
    if route is None or route.zone_id != zone.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "route not found in this zone")

    changes = payload.model_dump(exclude_unset=True)
    if changes.get("via_peer_id") is not None and (
        session.get(Peer, changes["via_peer_id"]) is None
    ):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unknown via_peer_id")
    for key, value in changes.items():
        setattr(route, key, value)
    session.flush()

    audit.record(
        session,
        action="zone.route.update",
        object_type="zone",
        object_id=zone.id,
        **audit_context(request),
        detail={"cidr": route.cidr, "changes": list(changes)},
    )
    regenerate_or_422(session, settings, "zone.route.update")
    session.commit()
    return route


@router.delete(
    "/{zone_id}/routes/{route_id}", status_code=status.HTTP_204_NO_CONTENT
)
def delete_route(
    zone_id: uuid.UUID,
    route_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    zone = _get_or_404(session, zone_id)
    route = session.get(ZoneRoute, route_id)
    if route is None or route.zone_id != zone.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "route not found in this zone")
    cidr = route.cidr
    # Removed from the collection for the same reason it is appended to it on
    # create: delete-orphan turns this into the DELETE, and the zone the
    # validator sees below no longer contains the route.
    zone.routes.remove(route)
    session.flush()

    audit.record(
        session,
        action="zone.route.delete",
        object_type="zone",
        object_id=zone.id,
        **audit_context(request),
        detail={"cidr": cidr},
    )
    regenerate_or_422(session, settings, "zone.route.delete")
    session.commit()
