"""Group CRUD."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import Group, GroupKind
from ...schemas import GroupCreate, GroupRead, GroupUpdate
from ...services import audit
from ..deps import (
    audit_context,
    integrity_conflict,
    regenerate_or_422,
    require_admin,
)

router = APIRouter(
    prefix="/api/v1/groups", tags=["groups"], dependencies=[Depends(require_admin)]
)


def _get_or_404(session: Session, group_id: uuid.UUID) -> Group:
    """Zones share this table but are not reachable through this router.

    Returning one here would let it be renamed, have ``internet_exit`` flipped,
    or be deleted without the zone endpoints' route handling ever running.
    """
    group = session.get(Group, group_id)
    if group is None or group.kind is GroupKind.ZONE:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "group not found")
    return group


@router.get("", response_model=list[GroupRead])
def list_groups(session: Session = Depends(get_db)) -> list[Group]:
    return list(
        session.execute(
            select(Group).where(Group.kind != GroupKind.ZONE).order_by(Group.slug)
        )
        .scalars()
        .all()
    )


@router.post("", response_model=GroupRead, status_code=status.HTTP_201_CREATED)
def create_group(
    payload: GroupCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Group:
    if payload.kind is GroupKind.ZONE:
        # Creating one here would skip everything that makes a zone a zone --
        # routes, the single-zone-per-peer rule, the dashboard's own page.
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "create zones through POST /api/v1/zones",
        )
    group = Group(**payload.model_dump())
    session.add(group)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(
            exc, f"group slug {payload.slug!r} already exists"
        ) from exc

    audit.record(
        session,
        action="group.create",
        object_type="group",
        object_id=group.id,
        **audit_context(request),
        detail={"slug": group.slug},
    )
    regenerate_or_422(session, settings, "group.create")
    session.commit()
    return group


@router.get("/{group_id}", response_model=GroupRead)
def get_group(group_id: uuid.UUID, session: Session = Depends(get_db)) -> Group:
    return _get_or_404(session, group_id)


@router.patch("/{group_id}", response_model=GroupRead)
def update_group(
    group_id: uuid.UUID,
    payload: GroupUpdate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Group:
    group = _get_or_404(session, group_id)
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(group, key, value)
    session.flush()

    audit.record(
        session,
        action="group.update",
        object_type="group",
        object_id=group.id,
        **audit_context(request),
        detail={"slug": group.slug, "changes": list(changes)},
    )
    regenerate_or_422(session, settings, "group.update")
    session.commit()
    return group


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_group(
    group_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    group = _get_or_404(session, group_id)
    slug = group.slug
    # ACL rules referencing this group cascade away with it, which is why the
    # regeneration below cannot produce a dangling group reference.
    session.delete(group)
    session.flush()

    audit.record(
        session,
        action="group.delete",
        object_type="group",
        object_id=group_id,
        **audit_context(request),
        detail={"slug": slug},
    )
    regenerate_or_422(session, settings, "group.delete")
    session.commit()
