"""ACL rule CRUD.

Every mutation regenerates the whole ruleset and validates it *before* the
transaction commits, so a rule that cannot be expressed in nftables is rejected
with a 422 instead of landing in the database and breaking the next agent poll.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import AclRule, Group, GroupKind
from ...nftables import EndpointKind
from ...schemas import AclEndpoint, AclRuleCreate, AclRuleRead, AclRuleUpdate
from ...services import audit
from ..deps import (
    audit_context,
    integrity_conflict,
    regenerate_or_422,
    require_admin,
)

router = APIRouter(
    prefix="/api/v1/acl-rules", tags=["acl"], dependencies=[Depends(require_admin)]
)


def _serialise_endpoint(
    kind: EndpointKind, group: Group | None, cidr: str | None
) -> dict:
    is_zone = kind is EndpointKind.ZONE
    return {
        "kind": kind,
        "group_slug": group.slug if group and not is_zone else None,
        "zone_slug": group.slug if group and is_zone else None,
        "cidr": cidr,
    }


def _serialise(rule: AclRule) -> dict:
    return {
        "id": rule.id,
        "ref": rule.ref,
        "name": rule.name,
        "description": rule.description,
        "priority": rule.priority,
        "enabled": rule.enabled,
        "action": rule.action,
        "src": _serialise_endpoint(rule.src_kind, rule.src_group, rule.src_cidr),
        "dst": _serialise_endpoint(rule.dst_kind, rule.dst_group, rule.dst_cidr),
        "protocol": rule.protocol,
        "dst_port_start": rule.dst_port_start,
        "dst_port_end": rule.dst_port_end,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }


def _group_id(session: Session, endpoint: AclEndpoint) -> uuid.UUID | None:
    """Resolve a group or zone endpoint to the ``groups`` row it references.

    The kind is re-checked against the row: naming a zone with ``kind=group``
    would store a reference the generator then renders against the *group* set,
    which for a zone is empty -- a rule that silently matches nothing is worse
    than one that is refused.
    """
    if endpoint.kind is EndpointKind.GROUP:
        slug, expected, label = endpoint.group_slug, GroupKind.GROUP, "group"
    elif endpoint.kind is EndpointKind.ZONE:
        slug, expected, label = endpoint.zone_slug, GroupKind.ZONE, "zone"
    else:
        return None

    group = session.execute(
        select(Group).where(Group.slug == slug)
    ).scalar_one_or_none()
    if group is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown {label} {slug!r}"
        )
    if group.kind is not expected:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{slug!r} is a {group.kind.value}, not a {label}",
        )
    return group.id


def _endpoint_columns(session: Session, endpoint: AclEndpoint, side: str) -> dict:
    return {
        f"{side}_kind": endpoint.kind,
        # One column for groups and zones alike: a zone is a groups row, and
        # the kind above says how to read the reference.
        f"{side}_group_id": _group_id(session, endpoint),
        f"{side}_cidr": endpoint.cidr if endpoint.kind is EndpointKind.CIDR else None,
    }


@router.get("", response_model=list[AclRuleRead])
def list_rules(session: Session = Depends(get_db)) -> list[dict]:
    rules = (
        session.execute(select(AclRule).order_by(AclRule.priority, AclRule.ref))
        .scalars()
        .unique()
        .all()
    )
    return [_serialise(rule) for rule in rules]


@router.post("", response_model=AclRuleRead, status_code=status.HTTP_201_CREATED)
def create_rule(
    payload: AclRuleCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    rule = AclRule(
        ref=payload.ref,
        name=payload.name,
        description=payload.description,
        priority=payload.priority,
        enabled=payload.enabled,
        action=payload.action,
        protocol=payload.protocol,
        dst_port_start=payload.dst_port_start,
        dst_port_end=payload.dst_port_end,
        **_endpoint_columns(session, payload.src, "src"),
        **_endpoint_columns(session, payload.dst, "dst"),
    )
    session.add(rule)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(
            exc, f"rule ref {payload.ref!r} already exists"
        ) from exc

    audit.record(
        session,
        action="acl.create",
        object_type="acl_rule",
        object_id=rule.id,
        **audit_context(request),
        detail={"ref": rule.ref},
    )
    regenerate_or_422(session, settings, "acl.create")
    session.commit()
    return _serialise(rule)


@router.patch("/{rule_id}", response_model=AclRuleRead)
def update_rule(
    rule_id: uuid.UUID,
    payload: AclRuleUpdate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    rule = session.get(AclRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "acl rule not found")

    changes = payload.model_dump(exclude_unset=True)
    if "src" in changes and payload.src is not None:
        changes.pop("src")
        for key, value in _endpoint_columns(session, payload.src, "src").items():
            setattr(rule, key, value)
    if "dst" in changes and payload.dst is not None:
        changes.pop("dst")
        for key, value in _endpoint_columns(session, payload.dst, "dst").items():
            setattr(rule, key, value)
    for key, value in changes.items():
        setattr(rule, key, value)
    session.flush()

    audit.record(
        session,
        action="acl.update",
        object_type="acl_rule",
        object_id=rule.id,
        **audit_context(request),
        detail={"ref": rule.ref, "changes": list(payload.model_dump(exclude_unset=True))},
    )
    regenerate_or_422(session, settings, "acl.update")
    session.commit()
    return _serialise(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    rule = session.get(AclRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "acl rule not found")
    ref = rule.ref
    session.delete(rule)
    session.flush()

    audit.record(
        session,
        action="acl.delete",
        object_type="acl_rule",
        object_id=rule_id,
        **audit_context(request),
        detail={"ref": ref},
    )
    regenerate_or_422(session, settings, "acl.delete")
    session.commit()
