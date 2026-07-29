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
from ...models import AclRule, Group
from ...nftables import EndpointKind, RulesetValidationError
from ...schemas import AclEndpoint, AclRuleCreate, AclRuleRead, AclRuleUpdate
from ...services import audit
from ...services import ruleset as ruleset_service
from ..deps import audit_context, integrity_conflict, require_admin

router = APIRouter(
    prefix="/api/v1/acl-rules", tags=["acl"], dependencies=[Depends(require_admin)]
)


def _serialise(rule: AclRule) -> dict:
    return {
        "id": rule.id,
        "ref": rule.ref,
        "name": rule.name,
        "description": rule.description,
        "priority": rule.priority,
        "enabled": rule.enabled,
        "action": rule.action,
        "src": {
            "kind": rule.src_kind,
            "group_slug": rule.src_group.slug if rule.src_group else None,
            "cidr": rule.src_cidr,
        },
        "dst": {
            "kind": rule.dst_kind,
            "group_slug": rule.dst_group.slug if rule.dst_group else None,
            "cidr": rule.dst_cidr,
        },
        "protocol": rule.protocol,
        "dst_port_start": rule.dst_port_start,
        "dst_port_end": rule.dst_port_end,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }


def _group_id(session: Session, endpoint: AclEndpoint) -> uuid.UUID | None:
    if endpoint.kind is not EndpointKind.GROUP:
        return None
    group = session.execute(
        select(Group).where(Group.slug == endpoint.group_slug)
    ).scalar_one_or_none()
    if group is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"unknown group {endpoint.group_slug!r}",
        )
    return group.id


def _endpoint_columns(session: Session, endpoint: AclEndpoint, side: str) -> dict:
    return {
        f"{side}_kind": endpoint.kind,
        f"{side}_group_id": _group_id(session, endpoint),
        f"{side}_cidr": endpoint.cidr if endpoint.kind is EndpointKind.CIDR else None,
    }


def _regenerate_or_422(session: Session, settings: Settings, actor: str) -> None:
    """Regenerate the ruleset, turning generator rejections into a 422.

    The session is rolled back by the ``get_db`` dependency when this raises, so
    the offending rule never reaches the database.
    """
    try:
        ruleset_service.regenerate(session, settings, generated_by=actor)
    except RulesetValidationError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"message": "resulting ruleset is invalid", "errors": list(exc.errors)},
        ) from exc


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
    _regenerate_or_422(session, settings, "acl.create")
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
    _regenerate_or_422(session, settings, "acl.update")
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
    _regenerate_or_422(session, settings, "acl.delete")
    session.commit()
