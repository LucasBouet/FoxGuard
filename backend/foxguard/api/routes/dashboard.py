"""Read-only aggregates for the admin dashboard.

Everything here could be assembled client-side from the CRUD endpoints. It is
not, for two reasons: an overview screen that fires eight requests and adds up
the results will disagree with itself the moment something changes between
them, and "who can talk to whom" is a question with a single correct answer that
belongs next to the code that compiles those rules into nftables.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import (
    AclRule,
    AuditLog,
    Group,
    Peer,
    PeerSession,
    RulesetStatus,
    RulesetVersion,
    SessionStatus,
    Tag,
    User,
)
from ...nftables import EndpointKind, ruleset_digest
from ...schemas import AuditLogRead, DashboardRead, PolicyMatrixRead, TagRead
from ...services import ruleset as ruleset_service
from ..deps import require_admin

router = APIRouter(prefix="/api/v1", tags=["dashboard"], dependencies=[Depends(require_admin)])


@router.get("/dashboard", response_model=DashboardRead)
def overview(
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    audit_limit: int = Query(default=10, ge=0, le=100),
) -> dict:
    """One snapshot of the whole control plane, taken in one transaction."""
    by_state = dict(
        session.execute(select(Peer.state, func.count()).group_by(Peer.state)).all()
    )
    by_type = dict(
        session.execute(select(Peer.peer_type, func.count()).group_by(Peer.peer_type)).all()
    )

    current = ruleset_service.render(session, settings)
    digest = ruleset_digest(current)
    applied = session.execute(
        select(RulesetVersion)
        .where(RulesetVersion.status == RulesetStatus.APPLIED)
        .order_by(RulesetVersion.applied_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    recent = (
        session.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(audit_limit))
        .scalars()
        .all()
        if audit_limit
        else []
    )

    return {
        "peers_total": sum(by_state.values()),
        # Keys as plain strings: the dashboard renders them and a JSON object
        # keyed by enum members is not something a client can rely on.
        "peers_by_state": {state.value: count for state, count in by_state.items()},
        "peers_by_type": {kind.value: count for kind, count in by_type.items()},
        "active_sessions": session.execute(
            select(func.count())
            .select_from(PeerSession)
            .where(PeerSession.status == SessionStatus.ACTIVE)
        ).scalar_one(),
        "groups": session.execute(select(func.count()).select_from(Group)).scalar_one(),
        "acl_rules": session.execute(
            select(func.count()).select_from(AclRule).where(AclRule.enabled.is_(True))
        ).scalar_one(),
        "acl_rules_disabled": session.execute(
            select(func.count()).select_from(AclRule).where(AclRule.enabled.is_(False))
        ).scalar_one(),
        "users": session.execute(select(func.count()).select_from(User)).scalar_one(),
        "ruleset": {
            "digest": digest,
            "applied_digest": applied.digest if applied else None,
            "status": applied.status if applied else None,
            "applied_at": applied.applied_at if applied else None,
            # The one number that says whether the box is running what the
            # database describes. Anything else on this screen is inventory.
            "in_sync": bool(applied and applied.digest == digest),
        },
        "recent_audit": [AuditLogRead.model_validate(entry) for entry in recent],
    }


@router.get("/policies/matrix", response_model=PolicyMatrixRead)
def policy_matrix(session: Session = Depends(get_db)) -> dict:
    """Who may reach whom, as a grid.

    Resolved here rather than in the browser so the dashboard and the generator
    cannot drift: both read the same ``acl_rules`` in the same
    ``(priority, ref)`` order, which is the order nftables will evaluate them.

    A cell's ``action`` is the **first matching rule's**, mirroring the
    dataplane: a later ``accept`` behind an earlier ``drop`` never fires, and
    showing it as "allowed" would be a lie a reader might act on.
    """
    rules = (
        session.execute(
            select(AclRule)
            .where(AclRule.enabled.is_(True))
            .order_by(AclRule.priority, AclRule.ref)
        )
        .scalars()
        .all()
    )

    def label(kind: EndpointKind, group: Group | None, cidr: str | None) -> str:
        if kind is EndpointKind.GROUP and group is not None:
            return group.slug
        if kind is EndpointKind.CIDR and cidr:
            return cidr
        return "any"

    cells: dict[tuple[str, str], dict] = {}
    sources: list[str] = []
    destinations: list[str] = []
    for rule in rules:
        src = label(rule.src_kind, rule.src_group, rule.src_cidr)
        dst = label(rule.dst_kind, rule.dst_group, rule.dst_cidr)
        if src not in sources:
            sources.append(src)
        if dst not in destinations:
            destinations.append(dst)

        cell = cells.get((src, dst))
        if cell is None:
            cells[(src, dst)] = {
                "src": src,
                "dst": dst,
                "action": rule.action,
                "rule_refs": [rule.ref],
            }
        else:
            # Keep the first rule's action -- it is the one that decides -- but
            # list every ref so the UI can show what else targets this pair.
            cell["rule_refs"].append(rule.ref)

    # Groups with no rules at all still belong on the axes: an empty row is the
    # useful observation that a group can reach nothing.
    for group in session.execute(select(Group).order_by(Group.slug)).scalars().all():
        if group.slug not in sources:
            sources.append(group.slug)
        if group.slug not in destinations:
            destinations.append(group.slug)

    return {
        "sources": sorted(sources),
        "destinations": sorted(destinations),
        "cells": list(cells.values()),
    }


@router.get("/tags", response_model=list[TagRead])
def list_tags(session: Session = Depends(get_db)) -> list[Tag]:
    """Every tag in use, for the dashboard's peer filter."""
    return list(session.execute(select(Tag).order_by(Tag.name)).scalars().all())
