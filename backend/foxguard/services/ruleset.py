"""Projection of the database onto a :class:`RulesetSpec`, and versioning.

This module is the only place that knows both the ORM and the dataplane model.
Keeping it thin means the generator stays testable in isolation, and that
"regenerate everything from the database" is the *only* way rules are produced
-- there is no incremental path that could drift.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session, selectinload

from ..config import Settings
from ..models import AclRule, Group, GroupKind, Peer, RulesetStatus, RulesetVersion
from ..nftables import (
    Endpoint,
    EndpointKind,
    GroupSpec,
    PeerSpec,
    RouteSpec,
    RulesetSpec,
    RulesetValidationError,
    RuleSpec,
    ZoneSpec,
    generate_ruleset,
    ruleset_digest,
)

__all__ = [
    "build_spec",
    "latest_applied",
    "mark_applied",
    "mark_failed",
    "regenerate",
    "render",
    "store_version",
]


def _endpoint(kind: EndpointKind, group: Group | None, cidr: str | None) -> Endpoint:
    # A rule whose group vanished would silently widen or narrow access. The FK
    # is ON DELETE CASCADE and the table has CHECK constraints so this cannot
    # normally happen -- but raise rather than assert, because an assert is
    # stripped under `python -O` and would let a malformed rule through.
    if kind in (EndpointKind.GROUP, EndpointKind.ZONE):
        if group is None:
            raise RulesetValidationError(
                [f"ACL rule has src/dst kind {kind.value!r} but no groups row"]
            )
        # The row's own kind decides which set the rule matches against, not the
        # endpoint kind. They can only disagree if a group was converted into a
        # zone behind a rule's back, and rendering against the wrong set would
        # silently point the rule at a different population.
        if group.kind is GroupKind.ZONE:
            return Endpoint.zone(group.slug)
        return Endpoint.group(group.slug)
    if kind is EndpointKind.CIDR:
        if cidr is None:
            raise RulesetValidationError(
                ["ACL rule has src/dst kind 'cidr' but no CIDR value"]
            )
        return Endpoint.network(cidr)
    return Endpoint.any_()


def build_spec(session: Session, settings: Settings) -> RulesetSpec:
    """Build the full dataplane spec from current database state."""
    rows = (
        session.execute(
            select(Group).options(selectinload(Group.routes)).order_by(Group.slug)
        )
        .scalars()
        .all()
    )
    groups = [row for row in rows if row.kind is not GroupKind.ZONE]
    zones = [row for row in rows if row.kind is GroupKind.ZONE]
    peers = (
        session.execute(
            select(Peer)
            .options(selectinload(Peer.groups))
            .order_by(Peer.created_at, Peer.id)
        )
        .scalars()
        .all()
    )
    rules = (
        session.execute(
            select(AclRule).where(AclRule.enabled.is_(True)).order_by(AclRule.priority, AclRule.ref)
        )
        .scalars()
        .all()
    )

    return RulesetSpec(
        gateway=settings.gateway_spec(),
        groups=tuple(
            GroupSpec(slug=group.slug, internet_exit=group.internet_exit)
            for group in groups
        ),
        zones=tuple(
            ZoneSpec(
                slug=zone.slug,
                intra_zone=zone.intra_zone,
                internet_exit=zone.internet_exit,
                routes=tuple(
                    RouteSpec(
                        cidr=route.cidr,
                        via_peer_id=str(route.via_peer_id) if route.via_peer_id else None,
                        comment=route.description,
                    )
                    # Sorted so the rendered set is byte-stable regardless of
                    # the order rows were inserted in.
                    for route in sorted(zone.routes, key=lambda r: r.cidr)
                    if route.enabled
                ),
            )
            for zone in zones
        ),
        peers=tuple(
            PeerSpec(
                id=str(peer.id),
                name=peer.name,
                state=peer.state,
                peer_type=peer.peer_type,
                tunnel_ip=str(peer.tunnel_ip) if peer.tunnel_ip else None,
                tunnel_ip6=str(peer.tunnel_ip6) if peer.tunnel_ip6 else None,
                group_slugs=tuple(
                    sorted(
                        group.slug
                        for group in peer.groups
                        if group.kind is not GroupKind.ZONE
                    )
                ),
                zone_slug=peer.zone.slug if peer.zone else None,
            )
            for peer in peers
        ),
        rules=tuple(
            RuleSpec(
                id=rule.ref,
                priority=rule.priority,
                action=rule.action,
                src=_endpoint(rule.src_kind, rule.src_group, rule.src_cidr),
                dst=_endpoint(rule.dst_kind, rule.dst_group, rule.dst_cidr),
                protocol=rule.protocol,
                dst_port_start=rule.dst_port_start,
                dst_port_end=rule.dst_port_end,
                comment=rule.name,
            )
            for rule in rules
        ),
    )


def render(session: Session, settings: Settings) -> str:
    """Render the current database state as an nft script."""
    return generate_ruleset(build_spec(session, settings))


def store_version(
    session: Session, content: str, *, generated_by: str | None = None
) -> RulesetVersion:
    """Persist a rendered ruleset, deduplicating on digest.

    Returns the existing row when nothing changed, so a no-op reconciliation
    does not fill the table with identical versions.
    """
    digest = ruleset_digest(content)
    existing = session.execute(
        select(RulesetVersion).where(RulesetVersion.digest == digest).limit(1)
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    # ORM-enabled UPDATE (not ``__table__.update()``) so objects already loaded
    # in this session see the new status instead of going stale.
    session.execute(
        update(RulesetVersion)
        .where(RulesetVersion.status == RulesetStatus.PENDING)
        .values(status=RulesetStatus.SUPERSEDED),
        execution_options={"synchronize_session": "fetch"},
    )
    version = RulesetVersion(
        digest=digest,
        content=content,
        status=RulesetStatus.PENDING,
        generated_by=generated_by,
    )
    session.add(version)
    session.flush()
    return version


def mark_applied(session: Session, version: RulesetVersion) -> RulesetVersion:
    version.status = RulesetStatus.APPLIED
    version.applied_at = datetime.now(UTC)
    version.error = None
    session.add(version)
    return version


def mark_failed(session: Session, version: RulesetVersion, error: str) -> RulesetVersion:
    version.status = RulesetStatus.FAILED
    version.error = error[:4000]
    session.add(version)
    return version


def regenerate(
    session: Session, settings: Settings, *, generated_by: str | None = None
) -> RulesetVersion:
    """Render the whole ruleset from database state and record it as pending.

    Called after *every* mutation. There is no incremental update path, which is
    what makes "database state -> ruleset" idempotent: the same state always
    yields the same digest, so drift is detectable by comparing digests.
    """
    return store_version(session, render(session, settings), generated_by=generated_by)


def latest_applied(session: Session) -> RulesetVersion | None:
    return session.execute(
        select(RulesetVersion)
        .where(RulesetVersion.status == RulesetStatus.APPLIED)
        .order_by(RulesetVersion.applied_at.desc())
        .limit(1)
    ).scalar_one_or_none()
