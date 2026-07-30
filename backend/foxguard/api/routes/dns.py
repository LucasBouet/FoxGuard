"""Internal DNS: the zone as rendered, and the records an admin authors by hand.

Every mutation here re-renders the whole zone inside the same transaction and
rolls back if it will not render. That is a deliberate departure from the ACL
routes, which let the ruleset be regenerated after the fact: a malformed nft
ruleset is caught by ``nft -c`` on the gateway before anything is applied,
whereas a malformed zone would simply be *skipped* by the agent (see
``services/dns.render_or_none``) and the administrator would be left with a
record that exists in the database and does nothing.

Two failure modes that look alike are treated differently, and the distinction
is the point:

* **an alias to a name that never existed** is a typo, refused here with a 409;
* **an alias whose target has since been revoked** is not an error at all. The
  projection drops it and the zone still renders, because otherwise revoking a
  peer -- or firing the kill switch -- would take name resolution down for the
  whole fleet. ``GET /api/v1/dns`` lists those under ``warnings``.
"""

from __future__ import annotations

import ipaddress
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...dns import DnsValidationError, RecordKind, dns_digest
from ...models import DnsRecord
from ...schemas import (
    DNS_NAME_PATTERN,
    DnsRecordCreate,
    DnsRecordRead,
    DnsRecordUpdate,
    DnsZoneRead,
)
from ...services import audit
from ...services import dns as dns_service
from ..deps import audit_context, integrity_conflict, require_admin

router = APIRouter(
    prefix="/api/v1/dns", tags=["dns"], dependencies=[Depends(require_admin)]
)


def _get_or_404(session: Session, record_id: uuid.UUID) -> DnsRecord:
    record = session.get(DnsRecord, record_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "DNS record not found")
    return record


def _assert_target_exists(session: Session, settings: Settings, record: DnsRecord) -> None:
    """An alias to a name that never existed is a typo, and refused.

    Distinct from an alias whose target *used to* exist and has since been
    revoked: that one is dropped at render time, because an access-control
    action must not be able to take the zone down. Only the typo is a 409.
    """
    if record.kind is not RecordKind.CNAME:
        return
    # Read before the rollback: afterwards ``record`` is expired, and touching
    # an attribute would emit a SELECT for a row that no longer exists.
    target = record.value
    if not dns_service.target_exists(session, settings, target):
        session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {
                "message": "the resulting DNS zone is not valid",
                "errors": [
                    f"{target!r} is not a name this resolver knows, so the "
                    "alias would resolve to nothing"
                ],
            },
        )


def _assert_renders(session: Session, settings: Settings) -> None:
    """Refuse the change if the zone it produces is not one we would serve."""
    session.flush()
    try:
        dns_service.render(session, settings)
    except DnsValidationError as exc:
        session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {"message": "the resulting DNS zone is not valid", "errors": list(exc.errors)},
        ) from exc


def _validate_kind_and_value(record: DnsRecord) -> None:
    if record.kind is RecordKind.CNAME:
        if not re.match(DNS_NAME_PATTERN, record.value):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "a CNAME value must be a DNS name"
            )
        return
    expected = 4 if record.kind is RecordKind.A else 6
    try:
        version = ipaddress.ip_address(record.value).version
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if version != expected:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"an {record.kind.value} record needs an IPv{expected} address",
        )


@router.get("", response_model=DnsZoneRead)
def read_zone(
    session: Session = Depends(get_db), settings: Settings = Depends(get_settings)
) -> DnsZoneRead:
    """The zone as it stands, artefacts included.

    Answers even when DNS is disabled, so the dashboard can show what *would* be
    served -- and reports validation errors rather than a 500, because "your
    zone is broken" is the single most useful thing this endpoint can say.
    """
    base = DnsZoneRead(
        enabled=settings.dns_enabled,
        zone=settings.dns_zone,
        mode=settings.dns_mode,
        listen_addresses=list(settings.dns_listen),
        upstreams=list(settings.dns_upstreams),
    )
    try:
        hosts, conf = dns_service.render(session, settings)
    except DnsValidationError as exc:
        base.errors = list(exc.errors)
        return base
    base.hosts = hosts
    base.conf = conf
    base.digest = dns_digest(hosts, conf)
    # Aliases whose target has since been revoked are dropped from the zone
    # rather than breaking it. Saying so here is what keeps that from being a
    # silent disappearance.
    base.warnings = dns_service.dangling_aliases(session, settings)
    return base


@router.get("/records", response_model=list[DnsRecordRead])
def list_records(session: Session = Depends(get_db)) -> list[DnsRecord]:
    return list(
        session.execute(select(DnsRecord).order_by(DnsRecord.name)).scalars().all()
    )


@router.post("/records", response_model=DnsRecordRead, status_code=status.HTTP_201_CREATED)
def create_record(
    payload: DnsRecordCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DnsRecord:
    record = DnsRecord(**payload.model_dump())
    session.add(record)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(
            exc, f"a DNS record named {payload.name!r} already exists"
        ) from exc

    _assert_target_exists(session, settings, record)
    _assert_renders(session, settings)
    audit.record(
        session,
        action="dns.record.create",
        object_type="dns_record",
        object_id=record.id,
        **audit_context(request),
        detail={"name": record.name, "kind": record.kind.value, "value": record.value},
    )
    session.commit()
    return record


@router.patch("/records/{record_id}", response_model=DnsRecordRead)
def update_record(
    record_id: uuid.UUID,
    payload: DnsRecordUpdate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DnsRecord:
    record = _get_or_404(session, record_id)
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(record, key, value)

    # Re-checked against the merged row: a PATCH carrying only ``value`` has no
    # ``kind`` of its own to be validated against, and an A record quietly
    # holding an IPv6 address renders a zone that answers the wrong question.
    _validate_kind_and_value(record)

    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(exc, "another DNS record already has that name") from exc

    _assert_target_exists(session, settings, record)
    _assert_renders(session, settings)
    audit.record(
        session,
        action="dns.record.update",
        object_type="dns_record",
        object_id=record.id,
        **audit_context(request),
        detail={"name": record.name, "changes": list(changes)},
    )
    session.commit()
    return record


@router.delete("/records/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_record(
    record_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    record = _get_or_404(session, record_id)
    name = record.name
    session.delete(record)

    # Deleting can break the zone too: a CNAME pointing at the A record that
    # just went away no longer resolves.
    _assert_renders(session, settings)
    audit.record(
        session,
        action="dns.record.delete",
        object_type="dns_record",
        object_id=record_id,
        **audit_context(request),
        detail={"name": name},
    )
    session.commit()
