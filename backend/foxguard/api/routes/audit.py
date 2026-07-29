"""Read-only access to the audit trail."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...db import get_db
from ...models import AuditLog
from ...schemas import AuditLogRead
from ..deps import require_admin

router = APIRouter(
    prefix="/api/v1/audit-log", tags=["audit"], dependencies=[Depends(require_admin)]
)


@router.get("", response_model=list[AuditLogRead])
def list_entries(
    session: Session = Depends(get_db),
    action: str | None = Query(default=None),
    object_type: str | None = Query(default=None),
    object_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[AuditLog]:
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if object_type:
        stmt = stmt.where(AuditLog.object_type == object_type)
    if object_id:
        stmt = stmt.where(AuditLog.object_id == object_id)
    return list(session.execute(stmt.limit(limit).offset(offset)).scalars().all())
