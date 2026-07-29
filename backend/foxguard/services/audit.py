"""Audit trail helpers.

Every state change that can affect the dataplane goes through here. The rows
are append-only: nothing in the API updates or deletes an ``audit_log`` entry.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from ..models import ActorType, AuditLog

__all__ = ["record"]


def record(
    session: Session,
    *,
    action: str,
    actor_type: ActorType = ActorType.ADMIN,
    actor_user_id: uuid.UUID | None = None,
    actor_label: str | None = None,
    object_type: str | None = None,
    object_id: str | uuid.UUID | None = None,
    source_ip: str | None = None,
    detail: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        action=action,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        actor_label=actor_label,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        source_ip=source_ip,
        detail=detail or {},
    )
    session.add(entry)
    return entry
