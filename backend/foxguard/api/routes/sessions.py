"""Live portal sessions, and a manual handle on the expiry sweep.

Session expiry runs on a timer inside the API process. These endpoints exist so
it is *observable* -- "why did that laptop drop off at 14:03" should be
answerable -- and so the same job can be driven by an external cron on a
deployment that would rather not have a background task at all
(``FOXGUARD_SESSION_SWEEP_ENABLED=false``).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import Peer, PeerSession, SessionStatus, User
from ...schemas import PeerSessionRead, SweepResultRead
from ...services import audit, expiry
from ...services.scheduler import SESSION_SWEEP_LOCK, advisory_lock
from ..deps import audit_context, require_admin

router = APIRouter(
    prefix="/api/v1/sessions", tags=["sessions"], dependencies=[Depends(require_admin)]
)


@router.get("", response_model=list[PeerSessionRead])
def list_sessions(
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    status_filter: SessionStatus | None = Query(default=SessionStatus.ACTIVE, alias="status"),
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[dict]:
    """Portal sessions, newest first. Defaults to the live ones.

    ``expires_at`` is the *effective* deadline, recomputed from current group
    membership rather than read back from the row -- otherwise moving a peer
    into a stricter group would leave this view claiming the old, longer
    session right up until the sweeper contradicted it.
    """
    stmt = (
        select(PeerSession, Peer, User)
        .join(Peer, Peer.id == PeerSession.peer_id)
        .join(User, User.id == PeerSession.user_id)
        .order_by(PeerSession.last_authenticated_at.desc())
        .limit(limit)
    )
    if status_filter is not None:
        stmt = stmt.where(PeerSession.status == status_filter)

    now = datetime.now(UTC)
    rows = []
    for row, peer, user in session.execute(stmt).all():
        deadline = expiry.effective_deadline(peer, row, settings)
        rows.append(
            {
                "id": row.id,
                "peer_id": peer.id,
                "peer_name": peer.name,
                "user_id": user.id,
                "username": user.username,
                "auth_method": row.auth_method,
                "authenticated_at": row.authenticated_at,
                "last_authenticated_at": row.last_authenticated_at,
                "expires_at": deadline,
                "seconds_remaining": (
                    max(0, int((deadline - now).total_seconds()))
                    if deadline is not None
                    else None
                ),
                "source_ip": row.source_ip,
            }
        )
    return rows


@router.post("/sweep", response_model=SweepResultRead, status_code=status.HTTP_200_OK)
def run_sweep(
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> SweepResultRead:
    """Expire whatever is due right now.

    Takes the same advisory lock as the background timer, so calling this from
    cron while the timer is also running cannot double-quarantine anything or
    write the audit entry twice. If the lock is held, this reports ``ran=false``
    rather than waiting -- the work is about to be done by whoever holds it.
    """
    with advisory_lock(session, SESSION_SWEEP_LOCK) as acquired:
        if not acquired:
            return SweepResultRead(expired=[], regenerated=False, ran=False)

        result = expiry.sweep(session, settings)
        if result.expired:
            audit.record(
                session,
                action="session.sweep",
                **audit_context(request),
                detail={"expired": [item.peer_id for item in result.expired]},
            )
        session.commit()

    return SweepResultRead(
        expired=[
            {
                "peer_id": item.peer_id,
                "name": item.name,
                "tunnel_ip": item.tunnel_ip,
                "reason": item.reason,
                "deadline": item.deadline,
            }
            for item in result.expired
        ],
        regenerated=result.regenerated,
        ran=True,
    )
