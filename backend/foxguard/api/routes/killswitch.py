"""The kill switch, in a module of its own.

Isolated deliberately. It is the only endpoint that can take the entire fleet
off the network in one call, and burying it among peer CRUD would make it look
like an ordinary operation. See ``services/killswitch`` for what each mode does
and why quarantine alone is not enough for a suspected compromise.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...schemas import KillSwitchRequest, KillSwitchResultRead
from ...services import killswitch
from ..deps import audit_context, require_admin

router = APIRouter(
    prefix="/api/v1/kill-switch",
    tags=["kill-switch"],
    dependencies=[Depends(require_admin)],
)


@router.post("", response_model=KillSwitchResultRead, status_code=status.HTTP_200_OK)
def trigger_kill_switch(
    payload: KillSwitchRequest,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> KillSwitchResultRead:
    """Cut every peer at once. Requires the confirmation phrase for the mode.

    There is no undo. Restoring the fleet is a deliberate, peer-by-peer act --
    an "undo" would have to guess which peers *should* come back, at the one
    moment when guessing is least appropriate. The previous state of every peer
    is written into the audit entry so the reconstruction is mechanical.
    """
    # The one action where "who did this" matters most, so it carries the
    # signed-in administrator rather than a generic label.
    context = audit_context(request)
    result = killswitch.trigger(
        session,
        settings,
        mode=payload.mode,
        actor_type=context.get("actor_type"),
        actor_user_id=context.get("actor_user_id"),
        actor_label=context.get("actor_label"),
        source_ip=context.get("source_ip"),
    )
    session.commit()

    return KillSwitchResultRead(
        mode=result.mode,
        affected=[
            {
                "peer_id": item.peer_id,
                "name": item.name,
                "peer_type": item.peer_type,
                "previous_state": item.previous_state,
                "state": item.state,
            }
            for item in result.affected
        ],
        sessions_revoked=result.sessions_revoked,
        regenerated=result.regenerated,
    )
