"""The panic button: cut every peer at once.

For the moment you suspect a compromise and want the fleet dark while you look.
It ignores sessions, enrollment keys and peer type -- server peers included, in
deliberate exception to their normal "stable until the key is revoked" rule.

## Two modes, because "quarantine everything" has a hole

``quarantine`` moves active peers back to ``quarantined``. Everyone is off the
network *right now*, including their open connections, because the quarantine
drop is evaluated before the ``established,related`` accept.

But quarantine is the state peers authenticate *out of*. A user peer types their
password again; a **server peer re-presents its enrollment key, automatically,
within one poll**. So for server peers this mode buys seconds, not an
investigation window. It is the default because it is what the brief asks for
and because it is the right tool for "something looks odd, make everyone
re-authenticate".

``lockdown`` moves them to ``disabled`` instead: no dataplane presence at all,
and ``disabled`` is outside the self-service transition table, so no credential
brings a peer back. Only an administrator can. **This is the one to reach for
when you actually suspect a compromise.**

## It can never grant access

Whatever the mode, a peer's access only ever narrows:

* ``revoked`` peers are never touched. The state is terminal, and it is
  *stricter* than both targets -- "quarantining" a revoked peer would put it
  back in ``fg_quarantine`` and hand it the portal.
* ``disabled`` peers are never touched in ``quarantine`` mode, for the same
  reason.
* ``staging`` peers are left alone in ``quarantine`` mode: they already have
  exactly quarantine's access, and rewriting their state would erase the fact
  that they never enrolled.

A kill switch that increases anybody's reach is worse than no kill switch,
because it is pressed precisely when nobody has time to check.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from sqlalchemy import select, update
from sqlalchemy.orm import Session, selectinload

from ..config import Settings
from ..models import ActorType, Peer, PeerSession, SessionStatus
from ..nftables import PeerState
from . import audit, peer_state
from . import ruleset as ruleset_service

logger = logging.getLogger(__name__)

__all__ = [
    "CONFIRMATION",
    "AffectedPeer",
    "KillSwitchMode",
    "KillSwitchResult",
    "trigger",
]


class KillSwitchMode(str, Enum):
    QUARANTINE = "quarantine"
    LOCKDOWN = "lockdown"

    @property
    def target(self) -> PeerState:
        return (
            PeerState.QUARANTINED
            if self is KillSwitchMode.QUARANTINE
            else PeerState.DISABLED
        )

    @property
    def sources(self) -> frozenset[PeerState]:
        """States this mode acts on. Everything else is left strictly alone."""
        if self is KillSwitchMode.QUARANTINE:
            return frozenset({PeerState.ACTIVE})
        return frozenset({PeerState.STAGING, PeerState.QUARANTINED, PeerState.ACTIVE})


#: The phrase the caller must send back. Per mode on purpose: it makes it
#: impossible to fire a lockdown while meaning to quarantine, and it means no
#: single stray POST can take the fleet down.
CONFIRMATION: dict[KillSwitchMode, str] = {
    KillSwitchMode.QUARANTINE: "QUARANTINE ALL PEERS",
    KillSwitchMode.LOCKDOWN: "DISABLE ALL PEERS",
}


@dataclass(frozen=True, slots=True)
class AffectedPeer:
    peer_id: str
    name: str
    peer_type: str
    previous_state: str
    state: str


@dataclass(frozen=True, slots=True)
class KillSwitchResult:
    mode: KillSwitchMode
    affected: tuple[AffectedPeer, ...] = ()
    sessions_revoked: int = 0
    regenerated: bool = False


def trigger(
    session: Session,
    settings: Settings,
    *,
    mode: KillSwitchMode = KillSwitchMode.QUARANTINE,
    actor_type: ActorType | None = None,
    actor_user_id: object | None = None,
    actor_label: str | None = None,
    source_ip: str | None = None,
    now: datetime | None = None,
) -> KillSwitchResult:
    """Cut every peer the mode applies to. Does not commit."""
    now = now or datetime.now(UTC)
    target = mode.target

    peers = (
        session.execute(
            select(Peer)
            .where(Peer.state.in_(tuple(mode.sources)))
            .options(selectinload(Peer.groups))
            .order_by(Peer.name, Peer.id)
        )
        .scalars()
        .all()
    )

    affected: list[AffectedPeer] = []
    for peer in peers:
        # Belt and braces: the source sets above already exclude the terminal
        # and lower-access states, but routing through the same guard as every
        # other transition means a future edit to `sources` cannot quietly
        # resurrect a revoked peer.
        peer_state.assert_admin_transition(peer.state, target)
        affected.append(
            AffectedPeer(
                peer_id=str(peer.id),
                name=peer.name,
                peer_type=peer.peer_type.value,
                previous_state=peer.state.value,
                state=target.value,
            )
        )
        peer.state = target

    # Every live session, not only those of the peers above: a session that
    # outlived its peer's state change would let the Phase 3 sweeper and the
    # dashboard disagree about who is authenticated.
    #
    # `synchronize_session="fetch"` keeps *loaded* attributes of in-session rows
    # current; one that was never loaded (a freshly constructed row's
    # `revoked_at`) keeps its in-memory value until refreshed. Nothing here
    # reads those objects back, and every reader re-queries -- but do not assume
    # the ORM identity map is fully up to date after this statement.
    revoked = session.execute(
        update(PeerSession)
        .where(PeerSession.status == SessionStatus.ACTIVE)
        .values(status=SessionStatus.REVOKED, revoked_at=now),
        execution_options={"synchronize_session": "fetch"},
    ).rowcount

    audit.record(
        session,
        action="killswitch.trigger",
        actor_type=actor_type or ActorType.ADMIN,
        actor_user_id=actor_user_id,
        actor_label=actor_label,
        object_type="fleet",
        source_ip=source_ip,
        detail={
            "mode": mode.value,
            "target_state": target.value,
            "peers_affected": len(affected),
            "sessions_revoked": revoked,
            # Previous states are kept so the fleet can be restored by hand:
            # there is no undo endpoint, and inventing one would mean guessing.
            "peers": [
                {"id": item.peer_id, "name": item.name, "from": item.previous_state}
                for item in affected
            ],
        },
    )
    logger.warning(
        "KILL SWITCH (%s): %d peer(s) -> %s, %d session(s) revoked",
        mode.value,
        len(affected),
        target.value,
        revoked,
    )

    session.flush()
    regenerated = False
    if affected or revoked:
        ruleset_service.regenerate(session, settings, generated_by="killswitch")
        regenerated = True

    return KillSwitchResult(
        mode=mode,
        affected=tuple(affected),
        sessions_revoked=revoked or 0,
        regenerated=regenerated,
    )
