"""Session expiry for user peers.

The Phase 3 half of the portal: authenticating buys access for a while, not
forever. A peer whose session has run out goes back to quarantine, and because
the quarantine drop is evaluated *before* the ``established,related`` accept,
its open connections are cut rather than merely its new ones. An expiry that
only applied to new flows would be advisory.

**Server peers are never touched here.** Their access is bound to an enrollment
key, not to a session, and the whole point of the two peer types is that a
backup job does not get logged out at 3am. The query filters on
``peer_type = 'user'``, and a test asserts a server peer survives a sweep that
would have expired it twice over.

The sweep is level-triggered like everything else in Foxguard: it asks "who
should not be active right now" and fixes that, so a missed tick, a restart or a
clock jump all converge on the next pass.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..config import Settings
from ..models import ActorType, Peer, PeerSession, SessionStatus
from ..nftables import PeerState, PeerType
from . import audit
from . import ruleset as ruleset_service
from . import sessions as session_service

logger = logging.getLogger(__name__)

__all__ = [
    "ExpiredPeer",
    "SweepResult",
    "effective_deadline",
    "find_expired",
    "sweep",
]

#: Why a peer was expired. Recorded in the audit log so "we quarantined you"
#: can be explained months later.
REASON_TIMEOUT = "session-expired"
REASON_NEVER = "never-authenticated"


def _aware(value: datetime | None) -> datetime | None:
    """PostgreSQL can hand back a naive datetime; treat it as UTC, not local."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class ExpiredPeer:
    peer_id: str
    name: str
    tunnel_ip: str | None
    reason: str
    deadline: datetime | None


@dataclass(frozen=True, slots=True)
class SweepResult:
    expired: tuple[ExpiredPeer, ...] = ()
    regenerated: bool = False

    def __bool__(self) -> bool:
        return bool(self.expired)


def effective_deadline(
    peer: Peer, row: PeerSession | None, settings: Settings
) -> datetime | None:
    """When this peer's access must stop, or ``None`` if it never authenticated.

    The **stricter** of two answers:

    * ``expires_at``, frozen onto the session when the user logged in, and
    * ``last_authenticated_at`` plus the lifetime the peer's *current* groups
      imply.

    Recomputing the second one is what makes group changes take effect on live
    sessions: moving a peer into ``pentest-lab`` (4h) must tighten it now, not at
    the next login. Taking the minimum means the reverse does **not** hold --
    moving a peer into a more lenient group cannot extend a session that is
    already running, which would otherwise be a way to grant someone more time
    without them proving anything.
    """
    anchor = _aware(peer.last_authenticated_at)
    if anchor is None:
        return None
    recomputed = anchor + timedelta(
        seconds=session_service.lifetime_seconds(peer, settings)
    )
    stored = _aware(row.expires_at) if row is not None else None
    return min(recomputed, stored) if stored is not None else recomputed


def find_expired(
    session: Session, settings: Settings, *, now: datetime | None = None
) -> list[tuple[Peer, PeerSession | None, ExpiredPeer]]:
    """Active *user* peers that are no longer entitled to be active."""
    now = now or datetime.now(UTC)

    peers = (
        session.execute(
            select(Peer)
            .where(Peer.peer_type == PeerType.USER, Peer.state == PeerState.ACTIVE)
            .options(selectinload(Peer.groups))
            .order_by(Peer.id)
        )
        .scalars()
        .all()
    )
    if not peers:
        return []

    # One query for every live session rather than one per peer: a sweep runs on
    # a timer and should not scale its query count with the fleet.
    rows = (
        session.execute(
            select(PeerSession).where(
                PeerSession.peer_id.in_([peer.id for peer in peers]),
                PeerSession.status == SessionStatus.ACTIVE,
            )
        )
        .scalars()
        .all()
    )
    live: dict[object, PeerSession] = {}
    for row in rows:
        current = live.get(row.peer_id)
        if current is None or _aware(row.last_authenticated_at) > _aware(
            current.last_authenticated_at
        ):
            live[row.peer_id] = row

    expired: list[tuple[Peer, PeerSession | None, ExpiredPeer]] = []
    for peer in peers:
        row = live.get(peer.id)
        deadline = effective_deadline(peer, row, settings)
        if deadline is None:
            # Active, but with no record of anyone ever authenticating. The API
            # no longer allows this (an admin cannot force a user peer active),
            # so reaching it means a hand-edited row or a bug -- and an
            # unexplained `active` is exactly what quarantine is for.
            reason = REASON_NEVER
        elif deadline <= now:
            reason = REASON_TIMEOUT
        else:
            continue
        expired.append(
            (
                peer,
                row,
                ExpiredPeer(
                    peer_id=str(peer.id),
                    name=peer.name,
                    tunnel_ip=str(peer.tunnel_ip) if peer.tunnel_ip else None,
                    reason=reason,
                    deadline=deadline,
                ),
            )
        )
    return expired


def sweep(
    session: Session, settings: Settings, *, now: datetime | None = None
) -> SweepResult:
    """Quarantine every user peer whose session has run out.

    Does not commit -- the caller owns the transaction, which is what lets the
    scheduler hold an advisory lock across the whole thing.
    """
    now = now or datetime.now(UTC)
    findings = find_expired(session, settings, now=now)
    if not findings:
        return SweepResult()

    for peer, row, record in findings:
        peer.state = PeerState.QUARANTINED
        if row is not None:
            # EXPIRED, not REVOKED: "your time ran out" and "an administrator
            # cut you off" are different events and the audit trail should say
            # which one happened.
            row.status = SessionStatus.EXPIRED
            row.revoked_at = now
        audit.record(
            session,
            action="session.expired",
            actor_type=ActorType.SYSTEM,
            actor_label="session-sweeper",
            object_type="peer",
            object_id=peer.id,
            detail={
                "reason": record.reason,
                "deadline": record.deadline.isoformat() if record.deadline else None,
                "groups": sorted(group.slug for group in peer.groups),
            },
        )
        logger.info(
            "session expired for peer %s (%s): %s", peer.id, peer.name, record.reason
        )

    session.flush()
    # Once for the whole batch: the ruleset is rendered from full database state,
    # so regenerating per peer would produce N identical-by-the-end versions.
    ruleset_service.regenerate(session, settings, generated_by="session.expiry")
    return SweepResult(
        expired=tuple(record for _, _, record in findings), regenerated=True
    )
