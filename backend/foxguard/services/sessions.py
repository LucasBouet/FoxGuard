"""Portal sessions for *user* peers.

A captive portal session is not an HTTP session. There is no cookie and no
token: what the user gets for authenticating is **network access**, held in the
nftables ruleset. So the row in ``sessions`` is a record of *when* a human last
proved they were there, which is exactly what Phase 3 needs to expire, and what
the audit log needs to explain why a peer was active.

Server peers never appear here. Their access is bound to an enrollment key, not
to a session that can time out -- see ``services/enrollment.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import AuthMethod, Peer, PeerSession, SessionStatus, User

__all__ = ["active_session", "lifetime_seconds", "open_session", "revoke_sessions"]


def lifetime_seconds(peer: Peer, settings: Settings) -> int:
    """How long this peer's session lasts.

    A peer in several groups gets the **shortest** of their lifetimes. Taking
    the longest would let membership of a lenient group silently extend access
    granted by a strict one -- a privilege escalation dressed up as a
    convenience. ``pentest-lab`` expiring in 4h must not become 24h because the
    peer is also in ``admin``.
    """
    overrides = [
        group.session_lifetime_seconds
        for group in peer.groups
        if group.session_lifetime_seconds
    ]
    if overrides:
        return min(overrides)
    return settings.default_session_lifetime_seconds


def active_session(session: Session, peer: Peer) -> PeerSession | None:
    return session.execute(
        select(PeerSession)
        .where(PeerSession.peer_id == peer.id, PeerSession.status == SessionStatus.ACTIVE)
        .order_by(PeerSession.last_authenticated_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def revoke_sessions(session: Session, peer: Peer, *, now: datetime | None = None) -> None:
    """Mark every live session of ``peer`` revoked.

    ORM-enabled UPDATE (not ``__table__.update()``) so rows already loaded in
    this session see the new status instead of going stale -- the same reason
    ``services/ruleset.store_version`` does it that way.

    The synchronisation is not total: it refreshes attributes an instance has
    already loaded, so a row constructed in this transaction without an explicit
    ``revoked_at`` still reads ``None`` from memory afterwards even though the
    column is set in the database. Re-query, or ``refresh()``, before trusting a
    field this statement wrote.
    """
    session.execute(
        update(PeerSession)
        .where(PeerSession.peer_id == peer.id, PeerSession.status == SessionStatus.ACTIVE)
        .values(status=SessionStatus.REVOKED, revoked_at=now or datetime.now(UTC)),
        execution_options={"synchronize_session": "fetch"},
    )


def open_session(
    session: Session,
    *,
    peer: Peer,
    user: User,
    method: AuthMethod,
    settings: Settings,
    source_ip: str | None = None,
    now: datetime | None = None,
) -> PeerSession:
    """Record a successful portal authentication.

    Exactly one session is live per peer: re-authenticating revokes the previous
    one rather than stacking, so "when did this device last prove a human was
    present" has a single answer.

    The caller is responsible for the state transition and for regenerating the
    ruleset -- this function only owns the session bookkeeping.
    """
    now = now or datetime.now(UTC)
    revoke_sessions(session, peer, now=now)

    row = PeerSession(
        peer_id=peer.id,
        user_id=user.id,
        auth_method=method,
        status=SessionStatus.ACTIVE,
        authenticated_at=now,
        last_authenticated_at=now,
        expires_at=now + timedelta(seconds=lifetime_seconds(peer, settings)),
        source_ip=source_ip,
    )
    session.add(row)

    # Denormalised onto the peer so the Phase 3 expiry job and the dashboard do
    # not have to join sessions for the one field they both read constantly.
    peer.last_authenticated_at = now
    user.last_login_at = now
    return row
