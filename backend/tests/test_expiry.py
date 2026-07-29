"""Session expiry rules.

Transient ORM objects and an injected ``now``: the decision "is this peer still
entitled to be active" is pure policy and deserves to be tested as such.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from foxguard.config import Settings
from foxguard.models import AuthMethod, Group, Peer, PeerSession, SessionStatus
from foxguard.nftables import PeerState, PeerType
from foxguard.services import expiry

NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)


def settings(**overrides) -> Settings:
    return Settings(dev_mode=True, **overrides)


def group(slug: str, lifetime: int | None = None) -> Group:
    return Group(slug=slug, name=slug, session_lifetime_seconds=lifetime)


def peer(
    *groups: Group,
    authenticated_at: datetime | None = NOW,
    peer_type: PeerType = PeerType.USER,
    state: PeerState = PeerState.ACTIVE,
) -> Peer:
    return Peer(
        name="laptop",
        peer_type=peer_type,
        state=state,
        wg_public_key="k" * 44,
        tunnel_ip="10.88.0.5",
        groups=list(groups),
        last_authenticated_at=authenticated_at,
    )


def session_row(expires_at: datetime | None) -> PeerSession:
    return PeerSession(
        auth_method=AuthMethod.LOCAL,
        status=SessionStatus.ACTIVE,
        authenticated_at=NOW,
        last_authenticated_at=NOW,
        expires_at=expires_at,
    )


# --------------------------------------------------------------------------- #
# the deadline
# --------------------------------------------------------------------------- #


def test_the_deadline_comes_from_the_group_lifetime():
    subject = peer(group("lab", 4 * 3600))
    assert expiry.effective_deadline(subject, None, settings()) == NOW + 4 * HOUR


def test_with_no_group_override_the_global_default_applies():
    subject = peer(group("plain"))
    assert expiry.effective_deadline(
        subject, None, settings(default_session_lifetime_seconds=3600)
    ) == NOW + HOUR


def test_a_peer_that_never_authenticated_has_no_deadline():
    assert expiry.effective_deadline(peer(authenticated_at=None), None, settings()) is None


def test_moving_a_peer_to_a_stricter_group_tightens_a_live_session():
    """The whole reason the deadline is recomputed instead of read back.

    A session opened as ``admin`` (24h) must not survive 24h once the peer has
    been moved into ``pentest-lab`` (4h).
    """
    stored = session_row(NOW + 24 * HOUR)
    subject = peer(group("lab", 4 * 3600))
    assert expiry.effective_deadline(subject, stored, settings()) == NOW + 4 * HOUR


def test_moving_a_peer_to_a_looser_group_does_not_extend_a_live_session():
    """Otherwise adding someone to a lenient group hands them time for free."""
    stored = session_row(NOW + 4 * HOUR)
    subject = peer(group("admin", 24 * 3600))
    assert expiry.effective_deadline(subject, stored, settings()) == NOW + 4 * HOUR


def test_the_strictest_group_still_wins_among_several():
    subject = peer(group("lab", 4 * 3600), group("admin", 24 * 3600))
    assert expiry.effective_deadline(subject, None, settings()) == NOW + 4 * HOUR


def test_a_naive_timestamp_from_the_database_is_read_as_utc():
    subject = peer(group("lab", 3600), authenticated_at=NOW.replace(tzinfo=None))
    assert expiry.effective_deadline(subject, None, settings()) == NOW + HOUR


def test_a_session_row_without_an_expiry_falls_back_to_the_computed_one():
    subject = peer(group("lab", 3600))
    assert expiry.effective_deadline(subject, session_row(None), settings()) == NOW + HOUR


# --------------------------------------------------------------------------- #
# what the sweep selects -- exercised through find_expired against a real DB
# --------------------------------------------------------------------------- #


@pytest.fixture()
def db(db_session):
    return db_session


def _persist(session, subject: Peer, *groups: Group) -> Peer:
    for item in groups:
        session.add(item)
    session.add(subject)
    session.flush()
    return subject


def test_an_expired_user_peer_is_selected(db):
    lab = group("lab", 3600)
    subject = _persist(db, peer(lab, authenticated_at=NOW - 2 * HOUR), lab)
    found = expiry.find_expired(db, settings(), now=NOW)
    assert [item.peer_id for _, _, item in found] == [str(subject.id)]
    assert found[0][2].reason == expiry.REASON_TIMEOUT


def test_a_peer_still_inside_its_lifetime_is_left_alone(db):
    lab = group("lab", 3600)
    _persist(db, peer(lab, authenticated_at=NOW - timedelta(minutes=30)), lab)
    assert expiry.find_expired(db, settings(), now=NOW) == []


def test_a_server_peer_is_never_expired(db):
    """The point of having two peer types: a backup job is not logged out at 3am."""
    lab = group("lab", 3600)
    _persist(
        db,
        peer(lab, authenticated_at=NOW - 100 * HOUR, peer_type=PeerType.SERVER),
        lab,
    )
    assert expiry.find_expired(db, settings(), now=NOW) == []


@pytest.mark.parametrize(
    "state", [PeerState.STAGING, PeerState.QUARANTINED, PeerState.DISABLED, PeerState.REVOKED]
)
def test_only_active_peers_are_considered(db, state):
    lab = group("lab", 3600)
    _persist(db, peer(lab, authenticated_at=NOW - 100 * HOUR, state=state), lab)
    assert expiry.find_expired(db, settings(), now=NOW) == []


def test_an_active_user_peer_that_never_authenticated_is_selected(db):
    """Unexplained `active` is exactly what quarantine is for."""
    lab = group("lab", 3600)
    _persist(db, peer(lab, authenticated_at=None), lab)
    found = expiry.find_expired(db, settings(), now=NOW)
    assert len(found) == 1
    assert found[0][2].reason == expiry.REASON_NEVER


def test_expiry_is_inclusive_at_the_deadline(db):
    """A session that expires "now" is over, not good for one more sweep."""
    lab = group("lab", 3600)
    _persist(db, peer(lab, authenticated_at=NOW - HOUR), lab)
    assert len(expiry.find_expired(db, settings(), now=NOW)) == 1


# --------------------------------------------------------------------------- #
# the sweep itself
# --------------------------------------------------------------------------- #


def test_sweeping_quarantines_and_regenerates(db):
    lab = group("lab", 3600)
    subject = _persist(db, peer(lab, authenticated_at=NOW - 2 * HOUR), lab)

    result = expiry.sweep(db, settings(), now=NOW)

    assert len(result.expired) == 1
    assert result.regenerated is True
    assert subject.state is PeerState.QUARANTINED


def test_a_sweep_with_nothing_to_do_writes_no_ruleset_version(db):
    """A no-op must stay a no-op, or every tick would add a version row."""
    lab = group("lab", 3600)
    _persist(db, peer(lab, authenticated_at=NOW), lab)

    result = expiry.sweep(db, settings(), now=NOW)
    assert not result
    assert result.regenerated is False


def test_sweeping_is_idempotent(db):
    """Level-triggered: the second pass finds nothing left to do."""
    lab = group("lab", 3600)
    _persist(db, peer(lab, authenticated_at=NOW - 2 * HOUR), lab)

    assert len(expiry.sweep(db, settings(), now=NOW).expired) == 1
    assert expiry.sweep(db, settings(), now=NOW).expired == ()


def test_the_session_row_is_marked_expired_not_revoked(db):
    """"Your time ran out" and "an admin cut you off" are different events."""
    from foxguard.models import User

    lab = group("lab", 3600)
    user = User(username="ada", password_hash="x")
    db.add_all([lab, user])
    db.flush()

    subject = peer(lab, authenticated_at=NOW - 2 * HOUR)
    subject.owner_user_id = user.id
    db.add(subject)
    db.flush()

    row = PeerSession(
        peer_id=subject.id,
        user_id=user.id,
        auth_method=AuthMethod.LOCAL,
        status=SessionStatus.ACTIVE,
        authenticated_at=NOW - 2 * HOUR,
        last_authenticated_at=NOW - 2 * HOUR,
        expires_at=NOW - HOUR,
    )
    db.add(row)
    db.flush()

    expiry.sweep(db, settings(), now=NOW)
    assert row.status is SessionStatus.EXPIRED
    assert row.revoked_at is not None


def test_the_expiry_is_recorded_in_the_audit_log(db):
    from foxguard.models import AuditLog

    lab = group("lab", 3600)
    _persist(db, peer(lab, authenticated_at=NOW - 2 * HOUR), lab)
    expiry.sweep(db, settings(), now=NOW)
    db.flush()

    entries = db.query(AuditLog).filter(AuditLog.action == "session.expired").all()
    assert len(entries) == 1
    assert entries[0].detail["reason"] == expiry.REASON_TIMEOUT
