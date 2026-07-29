"""The panic button.

The property that matters most is not "it quarantines peers" -- it is that it
can never *grant* anything. It is pressed at the one moment when nobody has
time to check what it did.
"""

from __future__ import annotations

import pytest

from foxguard.config import Settings
from foxguard.models import (
    AuditLog,
    AuthMethod,
    Group,
    Peer,
    PeerSession,
    SessionStatus,
    User,
)
from foxguard.nftables import PeerState, PeerType
from foxguard.services import killswitch
from foxguard.services.killswitch import KillSwitchMode

ALL_STATES = tuple(PeerState)


def settings(**overrides) -> Settings:
    return Settings(dev_mode=True, **overrides)


@pytest.fixture()
def db(db_session):
    return db_session


def make_peer(
    db,
    name: str,
    *,
    state: PeerState,
    peer_type: PeerType = PeerType.USER,
    ip: str,
    groups: list[Group] | None = None,
) -> Peer:
    peer = Peer(
        name=name,
        peer_type=peer_type,
        state=state,
        wg_public_key=name.ljust(44, "k")[:44],
        tunnel_ip=ip,
        groups=groups or [],
    )
    db.add(peer)
    db.flush()
    return peer


# --------------------------------------------------------------------------- #
# it never increases access
# --------------------------------------------------------------------------- #


def test_a_revoked_peer_is_never_touched(db):
    """Quarantine would put it back in fg_quarantine and hand it the portal."""
    peer = make_peer(db, "gone", state=PeerState.REVOKED, ip="10.88.0.2")
    killswitch.trigger(db, settings(), mode=KillSwitchMode.QUARANTINE)
    assert peer.state is PeerState.REVOKED


def test_a_revoked_peer_survives_a_lockdown_too(db):
    peer = make_peer(db, "gone", state=PeerState.REVOKED, ip="10.88.0.2")
    killswitch.trigger(db, settings(), mode=KillSwitchMode.LOCKDOWN)
    assert peer.state is PeerState.REVOKED


def test_quarantine_mode_leaves_disabled_peers_disabled(db):
    """`disabled` has no dataplane presence; `quarantined` has the portal."""
    peer = make_peer(db, "paused", state=PeerState.DISABLED, ip="10.88.0.3")
    killswitch.trigger(db, settings(), mode=KillSwitchMode.QUARANTINE)
    assert peer.state is PeerState.DISABLED


def test_quarantine_mode_leaves_staging_peers_alone(db):
    """They already have exactly quarantine's access, and rewriting the state
    would erase the fact that they never enrolled."""
    peer = make_peer(db, "new", state=PeerState.STAGING, ip="10.88.0.4")
    killswitch.trigger(db, settings(), mode=KillSwitchMode.QUARANTINE)
    assert peer.state is PeerState.STAGING


@pytest.mark.parametrize("mode", list(KillSwitchMode))
def test_no_peer_ever_ends_up_active(db, mode):
    for index, state in enumerate(ALL_STATES):
        make_peer(db, f"p{index}", state=state, ip=f"10.88.0.{10 + index}")
    killswitch.trigger(db, settings(), mode=mode)
    assert not [peer for peer in db.query(Peer).all() if peer.state is PeerState.ACTIVE]


# --------------------------------------------------------------------------- #
# it does cut everyone it should
# --------------------------------------------------------------------------- #


def test_quarantine_mode_cuts_active_peers(db):
    peer = make_peer(db, "laptop", state=PeerState.ACTIVE, ip="10.88.0.5")
    result = killswitch.trigger(db, settings(), mode=KillSwitchMode.QUARANTINE)
    assert peer.state is PeerState.QUARANTINED
    assert [item.peer_id for item in result.affected] == [str(peer.id)]


def test_server_peers_are_cut_too(db):
    """The explicit exception to their "stable until the key is revoked" rule."""
    peer = make_peer(
        db, "backup", state=PeerState.ACTIVE, peer_type=PeerType.SERVER, ip="10.88.0.6"
    )
    killswitch.trigger(db, settings(), mode=KillSwitchMode.QUARANTINE)
    assert peer.state is PeerState.QUARANTINED


def test_lockdown_disables_staging_quarantined_and_active(db):
    peers = [
        make_peer(db, "a", state=PeerState.STAGING, ip="10.88.0.7"),
        make_peer(db, "b", state=PeerState.QUARANTINED, ip="10.88.0.8"),
        make_peer(db, "c", state=PeerState.ACTIVE, ip="10.88.0.9"),
    ]
    killswitch.trigger(db, settings(), mode=KillSwitchMode.LOCKDOWN)
    assert all(peer.state is PeerState.DISABLED for peer in peers)


def test_lockdown_is_what_stops_a_server_peer_coming_straight_back(db):
    """Quarantine leaves a server peer able to re-enroll with its valid key;
    `disabled` is outside the self-service table, so nothing brings it back."""
    from foxguard.services import peer_state

    peer = make_peer(
        db, "backup", state=PeerState.ACTIVE, peer_type=PeerType.SERVER, ip="10.88.0.11"
    )

    killswitch.trigger(db, settings(), mode=KillSwitchMode.QUARANTINE)
    peer_state.assert_self_service_transition(peer.state, PeerState.ACTIVE)  # allowed

    killswitch.trigger(db, settings(), mode=KillSwitchMode.LOCKDOWN)
    with pytest.raises(peer_state.IllegalTransition):
        peer_state.assert_self_service_transition(peer.state, PeerState.ACTIVE)


# --------------------------------------------------------------------------- #
# sessions and bookkeeping
# --------------------------------------------------------------------------- #


def test_live_sessions_are_revoked(db):
    user = User(username="ada", password_hash="x")
    db.add(user)
    db.flush()
    peer = make_peer(db, "laptop", state=PeerState.ACTIVE, ip="10.88.0.12")
    row = PeerSession(
        peer_id=peer.id, user_id=user.id, auth_method=AuthMethod.LOCAL,
        status=SessionStatus.ACTIVE,
    )
    db.add(row)
    db.flush()

    result = killswitch.trigger(db, settings())
    assert result.sessions_revoked == 1

    # Read it back rather than trusting the in-memory object: a bulk UPDATE only
    # resynchronises attributes the instance had already loaded, and this one
    # never had `revoked_at` set. The database is the contract.
    db.refresh(row)
    assert row.status is SessionStatus.REVOKED
    assert row.revoked_at is not None


def test_the_ruleset_is_regenerated_once(db):
    from foxguard.models import RulesetVersion

    make_peer(db, "a", state=PeerState.ACTIVE, ip="10.88.0.13")
    make_peer(db, "b", state=PeerState.ACTIVE, ip="10.88.0.14")
    before = db.query(RulesetVersion).count()

    result = killswitch.trigger(db, settings())
    db.flush()
    assert len(result.affected) == 2
    assert result.regenerated is True
    assert db.query(RulesetVersion).count() == before + 1


def test_firing_on_an_empty_fleet_changes_nothing(db):
    result = killswitch.trigger(db, settings())
    assert result.affected == ()
    assert result.regenerated is False


def test_the_previous_state_of_every_peer_is_recorded(db):
    """There is no undo endpoint, so the audit entry has to be the record."""
    peer = make_peer(db, "laptop", state=PeerState.ACTIVE, ip="10.88.0.15")
    killswitch.trigger(db, settings(), mode=KillSwitchMode.LOCKDOWN)
    db.flush()

    entry = db.query(AuditLog).filter(AuditLog.action == "killswitch.trigger").one()
    assert entry.detail["mode"] == "lockdown"
    assert entry.detail["peers_affected"] == 1
    assert entry.detail["peers"] == [
        {"id": str(peer.id), "name": "laptop", "from": "active"}
    ]


def test_firing_twice_is_idempotent(db):
    make_peer(db, "laptop", state=PeerState.ACTIVE, ip="10.88.0.16")
    assert len(killswitch.trigger(db, settings()).affected) == 1
    assert killswitch.trigger(db, settings()).affected == ()


# --------------------------------------------------------------------------- #
# confirmation
# --------------------------------------------------------------------------- #


def test_each_mode_has_its_own_confirmation_phrase():
    """So a lockdown cannot be fired by someone who meant to quarantine."""
    phrases = set(killswitch.CONFIRMATION.values())
    assert len(phrases) == len(KillSwitchMode)
    assert all(mode in killswitch.CONFIRMATION for mode in KillSwitchMode)


@pytest.mark.parametrize("mode", list(KillSwitchMode))
def test_the_request_schema_demands_the_exact_phrase(mode):
    from pydantic import ValidationError

    from foxguard.schemas import KillSwitchRequest

    assert KillSwitchRequest(mode=mode, confirm=killswitch.CONFIRMATION[mode])
    for wrong in ("", "yes", killswitch.CONFIRMATION[mode].lower(), "KILL"):
        with pytest.raises(ValidationError):
            KillSwitchRequest(mode=mode, confirm=wrong)


def test_the_quarantine_phrase_does_not_fire_a_lockdown():
    from pydantic import ValidationError

    from foxguard.schemas import KillSwitchRequest

    with pytest.raises(ValidationError):
        KillSwitchRequest(
            mode=KillSwitchMode.LOCKDOWN,
            confirm=killswitch.CONFIRMATION[KillSwitchMode.QUARANTINE],
        )
