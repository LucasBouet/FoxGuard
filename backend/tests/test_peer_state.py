"""Safety properties of the peer state machine.

These are written as properties rather than as a transcription of the tables:
the tables are allowed to grow, the properties are not allowed to break.
"""

from __future__ import annotations

import pytest

from foxguard.nftables import PeerState
from foxguard.services import peer_state

ALL_STATES = tuple(PeerState)


# --------------------------------------------------------------------------- #
# revocation is final
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("target", ALL_STATES)
def test_nothing_ever_leaves_revoked(target):
    """Revocation that can be undone by editing a field is not revocation."""
    if target is PeerState.REVOKED:
        peer_state.assert_admin_transition(PeerState.REVOKED, target)  # no-op
        return
    with pytest.raises(peer_state.IllegalTransition):
        peer_state.assert_admin_transition(PeerState.REVOKED, target)


def test_the_revoked_error_says_what_to_do_instead():
    with pytest.raises(peer_state.IllegalTransition) as excinfo:
        peer_state.assert_admin_transition(PeerState.REVOKED, PeerState.ACTIVE)
    assert "delete the peer" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# self-service is far more restricted than the admin API
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("blocked", [PeerState.DISABLED, PeerState.REVOKED])
def test_credentials_cannot_resurrect_an_administratively_stopped_peer(blocked):
    """A valid enrollment key or password must not undo an admin's decision."""
    with pytest.raises(peer_state.IllegalTransition):
        peer_state.assert_self_service_transition(blocked, PeerState.ACTIVE)


@pytest.mark.parametrize("start", [PeerState.STAGING, PeerState.QUARANTINED])
def test_authenticating_activates_a_confined_peer(start):
    peer_state.assert_self_service_transition(start, PeerState.ACTIVE)


@pytest.mark.parametrize("start", ALL_STATES)
@pytest.mark.parametrize(
    "target", [s for s in ALL_STATES if s is not PeerState.ACTIVE]
)
def test_self_service_can_only_ever_target_active(start, target):
    """The portal and the enrollment endpoint grant access; they never take it."""
    if start is target:
        peer_state.assert_self_service_transition(start, target)  # idempotent
        return
    with pytest.raises(peer_state.IllegalTransition):
        peer_state.assert_self_service_transition(start, target)


# --------------------------------------------------------------------------- #
# idempotence
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("state", ALL_STATES)
def test_a_transition_to_the_same_state_is_always_allowed(state):
    """Re-enrolling or re-authenticating must refresh, not 409."""
    peer_state.assert_admin_transition(state, state)
    peer_state.assert_self_service_transition(state, state)


# --------------------------------------------------------------------------- #
# the admin table stays permissive apart from the one rule above
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("start", [s for s in ALL_STATES if s is not PeerState.REVOKED])
@pytest.mark.parametrize("target", ALL_STATES)
def test_an_admin_can_do_anything_except_undo_a_revocation(start, target):
    peer_state.assert_admin_transition(start, target)


def test_self_service_is_a_strict_subset_of_what_an_admin_may_do():
    """A peer must never be able to reach a state its administrator cannot."""
    for current, allowed in peer_state.SELF_SERVICE_TRANSITIONS.items():
        admin_allowed = peer_state.ADMIN_TRANSITIONS[current] | {current}
        assert allowed <= admin_allowed, current
