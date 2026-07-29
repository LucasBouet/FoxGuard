"""The peer state machine.

Phase 1 let the admin API write any value into ``peers.state``. That made two
guarantees weaker than they looked:

* **Revocation was reversible.** ``revoked`` is meant to be terminal -- a peer
  whose key leaked, or a laptop that was stolen. A stray ``PATCH`` could bring
  it back.
* **Self-service could resurrect an administratively stopped peer.** Once the
  enrollment endpoint and the portal exist, a *peer* can move itself to
  ``active``. Without a guard, a peer the admin had just ``disabled`` could
  present a still-valid enrollment key and undo that decision.

So there are two transition tables, not one, keyed on *who* is asking:

``ADMIN_TRANSITIONS``
    what an authenticated admin may do. Everything except leaving ``revoked``.

``SELF_SERVICE_TRANSITIONS``
    what a peer may do to *itself* by authenticating (enrollment key, portal
    login). Only ``staging``/``quarantined`` -> ``active``. ``disabled`` and
    ``revoked`` are administrative decisions and no credential overrides them.

Self-transitions are always allowed and are no-ops: re-authenticating an
already-``active`` peer must refresh its session rather than fail.
"""

from __future__ import annotations

from ..nftables import PeerState

__all__ = [
    "ADMIN_TRANSITIONS",
    "SELF_SERVICE_TRANSITIONS",
    "IllegalTransition",
    "assert_admin_transition",
    "assert_self_service_transition",
]


class IllegalTransition(ValueError):
    """A state change that the machine forbids. Routes turn this into a 409."""

    def __init__(self, current: PeerState, target: PeerState, reason: str) -> None:
        self.current = current
        self.target = target
        self.reason = reason
        super().__init__(
            f"cannot move a peer from {current.value!r} to {target.value!r}: {reason}"
        )


#: An admin may do anything except bring a peer back from ``revoked``.
#: Revocation that can be undone by editing a field is not revocation.
ADMIN_TRANSITIONS: dict[PeerState, frozenset[PeerState]] = {
    PeerState.STAGING: frozenset(
        {PeerState.ACTIVE, PeerState.QUARANTINED, PeerState.DISABLED, PeerState.REVOKED}
    ),
    PeerState.QUARANTINED: frozenset(
        {PeerState.ACTIVE, PeerState.STAGING, PeerState.DISABLED, PeerState.REVOKED}
    ),
    PeerState.ACTIVE: frozenset(
        {PeerState.QUARANTINED, PeerState.STAGING, PeerState.DISABLED, PeerState.REVOKED}
    ),
    PeerState.DISABLED: frozenset(
        {PeerState.STAGING, PeerState.QUARANTINED, PeerState.ACTIVE, PeerState.REVOKED}
    ),
    #: Terminal. Delete the peer and register it again to start over -- that way
    #: a new public key and a new enrollment key are forced.
    PeerState.REVOKED: frozenset(),
}

#: What authenticating as the peer itself can achieve. Deliberately tiny.
SELF_SERVICE_TRANSITIONS: dict[PeerState, frozenset[PeerState]] = {
    PeerState.STAGING: frozenset({PeerState.ACTIVE}),
    PeerState.QUARANTINED: frozenset({PeerState.ACTIVE}),
    PeerState.ACTIVE: frozenset({PeerState.ACTIVE}),
    PeerState.DISABLED: frozenset(),
    PeerState.REVOKED: frozenset(),
}

_TERMINAL_REASON = "revoked is terminal; delete the peer and register it again"


def _assert(
    table: dict[PeerState, frozenset[PeerState]],
    current: PeerState,
    target: PeerState,
    *,
    reason: str,
) -> None:
    if current is target:
        # Idempotent: re-enrolling or re-authenticating must refresh, not 409.
        return
    if target not in table.get(current, frozenset()):
        raise IllegalTransition(current, target, reason)


def assert_admin_transition(current: PeerState, target: PeerState) -> None:
    """Guard a state change requested through the admin API."""
    _assert(
        ADMIN_TRANSITIONS,
        current,
        target,
        reason=_TERMINAL_REASON if current is PeerState.REVOKED else "not an allowed transition",
    )


def assert_self_service_transition(current: PeerState, target: PeerState) -> None:
    """Guard a state change a peer performs on itself by authenticating.

    The failure message stays vague on purpose: it is returned to whoever
    controls the peer, and "this peer was disabled by an administrator" is more
    than they need to know.
    """
    _assert(
        SELF_SERVICE_TRANSITIONS,
        current,
        target,
        reason="this peer is not eligible to activate itself",
    )
