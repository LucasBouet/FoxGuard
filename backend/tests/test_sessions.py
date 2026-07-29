"""Session lifetime arithmetic.

Transient ORM objects, no database: the rule being tested is pure policy.
"""

from __future__ import annotations

import pytest

from foxguard.config import Settings
from foxguard.models import Group, Peer
from foxguard.nftables import PeerType
from foxguard.services import sessions


def settings(**overrides) -> Settings:
    return Settings(dev_mode=True, **overrides)


def peer_in(*groups: Group) -> Peer:
    return Peer(
        name="laptop",
        peer_type=PeerType.USER,
        wg_public_key="k" * 44,
        tunnel_ip="10.88.0.5",
        groups=list(groups),
    )


def group(slug: str, lifetime: int | None) -> Group:
    return Group(slug=slug, name=slug, session_lifetime_seconds=lifetime)


def test_no_group_override_falls_back_to_the_global_default():
    assert sessions.lifetime_seconds(
        peer_in(group("admin", None)), settings(default_session_lifetime_seconds=7200)
    ) == 7200


def test_a_peer_in_no_group_at_all_uses_the_default():
    assert sessions.lifetime_seconds(
        peer_in(), settings(default_session_lifetime_seconds=3600)
    ) == 3600


def test_a_single_override_wins_over_the_default():
    assert sessions.lifetime_seconds(
        peer_in(group("lab", 4 * 3600)), settings(default_session_lifetime_seconds=86400)
    ) == 4 * 3600


def test_the_shortest_group_lifetime_wins():
    """Being in a lenient group must not extend access granted by a strict one.

    ``pentest-lab`` expiring after 4h cannot become 24h because the peer also
    happens to be in ``admin``.
    """
    peer = peer_in(group("lab", 4 * 3600), group("admin", 24 * 3600))
    assert sessions.lifetime_seconds(peer, settings()) == 4 * 3600


def test_groups_without_an_override_do_not_dilute_the_strictest_one():
    peer = peer_in(group("lab", 4 * 3600), group("plain", None))
    assert sessions.lifetime_seconds(
        peer, settings(default_session_lifetime_seconds=86400)
    ) == 4 * 3600


@pytest.mark.parametrize("order", [(0, 1), (1, 0)])
def test_the_result_does_not_depend_on_group_order(order):
    pair = (group("lab", 4 * 3600), group("admin", 24 * 3600))
    peer = peer_in(*[pair[index] for index in order])
    assert sessions.lifetime_seconds(peer, settings()) == 4 * 3600
