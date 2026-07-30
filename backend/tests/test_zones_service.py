"""Zones as they exist in the database, projected onto the dataplane spec.

Needs PostgreSQL (``FOXGUARD_TEST_DATABASE_URL``). The rendering itself is
covered without one in ``test_nft_zones.py``; what is tested here is the
projection -- which is where a zone can be mistaken for a group.
"""

from __future__ import annotations

import uuid

import pytest

from foxguard.config import Settings
from foxguard.models import AclRule, Group, GroupKind, Peer, ZoneRoute
from foxguard.nftables import (
    Action,
    EndpointKind,
    PeerState,
    PeerType,
    Protocol,
    generate_ruleset,
)
from foxguard.services import ruleset as ruleset_service


def settings(**overrides) -> Settings:
    defaults = dict(dev_mode=True, wg_pool_v4="10.88.0.0/24", wan_interface="eth0")
    defaults.update(overrides)
    return Settings(**defaults)


def make_group(session, slug: str, **overrides) -> Group:
    group = Group(slug=slug, name=slug.title(), kind=GroupKind.GROUP, **overrides)
    session.add(group)
    session.flush()
    return group


def make_zone(session, slug: str, **overrides) -> Group:
    zone = Group(slug=slug, name=slug.title(), kind=GroupKind.ZONE, **overrides)
    session.add(zone)
    session.flush()
    return zone


def make_peer(session, name: str, ip: str, **overrides) -> Peer:
    defaults = dict(
        name=name,
        peer_type=PeerType.USER,
        state=PeerState.ACTIVE,
        wg_public_key=f"{uuid.uuid4().hex[:20]}{'A' * 23}=",
        wg_interface="wg0",
        tunnel_ip=ip,
        dns_label=name,
    )
    defaults.update(overrides)
    peer = Peer(**defaults)
    session.add(peer)
    session.flush()
    return peer


def build(session) -> object:
    return ruleset_service.build_spec(session, settings())


# --------------------------------------------------------------------------- #
# groups and zones are told apart
# --------------------------------------------------------------------------- #


def test_zones_do_not_appear_among_the_groups(db_session):
    make_group(db_session, "admin")
    make_zone(db_session, "office")
    spec = build(db_session)
    assert spec.group_slugs == {"admin"}
    assert spec.zone_slugs == {"office"}


def test_a_peers_zone_is_not_reported_as_one_of_its_groups(db_session):
    zone = make_zone(db_session, "office")
    group = make_group(db_session, "admin")
    peer = make_peer(db_session, "laptop", "10.88.0.5", zone_id=zone.id)
    peer.groups = [group]
    db_session.flush()

    spec = build(db_session)
    assert spec.peers[0].group_slugs == ("admin",)
    assert spec.peers[0].zone_slug == "office"


def test_a_peer_can_be_in_a_zone_and_several_groups(db_session):
    zone = make_zone(db_session, "office")
    peer = make_peer(db_session, "laptop", "10.88.0.5", zone_id=zone.id)
    peer.groups = [make_group(db_session, "admin"), make_group(db_session, "backup")]
    db_session.flush()

    spec = build(db_session)
    assert spec.peers[0].group_slugs == ("admin", "backup")
    assert spec.peers[0].zone_slug == "office"


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #


def test_enabled_routes_reach_the_spec(db_session):
    zone = make_zone(db_session, "office")
    db_session.add(ZoneRoute(zone_id=zone.id, cidr="192.168.10.0/24"))
    db_session.flush()

    spec = build(db_session)
    assert [r.cidr for r in spec.zones[0].routes] == ["192.168.10.0/24"]


def test_a_disabled_route_is_left_out(db_session):
    zone = make_zone(db_session, "office")
    db_session.add(ZoneRoute(zone_id=zone.id, cidr="192.168.10.0/24", enabled=False))
    db_session.add(ZoneRoute(zone_id=zone.id, cidr="192.168.20.0/24"))
    db_session.flush()

    spec = build(db_session)
    assert [r.cidr for r in spec.zones[0].routes] == ["192.168.20.0/24"]


def test_routes_are_sorted_so_the_ruleset_is_byte_stable(db_session):
    """Insertion order must not change the digest, or drift detection is noise."""
    zone = make_zone(db_session, "office")
    for cidr in ("192.168.30.0/24", "192.168.10.0/24", "192.168.20.0/24"):
        db_session.add(ZoneRoute(zone_id=zone.id, cidr=cidr))
    db_session.flush()

    assert [r.cidr for r in build(db_session).zones[0].routes] == [
        "192.168.10.0/24",
        "192.168.20.0/24",
        "192.168.30.0/24",
    ]


def test_the_routing_peer_is_carried_through(db_session):
    zone = make_zone(db_session, "office")
    peer = make_peer(db_session, "router", "10.88.0.9", zone_id=zone.id)
    db_session.add(
        ZoneRoute(zone_id=zone.id, cidr="192.168.10.0/24", via_peer_id=peer.id)
    )
    db_session.flush()

    assert build(db_session).zones[0].routes[0].via_peer_id == str(peer.id)


def test_deleting_the_routing_peer_withdraws_the_route(db_session):
    """A network is advertised because some peer can carry it."""
    zone = make_zone(db_session, "office")
    peer = make_peer(db_session, "router", "10.88.0.9", zone_id=zone.id)
    db_session.add(
        ZoneRoute(zone_id=zone.id, cidr="192.168.10.0/24", via_peer_id=peer.id)
    )
    db_session.flush()

    db_session.delete(peer)
    db_session.flush()
    db_session.expire_all()

    assert build(db_session).zones[0].routes == ()


def test_deleting_a_zone_unassigns_its_peers(db_session):
    zone = make_zone(db_session, "office")
    peer = make_peer(db_session, "laptop", "10.88.0.5", zone_id=zone.id)
    db_session.flush()

    db_session.delete(zone)
    db_session.flush()
    db_session.expire_all()

    assert db_session.get(Peer, peer.id) is not None
    assert build(db_session).peers[0].zone_slug is None


# --------------------------------------------------------------------------- #
# ACL endpoints
# --------------------------------------------------------------------------- #


def test_a_zone_endpoint_renders_against_the_zone_set(db_session):
    zone = make_zone(db_session, "office")
    make_peer(db_session, "laptop", "10.88.0.5", zone_id=zone.id)
    db_session.add(
        AclRule(
            ref="r1",
            name="office out",
            action=Action.ACCEPT,
            src_kind=EndpointKind.ZONE,
            src_group_id=zone.id,
            dst_kind=EndpointKind.ANY,
            protocol=Protocol.ANY,
        )
    )
    db_session.flush()

    output = generate_ruleset(build(db_session))
    assert "ip saddr @z_office_v4" in output
    assert "@g_office_v4" not in output


def test_the_row_kind_decides_the_set_not_the_endpoint_kind(db_session):
    """A rule stored with the wrong kind must not silently match nothing.

    ``src_kind='group'`` pointing at a zone would render ``@g_office_v4``, a set
    that is never populated -- a rule that quietly does nothing at all.
    """
    zone = make_zone(db_session, "office")
    make_peer(db_session, "laptop", "10.88.0.5", zone_id=zone.id)
    db_session.add(
        AclRule(
            ref="r1",
            name="mislabelled",
            action=Action.ACCEPT,
            src_kind=EndpointKind.GROUP,
            src_group_id=zone.id,
            dst_kind=EndpointKind.ANY,
            protocol=Protocol.ANY,
        )
    )
    db_session.flush()

    output = generate_ruleset(build(db_session))
    assert "ip saddr @z_office_v4" in output


# --------------------------------------------------------------------------- #
# end to end through the generator
# --------------------------------------------------------------------------- #


def test_a_zone_with_routes_and_members_renders(db_session):
    zone = make_zone(db_session, "office", intra_zone=True, internet_exit=True)
    make_peer(db_session, "laptop", "10.88.0.5", zone_id=zone.id)
    db_session.add(ZoneRoute(zone_id=zone.id, cidr="192.168.10.0/24"))
    db_session.flush()

    output = generate_ruleset(build(db_session))
    # Host addresses are written as /32 -- explicit, and unambiguous in an
    # interval set. ``nft list set`` prints them back without the prefix.
    assert "elements = { 10.88.0.5/32, 192.168.10.0/24 }" in output
    assert "fg:intra-zone:office" in output
    assert "fg:nat:office" in output


@pytest.mark.parametrize("default_route", ["0.0.0.0/0", "::/0"])
def test_a_default_route_in_a_zone_refuses_to_render(db_session, default_route):
    """Last line of defence: the API refuses it first, this refuses it always."""
    from foxguard.nftables import RulesetValidationError

    zone = make_zone(db_session, "office")
    db_session.add(ZoneRoute(zone_id=zone.id, cidr=default_route))
    db_session.flush()

    with pytest.raises(RulesetValidationError):
        generate_ruleset(build(db_session))
