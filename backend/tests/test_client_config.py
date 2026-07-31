"""The client-configuration profile.

Two halves. :func:`compute_allowed_ips` and :func:`join_endpoint` are pure and
tested without a database; the projection needs one
(``FOXGUARD_TEST_DATABASE_URL``) because what it mostly does is decide which
rows apply to which device.

The case worth reading first is the routing peer. A device that carries
192.168.10.0/24 for a zone must not get that prefix back in its own
``AllowedIPs``: it would route its own LAN into the tunnel and stop being able
to reach the network it exists to serve. That is a silent failure -- the tunnel
comes up, the config looks right -- so it gets tests in both halves.
"""

from __future__ import annotations

import uuid

import pytest

from foxguard.clientconfig import AllowedIpsMode, compute_allowed_ips, join_endpoint
from foxguard.config import Settings
from foxguard.dns.model import ResolverMode
from foxguard.models import Group, GroupKind, Peer, ZoneRoute
from foxguard.nftables import PeerState, PeerType
from foxguard.services import clientconfig

POOL = "10.88.0.0/24"


def settings(**overrides) -> Settings:
    defaults = dict(
        dev_mode=True,
        wg_pool_v4=POOL,
        wan_interface="eth0",
        wg_public_key="Y" * 43 + "=",
        wg_endpoint_host="vpn.example.com",
    )
    defaults.update(overrides)
    return Settings(**defaults)


# --------------------------------------------------------------------------- #
# pure: AllowedIPs
# --------------------------------------------------------------------------- #


def allowed(mode, **overrides):
    kwargs = dict(
        pools=(POOL,),
        own_zone_routes=("192.168.10.0/24",),
        fleet_routes=("192.168.10.0/24", "172.20.0.0/16"),
        carried_by_peer=(),
    )
    kwargs.update(overrides)
    return compute_allowed_ips(mode, **kwargs)


def test_tunnel_mode_is_the_pools_and_nothing_else():
    ips, excluded = allowed(AllowedIpsMode.TUNNEL)
    assert ips == (POOL,)
    assert excluded == ()


def test_zone_mode_adds_the_peers_own_zone():
    ips, _ = allowed(AllowedIpsMode.ZONE)
    assert ips == (POOL, "192.168.10.0/24")


def test_routed_mode_adds_every_network_in_the_fleet():
    ips, _ = allowed(AllowedIpsMode.ROUTED)
    assert ips == (POOL, "172.20.0.0/16", "192.168.10.0/24")


def test_full_mode_is_a_default_route():
    ips, _ = allowed(AllowedIpsMode.FULL)
    assert ips == ("0.0.0.0/0",)


def test_full_mode_covers_v6_only_when_the_deployment_has_v6():
    ips, _ = allowed(AllowedIpsMode.FULL, pools=(POOL, "fd00:88::/64"))
    assert ips == ("0.0.0.0/0", "::/0")


@pytest.mark.parametrize(
    "mode", [AllowedIpsMode.ZONE, AllowedIpsMode.ROUTED]
)
def test_a_peer_never_routes_the_network_it_carries(mode):
    # The whole reason this function exists rather than a set union.
    ips, excluded = allowed(mode, carried_by_peer=("192.168.10.0/24",))
    assert "192.168.10.0/24" not in ips
    assert excluded == ("192.168.10.0/24",)
    assert POOL in ips, "excluding a carried route must not cost it the tunnel"


def test_full_tunnel_still_gets_its_default_route_when_the_peer_carries_something():
    # 0.0.0.0/0 covers the carried network too, but dropping it would turn the
    # mode the operator chose into a different one without saying so.
    ips, excluded = allowed(AllowedIpsMode.FULL, carried_by_peer=("0.0.0.0/0",))
    assert ips == ("0.0.0.0/0",)
    assert excluded == ()


def test_the_carried_network_is_matched_by_value_not_by_string():
    # "192.168.10.7/24" is what someone types when they mean the network their
    # router sits on. Comparing strings would let it through as a second,
    # different route -- and put the carried network back in the config.
    ips, excluded = allowed(
        AllowedIpsMode.ROUTED,
        fleet_routes=("192.168.10.7/24",),
        carried_by_peer=("192.168.10.0/24",),
    )
    assert excluded == ("192.168.10.0/24",)
    assert ips == (POOL,)


def test_duplicates_collapse_and_the_order_is_stable():
    ips, _ = allowed(
        AllowedIpsMode.ROUTED,
        pools=(POOL, "fd00:88::/64"),
        fleet_routes=("192.168.10.0/24", POOL, "10.0.0.0/8"),
    )
    assert ips == ("10.0.0.0/8", POOL, "192.168.10.0/24", "fd00:88::/64")


def test_extra_allowed_ips_are_appended_in_every_mode():
    ips, _ = allowed(AllowedIpsMode.TUNNEL, extra=("172.31.0.0/16",))
    assert "172.31.0.0/16" in ips


def test_a_bad_prefix_is_refused_rather_than_written_into_a_config():
    with pytest.raises(ValueError):
        allowed(AllowedIpsMode.ROUTED, fleet_routes=("192.168.1.0/33",))


# --------------------------------------------------------------------------- #
# pure: endpoints
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("vpn.example.com", "vpn.example.com:51820"),
        ("vpn.example.com:41820", "vpn.example.com:41820"),
        ("203.0.113.4", "203.0.113.4:51820"),
        ("203.0.113.4:9", "203.0.113.4:9"),
        ("2001:db8::1", "[2001:db8::1]:51820"),
        ("[2001:db8::1]", "[2001:db8::1]:51820"),
        ("[2001:db8::1]:41820", "[2001:db8::1]:41820"),
        ("  vpn.example.com  ", "vpn.example.com:51820"),
    ],
)
def test_join_endpoint(host, expected):
    assert join_endpoint(host, 51820) == expected


# --------------------------------------------------------------------------- #
# the projection
# --------------------------------------------------------------------------- #


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


def make_zone(session, slug: str, **overrides) -> Group:
    zone = Group(slug=slug, name=slug.title(), kind=GroupKind.ZONE, **overrides)
    session.add(zone)
    session.flush()
    return zone


def add_route(session, zone: Group, cidr: str, via: Peer | None = None) -> ZoneRoute:
    route = ZoneRoute(zone_id=zone.id, cidr=cidr, via_peer_id=via.id if via else None)
    session.add(route)
    session.flush()
    return route


def test_a_plain_peer_gets_its_address_and_the_pool(db_session):
    peer = make_peer(db_session, "laptop", "10.88.0.5")
    profile = clientconfig.build_profile(db_session, settings(), peer)

    assert profile.addresses == ("10.88.0.5/32",)
    assert profile.allowed_ips == (POOL,)
    assert profile.endpoint == "vpn.example.com:51820"
    assert profile.server_public_key == "Y" * 43 + "="
    assert profile.persistent_keepalive == 25
    assert profile.complete is True


def test_a_dual_stack_peer_gets_both_addresses(db_session):
    peer = make_peer(db_session, "laptop", "10.88.0.5", tunnel_ip6="fd00:88::5")
    profile = clientconfig.build_profile(
        db_session, settings(wg_pool_v6="fd00:88::/64"), peer
    )
    assert profile.addresses == ("10.88.0.5/32", "fd00:88::5/128")


def test_the_staging_pool_is_routable_too(db_session):
    # A device in staging holds an address from the staging pool. If the pool is
    # missing from AllowedIPs, nobody can reach a device that is still enrolling
    # -- including the operator trying to work out why.
    peer = make_peer(db_session, "laptop", "10.88.0.5")
    profile = clientconfig.build_profile(
        db_session, settings(wg_staging_pool_v4="10.89.0.0/24"), peer
    )
    assert profile.allowed_ips == ("10.88.0.0/24", "10.89.0.0/24")


def test_the_routing_peer_does_not_route_its_own_network(db_session):
    zone = make_zone(db_session, "office")
    router = make_peer(db_session, "site-router", "10.88.0.9", zone_id=zone.id)
    laptop = make_peer(db_session, "laptop", "10.88.0.5", zone_id=zone.id)
    add_route(db_session, zone, "192.168.10.0/24", via=router)

    carrier = clientconfig.build_profile(db_session, settings(), router)
    assert "192.168.10.0/24" not in carrier.allowed_ips
    assert carrier.excluded_routes == ("192.168.10.0/24",)
    assert any("carries those networks" in w for w in carrier.warnings)

    other = clientconfig.build_profile(db_session, settings(), laptop)
    assert "192.168.10.0/24" in other.allowed_ips
    assert other.excluded_routes == ()


def test_zone_mode_leaves_another_zones_networks_out(db_session):
    office = make_zone(db_session, "office")
    datacenter = make_zone(db_session, "datacenter")
    add_route(db_session, office, "192.168.10.0/24")
    add_route(db_session, datacenter, "172.20.0.0/16")
    peer = make_peer(db_session, "laptop", "10.88.0.5", zone_id=office.id)

    zoned = clientconfig.build_profile(
        db_session, settings(), peer, mode=AllowedIpsMode.ZONE
    )
    assert zoned.allowed_ips == (POOL, "192.168.10.0/24")

    routed = clientconfig.build_profile(
        db_session, settings(), peer, mode=AllowedIpsMode.ROUTED
    )
    assert routed.allowed_ips == (POOL, "172.20.0.0/16", "192.168.10.0/24")


def test_a_zoneless_peer_in_zone_mode_gets_only_the_pool(db_session):
    zone = make_zone(db_session, "office")
    add_route(db_session, zone, "192.168.10.0/24")
    peer = make_peer(db_session, "laptop", "10.88.0.5")

    profile = clientconfig.build_profile(
        db_session, settings(), peer, mode=AllowedIpsMode.ZONE
    )
    assert profile.allowed_ips == (POOL,)


def test_a_disabled_route_reaches_nobodys_config(db_session):
    zone = make_zone(db_session, "office")
    route = add_route(db_session, zone, "192.168.10.0/24")
    route.enabled = False
    db_session.flush()
    peer = make_peer(db_session, "laptop", "10.88.0.5", zone_id=zone.id)

    profile = clientconfig.build_profile(db_session, settings(), peer)
    assert profile.allowed_ips == (POOL,)


def test_dns_appears_only_when_the_resolver_is_on(db_session):
    peer = make_peer(db_session, "laptop", "10.88.0.5")

    assert clientconfig.build_profile(db_session, settings(), peer).dns == ()

    on = clientconfig.build_profile(db_session, settings(dns_enabled=True), peer)
    assert on.dns == ("10.88.0.1", "fox.internal")
    assert on.fqdn == "laptop.fox.internal"


def test_dns_can_be_declined_per_device(db_session):
    peer = make_peer(db_session, "laptop", "10.88.0.5")
    profile = clientconfig.build_profile(
        db_session, settings(dns_enabled=True), peer, include_dns=False
    )
    assert profile.dns == ()


def test_split_mode_says_the_device_needs_a_second_resolver(db_session):
    peer = make_peer(db_session, "laptop", "10.88.0.5")
    profile = clientconfig.build_profile(
        db_session, settings(dns_enabled=True, dns_mode=ResolverMode.SPLIT), peer
    )
    assert any("second resolver" in w for w in profile.warnings)


def test_a_resolver_address_off_the_tunnel_is_not_offered_to_clients(db_session):
    # A resolver may legitimately bind a LAN address as well. A client that
    # cannot route to it would stall on every lookup, so only tunnel addresses
    # reach the DNS line.
    peer = make_peer(db_session, "laptop", "10.88.0.5")
    profile = clientconfig.build_profile(
        db_session,
        settings(dns_enabled=True, dns_listen_addresses=["10.88.0.1", "192.168.1.2"]),
        peer,
    )
    assert profile.dns == ("10.88.0.1", "fox.internal")


def test_an_unconfigured_gateway_yields_an_incomplete_profile(db_session):
    peer = make_peer(db_session, "laptop", "10.88.0.5")
    profile = clientconfig.build_profile(
        db_session, settings(wg_public_key=None, wg_endpoint_host=None), peer
    )
    assert profile.complete is False
    assert any("FOXGUARD_WG_PUBLIC_KEY" in w for w in profile.warnings)
    assert any("FOXGUARD_WG_ENDPOINT_HOST" in w for w in profile.warnings)


@pytest.mark.parametrize("state", [PeerState.DISABLED, PeerState.REVOKED])
def test_a_peer_that_cannot_connect_says_so(db_session, state):
    peer = make_peer(db_session, "laptop", "10.88.0.5", state=state)
    profile = clientconfig.build_profile(db_session, settings(), peer)
    assert any("will not accept its handshake" in w for w in profile.warnings)


def test_a_quarantined_peer_is_told_it_reaches_only_the_portal(db_session):
    peer = make_peer(db_session, "laptop", "10.88.0.5", state=PeerState.QUARANTINED)
    profile = clientconfig.build_profile(db_session, settings(), peer)
    assert any("only the portal" in w for w in profile.warnings)


def test_full_tunnel_without_an_exit_is_flagged(db_session):
    peer = make_peer(db_session, "laptop", "10.88.0.5")
    profile = clientconfig.build_profile(
        db_session, settings(), peer, mode=AllowedIpsMode.FULL
    )
    assert any("no internet at all" in w for w in profile.warnings)


def test_full_tunnel_with_an_exit_group_is_not_flagged(db_session):
    group = Group(slug="staff", name="Staff", kind=GroupKind.GROUP, internet_exit=True)
    db_session.add(group)
    db_session.flush()
    peer = make_peer(db_session, "laptop", "10.88.0.5")
    peer.groups = [group]
    db_session.flush()

    profile = clientconfig.build_profile(
        db_session, settings(), peer, mode=AllowedIpsMode.FULL
    )
    assert not any("no internet at all" in w for w in profile.warnings)


def test_a_zone_can_grant_the_exit_as_well_as_a_group(db_session):
    # internet_exit lives on the shared table and the generator honours it for
    # zones too; warning about a full-tunnel config that works would train the
    # operator to ignore warnings.
    zone = make_zone(db_session, "office", internet_exit=True)
    peer = make_peer(db_session, "laptop", "10.88.0.5", zone_id=zone.id)

    profile = clientconfig.build_profile(
        db_session, settings(), peer, mode=AllowedIpsMode.FULL
    )
    assert not any("no internet at all" in w for w in profile.warnings)


def test_per_device_overrides_win_over_the_deployment_defaults(db_session):
    peer = make_peer(db_session, "laptop", "10.88.0.5")
    profile = clientconfig.build_profile(
        db_session,
        settings(client_config_keepalive=0, client_config_mtu=1420),
        peer,
        keepalive=15,
        mtu=1280,
    )
    assert profile.persistent_keepalive == 15
    assert profile.mtu == 1280


def test_extra_allowed_ips_from_settings_reach_the_profile(db_session):
    peer = make_peer(db_session, "laptop", "10.88.0.5")
    profile = clientconfig.build_profile(
        db_session,
        settings(client_config_extra_allowed_ips=["172.31.0.0/16"]),
        peer,
    )
    assert "172.31.0.0/16" in profile.allowed_ips


def test_a_bad_extra_allowed_ip_is_refused_at_startup():
    with pytest.raises(ValueError, match="is not a network"):
        settings(client_config_extra_allowed_ips=["nope"])
