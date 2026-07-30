"""Zones in the generated ruleset.

A zone is a *region of the address space*: the peers assigned to it plus the
networks routed inside it. That is the difference from a group, and most of the
tests below exist to pin down its consequences -- interval sets, one zone per
peer, and a default route being refused rather than installed.
"""

from __future__ import annotations

import pytest
from conftest import chain_lines, gateway, index_of, peer, rule, set_elements, spec, zone

from foxguard.nftables import (
    Action,
    Endpoint,
    GroupSpec,
    PeerState,
    RulesetValidationError,
    generate_ruleset,
    zone_set_name,
)
from foxguard.nftables.model import Family

WAN = gateway(wan_interface="eth0")


# --------------------------------------------------------------------------- #
# sets
# --------------------------------------------------------------------------- #


def test_a_zone_set_is_an_interval_set():
    """It holds prefixes as well as host addresses; nft cannot mix the two."""
    output = generate_ruleset(spec(zones=(zone("office"),)))
    lines = output.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip() == "set z_office_v4 {")
    assert "flags interval" in lines[start + 2]


def test_a_group_set_stays_a_plain_address_set():
    """Groups hold devices, so they keep the cheaper set type."""
    output = generate_ruleset(spec(groups=(GroupSpec("admin"),)))
    lines = output.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip() == "set g_admin_v4 {")
    assert "flags interval" not in lines[start + 2]


def test_zone_members_are_rendered_as_prefixes():
    output = generate_ruleset(
        spec(zones=(zone("office"),), peers=(peer("p1", "10.88.0.5", zone="office"),))
    )
    assert set_elements(output, "z_office_v4") == ["10.88.0.5/32"]


def test_routed_networks_join_the_zone_set():
    """"Who may reach the office" has to mean the devices *and* what is behind them."""
    output = generate_ruleset(
        spec(
            zones=(zone("office", routes=("192.168.10.0/24", "192.168.20.0/24")),),
            peers=(peer("p1", "10.88.0.5", zone="office"),),
        )
    )
    assert set_elements(output, "z_office_v4") == [
        "10.88.0.5/32",
        "192.168.10.0/24",
        "192.168.20.0/24",
    ]


def test_routes_land_in_the_set_of_their_own_family():
    output = generate_ruleset(
        spec(zones=(zone("office", routes=("192.168.10.0/24", "fd00:10::/64")),))
    )
    assert set_elements(output, "z_office_v4") == ["192.168.10.0/24"]
    assert set_elements(output, "z_office_v6") == ["fd00:10::/64"]


def test_a_confined_peer_is_not_in_its_zone_set():
    """Same rule as groups: staging and quarantine mean no membership at all."""
    output = generate_ruleset(
        spec(
            zones=(zone("office"),),
            peers=(
                peer("p1", "10.88.0.5", zone="office", state=PeerState.STAGING),
                peer("p2", "10.88.0.6", zone="office", state=PeerState.QUARANTINED),
                peer("p3", "10.88.0.7", zone="office"),
            ),
        )
    )
    assert set_elements(output, "z_office_v4") == ["10.88.0.7/32"]


def test_a_routed_network_stays_reachable_even_with_no_active_peers():
    """The route describes the topology, not who happens to be online."""
    output = generate_ruleset(
        spec(
            zones=(zone("office", routes=("192.168.10.0/24",)),),
            peers=(peer("p1", "10.88.0.5", zone="office", state=PeerState.DISABLED),),
        )
    )
    assert set_elements(output, "z_office_v4") == ["192.168.10.0/24"]


def test_a_group_and_a_zone_never_share_a_set():
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("office"),),
            zones=(zone("office-net"),),
        )
    )
    assert "set g_office_v4 {" in output
    assert "set z_office_net_v4 {" in output


@pytest.mark.parametrize("family", list(Family))
def test_set_names_are_prefixed_per_kind(family):
    assert zone_set_name("office", family).startswith("z_")


# --------------------------------------------------------------------------- #
# ACL rules
# --------------------------------------------------------------------------- #


def test_a_zone_endpoint_matches_the_zone_set():
    output = generate_ruleset(
        spec(
            zones=(zone("office"), zone("lab")),
            rules=(rule("r1", src=Endpoint.zone("office"), dst=Endpoint.zone("lab")),),
        )
    )
    forward = chain_lines(output, "forward")
    assert any(
        "ip saddr @z_office_v4 ip daddr @z_lab_v4" in line for line in forward
    )


def test_zone_and_group_endpoints_mix_in_one_rule():
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("admin"),),
            zones=(zone("office"),),
            rules=(rule("r1", src=Endpoint.group("admin"), dst=Endpoint.zone("office")),),
        )
    )
    assert any(
        "ip saddr @g_admin_v4 ip daddr @z_office_v4" in line
        for line in chain_lines(output, "forward")
    )


def test_a_rule_naming_an_unknown_zone_is_refused():
    with pytest.raises(RulesetValidationError) as exc:
        generate_ruleset(spec(rules=(rule("r1", src=Endpoint.zone("ghost")),)))
    assert "unknown zone" in str(exc.value)


def test_a_peer_in_an_unknown_zone_is_refused():
    with pytest.raises(RulesetValidationError) as exc:
        generate_ruleset(spec(peers=(peer("p1", "10.88.0.5", zone="ghost"),)))
    assert "unknown zone" in str(exc.value)


# --------------------------------------------------------------------------- #
# intra-zone traffic
# --------------------------------------------------------------------------- #


def test_intra_zone_traffic_is_denied_by_default():
    """Default-deny is the product's thesis; a zone is not the exception to it."""
    output = generate_ruleset(
        spec(zones=(zone("office"),), peers=(peer("p1", "10.88.0.5", zone="office"),))
    )
    assert "fg:intra-zone" not in output


def test_intra_zone_traffic_can_be_turned_on_per_zone():
    output = generate_ruleset(spec(zones=(zone("office", intra_zone=True), zone("lab"))))
    forward = chain_lines(output, "forward")
    assert any(
        "ip saddr @z_office_v4 ip daddr @z_office_v4" in line for line in forward
    )
    assert not any("z_lab_v4 ip daddr @z_lab_v4" in line for line in forward)


def test_intra_zone_comes_after_the_acl_rules():
    """So an explicit drop still carves a subset out of a zone that talks to itself."""
    output = generate_ruleset(
        spec(
            zones=(zone("office", intra_zone=True),),
            rules=(
                rule(
                    "block-smb",
                    src=Endpoint.zone("office"),
                    dst=Endpoint.zone("office"),
                    action=Action.DROP,
                ),
            ),
        )
    )
    forward = chain_lines(output, "forward")
    assert index_of(forward, "fg:block-smb") < index_of(forward, "fg:intra-zone:office")


def test_intra_zone_still_comes_before_the_default_deny():
    output = generate_ruleset(spec(zones=(zone("office", intra_zone=True),)))
    forward = chain_lines(output, "forward")
    assert index_of(forward, "fg:intra-zone:office") < index_of(forward, "fg:default-deny")


# --------------------------------------------------------------------------- #
# internet exit
# --------------------------------------------------------------------------- #


def test_a_zone_can_be_an_internet_exit():
    output = generate_ruleset(spec(zones=(zone("office", internet_exit=True),), gw=WAN))
    forward = chain_lines(output, "forward")
    assert any("fg:internet-exit:office" in line for line in forward)
    assert any("fg:nat:office" in line for line in chain_lines(output, "postrouting"))


def test_a_zone_exit_cannot_shortcut_into_internal_networks():
    """The same guard groups get: otherwise a checkbox is an ACL bypass."""
    output = generate_ruleset(spec(zones=(zone("office", internet_exit=True),), gw=WAN))
    line = next(
        ln for ln in chain_lines(output, "forward") if "fg:internet-exit:office" in ln
    )
    assert "ip daddr != @fg_internal_v4" in line


def test_a_zone_exit_without_a_wan_interface_is_refused():
    with pytest.raises(RulesetValidationError) as exc:
        generate_ruleset(spec(zones=(zone("office", internet_exit=True),)))
    assert "wan_interface" in str(exc.value)


def test_group_and_zone_exits_coexist():
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("admin", internet_exit=True),),
            zones=(zone("office", internet_exit=True),),
            gw=WAN,
        )
    )
    nat = chain_lines(output, "postrouting")
    assert any("fg:nat:admin" in line for line in nat)
    assert any("fg:nat:office" in line for line in nat)


# --------------------------------------------------------------------------- #
# routes: the refusals that keep the gateway reachable
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("default_route", ["0.0.0.0/0", "::/0"])
def test_a_zone_route_may_not_be_a_default_route(default_route):
    """It would replace the gateway's own default route and cut every session.

    Refused at the spec boundary rather than only in the agent, so the API says
    no at creation time instead of the gateway saying no at 3am.
    """
    with pytest.raises(RulesetValidationError) as exc:
        generate_ruleset(spec(zones=(zone("office", routes=(default_route,)),)))
    assert "default route" in str(exc.value)


def test_an_invalid_route_cidr_is_refused():
    with pytest.raises(RulesetValidationError):
        generate_ruleset(spec(zones=(zone("office", routes=("192.168.1.0/33",)),)))


def test_the_same_route_twice_in_one_zone_is_refused():
    with pytest.raises(RulesetValidationError) as exc:
        generate_ruleset(
            spec(zones=(zone("office", routes=("192.168.1.0/24", "192.168.1.0/24")),))
        )
    assert "duplicate route" in str(exc.value)


# --------------------------------------------------------------------------- #
# naming
# --------------------------------------------------------------------------- #


def test_two_zone_slugs_cannot_collapse_onto_one_set_name():
    with pytest.raises(RulesetValidationError) as exc:
        generate_ruleset(spec(zones=(zone("back-up"), zone("back_up"))))
    assert "collides" in str(exc.value)


def test_a_duplicate_zone_slug_is_refused():
    with pytest.raises(RulesetValidationError) as exc:
        generate_ruleset(spec(zones=(zone("office"), zone("office"))))
    assert "duplicate slug" in str(exc.value)


def test_a_slug_cannot_name_both_a_group_and_a_zone():
    """An ACL rule saying "servers" must never be ambiguous about which it means."""
    with pytest.raises(RulesetValidationError) as exc:
        generate_ruleset(spec(groups=(GroupSpec("servers"),), zones=(zone("servers"),)))
    assert "both a group and a zone" in str(exc.value)


# --------------------------------------------------------------------------- #
# determinism
# --------------------------------------------------------------------------- #


def test_zone_output_is_stable_regardless_of_input_order():
    forward = spec(
        zones=(zone("b", routes=("10.1.0.0/24",)), zone("a", routes=("10.2.0.0/24",))),
        peers=(peer("p2", "10.88.0.6", zone="a"), peer("p1", "10.88.0.5", zone="b")),
    )
    reverse = spec(
        zones=tuple(reversed(forward.zones)), peers=tuple(reversed(forward.peers))
    )
    assert generate_ruleset(forward) == generate_ruleset(reverse)
