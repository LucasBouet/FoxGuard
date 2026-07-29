"""Tests for the nftables generator.

This is the component that can take a gateway offline, so the tests are written
as *safety properties* first (no lockout, no collateral damage, no injection)
and feature coverage second.
"""

from __future__ import annotations

import random
import re

import pytest
from conftest import chain_lines, gateway, index_of, peer, rule, set_elements, spec

from foxguard.nftables import (
    Action,
    Endpoint,
    GatewayInputPolicy,
    GroupSpec,
    PeerState,
    Protocol,
    RulesetValidationError,
    generate_ruleset,
    ruleset_digest,
)

# --------------------------------------------------------------------------- #
# safety properties
# --------------------------------------------------------------------------- #


def test_never_flushes_the_global_ruleset():
    """A flush would wipe the host firewall, Docker and fail2ban rules too."""
    output = generate_ruleset(spec(groups=(GroupSpec("admin"),)))
    assert "flush ruleset" not in output
    assert "flush table" not in output


def test_only_ever_deletes_its_own_table():
    output = generate_ruleset(spec())
    deletes = [line.strip() for line in output.splitlines() if line.strip().startswith("delete ")]
    assert deletes == ["delete table inet foxguard"]


def test_create_then_delete_makes_the_script_idempotent():
    """``table X`` then ``delete table X`` works whether or not X already exists."""
    lines = [line.strip() for line in generate_ruleset(spec()).splitlines() if line.strip()]
    declare = lines.index("table inet foxguard")
    assert lines[declare + 1] == "delete table inet foxguard"


@pytest.mark.parametrize("chain", ["input", "forward"])
def test_base_chains_never_use_policy_drop(chain):
    """A drop policy on input would cut SSH to the gateway on the first apply."""
    output = generate_ruleset(spec())
    header = next(
        line for line in output.splitlines() if f"type filter hook {chain}" in line
    )
    assert "policy accept" in header
    assert "policy drop" not in header


def test_traffic_unrelated_to_the_tunnel_is_left_alone():
    """Foxguard must cohabit with whatever else routes through this box."""
    output = generate_ruleset(spec())
    forward = chain_lines(output, "forward")
    assert forward[0] == 'iifname != "wg0" oifname != "wg0" accept comment "fg:foreign-traffic"'

    input_chain = chain_lines(output, "input")
    assert input_chain[0] == 'iifname != "wg0" accept'


def test_default_deny_is_explicit_and_last_in_forward():
    forward = chain_lines(generate_ruleset(spec()), "forward")
    assert forward[-1] == 'counter drop comment "fg:default-deny"'


def test_established_connections_survive_a_reload():
    forward = chain_lines(generate_ruleset(spec()), "forward")
    established = index_of(forward, "ct state established,related")
    default_deny = index_of(forward, "fg:default-deny")
    assert established < default_deny
    assert "accept" in forward[established]


def test_quarantine_drop_is_evaluated_before_the_established_accept():
    """Quarantining a peer must cut its *open* flows, not just its new ones.

    This ordering is what makes the kill switch and session expiry take effect
    immediately instead of whenever the peer happens to reconnect.
    """
    output = generate_ruleset(
        spec(peers=(peer("p1", "10.88.0.5", state=PeerState.QUARANTINED),))
    )
    for chain in ("input", "forward"):
        lines = chain_lines(output, chain)
        quarantine = index_of(lines, "@fg_quarantine_v4")
        established = index_of(lines, "ct state established,related")
        assert quarantine < established, f"{chain}: quarantine must come first"


def test_icmp_errors_are_always_accepted():
    """Dropping these silently black-holes every TCP flow above the PMTU."""
    for chain in ("input", "forward"):
        lines = chain_lines(generate_ruleset(spec()), chain)
        assert any("packet-too-big" in line for line in lines)
        assert any("time-exceeded" in line for line in lines)


# --------------------------------------------------------------------------- #
# determinism / idempotence
# --------------------------------------------------------------------------- #


def _sample_spec():
    groups = (GroupSpec("admin"), GroupSpec("db"), GroupSpec("lab", internet_exit=True))
    peers = (
        peer("a", "10.88.0.2", groups=("admin",)),
        peer("b", "10.88.0.3", groups=("db",)),
        peer("c", "10.88.0.4", state=PeerState.QUARANTINED),
        peer("d", "10.88.0.5", groups=("lab", "admin")),
    )
    rules = (
        rule("r-db", src=Endpoint.group("admin"), dst=Endpoint.group("db"),
             protocol=Protocol.TCP, port=5432, priority=10),
        rule("r-web", src=Endpoint.group("lab"), dst=Endpoint.network("192.168.10.0/24"),
             protocol=Protocol.TCP, port=80, port_end=443, priority=20),
        rule("r-deny", src=Endpoint.group("lab"), dst=Endpoint.group("db"),
             action=Action.DROP, priority=5),
    )
    return groups, peers, rules


def test_same_state_produces_identical_bytes():
    groups, peers, rules = _sample_spec()
    gw = gateway(wan_interface="eth0")
    first = generate_ruleset(spec(groups=groups, peers=peers, rules=rules, gw=gw))
    second = generate_ruleset(spec(groups=groups, peers=peers, rules=rules, gw=gw))
    assert first == second


def test_input_ordering_does_not_change_the_output():
    """Drift detection relies on the digest, so ORM row order must not leak in."""
    groups, peers, rules = _sample_spec()
    gw = gateway(wan_interface="eth0")
    reference = generate_ruleset(spec(groups=groups, peers=peers, rules=rules, gw=gw))

    rng = random.Random(1234)
    for _ in range(5):
        shuffled_groups = tuple(rng.sample(groups, len(groups)))
        shuffled_peers = tuple(rng.sample(peers, len(peers)))
        shuffled_rules = tuple(rng.sample(rules, len(rules)))
        assert (
            generate_ruleset(
                spec(
                    groups=shuffled_groups,
                    peers=shuffled_peers,
                    rules=shuffled_rules,
                    gw=gw,
                )
            )
            == reference
        )


def test_no_timestamp_leaks_into_the_output():
    """A date in the banner would make every regeneration look like a change."""
    import re as _re

    output = generate_ruleset(spec())
    assert not _re.search(r"\d{4}-\d{2}-\d{2}", output)
    assert not _re.search(r"\d{2}:\d{2}:\d{2}", output)


def test_digest_tracks_content():
    empty = generate_ruleset(spec())
    with_group = generate_ruleset(spec(groups=(GroupSpec("admin"),)))
    assert ruleset_digest(empty) == ruleset_digest(generate_ruleset(spec()))
    assert ruleset_digest(empty) != ruleset_digest(with_group)


# --------------------------------------------------------------------------- #
# set membership
# --------------------------------------------------------------------------- #


def test_only_active_peers_join_their_group_sets():
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("admin"),),
            peers=(
                peer("active", "10.88.0.2", groups=("admin",)),
                peer("quarantined", "10.88.0.3", state=PeerState.QUARANTINED, groups=("admin",)),
                peer("staging", "10.88.0.4", state=PeerState.STAGING, groups=("admin",)),
                peer("disabled", "10.88.0.5", state=PeerState.DISABLED, groups=("admin",)),
                peer("revoked", "10.88.0.6", state=PeerState.REVOKED, groups=("admin",)),
            ),
        )
    )
    assert set_elements(output, "g_admin_v4") == ["10.88.0.2"]


def test_staging_and_quarantined_peers_share_the_confinement_set():
    output = generate_ruleset(
        spec(
            peers=(
                peer("s", "10.88.0.3", state=PeerState.STAGING),
                peer("q", "10.88.0.2", state=PeerState.QUARANTINED),
            )
        )
    )
    # Sorted numerically, not by insertion order.
    assert set_elements(output, "fg_quarantine_v4") == ["10.88.0.2", "10.88.0.3"]


def test_disabled_and_revoked_peers_appear_nowhere():
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("admin"),),
            peers=(
                peer("disabled", "10.88.0.7", state=PeerState.DISABLED, groups=("admin",)),
                peer("revoked", "10.88.0.8", state=PeerState.REVOKED, groups=("admin",)),
            ),
        )
    )
    assert "10.88.0.7" not in output
    assert "10.88.0.8" not in output


def test_ipv6_members_land_in_the_v6_set():
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("admin"),),
            peers=(peer("a", "10.88.0.2", ip6="fd00:88::2", groups=("admin",)),),
        )
    )
    assert set_elements(output, "g_admin_v4") == ["10.88.0.2"]
    assert set_elements(output, "g_admin_v6") == ["fd00:88::2"]


def test_empty_group_still_declares_its_sets():
    """An empty set matches nothing; a missing set would be a syntax error."""
    output = generate_ruleset(spec(groups=(GroupSpec("empty"),)))
    assert "set g_empty_v4 {" in output
    assert "set g_empty_v6 {" in output
    assert set_elements(output, "g_empty_v4") == []


def test_hyphenated_slugs_become_underscored_set_names():
    """`-` is nft's range operator; keep set identifiers unambiguous."""
    output = generate_ruleset(spec(groups=(GroupSpec("backup-svc"),)))
    assert "set g_backup_svc_v4 {" in output
    assert "g_backup-svc" not in output


def test_hyphen_and_underscore_slugs_that_would_collide_are_rejected():
    """Otherwise one group would silently inherit the other's members."""
    with pytest.raises(RulesetValidationError, match="collides"):
        generate_ruleset(spec(groups=(GroupSpec("back-up"), GroupSpec("back_up"))))


def test_rules_reference_the_normalised_set_name():
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("backup-svc"), GroupSpec("prod-db")),
            rules=(
                rule(
                    "r1",
                    src=Endpoint.group("backup-svc"),
                    dst=Endpoint.group("prod-db"),
                    protocol=Protocol.TCP,
                    port=5432,
                ),
            ),
        )
    )
    forward = "\n".join(chain_lines(output, "forward"))
    assert "ip saddr @g_backup_svc_v4 ip daddr @g_prod_db_v4 tcp dport 5432" in forward


def test_no_nft_identifier_contains_a_hyphen():
    """Belt and braces across sets, chains and rule references."""
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("backup-svc", internet_exit=True),),
            peers=(peer("a", "10.88.0.2", groups=("backup-svc",)),),
            gw=gateway(wan_interface="eth0"),
        )
    )
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        # Hyphens are legitimate inside quoted comments, CIDRs and port ranges.
        without_quotes = re.sub(r'"[^"]*"', '""', stripped)
        identifiers = re.findall(r"@[A-Za-z0-9_-]+|set [A-Za-z0-9_-]+", without_quotes)
        for identifier in identifiers:
            assert "-" not in identifier, f"hyphen in nft identifier: {identifier}"


def test_set_names_stay_within_nft_identifier_limits():
    output = generate_ruleset(spec(groups=(GroupSpec("a" * 24),)))
    names = [
        line.strip().removeprefix("set ").removesuffix(" {")
        for line in output.splitlines()
        if line.strip().startswith("set ")
    ]
    assert names, "expected at least one set"
    assert all(len(name) <= 32 for name in names), names


# --------------------------------------------------------------------------- #
# ACL rule rendering
# --------------------------------------------------------------------------- #


def test_rules_are_ordered_by_priority_then_id():
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("a"), GroupSpec("b")),
            rules=(
                rule("zzz", priority=10),
                rule("aaa", priority=10),
                rule("mid", priority=5),
            ),
        )
    )
    forward = chain_lines(output, "forward")
    assert index_of(forward, "fg:mid:") < index_of(forward, "fg:aaa:")
    assert index_of(forward, "fg:aaa:") < index_of(forward, "fg:zzz:")


def test_group_to_group_tcp_port():
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("admin"), GroupSpec("db")),
            rules=(
                rule("r1", src=Endpoint.group("admin"), dst=Endpoint.group("db"),
                     protocol=Protocol.TCP, port=5432),
            ),
        )
    )
    forward = chain_lines(output, "forward")
    assert (
        'ip saddr @g_admin_v4 ip daddr @g_db_v4 tcp dport 5432 counter accept '
        'comment "fg:r1:rule r1"' in forward
    )
    assert "ip6 saddr @g_admin_v6 ip6 daddr @g_db_v6 tcp dport 5432" in "\n".join(forward)


def test_port_range_is_rendered_as_a_range():
    output = generate_ruleset(
        spec(rules=(rule("r1", protocol=Protocol.TCP, port=8000, port_end=8010),))
    )
    assert "tcp dport 8000-8010" in output


def test_single_port_range_collapses():
    output = generate_ruleset(
        spec(rules=(rule("r1", protocol=Protocol.TCP, port=443, port_end=443),))
    )
    assert "tcp dport 443 " in output
    assert "443-443" not in output


def test_protocol_without_port_uses_l4proto():
    output = generate_ruleset(spec(rules=(rule("r1", protocol=Protocol.UDP),)))
    assert "meta l4proto udp" in output


def test_icmp_maps_to_the_right_protocol_per_family():
    output = generate_ruleset(spec(rules=(rule("r1", protocol=Protocol.ICMP),)))
    assert "meta l4proto icmp" in output
    assert "meta l4proto ipv6-icmp" in output


def test_cidr_endpoint_only_emits_its_own_family():
    output = generate_ruleset(
        spec(rules=(rule("r1", dst=Endpoint.network("192.168.5.0/24")),))
    )
    forward = "\n".join(chain_lines(output, "forward"))
    assert "ip daddr 192.168.5.0/24" in forward
    assert "ip6 daddr 192.168.5.0/24" not in forward
    # The v6 variant must not be emitted as a family-agnostic rule either.
    assert forward.count("fg:r1:") == 1


def test_any_to_any_rule_is_pinned_to_a_family():
    """Without a family selector the same rule would be emitted twice verbatim."""
    output = generate_ruleset(spec(rules=(rule("r1", action=Action.DROP),)))
    forward = chain_lines(output, "forward")
    assert 'meta nfproto ipv4 counter drop comment "fg:r1:rule r1"' in forward
    assert 'meta nfproto ipv6 counter drop comment "fg:r1:rule r1"' in forward


def test_reject_action_is_supported():
    output = generate_ruleset(spec(rules=(rule("r1", action=Action.REJECT),)))
    assert "counter reject" in output


def test_every_rule_carries_a_counter_for_observability():
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("admin"),),
            rules=(rule("r1", src=Endpoint.group("admin")),),
        )
    )
    rendered = [line for line in chain_lines(output, "forward") if "fg:r1:" in line]
    assert rendered
    assert all("counter" in line for line in rendered)


# --------------------------------------------------------------------------- #
# internet exit / NAT
# --------------------------------------------------------------------------- #


def test_no_nat_chain_when_no_group_exits():
    output = generate_ruleset(
        spec(groups=(GroupSpec("admin"),), gw=gateway(wan_interface="eth0"))
    )
    assert "hook postrouting" not in output


def test_internet_exit_emits_masquerade():
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("road", internet_exit=True),),
            gw=gateway(wan_interface="eth0"),
        )
    )
    assert "type nat hook postrouting priority srcnat; policy accept;" in output
    assert (
        'ip saddr @g_road_v4 oifname "eth0" counter masquerade comment "fg:nat:road"'
        in output
    )


def test_internet_exit_cannot_be_used_to_reach_internal_networks():
    """Otherwise ``internet_exit`` would silently bypass every ACL rule."""
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("road", internet_exit=True),),
            gw=gateway(wan_interface="eth0"),
        )
    )
    exit_rule = next(line for line in chain_lines(output, "forward") if "fg:internet-exit:road" in line)
    assert "ip daddr != @fg_internal_v4" in exit_rule
    assert 'oifname "eth0"' in exit_rule


def test_exit_rules_come_after_policy_rules():
    """So an explicit deny can still block a subset of an exit-enabled group."""
    output = generate_ruleset(
        spec(
            groups=(GroupSpec("road", internet_exit=True),),
            rules=(rule("r-block", src=Endpoint.group("road"), action=Action.DROP),),
            gw=gateway(wan_interface="eth0"),
        )
    )
    forward = chain_lines(output, "forward")
    assert index_of(forward, "fg:r-block:") < index_of(forward, "fg:internet-exit:road")


def test_internet_exit_without_wan_interface_is_rejected():
    with pytest.raises(RulesetValidationError) as excinfo:
        generate_ruleset(spec(groups=(GroupSpec("road", internet_exit=True),)))
    assert "wan_interface" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# quarantine behaviour
# --------------------------------------------------------------------------- #


def test_quarantined_peers_can_reach_the_portal_and_nothing_else():
    output = generate_ruleset(
        spec(
            peers=(peer("q", "10.88.0.9", state=PeerState.QUARANTINED),),
            gw=gateway(portal_port=9443),
        )
    )
    lines = chain_lines(output, "input")
    portal = index_of(lines, "fg:quarantine-portal")
    deny = index_of(lines, "fg:quarantine-deny")
    assert "tcp dport 9443" in lines[portal]
    assert portal < deny
    assert lines[deny].endswith('counter drop comment "fg:quarantine-deny"')


def test_quarantined_peers_never_transit_the_gateway():
    output = generate_ruleset(
        spec(peers=(peer("q", "10.88.0.9", state=PeerState.QUARANTINED),))
    )
    forward = "\n".join(chain_lines(output, "forward"))
    assert "fg:quarantine-no-forward" in forward
    # Also unreachable as a destination, so an active peer cannot poke at it.
    assert "fg:quarantine-unreachable" in forward


def test_dns_can_be_denied_in_quarantine():
    allowed = generate_ruleset(spec(gw=gateway(allow_dns_in_quarantine=True)))
    denied = generate_ruleset(spec(gw=gateway(allow_dns_in_quarantine=False)))
    assert "fg:quarantine-dns" in allowed
    assert "fg:quarantine-dns" not in denied


def test_open_gateway_input_policy_defers_to_the_host_firewall():
    lines = chain_lines(generate_ruleset(spec()), "input")
    assert lines[-1] == 'accept comment "fg:gateway-input-open"'


def test_restricted_gateway_input_policy_drops_everything_else():
    output = generate_ruleset(
        spec(gw=gateway(gateway_input_policy=GatewayInputPolicy.RESTRICTED))
    )
    lines = chain_lines(output, "input")
    assert lines[-1] == 'counter drop comment "fg:gateway-input-deny"'
    assert any("fg:portal" in line for line in lines)


# --------------------------------------------------------------------------- #
# validation / injection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "slug",
    [
        'foo" ; flush ruleset ; #',
        "foo bar",
        "Foo",
        "-foo",
        "a" * 25,
        "",
        "foo\nbar",
    ],
)
def test_hostile_group_slugs_are_rejected(slug):
    with pytest.raises(RulesetValidationError):
        generate_ruleset(spec(groups=(GroupSpec(slug),)))


@pytest.mark.parametrize(
    "iface", ['eth0" ; flush ruleset ; #', "iface with spaces", "a" * 16, ""]
)
def test_hostile_interface_names_are_rejected(iface):
    with pytest.raises(RulesetValidationError):
        generate_ruleset(spec(gw=gateway(wg_interface=iface)))


def test_rule_comments_cannot_break_out_of_their_quotes():
    """A hostile rule name must stay inert text, not become an nft statement."""
    output = generate_ruleset(
        spec(rules=(rule("r1", comment='oops" ; flush ruleset ; #'),))
    )
    rendered = next(line for line in chain_lines(output, "forward") if "fg:r1:" in line)
    comment = rendered.split('comment "', 1)[1].rsplit('"', 1)[0]
    assert '"' not in comment
    assert ";" not in comment
    assert "#" not in comment
    assert "\n" not in comment
    # And the whole rule is still a single nft statement.
    assert rendered.count('comment "') == 1


def test_a_rule_named_flush_ruleset_is_still_appliable():
    """Sanitising keeps the words; the applier guard must not trip on a comment."""
    from foxguard.nftables import NftApplier

    output = generate_ruleset(spec(rules=(rule("r1", comment="flush ruleset"),)))
    NftApplier(runner=object(), table_name="foxguard").guard(output)  # must not raise


def test_unknown_group_reference_is_rejected():
    with pytest.raises(RulesetValidationError) as excinfo:
        generate_ruleset(spec(rules=(rule("r1", src=Endpoint.group("ghost")),)))
    assert "ghost" in str(excinfo.value)


def test_duplicate_group_slug_is_rejected():
    with pytest.raises(RulesetValidationError):
        generate_ruleset(spec(groups=(GroupSpec("admin"), GroupSpec("admin"))))


def test_duplicate_tunnel_address_is_rejected():
    with pytest.raises(RulesetValidationError) as excinfo:
        generate_ruleset(
            spec(peers=(peer("a", "10.88.0.2"), peer("b", "10.88.0.2")))
        )
    assert "already used" in str(excinfo.value)


def test_ports_without_a_layer4_protocol_are_rejected():
    with pytest.raises(RulesetValidationError) as excinfo:
        generate_ruleset(spec(rules=(rule("r1", protocol=Protocol.ICMP, port=80),)))
    assert "tcp/udp" in str(excinfo.value)


def test_inverted_port_range_is_rejected():
    with pytest.raises(RulesetValidationError):
        generate_ruleset(
            spec(rules=(rule("r1", protocol=Protocol.TCP, port=900, port_end=100),))
        )


def test_active_peer_without_an_address_is_rejected():
    with pytest.raises(RulesetValidationError) as excinfo:
        generate_ruleset(spec(peers=(peer("a", None),)))
    assert "without any tunnel address" in str(excinfo.value)


def test_all_validation_errors_are_reported_at_once():
    """An ACL import should show everything wrong, not fail one item at a time."""
    with pytest.raises(RulesetValidationError) as excinfo:
        generate_ruleset(
            spec(
                groups=(GroupSpec("Bad Slug"),),
                rules=(
                    rule("r1", src=Endpoint.group("ghost")),
                    rule("r2", protocol=Protocol.ICMP, port=80),
                ),
            )
        )
    assert len(excinfo.value.errors) >= 3


def test_invalid_cidr_is_rejected():
    with pytest.raises(RulesetValidationError):
        generate_ruleset(spec(rules=(rule("r1", dst=Endpoint.network("10.0.0.0/33")),)))


# --------------------------------------------------------------------------- #
# golden file
# --------------------------------------------------------------------------- #


def test_full_ruleset_matches_the_golden_file(tmp_path, request):
    """Approval test over a realistic configuration.

    The baseline is created on first run (or with ``FOXGUARD_UPDATE_GOLDEN=1``)
    and committed. After that, any change to the rendered output has to be an
    explicit, reviewable diff of ``tests/golden/full_ruleset.nft``.
    """
    import os
    from pathlib import Path

    groups, peers, rules = _sample_spec()
    output = generate_ruleset(
        spec(
            groups=groups,
            peers=peers,
            rules=rules,
            gw=gateway(wan_interface="eth0", wg_interface="wg0"),
        )
    )

    golden = Path(request.path).parent / "golden" / "full_ruleset.nft"
    if os.environ.get("FOXGUARD_UPDATE_GOLDEN") or not golden.exists():
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(output, encoding="utf-8")
        pytest.skip(f"golden baseline written to {golden}; re-run to compare")

    assert output == golden.read_text(encoding="utf-8"), (
        "rendered ruleset changed; review the diff and re-run with "
        "FOXGUARD_UPDATE_GOLDEN=1 if the change is intended"
    )
