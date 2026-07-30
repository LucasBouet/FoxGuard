"""Tests for the DNS artefact generator.

Written the same way as the nftables tests: safety properties first (no
injection, no open resolver, no name hijack, no leak of internal names) and
feature coverage second. Nothing here needs root, a database or dnsmasq --
``test_dns_live.py`` covers what only a real daemon can prove.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from foxguard.dns import (
    CnameEntry,
    DnsSpec,
    DnsValidationError,
    HostEntry,
    ResolverMode,
    derive_label,
    dns_digest,
    fallback_label,
    render_conf,
    render_hosts,
    reverse_zone,
)

ZONE = "fox.internal"


def host(address: str, *names: str, comment: str | None = None) -> HostEntry:
    return HostEntry(address=address, names=tuple(names), comment=comment)


def spec(**overrides) -> DnsSpec:
    defaults = dict(
        zone=ZONE,
        listen_addresses=("10.88.0.1",),
        hosts=(
            host("10.88.0.1", f"gw.{ZONE}"),
            host("10.88.0.5", f"laptop.{ZONE}"),
        ),
        reverse_pools=("10.88.0.0/24",),
    )
    defaults.update(overrides)
    return DnsSpec(**defaults)


def conf_lines(spec_: DnsSpec) -> list[str]:
    return [
        line
        for line in render_conf(spec_).splitlines()
        if line.strip() and not line.startswith("#")
    ]


# --------------------------------------------------------------------------- #
# safety properties
# --------------------------------------------------------------------------- #


def test_never_binds_every_interface():
    """A wildcard bind on the gateway publishes an open resolver on the WAN."""
    lines = conf_lines(spec())
    assert "listen-address=10.88.0.1" in lines
    assert "bind-interfaces" in lines
    assert not any(line.startswith("interface=") for line in lines)


def test_never_reads_the_hosts_configuration_of_the_box():
    """Foxguard's resolver serves Foxguard's records and nothing else."""
    lines = conf_lines(spec())
    assert "no-hosts" in lines
    assert not any(line.startswith("conf-dir") for line in lines)
    assert not any(line.startswith("conf-file") for line in lines)


def test_internal_names_are_never_asked_upstream():
    """`local=` makes the zone authoritative, so no internal name leaks out."""
    assert f"local=/{ZONE}/" in conf_lines(spec())


def test_reverse_lookups_for_the_pool_stay_local():
    assert "local=/0.88.10.in-addr.arpa/" in conf_lines(spec())


def test_short_names_are_never_served():
    """``expand-hosts`` would make us authoritative for bare labels globally.

    A peer named ``wpad`` or ``mail`` would then answer for a name its clients
    expect to resolve elsewhere. Short names belong to the client's search
    domain, which is why the peer config carries ``DNS = <gateway>, <zone>``.
    """
    assert "expand-hosts" not in conf_lines(spec())
    assert all(ZONE in line for line in render_hosts(spec()).splitlines() if line[:1].isdigit())


@pytest.mark.parametrize(
    "hostile",
    [
        "server=8.8.8.8",
        "gw.fox.internal\nserver=8.8.8.8",
        "a b",
        "-leading.fox.internal",
        "trailing-.fox.internal",
        "UPPER.fox.internal",
        "under_score.fox.internal",
        "",
    ],
)
def test_a_peer_name_can_never_become_a_directive(hostile):
    with pytest.raises(DnsValidationError):
        render_hosts(spec(hosts=(host("10.88.0.5", hostile),)))


def test_names_outside_the_zone_are_refused():
    """Answering for a name we do not own is a hijack, not a feature."""
    with pytest.raises(DnsValidationError) as exc:
        render_hosts(spec(hosts=(host("10.88.0.5", "www.google.com"),)))
    assert "outside the zone" in str(exc.value)


def test_two_devices_cannot_share_a_name():
    with pytest.raises(DnsValidationError) as exc:
        render_hosts(
            spec(
                hosts=(
                    host("10.88.0.5", f"laptop.{ZONE}"),
                    host("10.88.0.6", f"laptop.{ZONE}"),
                )
            )
        )
    assert "cannot share a name" in str(exc.value)


def test_a_dual_stack_peer_keeps_one_name():
    """A and AAAA for the same name is the normal shape of a dual-stack device."""
    rendered = render_hosts(
        spec(
            hosts=(
                host("10.88.0.5", f"laptop.{ZONE}"),
                host("fd00:88::5", f"laptop.{ZONE}"),
            ),
            reverse_pools=(),
        )
    )
    assert f"10.88.0.5\tlaptop.{ZONE}" in rendered
    assert f"fd00:88::5\tlaptop.{ZONE}" in rendered


def test_one_address_cannot_appear_twice():
    """Which name wins the reverse lookup would otherwise depend on file order."""
    with pytest.raises(DnsValidationError) as exc:
        render_hosts(
            spec(hosts=(host("10.88.0.5", f"a.{ZONE}"), host("10.88.0.5", f"b.{ZONE}")))
        )
    assert "duplicate address" in str(exc.value)


def test_a_hosts_path_with_a_newline_is_refused():
    """The configuration file is line-based; a newline in a value is a directive."""
    with pytest.raises(DnsValidationError):
        render_conf(spec(hosts_path="/etc/foxguard/dns/hosts\nlog-queries"))


@pytest.mark.parametrize("option", ["log-queries\nserver=8.8.8.8", "Server=1.1.1.1", "!"])
def test_extra_options_must_be_a_single_dnsmasq_option(option):
    with pytest.raises(DnsValidationError):
        render_conf(spec(extra_options=(option,)))


def test_extra_options_are_passed_through_verbatim():
    """The escape hatch has to actually work, or it is not one."""
    assert "dns-forward-max=300" in conf_lines(spec(extra_options=("dns-forward-max=300",)))


@pytest.mark.parametrize("bad", ["1.1.1.1:53", "not-an-ip", "1.1.1.1#99999", "8.8.8.8 "])
def test_upstreams_are_validated(bad):
    with pytest.raises(DnsValidationError):
        render_conf(spec(mode=ResolverMode.FORWARD, upstreams=(bad,)))


# --------------------------------------------------------------------------- #
# resolver modes
# --------------------------------------------------------------------------- #


def test_split_mode_has_no_upstream_at_all():
    """Nothing about the fleet's browsing reaches the gateway in this mode."""
    lines = conf_lines(spec(mode=ResolverMode.SPLIT, upstreams=("1.1.1.1",)))
    assert "no-resolv" in lines
    assert not any(line.startswith("server=") for line in lines)


def test_forward_mode_uses_the_configured_upstreams():
    lines = conf_lines(spec(mode=ResolverMode.FORWARD, upstreams=("1.1.1.1", "9.9.9.9#5353")))
    assert "no-resolv" in lines
    assert lines.count("server=1.1.1.1") == 1
    assert "server=9.9.9.9#5353" in lines


def test_forward_mode_without_upstreams_falls_back_to_the_host_resolver():
    """Emitting ``no-resolv`` with no server would leave a resolver that cannot resolve."""
    lines = conf_lines(spec(mode=ResolverMode.FORWARD, upstreams=()))
    assert "no-resolv" not in lines


def test_forward_mode_does_not_leak_private_reverse_lookups():
    lines = conf_lines(spec(mode=ResolverMode.FORWARD, upstreams=("1.1.1.1",)))
    assert "bogus-priv" in lines
    assert "domain-needed" in lines


def test_rebind_protection_is_off_by_default():
    """A split-horizon upstream legitimately answers with private addresses."""
    assert "stop-dns-rebind" not in conf_lines(spec(mode=ResolverMode.FORWARD))


def test_rebind_protection_exempts_our_own_zone():
    lines = conf_lines(spec(mode=ResolverMode.FORWARD, stop_dns_rebind=True))
    assert "stop-dns-rebind" in lines
    assert f"rebind-domain-ok=/{ZONE}/" in lines


# --------------------------------------------------------------------------- #
# records
# --------------------------------------------------------------------------- #


def test_the_first_name_on_a_line_is_the_canonical_one():
    """dnsmasq answers the reverse lookup with it, so ordering is data."""
    rendered = render_hosts(
        spec(hosts=(host("10.88.0.5", f"laptop.{ZONE}", f"old-laptop.{ZONE}"),))
    )
    line = next(ln for ln in rendered.splitlines() if ln.startswith("10.88.0.5"))
    assert line.split("\t")[1].split() == [f"laptop.{ZONE}", f"old-laptop.{ZONE}"]


def test_ipv6_hosts_render_alongside_ipv4():
    rendered = render_hosts(
        spec(
            hosts=(host("10.88.0.5", f"laptop.{ZONE}"), host("fd00::5", f"laptop6.{ZONE}")),
            reverse_pools=(),
        )
    )
    assert f"fd00::5\tlaptop6.{ZONE}" in rendered


def test_a_cname_must_point_at_a_name_we_serve():
    """An alias to an unknown target is a silently dead record."""
    with pytest.raises(DnsValidationError) as exc:
        render_conf(spec(cnames=(CnameEntry(f"portal.{ZONE}", f"ghost.{ZONE}"),)))
    assert "not a name this resolver knows" in str(exc.value)


def test_a_cname_cannot_shadow_a_host():
    with pytest.raises(DnsValidationError) as exc:
        render_conf(spec(cnames=(CnameEntry(f"laptop.{ZONE}", f"gw.{ZONE}"),)))
    assert "shadows" in str(exc.value)


def test_a_cname_cannot_point_at_itself():
    with pytest.raises(DnsValidationError):
        render_conf(spec(cnames=(CnameEntry(f"portal.{ZONE}", f"portal.{ZONE}"),)))


def test_cnames_render_as_dnsmasq_directives():
    lines = conf_lines(spec(cnames=(CnameEntry(f"portal.{ZONE}", f"gw.{ZONE}"),)))
    assert f"cname=portal.{ZONE},gw.{ZONE}" in lines


def test_the_zone_apex_may_be_a_host():
    """``fox.internal`` itself pointing at the gateway is a normal thing to want."""
    render_hosts(spec(hosts=(host("10.88.0.1", ZONE),)))


# --------------------------------------------------------------------------- #
# determinism
# --------------------------------------------------------------------------- #


def test_output_is_byte_stable_regardless_of_input_order():
    forward = spec(
        hosts=(
            host("10.88.0.1", f"gw.{ZONE}"),
            host("10.88.0.5", f"a.{ZONE}"),
            host("10.88.0.9", f"b.{ZONE}"),
        ),
        cnames=(CnameEntry(f"x.{ZONE}", f"a.{ZONE}"), CnameEntry(f"y.{ZONE}", f"b.{ZONE}")),
    )
    reverse = spec(
        hosts=tuple(reversed(forward.hosts)), cnames=tuple(reversed(forward.cnames))
    )
    assert render_hosts(forward) == render_hosts(reverse)
    assert render_conf(forward) == render_conf(reverse)


def test_addresses_sort_numerically_not_lexically():
    rendered = render_hosts(
        spec(
            hosts=(
                host("10.88.0.20", f"twenty.{ZONE}"),
                host("10.88.0.3", f"three.{ZONE}"),
            ),
        )
    )
    order = [ln.split("\t")[0] for ln in rendered.splitlines() if ln[:1].isdigit()]
    assert order == ["10.88.0.3", "10.88.0.20"]


def test_the_digest_covers_both_artefacts():
    """Either file changing alone must move the digest, or half a change applies."""
    base = dns_digest("hosts", "conf")
    assert dns_digest("hosts2", "conf") != base
    assert dns_digest("hosts", "conf2") != base


def test_the_digest_cannot_be_confused_by_moving_bytes_between_artefacts():
    assert dns_digest("ab", "c") != dns_digest("a", "bc")


# --------------------------------------------------------------------------- #
# reverse zones
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("cidr", "expected"),
    [
        ("10.88.0.0/24", "0.88.10.in-addr.arpa"),
        ("10.13.0.0/16", "13.10.in-addr.arpa"),
        ("10.0.0.0/8", "10.in-addr.arpa"),
        # Rounded outwards to the enclosing label boundary: the surplus answers
        # NXDOMAIN here rather than leaking a query about our addressing.
        ("10.88.0.0/25", "0.88.10.in-addr.arpa"),
        ("10.88.0.0/23", "88.10.in-addr.arpa"),
        # /64 is 16 nibbles: 14 zeros, then d and f from fd00.
        ("fd00::/64", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"),
    ],
)
def test_reverse_zone_rounds_outwards(cidr, expected):
    assert reverse_zone(cidr) == expected


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0", "10.0.0.0/4"])
def test_reverse_zone_refuses_to_claim_the_whole_tree(cidr):
    """Claiming ``in-addr.arpa`` would answer for every address on the internet."""
    assert reverse_zone(cidr) is None


# --------------------------------------------------------------------------- #
# label derivation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("laptop", "laptop"),
        ("Lucas' MacBook Pro", "lucas-macbook-pro"),
        ("  spaced  out  ", "spaced-out"),
        ("Café", "cafe"),
        ("under_score", "under-score"),
        ("-leading-and-trailing-", "leading-and-trailing"),
        ("a" * 80, "a" * 63),
    ],
)
def test_derive_label(name, expected):
    assert derive_label(name) == expected


def test_derive_label_never_ends_on_a_hyphen_after_truncation():
    """Truncating at 63 can land on a hyphen, which is not a legal label."""
    assert derive_label("a" * 62 + "-tail") == "a" * 62


@pytest.mark.parametrize("name", ["", "🦊", "---", "  "])
def test_derive_label_gives_up_rather_than_inventing(name):
    assert derive_label(name) is None


def test_fallback_label_is_stable_and_legal():
    from foxguard.dns import NAME_RE

    label = fallback_label("3f2504e0-4f89-11d3-9a0c-0305e82c3301")
    assert label == "peer-3f2504e04f89"
    assert NAME_RE.match(label)


# --------------------------------------------------------------------------- #
# golden files
# --------------------------------------------------------------------------- #


def _sample_spec() -> DnsSpec:
    return DnsSpec(
        zone=ZONE,
        listen_addresses=("10.88.0.1", "fd00:88::1"),
        hosts=(
            host("10.88.0.1", f"gw.{ZONE}", comment="gateway"),
            host("10.88.0.5", f"laptop.{ZONE}", comment="user peer"),
            host("10.88.0.6", f"backup.{ZONE}", f"nas.{ZONE}", comment="server peer"),
            host("fd00:88::1", f"gw6.{ZONE}"),
        ),
        cnames=(
            CnameEntry(f"portal.{ZONE}", f"gw.{ZONE}"),
            CnameEntry(f"files.{ZONE}", f"backup.{ZONE}"),
        ),
        mode=ResolverMode.FORWARD,
        upstreams=("1.1.1.1", "9.9.9.9"),
        reverse_pools=("10.88.0.0/24", "fd00:88::/64"),
    )


@pytest.mark.parametrize(
    ("name", "render"), [("hosts", render_hosts), ("dnsmasq.conf", render_conf)]
)
def test_matches_the_golden_file(name, render, request):
    """Approval test: any change to the served zone is a reviewable diff."""
    output = render(_sample_spec())
    golden = Path(request.path).parent / "golden" / f"dns_{name}"
    if os.environ.get("FOXGUARD_UPDATE_GOLDEN") or not golden.exists():
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(output, encoding="utf-8")
        pytest.skip(f"golden baseline written to {golden}; re-run to compare")

    assert output == golden.read_text(encoding="utf-8"), (
        f"rendered {name} changed; review the diff and re-run with "
        "FOXGUARD_UPDATE_GOLDEN=1 if the change is intended"
    )
