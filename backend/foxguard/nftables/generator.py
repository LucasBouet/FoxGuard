"""Deterministic nftables ruleset generator.

Design rules — every one of them is covered by a test in
``tests/test_nft_generator.py``:

1.  **Own table only.** Everything lives in ``table inet <name>`` (default
    ``foxguard``). The script never emits ``flush ruleset`` and never deletes a
    table it does not own, so it cohabits with the host firewall / Docker /
    fail2ban rules already on the box.
2.  **No lockout.** Base chains use ``policy accept`` and traffic that does not
    involve the WireGuard interface is accepted immediately (meaning: "this
    table has no opinion"). Default-deny is expressed as an *explicit* drop at
    the end of the tunnel-facing path, never as a chain policy. In nftables a
    ``drop`` in any table wins, so accepting here never weakens another table.
3.  **No connection reset on reload.** ``ct state established,related accept``
    comes before the policy rules, and the whole script is a single atomic nft
    transaction, so reloading does not touch conntrack.
4.  **Byte-stable output.** Same database state -> same bytes. No timestamps, no
    dict ordering leaks, no hostname. This is what makes drift detection and
    "regenerate from DB" idempotent.
5.  **No injection.** Every identifier that reaches the nft script is validated
    against a strict regex, and comments are sanitised. A group named
    ``foo" ; flush ruleset ; #`` is a validation error, not a ruleset.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterable, Iterator

from .model import (
    FAMILIES,
    Endpoint,
    EndpointKind,
    Family,
    GatewayInputPolicy,
    Protocol,
    RulesetSpec,
    RuleSpec,
    ZoneSpec,
)

__all__ = [
    "RulesetValidationError",
    "generate_ruleset",
    "ruleset_digest",
    "validate_spec",
    "group_set_name",
    "quarantine_set_name",
    "internal_set_name",
    "zone_set_name",
]

# nft identifiers are limited (historically NFT_NAME_MAXLEN=32 for set names).
# Keeping slugs short leaves room for the ``g_``/``_v4`` decoration.
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,23}$")
TABLE_RE = re.compile(r"^[a-z][a-z0-9_]{0,23}$")
# Linux IFNAMSIZ is 16 including the NUL terminator.
IFACE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}$")
RULE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_UNSAFE_COMMENT_CHARS = re.compile(r"[^A-Za-z0-9 :._/@=+-]")

INDENT = "    "
_MAX_COMMENT = 96

_BANNER = (
    "#!/usr/sbin/nft -f\n"
    "#\n"
    "# Foxguard generated ruleset -- DO NOT EDIT BY HAND.\n"
    "# Regenerate with: foxguard-cli ruleset render   (source of truth is the database)\n"
    "#\n"
    "# This file is byte-stable: identical database state produces identical bytes.\n"
    "#\n"
)

# ICMP error types that must always pass, otherwise Path MTU Discovery breaks
# and you get silent black holes inside the tunnel.
_ICMP_ERRORS_V4 = "{ destination-unreachable, time-exceeded, parameter-problem }"
_ICMP_ERRORS_V6 = (
    "{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem }"
)


class RulesetValidationError(ValueError):
    """Raised when a spec cannot be turned into a safe ruleset.

    Carries *all* problems found, not just the first one, so the API can report
    everything wrong with an ACL import in a single response.
    """

    def __init__(self, errors: Iterable[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors))


# --------------------------------------------------------------------------- #
# naming
# --------------------------------------------------------------------------- #


def group_set_name(slug: str, family: Family) -> str:
    """nft set name for a group.

    Hyphens are replaced by underscores. nft's scanner does accept ``-`` inside
    identifiers, but ``-`` is also its range/subtraction operator, and this is
    the one component where an ambiguity we cannot easily test is not worth
    carrying: ``@g_backup_svc_v4`` is unambiguous in every nft version.

    ``validate_spec`` rejects two slugs that would collapse to the same set name
    (``back-up`` and ``back_up``), so the mapping stays injective.
    """
    return f"g_{slug.replace('-', '_')}_{family.suffix}"


def zone_set_name(slug: str, family: Family) -> str:
    """nft set name for a zone.

    A different prefix from groups, and not merely for readability: zone sets
    carry ``flags interval`` because a zone holds routed prefixes as well as
    peer addresses, and nft cannot mix the two shapes in one set. Sharing the
    ``g_`` namespace would also let a group and a zone of the same slug collapse
    onto one set.
    """
    return f"z_{slug.replace('-', '_')}_{family.suffix}"


def quarantine_set_name(family: Family) -> str:
    return f"fg_quarantine_{family.suffix}"


def internal_set_name(family: Family) -> str:
    return f"fg_internal_{family.suffix}"


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #


def _check_cidr(value: str, label: str, errors: list[str]) -> None:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        errors.append(f"{label}: invalid CIDR {value!r} ({exc})")


def _validate_endpoint(
    endpoint: Endpoint,
    label: str,
    known_groups: frozenset[str],
    known_zones: frozenset[str],
    errors: list[str],
) -> None:
    if endpoint.kind is EndpointKind.GROUP:
        if not endpoint.group_slug:
            errors.append(f"{label}: group endpoint without a slug")
        elif endpoint.group_slug not in known_groups:
            errors.append(f"{label}: unknown group {endpoint.group_slug!r}")
    elif endpoint.kind is EndpointKind.ZONE:
        if not endpoint.zone_slug:
            errors.append(f"{label}: zone endpoint without a slug")
        elif endpoint.zone_slug not in known_zones:
            errors.append(f"{label}: unknown zone {endpoint.zone_slug!r}")
    elif endpoint.kind is EndpointKind.CIDR:
        if not endpoint.cidr:
            errors.append(f"{label}: cidr endpoint without a value")
        else:
            _check_cidr(endpoint.cidr, label, errors)


def _validate_ports(rule: RuleSpec, label: str, errors: list[str]) -> None:
    start, end = rule.dst_port_start, rule.dst_port_end
    if start is None and end is None:
        return
    if not rule.protocol.supports_ports:
        errors.append(
            f"{label}: ports are only valid for tcp/udp, got {rule.protocol.value}"
        )
        return
    if start is None:
        errors.append(f"{label}: port range end without a start")
        return
    for value, name in ((start, "dst_port_start"), (end, "dst_port_end")):
        if value is not None and not (1 <= value <= 65535):
            errors.append(f"{label}: {name} {value} out of range 1-65535")
    if end is not None and start > end:
        errors.append(f"{label}: port range {start}-{end} is inverted")


def validate_spec(spec: RulesetSpec) -> None:
    """Raise :class:`RulesetValidationError` if ``spec`` is unsafe or malformed."""
    errors: list[str] = []
    gw = spec.gateway

    if not TABLE_RE.match(gw.table_name):
        errors.append(f"gateway.table_name {gw.table_name!r} is not a safe nft identifier")
    if not IFACE_RE.match(gw.wg_interface):
        errors.append(f"gateway.wg_interface {gw.wg_interface!r} is not a valid interface name")
    if gw.wan_interface is not None and not IFACE_RE.match(gw.wan_interface):
        errors.append(f"gateway.wan_interface {gw.wan_interface!r} is not a valid interface name")
    if not (1 <= gw.portal_port <= 65535):
        errors.append(f"gateway.portal_port {gw.portal_port} out of range 1-65535")
    for cidr in gw.internal_cidrs:
        _check_cidr(cidr, "gateway.internal_cidrs", errors)

    seen_slugs: set[str] = set()
    set_names: dict[str, str] = {}
    for group in spec.groups:
        if not SLUG_RE.match(group.slug):
            errors.append(
                f"group {group.slug!r}: slug must match {SLUG_RE.pattern} "
                "(lowercase, max 24 chars)"
            )
        if group.slug in seen_slugs:
            errors.append(f"group {group.slug!r}: duplicate slug")
        seen_slugs.add(group.slug)

        # Two slugs must never collapse onto the same nft set name, or one
        # group would silently inherit the other's members.
        normalised = group_set_name(group.slug, Family.V4)
        clash = set_names.get(normalised)
        if clash is not None and clash != group.slug:
            errors.append(
                f"group {group.slug!r}: collides with group {clash!r} "
                f"on nft set name {normalised!r} (hyphens and underscores are equivalent there)"
            )
        set_names[normalised] = group.slug
        if group.internet_exit and not gw.wan_interface:
            errors.append(
                f"group {group.slug!r}: internet_exit requires gateway.wan_interface to be set"
            )

    known_groups = frozenset(seen_slugs)

    seen_zones: set[str] = set()
    zone_set_names: dict[str, str] = {}
    for zone in spec.zones:
        if not SLUG_RE.match(zone.slug):
            errors.append(
                f"zone {zone.slug!r}: slug must match {SLUG_RE.pattern} "
                "(lowercase, max 24 chars)"
            )
        if zone.slug in seen_zones:
            errors.append(f"zone {zone.slug!r}: duplicate slug")
        seen_zones.add(zone.slug)

        normalised = zone_set_name(zone.slug, Family.V4)
        clash = zone_set_names.get(normalised)
        if clash is not None and clash != zone.slug:
            errors.append(
                f"zone {zone.slug!r}: collides with zone {clash!r} on nft set name "
                f"{normalised!r} (hyphens and underscores are equivalent there)"
            )
        zone_set_names[normalised] = zone.slug

        if zone.internet_exit and not gw.wan_interface:
            errors.append(
                f"zone {zone.slug!r}: internet_exit requires gateway.wan_interface to be set"
            )

        seen_cidrs: set[str] = set()
        for route in zone.routes:
            rlabel = f"zone {zone.slug!r} route {route.cidr!r}"
            try:
                network = ipaddress.ip_network(route.cidr, strict=False)
            except ValueError as exc:
                errors.append(f"{rlabel}: invalid CIDR ({exc})")
                continue
            if network.prefixlen == 0:
                # A default route inside a zone would have the agent install
                # 0.0.0.0/0 dev wg0 on the gateway, replacing its own default
                # route and cutting every remote session including the one that
                # asked for this. Policy routing is the correct mechanism and it
                # is not what a route in a zone means.
                errors.append(
                    f"{rlabel}: a zone route may not be a default route -- it would "
                    "replace the gateway's own default route"
                )
            if str(network) in seen_cidrs:
                errors.append(f"{rlabel}: duplicate route in this zone")
            seen_cidrs.add(str(network))

    known_zones = frozenset(seen_zones)

    # A CIDR may be carried by at most one peer, across every zone. WireGuard
    # resolves an address to a peer through AllowedIPs, and two peers claiming
    # the same prefix is not a tie it reports -- ``wg`` silently moves the entry
    # to whichever peer was configured last, so the route would work until an
    # unrelated change reordered them.
    carriers: dict[str, str] = {}
    for zone in spec.zones:
        for route in zone.routes:
            if route.via_peer_id is None:
                continue
            try:
                cidr = str(ipaddress.ip_network(route.cidr, strict=False))
            except ValueError:
                continue  # already reported above
            previous = carriers.get(cidr)
            if previous is not None and previous != route.via_peer_id:
                errors.append(
                    f"route {cidr} is carried by two different peers "
                    f"({previous} and {route.via_peer_id}); WireGuard would give it "
                    "to whichever was configured last"
                )
            carriers[cidr] = route.via_peer_id

    # A slug identifies exactly one thing. Groups and zones live in one table
    # with a unique slug, so this can only be reached by a spec built by hand --
    # and an ACL rule naming "servers" must never be ambiguous about which
    # "servers" it means.
    for shared in sorted(known_groups & known_zones):
        errors.append(f"slug {shared!r} is used by both a group and a zone")

    seen_peer_ids: set[str] = set()
    seen_addresses: dict[str, str] = {}
    for peer in spec.peers:
        label = f"peer {peer.id!r}"
        if peer.id in seen_peer_ids:
            errors.append(f"{label}: duplicate id")
        seen_peer_ids.add(peer.id)
        for slug in peer.group_slugs:
            if slug not in known_groups:
                errors.append(f"{label}: member of unknown group {slug!r}")
        if peer.zone_slug is not None and peer.zone_slug not in known_zones:
            errors.append(f"{label}: assigned to unknown zone {peer.zone_slug!r}")
        for family in FAMILIES:
            for address in peer.addresses(family):
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError as exc:
                    errors.append(f"{label}: invalid tunnel address {address!r} ({exc})")
                    continue
                if parsed.version != family.version:
                    errors.append(
                        f"{label}: address {address!r} is not {family.value}"
                    )
                    continue
                owner = seen_addresses.get(address)
                if owner is not None and owner != peer.id:
                    errors.append(
                        f"{label}: tunnel address {address} already used by peer {owner!r}"
                    )
                seen_addresses[address] = peer.id
        if peer.state.is_active and not (peer.tunnel_ip or peer.tunnel_ip6):
            errors.append(f"{label}: active peer without any tunnel address")

    for cidr, carrier in sorted(carriers.items()):
        if carrier not in seen_peer_ids:
            errors.append(f"route {cidr}: carried by unknown peer {carrier!r}")

    seen_rule_ids: set[str] = set()
    for rule in spec.rules:
        label = f"rule {rule.id!r}"
        if not RULE_ID_RE.match(rule.id):
            errors.append(f"{label}: id must match {RULE_ID_RE.pattern}")
        if rule.id in seen_rule_ids:
            errors.append(f"{label}: duplicate id")
        seen_rule_ids.add(rule.id)
        _validate_endpoint(rule.src, f"{label}.src", known_groups, known_zones, errors)
        _validate_endpoint(rule.dst, f"{label}.dst", known_groups, known_zones, errors)
        _validate_ports(rule, label, errors)

    if errors:
        raise RulesetValidationError(errors)


# --------------------------------------------------------------------------- #
# rendering helpers
# --------------------------------------------------------------------------- #


def _sanitize_comment(value: str | None) -> str:
    if not value:
        return ""
    cleaned = _UNSAFE_COMMENT_CHARS.sub(" ", value).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned[:_MAX_COMMENT]


def _comment(value: str | None) -> str:
    cleaned = _sanitize_comment(value)
    return f' comment "{cleaned}"' if cleaned else ""


def _sorted_addresses(values: Iterable[str]) -> list[str]:
    return [str(addr) for addr in sorted({ipaddress.ip_address(v) for v in values})]


def _sorted_networks(values: Iterable[str]) -> list[str]:
    return [
        str(net)
        for net in sorted(
            {ipaddress.ip_network(v, strict=False) for v in values},
            key=lambda n: (n.version, n.network_address, n.prefixlen),
        )
    ]


def _render_set(
    name: str,
    family: Family,
    elements: list[str],
    *,
    interval: bool,
    description: str,
) -> Iterator[str]:
    yield f"{INDENT}# {description}"
    yield f"{INDENT}set {name} {{"
    yield f"{INDENT * 2}type {family.set_type}"
    if interval:
        yield f"{INDENT * 2}flags interval"
    if elements:
        yield f"{INDENT * 2}elements = {{ {', '.join(elements)} }}"
    yield f"{INDENT}}}"


def _endpoint_match(
    endpoint: Endpoint, direction: str, family: Family
) -> list[str] | None:
    """Return nft match tokens, or ``None`` if the endpoint excludes this family."""
    if endpoint.kind is EndpointKind.ANY:
        return []
    # These are guaranteed by validate_spec, but raise rather than assert: under
    # `python -O` an assert vanishes and we would emit a malformed rule instead
    # of refusing to generate one.
    if endpoint.kind is EndpointKind.GROUP:
        if endpoint.group_slug is None:
            raise RulesetValidationError(["group endpoint without a slug"])
        return [f"{family.addr_kw} {direction}addr @{group_set_name(endpoint.group_slug, family)}"]
    if endpoint.kind is EndpointKind.ZONE:
        if endpoint.zone_slug is None:
            raise RulesetValidationError(["zone endpoint without a slug"])
        return [f"{family.addr_kw} {direction}addr @{zone_set_name(endpoint.zone_slug, family)}"]
    if endpoint.cidr is None:
        raise RulesetValidationError(["cidr endpoint without a value"])
    network = ipaddress.ip_network(endpoint.cidr, strict=False)
    if network.version != family.version:
        return None
    return [f"{family.addr_kw} {direction}addr {network}"]


def _protocol_match(rule: RuleSpec, family: Family) -> list[str] | None:
    """Return protocol/port tokens, or ``None`` if the rule cannot apply here."""
    protocol = rule.protocol
    if protocol is Protocol.ANY:
        return []
    if protocol is Protocol.ICMP:
        return ["meta l4proto icmp" if family is Family.V4 else "meta l4proto ipv6-icmp"]

    name = protocol.value
    start, end = rule.dst_port_start, rule.dst_port_end
    if start is None:
        return [f"meta l4proto {name}"]
    if end is None or end == start:
        return [f"{name} dport {start}"]
    return [f"{name} dport {start}-{end}"]


def _render_acl_rule(rule: RuleSpec, family: Family) -> str | None:
    src = _endpoint_match(rule.src, "s", family)
    if src is None:
        return None
    dst = _endpoint_match(rule.dst, "d", family)
    if dst is None:
        return None
    proto = _protocol_match(rule, family)
    if proto is None:
        return None

    tokens = [*src, *dst, *proto]
    if not tokens:
        # any -> any, protocol any: pin the family so we do not emit the same
        # rule twice with identical text.
        tokens = [f"meta nfproto {family.nfproto}"]

    label = _sanitize_comment(rule.comment) or f"rule {rule.id}"
    tokens.append("counter")
    tokens.append(rule.action.value)
    return f"{INDENT * 2}{' '.join(tokens)}{_comment(f'fg:{rule.id}:{label}')}"


# --------------------------------------------------------------------------- #
# sets
# --------------------------------------------------------------------------- #


def _group_members(spec: RulesetSpec, slug: str, family: Family) -> list[str]:
    addresses: list[str] = []
    for peer in spec.peers:
        if not peer.state.is_active or slug not in peer.group_slugs:
            continue
        addresses.extend(peer.addresses(family))
    return _sorted_addresses(addresses)


def _zone_members(spec: RulesetSpec, zone: ZoneSpec, family: Family) -> list[str]:
    """A zone's set: its active peers as host addresses, plus its routed networks.

    Both in one set is the point. "Who may reach the finance zone" has to mean
    the devices *and* the networks behind them, or every routed subnet would
    need its own ACL rule alongside the zone's.
    """
    addresses = [
        address
        for peer in spec.peers
        if peer.state.is_active and peer.zone_slug == zone.slug
        for address in peer.addresses(family)
    ]
    elements = [str(ipaddress.ip_network(a)) for a in _sorted_addresses(addresses)]
    return elements + _sorted_networks(zone.route_cidrs(family))


def _confined_members(spec: RulesetSpec, family: Family) -> list[str]:
    addresses: list[str] = []
    for peer in spec.peers:
        if peer.state.is_confined:
            addresses.extend(peer.addresses(family))
    return _sorted_addresses(addresses)


def _internal_networks(spec: RulesetSpec, family: Family) -> list[str]:
    matching = [
        cidr
        for cidr in spec.gateway.internal_cidrs
        if ipaddress.ip_network(cidr, strict=False).version == family.version
    ]
    return _sorted_networks(matching)


def _render_sets(spec: RulesetSpec) -> Iterator[str]:
    for family in FAMILIES:
        yield from _render_set(
            internal_set_name(family),
            family,
            _internal_networks(spec, family),
            interval=True,
            description=f"networks Foxguard considers internal ({family.value})",
        )
        yield ""

    for family in FAMILIES:
        yield from _render_set(
            quarantine_set_name(family),
            family,
            _confined_members(spec, family),
            interval=False,
            description=(
                f"peers in staging/quarantine: portal access only ({family.value})"
            ),
        )
        yield ""

    for group in sorted(spec.groups, key=lambda g: g.slug):
        for family in FAMILIES:
            yield from _render_set(
                group_set_name(group.slug, family),
                family,
                _group_members(spec, group.slug, family),
                interval=False,
                description=f"members of group {group.slug} ({family.value})",
            )
            yield ""

    for zone in sorted(spec.zones, key=lambda z: z.slug):
        for family in FAMILIES:
            yield from _render_set(
                zone_set_name(zone.slug, family),
                family,
                _zone_members(spec, zone, family),
                interval=True,
                description=(
                    f"zone {zone.slug}: member peers and routed networks "
                    f"({family.value})"
                ),
            )
            yield ""


# --------------------------------------------------------------------------- #
# chains
# --------------------------------------------------------------------------- #


def _render_input_chain(spec: RulesetSpec) -> Iterator[str]:
    gw = spec.gateway
    wg = gw.wg_interface

    yield f"{INDENT}chain input {{"
    yield f"{INDENT * 2}type filter hook input priority filter; policy accept;"
    yield ""
    yield f"{INDENT * 2}# Foxguard only governs traffic arriving from the tunnel."
    yield f"{INDENT * 2}# Accepting here means 'no opinion': other tables still filter."
    yield f'{INDENT * 2}iifname != "{wg}" accept'
    yield f"{INDENT * 2}ct state invalid counter drop"
    yield ""
    yield f"{INDENT * 2}# --- staging / quarantined peers: captive portal only ---"
    yield f"{INDENT * 2}# Deliberately evaluated BEFORE the established/related accept:"
    yield f"{INDENT * 2}# moving a peer to quarantine (session expiry, kill switch) must"
    yield f"{INDENT * 2}# cut its open flows immediately, not only its new ones."
    for family in FAMILIES:
        quarantine = quarantine_set_name(family)
        yield (
            f"{INDENT * 2}{family.addr_kw} saddr @{quarantine} tcp dport {gw.portal_port} "
            f'counter accept comment "fg:quarantine-portal"'
        )
    if gw.allow_dns_in_quarantine:
        for family in FAMILIES:
            quarantine = quarantine_set_name(family)
            yield (
                f"{INDENT * 2}{family.addr_kw} saddr @{quarantine} udp dport 53 "
                f'counter accept comment "fg:quarantine-dns"'
            )
            yield (
                f"{INDENT * 2}{family.addr_kw} saddr @{quarantine} tcp dport 53 "
                f'counter accept comment "fg:quarantine-dns"'
            )
    if gw.allow_icmp_to_gateway:
        yield (
            f"{INDENT * 2}ip saddr @{quarantine_set_name(Family.V4)} icmp type echo-request "
            f'counter accept comment "fg:quarantine-ping"'
        )
        yield (
            f"{INDENT * 2}ip6 saddr @{quarantine_set_name(Family.V6)} "
            f'icmpv6 type echo-request counter accept comment "fg:quarantine-ping"'
        )
    for family in FAMILIES:
        yield (
            f"{INDENT * 2}{family.addr_kw} saddr @{quarantine_set_name(family)} "
            f'counter drop comment "fg:quarantine-deny"'
        )
    yield ""
    yield f"{INDENT * 2}# --- below this point, only non-confined peers are left ---"
    yield f"{INDENT * 2}ct state established,related counter accept"
    yield f"{INDENT * 2}# ICMP errors must pass or PMTU discovery black-holes."
    yield f"{INDENT * 2}icmp type {_ICMP_ERRORS_V4} counter accept"
    yield f"{INDENT * 2}icmpv6 type {_ICMP_ERRORS_V6} counter accept"
    yield ""

    if gw.gateway_input_policy is GatewayInputPolicy.RESTRICTED:
        yield f"{INDENT * 2}# --- active peers: gateway services are restricted ---"
        yield (
            f"{INDENT * 2}tcp dport {gw.portal_port} counter accept "
            f'comment "fg:portal"'
        )
        if gw.allow_dns_in_quarantine:
            yield f'{INDENT * 2}udp dport 53 counter accept comment "fg:dns"'
            yield f'{INDENT * 2}tcp dport 53 counter accept comment "fg:dns"'
        if gw.allow_icmp_to_gateway:
            yield f'{INDENT * 2}icmp type echo-request counter accept comment "fg:ping"'
            yield f'{INDENT * 2}icmpv6 type echo-request counter accept comment "fg:ping"'
        yield f'{INDENT * 2}counter drop comment "fg:gateway-input-deny"'
    else:
        yield f"{INDENT * 2}# --- active peers: gateway-local services left to the host firewall ---"
        yield f'{INDENT * 2}accept comment "fg:gateway-input-open"'
    yield f"{INDENT}}}"


def _render_forward_chain(spec: RulesetSpec) -> Iterator[str]:
    gw = spec.gateway
    wg = gw.wg_interface

    yield f"{INDENT}chain forward {{"
    yield f"{INDENT * 2}type filter hook forward priority filter; policy accept;"
    yield ""
    yield f"{INDENT * 2}# Traffic that neither enters nor leaves the tunnel is none of"
    yield f"{INDENT * 2}# our business -- never break unrelated routing on this box."
    yield f'{INDENT * 2}iifname != "{wg}" oifname != "{wg}" accept comment "fg:foreign-traffic"'
    yield f"{INDENT * 2}ct state invalid counter drop"
    yield ""
    yield f"{INDENT * 2}# --- staging / quarantined peers never transit the gateway ---"
    yield f"{INDENT * 2}# Before the established/related accept on purpose: quarantining"
    yield f"{INDENT * 2}# a peer must tear its open flows down, not just block new ones."
    for family in FAMILIES:
        quarantine = quarantine_set_name(family)
        yield (
            f"{INDENT * 2}{family.addr_kw} saddr @{quarantine} counter drop "
            f'comment "fg:quarantine-no-forward"'
        )
        yield (
            f"{INDENT * 2}{family.addr_kw} daddr @{quarantine} counter drop "
            f'comment "fg:quarantine-unreachable"'
        )
    yield ""
    yield f"{INDENT * 2}# --- below this point, only non-confined peers are left ---"
    yield (
        f"{INDENT * 2}ct state established,related counter accept "
        f'comment "fg:no-reset-on-reload"'
    )
    yield f"{INDENT * 2}icmp type {_ICMP_ERRORS_V4} counter accept"
    yield f"{INDENT * 2}icmpv6 type {_ICMP_ERRORS_V6} counter accept"
    yield ""

    yield f"{INDENT * 2}# --- ACL policy rules (priority asc, then rule id) ---"
    rendered_any = False
    for rule in sorted(spec.rules, key=lambda r: r.sort_key):
        for family in FAMILIES:
            line = _render_acl_rule(rule, family)
            if line is not None:
                yield line
                rendered_any = True
    if not rendered_any:
        yield f"{INDENT * 2}# (no ACL rules defined)"
    yield ""

    intra_zones = [z for z in sorted(spec.zones, key=lambda z: z.slug) if z.intra_zone]
    if intra_zones:
        yield f"{INDENT * 2}# --- intra-zone traffic (opt-in, per zone) ---"
        yield f"{INDENT * 2}# After the ACL rules on purpose: an explicit drop above still"
        yield f"{INDENT * 2}# carves a subset out of a zone that talks to itself."
        for zone in intra_zones:
            for family in FAMILIES:
                name = zone_set_name(zone.slug, family)
                yield (
                    f"{INDENT * 2}{family.addr_kw} saddr @{name} "
                    f"{family.addr_kw} daddr @{name} counter accept "
                    f'comment "fg:intra-zone:{zone.slug}"'
                )
        yield ""

    exit_sources = [
        (g.slug, group_set_name)
        for g in sorted(spec.groups, key=lambda g: g.slug)
        if g.internet_exit
    ] + [
        (z.slug, zone_set_name)
        for z in sorted(spec.zones, key=lambda z: z.slug)
        if z.internet_exit
    ]
    if exit_sources:
        yield f"{INDENT * 2}# --- internet exit (never a shortcut into internal networks) ---"
        for slug, naming in exit_sources:
            for family in FAMILIES:
                yield (
                    f"{INDENT * 2}{family.addr_kw} saddr @{naming(slug, family)} "
                    f"{family.addr_kw} daddr != @{internal_set_name(family)} "
                    f'oifname "{gw.wan_interface}" counter accept '
                    f'comment "fg:internet-exit:{slug}"'
                )
        yield ""

    if gw.log_dropped:
        yield (
            f"{INDENT * 2}limit rate 5/minute burst 10 packets "
            f'log prefix "fg-drop " level info'
        )
    yield f'{INDENT * 2}counter drop comment "fg:default-deny"'
    yield f"{INDENT}}}"


def _render_nat_chain(spec: RulesetSpec) -> Iterator[str]:
    gw = spec.gateway
    exit_sources = [
        (g.slug, group_set_name)
        for g in sorted(spec.groups, key=lambda g: g.slug)
        if g.internet_exit
    ] + [
        (z.slug, zone_set_name)
        for z in sorted(spec.zones, key=lambda z: z.slug)
        if z.internet_exit
    ]
    if not exit_sources or not gw.wan_interface:
        return

    yield f"{INDENT}chain postrouting {{"
    yield f"{INDENT * 2}type nat hook postrouting priority srcnat; policy accept;"
    for slug, naming in exit_sources:
        for family in FAMILIES:
            yield (
                f"{INDENT * 2}{family.addr_kw} saddr @{naming(slug, family)} "
                f'oifname "{gw.wan_interface}" counter masquerade '
                f'comment "fg:nat:{slug}"'
            )
    yield f"{INDENT}}}"


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #


def _render_body(spec: RulesetSpec) -> Iterator[str]:
    table = f"table inet {spec.gateway.table_name}"

    yield "# Create-then-delete makes the script idempotent: the first line is a"
    yield "# no-op if the table exists, and guarantees the delete never fails."
    yield table
    yield f"delete {table}"
    yield ""
    yield f"{table} {{"
    yield from _render_sets(spec)
    yield from _render_input_chain(spec)
    yield ""
    yield from _render_forward_chain(spec)
    nat = list(_render_nat_chain(spec))
    if nat:
        yield ""
        yield from nat
    yield "}"


def generate_ruleset(spec: RulesetSpec) -> str:
    """Render ``spec`` into a complete, self-contained nft script.

    Raises :class:`RulesetValidationError` before producing anything if the spec
    would yield an unsafe ruleset.
    """
    validate_spec(spec)
    body = "\n".join(_render_body(spec)).rstrip("\n") + "\n"
    return _BANNER + body


def ruleset_digest(text: str) -> str:
    """Stable digest of a rendered ruleset, used for drift detection."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
