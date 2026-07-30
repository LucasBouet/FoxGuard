"""Deterministic dnsmasq artefact generator.

Design rules, each covered by a test in ``tests/test_dns_generator.py``:

1.  **Two artefacts, one digest.** A hosts file carries every address, a
    configuration file carries everything else. They are rendered together and
    hashed together, so the agent cannot apply half a change.
2.  **Byte-stable output.** Same database state -> same bytes, exactly as for
    the nftables ruleset. Names and addresses are sorted, nothing is
    timestamped.
3.  **Names are fully qualified, never bare.** ``expand-hosts`` is deliberately
    *not* emitted. A bare label in the hosts file makes the resolver
    authoritative for that label globally, so a peer named ``wpad`` or ``mail``
    would answer for a name its clients expect to resolve elsewhere. Short
    names are the search domain's job, which is why the client config carries
    ``DNS = <gateway>, <zone>``.
4.  **Our own instance, our own files.** The generated configuration never
    includes ``conf-dir``, so the host's ``/etc/dnsmasq.d`` cannot alter what
    Foxguard serves, and Foxguard cannot alter what the host's own resolver
    serves. Same principle as owning a single nftables table.
5.  **No injection.** Anything reaching the configuration file is validated
    against a strict grammar first. Peer-derived names reach only the hosts
    file, whose grammar cannot express a directive at all.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterable, Iterator

from .model import NAME_RE, CnameEntry, DnsSpec, HostEntry, ResolverMode

__all__ = [
    "DnsValidationError",
    "dns_digest",
    "render_conf",
    "render_hosts",
    "reverse_zone",
    "validate_spec",
]

#: An upstream: bare address, or ``address#port`` as dnsmasq spells it.
_UPSTREAM_RE = re.compile(r"^(?P<addr>[0-9a-fA-F:.]+)(#(?P<port>\d{1,5}))?$")
#: A raw dnsmasq option. Single line, option name then an optional value.
_OPTION_RE = re.compile(r"^[a-z0-9-]+(=[^\r\n]*)?$")
_MAX_NAME = 253

_HOSTS_BANNER = (
    "# Foxguard generated hosts file -- DO NOT EDIT BY HAND.\n"
    "#\n"
    "# Written by foxguard-agent on every reconciliation; the source of truth is\n"
    "# the control plane's database, so an edit here survives until the next poll.\n"
    "# The first name on a line is canonical: it is what reverse lookups return.\n"
    "#\n"
)

_CONF_BANNER = (
    "# Foxguard generated dnsmasq configuration -- DO NOT EDIT BY HAND.\n"
    "#\n"
    "# Written by foxguard-agent on every reconciliation; an edit here survives\n"
    "# until the next poll.\n"
    "#\n"
    "# This file configures Foxguard's *own* dnsmasq instance, started by\n"
    "# foxguard-dns.service. It deliberately does not read /etc/dnsmasq.d, so the\n"
    "# host's resolver and this one cannot interfere with each other.\n"
    "#\n"
)


class DnsValidationError(ValueError):
    """Raised when a spec cannot be turned into a safe resolver configuration.

    Carries every problem found rather than the first, so an import of fifty
    records reports all fifty in one response.
    """

    def __init__(self, errors: Iterable[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors))


# --------------------------------------------------------------------------- #
# reverse zones
# --------------------------------------------------------------------------- #


def reverse_zone(cidr: str) -> str | None:
    """Reverse-DNS zone covering ``cidr``, or ``None`` when there is no useful one.

    A prefix that is not aligned to a label boundary is rounded *outwards* to
    the enclosing zone that is: ``10.13.37.0/25`` yields
    ``37.13.10.in-addr.arpa``. Claiming slightly more of the reverse tree than
    we allocate from is the right trade -- the surplus resolves to NXDOMAIN
    here instead of leaking a query about our internal addressing upstream.
    RFC 2317 delegation is the alternative and it needs a cooperating parent
    zone, which a private range does not have.

    ``/0`` returns ``None``: claiming the entire reverse tree would answer for
    every address on the internet.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    if network.prefixlen == 0:
        return None
    if network.version == 4:
        octets = network.prefixlen // 8
        if octets == 0:
            return None
        parts = str(network.network_address).split(".")[:octets]
        return ".".join(reversed(parts)) + ".in-addr.arpa"
    nibbles = network.prefixlen // 4
    if nibbles == 0:
        return None
    expanded = network.network_address.exploded.replace(":", "")
    return ".".join(reversed(expanded[:nibbles])) + ".ip6.arpa"


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #


def _check_name(value: str, label: str, errors: list[str]) -> bool:
    if not value:
        errors.append(f"{label}: empty name")
        return False
    if len(value) > _MAX_NAME:
        errors.append(f"{label}: name {value!r} exceeds {_MAX_NAME} characters")
        return False
    if not NAME_RE.match(value):
        errors.append(
            f"{label}: {value!r} is not a valid DNS name "
            "(lowercase letters, digits and hyphens, dot-separated)"
        )
        return False
    return True


def _check_in_zone(value: str, zone: str, label: str, errors: list[str]) -> None:
    if value != zone and not value.endswith(f".{zone}"):
        errors.append(f"{label}: {value!r} is outside the zone {zone!r}")


def validate_spec(spec: DnsSpec) -> None:
    """Raise :class:`DnsValidationError` if ``spec`` is unsafe or malformed."""
    errors: list[str] = []

    _check_name(spec.zone, "zone", errors)

    if not (1 <= spec.port <= 65535):
        errors.append(f"port {spec.port} out of range 1-65535")
    if spec.cache_size < 0:
        errors.append(f"cache_size {spec.cache_size} is negative")

    if not spec.hosts_path.startswith("/"):
        errors.append(f"hosts_path {spec.hosts_path!r} must be absolute")
    if any(ch in spec.hosts_path for ch in "\r\n"):
        # The configuration file is line-based, so a newline here is a directive.
        errors.append("hosts_path must not contain a line break")

    for address in spec.listen_addresses:
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            errors.append(f"listen_addresses: {address!r} is not an IP address ({exc})")

    for pool in spec.reverse_pools:
        try:
            ipaddress.ip_network(pool, strict=False)
        except ValueError as exc:
            errors.append(f"reverse_pools: {pool!r} is not a network ({exc})")

    for upstream in spec.upstreams:
        match = _UPSTREAM_RE.match(upstream)
        if not match:
            errors.append(
                f"upstreams: {upstream!r} is not an address or address#port"
            )
            continue
        try:
            ipaddress.ip_address(match.group("addr"))
        except ValueError as exc:
            errors.append(f"upstreams: {upstream!r} has a bad address ({exc})")
        port = match.group("port")
        if port is not None and not (1 <= int(port) <= 65535):
            errors.append(f"upstreams: {upstream!r} has a port outside 1-65535")

    for option in spec.extra_options:
        if not _OPTION_RE.match(option):
            errors.append(
                f"extra_options: {option!r} is not a single dnsmasq option "
                "(name, or name=value, on one line)"
            )

    # Keyed on (name, family): one name legitimately has both an A and an AAAA
    # record, which is the normal shape of a dual-stack peer. Two *different*
    # addresses of the same family behind one name is the collision that matters.
    seen_names: dict[tuple[str, int], str] = {}
    known_names: set[str] = set()
    seen_addresses: set[str] = set()
    for host in spec.hosts:
        label = f"host {host.address!r}"
        try:
            parsed = ipaddress.ip_address(host.address)
        except ValueError as exc:
            errors.append(f"{label}: not an IP address ({exc})")
            continue
        if str(parsed) in seen_addresses:
            # The hosts file tolerates it; reverse lookups would not. Which name
            # wins the PTR would depend on file order, which is not a decision
            # anyone made on purpose.
            errors.append(f"{label}: duplicate address")
        seen_addresses.add(str(parsed))

        if not host.names:
            errors.append(f"{label}: no names")
        for name in host.names:
            if not _check_name(name, label, errors):
                continue
            _check_in_zone(name, spec.zone, label, errors)
            key = (name, parsed.version)
            owner = seen_names.get(key)
            if owner is not None and owner != host.address:
                errors.append(
                    f"{label}: name {name} already resolves to {owner} "
                    "(two devices cannot share a name)"
                )
            seen_names[key] = host.address
            known_names.add(name)

    seen_aliases: set[str] = set()
    for cname in spec.cnames:
        label = f"cname {cname.alias!r}"
        if _check_name(cname.alias, label, errors):
            _check_in_zone(cname.alias, spec.zone, label, errors)
            if cname.alias in known_names:
                errors.append(f"{label}: shadows the host name {cname.alias}")
            if cname.alias in seen_aliases:
                errors.append(f"{label}: duplicate alias")
            seen_aliases.add(cname.alias)
        if _check_name(cname.target, f"{label} target", errors):
            if cname.target == cname.alias:
                errors.append(f"{label}: points at itself")
            elif cname.target not in known_names:
                # dnsmasq resolves cname targets against its own records, so an
                # unknown target is a silently dead alias rather than an error
                # anyone would notice.
                errors.append(
                    f"{label}: target {cname.target} is not a name this resolver knows"
                )

    if errors:
        raise DnsValidationError(errors)


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #


def _sorted_hosts(hosts: Iterable[HostEntry]) -> list[HostEntry]:
    return sorted(hosts, key=lambda h: (h.version, ipaddress.ip_address(h.address)))


def _sorted_cnames(cnames: Iterable[CnameEntry]) -> list[CnameEntry]:
    return sorted(cnames, key=lambda c: c.alias)


def _comment(value: str | None) -> str:
    if not value:
        return ""
    # The hosts file treats everything after '#' as a comment, so the only
    # character that matters here is the line break.
    cleaned = " ".join(value.split())
    return f"\t# {cleaned[:80]}" if cleaned else ""


def render_hosts(spec: DnsSpec) -> str:
    """Render the hosts-format artefact.

    Note for whoever wires this up: this file is re-read by dnsmasq *after* it
    has dropped privileges, so it must be readable by the unprivileged user the
    daemon runs as -- 0644, on a path that user can traverse. Every other file
    Foxguard writes is 0600, and copying that habit here produces a resolver
    that works until its first reload and then quietly serves nothing.
    """
    validate_spec(spec)
    lines = [_HOSTS_BANNER.rstrip("\n")]
    for host in _sorted_hosts(spec.hosts):
        lines.append(f"{host.address}\t{' '.join(host.names)}{_comment(host.comment)}")
    return "\n".join(lines).rstrip("\n") + "\n"


def _render_conf_body(spec: DnsSpec) -> Iterator[str]:
    yield f"port={spec.port}"

    yield ""
    yield "# Answer only where Foxguard is reachable. Binding every interface"
    yield "# would publish an open resolver on the WAN."
    for address in spec.listen_addresses:
        yield f"listen-address={address}"
    if spec.listen_addresses:
        # Without this dnsmasq binds the wildcard address and merely filters by
        # destination, which still holds :53 against anything else on the box.
        yield "bind-interfaces"

    yield ""
    yield "# Foxguard's records only: never /etc/hosts, never /etc/dnsmasq.d."
    yield "no-hosts"
    yield f"addn-hosts={spec.hosts_path}"
    yield "no-poll"

    yield ""
    yield f"domain={spec.zone}"
    yield "# Authoritative for the zone: these names are never asked upstream."
    yield f"local=/{spec.zone}/"
    for pool in spec.reverse_pools:
        zone = reverse_zone(pool)
        if zone:
            yield f"local=/{zone}/"

    yield ""
    if spec.mode is ResolverMode.SPLIT:
        yield "# Split DNS: no upstream at all. Anything outside the zone is answered"
        yield "# REFUSED, which a client with a second resolver falls through on."
        yield "no-resolv"
    else:
        yield "# Forwarding resolver: the fleet's queries leave through these."
        if spec.upstreams:
            yield "no-resolv"
            for upstream in spec.upstreams:
                yield f"server={upstream}"
        else:
            yield "# (no upstream configured: /etc/resolv.conf on the gateway is used)"
        yield "domain-needed"
        yield "bogus-priv"
        if spec.stop_dns_rebind:
            yield "stop-dns-rebind"
            yield f"rebind-domain-ok=/{spec.zone}/"

    cnames = _sorted_cnames(spec.cnames)
    if cnames:
        yield ""
        yield "# Aliases. dnsmasq resolves these against its own records."
        for cname in cnames:
            yield f"cname={cname.alias},{cname.target}"

    yield ""
    yield f"cache-size={spec.cache_size}"
    if spec.log_queries:
        yield "log-queries"

    if spec.extra_options:
        yield ""
        yield "# FOXGUARD_DNS_EXTRA_OPTIONS, verbatim."
        yield from spec.extra_options


def render_conf(spec: DnsSpec) -> str:
    """Render the dnsmasq configuration artefact."""
    validate_spec(spec)
    body = "\n".join(_render_conf_body(spec)).strip("\n")
    return _CONF_BANNER + body + "\n"


def dns_digest(hosts: str, conf: str) -> str:
    """Stable digest of both artefacts together.

    One digest rather than two because they are only meaningful as a pair: a
    hosts file naming a device the configuration does not serve, or the reverse,
    is not a state the agent should ever be able to reach.
    """
    return hashlib.sha256(
        b"hosts\0" + hosts.encode("utf-8") + b"\0conf\0" + conf.encode("utf-8")
    ).hexdigest()
