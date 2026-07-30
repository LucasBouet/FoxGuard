"""Pure data model consumed by the DNS renderer.

Same boundary as :mod:`foxguard.nftables.model`, for the same reason: everything
that decides what a name resolves to is described here as frozen data, so it can
be unit-tested without a database, without root, and without ``dnsmasq``
installed.

Two properties of this model exist purely to keep peer-controlled text away from
the resolver's configuration language:

* **Peer-derived names only ever reach the hosts file.** A hosts file's grammar
  is ``address name...`` per line and cannot express a directive, so a peer
  called ``server=8.8.8.8`` is at worst a malformed host entry -- and
  :func:`validate_spec` rejects it long before that.
* **Everything that lands in ``dnsmasq.conf`` is validated against a strict
  grammar**, because that file *can* express directives. CNAMEs come from the
  admin API and upstreams from the environment; neither is trusted on that
  basis alone.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "CnameEntry",
    "DnsSpec",
    "HostEntry",
    "RecordKind",
    "ResolverMode",
    "LABEL_RE",
    "NAME_RE",
]

#: A single DNS label, RFC 1123: letters, digits and hyphens, never leading or
#: trailing a hyphen, 63 characters at most. Underscores are excluded on
#: purpose -- they are legal in some record types but not in host names, and
#: allowing them here would let a peer name produce something a resolver may or
#: may not accept depending on its strictness.
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
#: A fully qualified name: labels joined by dots, 253 characters at most.
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


class RecordKind(str, Enum):
    """Record types an administrator can author by hand.

    Deliberately short. Foxguard is a name service for a WireGuard fleet, not a
    general DNS hosting product: MX, TXT and SRV would all have to be forwarded
    to a real authoritative server anyway, and every one of them is another
    string reaching the resolver's configuration.
    """

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"


class ResolverMode(str, Enum):
    """What the resolver does with a query it is not authoritative for.

    ``FORWARD`` (default) — send it upstream. This is the only mode in which
    pointing a client's whole resolver at the gateway works, which is what
    ``DNS = <gateway>`` in a WireGuard config actually does, so it is the
    default despite being the more exposed of the two.

    ``SPLIT`` — answer for the zone and ``REFUSED`` for everything else
    (measured: dnsmasq with ``no-resolv`` and no ``server=`` returns rcode 5).
    Nothing about the fleet's browsing reaches the gateway. The cost is that
    the client must be configured to send *only* in-zone queries here; a client
    that sends everything gets REFUSED for the internet and falls through to its
    next resolver only if it has one.
    """

    FORWARD = "forward"
    SPLIT = "split"


@dataclass(frozen=True, slots=True)
class HostEntry:
    """One address and the fully qualified names that resolve to it.

    ``names`` is ordered and the first entry is canonical: dnsmasq answers the
    reverse lookup for ``address`` with it. Ordering is therefore part of the
    data, not a rendering detail.
    """

    address: str
    names: tuple[str, ...]
    comment: str | None = None

    @property
    def version(self) -> int:
        return ipaddress.ip_address(self.address).version


@dataclass(frozen=True, slots=True)
class CnameEntry:
    """An alias for a name the resolver already knows.

    dnsmasq resolves ``cname=`` targets against its own records, so the target
    must be one of the spec's host names. :func:`validate_spec` enforces that
    rather than leaving a silently dead alias in the zone.
    """

    alias: str
    target: str
    comment: str | None = None


@dataclass(frozen=True, slots=True)
class DnsSpec:
    """Everything the resolver on the gateway needs to know.

    ``hosts_path`` is part of the spec rather than the renderer's business
    because it appears *inside* the generated configuration (``addn-hosts=``),
    so two deployments with different paths must produce different bytes.
    """

    zone: str = "fox.internal"
    #: Addresses to listen on. Tunnel addresses only -- binding the WAN would
    #: publish an open resolver, which the healthcheck also tests for.
    listen_addresses: tuple[str, ...] = ()
    port: int = 53
    hosts_path: str = "/etc/foxguard/dns/hosts"

    hosts: tuple[HostEntry, ...] = ()
    cnames: tuple[CnameEntry, ...] = ()

    mode: ResolverMode = ResolverMode.FORWARD
    #: Upstream resolvers, ``address`` or ``address#port``. Only consulted in
    #: FORWARD mode; empty then means "use whatever /etc/resolv.conf says",
    #: which is expressed by *not* emitting ``no-resolv``.
    upstreams: tuple[str, ...] = ()

    cache_size: int = 1000
    #: Answer PTR for these prefixes locally instead of asking upstream. Built
    #: from the WireGuard pools: nothing outside this gateway can answer them.
    reverse_pools: tuple[str, ...] = ()
    #: Refuse upstream answers that point into private space. Off by default:
    #: a legitimate split-horizon upstream returns exactly such answers, and
    #: breaking those silently is worse than the rebinding it prevents.
    stop_dns_rebind: bool = False
    log_queries: bool = False
    #: Raw dnsmasq options appended verbatim. Operator-supplied (environment),
    #: never peer-supplied, and still validated to a single line each.
    extra_options: tuple[str, ...] = field(default_factory=tuple)

    @property
    def names(self) -> frozenset[str]:
        """Every name the resolver answers for, aliases included."""
        return frozenset(
            [name for host in self.hosts for name in host.names]
            + [cname.alias for cname in self.cnames]
        )
