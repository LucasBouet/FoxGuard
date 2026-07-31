"""The half of a client configuration a server is allowed to know.

Foxguard stores no private keys. That is not a slogan here -- it is the reason
this module returns *structured data* and never a finished ``.conf``: the file
is assembled in the browser, where the private key is, and the private key gets
there by being generated there. Nothing in this module, in the API, or in the
audit log ever sees it.

What is left over once the secret is removed is still most of the work: which
addresses the device holds, which resolver it should ask, what to dial, and --
the part people get wrong by hand -- which networks belong in ``AllowedIPs``.

``AllowedIPs`` is doing two jobs at once, and that is why it has four modes
rather than a checkbox. On the client it is a *routing table*: every prefix
listed is pulled into the tunnel and stops being reachable locally. So a device
that carries a network for a zone must never receive that network back in its
own ``AllowedIPs`` -- it would route its own LAN into the tunnel and lose the
very thing it was carrying. :func:`compute_allowed_ips` enforces that in every
mode, and reports what it took out so the dashboard can say why.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "AllowedIpsMode",
    "ClientProfile",
    "compute_allowed_ips",
    "join_endpoint",
]


class AllowedIpsMode(str, Enum):
    """How much of the world the device should route into the tunnel."""

    #: The WireGuard pools only. Reaches the gateway and other peers, nothing else.
    TUNNEL = "tunnel"
    #: Pools plus the routes of the device's own zone -- "its zone comes with it".
    ZONE = "zone"
    #: Pools plus every routed network in the fleet. The gateway's ACLs still
    #: decide what actually passes; this only decides what the device offers to
    #: send. The default, because the usual complaint is "the rule is there but
    #: nothing works" and this is that cause removed.
    ROUTED = "routed"
    #: Full tunnel: everything, including internet. Needs a group with
    #: ``internet_exit`` and a WAN interface, or the device has no internet at all.
    FULL = "full"


def _network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(cidr, strict=False)


def _sort_key(cidr: str) -> tuple[int, int, int]:
    net = _network(cidr)
    return (net.version, int(net.network_address), net.prefixlen)


def compute_allowed_ips(
    mode: AllowedIpsMode,
    *,
    pools: tuple[str, ...],
    own_zone_routes: tuple[str, ...],
    fleet_routes: tuple[str, ...],
    carried_by_peer: tuple[str, ...],
    extra: tuple[str, ...] = (),
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return ``(allowed_ips, excluded)`` for one device.

    ``excluded`` is the networks this peer carries and therefore must not route
    into the tunnel. It is returned rather than silently dropped because the
    absence of a network from a config is exactly the kind of thing an operator
    spends an evening on.

    Invalid CIDRs are refused loudly: an unparseable prefix reaching a client
    config makes ``wg-quick`` fail at the worst possible moment, on a device
    that is now the far side of a tunnel that does not exist.
    """
    carried = {_network(cidr) for cidr in carried_by_peer}

    chosen: list[str] = []
    if mode is AllowedIpsMode.FULL:
        chosen.append("0.0.0.0/0")
        if any(_network(pool).version == 6 for pool in pools):
            chosen.append("::/0")
    else:
        chosen.extend(pools)
        if mode is AllowedIpsMode.ZONE:
            chosen.extend(own_zone_routes)
        elif mode is AllowedIpsMode.ROUTED:
            chosen.extend(fleet_routes)
    chosen.extend(extra)

    # A default route swallows the carried network too, but taking 0.0.0.0/0
    # away would silently turn full tunnel into no tunnel. The dashboard warns
    # about the combination instead; here the exclusion is only ever a prefix
    # the operator can lose without losing the mode they asked for.
    keep: dict[str, None] = {}
    excluded: dict[str, None] = {}
    for cidr in chosen:
        net = _network(cidr)
        if net in carried and net.prefixlen > 0:
            excluded[str(net)] = None
            continue
        keep[str(net)] = None

    return (
        tuple(sorted(keep, key=_sort_key)),
        tuple(sorted(excluded, key=_sort_key)),
    )


def join_endpoint(host: str, default_port: int) -> str:
    """``host`` as WireGuard wants it, adding the port only when it is missing.

    Deployments configure this either way -- the installer's ``--endpoint`` takes
    ``HOST[:PORT]`` -- and an IPv6 literal has colons of its own, so "contains a
    colon" is not the test. A bracketed literal is only ported if the bracket is
    the last character.
    """
    text = host.strip()
    if text.startswith("["):
        return text if text.rfind("]") < len(text) - 1 else f"{text}:{default_port}"
    if text.count(":") == 1:
        return text
    if text.count(":") > 1:
        # A bare IPv6 literal. Brackets are mandatory once a port is appended.
        return f"[{text}]:{default_port}"
    return f"{text}:{default_port}"


@dataclass(frozen=True, slots=True)
class ClientProfile:
    """Everything the browser needs to write a config, minus the secret."""

    peer_id: str
    peer_name: str
    peer_state: str
    #: Fully qualified name inside the internal zone, when DNS is on.
    fqdn: str | None

    # [Interface]
    addresses: tuple[str, ...]
    dns: tuple[str, ...]
    mtu: int | None

    # [Peer]
    server_public_key: str | None
    endpoint: str | None
    allowed_ips: tuple[str, ...]
    persistent_keepalive: int

    allowed_ips_mode: AllowedIpsMode
    #: Networks this peer carries, removed from its own AllowedIPs.
    excluded_routes: tuple[str, ...] = ()
    #: Things the operator should read before handing the file over. Not errors:
    #: a config for a quarantined device is still the right config.
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def complete(self) -> bool:
        """Can this profile become a config that actually connects?

        The dashboard refuses to offer a download when this is false. Handing
        someone a file with a missing ``PublicKey`` is worse than handing them
        nothing: it fails at connect time, on their machine, with an error that
        does not name the gateway setting that is missing.
        """
        return bool(self.server_public_key and self.endpoint and self.addresses)
