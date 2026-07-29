"""Tunnel address allocation.

The allocation policy is deliberately boring and deterministic: lowest free
host address in the pool. Keeping the core as a pure function means the tricky
part (skipping network/broadcast/gateway, exhaustion, IPv6) is unit-tested
without a database.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Peer

__all__ = ["PoolExhaustedError", "next_free_address", "allocate_addresses"]

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class PoolExhaustedError(RuntimeError):
    """No address left in the pool."""


def _hosts(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> Iterable[IPAddress]:
    # ``hosts()`` already excludes network and broadcast for IPv4 prefixes
    # shorter than /31, and the network address for IPv6.
    return network.hosts()


def next_free_address(
    pool: str,
    used: Iterable[str],
    *,
    reserved: Iterable[str] = (),
) -> str:
    """Return the lowest address of ``pool`` that is neither used nor reserved.

    ``used``/``reserved`` may contain addresses outside the pool; they are
    ignored. Raises :class:`PoolExhaustedError` when nothing is left.
    """
    network = ipaddress.ip_network(pool, strict=False)
    taken: set[IPAddress] = set()
    for value in (*used, *reserved):
        if not value:
            continue
        try:
            address = ipaddress.ip_address(str(value).split("/", 1)[0])
        except ValueError:
            continue
        if address.version == network.version:
            taken.add(address)

    for candidate in _hosts(network):
        if candidate not in taken:
            return str(candidate)
    raise PoolExhaustedError(f"no free address left in {pool}")


def _used_addresses(session: Session, version: int) -> list[str]:
    column = Peer.tunnel_ip if version == 4 else Peer.tunnel_ip6
    rows = session.execute(select(column).where(column.is_not(None))).scalars().all()
    return [str(row) for row in rows]


def allocate_addresses(
    session: Session,
    *,
    pool_v4: str | None,
    pool_v6: str | None,
    reserved: Iterable[str] = (),
) -> tuple[str | None, str | None]:
    """Allocate one address per configured pool, avoiding everything in use.

    Concurrency note: the unique constraints on ``peers.tunnel_ip`` /
    ``peers.tunnel_ip6`` are the real guarantee. Two racing allocations make one
    of the inserts fail, which the caller retries -- rather than us taking a
    table lock on every peer creation.
    """
    reserved = list(reserved)
    ipv4 = (
        next_free_address(pool_v4, _used_addresses(session, 4), reserved=reserved)
        if pool_v4
        else None
    )
    ipv6 = (
        next_free_address(pool_v6, _used_addresses(session, 6), reserved=reserved)
        if pool_v6
        else None
    )
    return ipv4, ipv6
