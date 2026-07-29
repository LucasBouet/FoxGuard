"""Tests for tunnel address allocation."""

from __future__ import annotations

import pytest

from foxguard.services.ipam import PoolExhaustedError, next_free_address


def test_allocates_the_lowest_free_host():
    assert next_free_address("10.88.0.0/24", []) == "10.88.0.1"


def test_skips_used_addresses():
    used = ["10.88.0.1", "10.88.0.2", "10.88.0.4"]
    assert next_free_address("10.88.0.0/24", used) == "10.88.0.3"


def test_honours_reserved_addresses():
    """The gateway's own tunnel address must never be handed to a peer."""
    assert next_free_address("10.88.0.0/24", [], reserved=["10.88.0.1"]) == "10.88.0.2"


def test_never_returns_the_network_or_broadcast_address():
    allocated = [next_free_address("10.88.0.0/29", [f"10.88.0.{i}" for i in range(1, n)])
                 for n in range(1, 7)]
    assert "10.88.0.0" not in allocated
    assert "10.88.0.7" not in allocated


def test_addresses_of_the_other_family_are_ignored():
    assert next_free_address("10.88.0.0/24", ["fd00::1", "10.88.0.1"]) == "10.88.0.2"


def test_prefixed_values_are_accepted():
    """``peers.tunnel_ip`` comes back from PostgreSQL INET as a bare address,
    but an AllowedIPs-style ``10.88.0.1/32`` must not confuse the allocator."""
    assert next_free_address("10.88.0.0/24", ["10.88.0.1/32"]) == "10.88.0.2"


def test_malformed_values_do_not_break_allocation():
    assert next_free_address("10.88.0.0/24", ["", "not-an-ip", None]) == "10.88.0.1"


def test_ipv6_allocation():
    assert next_free_address("fd00:88::/64", []) == "fd00:88::1"


def test_exhausted_pool_raises():
    used = [f"10.88.0.{i}" for i in range(1, 7)]
    with pytest.raises(PoolExhaustedError):
        next_free_address("10.88.0.0/29", used)


def test_allocation_is_deterministic():
    used = ["10.88.0.1", "10.88.0.3"]
    assert next_free_address("10.88.0.0/24", used) == next_free_address(
        "10.88.0.0/24", list(reversed(used))
    )
