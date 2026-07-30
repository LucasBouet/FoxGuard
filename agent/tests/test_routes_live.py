"""Route reconciliation against a real kernel routing table.

The unit tests prove the reconciler makes the right decisions. This proves the
decisions do what they are supposed to once ``ip`` actually runs: that a route
lands on the tunnel interface, that ``ip route get`` then resolves through it,
that a route somebody else installed genuinely survives a reconciliation, and
that withdrawing ours leaves theirs behind.

Opt-in and privileged, because it creates a network interface::

    FOXGUARD_LIVE_ROUTES=1 pytest tests/test_routes_live.py

or ``make test-routes-live``. Needs CAP_NET_ADMIN (passwordless ``sudo`` is used
to create the dummy interface) and skips otherwise. Everything it creates lives
under a fixed name and is removed in teardown even when a test fails.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from foxguard_agent.routes import RouteApplier

pytestmark = pytest.mark.skipif(
    not os.environ.get("FOXGUARD_LIVE_ROUTES"),
    reason="live route test is opt-in and privileged: set FOXGUARD_LIVE_ROUTES=1",
)

IFACE = "fgtest0"
IFACE_CIDR = "10.99.0.1/24"
#: Documentation ranges (RFC 5737 / RFC 3849). Nothing real routes through them,
#: so a leftover entry cannot affect this machine.
ROUTE_A = "198.51.100.0/24"
ROUTE_B = "203.0.113.0/24"
ROUTE_V6 = "2001:db8:beef::/48"
FOREIGN = "192.0.2.0/24"


def sudo(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sudo", "-n", *args], capture_output=True, text=True, check=check
    )


@pytest.fixture(scope="module", autouse=True)
def dummy_interface():
    probe = sudo("ip", "link", "add", IFACE, "type", "dummy", check=False)
    if probe.returncode != 0:
        pytest.skip(f"cannot create a dummy interface: {probe.stderr.strip()}")
    try:
        sudo("ip", "addr", "add", IFACE_CIDR, "dev", IFACE)
        sudo("ip", "link", "set", IFACE, "up")
        yield IFACE
    finally:
        # Deleting the link takes every route through it with it, so this
        # cleans up whatever the tests left behind as well.
        sudo("ip", "link", "del", IFACE, check=False)


@pytest.fixture()
def applier(tmp_path, dummy_interface):
    app = RouteApplier(
        interface=dummy_interface,
        state_file=tmp_path / "routes.json",
        ip_path="ip",
    )
    # The reconciler runs `ip route add`, which needs privileges the test user
    # does not have; wrapping the runner in sudo is the smallest change that
    # exercises the real code path rather than a stub.
    inner = app._runner

    class SudoRunner:
        def run(self, argv, *, timeout: float = 30.0):
            argv = list(argv)
            mutating = "add" in argv or "del" in argv
            return inner.run(["sudo", "-n", *argv] if mutating else argv, timeout=timeout)

    app._runner = SudoRunner()
    yield app
    for cidr in (ROUTE_A, ROUTE_B, ROUTE_V6):
        family = "-6" if ":" in cidr else "-4"
        sudo("ip", family, "route", "del", cidr, "dev", IFACE, check=False)


def route_device(address: str) -> str | None:
    """Which interface the kernel would use for ``address``."""
    family = "-6" if ":" in address else "-4"
    result = subprocess.run(
        ["ip", family, "route", "get", address], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return None
    parts = result.stdout.split()
    return parts[parts.index("dev") + 1] if "dev" in parts else None


def route_exists(cidr: str) -> str:
    family = "-6" if ":" in cidr else "-4"
    return subprocess.run(
        ["ip", family, "route", "show", "exact", cidr],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()


# --------------------------------------------------------------------------- #
# a route that actually routes
# --------------------------------------------------------------------------- #


def test_an_installed_route_carries_traffic_to_the_tunnel(applier):
    """The whole point: `ip route get` has to land on the tunnel interface."""
    assert route_device("198.51.100.7") != IFACE

    added, _, problems = applier.apply([ROUTE_A])
    assert added == [ROUTE_A]
    assert problems == []
    assert route_device("198.51.100.7") == IFACE


def test_an_ipv6_route_is_installed_too(applier):
    added, _, problems = applier.apply([ROUTE_V6])
    assert added == [ROUTE_V6]
    assert problems == []
    assert route_device("2001:db8:beef::7") == IFACE


def test_withdrawing_a_route_removes_it_from_the_kernel(applier):
    applier.apply([ROUTE_A])
    assert route_exists(ROUTE_A)

    _, removed, _ = applier.apply([])
    assert removed == [ROUTE_A]
    assert route_exists(ROUTE_A) == ""
    assert route_device("198.51.100.7") != IFACE


def test_reconciliation_converges_on_the_desired_set(applier):
    applier.apply([ROUTE_A])
    added, removed, problems = applier.apply([ROUTE_B])
    assert added == [ROUTE_B]
    assert removed == [ROUTE_A]
    assert problems == []
    assert route_exists(ROUTE_A) == ""
    assert route_device("203.0.113.7") == IFACE


def test_a_second_pass_is_a_no_op(applier):
    """Level-triggered reconciliation must not churn the routing table."""
    applier.apply([ROUTE_A, ROUTE_B])
    added, removed, problems = applier.apply([ROUTE_A, ROUTE_B])
    assert (added, removed, problems) == ([], [], [])
    assert route_device("198.51.100.7") == IFACE


# --------------------------------------------------------------------------- #
# somebody else's routes
# --------------------------------------------------------------------------- #


def test_a_route_installed_by_hand_survives_a_reconciliation(applier):
    """The operator's static route to that network is not ours to replace."""
    sudo("ip", "route", "add", FOREIGN, "dev", IFACE, "metric", "50")
    try:
        added, _, problems = applier.apply([FOREIGN])
        assert added == []
        assert "Foxguard did not install" in problems[0]
        assert "metric 50" in route_exists(FOREIGN)
    finally:
        sudo("ip", "route", "del", FOREIGN, "dev", IFACE, check=False)


def test_withdrawing_ours_leaves_theirs_alone(applier):
    sudo("ip", "route", "add", FOREIGN, "dev", IFACE, "metric", "50")
    try:
        applier.apply([ROUTE_A])
        _, removed, _ = applier.apply([])
        assert removed == [ROUTE_A]
        assert route_exists(FOREIGN) != ""
    finally:
        sudo("ip", "route", "del", FOREIGN, "dev", IFACE, check=False)


# --------------------------------------------------------------------------- #
# the refusals, against the real address list
# --------------------------------------------------------------------------- #


def test_a_route_covering_this_boxs_own_address_is_refused(applier):
    """Read from the live `ip addr` output, not from a fixture."""
    primary = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "scope", "global"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    lan = next(
        line.split()[3] for line in primary.splitlines() if f" {IFACE} " not in line
    )

    added, _, problems = applier.apply([lan])
    assert added == []
    assert route_exists(lan.split("/")[0] + "/32") == ""
    assert "already reachable on" in problems[0]


def test_a_default_route_never_reaches_the_kernel(applier):
    before = route_device("1.1.1.1")
    added, _, problems = applier.apply(["0.0.0.0/0"])
    assert added == []
    assert "default route" in problems[0]
    assert route_device("1.1.1.1") == before
