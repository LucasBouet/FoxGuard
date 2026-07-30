"""Tests for the kernel route reconciler.

This is the one component that can cut the operator's own access to the
gateway, so the tests are written as refusals first and reconciliation second.
``test_routes_live.py`` repeats the important ones against a real kernel.
"""

from __future__ import annotations

import json

import pytest
from foxguard.nftables.applier import CommandResult

from foxguard_agent.routes import RouteApplier, RouteError, RouteRefused

#: What `ip -json addr show` looks like on a gateway with a LAN and a tunnel.
ADDR_JSON = json.dumps(
    [
        {"ifname": "lo", "addr_info": [{"local": "127.0.0.1"}]},
        {"ifname": "eth0", "addr_info": [{"local": "192.168.1.10"}]},
        {"ifname": "wg0", "addr_info": [{"local": "10.88.0.1"}]},
    ]
)


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.addr_json = ADDR_JSON
        self.addr_ok = True
        #: Prefixes the kernel already has a route for, and what it looks like.
        self.existing: dict[str, str] = {}
        self.add_ok = True

    def run(self, argv, *, timeout: float = 30.0) -> CommandResult:
        argv = list(argv)
        self.calls.append(argv)
        if "addr" in argv:
            return (
                CommandResult(0, self.addr_json, "")
                if self.addr_ok
                else CommandResult(1, "", "netlink is unavailable")
            )
        if "show" in argv:
            return CommandResult(0, self.existing.get(argv[-1], ""), "")
        if "add" in argv:
            return (
                CommandResult(0, "", "")
                if self.add_ok
                else CommandResult(2, "", "RTNETLINK answers: File exists")
            )
        return CommandResult(0, "", "")

    def commands(self, verb: str) -> list[list[str]]:
        return [c for c in self.calls if verb in c]


@pytest.fixture()
def applier(tmp_path):
    runner = FakeRunner()
    return (
        RouteApplier(
            interface="wg0",
            state_file=tmp_path / "routes.json",
            runner=runner,
            protected=("10.0.0.5",),
        ),
        runner,
        tmp_path / "routes.json",
    )


# --------------------------------------------------------------------------- #
# refusals
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("default_route", ["0.0.0.0/0", "::/0"])
def test_a_default_route_is_refused(applier, default_route):
    """It would replace the gateway's own and cut every remote session."""
    app, runner, _ = applier
    added, _, problems = app.apply([default_route])
    assert added == []
    assert runner.commands("add") == []
    assert "default route" in problems[0]


def test_a_route_covering_a_local_address_is_refused(applier):
    """192.168.1.0/24 on a box whose LAN address is 192.168.1.10 kills SSH."""
    app, runner, _ = applier
    added, _, problems = app.apply(["192.168.1.0/24"])
    assert added == []
    assert runner.commands("add") == []
    assert "192.168.1.10" in problems[0]


def test_a_route_covering_the_control_plane_is_refused(applier):
    """Otherwise the agent loses the API that could tell it to undo this."""
    app, _, _ = applier
    added, _, problems = app.apply(["10.0.0.0/8"])
    assert added == []
    assert "10.0.0.5" in problems[0]


def test_the_tunnel_interfaces_own_address_does_not_block_routes(applier):
    """wg0's prefix is exactly what routes are meant to point at."""
    app, _runner, _ = applier
    added, _, problems = app.apply(["10.88.0.0/24"])
    assert added == ["10.88.0.0/24"]
    assert problems == []


def test_an_unreadable_address_list_stops_everything(applier):
    """Not knowing what this box answers on is when a route is most dangerous."""
    app, runner, _ = applier
    runner.addr_ok = False
    with pytest.raises(RouteRefused):
        app.apply(["192.168.10.0/24"])
    assert runner.commands("add") == []


def test_a_malformed_cidr_is_refused_not_passed_to_ip(applier):
    app, runner, _ = applier
    added, _, problems = app.apply(["192.168.1.0/33"])
    assert added == []
    assert runner.commands("add") == []
    assert "not a network" in problems[0]


def test_one_refused_route_does_not_stop_the_others(applier):
    app, _, _ = applier
    added, _, problems = app.apply(["0.0.0.0/0", "192.168.10.0/24"])
    assert added == ["192.168.10.0/24"]
    assert len(problems) == 1


# --------------------------------------------------------------------------- #
# never touching someone else's route
# --------------------------------------------------------------------------- #


def test_an_existing_foreign_route_is_left_alone(applier):
    """It might be the operator's own static route to that very network."""
    app, runner, _ = applier
    runner.existing["192.168.10.0/24"] = "192.168.10.0/24 via 192.168.1.1 dev eth0"
    added, _, problems = app.apply(["192.168.10.0/24"])
    assert added == []
    assert runner.commands("add") == []
    assert "Foxguard did not install" in problems[0]


def test_a_foreign_route_is_not_recorded_as_ours(applier):
    """Recording it would make the next reconciliation delete it."""
    app, runner, state = applier
    runner.existing["192.168.10.0/24"] = "192.168.10.0/24 dev eth0"
    app.apply(["192.168.10.0/24"])
    assert not state.exists() or json.loads(state.read_text()) == []


# --------------------------------------------------------------------------- #
# reconciliation
# --------------------------------------------------------------------------- #


def test_a_route_is_installed_on_the_tunnel_interface(applier):
    app, runner, _ = applier
    added, removed, problems = app.apply(["192.168.10.0/24"])
    assert added == ["192.168.10.0/24"]
    assert removed == [] and problems == []
    assert runner.commands("add")[0] == [
        "ip", "-4", "route", "add", "192.168.10.0/24", "dev", "wg0"
    ]


def test_an_ipv6_route_uses_the_right_family_flag(applier):
    app, runner, _ = applier
    app.apply(["fd00:10::/64"])
    assert runner.commands("add")[0][:2] == ["ip", "-6"]


def test_an_unchanged_set_of_routes_touches_nothing(applier):
    app, runner, _ = applier
    app.apply(["192.168.10.0/24"])
    runner.calls.clear()
    added, removed, _ = app.apply(["192.168.10.0/24"])
    assert (added, removed) == ([], [])
    assert runner.commands("add") == [] and runner.commands("del") == []


def test_a_withdrawn_route_is_removed(applier):
    app, runner, _ = applier
    app.apply(["192.168.10.0/24", "192.168.20.0/24"])
    runner.calls.clear()
    _added, removed, _ = app.apply(["192.168.10.0/24"])
    assert removed == ["192.168.20.0/24"]
    assert runner.commands("del")[0] == [
        "ip", "-4", "route", "del", "192.168.20.0/24", "dev", "wg0"
    ]


def test_removing_everything_removes_only_what_we_installed(applier):
    app, runner, _ = applier
    app.apply(["192.168.10.0/24"])
    runner.calls.clear()
    _, removed, _ = app.apply([])
    assert removed == ["192.168.10.0/24"]
    assert len(runner.commands("del")) == 1


def test_a_lost_state_file_removes_nothing(applier):
    """The only safe guess about routes we have no record of is to leave them."""
    app, runner, state = applier
    app.apply(["192.168.10.0/24"])
    state.unlink()
    runner.calls.clear()
    _, removed, _ = app.apply([])
    assert removed == []
    assert runner.commands("del") == []


def test_a_corrupt_state_file_is_treated_as_empty(applier):
    app, _runner, state = applier
    state.write_text("{ not json")
    _, removed, _ = app.apply([])
    assert removed == []


def test_the_state_file_records_what_is_installed(applier):
    app, _, state = applier
    app.apply(["192.168.20.0/24", "192.168.10.0/24"])
    assert json.loads(state.read_text()) == ["192.168.10.0/24", "192.168.20.0/24"]


def test_a_route_that_will_not_install_is_reported_not_recorded(applier):
    app, runner, state = applier
    runner.add_ok = False
    added, _, problems = app.apply(["192.168.10.0/24"])
    assert added == []
    assert "RTNETLINK" in problems[0]
    assert not state.exists() or json.loads(state.read_text()) == []


def test_cidrs_are_normalised_before_comparison(applier):
    """192.168.10.7/24 and 192.168.10.0/24 are the same route."""
    app, runner, _ = applier
    app.apply(["192.168.10.0/24"])
    runner.calls.clear()
    added, removed, _ = app.apply(["192.168.10.7/24"])
    assert (added, removed) == ([], [])


# --------------------------------------------------------------------------- #
# dry run
# --------------------------------------------------------------------------- #


def test_plan_changes_nothing(applier):
    app, runner, state = applier
    to_add, to_remove, refused = app.plan(["192.168.10.0/24", "0.0.0.0/0"])
    assert to_add == ["192.168.10.0/24"]
    assert to_remove == []
    assert len(refused) == 1
    assert runner.commands("add") == [] and runner.commands("del") == []
    assert not state.exists()


def test_plan_reports_what_apply_would_remove(applier):
    app, _, _ = applier
    app.apply(["192.168.10.0/24"])
    to_add, to_remove, _ = app.plan([])
    assert (to_add, to_remove) == ([], ["192.168.10.0/24"])


def test_a_delete_that_fails_still_forgets_the_route(applier):
    """Already gone counts as removed, or the agent retries it forever."""
    app, _runner, state = applier
    app.apply(["192.168.10.0/24"])

    class FailingDelete(FakeRunner):
        def run(self, argv, *, timeout: float = 30.0) -> CommandResult:
            if "del" in list(argv):
                return CommandResult(2, "", "RTNETLINK answers: No such process")
            return super().run(argv, timeout=timeout)

    app._runner = FailingDelete()  # deliberately reaching in: exercising the failure path
    _, removed, _ = app.apply([])
    assert removed == ["192.168.10.0/24"]
    assert json.loads(state.read_text()) == []


def test_reading_addresses_reports_a_bad_command(applier):
    from foxguard_agent.routes import local_addresses

    _app, runner, _ = applier
    runner.addr_json = "not json"
    with pytest.raises(RouteError):
        local_addresses(runner)
