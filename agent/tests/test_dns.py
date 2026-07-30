"""Tests for DNS reconciliation.

Two properties matter most here, and both were found by getting them wrong:

* A configuration ``dnsmasq --test`` rejects must never reach the daemon, and
  the previous zone must survive the attempt.
* Adding a peer is a *reload*, not a restart. dnsmasq re-reads its hosts files
  on SIGHUP but not its configuration file, so conflating the two would drop
  in-flight queries every time somebody registers a device.
"""

from __future__ import annotations

import pytest
from foxguard.nftables.applier import CommandResult

from foxguard_agent.dns import DnsApplier, DnsReloadError, DnsValidationError

HOSTS_A = "10.88.0.1\tgw.fox.internal\n"
HOSTS_B = "10.88.0.1\tgw.fox.internal\n10.88.0.5\tlaptop.fox.internal\n"
CONF_A = "port=53\nlocal=/fox.internal/\n"
CONF_B = "port=53\nlocal=/other.internal/\n"


class FakeRunner:
    """Records every command and lets a test decide which ones fail."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.test_ok = True
        self.systemctl_ok = True

    def run(self, argv, *, timeout: float = 30.0) -> CommandResult:
        argv = list(argv)
        self.calls.append(argv)
        if "--test" in argv:
            return (
                CommandResult(0, "dnsmasq: syntax check OK.", "")
                if self.test_ok
                else CommandResult(1, "", "bad option at line 2")
            )
        if self.systemctl_ok:
            return CommandResult(0, "", "")
        return CommandResult(1, "", "Job failed")

    @property
    def systemctl_verbs(self) -> list[str]:
        return [c[1] for c in self.calls if c[0] == "systemctl"]


@pytest.fixture()
def applier(tmp_path):
    runner = FakeRunner()
    return (
        DnsApplier(
            hosts_path=tmp_path / "dns" / "hosts",
            conf_path=tmp_path / "dns" / "dnsmasq.conf",
            runner=runner,
            dnsmasq_path="dnsmasq",
            systemctl_path="systemctl",
            service="foxguard-dns",
        ),
        runner,
        tmp_path / "dns",
    )


# --------------------------------------------------------------------------- #
# reload vs restart
# --------------------------------------------------------------------------- #


def test_first_apply_writes_both_artefacts_and_restarts(applier):
    app, runner, directory = applier
    assert app.apply(HOSTS_A, CONF_A) == "restarted"
    assert (directory / "hosts").read_text() == HOSTS_A
    assert (directory / "dnsmasq.conf").read_text() == CONF_A
    assert runner.systemctl_verbs == ["restart"]


def test_a_new_peer_is_a_reload_not_a_restart(applier):
    """SIGHUP re-reads the hosts file without dropping the listening socket."""
    app, runner, _ = applier
    app.apply(HOSTS_A, CONF_A)
    runner.calls.clear()
    assert app.apply(HOSTS_B, CONF_A) == "reloaded"
    assert runner.systemctl_verbs == ["reload"]


def test_a_changed_configuration_needs_a_restart(applier):
    """dnsmasq does not re-read its configuration file on SIGHUP."""
    app, runner, _ = applier
    app.apply(HOSTS_A, CONF_A)
    runner.calls.clear()
    assert app.apply(HOSTS_A, CONF_B) == "restarted"
    assert runner.systemctl_verbs == ["restart"]


def test_an_unchanged_zone_touches_nothing(applier):
    app, runner, _ = applier
    app.apply(HOSTS_A, CONF_A)
    runner.calls.clear()
    assert app.apply(HOSTS_A, CONF_A) == "unchanged"
    assert runner.calls == []


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #


def test_a_rejected_configuration_never_reaches_the_daemon(applier):
    app, runner, _ = applier
    runner.test_ok = False
    with pytest.raises(DnsValidationError):
        app.apply(HOSTS_A, CONF_A)
    assert runner.systemctl_verbs == []


def test_a_rejected_configuration_restores_the_previous_zone(applier):
    app, runner, directory = applier
    app.apply(HOSTS_A, CONF_A)
    runner.test_ok = False
    with pytest.raises(DnsValidationError):
        app.apply(HOSTS_B, CONF_B)
    assert (directory / "hosts").read_text() == HOSTS_A
    assert (directory / "dnsmasq.conf").read_text() == CONF_A


def test_a_rejected_first_configuration_leaves_no_files_behind(applier):
    """There was no zone before, so a half-written one is worse than none."""
    app, runner, directory = applier
    runner.test_ok = False
    with pytest.raises(DnsValidationError):
        app.apply(HOSTS_A, CONF_A)
    assert not (directory / "hosts").exists()
    assert not (directory / "dnsmasq.conf").exists()


def test_check_validates_without_writing_anything(applier):
    """The dry-run path: the gateway's real zone must be untouched."""
    app, runner, directory = applier
    app.check(CONF_A)
    assert not directory.exists() or not (directory / "dnsmasq.conf").exists()
    assert runner.systemctl_verbs == []


def test_check_reports_a_bad_configuration(applier):
    app, runner, _ = applier
    runner.test_ok = False
    with pytest.raises(DnsValidationError) as exc:
        app.check(CONF_A)
    assert "bad option" in str(exc.value)


# --------------------------------------------------------------------------- #
# the daemon refusing to come back
# --------------------------------------------------------------------------- #


def test_a_failed_reload_restores_and_restarts(applier):
    app, runner, directory = applier
    app.apply(HOSTS_A, CONF_A)
    runner.calls.clear()
    runner.systemctl_ok = False
    with pytest.raises(DnsReloadError):
        app.apply(HOSTS_B, CONF_A)
    assert (directory / "hosts").read_text() == HOSTS_A
    # reload failed, then a restart to put the fleet's resolution back.
    assert runner.systemctl_verbs == ["reload", "restart"]


# --------------------------------------------------------------------------- #
# file modes
# --------------------------------------------------------------------------- #


def test_artefacts_are_world_readable(applier):
    """dnsmasq drops privileges and re-reads addn-hosts as an unprivileged user.

    Written 0600 -- the mode everything else in Foxguard uses -- the resolver
    works until its first reload and then quietly serves an empty zone.
    """
    app, _, directory = applier
    app.apply(HOSTS_A, CONF_A)
    assert (directory / "hosts").stat().st_mode & 0o777 == 0o644
    assert (directory / "dnsmasq.conf").stat().st_mode & 0o777 == 0o644
    assert directory.stat().st_mode & 0o777 == 0o755


def test_no_temporary_file_is_left_behind(applier):
    """The write is a rename, so dnsmasq never reads half a hosts file."""
    app, _, directory = applier
    app.apply(HOSTS_A, CONF_A)
    app.apply(HOSTS_B, CONF_B)
    assert sorted(p.name for p in directory.iterdir()) == ["dnsmasq.conf", "hosts"]
