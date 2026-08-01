"""The DNS applier against a real dnsmasq.

Opt-in and privileged-ish::

    FOXGUARD_LIVE_DNS=1 pytest tests/test_dns_live.py

``systemd`` is not available in a build container, so ``systemctl`` is a shim
script that starts, stops and reports on a real dnsmasq process. That is enough
for the thing under test: the applier only ever speaks to systemd through
``restart``, ``reload`` and ``is-active``, and the shim implements exactly those
three verbs with the same exit-code contract.

The case worth having here is the reboot. ``foxguard-dns`` is deliberately not
enabled at boot -- before a zone exists its ``ExecStartPre`` fails and systemd
would restart it in a loop -- so the agent is what starts it. After a reboot the
rendered files are already on disk and byte-identical, which used to make the
applier decide there was nothing to do, leaving the fleet with no resolver until
somebody happened to add a peer. Files matching is not the same as the zone
being served, and only a live daemon can show the difference.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from foxguard_agent.dns import DnsApplier, DnsReloadError

pytestmark = pytest.mark.skipif(
    not os.environ.get("FOXGUARD_LIVE_DNS"),
    reason="live DNS test is opt-in: set FOXGUARD_LIVE_DNS=1 (needs dnsmasq and dig)",
)

DNSMASQ = "/usr/sbin/dnsmasq"
PORT = 5354
ZONE = "fox.internal"

HOSTS_A = f"127.0.0.1\tgw.{ZONE}\n"
HOSTS_B = f"127.0.0.1\tgw.{ZONE}\n127.0.0.2\tlaptop.{ZONE}\n"


def _conf(hosts_path: Path) -> str:
    return "\n".join(
        [
            "bind-interfaces",
            "listen-address=127.0.0.1",
            f"port={PORT}",
            "no-hosts",
            "no-resolv",
            "no-poll",
            f"local=/{ZONE}/",
            f"addn-hosts={hosts_path}",
            "",
        ]
    )


@pytest.fixture()
def live(tmp_path):
    """A directory, a systemctl shim, and a guarantee nothing is left running."""
    if not Path(DNSMASQ).exists():
        pytest.skip("dnsmasq is not installed")
    if shutil.which("dig") is None:
        pytest.skip("dig is not installed")

    directory = tmp_path / "dns"
    pidfile = tmp_path / "dnsmasq.pid"
    conf_path = directory / "dnsmasq.conf"

    shim = tmp_path / "systemctl"
    shim.write_text(
        f"""#!/bin/sh
# A stand-in for systemd, implementing only what DnsApplier uses.
verb=$1
pidfile={pidfile}
running() {{ [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; }}
case "$verb" in
  is-active)
    if running; then echo active; exit 0; else echo inactive; exit 3; fi ;;
  restart)
    running && kill "$(cat "$pidfile")" 2>/dev/null
    rm -f "$pidfile"
    {DNSMASQ} --keep-in-foreground --conf-file={conf_path} &
    echo $! > "$pidfile"
    sleep 0.4
    running || exit 1
    exit 0 ;;
  reload)
    running || exit 1
    kill -HUP "$(cat "$pidfile")"
    exit 0 ;;
  stop)
    running && kill "$(cat "$pidfile")" 2>/dev/null
    rm -f "$pidfile"
    exit 0 ;;
esac
exit 2
""",
        encoding="utf-8",
    )
    shim.chmod(0o755)

    applier = DnsApplier(
        hosts_path=directory / "hosts",
        conf_path=conf_path,
        dnsmasq_path=DNSMASQ,
        systemctl_path=str(shim),
        service="foxguard-dns",
    )
    try:
        yield applier, directory, pidfile, shim
    finally:
        subprocess.run([str(shim), "stop"], check=False)


def resolve(name: str) -> str:
    """Ask the daemon under test, and return the first address it gives."""
    out = subprocess.run(
        ["dig", "@127.0.0.1", "-p", str(PORT), "+short", "+time=2", "+tries=1", name],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    answers = [
        line.strip()
        for line in out.splitlines()
        if line.strip() and all(c in "0123456789abcdefABCDEF.:" for c in line.strip())
    ]
    return answers[0] if answers else ""


def alive(pidfile: Path) -> bool:
    return (
        subprocess.run(
            ["sh", "-c", f'[ -f {pidfile} ] && kill -0 "$(cat {pidfile})"'], check=False
        ).returncode
        == 0
    )


def test_the_first_apply_starts_a_daemon_that_serves_the_zone(live):
    applier, directory, pidfile, _ = live
    assert applier.apply(HOSTS_A, _conf(directory / "hosts")) == "restarted"
    assert alive(pidfile)
    assert resolve(f"gw.{ZONE}") == "127.0.0.1"


def test_adding_a_name_reloads_without_replacing_the_process(live):
    applier, directory, pidfile, _ = live
    conf = _conf(directory / "hosts")
    applier.apply(HOSTS_A, conf)
    before = pidfile.read_text().strip()

    assert applier.apply(HOSTS_B, conf) == "reloaded"
    time.sleep(0.3)
    assert pidfile.read_text().strip() == before, "a reload must not restart the daemon"
    assert resolve(f"laptop.{ZONE}") == "127.0.0.2"
    assert resolve(f"gw.{ZONE}") == "127.0.0.1"


def test_an_unchanged_zone_leaves_the_running_daemon_alone(live):
    applier, directory, pidfile, _ = live
    conf = _conf(directory / "hosts")
    applier.apply(HOSTS_A, conf)
    before = pidfile.read_text().strip()

    assert applier.apply(HOSTS_A, conf) == "unchanged"
    assert pidfile.read_text().strip() == before
    assert resolve(f"gw.{ZONE}") == "127.0.0.1"


def test_a_dead_daemon_comes_back_although_the_files_never_changed(live):
    """The reboot. This is the regression the whole module exists for."""
    applier, directory, pidfile, shim = live
    conf = _conf(directory / "hosts")
    applier.apply(HOSTS_A, conf)
    assert resolve(f"gw.{ZONE}") == "127.0.0.1"

    # The machine restarts: the rendered files survive, the daemon does not.
    subprocess.run([str(shim), "stop"], check=False)
    assert not alive(pidfile)
    assert resolve(f"gw.{ZONE}") == "", "nothing should be answering yet"

    # Same zone, byte for byte. The applier still has to notice it is not served.
    assert applier.apply(HOSTS_A, conf) == "started"
    assert alive(pidfile)
    assert resolve(f"gw.{ZONE}") == "127.0.0.1"


def test_a_daemon_that_cannot_start_is_an_error_not_a_silent_no_op(live):
    applier, directory, pidfile, shim = live
    conf = _conf(directory / "hosts")
    applier.apply(HOSTS_A, conf)
    subprocess.run([str(shim), "stop"], check=False)

    # Break the config on disk behind the applier's back, so the restart it is
    # about to attempt fails the unit's own validation.
    (directory / "dnsmasq.conf").write_text("this-is-not-an-option\n", encoding="utf-8")

    with pytest.raises(DnsReloadError, match="not running"):
        applier.apply(HOSTS_A, "this-is-not-an-option\n")
    assert not alive(pidfile)
