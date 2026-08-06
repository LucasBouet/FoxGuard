"""End-to-end verification against a real dnsmasq.

Everything else about DNS is tested against strings and fake runners. This file
starts the actual daemon on the actual artefacts and asks it actual questions,
because the interesting failures are all in the seam:

* dnsmasq accepting a configuration we generate is not the same as dnsmasq
  *serving* what we meant;
* SIGHUP re-reading the hosts file is documented behaviour we depend on for
  every peer registration, and documented behaviour is worth measuring once;
* the daemon drops privileges and re-reads that file as an unprivileged user,
  which is invisible until the first reload.

Opt-in, because it starts a process and binds a port::

    FOXGUARD_LIVE_DNS=1 pytest tests/test_dns_live.py

or ``make test-dns-live``. Skipped otherwise, and skipped if ``dnsmasq`` or
``dig`` is not installed.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import replace
from pathlib import Path

import pytest

from foxguard.dns import CnameEntry, DnsSpec, HostEntry, ResolverMode, render_conf, render_hosts

pytestmark = pytest.mark.skipif(
    not os.environ.get("FOXGUARD_LIVE_DNS"),
    reason="live DNS test is opt-in: set FOXGUARD_LIVE_DNS=1",
)

ZONE = "fox.internal"
#: Loopback and a high port, so the test needs no privileges and no interface.
#: Binding behaviour itself is covered by the generator tests.
ADDRESS = "127.0.0.1"
PORT = 5399


def _which(name: str) -> str | None:
    return shutil.which(name) or shutil.which(name, path="/usr/sbin:/sbin")


@pytest.fixture(scope="module")
def dnsmasq_path() -> str:
    path = _which("dnsmasq")
    if not path:
        pytest.skip("dnsmasq is not installed")
    return path


@pytest.fixture(scope="module")
def dig_path() -> str:
    path = _which("dig")
    if not path:
        pytest.skip("dig is not installed")
    return path


def sample_spec(hosts_path: Path, **overrides) -> DnsSpec:
    defaults = dict(
        zone=ZONE,
        listen_addresses=(ADDRESS,),
        port=PORT,
        hosts_path=str(hosts_path),
        hosts=(
            HostEntry("10.88.0.1", (f"gw.{ZONE}",)),
            HostEntry("10.88.0.5", (f"laptop.{ZONE}",)),
            HostEntry("10.88.0.6", (f"backup.{ZONE}", f"nas.{ZONE}")),
            HostEntry("fd00:88::5", (f"laptop.{ZONE}",)),
            HostEntry("192.168.1.50", (f"printer.{ZONE}",)),
        ),
        cnames=(CnameEntry(f"portal.{ZONE}", f"gw.{ZONE}"),),
        mode=ResolverMode.SPLIT,
        reverse_pools=("10.88.0.0/24",),
    )
    defaults.update(overrides)
    return DnsSpec(**defaults)


class Resolver:
    """A real dnsmasq, started on real generated artefacts."""

    def __init__(self, directory: Path, dnsmasq: str, dig: str) -> None:
        self.dir = directory
        self.hosts_path = directory / "hosts"
        self.conf_path = directory / "dnsmasq.conf"
        self._dnsmasq = dnsmasq
        self._dig = dig
        self.process: subprocess.Popen | None = None

    def write(self, spec: DnsSpec) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.dir.chmod(0o755)
        self.hosts_path.write_text(render_hosts(spec), encoding="utf-8")
        self.conf_path.write_text(render_conf(spec), encoding="utf-8")
        # The mode the applier uses, for the reason the applier uses it.
        self.hosts_path.chmod(0o644)
        self.conf_path.chmod(0o644)

    def check(self) -> subprocess.CompletedProcess:
        return subprocess.run(  # noqa: S603
            [self._dnsmasq, "--test", f"--conf-file={self.conf_path}"],
            capture_output=True,
            text=True,
            check=False,
        )

    def start(self) -> None:
        self.process = subprocess.Popen(  # noqa: S603
            [
                self._dnsmasq,
                "--keep-in-foreground",
                f"--conf-file={self.conf_path}",
                "--log-facility=-",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for _ in range(50):
            if self.query(f"gw.{ZONE}"):
                return
            time.sleep(0.1)
        raise RuntimeError(f"dnsmasq did not come up: {self.output()}")

    def reload(self) -> None:
        """What ``systemctl reload foxguard-dns`` does, via the unit's ExecReload."""
        if self.process:
            self.process.send_signal(signal.SIGHUP)
            time.sleep(0.3)

    def stop(self) -> None:
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
            self.process = None

    def output(self) -> str:
        if self.process and self.process.stdout:
            self.process.terminate()
            return self.process.stdout.read()
        return ""

    def _dig_run(self, *args: str) -> str:
        result = subprocess.run(  # noqa: S603
            [self._dig, f"@{ADDRESS}", "-p", str(PORT), "+time=1", "+tries=1", *args],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout.strip()

    def query(self, name: str, kind: str = "A") -> list[str]:
        return [line for line in self._dig_run("+short", name, kind).splitlines() if line]

    def reverse(self, address: str) -> list[str]:
        return [line for line in self._dig_run("+short", "-x", address).splitlines() if line]

    def status(self, name: str, kind: str = "A") -> str:
        out = self._dig_run("+noall", "+comments", name, kind)
        for line in out.splitlines():
            if "status:" in line:
                return line.split("status:")[1].split(",")[0].strip()
        return "NO-ANSWER"


@pytest.fixture()
def resolver(tmp_path, dnsmasq_path, dig_path):
    server = Resolver(tmp_path / "dns", dnsmasq_path, dig_path)
    server.write(sample_spec(server.hosts_path))
    try:
        server.start()
        yield server
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# the generated configuration is one dnsmasq accepts
# --------------------------------------------------------------------------- #


def test_dnsmasq_accepts_what_we_generate(tmp_path, dnsmasq_path, dig_path):
    """The DNS equivalent of ``nft -c -f``: the agent runs exactly this check."""
    server = Resolver(tmp_path / "dns", dnsmasq_path, dig_path)
    server.write(sample_spec(server.hosts_path))
    result = server.check()
    assert result.returncode == 0, result.stdout + result.stderr


def test_dnsmasq_accepts_the_forwarding_variant(tmp_path, dnsmasq_path, dig_path):
    server = Resolver(tmp_path / "dns", dnsmasq_path, dig_path)
    server.write(
        sample_spec(
            server.hosts_path,
            mode=ResolverMode.FORWARD,
            upstreams=("1.1.1.1", "9.9.9.9#5353"),
            stop_dns_rebind=True,
        )
    )
    result = server.check()
    assert result.returncode == 0, result.stdout + result.stderr


# --------------------------------------------------------------------------- #
# it serves what we meant
# --------------------------------------------------------------------------- #


def test_a_peer_resolves(resolver):
    assert resolver.query(f"laptop.{ZONE}") == ["10.88.0.5"]


def test_the_gateway_resolves(resolver):
    assert resolver.query(f"gw.{ZONE}") == ["10.88.0.1"]


def test_a_second_name_on_one_address_resolves(resolver):
    assert resolver.query(f"nas.{ZONE}") == ["10.88.0.6"]


def test_a_dual_stack_peer_answers_both_families(resolver):
    assert resolver.query(f"laptop.{ZONE}", "A") == ["10.88.0.5"]
    assert resolver.query(f"laptop.{ZONE}", "AAAA") == ["fd00:88::5"]


def test_a_record_pointing_off_the_tunnel_resolves(resolver):
    """Split horizon for a device on the LAN behind the gateway."""
    assert resolver.query(f"printer.{ZONE}") == ["192.168.1.50"]


def test_a_cname_resolves_through_to_its_target(resolver):
    assert resolver.query(f"portal.{ZONE}") == [f"gw.{ZONE}.", "10.88.0.1"]


def test_reverse_lookup_returns_the_canonical_name(resolver):
    """The first name on the hosts line, which is why its order is data."""
    assert resolver.reverse("10.88.0.6") == [f"backup.{ZONE}."]


def test_an_unknown_name_in_the_zone_is_nxdomain(resolver):
    assert resolver.status(f"ghost.{ZONE}") == "NXDOMAIN"


def test_a_bare_label_is_never_served(resolver):
    """No ``expand-hosts``: a peer named ``wpad`` must not answer for ``wpad``."""
    assert resolver.status("laptop") == "REFUSED"


def test_split_mode_refuses_rather_than_failing(resolver):
    """REFUSED is what a stub resolver falls through on to its next server."""
    assert resolver.status("example.com") == "REFUSED"


# --------------------------------------------------------------------------- #
# reload semantics -- the thing every peer registration depends on
# --------------------------------------------------------------------------- #


def test_sighup_picks_up_a_new_peer_without_restarting(resolver):
    """Adding a device must not drop in-flight queries for everyone else."""
    pid_before = resolver.process.pid
    assert resolver.status(f"phone.{ZONE}") == "NXDOMAIN"

    spec = sample_spec(resolver.hosts_path)
    resolver.write(
        replace(spec, hosts=(*spec.hosts, HostEntry("10.88.0.9", (f"phone.{ZONE}",))))
    )
    resolver.reload()

    assert resolver.query(f"phone.{ZONE}") == ["10.88.0.9"]
    assert resolver.process.pid == pid_before
    assert resolver.process.poll() is None


def test_sighup_forgets_a_revoked_peer(resolver):
    """Revocation has to take a name away, not only stop refreshing it."""
    assert resolver.query(f"laptop.{ZONE}") == ["10.88.0.5"]

    spec = sample_spec(resolver.hosts_path)
    without_laptop = tuple(
        h for h in spec.hosts if f"laptop.{ZONE}" not in h.names
    )
    resolver.write(replace(spec, hosts=without_laptop))
    resolver.reload()

    assert resolver.status(f"laptop.{ZONE}", "A") == "NXDOMAIN"


def test_losing_one_family_leaves_the_other_answering(resolver):
    """NODATA, not NXDOMAIN: the name still exists, just not for that type.

    Worth pinning down, because it is the difference between "this device has no
    IPv4 address" and "this device is gone", and a client behaves differently.
    """
    spec = sample_spec(resolver.hosts_path)
    resolver.write(
        replace(spec, hosts=tuple(h for h in spec.hosts if h.address != "10.88.0.5"))
    )
    resolver.reload()

    assert resolver.status(f"laptop.{ZONE}", "A") == "NOERROR"
    assert resolver.query(f"laptop.{ZONE}", "A") == []
    assert resolver.query(f"laptop.{ZONE}", "AAAA") == ["fd00:88::5"]
