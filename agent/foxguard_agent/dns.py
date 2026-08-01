"""Applying a rendered DNS zone to the gateway's resolver.

The nftables applier's contract, transposed:

* ``dnsmasq --test`` runs before anything is installed, and a configuration it
  rejects is never handed to the daemon. It is this component's ``nft -c -f``.
* The previous artefacts are restored if the daemon refuses to come back, so a
  bad zone costs one reconciliation rather than name resolution for the fleet.
* **Reload, not restart, whenever possible.** dnsmasq re-reads its hosts files
  on SIGHUP but *not* its configuration file, so the two cases are genuinely
  different: adding a peer is a reload, changing the zone or the upstreams is a
  restart. Treating everything as a restart would drop in-flight queries every
  time somebody registers a device.
* The command runner is injected, so all of this is testable without root and
  without dnsmasq installed.

One non-obvious requirement, found by breaking it: dnsmasq drops privileges at
startup and re-reads ``addn-hosts`` **as the unprivileged user**. The hosts file
must therefore be world-readable on a traversable path. Every other file
Foxguard writes is 0600, and copying that habit here produces a resolver that
works until its first reload and then quietly serves an empty zone.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path

from foxguard.nftables.applier import CommandRunner, SubprocessRunner

logger = logging.getLogger(__name__)

__all__ = ["DnsApplier", "DnsError", "DnsReloadError", "DnsValidationError"]

#: dnsmasq re-reads these as the unprivileged user it drops to.
_ARTEFACT_MODE = 0o644
_DIR_MODE = 0o755


class DnsError(RuntimeError):
    """Base class for resolver failures."""


class DnsValidationError(DnsError):
    """``dnsmasq --test`` rejected the configuration. Nothing was installed."""


class DnsReloadError(DnsError):
    """The daemon would not pick the new zone up."""


class DnsApplier:
    def __init__(
        self,
        *,
        hosts_path: Path | str,
        conf_path: Path | str,
        runner: CommandRunner | None = None,
        dnsmasq_path: str = "dnsmasq",
        service: str = "foxguard-dns",
        systemctl_path: str = "systemctl",
        timeout: float = 30.0,
    ) -> None:
        self._hosts = Path(hosts_path)
        self._conf = Path(conf_path)
        self._runner = runner or SubprocessRunner()
        self._dnsmasq = dnsmasq_path
        self._service = service
        self._systemctl = systemctl_path
        self._timeout = timeout

    # ------------------------------------------------------------- primitives

    def _run(self, argv: Sequence[str]):
        return self._runner.run(argv, timeout=self._timeout)

    def _service_active(self) -> bool:
        """Is the resolver actually running?

        ``systemctl is-active`` exits non-zero for anything that is not active,
        so the exit code alone is the answer; the word is compared too because
        ``activating`` also exits non-zero and is not a reason to restart a unit
        that is already on its way up.
        """
        result = self._run([self._systemctl, "is-active", self._service])
        state = result.stdout.strip()
        return result.ok or state in {"active", "activating", "reloading"}

    @staticmethod
    def _read(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return None

    def _write(self, path: Path, content: str) -> None:
        """Write ``content`` atomically, world-readable.

        A rename rather than a truncate-and-write: dnsmasq may be reading the
        file at this instant (its own reload, an operator's SIGHUP), and half a
        hosts file is a zone missing devices.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, _DIR_MODE)
        fd, name = tempfile.mkstemp(prefix=f".{path.name}-", dir=str(path.parent))
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(name, _ARTEFACT_MODE)
        shutil.move(name, str(path))

    # ------------------------------------------------------------- validation

    def validate(self) -> None:
        """Run ``dnsmasq --test`` against the configuration currently on disk."""
        self._test(self._conf)

    def check(self, conf: str) -> None:
        """Validate a configuration without installing it -- the dry-run path.

        ``--test`` parses the configuration file and does not follow
        ``addn-hosts``, so checking the text in isolation is exactly as
        meaningful as checking it in place.
        """
        fd, name = tempfile.mkstemp(prefix="foxguard-dns-", suffix=".conf")
        try:
            os.write(fd, conf.encode("utf-8"))
        finally:
            os.close(fd)
        try:
            self._test(Path(name))
        finally:
            Path(name).unlink(missing_ok=True)

    def _test(self, path: Path) -> None:
        result = self._run([self._dnsmasq, "--test", f"--conf-file={path}"])
        if not result.ok:
            raise DnsValidationError(
                "dnsmasq rejected the generated configuration: "
                + (result.stderr.strip() or result.stdout.strip() or "no output")
            )

    # ------------------------------------------------------------------ apply

    def apply(self, hosts: str, conf: str) -> str:
        """Install the artefacts and make the daemon serve them.

        Returns what it did: ``"unchanged"``, ``"started"``, ``"reloaded"`` or
        ``"restarted"``.
        """
        previous_hosts = self._read(self._hosts)
        previous_conf = self._read(self._conf)

        hosts_changed = previous_hosts != hosts
        conf_changed = previous_conf != conf
        if not hosts_changed and not conf_changed:
            # The files being right is not the same as the zone being served.
            #
            # ``foxguard-dns`` is deliberately not enabled at boot: before a
            # zone exists its ExecStartPre fails, and systemd would restart it
            # in a loop. The agent starts it instead. So after a reboot the
            # rendered files are already on disk and identical, and comparing
            # only files concludes there is nothing to do -- leaving the fleet
            # with no name resolution until somebody happens to add a peer.
            #
            # Checking the unit is what makes this converge on the desired
            # state rather than on the last change, which is how every other
            # part of the agent behaves.
            if self._service_active():
                return "unchanged"
            result = self._run([self._systemctl, "restart", self._service])
            if not result.ok:
                raise DnsReloadError(
                    f"the zone is current but {self._service} is not running, "
                    "and it would not start: "
                    + (result.stderr.strip() or result.stdout.strip() or "no output")
                )
            return "started"

        if conf_changed:
            self._write(self._conf, conf)
        if hosts_changed:
            self._write(self._hosts, hosts)

        try:
            self.validate()
        except DnsValidationError:
            self._restore(previous_hosts, previous_conf)
            raise

        # A changed configuration needs a restart: SIGHUP re-reads hosts files
        # and flushes the cache, and nothing else.
        action = "restarted" if conf_changed else "reloaded"
        verb = "restart" if conf_changed else "reload"
        result = self._run([self._systemctl, verb, self._service])
        if not result.ok:
            self._restore(previous_hosts, previous_conf)
            # Best effort: if the daemon died on the new configuration, this is
            # what puts the fleet's name resolution back.
            self._run([self._systemctl, "restart", self._service])
            raise DnsReloadError(
                f"systemctl {verb} {self._service} failed, restored the previous "
                f"zone: {result.stderr.strip() or result.stdout.strip()}"
            )
        return action

    def _restore(self, hosts: str | None, conf: str | None) -> None:
        for path, content in ((self._hosts, hosts), (self._conf, conf)):
            if content is None:
                # There was nothing there before, so leaving our rejected file
                # behind would be worse than removing it.
                path.unlink(missing_ok=True)
            else:
                self._write(path, content)
