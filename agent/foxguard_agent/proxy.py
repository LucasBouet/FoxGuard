"""Applying a rendered HAProxy configuration to the gateway.

The nftables and DNS appliers' contract, transposed again:

* ``haproxy -c -f`` runs before anything is installed. It is this component's
  ``nft -c -f`` and ``dnsmasq --test``.
* The previous artefacts are restored if the daemon refuses to come back.
* The command runner is injected, so all of this is testable without root and
  without HAProxy installed.

Three things are specific to HAProxy, and all three were measured against
3.0.11 rather than assumed.

**Pattern files are written before validation, always.** ``haproxy -c``
resolves every ``-f`` reference at parse time and fails with "failed to open
pattern file" if a map is missing. So the ordering here is not a preference: the
maps go down first, then the configuration, then the check.

**A reload keeps in-flight connections.** Measured: a six-second response with
the reload fired two seconds in completed with 200, and a request arriving
during the drain was served too. That matters far more here than for DNS,
because a passthrough session can be a shell somebody is typing in.

**Whatever is pushed over the Runtime API must also be written to disk.**
Measured, and this is the trap the whole applier is shaped around: ``add map``
takes effect immediately and is *gone* after the next reload, and
``commit ssl cert`` reverts to the certificate on disk. A runtime update alone
is a change that silently undoes itself the next time anything else changes.
So the files are always written; the Runtime API is only ever an optimisation
that avoids a reload when nothing but a pattern file moved.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import tempfile
from collections.abc import Sequence
from pathlib import Path

from foxguard.nftables.applier import CommandRunner, SubprocessRunner

logger = logging.getLogger(__name__)

__all__ = [
    "ProxyApplier",
    "ProxyError",
    "ProxyReloadError",
    "ProxyValidationError",
]

#: HAProxy reads its configuration, maps and certificates *before* dropping
#: privileges, unlike dnsmasq's ``addn-hosts``. So the project's normal 0600
#: regime applies and these never need to be world-readable.
_ARTEFACT_MODE = 0o640
_DIR_MODE = 0o750

#: Files in the maps directory that Foxguard did not render are removed. The
#: prefix keeps that from ever touching something an operator left there.
_MANAGED_PREFIXES = ("set_", "tok_", "ipf_", "err_", "peers.map", "groups.map")


class ProxyError(RuntimeError):
    """Base class for proxy failures."""


class ProxyValidationError(ProxyError):
    """``haproxy -c`` rejected the configuration. Nothing was installed."""


class ProxyReloadError(ProxyError):
    """The daemon would not pick the new configuration up."""


class ProxyApplier:
    def __init__(
        self,
        *,
        conf_path: Path | str,
        maps_dir: Path | str,
        runtime_socket: Path | str | None = None,
        runner: CommandRunner | None = None,
        haproxy_path: str = "haproxy",
        service: str = "foxguard-proxy",
        systemctl_path: str = "systemctl",
        timeout: float = 30.0,
    ) -> None:
        self._conf = Path(conf_path)
        self._maps = Path(maps_dir)
        self._socket = Path(runtime_socket) if runtime_socket else None
        self._runner = runner or SubprocessRunner()
        self._haproxy = haproxy_path
        self._service = service
        self._systemctl = systemctl_path
        self._timeout = timeout

    def _run(self, argv: Sequence[str]):
        return self._runner.run(argv, timeout=self._timeout)

    def _service_active(self) -> bool:
        """Is the proxy actually running?

        Same reasoning as ``DnsApplier``: the unit is not enabled at boot,
        because before a configuration exists its ``ExecStartPre`` fails and
        systemd would restart it in a loop. So after a reboot the files can be
        current while nothing is listening, and comparing files alone would
        conclude there is nothing to do.
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
        """Write ``content`` atomically.

        A rename rather than a truncate-and-write: HAProxy may be parsing this
        file at this instant during somebody else's reload, and half a map is a
        token file that authenticates nobody.
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

    def _current_files(self) -> dict[str, str]:
        """What is on disk now, restricted to what Foxguard manages."""
        current: dict[str, str] = {}
        if not self._maps.is_dir():
            return current
        for entry in self._maps.iterdir():
            if not entry.is_file() or not entry.name.startswith(_MANAGED_PREFIXES):
                continue
            body = self._read(entry)
            if body is not None:
                current[entry.name] = body
        return current

    # ------------------------------------------------------------- validation

    def validate(self) -> None:
        """Run ``haproxy -c`` against the configuration currently on disk."""
        self._test(self._conf)

    def check(self, conf: str, files: dict[str, str]) -> None:
        """Validate without touching the live configuration -- the dry-run path.

        The whole artefact goes into a scratch directory, because a
        configuration whose pattern files are absent does not parse and the
        check would fail for the wrong reason. The paths inside ``conf`` still
        point at the real maps directory, so this is only meaningful while that
        directory holds a *previous* valid set -- which is exactly the dry-run
        situation.
        """
        with tempfile.TemporaryDirectory(prefix="foxguard-proxy-") as tmp:
            scratch = Path(tmp) / "haproxy.cfg"
            scratch.write_text(conf, encoding="utf-8")
            for name, body in files.items():
                (Path(tmp) / name).write_text(body, encoding="utf-8")
            self._test(scratch)

    def _test(self, path: Path) -> None:
        result = self._run([self._haproxy, "-c", "-f", str(path)])
        if not result.ok:
            raise ProxyValidationError(
                "haproxy rejected the generated configuration: "
                + (result.stderr.strip() or result.stdout.strip() or "no output")
            )

    # ------------------------------------------------------------------ apply

    def apply(self, conf: str, files: dict[str, str]) -> str:
        """Install the artefacts and make the daemon serve them.

        Returns what it did: ``"unchanged"``, ``"started"``, ``"reloaded"`` or
        ``"synced"`` -- the last meaning pattern files moved and were pushed
        over the Runtime API without a reload.
        """
        previous_conf = self._read(self._conf)
        previous_files = self._current_files()

        conf_changed = previous_conf != conf
        changed_files = {
            name: body for name, body in files.items() if previous_files.get(name) != body
        }
        stale = set(previous_files) - set(files)

        if not conf_changed and not changed_files and not stale:
            if self._service_active():
                return "unchanged"
            result = self._run([self._systemctl, "restart", self._service])
            if not result.ok:
                raise ProxyReloadError(
                    f"the configuration is current but {self._service} is not "
                    "running, and it would not start: "
                    + (result.stderr.strip() or result.stdout.strip() or "no output")
                )
            return "started"

        # Maps first: haproxy -c resolves -f references at parse time, so a
        # configuration validated before its pattern files exist fails for a
        # reason that has nothing to do with what changed.
        for name, body in changed_files.items():
            self._write(self._maps / name, body)
        for name in stale:
            (self._maps / name).unlink(missing_ok=True)
        if conf_changed:
            self._write(self._conf, conf)

        try:
            self.validate()
        except ProxyValidationError:
            self._restore(previous_conf, previous_files, files)
            raise

        # Only pattern files moved: push them over the Runtime API and skip the
        # reload entirely. They are already on disk, so the next reload -- for
        # whatever reason -- keeps them. Doing one without the other is the
        # measured trap this applier exists to avoid.
        if not conf_changed and self._service_active() and self._sync_maps(changed_files):
            return "synced"

        action = "reloaded"
        result = self._run([self._systemctl, "reload", self._service])
        if not result.ok:
            # A unit that is not running cannot be reloaded, and that is not an
            # error worth restoring a configuration over.
            result = self._run([self._systemctl, "restart", self._service])
            action = "started"
        if not result.ok:
            self._restore(previous_conf, previous_files, files)
            self._run([self._systemctl, "restart", self._service])
            raise ProxyReloadError(
                f"{self._service} would not take the new configuration, restored "
                f"the previous one: {result.stderr.strip() or result.stdout.strip()}"
            )
        return action

    # ---------------------------------------------------------- runtime API

    def _sync_maps(self, changed: dict[str, str]) -> bool:
        """Push changed pattern files over the Runtime API.

        Returns whether *every* change was pushed. Anything less falls back to a
        reload, because a partially synced proxy is worse than a reloaded one.

        Only ``.map`` and ``.lst`` files are pushable; an error page or a
        certificate is not, and a changed one means a reload.
        """
        if self._socket is None or not changed:
            return False
        for name in changed:
            if not name.endswith((".map", ".lst")):
                return False
        try:
            for name, body in changed.items():
                path = self._maps / name
                verb = "map" if name.endswith(".map") else "acl"
                reply = self._runtime(f"clear {verb} {path}")
                if "error" in reply.lower() or "unknown" in reply.lower():
                    return False
                reply = self._runtime(f"add {verb} {path} <<\n{body}\n\n")
                if "error" in reply.lower() or "unknown" in reply.lower():
                    return False
        except OSError as exc:
            logger.debug("runtime API unavailable, falling back to reload: %s", exc)
            return False
        return True

    def _runtime(self, command: str) -> str:
        """One Runtime API round trip over the stats socket."""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self._timeout)
            sock.connect(str(self._socket))
            sock.sendall(command.encode("utf-8") + b"\n")
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).decode("utf-8", "replace")

    # ---------------------------------------------------------------- restore

    def _restore(
        self,
        conf: str | None,
        previous_files: dict[str, str],
        attempted: dict[str, str],
    ) -> None:
        for name in attempted:
            if name in previous_files:
                self._write(self._maps / name, previous_files[name])
            else:
                # Nothing was there before, so leaving our rejected file behind
                # would be worse than removing it.
                (self._maps / name).unlink(missing_ok=True)
        for name, body in previous_files.items():
            if name not in attempted:
                self._write(self._maps / name, body)
        if conf is None:
            self._conf.unlink(missing_ok=True)
        else:
            self._write(self._conf, conf)
