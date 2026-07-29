"""WireGuard peer reconciliation.

``wg syncconf`` is used rather than ``wg-quick down/up``: it applies the
difference between the running interface and a config file without tearing the
interface down, so peers that did not change keep their handshakes and their
open connections.

The interface's private key never leaves the gateway. We read the *current*
configuration with ``wg showconf`` and rewrite only its ``[Peer]`` sections --
the control plane only ever knows public keys.
"""

from __future__ import annotations

import logging
import os
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path

from foxguard.nftables.applier import CommandRunner, SubprocessRunner

from .client import WireGuardPeer

logger = logging.getLogger(__name__)


class WireGuardError(RuntimeError):
    pass


class WireGuardManager:
    def __init__(
        self,
        interface: str,
        *,
        runner: CommandRunner | None = None,
        wg_path: str = "wg",
        timeout: float = 15.0,
    ) -> None:
        self._interface = interface
        self._runner = runner or SubprocessRunner()
        self._wg = wg_path
        self._timeout = timeout

    def _run(self, argv: Sequence[str]):
        return self._runner.run(argv, timeout=self._timeout)

    def current_config(self) -> str:
        result = self._run([self._wg, "showconf", self._interface])
        if not result.ok:
            raise WireGuardError(
                f"wg showconf {self._interface} failed: {result.stderr.strip()}"
            )
        return result.stdout

    @staticmethod
    def interface_section(config: str) -> str:
        """Return the ``[Interface]`` block only, private key included.

        Kept local: this value is never sent anywhere.
        """
        lines: list[str] = []
        in_interface = False
        for line in config.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_interface = stripped.lower() == "[interface]"
                if in_interface:
                    lines.append(stripped)
                continue
            if in_interface:
                lines.append(line.rstrip())
        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def render_config(interface_section: str, peers: Iterable[WireGuardPeer]) -> str:
        blocks = [interface_section.rstrip() + "\n"]
        for peer in sorted(peers, key=lambda p: p.public_key):
            blocks.append(
                "\n[Peer]\n"
                f"PublicKey = {peer.public_key}\n"
                f"AllowedIPs = {', '.join(peer.allowed_ips)}\n"
            )
        return "".join(blocks)

    def sync(self, peers: Iterable[WireGuardPeer]) -> bool:
        """Reconcile the interface's peers. Returns True when something changed."""
        current = self.current_config()
        desired = self.render_config(self.interface_section(current), peers)

        if _peer_sections(current) == _peer_sections(desired):
            return False

        fd, name = tempfile.mkstemp(prefix="foxguard-wg-", suffix=".conf")
        try:
            os.write(fd, desired.encode("utf-8"))
        finally:
            os.close(fd)
        path = Path(name)
        os.chmod(path, 0o600)
        try:
            result = self._run([self._wg, "syncconf", self._interface, str(path)])
        finally:
            path.unlink(missing_ok=True)

        if not result.ok:
            raise WireGuardError(
                f"wg syncconf {self._interface} failed: {result.stderr.strip()}"
            )
        return True


def _peer_sections(config: str) -> set[tuple[str, ...]]:
    """Normalised set of peer blocks, for change detection."""
    sections: set[tuple[str, ...]] = set()
    current: list[str] = []
    in_peer = False
    for line in config.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            if in_peer and current:
                sections.add(tuple(sorted(current)))
            current = []
            in_peer = stripped.lower() == "[peer]"
            continue
        if in_peer and stripped:
            key, _, value = stripped.partition("=")
            normalised_value = ",".join(
                part.strip() for part in value.split(",") if part.strip()
            )
            current.append(f"{key.strip().lower()}={normalised_value}")
    if in_peer and current:
        sections.add(tuple(sorted(current)))
    return sections
