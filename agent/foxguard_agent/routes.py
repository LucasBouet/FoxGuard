"""Installing the kernel routes a zone's networks need.

This is the only component in Foxguard that can take away the operator's own
access to the gateway, so it is written as a list of refusals with a
reconciler attached rather than the other way round.

Why a kernel route is needed at all: ``wg syncconf`` sets cryptokey routing and
**does not touch the routing table** -- deliberately, since that is what lets
untouched peers keep their handshakes. A zone route therefore needs both halves.
``AllowedIPs`` on the carrying peer decides which peer a packet for
``192.168.10.7`` is encrypted to, and a route decides that the packet reaches
``wg0`` in the first place. With only the first, the gateway sends it out of its
default route; with only the second, the wg layer drops it as unroutable.

Four refusals, each with a test:

1. **Never a default route.** ``0.0.0.0/0`` or ``::/0`` would replace the
   gateway's own default route and cut every remote session, including the one
   that asked for it. Policy routing is the right mechanism for that and it is
   not what a route in a zone means.
2. **Never a prefix covering an address this box already uses off-tunnel.** A
   route for ``192.168.1.0/24`` on a gateway whose LAN address is
   ``192.168.1.10`` sends the operator's own SSH replies into the tunnel.
3. **Never touch a route we did not install.** If something is already there,
   it belongs to whoever put it there -- the reconciler says so and moves on.
4. **Never guess on withdrawal.** Only routes recorded in the state file are
   removed, so a restart with an empty file removes nothing rather than
   everything.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
from collections.abc import Iterable, Sequence
from pathlib import Path

from foxguard.nftables.applier import CommandRunner, SubprocessRunner

logger = logging.getLogger(__name__)

__all__ = ["RouteApplier", "RouteError", "RouteRefused", "local_addresses"]


class RouteError(RuntimeError):
    """A route could not be programmed."""


class RouteRefused(RouteError):
    """A route was rejected on safety grounds and never reached the kernel."""


def local_addresses(
    runner: CommandRunner, *, ip_path: str = "ip", exclude: str = ""
) -> list[str]:
    """Addresses configured on this box, excluding one interface.

    Used to refuse a route that would swallow an address the gateway is already
    reachable on. The tunnel interface is excluded because its own prefix is
    exactly what routes are supposed to point at.
    """
    result = runner.run([ip_path, "-json", "addr", "show"], timeout=10.0)
    if not result.ok:
        raise RouteError(f"could not read local addresses: {result.stderr.strip()}")
    try:
        interfaces = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RouteError(f"could not parse `ip -json addr show`: {exc}") from exc

    addresses: list[str] = []
    for interface in interfaces:
        if interface.get("ifname") == exclude:
            continue
        for entry in interface.get("addr_info", []):
            address = entry.get("local")
            if address:
                addresses.append(address)
    return addresses


class RouteApplier:
    def __init__(
        self,
        *,
        interface: str,
        state_file: Path | str,
        runner: CommandRunner | None = None,
        ip_path: str = "ip",
        protected: Iterable[str] = (),
        timeout: float = 15.0,
    ) -> None:
        self._interface = interface
        self._state_file = Path(state_file)
        self._runner = runner or SubprocessRunner()
        self._ip = ip_path
        #: Extra addresses that must never fall inside an installed route --
        #: the control plane's own address, typically, so a zone route can never
        #: cut the agent off from the API that would tell it to remove it.
        self._protected = tuple(protected)
        self._timeout = timeout

    # ------------------------------------------------------------------ state

    def installed(self) -> list[str]:
        """Routes this agent installed, as recorded on disk."""
        try:
            data = json.loads(self._state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(data, list):
            return []
        return [str(item) for item in data]

    def _record(self, cidrs: Sequence[str]) -> None:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(sorted(cidrs), indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        shutil.move(str(tmp), str(self._state_file))

    # ------------------------------------------------------------------ guards

    def _refusal(self, cidr: str, protected: Sequence[str]) -> str | None:
        """Why ``cidr`` must not be installed, or ``None`` if it may be."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            return f"not a network ({exc})"

        if network.prefixlen == 0:
            return (
                "it is a default route, which would replace this gateway's own "
                "and cut every remote session"
            )

        for candidate in protected:
            try:
                address = ipaddress.ip_address(str(candidate).split("/", 1)[0])
            except ValueError:
                continue
            if address.version == network.version and address in network:
                return (
                    f"it covers {address}, an address this gateway is already "
                    "reachable on -- traffic for it would be sent into the tunnel"
                )
        return None

    # ------------------------------------------------------------------ kernel

    def _run(self, argv: Sequence[str]):
        return self._runner.run(argv, timeout=self._timeout)

    @staticmethod
    def _family_flag(cidr: str) -> str:
        return "-6" if ipaddress.ip_network(cidr, strict=False).version == 6 else "-4"

    def _existing(self, cidr: str) -> str | None:
        """The route currently covering exactly ``cidr``, or ``None``."""
        result = self._run(
            [self._ip, self._family_flag(cidr), "route", "show", "exact", cidr]
        )
        if not result.ok:
            return None
        return result.stdout.strip() or None

    def _add(self, cidr: str) -> None:
        result = self._run(
            [self._ip, self._family_flag(cidr), "route", "add", cidr, "dev", self._interface]
        )
        if not result.ok:
            raise RouteError(
                f"could not add route {cidr} dev {self._interface}: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )

    def _delete(self, cidr: str) -> None:
        result = self._run(
            [self._ip, self._family_flag(cidr), "route", "del", cidr, "dev", self._interface]
        )
        if not result.ok:
            raise RouteError(
                f"could not remove route {cidr} dev {self._interface}: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )

    # ------------------------------------------------------------------- apply

    def plan(self, desired: Sequence[str]) -> tuple[list[str], list[str], list[str]]:
        """``(to_add, to_remove, refused)`` for ``desired``, touching nothing.

        The dry-run path, and what :meth:`apply` decides from.
        """
        protected = list(self._protected)
        try:
            protected += local_addresses(
                self._runner, ip_path=self._ip, exclude=self._interface
            )
        except RouteError as exc:
            # Fail closed. Not knowing which addresses this box answers on is
            # exactly the situation in which installing a route is dangerous.
            raise RouteRefused(
                f"refusing to change any route: {exc}"
            ) from exc

        wanted: list[str] = []
        refused: list[str] = []
        for cidr in desired:
            reason = self._refusal(cidr, protected)
            if reason:
                refused.append(f"{cidr}: {reason}")
                logger.error("refusing route %s because %s", cidr, reason)
                continue
            wanted.append(str(ipaddress.ip_network(cidr, strict=False)))

        known = set(self.installed())
        to_add = [cidr for cidr in wanted if cidr not in known]
        to_remove = [cidr for cidr in sorted(known) if cidr not in set(wanted)]
        return to_add, to_remove, refused

    def apply(self, desired: Sequence[str]) -> tuple[list[str], list[str], list[str]]:
        """Reconcile the kernel's routes with ``desired``.

        Returns ``(added, removed, problems)``. Problems are reported rather
        than raised: one route that will not install must not stop the others
        being withdrawn, and a half-reconciled routing table is worse than a
        fully reported one.
        """
        to_add, to_remove, problems = self.plan(desired)
        known = set(self.installed())
        added: list[str] = []
        removed: list[str] = []

        for cidr in to_remove:
            try:
                self._delete(cidr)
            except RouteError as exc:
                # Already gone counts as removed: the desired state is reached
                # either way, and keeping it in the file would mean retrying
                # forever.
                logger.warning("%s", exc)
            known.discard(cidr)
            removed.append(cidr)

        for cidr in to_add:
            existing = self._existing(cidr)
            if existing is not None:
                # Someone else put it there. It might be the operator's static
                # route to the very network we were asked to reach; replacing it
                # is not a decision an agent gets to make.
                message = (
                    f"{cidr} is already routed by something Foxguard did not "
                    f"install ({existing}); leaving it alone"
                )
                logger.warning("%s", message)
                problems.append(message)
                continue
            try:
                self._add(cidr)
            except RouteError as exc:
                logger.error("%s", exc)
                problems.append(str(exc))
                continue
            known.add(cidr)
            added.append(cidr)

        if added or removed:
            self._record(sorted(known))
        return added, removed, problems
