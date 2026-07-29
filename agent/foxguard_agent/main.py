"""Agent entry point: poll, reconcile, report.

Reconciliation is level-triggered, not edge-triggered: every pass applies the
full desired state. A missed poll, an agent restart or a hand-edited ruleset all
converge on the next tick instead of leaving the gateway in a half state.
"""

from __future__ import annotations

import logging
import signal
import sys
import time
from collections.abc import Callable
from types import FrameType

import httpx
from foxguard.nftables.applier import NftApplier, NftError

from .client import ControlPlaneClient, DesiredState
from .config import AgentSettings, get_agent_settings
from .wireguard import WireGuardError, WireGuardManager

logger = logging.getLogger("foxguard.agent")

_running = True


def _stop(signum: int, _frame: FrameType | None) -> None:
    global _running
    logger.info("received signal %s, shutting down", signum)
    _running = False


def reconcile(
    state: DesiredState,
    applier: NftApplier,
    wireguard: WireGuardManager | None,
    *,
    dry_run: bool,
) -> str | None:
    """Apply one desired state. Returns an error message, or None on success."""
    try:
        if dry_run:
            applier.validate(state.ruleset)
            logger.info("dry run: ruleset %s validated, not applied", state.digest[:12])
        else:
            applier.apply(state.ruleset)
            logger.info("applied ruleset %s", state.digest[:12])
    except NftError as exc:
        logger.error("nftables reconciliation failed: %s", exc)
        return str(exc)

    if wireguard is not None and not dry_run:
        try:
            changed = wireguard.sync(state.wg_peers)
            if changed:
                logger.info("synced %d WireGuard peers", len(state.wg_peers))
        except WireGuardError as exc:
            logger.error("WireGuard reconciliation failed: %s", exc)
            return str(exc)

    return None


def run_once(
    client: ControlPlaneClient,
    applier: NftApplier,
    wireguard_for: Callable[[str], WireGuardManager | None],
    settings: AgentSettings,
    last_digest: str | None,
) -> str | None:
    """One poll cycle. Returns the digest now live on this box."""
    state = client.fetch_state()

    if state.digest == last_digest:
        logger.debug("no change (%s)", state.digest[:12])
        return last_digest

    error = reconcile(
        state, applier, wireguard_for(state.wg_interface), dry_run=settings.dry_run
    )
    try:
        client.report(state.digest, success=error is None, error=error)
    except httpx.HTTPError as exc:
        logger.warning("could not report back to the control plane: %s", exc)

    # On failure, keep the previous digest so the next tick retries instead of
    # assuming the box is in the desired state.
    return last_digest if error else state.digest


def main() -> int:
    settings = get_agent_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    settings.state_dir.mkdir(parents=True, exist_ok=True)

    client = ControlPlaneClient(
        settings.api_url,
        settings.api_token.get_secret_value(),
        timeout=settings.request_timeout_seconds,
    )
    applier = NftApplier(
        nft_path=settings.nft_path,
        table_name=settings.nft_table_name,
        state_file=settings.last_good_path,
    )

    last_digest: str | None = None
    managers: dict[str, WireGuardManager] = {}

    def wireguard_for(interface: str) -> WireGuardManager | None:
        # The interface name comes from the control plane, so renaming it there
        # does not require touching the agent's configuration.
        if not settings.manage_wireguard:
            return None
        if interface not in managers:
            managers[interface] = WireGuardManager(interface, wg_path=settings.wg_path)
        return managers[interface]

    logger.info(
        "foxguard agent starting (api=%s, dry_run=%s)", settings.api_url, settings.dry_run
    )
    while _running:
        try:
            last_digest = run_once(client, applier, wireguard_for, settings, last_digest)
        except httpx.HTTPError as exc:
            logger.warning("control plane unreachable: %s", exc)
        except Exception:
            logger.exception("unexpected error during reconciliation")

        for _ in range(int(settings.poll_interval_seconds * 10)):
            if not _running:
                break
            time.sleep(0.1)

    client.close()
    logger.info("foxguard agent stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
