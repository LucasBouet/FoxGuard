"""Agent entry point: poll, reconcile, report.

Reconciliation is level-triggered, not edge-triggered: every pass applies the
full desired state. A missed poll, an agent restart or a hand-edited ruleset all
converge on the next tick instead of leaving the gateway in a half state.

The three subsystems -- nftables, WireGuard and DNS -- are reconciled
independently and tracked by separate digests. That is not tidiness: a resolver
that will not reload must not stop firewall rules being applied, and a peer
added to the zone must not be skipped because the ruleset happened not to
change.
"""

from __future__ import annotations

import logging
import signal
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import FrameType

import httpx
from foxguard.nftables.applier import NftApplier, NftError

from .client import ControlPlaneClient, DesiredState, DnsState, ProxyState
from .config import AgentSettings, get_agent_settings
from .dns import DnsApplier, DnsError
from .proxy import ProxyApplier, ProxyError
from .routes import RouteApplier, RouteError
from .wireguard import WireGuardError, WireGuardManager

logger = logging.getLogger("foxguard.agent")

_running = True


@dataclass(frozen=True, slots=True)
class Applied:
    """What is live on this box, per subsystem.

    ``None`` means "not known to be applied", which is also what a failure
    leaves behind, so the next tick retries rather than assuming success.
    """

    ruleset: str | None = None
    dns: str | None = None
    proxy: str | None = None


def _stop(signum: int, _frame: FrameType | None) -> None:
    global _running
    logger.info("received signal %s, shutting down", signum)
    _running = False


def reconcile(
    state: DesiredState,
    applier: NftApplier,
    wireguard: WireGuardManager | None,
    router: RouteApplier | None,
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

    if router is not None:
        # After WireGuard, always: a route pointing into the tunnel before the
        # carrying peer's AllowedIPs exist is a black hole for as long as the
        # window lasts.
        desired = [route.cidr for route in state.routes]
        try:
            if dry_run:
                to_add, to_remove, refused = router.plan(desired)
                logger.info(
                    "dry run: routes +%s -%s (refused: %s)", to_add, to_remove, refused
                )
                if refused:
                    return "; ".join(refused)
            else:
                added, removed, problems = router.apply(desired)
                if added or removed:
                    logger.info("routes: added %s, removed %s", added, removed)
                if problems:
                    return "; ".join(problems)
        except RouteError as exc:
            logger.error("route reconciliation failed: %s", exc)
            return str(exc)

    return None


def reconcile_dns(
    dns: DnsState, applier: DnsApplier, *, dry_run: bool
) -> str | None:
    """Apply one DNS zone. Returns an error message, or None on success."""
    try:
        if dry_run:
            applier.check(dns.conf)
            logger.info("dry run: DNS zone %s validated, not applied", dns.digest[:12])
        else:
            action = applier.apply(dns.hosts, dns.conf)
            logger.info("DNS zone %s %s", dns.digest[:12], action)
    except DnsError as exc:
        logger.error("DNS reconciliation failed: %s", exc)
        return str(exc)
    return None


def reconcile_proxy(
    proxy: ProxyState, applier: ProxyApplier, *, dry_run: bool
) -> str | None:
    """Apply one proxy configuration. Returns an error message, or None."""
    try:
        if dry_run:
            applier.check(proxy.conf, proxy.files)
            logger.info(
                "dry run: proxy configuration %s validated, not applied",
                proxy.digest[:12],
            )
        else:
            action = applier.apply(proxy.conf, proxy.files)
            logger.info("proxy configuration %s %s", proxy.digest[:12], action)
    except ProxyError as exc:
        logger.error("proxy reconciliation failed: %s", exc)
        return str(exc)
    return None


def run_once(
    client: ControlPlaneClient,
    applier: NftApplier,
    wireguard_for: Callable[[str], WireGuardManager | None],
    router_for: Callable[[str], RouteApplier | None],
    dns_applier: DnsApplier | None,
    proxy_applier: ProxyApplier | None,
    settings: AgentSettings,
    applied: Applied,
) -> Applied:
    """One poll cycle. Returns what is live on this box afterwards."""
    state = client.fetch_state()

    ruleset_error: str | None = None
    ruleset_digest = applied.ruleset
    ruleset_changed = state.digest != applied.ruleset
    if ruleset_changed:
        # Routes ride with the ruleset digest rather than having their own:
        # adding or removing one changes a zone's nft set, so the digest already
        # moves exactly when the routes do.
        ruleset_error = reconcile(
            state,
            applier,
            wireguard_for(state.wg_interface),
            router_for(state.wg_interface),
            dry_run=settings.dry_run,
        )
        # On failure keep the previous digest, so the next tick retries instead
        # of assuming the box is in the desired state.
        ruleset_digest = applied.ruleset if ruleset_error else state.digest
    else:
        logger.debug("no ruleset change (%s)", state.digest[:12])

    dns_error: str | None = None
    dns_digest = applied.dns
    dns_changed = False
    if (
        dns_applier is not None
        and state.dns is not None
        and state.dns.digest != applied.dns
    ):
        dns_changed = True
        dns_error = reconcile_dns(state.dns, dns_applier, dry_run=settings.dry_run)
        dns_digest = applied.dns if dns_error else state.dns.digest

    proxy_error: str | None = None
    proxy_digest = applied.proxy
    proxy_changed = False
    if (
        proxy_applier is not None
        and state.proxy is not None
        and state.proxy.digest != applied.proxy
    ):
        proxy_changed = True
        proxy_error = reconcile_proxy(
            state.proxy, proxy_applier, dry_run=settings.dry_run
        )
        proxy_digest = applied.proxy if proxy_error else state.proxy.digest

    if ruleset_changed or dns_changed or proxy_changed:
        try:
            client.report(
                state.digest,
                success=ruleset_error is None,
                error=ruleset_error,
                dns_digest=state.dns.digest if state.dns else None,
                dns_error=dns_error,
                proxy_digest=state.proxy.digest if state.proxy else None,
                proxy_error=proxy_error,
            )
        except httpx.HTTPError as exc:
            logger.warning("could not report back to the control plane: %s", exc)

    return Applied(ruleset=ruleset_digest, dns=dns_digest, proxy=proxy_digest)


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
    dns_applier = (
        DnsApplier(
            hosts_path=settings.dns_hosts_path,
            conf_path=settings.dns_conf_path,
            dnsmasq_path=settings.dnsmasq_path,
            systemctl_path=settings.systemctl_path,
            service=settings.dns_service,
        )
        if settings.manage_dns
        else None
    )

    proxy_applier = (
        ProxyApplier(
            conf_path=settings.proxy_conf_path,
            maps_dir=settings.proxy_maps_dir,
            runtime_socket=settings.proxy_runtime_socket,
            haproxy_path=settings.haproxy_path,
            systemctl_path=settings.systemctl_path,
            service=settings.proxy_service,
        )
        if settings.manage_proxy
        else None
    )

    applied = Applied()
    managers: dict[str, WireGuardManager] = {}
    routers: dict[str, RouteApplier] = {}

    def wireguard_for(interface: str) -> WireGuardManager | None:
        # The interface name comes from the control plane, so renaming it there
        # does not require touching the agent's configuration.
        if not settings.manage_wireguard:
            return None
        if interface not in managers:
            managers[interface] = WireGuardManager(interface, wg_path=settings.wg_path)
        return managers[interface]

    def router_for(interface: str) -> RouteApplier | None:
        if not settings.manage_routes:
            return None
        if interface not in routers:
            routers[interface] = RouteApplier(
                interface=interface,
                state_file=settings.routes_state_path,
                ip_path=settings.ip_path,
                protected=[a for a in (settings.api_address,) if a],
            )
        return routers[interface]

    logger.info(
        "foxguard agent starting (api=%s, dry_run=%s, dns=%s, routes=%s, proxy=%s)",
        settings.api_url,
        settings.dry_run,
        "on" if dns_applier else "off",
        "on" if settings.manage_routes else "off",
        "on" if proxy_applier else "off",
    )
    while _running:
        try:
            applied = run_once(
                client,
                applier,
                wireguard_for,
                router_for,
                dns_applier,
                proxy_applier,
                settings,
                applied,
            )
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
