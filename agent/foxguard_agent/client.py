"""HTTP client for the Foxguard control plane."""

from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True, slots=True)
class WireGuardPeer:
    public_key: str
    allowed_ips: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Route:
    cidr: str
    via_peer_id: str


@dataclass(frozen=True, slots=True)
class DnsState:
    digest: str
    hosts: str
    conf: str
    hosts_path: str
    conf_path: str


@dataclass(frozen=True, slots=True)
class DesiredState:
    digest: str
    ruleset: str
    wg_interface: str
    wg_peers: tuple[WireGuardPeer, ...]
    #: Networks a peer carries, which the gateway must route into the tunnel.
    routes: tuple[Route, ...] = ()
    #: ``None`` when DNS is off, or when the control plane could not render a
    #: valid zone. Both mean "leave the resolver alone".
    dns: DnsState | None = None


class ControlPlaneClient:
    """Pull client. The agent never writes to the database directly."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 15.0) -> None:
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )

    def fetch_state(self) -> DesiredState:
        response = self._client.get("/api/v1/agent/state")
        response.raise_for_status()
        payload = response.json()
        # .get, not [], for dns: an agent may poll a control plane that predates
        # this field, and the agent is the component that gets upgraded last.
        dns = payload.get("dns")
        return DesiredState(
            digest=payload["digest"],
            ruleset=payload["ruleset"],
            wg_interface=payload["wg_interface"],
            wg_peers=tuple(
                WireGuardPeer(
                    public_key=peer["public_key"],
                    allowed_ips=tuple(peer["allowed_ips"]),
                )
                for peer in payload["wg_peers"]
            ),
            routes=tuple(
                Route(cidr=route["cidr"], via_peer_id=route["via_peer_id"])
                for route in payload.get("routes", [])
            ),
            dns=DnsState(**dns) if dns else None,
        )

    def report(
        self,
        digest: str,
        *,
        success: bool,
        error: str | None = None,
        dns_digest: str | None = None,
        dns_error: str | None = None,
    ) -> None:
        response = self._client.post(
            "/api/v1/agent/report",
            json={
                "digest": digest,
                "success": success,
                "error": error,
                "dns_digest": dns_digest,
                "dns_error": dns_error,
            },
        )
        response.raise_for_status()

    def close(self) -> None:
        self._client.close()
