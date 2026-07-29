"""HTTP client for the Foxguard control plane."""

from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True, slots=True)
class WireGuardPeer:
    public_key: str
    allowed_ips: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DesiredState:
    digest: str
    ruleset: str
    wg_interface: str
    wg_peers: tuple[WireGuardPeer, ...]


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
        )

    def report(self, digest: str, *, success: bool, error: str | None = None) -> None:
        response = self._client.post(
            "/api/v1/agent/report",
            json={"digest": digest, "success": success, "error": error},
        )
        response.raise_for_status()

    def close(self) -> None:
        self._client.close()
