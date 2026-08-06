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
class ProxyState:
    digest: str
    conf: str
    conf_path: str
    maps_dir: str
    certs_dir: str
    runtime_socket: str
    #: Pattern files the configuration references, keyed by base name. They
    #: travel with it because ``haproxy -c`` resolves ``-f`` at parse time.
    files: dict[str, str]
    #: Countries the geo map must cover, or empty when nothing uses geo. The
    #: map itself is built here rather than sent: the whole world is 1.37
    #: million prefixes and 367 MiB of HAProxy memory, the countries somebody
    #: actually named are a fraction of that, and only the gateway knows when it
    #: last refreshed its dataset.
    geo_countries: tuple[str, ...] = ()


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
    #: ``None`` when the proxy is off, or when the control plane could not
    #: render a valid configuration. Both mean "leave the proxy alone".
    proxy: ProxyState | None = None


def _proxy_state(payload: dict | None) -> ProxyState | None:
    """Build a :class:`ProxyState`, tolerating a control plane that predates a field.

    The agent is the component upgraded last, so a key it has never heard of
    must not turn a whole reconciliation into a ``TypeError``. Same reasoning as
    the ``.get`` on ``dns`` above, applied per field rather than per block.
    """
    if not payload:
        return None
    known = {name for name in ProxyState.__annotations__}
    data = {name: value for name, value in payload.items() if name in known}
    if "geo_countries" in data:
        data["geo_countries"] = tuple(data["geo_countries"])
    return ProxyState(**data)


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
        proxy = payload.get("proxy")
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
            proxy=_proxy_state(proxy),
        )

    def report(
        self,
        digest: str,
        *,
        success: bool,
        error: str | None = None,
        dns_digest: str | None = None,
        dns_error: str | None = None,
        proxy_digest: str | None = None,
        proxy_error: str | None = None,
    ) -> None:
        response = self._client.post(
            "/api/v1/agent/report",
            json={
                "digest": digest,
                "success": success,
                "error": error,
                "dns_digest": dns_digest,
                "dns_error": dns_error,
                "proxy_digest": proxy_digest,
                "proxy_error": proxy_error,
            },
        )
        response.raise_for_status()

    def close(self) -> None:
        self._client.close()
