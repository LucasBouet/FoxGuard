"""Agent configuration (environment driven)."""

from __future__ import annotations

import functools
import ipaddress
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FOXGUARD_AGENT_",
        env_file="/etc/foxguard/agent.env",
        extra="ignore",
    )

    api_url: str = "http://127.0.0.1:8000"
    api_token: SecretStr = Field(description="Must match FOXGUARD_AGENT_API_TOKEN.")
    poll_interval_seconds: float = Field(default=10.0, ge=1.0)
    request_timeout_seconds: float = 15.0

    nft_path: str = "nft"
    nft_table_name: str = "foxguard"
    wg_path: str = "wg"
    ip_path: str = "ip"
    manage_routes: bool = Field(
        default=True,
        description=(
            "Install the kernel routes a zone's networks need. Turn off to "
            "manage them yourself; the AllowedIPs half is still programmed, so "
            "an `ip route add <cidr> dev wg0` by hand completes the path."
        ),
    )
    manage_wireguard: bool = Field(
        default=True,
        description="Sync WireGuard peers as well as nftables. Turn off if wg is managed elsewhere.",
    )

    dnsmasq_path: str = "dnsmasq"
    systemctl_path: str = "systemctl"
    dns_service: str = "foxguard-dns"
    manage_dns: bool = Field(
        default=True,
        description=(
            "Apply the DNS zone the control plane renders. Has no effect unless "
            "FOXGUARD_DNS_ENABLED is on there; turn it off to run the resolver "
            "from somewhere else."
        ),
    )
    #: Must match FOXGUARD_DNS_HOSTS_PATH / FOXGUARD_DNS_CONF_PATH on the API,
    #: because the rendered configuration refers to the hosts file by path.
    dns_dir: Path = Path("/etc/foxguard/dns")

    haproxy_path: str = "haproxy"
    proxy_service: str = "foxguard-proxy"
    manage_proxy: bool = Field(
        default=True,
        description=(
            "Apply the HAProxy configuration the control plane renders. Has no "
            "effect unless FOXGUARD_PROXY_ENABLED is on there; turn it off to "
            "run the proxy from somewhere else."
        ),
    )
    #: Must match FOXGUARD_PROXY_CONF_PATH / FOXGUARD_PROXY_MAPS_DIR on the API:
    #: the rendered configuration refers to its pattern files by absolute path.
    proxy_dir: Path = Path("/etc/foxguard/proxy")
    proxy_runtime_socket: Path = Path("/run/foxguard/haproxy.sock")

    state_dir: Path = Path("/var/lib/foxguard")
    #: Render and validate but never apply. Useful for a first dry deployment.
    dry_run: bool = False
    log_level: str = "INFO"

    @property
    def last_good_path(self) -> Path:
        return self.state_dir / "last-good.nft"

    @property
    def routes_state_path(self) -> Path:
        """Which routes this agent installed.

        Without it, withdrawal would have to guess, and the only safe guess is
        "remove nothing" -- so the file is what makes a zone route removable.
        """
        return self.state_dir / "routes.json"

    @property
    def api_address(self) -> str | None:
        """The control plane's address, when it is a literal IP.

        Passed to the route applier as protected: a zone route that swallowed
        it would cut the agent off from the API that could tell it to remove
        the route, and nothing short of console access would fix that.
        """
        from urllib.parse import urlparse

        host = urlparse(self.api_url).hostname
        if not host:
            return None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return None
        return host

    @property
    def dns_hosts_path(self) -> Path:
        return self.dns_dir / "hosts"

    @property
    def dns_conf_path(self) -> Path:
        return self.dns_dir / "dnsmasq.conf"

    @property
    def proxy_conf_path(self) -> Path:
        return self.proxy_dir / "haproxy.cfg"

    @property
    def proxy_maps_dir(self) -> Path:
        return self.proxy_dir / "maps"

    @property
    def geo_dataset_path(self) -> Path:
        """The downloaded dataset. State, not configuration.

        Under ``state_dir`` because it is a cache of somebody else's data that
        the agent replaces wholesale every month, not something an operator
        edits -- and because nothing breaks if it is deleted.
        """
        return self.state_dir / "dbip-country-lite.csv.gz"

    @property
    def geo_map_path(self) -> Path:
        """The built map, which lives beside the other pattern files.

        Its name is deliberately outside the prefixes the applier treats as
        Foxguard-rendered: it is built here rather than sent by the control
        plane, so the reconcile loop must not see it as an unexpected file and
        delete it.
        """
        return self.proxy_maps_dir / "geo.map"


@functools.lru_cache
def get_agent_settings() -> AgentSettings:
    return AgentSettings()
