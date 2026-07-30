"""Runtime configuration.

Everything is environment-driven (12-factor) so the same image runs in dev and
on the gateway. Nothing security-sensitive has a usable default: the API
refuses to start without explicit tokens unless ``dev_mode`` is on.
"""

from __future__ import annotations

import functools
import ipaddress
import json
import logging
from typing import Annotated, Any

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from .dns.model import NAME_RE, DnsSpec, ResolverMode
from .nftables.model import GatewayInputPolicy, GatewaySpec

logger = logging.getLogger(__name__)


def _split_list(value: Any) -> Any:
    """Accept both JSON lists and ``a,b,c`` in environment variables.

    ``NoDecode`` on the field turns off pydantic-settings' own JSON handling, so
    both forms are decoded here -- otherwise the comma-separated form documented
    in ``.env.example`` raises a SettingsError before any validator runs.
    """
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith("["):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"expected a JSON list, got {stripped!r}: {exc}") from exc
        return [item.strip() for item in stripped.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FOXGUARD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- general -----------------------------------------------------------
    dev_mode: bool = Field(
        default=False,
        description="Relaxes token requirements. Never enable on the gateway.",
    )
    log_level: str = "INFO"

    # --- database ----------------------------------------------------------
    # PostgreSQL only, dev and prod alike -- no SQLite fallback, on purpose.
    database_url: str = "postgresql+psycopg://foxguard:foxguard@localhost:5432/foxguard"

    # --- authentication ----------------------------------------------------
    admin_api_token: SecretStr | None = Field(
        default=None,
        description=(
            "Shared bearer token for machine access to the admin API "
            "(provisioning scripts, CI). People sign in instead, which is what "
            "gives the audit log a name; actions taken with this token are "
            "recorded as 'admin-token'."
        ),
    )
    #: How long an administrator stays signed in.
    admin_session_lifetime_seconds: int = Field(default=12 * 3600, ge=300)
    #: Throttling for admin sign-in, keyed on the source address.
    admin_login_max_attempts: int = Field(default=10, ge=1)
    admin_login_window_seconds: int = Field(default=300, ge=1)
    agent_api_token: SecretStr | None = Field(
        default=None, description="Bearer token used by the gateway agent."
    )

    # --- WireGuard / IPAM --------------------------------------------------
    wg_interface: str = "wg0"
    wg_listen_port: int = 51820
    wg_public_key: str | None = None
    wg_endpoint_host: str | None = None
    wg_config_path: str = "/etc/wireguard/wg0.conf"
    #: Address pool for enrolled peers.
    wg_pool_v4: str = "10.88.0.0/24"
    wg_pool_v6: str | None = None
    #: Pool for peers that have registered a public key but not yet presented a
    #: valid enrollment key. Kept separate so quarantine is visible in `wg show`.
    wg_staging_pool_v4: str | None = None
    wg_staging_pool_v6: str | None = None
    #: Gateway address inside the tunnel. Defaults to the first host of the pool.
    wg_gateway_ip: str | None = None

    # --- dataplane ---------------------------------------------------------
    nft_table_name: str = "foxguard"
    nft_path: str = "nft"
    wan_interface: str | None = None
    portal_port: int = 8080
    # NoDecode is required: without it pydantic-settings JSON-decodes list-typed
    # fields inside the env source, before any validator runs, and the
    # documented `a,b,c` form raises a SettingsError at import time.
    internal_cidrs: Annotated[list[str], NoDecode] = Field(default_factory=list)
    allow_dns_in_quarantine: bool = True
    allow_icmp_to_gateway: bool = True
    gateway_input_policy: GatewayInputPolicy = GatewayInputPolicy.OPEN
    log_dropped: bool = True

    # --- internal DNS (Phase 5) --------------------------------------------
    #: Off by default. Turning it on makes the gateway a resolver for the
    #: tunnel, which is a service an existing deployment did not ask for.
    dns_enabled: bool = False
    #: The zone every peer and record lives in. Use a name you control or one
    #: reserved for the purpose; ``.local`` is mDNS and will fight with it.
    dns_zone: str = "fox.internal"
    #: Label the gateway answers to inside the zone.
    dns_gateway_label: str = "gw"
    #: ``forward`` resolves everything and sends the rest upstream, which is
    #: what makes ``DNS = <gateway>`` in a client config work on its own.
    #: ``split`` answers for the zone and REFUSES the rest, which only works if
    #: the client is configured to send just in-zone queries here.
    dns_mode: ResolverMode = ResolverMode.FORWARD
    dns_upstreams: Annotated[list[str], NoDecode] = Field(default_factory=list)
    dns_port: int = Field(default=53, ge=1, le=65535)
    #: Defaults to the gateway's own tunnel address. Never set this to a WAN
    #: address: it would publish an open resolver.
    dns_listen_addresses: Annotated[list[str], NoDecode] = Field(default_factory=list)
    #: Where the agent writes the artefacts. Part of the rendered configuration
    #: (``addn-hosts=``), so it is the control plane that decides it.
    dns_hosts_path: str = "/etc/foxguard/dns/hosts"
    dns_conf_path: str = "/etc/foxguard/dns/dnsmasq.conf"
    dns_cache_size: int = Field(default=1000, ge=0)
    dns_stop_dns_rebind: bool = False
    dns_log_queries: bool = False
    #: Raw dnsmasq options, appended verbatim. Operator-supplied escape hatch;
    #: each entry must be a single ``name`` or ``name=value`` line.
    dns_extra_options: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- sessions (Phase 3) ------------------------------------------------
    default_session_lifetime_seconds: int = 8 * 3600
    enrollment_key_bytes: int = 32
    #: Turning this off means user peers stay active until they log out or an
    #: admin intervenes. Only sensible if an external cron drives
    #: POST /api/v1/sessions/sweep instead.
    session_sweep_enabled: bool = True
    #: How often the sweeper looks for expired sessions. This is the granularity
    #: of expiry, not its accuracy: a 4h lifetime ends within one interval of 4h.
    session_sweep_interval_seconds: int = Field(default=60, ge=5)

    # --- portal / enrollment (Phase 2) -------------------------------------
    #: Throttling for the two endpoints a confined peer can already reach.
    #: Counted per source tunnel address, failures only. See services/ratelimit.
    portal_login_max_attempts: int = Field(default=10, ge=1)
    portal_login_window_seconds: int = Field(default=300, ge=1)
    enroll_max_attempts: int = Field(default=10, ge=1)
    enroll_window_seconds: int = Field(default=300, ge=1)
    #: Shown in the authenticator app next to the account name.
    totp_issuer: str = "Foxguard"
    #: Directory holding the built captive-portal bundle. When set, it is served
    #: at "/" by this same app, which is the only arrangement that keeps peer
    #: identification working -- see api/static.py.
    portal_static_dir: str | None = None

    # --- OIDC (Phase 2, entirely optional) ---------------------------------
    # Foxguard must stay fully usable with no IdP configured, so every field
    # defaults to None and `oidc_enabled` is false until all of them are set.
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    #: Absolute URL of the callback, as registered with the IdP. It must resolve
    #: to the portal *inside the tunnel*.
    oidc_redirect_url: str | None = None
    oidc_scopes: str = "openid profile email"
    #: How long an in-flight authorisation request stays valid.
    oidc_transaction_ttl_seconds: int = Field(default=600, ge=30)
    #: Where to send the browser after a successful callback. Unset -> the
    #: callback answers with JSON, which is what the tests and API clients use.
    oidc_post_login_redirect: str | None = None
    #: Redirect URI for *administrator* sign-in, pointing at the dashboard's own
    #: callback route rather than at the API. The dashboard finishes the exchange
    #: server-side, so the session token lands in its httpOnly cookie instead of
    #: travelling through a URL. Unset -> admin SSO is off even if the portal's
    #: OIDC is configured.
    oidc_admin_redirect_url: str | None = None

    @field_validator(
        "internal_cidrs",
        "dns_upstreams",
        "dns_listen_addresses",
        "dns_extra_options",
        mode="before",
    )
    @classmethod
    def _parse_internal_cidrs(cls, value: Any) -> Any:
        return _split_list(value)

    @field_validator("dns_zone")
    @classmethod
    def _validate_dns_zone(cls, value: str) -> str:
        """A bad zone is a configuration mistake, so it fails at startup.

        Unlike the pool checks below, nothing about this needs to see the
        gateway: either the string is a DNS name or it is not.
        """
        candidate = value.strip().rstrip(".").lower()
        if not candidate or not NAME_RE.match(candidate) or len(candidate) > 253:
            raise ValueError(
                f"FOXGUARD_DNS_ZONE {value!r} is not a valid DNS name "
                "(lowercase letters, digits and hyphens, dot-separated)"
            )
        return candidate

    @field_validator("internal_cidrs")
    @classmethod
    def _validate_internal_cidrs(cls, value: list[str]) -> list[str]:
        for cidr in value:
            ipaddress.ip_network(cidr, strict=False)
        return value

    @field_validator("wg_pool_v4", "wg_staging_pool_v4")
    @classmethod
    def _validate_v4_pool(cls, value: str | None) -> str | None:
        if value is None:
            return None
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4:
            raise ValueError(f"{value} is not an IPv4 network")
        return str(network)

    @field_validator("wg_pool_v6", "wg_staging_pool_v6")
    @classmethod
    def _validate_v6_pool(cls, value: str | None) -> str | None:
        if value is None:
            return None
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 6:
            raise ValueError(f"{value} is not an IPv6 network")
        return str(network)

    @model_validator(mode="after")
    def _warn_if_staging_pool_looks_unroutable(self) -> Settings:
        """Flag a staging pool that sits outside the main pool.

        Foxguard programs peers with ``wg syncconf``, which sets the crypto
        configuration and **does not touch the routing table** -- deliberately,
        because that is what lets untouched peers keep their handshakes. The
        only route to the tunnel is therefore the connected one implied by the
        interface's own address, e.g. ``10.88.0.1/24`` covering ``10.88.0.0/24``.

        Give a peer an address outside that prefix and the gateway sends its
        replies out of the default route instead: the handshake succeeds and
        nothing else works. Measured: with the interface on ``10.13.37.1/24``,
        ``ip route get 10.13.38.1`` resolves via ``eth0``, not the tunnel.

        A warning rather than a startup error, because the invariant that
        actually matters is *"every pool is covered by the interface's prefix"*,
        and this process may not be able to see the interface -- the control
        plane is allowed to run somewhere other than the gateway. A wide
        interface (``10.13.0.1/16``) routes two sibling ``/24``s perfectly well.
        All that can be said from configuration alone is that a staging pool
        outside the main pool is unusual enough to name. The authoritative check
        runs where the interface is: installer preflight and
        ``deploy/foxguard-healthcheck.sh``.
        """
        for staging, main, label in (
            (self.wg_staging_pool_v4, self.wg_pool_v4, "V4"),
            (self.wg_staging_pool_v6, self.wg_pool_v6, "V6"),
        ):
            if not staging:
                continue
            if not main:
                logger.warning(
                    "FOXGUARD_WG_STAGING_POOL_%s is set but FOXGUARD_WG_POOL_%s "
                    "is not, so every peer is allocated out of the staging pool.",
                    label,
                    label,
                )
                continue
            staging_net = ipaddress.ip_network(staging, strict=False)
            main_net = ipaddress.ip_network(main, strict=False)
            if not staging_net.subnet_of(main_net):
                logger.warning(
                    "FOXGUARD_WG_STAGING_POOL_%s (%s) is not inside "
                    "FOXGUARD_WG_POOL_%s (%s). Peers are allocated there at "
                    "registration and never move, so unless %s's own address "
                    "covers both ranges they are unroutable: wg syncconf adds "
                    "no routes, and the only route to the tunnel is the one the "
                    "interface address implies. Run foxguard-healthcheck.sh on "
                    "the gateway to find out. Dropping the staging pool costs "
                    "nothing -- an address never changes after registration, so "
                    "a separate range does not mark confinement.",
                    label,
                    staging_net,
                    label,
                    main_net,
                    self.wg_interface,
                )
        return self

    @model_validator(mode="after")
    def _check_secrets(self) -> Settings:
        if not self.dev_mode:
            missing = [
                name
                for name, value in (
                    ("FOXGUARD_ADMIN_API_TOKEN", self.admin_api_token),
                    ("FOXGUARD_AGENT_API_TOKEN", self.agent_api_token),
                )
                if value is None or not value.get_secret_value()
            ]
            if missing:
                raise ValueError(
                    "missing required secrets: "
                    + ", ".join(missing)
                    + " (set FOXGUARD_DEV_MODE=true only for local development)"
                )
        return self

    # --- derived -----------------------------------------------------------

    @property
    def gateway_ip(self) -> str:
        if self.wg_gateway_ip:
            return self.wg_gateway_ip
        network = ipaddress.ip_network(self.wg_pool_v4, strict=False)
        return str(next(network.hosts()))

    @property
    def oidc_enabled(self) -> bool:
        """True only when the whole OIDC quartet is configured.

        Half-configured is treated as off rather than as an error: the portal
        must keep serving local logins on a box where someone started wiring an
        IdP and stopped.
        """
        return all(
            (
                self.oidc_issuer,
                self.oidc_client_id,
                self.oidc_client_secret and self.oidc_client_secret.get_secret_value(),
                self.oidc_redirect_url,
            )
        )

    @property
    def oidc_admin_enabled(self) -> bool:
        """Admin SSO needs its own redirect URI on top of a working IdP."""
        return self.oidc_enabled and bool(self.oidc_admin_redirect_url)

    @property
    def tunnel_pools(self) -> tuple[str, ...]:
        return tuple(
            pool
            for pool in (
                self.wg_pool_v4,
                self.wg_pool_v6,
                self.wg_staging_pool_v4,
                self.wg_staging_pool_v6,
            )
            if pool
        )

    def is_tunnel_address(self, address: str) -> bool:
        """Is ``address`` inside one of the WireGuard pools?

        Defence in depth for the portal and the enrollment endpoint, which
        identify their caller by source address. That identification is sound
        *only* for packets that arrived on the tunnel: WireGuard's
        cryptokey routing means a peer cannot send from an address outside its
        own ``AllowedIPs``, so inside wg0 the source address is as trustworthy
        as the peer's key.

        Nothing in an ASGI scope says which interface a packet came in on, so we
        check the next best thing -- that the address belongs to a pool we
        allocate from. A request from the LAN or the WAN fails this immediately,
        and an off-tunnel attacker who forges a pool address cannot complete a
        TCP handshake, because the replies are routed into the tunnel.
        """
        try:
            candidate = ipaddress.ip_address(address)
        except ValueError:
            return False
        for pool in self.tunnel_pools:
            network = ipaddress.ip_network(pool, strict=False)
            if candidate.version == network.version and candidate in network:
                return True
        return False

    @property
    def dns_listen(self) -> tuple[str, ...]:
        """Addresses the resolver binds to.

        Defaults to the gateway's own tunnel address rather than to everything:
        the failure mode of guessing wide here is an open resolver on the WAN,
        and the failure mode of guessing narrow is a resolver that answers only
        inside the tunnel -- which is the whole point.
        """
        if self.dns_listen_addresses:
            return tuple(self.dns_listen_addresses)
        return (self.gateway_ip,)

    def dns_base_spec(self) -> DnsSpec:
        """Project settings onto a DNS spec with no records in it yet.

        ``services/dns.py`` fills in the hosts and aliases from the database,
        exactly as ``services/ruleset.py`` fills in peers and rules.
        """
        return DnsSpec(
            zone=self.dns_zone,
            listen_addresses=self.dns_listen,
            port=self.dns_port,
            hosts_path=self.dns_hosts_path,
            mode=self.dns_mode,
            upstreams=tuple(self.dns_upstreams),
            cache_size=self.dns_cache_size,
            reverse_pools=self.tunnel_pools,
            stop_dns_rebind=self.dns_stop_dns_rebind,
            log_queries=self.dns_log_queries,
            extra_options=tuple(self.dns_extra_options),
        )

    def gateway_spec(self) -> GatewaySpec:
        """Project settings onto the pure dataplane spec used by the generator."""
        return GatewaySpec(
            wg_interface=self.wg_interface,
            wan_interface=self.wan_interface,
            table_name=self.nft_table_name,
            portal_port=self.portal_port,
            internal_cidrs=tuple(self.internal_cidrs),
            allow_dns_in_quarantine=self.allow_dns_in_quarantine,
            allow_icmp_to_gateway=self.allow_icmp_to_gateway,
            gateway_input_policy=self.gateway_input_policy,
            log_dropped=self.log_dropped,
        )


@functools.lru_cache
def get_settings() -> Settings:
    return Settings()
