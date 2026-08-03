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

from .clientconfig import AllowedIpsMode, join_endpoint
from .dns.model import NAME_RE, DnsSpec, ResolverMode
from .nftables.model import GatewayInputPolicy, GatewaySpec
from .proxy.model import ProxySpec

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

    # --- reverse proxy (Phase 6) -------------------------------------------
    #: Off by default, like the resolver: turning it on makes the gateway
    #: terminate traffic from strangers, which an existing deployment did not
    #: ask for.
    proxy_enabled: bool = False
    #: The real domain services live under. Peer names stay on ``dns_zone``
    #: (``laptop.fox.internal``); services need a name a public CA will sign,
    #: which ``.internal`` can never be. Two namespaces, no collision.
    proxy_domain: str | None = None
    #: Tunnel addresses the internal listener binds. Defaults to the gateway's
    #: own tunnel address. This is the *only* listener on which a source
    #: address is an identity.
    proxy_internal_binds: Annotated[list[str], NoDecode] = Field(default_factory=list)
    #: WAN addresses the external listener binds. Empty means no external
    #: exposure is possible, and a service asking for it is refused.
    proxy_external_binds: Annotated[list[str], NoDecode] = Field(default_factory=list)
    proxy_internal_https_port: int = Field(default=443, ge=1, le=65535)
    proxy_external_https_port: int = Field(default=443, ge=1, le=65535)
    #: Plain HTTP on the WAN exists only to redirect. ACME uses DNS-01, so
    #: nothing is ever served here.
    proxy_external_http_port: int = Field(default=80, ge=1, le=65535)
    #: Range plain-TCP services are allocated a dedicated port from. Plain TCP
    #: has neither SNI nor a Host header, so it cannot share one.
    proxy_tcp_port_start: int = Field(default=20000, ge=1, le=65535)
    proxy_tcp_port_end: int = Field(default=20999, ge=1, le=65535)

    proxy_conf_path: str = "/etc/foxguard/proxy/haproxy.cfg"
    proxy_certs_dir: str = "/etc/foxguard/proxy/certs"
    proxy_maps_dir: str = "/etc/foxguard/proxy/maps"
    #: HAProxy caps a stats socket path at 97 characters -- measured, it is a
    #: fatal parse error rather than a warning.
    proxy_runtime_socket: str = "/run/foxguard/haproxy.sock"

    proxy_hsts_max_age: int = Field(default=31536000, ge=0)
    #: Hands every upstream the names of every group the caller belongs to.
    #: Off by default because that is more than most upstreams need to know.
    proxy_send_group_header: bool = False
    #: The kill switch stops internal services by default and leaves external
    #: ones serving. Worth knowing: it disables *peers*, so an upstream behind
    #: a disabled peer stops answering either way -- this only really changes
    #: behaviour for services the gateway hosts itself.
    proxy_killswitch_stops_internal: bool = True
    proxy_killswitch_stops_external: bool = False

    proxy_connect_timeout_seconds: int = Field(default=5, ge=1)
    proxy_client_timeout_seconds: int = Field(default=60, ge=1)
    proxy_server_timeout_seconds: int = Field(default=60, ge=1)
    #: Long on purpose: a passthrough session is often a shell someone is
    #: typing in, and a short tunnel timeout would drop it mid-command.
    proxy_tunnel_timeout_seconds: int = Field(default=3600, ge=1)
    #: Raw HAProxy stanzas, appended verbatim. Same escape hatch as
    #: ``dns_extra_options`` and the same rule: one line each.
    proxy_extra_options: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- single sign-on for published services (Phase 7c) -------------------
    #: Signs the session cookie. The proxy verifies with the same value, so it
    #: is rendered into the HAProxy configuration -- which is why that file is
    #: 0640 root:haproxy and why rotating this signs everybody out.
    proxy_sso_secret: SecretStr | None = None
    proxy_sso_cookie_name: str = "fg_sso"
    #: How long a browser session lasts. Short by default: the proxy verifies
    #: the token on its own, so an unrevoked one stays good until it expires,
    #: and the revocation list is the only thing that shortens it.
    proxy_sso_lifetime_seconds: int = Field(default=8 * 3600, ge=60)
    #: Host name the login page answers on. Defaults to ``auth.<proxy_domain>``.
    #: This vhost is the ONLY place the proxy is ever put in front of the
    #: Foxguard API, and only ``/api/v1/sso/`` is routed there.
    proxy_sso_hostname: str | None = None

    # --- client configuration (Phase 6) ------------------------------------
    #: What a generated client config puts in ``AllowedIPs``. See
    #: :class:`~foxguard.clientconfig.AllowedIpsMode`.
    client_config_allowed_ips: AllowedIpsMode = AllowedIpsMode.ROUTED
    #: Appended to every generated config whatever the mode. The escape hatch
    #: for a network Foxguard does not model as a zone route.
    client_config_extra_allowed_ips: Annotated[list[str], NoDecode] = Field(
        default_factory=list
    )
    #: 0 disables the line. 25 is the value that keeps a NAT binding alive
    #: without being noticeable; a device on a public address does not need it.
    client_config_keepalive: int = Field(default=25, ge=0, le=65535)
    #: Left unset, no MTU line is written and wg-quick works it out. Set it when
    #: the path is doing PMTU badly -- 1420 is the usual answer over Ethernet.
    client_config_mtu: int | None = Field(default=None, ge=576, le=9000)
    #: Whether generated configs point the device at the internal resolver.
    #: Ignored when the resolver is off.
    client_config_dns: bool = True

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
        "client_config_extra_allowed_ips",
        "proxy_internal_binds",
        "proxy_external_binds",
        "proxy_extra_options",
        mode="before",
    )
    @classmethod
    def _parse_internal_cidrs(cls, value: Any) -> Any:
        return _split_list(value)

    @field_validator("client_config_extra_allowed_ips")
    @classmethod
    def _validate_extra_allowed_ips(cls, value: list[str]) -> list[str]:
        """Caught at startup rather than at the moment someone needs a config.

        These end up in a file a device is about to depend on; ``wg-quick``
        rejects the whole interface for one bad prefix, and the person holding
        the broken file is not the person who set the variable.
        """
        for cidr in value:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"FOXGUARD_CLIENT_CONFIG_EXTRA_ALLOWED_IPS: {cidr!r} is not a network"
                ) from exc
        return value

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
    def client_endpoint(self) -> str | None:
        """``host:port`` a generated config dials, or None if nobody said.

        There is deliberately no guess here. The gateway's own addresses are
        tunnel and LAN addresses; the one thing a client needs is the *public*
        address its packets can reach, and only the operator knows what their
        router forwards udp/``wg_listen_port`` to.
        """
        if not self.wg_endpoint_host:
            return None
        return join_endpoint(self.wg_endpoint_host, self.wg_listen_port)

    @property
    def client_dns(self) -> tuple[str, ...]:
        """What a generated config puts on its ``DNS =`` line.

        A resolver address plus the zone as a search domain, which is what makes
        ``ssh nas`` work without making the gateway authoritative for bare
        labels globally -- the short-name expansion is the client's job, and
        this is where it gets told.

        Listen addresses outside the tunnel pools are dropped: the resolver may
        legitimately bind several, but a client that cannot route to one would
        stall every lookup until it timed out.
        """
        if not (self.dns_enabled and self.client_config_dns):
            return ()
        reachable = tuple(
            address for address in self.dns_listen if self.is_tunnel_address(address)
        )
        if not reachable:
            reachable = (self.gateway_ip,)
        return (*reachable, self.dns_zone)

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

    @property
    def proxy_sso_secret_value(self) -> str:
        return (
            self.proxy_sso_secret.get_secret_value() if self.proxy_sso_secret else ""
        )

    @property
    def proxy_sso_host(self) -> str | None:
        """Where the login page lives.

        A subdomain of the proxy domain, so the wildcard certificate already
        covers it and the cookie can be scoped to the parent domain -- which is
        what makes one sign-in work across every published service.
        """
        if self.proxy_sso_hostname:
            return self.proxy_sso_hostname
        return f"auth.{self.proxy_domain}" if self.proxy_domain else None

    @property
    def proxy_internal_listen(self) -> tuple[str, ...]:
        """Tunnel addresses the internal listener binds.

        Defaults to the gateway's own tunnel address, and anything outside the
        tunnel pools is dropped: the guarantee that makes ``peer_identity``
        sound is that the packet arrived on ``wg0``, so a listener bound
        anywhere else would hand out the same identity for a source address
        that proves nothing.
        """
        if self.proxy_internal_binds:
            return tuple(
                address
                for address in self.proxy_internal_binds
                if self.is_tunnel_address(address)
            )
        return (self.gateway_ip,)

    def proxy_base_spec(self) -> ProxySpec:
        """Project settings onto a proxy spec with no services in it yet.

        ``services/proxy.py`` fills in the services, source sets and peers,
        exactly as ``services/dns.py`` fills in hosts and aliases.
        """
        return ProxySpec(
            domain=self.proxy_domain or "",
            internal_binds=self.proxy_internal_listen,
            external_binds=tuple(self.proxy_external_binds),
            internal_https_port=self.proxy_internal_https_port,
            external_http_port=self.proxy_external_http_port,
            external_https_port=self.proxy_external_https_port,
            certs_dir=self.proxy_certs_dir,
            maps_dir=self.proxy_maps_dir,
            runtime_socket=self.proxy_runtime_socket,
            hsts_max_age=self.proxy_hsts_max_age,
            send_group_header=self.proxy_send_group_header,
            sso_secret=self.proxy_sso_secret_value,
            sso_cookie=self.proxy_sso_cookie_name,
            sso_hostname=self.proxy_sso_host,
            sso_cookie_domain=self.proxy_domain or "",
            sso_api_port=self.portal_port,
            connect_timeout_seconds=self.proxy_connect_timeout_seconds,
            client_timeout_seconds=self.proxy_client_timeout_seconds,
            server_timeout_seconds=self.proxy_server_timeout_seconds,
            tunnel_timeout_seconds=self.proxy_tunnel_timeout_seconds,
            extra_options=tuple(self.proxy_extra_options),
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
