"""Pure data model consumed by the HAProxy renderer.

Same boundary as :mod:`foxguard.nftables.model` and :mod:`foxguard.dns.model`:
everything that decides what the proxy does is frozen data here, testable
without a database, without root, and without HAProxy installed.

Three properties of this model exist because a reverse proxy is the one
component in Foxguard that terminates traffic from strangers.

* **Identity is a property of the listener, not of the service.** An
  :class:`Authenticator` carries a :class:`Scope`, because the same service can
  legitimately want "the tunnel proves who you are" on one door and "show me a
  token" on the other. :data:`AuthKind.PEER_IDENTITY` scoped to the outside is
  not a policy, it is a bug, and :func:`~foxguard.proxy.haproxy.validate_spec`
  refuses it.
* **Passthrough is not HTTP.** A TCP service never sees the plaintext, so it
  cannot carry an HTTP authenticator or a WAF. The capability table lives in
  :data:`HTTP_ONLY_AUTH` and :data:`HTTP_ONLY_FILTERS` rather than in prose.
* **Secrets arrive pre-hashed.** :class:`Service` carries
  ``token_hashes`` (lowercase SHA-256 hex) and :class:`Account` carries a
  crypt(3) string. This model has no way to express a plaintext credential, so
  no renderer can accidentally write one to disk.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "HTTP_ONLY_AUTH",
    "HTTP_ONLY_FILTERS",
    "SLUG_RE",
    "AccessRule",
    "Account",
    "Authenticator",
    "Backend",
    "Exposure",
    "Filter",
    "FilterKind",
    "PeerIdentity",
    "ProxySpec",
    "Scope",
    "Service",
    "ServiceKind",
    "SourceSet",
    "AuthKind",
]

#: Same grammar as ``groups.slug`` (``ck_groups_slug_format``). Shared on
#: purpose: a slug names a group, a zone, a peer label *or* a service, and a
#: name that could mean two of those makes an access rule ambiguous.
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,23}$")

#: A fully qualified host name. Same shape as the DNS module's, minus the
#: trailing-dot handling: these come from the admin API already normalised.
_HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_MAX_HOSTNAME = 253

#: A crypt(3) hash HAProxy's ``userlist`` can verify. Restricted to SHA-crypt
#: because the alternatives it also accepts (DES, MD5) have no business holding
#: a credential in 2026, and because ``insecure-password`` must never appear.
_CRYPT_RE = re.compile(r"^\$[56]\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{20,}$")

#: Lowercase SHA-256 hex. Lowercase specifically: HAProxy's ``hex`` converter
#: emits uppercase, so the rendered configuration appends ``,lower`` to match
#: what Python and the database store. Measured -- without it nothing matches
#: and the failure mode is a silent 403.
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ServiceKind(str, Enum):
    """How the proxy handles the connection.

    ``HTTP`` terminates TLS: the request is in the clear inside HAProxy, so
    header-based authentication, a WAF and identity injection are all possible.

    ``TCP`` passes the bytes through untouched. Nothing above layer 4 is
    visible, which is the point -- it is what makes SSH, RDP and Postgres work
    -- and also why most of the policy surface does not apply.
    """

    HTTP = "http"
    TCP = "tcp"


class Exposure(str, Enum):
    """Which doors a service has.

    ``INTERNAL`` binds a listener on the tunnel address only; ``EXTERNAL`` binds
    the WAN. ``BOTH`` is the split-horizon case: one name, two frontends, one
    certificate, and *different* policy on each.
    """

    INTERNAL = "internal"
    EXTERNAL = "external"
    BOTH = "both"

    @property
    def has_internal(self) -> bool:
        return self in (Exposure.INTERNAL, Exposure.BOTH)

    @property
    def has_external(self) -> bool:
        return self in (Exposure.EXTERNAL, Exposure.BOTH)


class Scope(str, Enum):
    """Which door a rule applies to."""

    INTERNAL = "internal"
    EXTERNAL = "external"
    BOTH = "both"

    def covers(self, exposure: Exposure) -> bool:
        if self is Scope.BOTH:
            return True
        if self is Scope.INTERNAL:
            return exposure is Exposure.INTERNAL
        return exposure is Exposure.EXTERNAL


class AuthKind(str, Enum):
    """Ways a caller can prove who it is. Combined with OR: one is enough.

    ``PEER_IDENTITY`` is the strongest and the cheapest. Inside the tunnel the
    source address is bound to a public key by cryptokey routing -- WireGuard
    drops any packet whose source is outside the sending peer's ``AllowedIPs``,
    and Foxguard writes those itself, one ``/32`` per peer. So it needs no
    lookup, no secret and no round trip to the control plane. It is also
    meaningless outside the tunnel, where a source address belongs to an ISP or
    a NAT and is bound to nothing.
    """

    PEER_IDENTITY = "peer_identity"
    BEARER = "bearer"
    BASIC = "basic"
    FOXGUARD_SSO = "foxguard_sso"
    MTLS = "mtls"


class FilterKind(str, Enum):
    """Conditions that must *all* pass. Combined with AND.

    Filters narrow, authenticators admit. Keeping them in separate lists is what
    makes "bearer or peer identity, but never from these countries" expressible
    without a boolean tree in the UI.
    """

    IP_ALLOW = "ip_allow"
    IP_DENY = "ip_deny"
    GEO_ALLOW = "geo_allow"
    GEO_DENY = "geo_deny"
    RATE_LIMIT = "rate_limit"
    WAF = "waf"
    CROWDSEC = "crowdsec"


class AccessAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


#: Authenticators that need to read an HTTP request. A TCP passthrough service
#: carrying one of these is a configuration error, not a no-op: the operator
#: believes the service is protected and it is not.
HTTP_ONLY_AUTH = frozenset({AuthKind.BEARER, AuthKind.BASIC, AuthKind.FOXGUARD_SSO})

#: Filters that need the plaintext. ``CROWDSEC`` is absent on purpose: its IP
#: level remediation works fine on a TCP frontend, only its AppSec half does not.
HTTP_ONLY_FILTERS = frozenset({FilterKind.WAF})

#: Filters accepted by the schema but not implemented yet. Rejected loudly
#: rather than silently ignored -- a geo rule that does nothing is worse than a
#: geo rule that refuses to save.
UNIMPLEMENTED_FILTERS = frozenset(
    {FilterKind.GEO_ALLOW, FilterKind.GEO_DENY, FilterKind.WAF, FilterKind.CROWDSEC}
)


@dataclass(frozen=True, slots=True)
class SourceSet:
    """A named list of addresses, rendered as a HAProxy pattern file.

    The proxy's equivalent of an nftables set, and populated from the same
    place: the members of a group or a zone, as tunnel addresses. Referenced by
    :class:`AccessRule` and only ever consulted on an internal frontend, because
    a tunnel address arriving from the WAN proves nothing.
    """

    name: str
    members: tuple[str, ...] = ()
    comment: str | None = None


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """One tunnel address and what it means.

    Rendered into ``peers.map`` and ``groups.map`` so the proxy can put a name
    on the caller for the upstream. Only ever consulted on an internal
    frontend: this is a lookup table, not a credential, and the thing that makes
    it trustworthy is which listener the packet arrived on.
    """

    address: str
    label: str
    groups: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AccessRule:
    """Who may use a service, in the ACL module's vocabulary.

    ``source`` is the name of a :class:`SourceSet`, a CIDR, or ``None`` meaning
    "any". Rules naming a source set are skipped on the external frontend: a
    public source address cannot be a peer, so evaluating them there would deny
    everyone for a reason nobody could read. External authorisation is the
    authenticators' job, plus any CIDR rules.
    """

    action: AccessAction
    source: str | None = None
    is_set: bool = False
    comment: str | None = None


@dataclass(frozen=True, slots=True)
class Authenticator:
    kind: AuthKind
    scope: Scope = Scope.BOTH
    #: ``BASIC`` only: the realm shown in the browser prompt.
    realm: str | None = None


@dataclass(frozen=True, slots=True)
class Filter:
    kind: FilterKind
    scope: Scope = Scope.BOTH
    #: ``IP_ALLOW`` / ``IP_DENY``: addresses and prefixes.
    values: tuple[str, ...] = ()
    #: ``RATE_LIMIT``: requests allowed per ``period_seconds``.
    rate: int | None = None
    period_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class Account:
    """A basic-auth service account.

    ``password_hash`` is a crypt(3) SHA-crypt string. Measured against HAProxy
    3.0.11: a ``userlist`` verifies ``$6$`` correctly (401 without credentials,
    200 with, 401 with a wrong password). It is acceptable here only because the
    password is machine-generated and high-entropy -- human passwords stay in
    the database behind argon2 and never reach the gateway.
    """

    username: str
    password_hash: str


@dataclass(frozen=True, slots=True)
class Backend:
    """Where the proxy sends the traffic.

    ``address`` is inside the tunnel, or inside a network a peer routes for. The
    control plane checks that before this ever renders, because a backend
    pointing at an address no peer carries fails as a timeout, which is the
    least diagnosable failure in the system.
    """

    address: str
    port: int
    tls: bool = False
    #: Off by default. These upstreams are appliances with self-signed
    #: certificates, and the hop already runs inside WireGuard, so verification
    #: buys little and breaks much. Opt in per service when the upstream has a
    #: real certificate.
    tls_verify: bool = False
    #: Off by default: an upstream behind a roaming laptop flaps every time the
    #: lid closes, and an aggressive check turns that into log noise and
    #: spurious 503s.
    check: bool = False
    check_interval_seconds: int = 30
    #: Peer this lives behind, for the offline error page. ``None`` -> gateway.
    peer_label: str | None = None


@dataclass(frozen=True, slots=True)
class Service:
    """One published service."""

    slug: str
    kind: ServiceKind
    exposure: Exposure
    backend: Backend

    #: HTTP: the Host header routed on. Split-horizon makes these the same
    #: value, which is the whole reason services live under a real domain.
    internal_hostname: str | None = None
    external_hostname: str | None = None

    #: TCP without TLS: a dedicated port, because there is no SNI to route on.
    listen_port: int | None = None
    #: TCP with TLS: shares ``:443`` and is routed by SNI instead.
    sni_hostname: str | None = None

    authenticators: tuple[Authenticator, ...] = ()
    filters: tuple[Filter, ...] = ()
    access: tuple[AccessRule, ...] = ()

    token_hashes: tuple[str, ...] = ()
    accounts: tuple[Account, ...] = ()

    description: str | None = None

    def auth_for(self, exposure: Exposure) -> tuple[Authenticator, ...]:
        return tuple(a for a in self.authenticators if a.scope.covers(exposure))

    def filters_for(self, exposure: Exposure) -> tuple[Filter, ...]:
        return tuple(f for f in self.filters if f.scope.covers(exposure))

    def access_for(self, exposure: Exposure) -> tuple[AccessRule, ...]:
        """Access rules meaningful on this door.

        Set-backed rules are dropped on the external frontend -- see
        :class:`AccessRule`.
        """
        if exposure is Exposure.EXTERNAL:
            return tuple(rule for rule in self.access if not rule.is_set)
        return self.access

    @property
    def needs_https_frontend(self) -> bool:
        return self.kind is ServiceKind.HTTP

    @property
    def rate_limit(self) -> Filter | None:
        for item in self.filters:
            if item.kind is FilterKind.RATE_LIMIT:
                return item
        return None


@dataclass(frozen=True, slots=True)
class ProxySpec:
    """Everything the proxy on the gateway needs to know.

    Paths are part of the spec rather than the renderer's business for the same
    reason they are in :class:`~foxguard.dns.model.DnsSpec`: they appear *inside*
    the generated configuration, so two deployments with different paths must
    produce different bytes and therefore a different digest.
    """

    #: The real domain services live under. Peer names stay on the DNS zone
    #: (``fox.internal``); services need a name a public CA will sign.
    domain: str = ""

    internal_binds: tuple[str, ...] = ()
    external_binds: tuple[str, ...] = ()
    internal_https_port: int = 443
    external_http_port: int = 80
    external_https_port: int = 443

    certs_dir: str = "/etc/foxguard/proxy/certs"
    maps_dir: str = "/etc/foxguard/proxy/maps"
    #: Capped at 97 characters by HAProxy itself -- measured, it is a hard parse
    #: error, not a warning.
    runtime_socket: str = "/run/foxguard/haproxy.sock"

    hsts_max_age: int = 31536000
    #: Sent to upstreams as ``X-Foxguard-Groups``. Off by default: it hands every
    #: upstream the names of every group the caller belongs to.
    send_group_header: bool = False

    # --- single sign-on -----------------------------------------------------
    #: Signs and verifies the session cookie. Rendered into the configuration,
    #: which is why that file is 0640 and why rotating it signs everyone out.
    sso_secret: str = ""
    sso_cookie: str = "fg_sso"
    #: Where the login page answers. The one vhost that puts the proxy in front
    #: of the Foxguard API, and only ``/api/v1/sso/`` is routed there.
    sso_hostname: str | None = None
    #: Parent domain the cookie is scoped to, so one sign-in covers every
    #: published service.
    sso_cookie_domain: str = ""
    sso_api_port: int = 8080
    #: Session ids the proxy must refuse despite a good signature. This is what
    #: makes revocation immediate rather than "whenever the token expires".
    sso_revoked: tuple[str, ...] = ()

    services: tuple[Service, ...] = ()
    source_sets: tuple[SourceSet, ...] = ()
    peers: tuple[PeerIdentity, ...] = ()

    connect_timeout_seconds: int = 5
    client_timeout_seconds: int = 60
    server_timeout_seconds: int = 60
    #: Long, because a passthrough session is often a shell someone is typing in.
    tunnel_timeout_seconds: int = 3600

    extra_options: tuple[str, ...] = field(default_factory=tuple)

    @property
    def uses_sso(self) -> bool:
        return any(
            auth.kind is AuthKind.FOXGUARD_SSO
            for service in self.services
            for auth in service.authenticators
        )

    @property
    def has_internal(self) -> bool:
        return any(s.exposure.has_internal for s in self.services)

    @property
    def has_external(self) -> bool:
        return any(s.exposure.has_external for s in self.services)

    @property
    def set_names(self) -> frozenset[str]:
        return frozenset(item.name for item in self.source_sets)


def is_address_or_cidr(value: str) -> bool:
    """Is this a bare address or a prefix, either family?"""
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def is_hostname(value: str) -> bool:
    return bool(value) and len(value) <= _MAX_HOSTNAME and bool(_HOSTNAME_RE.match(value))


def is_crypt_hash(value: str) -> bool:
    return bool(_CRYPT_RE.match(value))


def is_sha256_hex(value: str) -> bool:
    return bool(_SHA256_RE.match(value))
