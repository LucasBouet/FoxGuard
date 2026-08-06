"""Deterministic HAProxy artefact generator.

Design rules, each covered by a test in ``tests/test_proxy_generator.py``:

1.  **One configuration, many pattern files, one digest.** Everything is
    rendered together and hashed together, so the agent can never apply a
    configuration that references a token map from a previous state.
2.  **Byte-stable output.** Same database state -> same bytes. Services are
    emitted in slug order, addresses sorted, nothing timestamped.
3.  **Pattern files are written before the configuration is validated.**
    Measured: ``haproxy -c`` fails with ``failed to open pattern file`` when an
    ``-f`` reference is missing, so the ordering is not a preference.
4.  **Whatever is pushed over the Runtime API is also written to disk.**
    Measured on 3.0.11: an ``add map`` is live immediately and *gone* after the
    next reload, and a ``commit ssl cert`` reverts to the on-disk certificate.
    One without the other is a change that silently undoes itself.
5.  **Client-supplied identity headers die at the door.** ``X-Foxguard-*`` is
    deleted unconditionally at the top of every frontend, before any rule can
    set it. A service that trusts those headers must not be able to be lied to
    by the caller.
6.  **No injection.** Slugs, host names and addresses are validated against
    strict grammars before they reach a configuration file, because unlike the
    DNS hosts file this format *can* express directives.

The uppercase trap, since it cost a debugging session: HAProxy's ``hex``
converter emits ``F52FBD…`` while ``hashlib.sha256().hexdigest()`` emits
``f52fbd…``. Every token expression here ends in ``,lower``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterator

from .model import (
    HTTP_ONLY_AUTH,
    HTTP_ONLY_FILTERS,
    SLUG_RE,
    UNIMPLEMENTED_FILTERS,
    AccessAction,
    Authenticator,
    AuthKind,
    Exposure,
    FilterKind,
    ProxySpec,
    Scope,
    Service,
    ServiceKind,
    is_address_or_cidr,
    is_crypt_hash,
    is_hostname,
    is_sha256_hex,
)

#: The one algorithm Foxguard issues and the proxy is told to expect.
#: Duplicated from ``services/sso`` deliberately: this module must not import
#: anything that touches a database, and a mismatch is caught by a test.
ALGORITHM = "HS256"

#: Wraps and separates the slugs in the token's ``groups`` claim. Duplicated
#: from ``services/sso`` for the same reason as ``ALGORITHM``, and guarded by
#: the same kind of test.
GROUP_DELIMITER = ","

__all__ = [
    "ALGORITHM",
    "GROUP_DELIMITER",
    "ProxyValidationError",
    "PEER_SET",
    "SSO_REVOKED_FILE",
    "proxy_digest",
    "render_conf",
    "render_files",
    "validate_spec",
]

INDENT = "    "

#: Built-in source set holding every named peer's tunnel addresses. What
#: ``peer_identity`` actually tests: "did this come from a peer we know".
PEER_SET = "fg_peers"

#: Maximum length HAProxy accepts for a stats socket path. Measured: exceeding
#: it is a fatal parse error, not a warning.
MAX_SOCKET_PATH = 97

_MAX_PORT = 65535
#: Same expression as ``ck_groups_slug_format`` in the schema. Enforced again
#: here because it is what makes ``GROUP_DELIMITER`` unambiguous: a slug that
#: could contain a comma would let one group's name impersonate two.
GROUP_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,23}$")
_SET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
_OPTION_RE = re.compile(r"^[a-z0-9][a-z0-9. _-]*[^\r\n]*$")

_BANNER = (
    "# Foxguard generated HAProxy configuration -- DO NOT EDIT BY HAND.\n"
    "#\n"
    "# Written by foxguard-agent on every reconciliation; the source of truth is\n"
    "# the control plane's database, so an edit here survives until the next poll.\n"
    "# Pattern files referenced below live in the same directory tree and are\n"
    "# rewritten with this file -- they are one artefact, with one digest.\n"
    "#\n"
)

_FILE_BANNER = "# Foxguard generated -- DO NOT EDIT BY HAND. Rewritten on every reconciliation.\n"


class ProxyValidationError(ValueError):
    """The spec cannot produce a safe configuration."""


# --------------------------------------------------------------------------- #
# naming
# --------------------------------------------------------------------------- #


def backend_name(slug: str) -> str:
    return f"be_{slug}"


def table_name(slug: str) -> str:
    return f"st_{slug}"


def userlist_name(slug: str) -> str:
    return f"ul_{slug}"


def tcp_frontend_name(slug: str) -> str:
    return f"fg_tcp_{slug}"


def set_file(name: str) -> str:
    return f"set_{name}.lst"


def token_file(slug: str) -> str:
    return f"tok_{slug}.map"


def ipfilter_file(slug: str, index: int) -> str:
    return f"ipf_{slug}_{index}.lst"


def error_file(slug: str) -> str:
    return f"err_{slug}_503.http"


DEFAULT_ERROR_FILE = "err_default_503.http"
PEERS_MAP_FILE = "peers.map"
GROUPS_MAP_FILE = "groups.map"


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #


def validate_spec(spec: ProxySpec) -> None:
    """Refuse anything that would produce an unsafe or unloadable config.

    Raised errors are surfaced as 422 by the mutation endpoints, so the message
    is read by a human deciding what to fix.
    """
    if len(spec.runtime_socket) > MAX_SOCKET_PATH:
        raise ProxyValidationError(
            f"runtime socket path is {len(spec.runtime_socket)} characters; "
            f"HAProxy refuses anything over {MAX_SOCKET_PATH}"
        )
    if not spec.runtime_socket.startswith("/"):
        raise ProxyValidationError("runtime socket path must be absolute")

    for directory, label in (
        (spec.certs_dir, "certs_dir"),
        (spec.maps_dir, "maps_dir"),
    ):
        if not directory.startswith("/"):
            raise ProxyValidationError(f"{label} must be an absolute path")

    for address in (*spec.internal_binds, *spec.external_binds):
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise ProxyValidationError(f"bind address {address!r} is not valid") from exc

    if spec.domain and not is_hostname(spec.domain):
        raise ProxyValidationError(f"domain {spec.domain!r} is not a valid host name")

    _validate_source_sets(spec)

    seen_slugs: set[str] = set()
    seen_hostnames: dict[str, str] = {}
    seen_ports: dict[int, str] = {}
    for service in spec.services:
        _validate_service(spec, service, seen_slugs, seen_hostnames, seen_ports)

    if spec.has_internal and not spec.internal_binds:
        raise ProxyValidationError(
            "a service is exposed internally but no internal bind address is set"
        )
    if spec.has_external and not spec.external_binds:
        raise ProxyValidationError(
            "a service is exposed externally but no external bind address is set"
        )

    for option in spec.extra_options:
        if "\n" in option or "\r" in option or not _OPTION_RE.match(option):
            raise ProxyValidationError(f"extra option {option!r} is not a single line")


def _validate_source_sets(spec: ProxySpec) -> None:
    seen: set[str] = set()
    for source in spec.source_sets:
        if not _SET_NAME_RE.match(source.name):
            raise ProxyValidationError(f"source set name {source.name!r} is not valid")
        if source.name in seen:
            raise ProxyValidationError(f"source set {source.name!r} is defined twice")
        seen.add(source.name)
        for member in source.members:
            if not is_address_or_cidr(member):
                raise ProxyValidationError(
                    f"source set {source.name!r} member {member!r} is not an address"
                )


def _validate_service(
    spec: ProxySpec,
    service: Service,
    seen_slugs: set[str],
    seen_hostnames: dict[str, str],
    seen_ports: dict[int, str],
) -> None:
    if not SLUG_RE.match(service.slug):
        raise ProxyValidationError(f"service slug {service.slug!r} is not valid")
    if service.slug in seen_slugs:
        raise ProxyValidationError(f"service slug {service.slug!r} is used twice")
    seen_slugs.add(service.slug)

    backend = service.backend
    if not is_address_or_cidr(backend.address) or "/" in backend.address:
        raise ProxyValidationError(
            f"service {service.slug!r}: upstream {backend.address!r} is not an address"
        )
    if not 1 <= backend.port <= _MAX_PORT:
        raise ProxyValidationError(
            f"service {service.slug!r}: upstream port {backend.port} is out of range"
        )

    if service.kind is ServiceKind.HTTP:
        _validate_http_service(service, seen_hostnames)
    else:
        _validate_tcp_service(service, seen_hostnames, seen_ports)

    _validate_policy(spec, service)


def _validate_http_service(service: Service, seen_hostnames: dict[str, str]) -> None:
    for exposure, hostname in (
        (Exposure.INTERNAL, service.internal_hostname),
        (Exposure.EXTERNAL, service.external_hostname),
    ):
        needed = (
            service.exposure.has_internal
            if exposure is Exposure.INTERNAL
            else service.exposure.has_external
        )
        if needed and not hostname:
            raise ProxyValidationError(
                f"service {service.slug!r} is exposed {exposure.value}ly but has no "
                f"{exposure.value} host name to route on"
            )
        if hostname and not is_hostname(hostname):
            raise ProxyValidationError(
                f"service {service.slug!r}: {hostname!r} is not a valid host name"
            )
    # A name may only route to one service *per door*. The same name on both
    # doors is the split-horizon case and is exactly what we want.
    for hostname, door in (
        (service.internal_hostname, "internal"),
        (service.external_hostname, "external"),
    ):
        if not hostname:
            continue
        key = f"{door}:{hostname}"
        if key in seen_hostnames and seen_hostnames[key] != service.slug:
            raise ProxyValidationError(
                f"{hostname!r} is claimed by both {seen_hostnames[key]!r} and "
                f"{service.slug!r} on the {door} listener"
            )
        seen_hostnames[key] = service.slug


def _validate_tcp_service(
    service: Service, seen_hostnames: dict[str, str], seen_ports: dict[int, str]
) -> None:
    if not service.listen_port and not service.sni_hostname:
        raise ProxyValidationError(
            f"service {service.slug!r} is TCP passthrough, so it needs either a "
            "dedicated port or an SNI host name: plain TCP has nothing to route on"
        )
    if service.listen_port is not None:
        if not 1 <= service.listen_port <= _MAX_PORT:
            raise ProxyValidationError(
                f"service {service.slug!r}: listen port {service.listen_port} is out of range"
            )
        owner = seen_ports.get(service.listen_port)
        if owner and owner != service.slug:
            raise ProxyValidationError(
                f"port {service.listen_port} is claimed by both {owner!r} and {service.slug!r}"
            )
        seen_ports[service.listen_port] = service.slug
    if service.sni_hostname and not is_hostname(service.sni_hostname):
        raise ProxyValidationError(
            f"service {service.slug!r}: SNI name {service.sni_hostname!r} is not valid"
        )


def _validate_policy(spec: ProxySpec, service: Service) -> None:
    known_sets = spec.set_names | {PEER_SET}

    for auth in service.authenticators:
        if auth.kind is AuthKind.PEER_IDENTITY and auth.scope is not Scope.INTERNAL:
            raise ProxyValidationError(
                f"service {service.slug!r}: peer identity cannot apply to the "
                "external listener. Outside the tunnel a source address belongs "
                "to an ISP or a NAT and is bound to no key -- scope it to "
                "'internal', or add an authenticator that works from outside"
            )
        if service.kind is ServiceKind.TCP and auth.kind in HTTP_ONLY_AUTH:
            raise ProxyValidationError(
                f"service {service.slug!r}: {auth.kind.value} needs to read the "
                "request, and a TCP passthrough service never sees the plaintext"
            )
        if auth.kind is AuthKind.MTLS:
            raise ProxyValidationError(
                f"service {service.slug!r}: {auth.kind.value} is not implemented yet"
            )
        if auth.kind is AuthKind.FOXGUARD_SSO and not spec.sso_secret:
            raise ProxyValidationError(
                f"service {service.slug!r}: single sign-on needs "
                "FOXGUARD_PROXY_SSO_SECRET, which Foxguard signs the cookie with "
                "and the proxy verifies against"
            )
        if auth.kind is AuthKind.FOXGUARD_SSO and not spec.sso_hostname:
            raise ProxyValidationError(
                f"service {service.slug!r}: single sign-on needs a host name for "
                "the login page (FOXGUARD_PROXY_DOMAIN, or "
                "FOXGUARD_PROXY_SSO_HOSTNAME to override it)"
            )
        if auth.kind is not AuthKind.FOXGUARD_SSO and (auth.groups or auth.require_admin):
            raise ProxyValidationError(
                f"service {service.slug!r}: {auth.kind.value} carries a group or "
                "admin requirement, and only single sign-on knows who the caller "
                "is. A bearer token names no person"
            )
        for slug in auth.groups:
            if not GROUP_SLUG.fullmatch(slug):
                # The delimiter the claim is built from lives in this module's
                # contract with services.sso: a slug containing one would let a
                # membership be forged by naming a group after two others.
                raise ProxyValidationError(
                    f"service {service.slug!r}: {slug!r} is not a valid group slug"
                )
        if auth.kind is AuthKind.BASIC and not service.accounts:
            raise ProxyValidationError(
                f"service {service.slug!r}: basic auth is enabled but no service "
                "account exists, so nothing could ever authenticate"
            )
        if auth.kind is AuthKind.BEARER and not service.token_hashes:
            raise ProxyValidationError(
                f"service {service.slug!r}: bearer auth is enabled but no token "
                "exists, so nothing could ever authenticate"
            )

    for item in service.filters:
        if item.kind in UNIMPLEMENTED_FILTERS:
            raise ProxyValidationError(
                f"service {service.slug!r}: filter {item.kind.value} is not implemented yet"
            )
        if service.kind is ServiceKind.TCP and item.kind in HTTP_ONLY_FILTERS:
            raise ProxyValidationError(
                f"service {service.slug!r}: filter {item.kind.value} needs the "
                "plaintext and this service is TCP passthrough"
            )
        if item.kind in (FilterKind.IP_ALLOW, FilterKind.IP_DENY):
            if not item.values:
                raise ProxyValidationError(
                    f"service {service.slug!r}: an {item.kind.value} filter with no "
                    "addresses would deny everything"
                )
            for value in item.values:
                if not is_address_or_cidr(value):
                    raise ProxyValidationError(
                        f"service {service.slug!r}: {value!r} is not an address"
                    )
        if item.kind is FilterKind.RATE_LIMIT and (not item.rate or not item.period_seconds):
            raise ProxyValidationError(
                f"service {service.slug!r}: a rate limit needs both a rate and a period"
            )

    for rule in service.access:
        if rule.is_set:
            if rule.source not in known_sets:
                raise ProxyValidationError(
                    f"service {service.slug!r}: access rule names unknown source "
                    f"set {rule.source!r}"
                )
        elif rule.source is not None and not is_address_or_cidr(rule.source):
            raise ProxyValidationError(
                f"service {service.slug!r}: access rule source {rule.source!r} "
                "is neither a known set nor an address"
            )

    for account in service.accounts:
        if not _USERNAME_RE.match(account.username):
            raise ProxyValidationError(
                f"service {service.slug!r}: account name {account.username!r} is not valid"
            )
        if not is_crypt_hash(account.password_hash):
            raise ProxyValidationError(
                f"service {service.slug!r}: account {account.username!r} does not "
                "carry a SHA-crypt hash. HAProxy would need 'insecure-password', "
                "which would put the plaintext on the gateway's disk"
            )

    for digest in service.token_hashes:
        if not is_sha256_hex(digest):
            raise ProxyValidationError(
                f"service {service.slug!r}: token digest {digest!r} is not lowercase SHA-256 hex"
            )

    # The rule with teeth: a door with no way in is either wide open or wholly
    # shut depending on how the fallback is written, and both are surprises.
    for exposure in (Exposure.INTERNAL, Exposure.EXTERNAL):
        covered = (
            service.exposure.has_internal
            if exposure is Exposure.INTERNAL
            else service.exposure.has_external
        )
        if not covered:
            continue
        if not service.auth_for(exposure):
            raise ProxyValidationError(
                f"service {service.slug!r} is exposed on the {exposure.value} "
                "listener with no authenticator that applies there. Add one, or "
                "narrow the exposure -- Foxguard will not publish a door it "
                "cannot describe"
            )


# --------------------------------------------------------------------------- #
# rendering: pattern files
# --------------------------------------------------------------------------- #


def render_files(spec: ProxySpec) -> dict[str, str]:
    """Every file the configuration references, keyed by base name.

    Flat rather than nested so the applier can sync a directory by comparing
    two sets of names: anything on disk that is not a key here is stale and
    goes. A nested layout would make that a tree walk for no benefit.
    """
    files: dict[str, str] = {}

    for source in spec.source_sets:
        body = "".join(f"{member}\n" for member in sorted(source.members, key=_addr_key))
        comment = f"# {source.comment}\n" if source.comment else ""
        files[set_file(source.name)] = _FILE_BANNER + comment + body

    for service in spec.services:
        if service.token_hashes:
            files[token_file(service.slug)] = _FILE_BANNER + "".join(
                f"{digest} 1\n" for digest in sorted(service.token_hashes)
            )
        for index, item in enumerate(service.filters):
            if item.kind in (FilterKind.IP_ALLOW, FilterKind.IP_DENY):
                files[ipfilter_file(service.slug, index)] = _FILE_BANNER + "".join(
                    f"{value}\n" for value in sorted(item.values, key=_addr_key)
                )
        files[error_file(service.slug)] = _render_error_page(service)

    files[SSO_REVOKED_FILE] = _FILE_BANNER + "".join(
        f"{jti} 1\n" for jti in sorted(spec.sso_revoked)
    )
    files[DEFAULT_ERROR_FILE] = _render_default_error_page()
    files[PEERS_MAP_FILE] = _render_peers_map(spec)
    files[GROUPS_MAP_FILE] = _render_groups_map(spec)
    return files


def _addr_key(value: str) -> tuple[int, int, int]:
    """Sort addresses numerically, v4 before v6, so output is stable."""
    network = ipaddress.ip_network(value, strict=False)
    return (network.version, int(network.network_address), network.prefixlen)


def _render_error_page(service: Service) -> str:
    where = (
        f"the device hosting it ({service.backend.peer_label}) is not reachable"
        if service.backend.peer_label
        else "it is not responding"
    )
    body = (
        "<!doctype html><html><head><meta charset=utf-8>"
        f"<title>{service.slug} unavailable</title></head><body>"
        f"<h1>{service.slug} is unavailable</h1>"
        f"<p>Foxguard reached the proxy, but {where}.</p>"
        "<p>This is not a proxy fault: the service itself did not answer.</p>"
        "</body></html>"
    )
    return _http_error(503, body)


def _render_default_error_page() -> str:
    body = (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>No such service</title></head><body>"
        "<h1>No such service</h1>"
        "<p>No Foxguard service is published under this name.</p>"
        "</body></html>"
    )
    return _http_error(503, body)


def _http_error(status: int, body: str) -> str:
    reason = {503: "Service Unavailable"}[status]
    # errorfile wants a complete raw response with CRLF line endings.
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
    )
    return head + body


def _render_peers_map(spec: ProxySpec) -> str:
    """Address -> peer label, for the ``X-Foxguard-Peer`` header.

    An empty map is valid and simply means no identity header is ever set.
    """
    return _FILE_BANNER + "".join(
        f"{peer.address} {peer.label}\n"
        for peer in sorted(spec.peers, key=lambda p: _addr_key(p.address))
    )


def _render_groups_map(spec: ProxySpec) -> str:
    """Address -> space-separated group slugs, for ``X-Foxguard-Groups``."""
    return _FILE_BANNER + "".join(
        f"{peer.address} {','.join(sorted(peer.groups))}\n"
        for peer in sorted(spec.peers, key=lambda p: _addr_key(p.address))
        if peer.groups
    )


# --------------------------------------------------------------------------- #
# rendering: the configuration
# --------------------------------------------------------------------------- #


def render_conf(spec: ProxySpec) -> str:
    validate_spec(spec)
    return _BANNER + "\n".join(_conf_lines(spec)) + "\n"


def _conf_lines(spec: ProxySpec) -> Iterator[str]:
    yield from _global_section(spec)
    yield ""
    yield from _defaults_section(spec)

    for service in _ordered(spec):
        if service.accounts:
            yield ""
            yield f"userlist {userlist_name(service.slug)}"
            for account in sorted(service.accounts, key=lambda a: a.username):
                yield f"{INDENT}user {account.username} password {account.password_hash}"

    for service in _ordered(spec):
        limit = service.rate_limit
        if limit:
            yield ""
            yield f"# Rate limit for {service.slug}: {limit.rate}/{limit.period_seconds}s"
            yield f"backend {table_name(service.slug)}"
            yield (
                f"{INDENT}stick-table type ip size 100k expire "
                f"{limit.period_seconds * 2}s store http_req_rate({limit.period_seconds}s)"
            )

    if spec.has_external:
        yield ""
        yield from _external_http_frontend(spec)
        yield ""
        yield from _https_frontend(spec, Exposure.EXTERNAL)

    if spec.has_internal:
        yield ""
        yield from _https_frontend(spec, Exposure.INTERNAL)

    for service in _ordered(spec):
        if service.kind is ServiceKind.TCP:
            yield ""
            yield from _tcp_frontend(spec, service)

    for service in _ordered(spec):
        yield ""
        yield from _backend(spec, service)

    if spec.uses_sso and spec.sso_hostname:
        yield ""
        yield "# The login page, and nothing else on the API. See _sso_vhost."
        yield "backend be_fg_sso"
        yield f"{INDENT}mode http"
        yield f"{INDENT}server s1 {_bind(spec.internal_binds[0] if spec.internal_binds else '127.0.0.1')}:{spec.sso_api_port}"

    if spec.has_external or spec.has_internal:
        yield ""
        yield from _no_service_backend(spec)

    if spec.extra_options:
        yield ""
        yield "# Operator-supplied options, appended verbatim."
        yield from spec.extra_options


def _ordered(spec: ProxySpec) -> list[Service]:
    return sorted(spec.services, key=lambda s: s.slug)


def _global_section(spec: ProxySpec) -> Iterator[str]:
    yield "global"
    yield f"{INDENT}log stdout format raw local0 info"
    yield (f"{INDENT}stats socket {spec.runtime_socket} mode 660 level admin expose-fd listeners")
    yield f"{INDENT}stats timeout 30s"
    yield f"{INDENT}ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets"
    yield f"{INDENT}ssl-default-server-options ssl-min-ver TLSv1.2"
    yield f"{INDENT}tune.ssl.default-dh-param 2048"


def _defaults_section(spec: ProxySpec) -> Iterator[str]:
    yield "defaults"
    yield f"{INDENT}mode http"
    yield f"{INDENT}log global"
    yield f"{INDENT}option httplog"
    yield f"{INDENT}option dontlognull"
    yield f"{INDENT}option http-server-close"
    yield f"{INDENT}timeout connect {spec.connect_timeout_seconds}s"
    yield f"{INDENT}timeout client {spec.client_timeout_seconds}s"
    yield f"{INDENT}timeout server {spec.server_timeout_seconds}s"
    # Long, because a passthrough session is often a shell someone is typing in.
    yield f"{INDENT}timeout tunnel {spec.tunnel_timeout_seconds}s"
    yield f"{INDENT}timeout http-request 10s"
    yield f"{INDENT}timeout http-keep-alive 10s"
    yield f"{INDENT}errorfile 503 {spec.maps_dir}/{DEFAULT_ERROR_FILE}"


def _external_http_frontend(spec: ProxySpec) -> Iterator[str]:
    yield "# Plain HTTP on the WAN exists only to send callers to HTTPS. ACME uses"
    yield "# DNS-01, so nothing is ever served here."
    yield "frontend fg_ext_http"
    for address in spec.external_binds:
        yield f"{INDENT}bind {_bind(address)}:{spec.external_http_port}"
    yield f"{INDENT}mode http"
    yield f"{INDENT}http-request redirect scheme https code 301"


def _https_frontend(spec: ProxySpec, exposure: Exposure) -> Iterator[str]:
    internal = exposure is Exposure.INTERNAL
    name = "fg_int_https" if internal else "fg_ext_https"
    binds = spec.internal_binds if internal else spec.external_binds
    port = spec.internal_https_port if internal else spec.external_https_port

    if internal:
        yield "# The tunnel-facing door. This is the only listener on which a source"
        yield "# address is an identity: cryptokey routing binds it to a public key."
    else:
        yield "# The WAN door. No source address here proves anything."

    yield f"frontend {name}"
    for address in binds:
        yield f"{INDENT}bind {_bind(address)}:{port} ssl crt {spec.certs_dir} alpn h2,http/1.1"
    yield f"{INDENT}mode http"
    yield f'{INDENT}http-response set-header Strict-Transport-Security "max-age={spec.hsts_max_age}"'

    yield ""
    yield f"{INDENT}# Identity headers are ours alone. Deleting before any rule can"
    yield f"{INDENT}# set them means a caller cannot forge one."
    for header in ("X-Foxguard-Peer", "X-Foxguard-User", "X-Foxguard-Groups"):
        yield f"{INDENT}http-request del-header {header}"

    if internal:
        yield (
            f"{INDENT}http-request set-var(txn.fg_peer) "
            f"src,map_str({spec.maps_dir}/{PEERS_MAP_FILE})"
        )

    if spec.uses_sso and spec.sso_hostname:
        yield ""
        yield from _sso_vhost(spec)

    services = [
        service
        for service in _ordered(spec)
        if service.kind is ServiceKind.HTTP
        and (service.exposure.has_internal if internal else service.exposure.has_external)
    ]

    for service in services:
        hostname = service.internal_hostname if internal else service.external_hostname
        yield ""
        yield f"{INDENT}# --- {service.slug} ({hostname}) ---"
        yield f"{INDENT}acl h_{service.slug} req.hdr(host),host_only -i {hostname}"
        yield from _service_rules(spec, service, exposure, f"h_{service.slug}")

    yield ""
    if spec.uses_sso and spec.sso_hostname:
        yield f"{INDENT}use_backend be_fg_sso if h_fg_sso"
    for service in services:
        yield f"{INDENT}use_backend {backend_name(service.slug)} if h_{service.slug}"
    yield f"{INDENT}default_backend be_fg_no_service"


def _sso_vhost(spec: ProxySpec) -> Iterator[str]:
    """Route the login page, and only the login page, to the Foxguard API.

    This is the single exception to "never put the proxy in front of the
    Foxguard API", and it is narrow on purpose. ``deps.calling_peer`` identifies
    portal and enrollment callers by source address and
    ``assert_no_forwarded_headers`` refuses anything carrying a forwarded
    header, so a proxy in front of *those* destroys the identity they run on.
    The SSO endpoints identify by password and TOTP instead, so they are safe
    behind a proxy -- and the path ACL below is what keeps this vhost from ever
    reaching anything else.

    ``X-Foxguard-Client-IP`` is set from the real source address. It is
    unforgeable because every ``X-Foxguard-*`` header the caller sent was
    deleted at the top of this frontend, before any rule ran. The sign-in
    throttle reads it; without it every attempt would appear to come from the
    gateway and share one budget.
    """
    yield f"{INDENT}# --- {spec.sso_hostname}: the login page only ---"
    yield f"{INDENT}acl h_fg_sso req.hdr(host),host_only -i {spec.sso_hostname}"
    yield f"{INDENT}acl p_fg_sso path_beg /api/v1/sso/"
    yield f"{INDENT}http-request deny deny_status 404 if h_fg_sso !p_fg_sso"
    yield f"{INDENT}http-request set-header X-Foxguard-Client-IP %[src] if h_fg_sso"


def _service_rules(
    spec: ProxySpec, service: Service, exposure: Exposure, guard: str | None
) -> Iterator[str]:
    """Filters, then access, then authentication -- cheapest and least forgeable first.

    ``guard`` is the ACL selecting this service on a shared frontend. A TCP
    passthrough service has a frontend to itself, so there is nothing to select
    on and ``guard`` is ``None``: HAProxy has no "always" ACL name, and writing
    one would be a condition that is read on every request for no reason.
    """
    http = service.kind is ServiceKind.HTTP
    deny = "http-request deny" if http else "tcp-request content reject"
    prefix = INDENT

    def cond(*parts: str) -> str:
        """Join a guard and its conditions into an ``if`` clause."""
        terms = [term for term in ((guard,) + parts) if term]
        return (" if " + " ".join(terms)) if terms else ""

    for index, item in enumerate(service.filters):
        if not item.scope.covers(exposure):
            continue
        if item.kind is FilterKind.IP_DENY:
            path = f"{spec.maps_dir}/{ipfilter_file(service.slug, index)}"
            yield f"{prefix}{deny}{cond(f'{{ src -f {path} }}')}"
        elif item.kind is FilterKind.IP_ALLOW:
            path = f"{spec.maps_dir}/{ipfilter_file(service.slug, index)}"
            yield f"{prefix}{deny}{cond(f'!{{ src -f {path} }}')}"
        elif item.kind is FilterKind.RATE_LIMIT and http:
            table = table_name(service.slug)
            yield f"{prefix}http-request track-sc0 src table {table}{cond()}"
            yield (
                f"{prefix}http-request deny deny_status 429"
                f"{cond(f'{{ sc_http_req_rate(0) gt {item.rate} }}')}"
            )

    rules = service.access_for(exposure)
    denies = [rule for rule in rules if rule.action is AccessAction.DENY]
    allows = [rule for rule in rules if rule.action is AccessAction.ALLOW]

    for rule in denies:
        source = _source_cond(spec, rule)
        yield f"{prefix}{deny}{cond(*((source,) if source else ()))}"
    # Deny when *none* of the allow rules matched. Expressed as a chain of
    # negations because HAProxy's condition language has no OR. An allow rule
    # for "any" produces no condition at all, so it correctly matches
    # everything and suppresses the catch-all deny.
    if allows and all(_source_cond(spec, rule) for rule in allows):
        negated = tuple(f"!{_source_cond(spec, rule)}" for rule in allows)
        yield f"{prefix}{deny}{cond(*negated)}"

    auths = service.auth_for(exposure)
    if not auths:
        return

    sso = next((a for a in auths if a.kind is AuthKind.FOXGUARD_SSO), None)
    if sso and http:
        yield from _sso_setup(spec, service, sso, cond)

    conditions: list[str] = []
    for auth in auths:
        if auth.kind is AuthKind.FOXGUARD_SSO and http:
            allowed = _sso_authorized(service, auth)
            conditions.append(
                f"{_sso_condition(service)} {allowed}" if allowed
                else _sso_condition(service)
            )
        elif auth.kind is AuthKind.PEER_IDENTITY:
            conditions.append(f"{{ src -f {spec.maps_dir}/{set_file(PEER_SET)} }}")
        elif auth.kind is AuthKind.BEARER and http:
            conditions.append(f"{{ var(txn.fg_tok_{_var(service.slug)}) -m found }}")
        elif auth.kind is AuthKind.BASIC and http:
            conditions.append(f"{{ http_auth({userlist_name(service.slug)}) }}")

    if not conditions:
        return

    if any(a.kind is AuthKind.BEARER for a in auths) and http:
        # ,lower because HAProxy's hex converter is uppercase and the map is not.
        path = f"{spec.maps_dir}/{token_file(service.slug)}"
        yield (
            f"{prefix}http-request set-var(txn.fg_tok_{_var(service.slug)}) "
            f"req.hdr(authorization),regsub(^Bearer\\ ,),sha2(256),hex,lower,"
            f"map_str({path}){cond()}"
        )

    if http:
        yield f"{prefix}http-request set-var(txn.fg_auth) int(0){cond()}"
        for condition in conditions:
            yield f"{prefix}http-request set-var(txn.fg_auth) int(1){cond(condition)}"
        failed = "{ var(txn.fg_auth) -m int eq 0 }"
        basic = next((a for a in auths if a.kind is AuthKind.BASIC), None)
        if sso and (refused := _sso_authorized(service, sso, negated=True)):
            # Signed in, and not allowed here. This must come *before* the
            # redirect below and must not be one: sending this browser to the
            # login page would sign it in again, hand it the very same cookie,
            # and bounce it straight back -- a loop the person cannot break and
            # that reads as the service being down. Say what is wrong instead.
            wanted = ", ".join(sso.groups) if sso.groups else ""
            need = " and ".join(
                part for part in (
                    "an administrator account" if sso.require_admin else "",
                    f"membership of: {wanted}" if wanted else "",
                ) if part
            )
            yield (
                f"{prefix}http-request return status 403 content-type text/plain "
                f'lf-string "signed in as %[var(txn.fg_sub_{_var(service.slug)})], '
                f'but {service.slug} needs {need}"'
                f"{cond(failed, _sso_condition(service), refused)}"
            )
        if sso:
            # A browser gets sent to sign in; a 401 would just show it a blank
            # page. ``h`` and ``p`` are url-encoded and the login endpoint
            # refuses any host it does not publish, so this is not an open
            # redirect.
            target = (
                f"https://{spec.sso_hostname}/api/v1/sso/login"
                "?h=%[req.hdr(host),host_only,url_enc]&p=%[pathq,url_enc]"
            )
            yield f"{prefix}http-request redirect location {target} code 302{cond(failed)}"
        elif basic:
            realm = basic.realm or service.slug
            yield f'{prefix}http-request auth realm "{realm}"{cond(failed)}'
        elif any(a.kind is AuthKind.BEARER for a in auths):
            yield (
                f"{prefix}http-request return status 401 content-type text/plain "
                f"hdr www-authenticate 'Bearer realm=\"{service.slug}\"' "
                f'lf-string "authentication required"{cond(failed)}'
            )
        else:
            yield f"{prefix}http-request deny deny_status 403{cond(failed)}"

        if sso:
            yield (
                f"{prefix}http-request set-header X-Foxguard-User "
                f"%[var(txn.fg_sub_{_var(service.slug)})]"
                f"{cond(f'{{ var(txn.fg_sub_{_var(service.slug)}) -m found }}')}"
            )
        if exposure is Exposure.INTERNAL:
            # Only the internal frontend populates ``txn.fg_peer``, because only
            # there does a source address mean anything. Emitting this on the
            # WAN would be a header that can never be set -- harmless, but it
            # would suggest the identity exists out there.
            yield (
                f"{prefix}http-request set-header X-Foxguard-Peer %[var(txn.fg_peer)]"
                f"{cond('{ var(txn.fg_peer) -m found }')}"
            )
            if spec.send_group_header:
                yield (
                    f"{prefix}http-request set-header X-Foxguard-Groups "
                    f"%[src,map_str({spec.maps_dir}/{GROUPS_MAP_FILE})]"
                    f"{cond(f'{{ src,map_str({spec.maps_dir}/{GROUPS_MAP_FILE}) -m found }}')}"
                )
    else:
        negated = tuple(f"!{condition}" for condition in conditions)
        yield f"{prefix}{deny}{cond(*negated)}"


SSO_REVOKED_FILE = "sso_revoked.map"


def _sso_setup(
    spec: ProxySpec, service: Service, auth: Authenticator, cond
) -> Iterator[str]:
    """Unpack and check the session cookie.

    Every line here exists because of something measured against HAProxy
    3.0.11, so none of it is stylistic:

    * **The algorithm is pinned.** ``jwt_verify`` is given a value *we* set, not
      ``jwt_header_query('$.alg')``. Measured: a token carrying
      ``{"alg":"none"}`` and no signature verifies as **1** when the algorithm
      comes from the token, and as -3 when it does not. The idiomatic snippet is
      forgeable.
    * **Expiry is compared here.** ``jwt_verify`` ignores ``exp`` entirely -- an
      expired token verifies happily -- so ``exp - now`` is computed and
      required to be positive.
    * **Only ``1`` counts.** The converter returns negative values for invalid
      tokens, and a truthiness test would let those through.
    """
    tag = _var(service.slug)
    maps = spec.maps_dir
    yield f"{INDENT}# --- single sign-on: pinned algorithm, explicit expiry ---"
    yield f"{INDENT}http-request set-var(txn.fg_alg_{tag}) str({ALGORITHM}){cond()}"
    yield (f"{INDENT}http-request set-var(txn.fg_jwt_{tag}) req.cook({spec.sso_cookie}){cond()}")
    yield (
        f"{INDENT}http-request set-var(txn.fg_ok_{tag}) var(txn.fg_jwt_{tag}),"
        f'jwt_verify(txn.fg_alg_{tag},"{spec.sso_secret}"){cond()}'
    )
    yield (
        f"{INDENT}http-request set-var(txn.fg_exp_{tag}) var(txn.fg_jwt_{tag}),"
        f"jwt_payload_query('$.exp','int'){cond()}"
    )
    yield f"{INDENT}http-request set-var(txn.fg_now_{tag}) date(){cond()}"
    yield (
        f"{INDENT}http-request set-var(txn.fg_left_{tag}) var(txn.fg_exp_{tag}),"
        f"sub(txn.fg_now_{tag}){cond()}"
    )
    yield (
        f"{INDENT}http-request set-var(txn.fg_sub_{tag}) var(txn.fg_jwt_{tag}),"
        f"jwt_payload_query('$.sub'){cond()}"
    )
    yield (
        f"{INDENT}http-request set-var(txn.fg_jti_{tag}) var(txn.fg_jwt_{tag}),"
        f"jwt_payload_query('$.jti'){cond()}"
    )
    # Revocation. A signature stays valid until the token expires, so this map
    # is the only thing that makes signing somebody out mean *now*. The agent
    # pushes it over the runtime socket without a reload.
    yield (
        f"{INDENT}http-request set-var(txn.fg_rev_{tag}) var(txn.fg_jti_{tag}),"
        f"map_str({maps}/{SSO_REVOKED_FILE}){cond()}"
    )
    yield from _sso_authz(service, auth, cond)


def _sso_authz(service: Service, auth: Authenticator, cond) -> Iterator[str]:
    """Reduce "may this person use this service" to one integer.

    A variable rather than a condition reused in two places, because the answer
    is needed **negated** as well -- and the requirement is a conjunction, whose
    negation is a disjunction, which HAProxy's condition language cannot
    express. Computing it once sidesteps that: ``eq 0`` is a perfectly good
    negation of ``eq 1``.

    Emitted only when something is actually required. A service that admits any
    signed-in account renders exactly what it did before this existed.
    """
    if not (auth.groups or auth.require_admin):
        return
    tag = _var(service.slug)
    yield f"{INDENT}# authorisation: signed in is not the same as allowed in"
    terms: list[str] = []
    if auth.groups:
        yield (
            f"{INDENT}http-request set-var(txn.fg_grp_{tag}) var(txn.fg_jwt_{tag}),"
            f"jwt_payload_query('$.groups'){cond()}"
        )
        # Several patterns on one condition are an OR -- measured. The claim
        # wraps every slug in the delimiter, which is what stops ',inf,' from
        # matching a member of 'infra'.
        patterns = " ".join(
            f"{GROUP_DELIMITER}{slug}{GROUP_DELIMITER}" for slug in auth.groups
        )
        terms.append(f"{{ var(txn.fg_grp_{tag}) -m sub {patterns} }}")
    if auth.require_admin:
        yield (
            f"{INDENT}http-request set-var(txn.fg_adm_{tag}) var(txn.fg_jwt_{tag}),"
            f"jwt_payload_query('$.admin','int'){cond()}"
        )
        terms.append(f"{{ var(txn.fg_adm_{tag}) -m int eq 1 }}")
    yield f"{INDENT}http-request set-var(txn.fg_az_{tag}) int(0){cond()}"
    yield f"{INDENT}http-request set-var(txn.fg_az_{tag}) int(1){cond(*terms)}"


def _sso_condition(service: Service) -> str:
    """All three checks, as one condition. Any missing one lets a forgery in.

    Session *validity* only. Authorisation is deliberately not folded in here,
    because the two failures deserve different answers -- see
    :func:`_sso_authorized`.
    """
    tag = _var(service.slug)
    return (
        f"{{ var(txn.fg_ok_{tag}) -m int eq 1 }} "
        f"{{ var(txn.fg_left_{tag}) -m int gt 0 }} "
        f"!{{ var(txn.fg_rev_{tag}) -m found }}"
    )


def _sso_authorized(service: Service, auth: Authenticator, *, negated: bool = False) -> str:
    """The authorisation verdict, or ``""`` when nothing is required."""
    if not (auth.groups or auth.require_admin):
        return ""
    return f"{{ var(txn.fg_az_{_var(service.slug)}) -m int eq {0 if negated else 1} }}"


def _var(slug: str) -> str:
    """A slug as a HAProxy variable-name component.

    Slugs may contain hyphens (``ck_groups_slug_format`` allows them) and a
    variable name may not. Same substitution the nftables generator makes for
    set names, and for the same reason.
    """
    return slug.replace("-", "_")


def _source_cond(spec: ProxySpec, rule) -> str:
    """The condition selecting a rule's source, or ``""`` for "any"."""
    if rule.source is None:
        return ""
    if rule.is_set:
        return f"{{ src -f {spec.maps_dir}/{set_file(rule.source)} }}"
    return f"{{ src {rule.source} }}"


def _tcp_frontend(spec: ProxySpec, service: Service) -> Iterator[str]:
    internal = service.exposure.has_internal
    external = service.exposure.has_external
    binds: list[str] = []
    if internal:
        binds += list(spec.internal_binds)
    if external:
        binds += list(spec.external_binds)

    yield f"# {service.slug}: passthrough, so nothing above layer 4 is visible."
    yield f"frontend {tcp_frontend_name(service.slug)}"
    yield f"{INDENT}mode tcp"
    yield f"{INDENT}option tcplog"
    for address in binds:
        yield f"{INDENT}bind {_bind(address)}:{service.listen_port}"

    exposure = Exposure.INTERNAL if internal and not external else Exposure.EXTERNAL
    yield f"{INDENT}tcp-request inspect-delay 5s"
    yield from _service_rules(spec, service, exposure, None)
    yield f"{INDENT}default_backend {backend_name(service.slug)}"


def _backend(spec: ProxySpec, service: Service) -> Iterator[str]:
    backend = service.backend
    yield f"backend {backend_name(service.slug)}"
    yield f"{INDENT}mode {'http' if service.kind is ServiceKind.HTTP else 'tcp'}"
    yield f"{INDENT}errorfile 503 {spec.maps_dir}/{error_file(service.slug)}"

    options = []
    if backend.tls:
        options.append("ssl")
        options.append("verify required" if backend.tls_verify else "verify none")
        if backend.tls_verify:
            options.append("ca-file @system-ca")
    if backend.check:
        options.append(f"check inter {backend.check_interval_seconds}s")
    suffix = (" " + " ".join(options)) if options else ""
    yield f"{INDENT}server s1 {_bind(backend.address)}:{backend.port}{suffix}"


def _no_service_backend(spec: ProxySpec) -> Iterator[str]:
    yield "# Anything whose Host matches no published service."
    yield "backend be_fg_no_service"
    yield f"{INDENT}mode http"
    yield f"{INDENT}errorfile 503 {spec.maps_dir}/{DEFAULT_ERROR_FILE}"
    yield f"{INDENT}http-request deny deny_status 503"


def _bind(address: str) -> str:
    """IPv6 literals need brackets in a bind line."""
    return f"[{address}]" if ":" in address else address


# --------------------------------------------------------------------------- #
# digest
# --------------------------------------------------------------------------- #


def proxy_digest(conf: str, files: dict[str, str]) -> str:
    """Stable digest of the configuration and every file it references.

    One digest rather than many because they are only meaningful together: a
    configuration referencing a token map from a previous state is not a state
    the agent should be able to reach.
    """
    hasher = hashlib.sha256()
    hasher.update(b"conf\0")
    hasher.update(conf.encode("utf-8"))
    for name in sorted(files):
        hasher.update(b"\0file\0")
        hasher.update(name.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(files[name].encode("utf-8"))
    return hasher.hexdigest()
