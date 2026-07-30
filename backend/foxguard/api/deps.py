"""Shared FastAPI dependencies.

Phase 1 authentication is deliberately minimal: two static bearer tokens, one
for the admin API and one for the gateway agent. Phase 2 replaces the admin one
with real sessions (local login / OIDC); the agent token stays as-is because
the agent is a machine with no human behind it.
"""

from __future__ import annotations

import functools
import hmac
import ipaddress
import logging

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..db import get_db
from ..models import Peer
from ..nftables import RulesetValidationError
from ..services import admin_auth
from ..services import ruleset as ruleset_service
from ..services.admin_auth import AdminIdentity
from ..services.ratelimit import RateLimited, RateLimiter

logger = logging.getLogger(__name__)

__all__ = [
    "SettingsDep",
    "DbDep",
    "AdminIdentity",
    "admin_login_limiter",
    "assert_no_forwarded_headers",
    "bearer_token",
    "audit_context",
    "calling_peer",
    "enroll_limiter",
    "login_limiter",
    "require_admin",
    "require_agent",
    "client_ip",
    "integrity_conflict",
    "rate_limited_response",
    "reset_limiters",
]


def integrity_conflict(exc: IntegrityError, fallback: str) -> HTTPException:
    """Turn a constraint violation into a 409 **without guessing the cause**.

    The original error is logged in full and the violated constraint is named in
    the response. Swallowing it and asserting a cause is actively harmful: a
    duplicate group slug once surfaced as "a peer with this public key already
    exists", which sent debugging in entirely the wrong direction.
    """
    constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
    logger.warning("integrity error (constraint=%s): %s", constraint, exc.orig)
    detail = f"{fallback} (violated constraint: {constraint})" if constraint else fallback
    return HTTPException(status.HTTP_409_CONFLICT, detail)


def _check_bearer(header: str | None, expected: str | None, realm: str) -> None:
    if not expected:
        # Only reachable in dev mode; the settings validator rejects empty
        # tokens otherwise.
        return
    if not header or not header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"missing {realm} bearer token",
            headers={"WWW-Authenticate": f'Bearer realm="{realm}"'},
        )
    presented = header.split(" ", 1)[1].strip()
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"invalid {realm} token"
        )


def _is_loopback(address: str | None) -> bool:
    if not address:
        return False
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def bearer_token(header: str | None) -> str | None:
    """Extract the credential from an `Authorization: Bearer` header."""
    if not header or not header.lower().startswith("bearer "):
        return None
    return header.split(" ", 1)[1].strip() or None


def require_admin(
    request: Request,
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AdminIdentity:
    """Authenticate an admin request, as a person or as a machine.

    Two credentials are accepted, and the difference is recorded rather than
    flattened:

    * an **admin session token** issued by ``POST /api/v1/admin/login``, which
      names the person who signed in;
    * the **static token**, for provisioning scripts and CI, recorded as
      ``admin-token``.

    Sessions are tried first so that a person's identity is never lost to a
    shared secret that happens to also be present.

    The resolved identity is stashed on ``request.state`` so audit entries can
    pick it up without every route having to pass it down (see
    :func:`audit_context`).
    """
    presented = bearer_token(authorization)

    if presented:
        row = admin_auth.resolve(session, presented)
        if row is not None:
            identity = AdminIdentity.person(row.user)
            request.state.admin = identity
            # resolve() refreshed last_seen_at; nothing else in a read-only
            # request will commit, so persist it here.
            session.commit()
            return identity

    expected = (
        settings.admin_api_token.get_secret_value() if settings.admin_api_token else None
    )
    if not expected:
        # Dev mode: no token is configured, so there is nothing to check. The
        # bypass is confined to loopback rather than granted to everyone --
        # otherwise a gateway accidentally left in dev mode hands its admin API
        # to every peer on the tunnel, which is a considerably worse outcome
        # than a developer having to bind to 127.0.0.1.
        address = client_ip(request)
        if not _is_loopback(address):
            logger.error(
                "refusing an unauthenticated admin request from %s: dev mode "
                "only bypasses authentication for loopback callers",
                address,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing foxguard-admin credentials",
                headers={"WWW-Authenticate": 'Bearer realm="foxguard-admin"'},
            )
        identity = AdminIdentity.machine()
        request.state.admin = identity
        return identity

    if not presented:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing foxguard-admin credentials",
            headers={"WWW-Authenticate": 'Bearer realm="foxguard-admin"'},
        )
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid foxguard-admin credentials",
        )

    identity = AdminIdentity.machine()
    request.state.admin = identity
    return identity


def regenerate_or_422(session: Session, settings, actor: str) -> None:
    """Regenerate the ruleset, turning generator rejections into a 422.

    Every mutating route calls this instead of ``ruleset_service.regenerate``
    directly, so a state that cannot be expressed in nftables is refused by the
    request that caused it rather than committed.

    It matters on routes that seem unrelated too. The generator validates the
    *whole* spec, so once one bad row exists every later regeneration fails --
    and without this, registering an unrelated peer answers 500 instead of
    saying which rule or route is the problem. Observed exactly that way.
    """
    try:
        ruleset_service.regenerate(session, settings, generated_by=actor)
    except RulesetValidationError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"message": "resulting ruleset is invalid", "errors": list(exc.errors)},
        ) from exc


def audit_context(request: Request) -> dict:
    """Actor and source address for an audit entry, as keyword arguments.

    Call sites splat this instead of passing ``source_ip=client_ip(request)``,
    so identity travels with the address rather than being forgotten separately.
    """
    identity: AdminIdentity | None = getattr(request.state, "admin", None)
    if identity is None:
        return {"source_ip": client_ip(request)}
    return {
        "actor_type": identity.actor_type,
        "actor_user_id": identity.user_id,
        "actor_label": identity.label,
        "source_ip": client_ip(request),
    }


def require_agent(
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    token = settings.agent_api_token.get_secret_value() if settings.agent_api_token else None
    _check_bearer(authorization, token, "foxguard-agent")


#: Headers that claim to carry an originating address. Foxguard never trusts
#: them -- see `assert_no_forwarded_headers`.
_FORWARDED_HEADERS = ("x-forwarded-for", "forwarded", "x-real-ip")


def client_ip(request: Request) -> str | None:
    """Peer address of the caller.

    Foxguard parses no forwarded headers itself. That is necessary but **not
    sufficient**: uvicorn ships ``ProxyHeadersMiddleware`` enabled by default,
    trusting ``127.0.0.1``, and it rewrites ``scope["client"]`` from
    ``X-Forwarded-For`` before the application ever runs. Serve the API with
    ``foxguard.server`` (or ``uvicorn --no-proxy-headers``) so this returns the
    real TCP peer; :func:`assert_no_forwarded_headers` is the backstop for when
    it does not.
    """
    return request.client.host if request.client else None


def assert_no_forwarded_headers(request: Request) -> None:
    """Refuse a request that carries an originating-address claim.

    Belt to ``--no-proxy-headers``' braces, and the one that cannot be
    misconfigured away.

    Without it, anything able to open a connection from an address uvicorn
    trusts -- ``127.0.0.1`` by default, so any process or container on the
    gateway -- impersonates any peer by naming its tunnel address in
    ``X-Forwarded-For``. Measured against this codebase: a request that was
    correctly refused with 403 became a 200 carrying another peer's identity,
    which is enough to attempt a portal login or an enrollment as that peer.

    Foxguard's documented deployment never puts a proxy in front of the portal,
    precisely because the source address *is* the identity there. So a forwarded
    header is either a misconfiguration or an attack, and refusing is right in
    both cases -- loudly, rather than quietly trusting it.
    """
    present = [name for name in _FORWARDED_HEADERS if name in request.headers]
    if not present:
        return
    logger.error(
        "refusing a peer-identified request carrying %s from %s: the source "
        "address is the identity on this endpoint and a proxy destroys it",
        ", ".join(present),
        request.client.host if request.client else "an unknown address",
    )
    raise HTTPException(
        status.HTTP_403_FORBIDDEN,
        "this endpoint must be reached directly from the tunnel, not through a proxy",
    )


SettingsDep = Depends(get_settings)
DbDep = Depends(get_db)


# --------------------------------------------------------------------------- #
# identifying the peer behind an unauthenticated request (portal / enrollment)
# --------------------------------------------------------------------------- #


def calling_peer(
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Peer:
    """Resolve the peer a portal/enrollment request came from, by source address.

    This is the one place in Foxguard where an IP address is treated as an
    identity, so it is worth being precise about why that is sound here and
    nowhere else.

    Inside a WireGuard tunnel, the source address *is* cryptographically bound:
    cryptokey routing drops any packet whose source is not in the sending peer's
    ``AllowedIPs``, and Foxguard writes those itself, one ``/32`` per peer. A
    packet from ``10.88.0.7`` on ``wg0`` can only have been sent by the peer
    holding that address's private key.

    That guarantee evaporates the moment the request did not arrive on the
    tunnel, which is why :meth:`Settings.is_tunnel_address` is checked first and
    why ``client_ip`` deliberately ignores ``X-Forwarded-For``: a portal behind
    a header-rewriting proxy would let anyone claim any peer.

    Failures are a flat 403 with one message. Distinguishing "not on the tunnel"
    from "no such peer" would turn this into an address scanner for anyone who
    can reach the portal.
    """
    # Before anything else: if something claims to be forwarding on the caller's
    # behalf, the address below cannot be trusted to mean what it says.
    assert_no_forwarded_headers(request)

    address = client_ip(request)
    forbidden = HTTPException(
        status.HTTP_403_FORBIDDEN,
        "this endpoint is only reachable from inside the WireGuard tunnel",
    )
    if not address or not settings.is_tunnel_address(address):
        logger.warning("portal/enrollment request from non-tunnel address %s", address)
        raise forbidden

    peer = session.execute(
        select(Peer)
        .where(or_(Peer.tunnel_ip == address, Peer.tunnel_ip6 == address))
        .limit(1)
    ).scalar_one_or_none()
    if peer is None:
        logger.warning("no peer holds tunnel address %s", address)
        raise forbidden
    return peer


# --------------------------------------------------------------------------- #
# throttling
# --------------------------------------------------------------------------- #


@functools.lru_cache(maxsize=1)
def login_limiter() -> RateLimiter:
    settings = get_settings()
    return RateLimiter(
        max_attempts=settings.portal_login_max_attempts,
        window_seconds=settings.portal_login_window_seconds,
    )


@functools.lru_cache(maxsize=1)
def enroll_limiter() -> RateLimiter:
    settings = get_settings()
    return RateLimiter(
        max_attempts=settings.enroll_max_attempts,
        window_seconds=settings.enroll_window_seconds,
    )


@functools.lru_cache(maxsize=1)
def admin_login_limiter() -> RateLimiter:
    settings = get_settings()
    return RateLimiter(
        max_attempts=settings.admin_login_max_attempts,
        window_seconds=settings.admin_login_window_seconds,
    )


def reset_limiters() -> None:
    """Drop the cached limiters. For tests that change the settings."""
    login_limiter.cache_clear()
    enroll_limiter.cache_clear()
    admin_login_limiter.cache_clear()


def rate_limited_response(exc: RateLimited) -> HTTPException:
    """429 carrying a ``Retry-After``, so a client can back off politely."""
    return HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        "too many attempts; try again later",
        headers={"Retry-After": str(exc.retry_after)},
    )
