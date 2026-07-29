"""The captive portal: where a *user* peer leaves quarantine.

Reachable without a bearer token, from inside the tunnel only. The caller is
identified the same way as for enrollment -- by the tunnel address it sends
from, which WireGuard binds to a public key -- and then has to prove a human is
present.

**There is no cookie and no session token.** What authenticating buys is
*network access*, expressed in the nftables ruleset; an HTTP session on top of
that would be a second, weaker copy of the same state. So every endpoint here
re-derives the peer from the source address, and "log out" means going back to
quarantine, not dropping a cookie.

**The account must be the one the device is bound to.** ``owner_user_id`` is set
when the peer is registered and never inferred at request time. Without that
check, any valid credential in the database would unlock any device -- and
because ACL groups belong to the *peer*, an attacker with their own low-privilege
account could log in on a stolen admin laptop and inherit its access.
"""

from __future__ import annotations

import functools
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import ActorType, AuthMethod, Peer, User
from ...nftables import PeerState, PeerType
from ...schemas import (
    OidcStartResponse,
    PortalLoginRequest,
    PortalLoginResponse,
    PortalLogoutResponse,
    PortalStatusRead,
)
from ...services import audit, passwords, peer_state, sessions
from ...services import ruleset as ruleset_service
from ...services import totp as totp_service
from ...services.oidc import OidcClient, OidcError, TransactionStore
from ...services.ratelimit import RateLimited
from ..deps import calling_peer, client_ip, login_limiter, rate_limited_response

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/portal", tags=["portal"])


def _owner(session: Session, peer: Peer) -> User | None:
    if peer.owner_user_id is None:
        return None
    return session.get(User, peer.owner_user_id)


# Built once per process rather than per request: the transaction store *is*
# process state, and the client caches discovery + JWKS. Both take no argument
# because `get_settings` is itself a cached singleton -- a pydantic Settings is
# mutable and therefore not hashable, so it cannot be an lru_cache key.
@functools.lru_cache(maxsize=1)
def _transactions_cached() -> TransactionStore:
    return TransactionStore(ttl_seconds=get_settings().oidc_transaction_ttl_seconds)


@functools.lru_cache(maxsize=1)
def _oidc_client_cached() -> OidcClient:
    return OidcClient(get_settings())


def _transactions(settings: Settings) -> TransactionStore:  # noqa: ARG001 - DI shape
    return _transactions_cached()


def _oidc_client(settings: Settings) -> OidcClient:  # noqa: ARG001 - DI shape
    return _oidc_client_cached()


def reset_oidc_state() -> None:
    """Drop the cached client and store. For tests that change the settings."""
    _transactions_cached.cache_clear()
    _oidc_client_cached.cache_clear()


def _oidc_owner(session: Session, peer: Peer, settings: Settings) -> User:
    """Everything that must hold before an OIDC flow is worth starting."""
    if not settings.oidc_enabled:
        raise HTTPException(
            status.HTTP_501_NOT_IMPLEMENTED, "no identity provider is configured"
        )
    if peer.peer_type is not PeerType.USER:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "server peers enroll with a key, not the portal"
        )
    owner = _owner(session, peer)
    if owner is None or not owner.external_idp_subject:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "this peer's account has no IdP binding"
        )
    return owner


@router.get("/status", response_model=PortalStatusRead)
def status_(
    peer: Peer = Depends(calling_peer),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> PortalStatusRead:
    """What the portal UI needs to render the right form.

    Only ever describes the peer that owns the calling address, so it discloses
    nothing the caller could not already infer from its own access.
    """
    owner = _owner(session, peer)
    live = sessions.active_session(session, peer) if peer.state is PeerState.ACTIVE else None
    return PortalStatusRead(
        peer_id=peer.id,
        peer_name=peer.name,
        peer_type=peer.peer_type,
        state=peer.state,
        authenticated=peer.state is PeerState.ACTIVE,
        username=owner.username if owner else None,
        auth_methods=owner.available_auth_methods if owner else [],
        totp_required=bool(owner and owner.totp_enabled),
        oidc_available=settings.oidc_enabled and bool(owner and owner.external_idp_subject),
        session_expires_at=live.expires_at if live else None,
    )


@router.post("/login", response_model=PortalLoginResponse)
def login(
    payload: PortalLoginRequest,
    request: Request,
    peer: Peer = Depends(calling_peer),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> PortalLoginResponse:
    """Authenticate with a local account (password, plus TOTP when enabled)."""
    limiter = login_limiter()
    # Keyed on the peer, not the username: the peer is the thing an attacker
    # cannot forge, and keying on the username would let anyone lock out an
    # account they merely know the name of.
    limiter_key = f"portal:{peer.id}"
    try:
        limiter.check(limiter_key)
    except RateLimited as exc:
        session.commit()
        raise rate_limited_response(exc) from exc

    def refuse(reason: str) -> HTTPException:
        """Opaque 401 outward, precise reason in the audit log."""
        limiter.record_failure(limiter_key)
        audit.record(
            session,
            action="portal.login.denied",
            actor_type=ActorType.PEER,
            actor_label=peer.name,
            object_type="peer",
            object_id=peer.id,
            source_ip=client_ip(request),
            detail={"reason": reason, "username": payload.username},
        )
        session.commit()
        return HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    if peer.peer_type is not PeerType.USER:
        # Server peers have no portal flow at all -- they enroll with a key.
        raise refuse("not a user peer")

    owner = _owner(session, peer)
    candidate = session.execute(
        select(User).where(User.username == payload.username).limit(1)
    ).scalar_one_or_none()

    if candidate is None or owner is None or candidate.id != owner.id:
        # Spend the time a real verification would, so "no such user" and "wrong
        # account for this device" are not distinguishable from "wrong password".
        passwords.burn(payload.password)
        raise refuse("username does not match the account bound to this peer")

    if not owner.is_active:
        passwords.burn(payload.password)
        raise refuse("account disabled")

    if not passwords.verify_password(payload.password, owner.password_hash):
        raise refuse("wrong password")

    if owner.totp_enabled:
        step = totp_service.verify(
            owner.totp_secret,
            payload.totp_code,
            last_used_step=owner.totp_last_used_step,
        )
        if step is None:
            raise refuse("missing or invalid TOTP code")
        # Burn the step before anything else can fail: a code must not survive
        # to a second attempt even if the rest of this request goes wrong.
        owner.totp_last_used_step = step

    try:
        peer_state.assert_self_service_transition(peer.state, PeerState.ACTIVE)
    except peer_state.IllegalTransition as exc:
        raise refuse(f"state {peer.state.value} is not eligible") from exc

    # Correct credentials always cost the account a rehash check -- the cost
    # parameters change over the years and login is the only moment we hold the
    # plaintext.
    if owner.password_hash and passwords.needs_rehash(owner.password_hash):
        owner.password_hash = passwords.hash_password(payload.password)

    row = sessions.open_session(
        session,
        peer=peer,
        user=owner,
        method=AuthMethod.LOCAL,
        settings=settings,
        source_ip=client_ip(request),
    )
    peer.state = PeerState.ACTIVE
    session.flush()

    limiter.reset(limiter_key)
    audit.record(
        session,
        action="portal.login",
        actor_type=ActorType.USER,
        actor_user_id=owner.id,
        actor_label=owner.username,
        object_type="peer",
        object_id=peer.id,
        source_ip=client_ip(request),
        detail={"method": AuthMethod.LOCAL.value, "expires_at": row.expires_at.isoformat()},
    )
    ruleset_service.regenerate(session, settings, generated_by="portal.login")
    session.commit()

    return PortalLoginResponse(
        peer_id=peer.id,
        state=peer.state,
        username=owner.username,
        auth_method=AuthMethod.LOCAL,
        group_slugs=sorted(group.slug for group in peer.groups),
        session_expires_at=row.expires_at,
    )


# --------------------------------------------------------------------------- #
# OIDC
# --------------------------------------------------------------------------- #


@router.get("/oidc/start", response_model=OidcStartResponse)
def oidc_start(
    peer: Peer = Depends(calling_peer),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> OidcStartResponse:
    """Begin an authorization-code flow and hand the URL back to the portal UI.

    JSON rather than a 307 so the caller decides how to navigate; the Phase 4
    portal will simply assign it to ``window.location``.
    """
    owner = _oidc_owner(session, peer, settings)
    transaction = _transactions(settings).start(peer.id)
    try:
        url = _oidc_client(settings).authorization_url(transaction)
    except OidcError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc

    logger.info("oidc: started a login for peer %s (user %s)", peer.id, owner.username)
    return OidcStartResponse(authorization_url=url, state=transaction.state)


@router.get("/oidc/callback")
def oidc_callback(
    request: Request,
    state: str,
    code: str | None = None,
    error: str | None = None,
    peer: Peer = Depends(calling_peer),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Finish the flow: verify the ID token, then activate the peer."""
    client = _oidc_client(settings)

    def refuse(reason: str) -> HTTPException:
        audit.record(
            session,
            action="portal.login.denied",
            actor_type=ActorType.PEER,
            actor_label=peer.name,
            object_type="peer",
            object_id=peer.id,
            source_ip=client_ip(request),
            detail={"reason": reason, "method": AuthMethod.OIDC.value},
        )
        session.commit()
        return HTTPException(status.HTTP_401_UNAUTHORIZED, "OIDC login failed")

    if error:
        raise refuse(f"identity provider returned {error}")
    if not code:
        raise refuse("no authorization code")

    transaction = _transactions(settings).consume(state)
    if transaction is None:
        # Unknown, expired, or already used: a callback is good exactly once.
        raise refuse("unknown or expired state")
    if transaction.subject != peer.id:
        # The flow was started from a different tunnel address. Finishing
        # someone else's login is how a peer would inherit their session.
        raise refuse("state belongs to a different peer")

    try:
        tokens = client.exchange_code(code, transaction)
        claims = client.verify_id_token(tokens["id_token"], nonce=transaction.nonce)
    except OidcError as exc:
        raise refuse(str(exc)) from exc

    subject = claims.get("sub")
    issuer = claims.get("iss")
    if not subject:
        raise refuse("id_token carried no subject")

    user = session.execute(
        select(User)
        .where(User.external_idp_issuer == issuer, User.external_idp_subject == subject)
        .limit(1)
    ).scalar_one_or_none()

    # Same rule as the local flow: the account must be the one this device is
    # bound to. A valid token for *some* user is not a valid token for *this* peer.
    if user is None or peer.owner_user_id != user.id:
        raise refuse("no local account is bound to this subject and peer")
    if not user.is_active:
        raise refuse("account disabled")

    try:
        peer_state.assert_self_service_transition(peer.state, PeerState.ACTIVE)
    except peer_state.IllegalTransition as exc:
        raise refuse(f"state {peer.state.value} is not eligible") from exc

    row = sessions.open_session(
        session,
        peer=peer,
        user=user,
        method=AuthMethod.OIDC,
        settings=settings,
        source_ip=client_ip(request),
    )
    peer.state = PeerState.ACTIVE
    session.flush()

    audit.record(
        session,
        action="portal.login",
        actor_type=ActorType.USER,
        actor_user_id=user.id,
        actor_label=user.username,
        object_type="peer",
        object_id=peer.id,
        source_ip=client_ip(request),
        detail={"method": AuthMethod.OIDC.value, "issuer": issuer},
    )
    ruleset_service.regenerate(session, settings, generated_by="portal.login.oidc")
    session.commit()

    if settings.oidc_post_login_redirect:
        return RedirectResponse(
            settings.oidc_post_login_redirect, status_code=status.HTTP_303_SEE_OTHER
        )
    return PortalLoginResponse(
        peer_id=peer.id,
        state=peer.state,
        username=user.username,
        auth_method=AuthMethod.OIDC,
        group_slugs=sorted(group.slug for group in peer.groups),
        session_expires_at=row.expires_at,
    )


@router.post("/logout", response_model=PortalLogoutResponse)
def logout(
    request: Request,
    peer: Peer = Depends(calling_peer),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> PortalLogoutResponse:
    """Give up network access voluntarily: back to quarantine, now.

    Because the quarantine drop is evaluated before the ``established,related``
    accept, this cuts connections that are already open rather than only new
    ones -- logging out on a shared machine means something.
    """
    if peer.peer_type is not PeerType.USER:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "server peers do not have portal sessions"
        )

    sessions.revoke_sessions(session, peer)
    if peer.state is PeerState.ACTIVE:
        peer.state = PeerState.QUARANTINED
    session.flush()

    audit.record(
        session,
        action="portal.logout",
        actor_type=ActorType.PEER,
        actor_label=peer.name,
        object_type="peer",
        object_id=peer.id,
        source_ip=client_ip(request),
        detail={},
    )
    ruleset_service.regenerate(session, settings, generated_by="portal.logout")
    session.commit()
    return PortalLogoutResponse(peer_id=peer.id, state=peer.state)
