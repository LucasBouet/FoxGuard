"""Administrator sign-in.

The endpoints here are the reason an audit entry can name a person. Everything
else under ``/api/v1`` requires an identity; these three establish one.

``/login`` is deliberately *not* behind ``require_admin`` -- it is how you get
credentials -- so it carries the same protections as the portal's login: opaque
failures outward, precise reasons in the audit log, and a throttle keyed on the
source address.
"""

from __future__ import annotations

import functools
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import ActorType, AdminSession, User
from ...schemas import (
    AdminLoginRequest,
    AdminLoginResponse,
    AdminOidcCompleteRequest,
    AdminOidcStartResponse,
    AdminSessionRead,
    AdminWhoAmI,
)
from ...services import admin_auth, audit
from ...services.admin_auth import AdminIdentity
from ...services.oidc import OidcClient, OidcError, TransactionStore
from ...services.ratelimit import RateLimited
from ..deps import (
    admin_login_limiter,
    audit_context,
    bearer_token,
    client_ip,
    rate_limited_response,
    require_admin,
)

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.post("/login", response_model=AdminLoginResponse)
def login(
    payload: AdminLoginRequest,
    request: Request,
    user_agent: str | None = Header(default=None),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AdminLoginResponse:
    """Sign in and receive a session token, shown once.

    The token is a bearer credential: send it as ``Authorization: Bearer``. The
    dashboard keeps it in an httpOnly cookie on its own origin so it never
    reaches client-side JavaScript.
    """
    limiter = admin_login_limiter()
    # Keyed on the source address rather than the username: keying on a name
    # would let anyone lock out an administrator they merely know of.
    key = f"admin:{client_ip(request) or 'unknown'}"
    try:
        limiter.check(key)
    except RateLimited as exc:
        session.commit()
        raise rate_limited_response(exc) from exc

    outcome = admin_auth.authenticate(
        session,
        username=payload.username,
        password=payload.password,
        totp_code=payload.totp_code,
    )
    if not outcome:
        limiter.record_failure(key)
        audit.record(
            session,
            action="admin.login.denied",
            actor_type=ActorType.SYSTEM,
            actor_label=payload.username,
            source_ip=client_ip(request),
            detail={"reason": outcome.reason},
        )
        session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    user = outcome.user
    assert user is not None  # noqa: S101 - narrowed by `if not outcome`
    row, token = admin_auth.issue(
        session,
        user,
        lifetime_seconds=settings.admin_session_lifetime_seconds,
        source_ip=client_ip(request),
        user_agent=user_agent,
    )

    limiter.reset(key)
    audit.record(
        session,
        action="admin.login",
        actor_type=ActorType.ADMIN,
        actor_user_id=user.id,
        actor_label=user.username,
        source_ip=client_ip(request),
        detail={"session": str(row.id)},
    )
    session.commit()

    return AdminLoginResponse(
        token=token,
        expires_at=row.expires_at,
        user=AdminWhoAmI(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            totp_enabled=user.totp_enabled,
            via="session",
        ),
    )


# --------------------------------------------------------------------------- #
# OIDC sign-in
# --------------------------------------------------------------------------- #
#
# Split into start/complete rather than a single callback on purpose. The IdP
# redirects the *browser*, and the browser is talking to the dashboard, not to
# this API -- so the dashboard receives the code and completes the exchange
# server-side. That way the session token goes straight into its httpOnly cookie
# instead of travelling back through a URL, where it would land in logs, history
# and `Referer` headers.


@functools.lru_cache(maxsize=1)
def _transactions() -> TransactionStore:
    return TransactionStore(ttl_seconds=get_settings().oidc_transaction_ttl_seconds)


@functools.lru_cache(maxsize=1)
def _client() -> OidcClient:
    return OidcClient(get_settings())


def reset_oidc_state() -> None:
    """Drop the cached client and store. For tests that change the settings."""
    _transactions.cache_clear()
    _client.cache_clear()


def _require_oidc(settings: Settings) -> None:
    if not settings.oidc_admin_enabled:
        raise HTTPException(
            status.HTTP_501_NOT_IMPLEMENTED,
            "administrator single sign-on is not configured",
        )


@router.get("/oidc/start", response_model=AdminOidcStartResponse)
def oidc_start(settings: Settings = Depends(get_settings)) -> AdminOidcStartResponse:
    """Begin an administrator SSO flow.

    Unauthenticated by design -- it is how you become authenticated. It reveals
    nothing: the authorization URL is derived from public IdP metadata plus a
    fresh random state.
    """
    _require_oidc(settings)
    # No subject: an administrator login is not bound to a peer. The portal's
    # callback compares the subject to a peer id, so a state minted here can
    # never be redeemed there, and vice versa.
    transaction = _transactions().start(None)
    try:
        url = _client().authorization_url(
            transaction, redirect_uri=settings.oidc_admin_redirect_url
        )
    except OidcError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    return AdminOidcStartResponse(authorization_url=url, state=transaction.state)


@router.post("/oidc/complete", response_model=AdminLoginResponse)
def oidc_complete(
    payload: AdminOidcCompleteRequest,
    request: Request,
    user_agent: str | None = Header(default=None),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AdminLoginResponse:
    """Finish an administrator SSO flow and issue a session."""
    _require_oidc(settings)
    client = _client()

    def refuse(reason: str) -> HTTPException:
        audit.record(
            session,
            action="admin.login.denied",
            actor_type=ActorType.SYSTEM,
            actor_label="oidc",
            source_ip=client_ip(request),
            detail={"reason": reason, "method": "oidc"},
        )
        session.commit()
        return HTTPException(status.HTTP_401_UNAUTHORIZED, "sign-in failed")

    transaction = _transactions().consume(payload.state)
    if transaction is None:
        raise refuse("unknown or expired state")
    if transaction.subject is not None:
        # A portal transaction: it belongs to a peer, and redeeming it here
        # would turn a device login into an administrator session.
        raise refuse("state does not belong to an administrator flow")

    try:
        tokens = client.exchange_code(
            payload.code, transaction, redirect_uri=settings.oidc_admin_redirect_url
        )
        claims = client.verify_id_token(tokens["id_token"], nonce=transaction.nonce)
    except OidcError as exc:
        raise refuse(str(exc)) from exc

    subject, issuer = claims.get("sub"), claims.get("iss")
    if not subject:
        raise refuse("id_token carried no subject")

    user = session.execute(
        select(User)
        .where(User.external_idp_issuer == issuer, User.external_idp_subject == subject)
        .limit(1)
    ).scalar_one_or_none()

    # The IdP says who they are; Foxguard decides whether they administer it.
    # Everything below is checked here rather than delegated, so a group change
    # at the IdP can never silently grant control of the network.
    if user is None:
        raise refuse("no local account is bound to this subject")
    if not user.is_active:
        raise refuse("account disabled")
    if not user.is_admin:
        raise refuse("not an administrator")

    row, token = admin_auth.issue(
        session,
        user,
        lifetime_seconds=settings.admin_session_lifetime_seconds,
        source_ip=client_ip(request),
        user_agent=user_agent,
    )
    audit.record(
        session,
        action="admin.login",
        actor_type=ActorType.ADMIN,
        actor_user_id=user.id,
        actor_label=user.username,
        source_ip=client_ip(request),
        detail={"session": str(row.id), "method": "oidc", "issuer": issuer},
    )
    session.commit()

    return AdminLoginResponse(
        token=token,
        expires_at=row.expires_at,
        user=AdminWhoAmI(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            totp_enabled=user.totp_enabled,
            via="session",
        ),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_db),
    identity: AdminIdentity = Depends(require_admin),
) -> None:
    """Revoke the session this request authenticated with.

    A no-op for the static token: there is nothing to revoke, and pretending
    otherwise would suggest a machine credential can be retired from here.
    """
    presented = bearer_token(authorization)
    row = admin_auth.resolve(session, presented) if presented else None
    if row is not None:
        admin_auth.revoke(session, row)
        audit.record(
            session,
            action="admin.logout",
            **audit_context(request),
            detail={"session": str(row.id)},
        )
    session.commit()


@router.get("/sessions", response_model=list[AdminSessionRead])
def list_sessions(
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_db),
    identity: AdminIdentity = Depends(require_admin),
) -> list[dict]:
    """Every administrator currently signed in.

    Deliberately not scoped to the caller: on a homelab gateway "who else is
    signed in" is the question worth answering, and an admin who can fire the
    kill switch can already see far more than this.
    """
    presented = bearer_token(authorization)
    current = admin_auth.resolve(session, presented) if presented else None
    now = datetime.now(UTC)

    rows = (
        session.execute(
            select(AdminSession, User)
            .join(User, User.id == AdminSession.user_id)
            .where(AdminSession.revoked_at.is_(None), AdminSession.expires_at > now)
            .order_by(AdminSession.last_seen_at.desc())
        )
        .all()
    )
    return [
        {
            "id": row.id,
            "user_id": user.id,
            "username": user.username,
            "created_at": row.created_at,
            "last_seen_at": row.last_seen_at,
            "expires_at": row.expires_at,
            "source_ip": row.source_ip,
            "user_agent": row.user_agent,
            "current": current is not None and current.id == row.id,
        }
        for row, user in rows
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session(
    session_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    identity: AdminIdentity = Depends(require_admin),
) -> None:
    """Cut one session without touching the account it belongs to.

    The lighter tool: deactivating an account or changing its password also ends
    its sessions, but those are decisions about the *person*. This is for "that
    laptop should not still be signed in".
    """
    row = session.get(AdminSession, session_id)
    if row is None or row.revoked_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")

    admin_auth.revoke(session, row)
    audit.record(
        session,
        action="admin.session.revoke",
        object_type="admin_session",
        object_id=row.id,
        **audit_context(request),
        detail={"user_id": str(row.user_id)},
    )
    session.commit()


@router.get("/me", response_model=AdminWhoAmI)
def whoami(
    session: Session = Depends(get_db),
    identity: AdminIdentity = Depends(require_admin),
) -> AdminWhoAmI:
    """Who this request is authenticated as. The dashboard's session check."""
    if not identity.is_person:
        return AdminWhoAmI(
            user_id=None, username=identity.label, display_name=None,
            totp_enabled=False, via="token",
        )
    from ...models import User

    user = session.get(User, identity.user_id)
    return AdminWhoAmI(
        user_id=identity.user_id,
        username=identity.label,
        display_name=user.display_name if user else None,
        totp_enabled=bool(user and user.totp_enabled),
        via="session",
    )
