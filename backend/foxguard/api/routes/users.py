"""User CRUD.

A user may hold a local password, an OIDC binding, or both -- the portal picks
the flow at login time (Phase 2). Nothing here depends on an IdP being
configured, which is the point: Foxguard must stay usable without one.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import User
from ...schemas import (
    TotpConfirmRequest,
    TotpProvisionRead,
    UserCreate,
    UserRead,
    UserUpdate,
)
from ...services import admin_auth, audit, passwords
from ...services import sso as sso_service
from ...services import totp as totp_service
from ..deps import (
    audit_context,
    integrity_conflict,
    regenerate_or_422,
    require_admin,
    resolve_groups,
)

router = APIRouter(
    prefix="/api/v1/users", tags=["users"], dependencies=[Depends(require_admin)]
)


def _get_or_404(session: Session, user_id: uuid.UUID) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return user


def _serialise(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "is_admin": user.is_admin,
        "is_active": user.is_active,
        "totp_enabled": user.totp_enabled,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
        "auth_methods": user.available_auth_methods,
        "group_slugs": sorted(group.slug for group in user.groups),
    }


def _resolve_groups(session: Session, slugs: list[str]) -> list:
    return resolve_groups(
        session,
        slugs,
        zone_hint="a zone is a routed network segment and a person does not "
        "sit in one; put their devices in it instead",
    )


@router.get("", response_model=list[UserRead])
def list_users(session: Session = Depends(get_db)) -> list[dict]:
    users = session.execute(select(User).order_by(User.username)).scalars().all()
    return [_serialise(user) for user in users]


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate, request: Request, session: Session = Depends(get_db)
) -> dict:
    user = User(
        username=payload.username,
        email=payload.email,
        display_name=payload.display_name,
        is_admin=payload.is_admin,
        is_active=payload.is_active,
        external_idp_issuer=payload.external_idp_issuer,
        external_idp_subject=payload.external_idp_subject,
        password_hash=passwords.hash_password(payload.password) if payload.password else None,
    )
    user.groups = _resolve_groups(session, payload.group_slugs)
    session.add(user)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(
            exc, "username or IdP subject already exists"
        ) from exc

    audit.record(
        session,
        action="user.create",
        object_type="user",
        object_id=user.id,
        **audit_context(request),
        detail={"username": user.username, "admin": user.is_admin},
    )
    session.commit()
    return _serialise(user)


@router.get("/{user_id}", response_model=UserRead)
def get_user(user_id: uuid.UUID, session: Session = Depends(get_db)) -> dict:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return _serialise(user)


@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")

    changes = payload.model_dump(exclude_unset=True)
    password = changes.pop("password", None)
    if password:
        user.password_hash = passwords.hash_password(password)
    membership_changed = False
    if "group_slugs" in changes:
        slugs = changes.pop("group_slugs") or []
        before = {group.slug for group in user.groups}
        user.groups = _resolve_groups(session, slugs)
        membership_changed = before != set(slugs)
    for key, value in changes.items():
        setattr(user, key, value)

    # Deactivating an account or taking its admin rights away must end the
    # sessions it already holds. `admin_auth.resolve` re-checks both flags on
    # every request, so those sessions are already dead -- this marks the rows
    # too, so "who is signed in" does not list people who are not.
    revoked = 0
    if changes.get("is_active") is False or changes.get("is_admin") is False:
        revoked = admin_auth.revoke_all_for_user(session, user.id)
    if password:
        # A password change invalidates anything issued against the old one.
        revoked += admin_auth.revoke_all_for_user(session, user.id)

    # SSO sessions are a separate matter, and the reasoning is the opposite of
    # the one above: nothing re-checks them per request. The groups and the
    # admin flag are claims inside a cookie the proxy verifies on its own, so
    # they keep saying whatever they said when the token was signed. Taking an
    # access away therefore has to end the sessions carrying it, or the removal
    # would not take effect until the cookie happened to expire.
    sso_revoked = 0
    if (
        membership_changed
        or changes.get("is_active") is False
        or changes.get("is_admin") is False
    ):
        sso_revoked = sso_service.revoke_for_user(session, user.id)
    session.flush()
    if sso_revoked:
        # Puts the revoked jtis in the denylist map the proxy reads; the agent
        # pushes it over the runtime socket without a reload.
        regenerate_or_422(session, settings, actor="admin-api")

    audit.record(
        session,
        action="user.update",
        object_type="user",
        object_id=user.id,
        **audit_context(request),
        detail={
            "changes": [
                *changes,
                *(["password"] if password else []),
                *(["group_slugs"] if membership_changed else []),
            ],
            "admin_sessions_revoked": revoked,
            "sso_sessions_revoked": sso_revoked,
        },
    )
    session.commit()
    return _serialise(user)


# --------------------------------------------------------------------------- #
# TOTP (local accounts only -- an OIDC account's second factor is the IdP's job)
# --------------------------------------------------------------------------- #


@router.post(
    "/{user_id}/totp", response_model=TotpProvisionRead, status_code=status.HTTP_201_CREATED
)
def provision_totp(
    user_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> TotpProvisionRead:
    """Generate a secret and return it once, **without enabling TOTP yet**.

    Enabling on provisioning would lock the user out of their own account the
    moment the QR code failed to scan, so the flag only flips once they prove
    they can produce a code (see :func:`confirm_totp`).
    """
    user = _get_or_404(session, user_id)
    if not user.password_hash:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "TOTP protects a local password; this account has none",
        )

    secret = totp_service.generate_secret()
    user.totp_secret = secret
    user.totp_enabled = False
    # A fresh secret starts with a clean replay ledger; carrying the old high
    # water mark over would reject valid codes from the new authenticator.
    user.totp_last_used_step = None
    session.flush()

    audit.record(
        session,
        action="user.totp.provision",
        object_type="user",
        object_id=user.id,
        **audit_context(request),
        detail={"username": user.username},
    )
    session.commit()
    return TotpProvisionRead(
        secret=secret,
        provisioning_uri=totp_service.provisioning_uri(
            secret, username=user.username, issuer=settings.totp_issuer
        ),
        enabled=False,
    )


@router.post("/{user_id}/totp/confirm", response_model=UserRead)
def confirm_totp(
    user_id: uuid.UUID,
    payload: TotpConfirmRequest,
    request: Request,
    session: Session = Depends(get_db),
) -> dict:
    """Verify one code, then enforce TOTP for this account from now on."""
    user = _get_or_404(session, user_id)
    if not user.totp_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "no TOTP secret provisioned")

    step = totp_service.verify(
        user.totp_secret, payload.code, last_used_step=user.totp_last_used_step
    )
    if step is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid TOTP code")

    user.totp_enabled = True
    user.totp_last_used_step = step
    session.flush()

    audit.record(
        session,
        action="user.totp.enable",
        object_type="user",
        object_id=user.id,
        **audit_context(request),
        detail={"username": user.username},
    )
    session.commit()
    return _serialise(user)


@router.delete("/{user_id}/totp", response_model=UserRead)
def disable_totp(
    user_id: uuid.UUID, request: Request, session: Session = Depends(get_db)
) -> dict:
    """Turn TOTP off and destroy the secret.

    The secret is cleared rather than kept "in case they turn it back on": a
    disabled factor whose seed is still in the database is a credential nobody
    is watching.
    """
    user = _get_or_404(session, user_id)
    user.totp_enabled = False
    user.totp_secret = None
    user.totp_last_used_step = None
    session.flush()

    audit.record(
        session,
        action="user.totp.disable",
        object_type="user",
        object_id=user.id,
        **audit_context(request),
        detail={"username": user.username},
    )
    session.commit()
    return _serialise(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: uuid.UUID, request: Request, session: Session = Depends(get_db)
) -> None:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    username = user.username
    session.delete(user)
    session.flush()

    audit.record(
        session,
        action="user.delete",
        object_type="user",
        object_id=user_id,
        **audit_context(request),
        detail={"username": username},
    )
    session.commit()
