"""Services published through the reverse proxy.

Every mutation regenerates *and re-renders the proxy* before the transaction
commits, so a service that cannot be expressed in HAProxy is a 422 rather than
a row that breaks the next agent poll. See ``deps.regenerate_or_422``, which
now covers both artefacts for the same reason it covered the ruleset: the
renderer validates the whole spec, so one bad row otherwise fails every later
request from anywhere in the application.

Child rows are appended to the parent's relationship rather than inserted by
foreign key. ``Service.authenticators`` and friends are ``lazy="selectin"`` and
already loaded by ``_get_or_404``, so a bare INSERT leaves the collection stale
and the validator runs against a state that is not the one being committed --
the mistake that let a rejected zone route commit in Phase 5 and then broke
every subsequent regeneration.

Administrators only, on every route. Publishing a service punches a path
through the segmentation model and can expose it to the internet; that is not
an ordinary user's decision.
"""

from __future__ import annotations

import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import (
    Peer,
    Service,
    ServiceAccess,
    ServiceAccount,
    ServiceAuth,
    ServiceFilter,
    ServiceKind,
    ServiceToken,
)
from ...schemas import (
    ServiceAccessCreate,
    ServiceAccountCreate,
    ServiceAccountCreated,
    ServiceAccountRead,
    ServiceAuthCreate,
    ServiceCreate,
    ServiceFilterCreate,
    ServiceRead,
    ServiceTokenCreate,
    ServiceTokenCreated,
    ServiceTokenRead,
    ServiceUpdate,
)
from ...services import audit, passwords
from ...services import proxy as proxy_service
from ..deps import (
    audit_context,
    integrity_conflict,
    regenerate_or_422,
    require_admin,
    resolve_groups,
)

router = APIRouter(
    prefix="/api/v1/services", tags=["services"], dependencies=[Depends(require_admin)]
)

#: Long enough that a plain SHA-256 is the right storage, short enough to paste.
TOKEN_BYTES = 32
PASSWORD_BYTES = 24


def _get_or_404(session: Session, service_id: uuid.UUID) -> Service:
    service = session.get(Service, service_id)
    if service is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "service not found")
    return service


def _build_authenticator(session: Session, data: dict) -> ServiceAuth:
    """One authenticator row, with its group requirement resolved to real rows.

    Slugs arrive on the wire and foreign keys are stored, so a group that is
    later deleted takes its requirement with it instead of leaving a string that
    an unrelated future group with the same slug would satisfy.
    """
    slugs = data.pop("group_slugs", []) or []
    row = ServiceAuth(**data)
    row.groups = resolve_groups(
        session,
        slugs,
        zone_hint="a person is not in a routed segment, so a zone can never "
        "grant access to a published service",
    )
    return row


def _serialise_auth(row: ServiceAuth) -> dict:
    return {
        "id": row.id,
        "kind": row.kind,
        "scope": row.scope,
        "enabled": row.enabled,
        "priority": row.priority,
        "realm": row.realm,
        "group_slugs": sorted(group.slug for group in row.groups),
        "require_admin": row.require_admin,
        "created_at": row.created_at,
    }


def _serialise(service: Service, settings: Settings) -> dict:
    doors = proxy_service.doors_for(service, settings)
    return {
        "id": service.id,
        "slug": service.slug,
        "name": service.name,
        "description": service.description,
        "enabled": service.enabled,
        "kind": service.kind,
        "exposure": service.exposure,
        "upstream_peer_id": service.upstream_peer_id,
        "upstream_peer_name": service.upstream_peer.name if service.upstream_peer else None,
        "upstream_host": str(service.upstream_host),
        "upstream_port": service.upstream_port,
        "upstream_tls": service.upstream_tls,
        "upstream_tls_verify": service.upstream_tls_verify,
        "internal_hostname": service.internal_hostname,
        "external_hostname": service.external_hostname,
        "listen_port": service.listen_port,
        "sni_hostname": service.sni_hostname,
        "health_check": service.health_check,
        "health_check_interval": service.health_check_interval,
        "active_doors": doors.value if doors else None,
        "authenticators": [
            _serialise_auth(row)
            for row in sorted(
                service.authenticators, key=lambda r: (r.priority, r.kind.value)
            )
        ],
        "filters": sorted(service.filters, key=lambda r: (r.priority, r.kind.value)),
        "access": [
            {
                "id": rule.id,
                "action": rule.action,
                "kind": rule.kind,
                "group_id": rule.group_id,
                "group_slug": rule.group.slug if rule.group else None,
                "cidr": rule.cidr,
                "priority": rule.priority,
                "created_at": rule.created_at,
            }
            for rule in sorted(service.access, key=lambda r: (r.priority, str(r.id)))
        ],
        "token_count": sum(1 for row in service.tokens if row.revoked_at is None),
        "account_count": sum(1 for row in service.accounts if row.revoked_at is None),
        "created_at": service.created_at,
        "updated_at": service.updated_at,
    }


def _check_upstream(session: Session, settings: Settings, service: Service) -> None:
    """The two refusals that must happen before a service is ever written."""
    forbidden = proxy_service.forbidden_upstream(
        settings, str(service.upstream_host), service.upstream_port
    )
    if forbidden:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, forbidden)

    peer = service.upstream_peer
    if peer is None and service.upstream_peer_id:
        peer = session.get(Peer, service.upstream_peer_id)
    reachable, why = proxy_service.upstream_reachable(session, peer, str(service.upstream_host))
    if not reachable:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, why)


# --------------------------------------------------------------------------- #
# services
# --------------------------------------------------------------------------- #


@router.get("", response_model=list[ServiceRead])
def list_services(
    session: Session = Depends(get_db), settings: Settings = Depends(get_settings)
) -> list[dict]:
    services = session.execute(select(Service).order_by(Service.slug)).scalars().all()
    return [_serialise(service, settings) for service in services]


@router.post("", response_model=ServiceRead, status_code=status.HTTP_201_CREATED)
def create_service(
    payload: ServiceCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    if not settings.proxy_enabled:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "the reverse proxy is disabled; set FOXGUARD_PROXY_ENABLED=true first",
        )
    conflict = proxy_service.slug_conflict(session, payload.slug)
    if conflict:
        raise HTTPException(status.HTTP_409_CONFLICT, conflict)

    data = payload.model_dump()
    # Plain TCP cannot share a port, so one is allocated rather than left to
    # collide. An explicit port is honoured and the unique index catches a clash.
    if payload.kind is ServiceKind.TCP and not payload.listen_port and not payload.sni_hostname:
        data["listen_port"] = proxy_service.allocate_listen_port(session, settings)
    if payload.kind is ServiceKind.HTTP:
        data.setdefault("internal_hostname", None)
        data["internal_hostname"] = (
            payload.internal_hostname or _default_hostname(settings, payload.slug)
            if payload.exposure.has_internal
            else None
        )
        data["external_hostname"] = (
            payload.external_hostname or _default_hostname(settings, payload.slug)
            if payload.exposure.has_external
            else None
        )

    authenticators = data.pop("authenticators", [])
    filters = data.pop("filters", [])
    access = data.pop("access", [])

    service = Service(**data)
    # Appended to the relationships rather than inserted afterwards, so the
    # service and its policy reach the validator as one state. Creating them in
    # two requests could not work at all: a listener with no authenticator is
    # refused, so the first request would always fail.
    for row in authenticators:
        service.authenticators.append(_build_authenticator(session, row))
    for row in filters:
        service.filters.append(ServiceFilter(**row))
    for row in access:
        service.access.append(ServiceAccess(**row))
    session.add(service)
    session.flush()
    _check_upstream(session, settings, service)

    try:
        regenerate_or_422(session, settings, actor="admin-api")
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(exc, "service") from exc
    session.refresh(service)
    audit.record(
        session,
        action="service.create",
        object_type="service",
        object_id=service.slug,
        **audit_context(request),
    )
    session.commit()
    return _serialise(service, settings)


def _default_hostname(settings: Settings, slug: str) -> str | None:
    """``<slug>.<proxy_domain>``, or nothing if no domain is configured.

    The same name on both doors is the split-horizon case and is exactly what
    is wanted: a connected peer resolves it to the tunnel address and never
    leaves the tunnel, while everyone else reaches the WAN listener.
    """
    return f"{slug}.{settings.proxy_domain}" if settings.proxy_domain else None


@router.get("/{service_id}", response_model=ServiceRead)
def get_service(
    service_id: uuid.UUID,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    return _serialise(_get_or_404(session, service_id), settings)


@router.patch("/{service_id}", response_model=ServiceRead)
def update_service(
    service_id: uuid.UUID,
    payload: ServiceUpdate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    service = _get_or_404(session, service_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(service, field, value)
    session.flush()
    _check_upstream(session, settings, service)
    try:
        regenerate_or_422(session, settings, actor="admin-api")
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(exc, "service") from exc
    session.refresh(service)
    audit.record(
        session,
        action="service.update",
        object_type="service",
        object_id=service.slug,
        **audit_context(request),
    )
    session.commit()
    return _serialise(service, settings)


@router.delete("/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_service(
    service_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    service = _get_or_404(session, service_id)
    slug = service.slug
    session.delete(service)
    session.flush()
    regenerate_or_422(session, settings, actor="admin-api")
    audit.record(
        session,
        action="service.delete",
        object_type="service",
        object_id=slug,
        **audit_context(request),
    )
    session.commit()


# --------------------------------------------------------------------------- #
# policy: authenticators, filters, access
# --------------------------------------------------------------------------- #


def _add_child(
    session: Session,
    settings: Settings,
    request: Request,
    service: Service,
    collection: list,
    row,
    action: str,
) -> Service:
    # Appended to the relationship, not inserted by foreign key: the collection
    # is already loaded, and a bare INSERT would leave the validator looking at
    # a state that is not the one about to commit.
    collection.append(row)
    try:
        # The flush is inside the try, not before it: a duplicate authenticator
        # violates uq_service_auth_kind *here*, and leaving it outside turned
        # "you already have that way in" into a 500.
        session.flush()
        regenerate_or_422(session, settings, actor="admin-api")
    except HTTPException:
        session.rollback()
        raise
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(exc, "service policy") from exc
    audit.record(
        session,
        action=action,
        object_type="service",
        object_id=service.slug,
        **audit_context(request),
    )
    session.commit()
    session.refresh(service)
    return service


@router.post(
    "/{service_id}/auth",
    response_model=ServiceRead,
    status_code=status.HTTP_201_CREATED,
)
def add_authenticator(
    service_id: uuid.UUID,
    payload: ServiceAuthCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    service = _get_or_404(session, service_id)
    row = _build_authenticator(session, payload.model_dump())
    service = _add_child(
        session,
        settings,
        request,
        service,
        service.authenticators,
        row,
        "service.auth.add",
    )
    return _serialise(service, settings)


@router.delete("/{service_id}/auth/{auth_id}", response_model=ServiceRead)
def remove_authenticator(
    service_id: uuid.UUID,
    auth_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    service = _get_or_404(session, service_id)
    row = next((item for item in service.authenticators if item.id == auth_id), None)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "authenticator not found")
    service.authenticators.remove(row)
    session.flush()
    regenerate_or_422(session, settings, actor="admin-api")
    audit.record(
        session,
        action="service.auth.remove",
        object_type="service",
        object_id=service.slug,
        **audit_context(request),
    )
    session.commit()
    session.refresh(service)
    return _serialise(service, settings)


@router.post(
    "/{service_id}/filters",
    response_model=ServiceRead,
    status_code=status.HTTP_201_CREATED,
)
def add_filter(
    service_id: uuid.UUID,
    payload: ServiceFilterCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    service = _get_or_404(session, service_id)
    row = ServiceFilter(**payload.model_dump())
    service = _add_child(
        session, settings, request, service, service.filters, row, "service.filter.add"
    )
    return _serialise(service, settings)


@router.delete("/{service_id}/filters/{filter_id}", response_model=ServiceRead)
def remove_filter(
    service_id: uuid.UUID,
    filter_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    service = _get_or_404(session, service_id)
    row = next((item for item in service.filters if item.id == filter_id), None)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "filter not found")
    service.filters.remove(row)
    session.flush()
    regenerate_or_422(session, settings, actor="admin-api")
    audit.record(
        session,
        action="service.filter.remove",
        object_type="service",
        object_id=service.slug,
        **audit_context(request),
    )
    session.commit()
    session.refresh(service)
    return _serialise(service, settings)


@router.post(
    "/{service_id}/access",
    response_model=ServiceRead,
    status_code=status.HTTP_201_CREATED,
)
def add_access_rule(
    service_id: uuid.UUID,
    payload: ServiceAccessCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    service = _get_or_404(session, service_id)
    row = ServiceAccess(**payload.model_dump())
    service = _add_child(
        session, settings, request, service, service.access, row, "service.access.add"
    )
    return _serialise(service, settings)


@router.delete("/{service_id}/access/{rule_id}", response_model=ServiceRead)
def remove_access_rule(
    service_id: uuid.UUID,
    rule_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    service = _get_or_404(session, service_id)
    row = next((item for item in service.access if item.id == rule_id), None)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "access rule not found")
    service.access.remove(row)
    session.flush()
    regenerate_or_422(session, settings, actor="admin-api")
    audit.record(
        session,
        action="service.access.remove",
        object_type="service",
        object_id=service.slug,
        **audit_context(request),
    )
    session.commit()
    session.refresh(service)
    return _serialise(service, settings)


# --------------------------------------------------------------------------- #
# credentials
# --------------------------------------------------------------------------- #


@router.get("/{service_id}/tokens", response_model=list[ServiceTokenRead])
def list_tokens(service_id: uuid.UUID, session: Session = Depends(get_db)) -> list[ServiceToken]:
    service = _get_or_404(session, service_id)
    return sorted(service.tokens, key=lambda row: row.created_at)


@router.post(
    "/{service_id}/tokens",
    response_model=ServiceTokenCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_token(
    service_id: uuid.UUID,
    payload: ServiceTokenCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Issue a bearer token. The plaintext is returned once and never stored.

    Hashed with a plain SHA-256 rather than a KDF, deliberately: this is a
    generated 256-bit secret, so stretching protects against nothing. The same
    reasoning as ``admin_sessions`` and enrollment keys.
    """
    service = _get_or_404(session, service_id)
    plaintext = secrets.token_urlsafe(TOKEN_BYTES)
    row = ServiceToken(
        name=payload.name,
        token_hash=passwords.token_digest(plaintext),
        prefix=plaintext[:8],
        expires_at=payload.expires_at,
        created_by_user_id=getattr(getattr(request.state, "admin", None), "user_id", None),
    )
    service.tokens.append(row)
    session.flush()
    regenerate_or_422(session, settings, actor="admin-api")
    audit.record(
        session,
        action="service.token.create",
        object_type="service",
        object_id=f"{service.slug}/{payload.name}",
        **audit_context(request),
    )
    session.commit()
    session.refresh(row)
    return {
        "id": row.id,
        "name": row.name,
        "prefix": row.prefix,
        "expires_at": row.expires_at,
        "revoked_at": row.revoked_at,
        "created_at": row.created_at,
        "token": plaintext,
    }


@router.delete("/{service_id}/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(
    service_id: uuid.UUID,
    token_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    service = _get_or_404(session, service_id)
    row = next((item for item in service.tokens if item.id == token_id), None)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    # Removed rather than flagged: a revoked token must leave the rendered map,
    # and keeping the row would only preserve a hash nobody can use.
    service.tokens.remove(row)
    session.flush()
    regenerate_or_422(session, settings, actor="admin-api")
    audit.record(
        session,
        action="service.token.revoke",
        object_type="service",
        object_id=f"{service.slug}/{row.name}",
        **audit_context(request),
    )
    session.commit()


@router.get("/{service_id}/accounts", response_model=list[ServiceAccountRead])
def list_accounts(
    service_id: uuid.UUID, session: Session = Depends(get_db)
) -> list[ServiceAccount]:
    service = _get_or_404(session, service_id)
    return sorted(service.accounts, key=lambda row: row.username)


@router.post(
    "/{service_id}/accounts",
    response_model=ServiceAccountCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_account(
    service_id: uuid.UUID,
    payload: ServiceAccountCreate,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Create a basic-auth service account with a generated password.

    Generated, not chosen. A HAProxy ``userlist`` can only verify crypt(3)
    hashes, so a human password would have to leave argon2 behind and land on
    the gateway's disk as sha-512-crypt. A 192-bit generated secret makes that
    hash adequate, which is the whole reason this is not the ``users`` table.
    """
    service = _get_or_404(session, service_id)
    plaintext = secrets.token_urlsafe(PASSWORD_BYTES)
    row = ServiceAccount(
        username=payload.username,
        password_hash=passwords.crypt_hash(plaintext),
    )
    service.accounts.append(row)
    session.flush()
    try:
        regenerate_or_422(session, settings, actor="admin-api")
    except IntegrityError as exc:
        session.rollback()
        raise integrity_conflict(exc, "service account") from exc
    audit.record(
        session,
        action="service.account.create",
        object_type="service",
        object_id=f"{service.slug}/{payload.username}",
        **audit_context(request),
    )
    session.commit()
    session.refresh(row)
    return {
        "id": row.id,
        "username": row.username,
        "revoked_at": row.revoked_at,
        "created_at": row.created_at,
        "password": plaintext,
    }


@router.delete("/{service_id}/accounts/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(
    service_id: uuid.UUID,
    account_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    service = _get_or_404(session, service_id)
    row = next((item for item in service.accounts if item.id == account_id), None)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    username = row.username
    service.accounts.remove(row)
    session.flush()
    regenerate_or_422(session, settings, actor="admin-api")
    audit.record(
        session,
        action="service.account.delete",
        object_type="service",
        object_id=f"{service.slug}/{username}",
        **audit_context(request),
    )
    session.commit()
