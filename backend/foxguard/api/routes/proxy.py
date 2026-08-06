"""What the proxy is currently serving.

Read-only, and the counterpart of ``GET /api/v1/dns`` and ``/api/v1/ruleset``:
it renders from the same state the agent will and shows the result, so "what is
actually published" is answerable without reading the gateway's disk.

``implicit_paths`` is the part that matters most. Publishing a service opens a
gateway-to-upstream path the ACL model does not cover, and this is where it
becomes visible.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import SsoSession
from ...proxy import ProxyValidationError
from ...schemas import ProxyStatusRead, SsoSessionRead
from ...services import audit
from ...services import proxy as proxy_service
from ...services import sso as sso_service
from ..deps import audit_context, regenerate_or_422, require_admin

router = APIRouter(prefix="/api/v1/proxy", tags=["proxy"], dependencies=[Depends(require_admin)])


@router.get("", response_model=ProxyStatusRead)
def read_proxy(
    session: Session = Depends(get_db), settings: Settings = Depends(get_settings)
) -> dict:
    spec = proxy_service.build_spec(session, settings)
    warnings: list[str] = []
    conf: str | None = None
    files: dict[str, str] = {}
    digest: str | None = None

    if settings.proxy_enabled:
        try:
            conf, files = proxy_service.render(session, settings)
            digest = proxy_service.digest(conf, files)
        except ProxyValidationError as exc:
            # Reported rather than raised: this endpoint exists to explain the
            # state, and refusing to describe a broken configuration is exactly
            # when a description is most wanted.
            warnings.append(str(exc))
    else:
        warnings.append("the reverse proxy is disabled (FOXGUARD_PROXY_ENABLED)")

    if settings.proxy_enabled and not settings.proxy_domain:
        warnings.append(
            "no proxy domain is set, so services have no default host name and "
            "no certificate can cover them"
        )
    if any(service.exposure.has_external for service in spec.services) and not (
        settings.proxy_external_binds
    ):
        warnings.append("a service asks for external exposure but no WAN bind address is set")

    if spec.uses_geo:
        # Stated rather than assumed. A country filter is the one rule here that
        # depends on data Foxguard does not own and that goes stale by itself,
        # and its failure mode is silent in one direction: an out-of-date deny
        # list simply stops matching.
        warnings.append(
            "a service filters by country. The gateway builds its own prefix map "
            f"for {', '.join(spec.geo_countries)} from a dataset refreshed by "
            "'foxguard-geo-refresh'; if that has never run, an allow list "
            "refuses everyone and a deny list blocks nobody. Geo is noise "
            "reduction, not a security control -- any VPN defeats it"
        )

    return {
        "enabled": settings.proxy_enabled,
        "domain": settings.proxy_domain,
        "internal_binds": list(spec.internal_binds),
        "external_binds": list(spec.external_binds),
        "service_count": len(spec.services),
        "digest": digest,
        "config": conf,
        "files": files,
        "geo_countries": list(spec.geo_countries),
        "implicit_paths": proxy_service.implicit_paths(session, settings),
        "warnings": warnings,
    }


@router.get("/sso-sessions", response_model=list[SsoSessionRead])
def list_sso_sessions(
    session: Session = Depends(get_db),
) -> list[dict]:
    """Who is signed in to published services, and from where."""
    rows = (
        session.execute(
            select(SsoSession)
            .where(SsoSession.revoked_at.is_(None))
            .order_by(SsoSession.created_at.desc())
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": row.id,
            "username": row.user.username if row.user else None,
            "source_ip": str(row.source_ip) if row.source_ip else None,
            "user_agent": row.user_agent,
            "expires_at": row.expires_at,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@router.delete("/sso-sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_sso_session(
    session_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    """Sign one person out now.

    The cookie stays valid-looking to a browser -- its signature is fine and it
    has not expired -- so what makes this immediate is the ``jti`` landing in
    the proxy's denylist map. Regenerating puts it there; the agent pushes the
    map over the runtime socket on its next poll, without a reload.
    """
    if not sso_service.revoke(session, settings, session_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such session")
    regenerate_or_422(session, settings, actor="admin-api")
    audit.record(
        session,
        action="sso.revoke",
        object_type="sso_session",
        object_id=session_id,
        **audit_context(request),
    )
    session.commit()
