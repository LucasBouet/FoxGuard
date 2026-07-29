"""Ruleset inspection and forced regeneration."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import RulesetVersion
from ...nftables import RulesetValidationError, ruleset_digest
from ...schemas import RulesetPreview, RulesetVersionRead
from ...services import audit
from ...services import ruleset as ruleset_service
from ..deps import audit_context, require_admin

router = APIRouter(
    prefix="/api/v1/ruleset", tags=["ruleset"], dependencies=[Depends(require_admin)]
)


@router.get("/preview", response_model=RulesetPreview)
def preview_ruleset(
    session: Session = Depends(get_db), settings: Settings = Depends(get_settings)
) -> RulesetPreview:
    """Render the ruleset the current database state implies. Read-only."""
    try:
        content = ruleset_service.render(session, settings)
    except RulesetValidationError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            {"message": "current database state renders an invalid ruleset", "errors": list(exc.errors)},
        ) from exc
    return RulesetPreview(digest=ruleset_digest(content), content=content)


@router.post("/regenerate", response_model=RulesetVersionRead)
def regenerate_ruleset(
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RulesetVersion:
    """Force a regeneration. Useful after a manual database fix-up.

    Returns the existing version when nothing changed -- regenerating is a
    no-op by construction, which is exactly the idempotence property we want.
    """
    version = ruleset_service.regenerate(session, settings, generated_by="manual")
    audit.record(
        session,
        action="ruleset.regenerate",
        object_type="ruleset_version",
        object_id=version.id,
        **audit_context(request),
        detail={"digest": version.digest},
    )
    session.commit()
    return version


@router.get("/versions", response_model=list[RulesetVersionRead])
def list_versions(
    session: Session = Depends(get_db), limit: int = Query(default=25, ge=1, le=200)
) -> list[RulesetVersion]:
    return list(
        session.execute(
            select(RulesetVersion).order_by(RulesetVersion.created_at.desc()).limit(limit)
        )
        .scalars()
        .all()
    )
