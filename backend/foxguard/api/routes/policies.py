"""Import/export of the ACL model as a versionable JSON document."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...nftables import RulesetValidationError
from ...schemas import PolicyDiffResponse, PolicyDocument, PolicyImportRequest
from ...services import audit, policies
from ...services import ruleset as ruleset_service
from ..deps import audit_context, require_admin

router = APIRouter(
    prefix="/api/v1/policies", tags=["policies"], dependencies=[Depends(require_admin)]
)


@router.get("/export", response_model=PolicyDocument)
def export_policies(session: Session = Depends(get_db)) -> dict:
    """Export groups + ACL rules. Deterministic order, safe to commit to git."""
    return policies.export_document(session)


@router.post("/import", response_model=PolicyDiffResponse)
def import_policies(
    payload: PolicyImportRequest,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> PolicyDiffResponse:
    """Validate, diff and (optionally) apply a policy document.

    ``dry_run`` defaults to true: the diff below is produced by running the real
    import inside the transaction and then rolling it back, so the preview and
    the application cannot disagree.

    The nft ruleset is rendered before committing, which gives an import the
    same atomicity guarantee as ``nft -c -f``: a document that would produce an
    invalid ruleset changes nothing.
    """
    document = payload.document.model_dump(mode="json")

    try:
        diff = policies.apply_document(session, document, prune=payload.prune)
    except policies.PolicyImportError as exc:
        session.rollback()
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"message": "invalid policy document", "errors": exc.errors},
        ) from exc

    try:
        version = ruleset_service.regenerate(
            session, settings, generated_by="policies.import"
        )
    except RulesetValidationError as exc:
        session.rollback()
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {
                "message": "the imported policies would produce an invalid ruleset",
                "errors": list(exc.errors),
            },
        ) from exc

    digest = version.digest

    if payload.dry_run:
        session.rollback()
        return PolicyDiffResponse(
            dry_run=True,
            applied=False,
            summary=diff.summary(),
            groups_created=diff.groups_created,
            groups_updated=diff.groups_updated,
            groups_deleted=diff.groups_deleted,
            rules_created=diff.rules_created,
            rules_updated=diff.rules_updated,
            rules_deleted=diff.rules_deleted,
            ruleset_digest=digest,
        )

    audit.record(
        session,
        action="policies.import",
        object_type="policy_document",
        **audit_context(request),
        detail={"summary": diff.summary(), "prune": payload.prune, "digest": digest},
    )
    session.commit()
    return PolicyDiffResponse(
        dry_run=False,
        applied=True,
        summary=diff.summary(),
        groups_created=diff.groups_created,
        groups_updated=diff.groups_updated,
        groups_deleted=diff.groups_deleted,
        rules_created=diff.rules_created,
        rules_updated=diff.rules_updated,
        rules_deleted=diff.rules_deleted,
        ruleset_digest=digest,
    )
