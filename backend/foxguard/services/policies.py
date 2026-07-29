"""Import/export of the ACL model as a versionable JSON document.

Goal: keep the ACLs in a git repository and be able to reapply them after a
gateway rebuild. Two properties matter:

* **Portability** — the document references groups by ``slug`` and rules by
  ``ref``, never by database UUID, so it survives a rebuild from scratch.
* **Atomicity** — an import either applies fully or not at all. The route runs
  it inside a single transaction and renders the resulting nft ruleset *before*
  committing, so a document that would produce an invalid ruleset is rejected
  with the database untouched.

``compute_diff`` is side-effect free, which is what makes the dry-run mode
trustworthy: the preview is computed by the same code path as the real thing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AclRule, Group, GroupKind
from ..nftables import Action, EndpointKind, Protocol

__all__ = [
    "POLICY_DOCUMENT_VERSION",
    "PolicyDiff",
    "PolicyImportError",
    "apply_document",
    "compute_diff",
    "export_document",
]

POLICY_DOCUMENT_VERSION = 1

_GROUP_FIELDS = (
    "name",
    "description",
    "kind",
    "internet_exit",
    "session_lifetime_seconds",
)
_RULE_FIELDS = (
    "name",
    "description",
    "priority",
    "enabled",
    "action",
    "src_kind",
    "src_group",
    "src_cidr",
    "dst_kind",
    "dst_group",
    "dst_cidr",
    "protocol",
    "dst_port_start",
    "dst_port_end",
)


class PolicyImportError(ValueError):
    """The document is structurally valid but inconsistent (unknown group, ...)."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass
class PolicyDiff:
    """Human-readable preview of what an import would change."""

    groups_created: list[str] = field(default_factory=list)
    groups_updated: list[dict[str, Any]] = field(default_factory=list)
    groups_deleted: list[str] = field(default_factory=list)
    rules_created: list[str] = field(default_factory=list)
    rules_updated: list[dict[str, Any]] = field(default_factory=list)
    rules_deleted: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not any(
            (
                self.groups_created,
                self.groups_updated,
                self.groups_deleted,
                self.rules_created,
                self.rules_updated,
                self.rules_deleted,
            )
        )

    def summary(self) -> str:
        return (
            f"groups +{len(self.groups_created)} ~{len(self.groups_updated)} "
            f"-{len(self.groups_deleted)}, "
            f"rules +{len(self.rules_created)} ~{len(self.rules_updated)} "
            f"-{len(self.rules_deleted)}"
        )


# --------------------------------------------------------------------------- #
# serialisation
# --------------------------------------------------------------------------- #


def _group_to_dict(group: Group) -> dict[str, Any]:
    return {
        "slug": group.slug,
        "name": group.name,
        "description": group.description,
        "kind": group.kind.value,
        "internet_exit": group.internet_exit,
        "session_lifetime_seconds": group.session_lifetime_seconds,
    }


def _rule_to_dict(rule: AclRule) -> dict[str, Any]:
    return {
        "ref": rule.ref,
        "name": rule.name,
        "description": rule.description,
        "priority": rule.priority,
        "enabled": rule.enabled,
        "action": rule.action.value,
        "src_kind": rule.src_kind.value,
        "src_group": rule.src_group.slug if rule.src_group else None,
        "src_cidr": rule.src_cidr,
        "dst_kind": rule.dst_kind.value,
        "dst_group": rule.dst_group.slug if rule.dst_group else None,
        "dst_cidr": rule.dst_cidr,
        "protocol": rule.protocol.value,
        "dst_port_start": rule.dst_port_start,
        "dst_port_end": rule.dst_port_end,
    }


def export_document(session: Session) -> dict[str, Any]:
    """Serialise groups + ACL rules. Deterministically ordered for clean diffs."""
    groups = session.execute(select(Group).order_by(Group.slug)).scalars().all()
    rules = (
        session.execute(select(AclRule).order_by(AclRule.priority, AclRule.ref))
        .scalars()
        .all()
    )
    return {
        "version": POLICY_DOCUMENT_VERSION,
        "groups": [_group_to_dict(group) for group in groups],
        "acl_rules": [_rule_to_dict(rule) for rule in rules],
    }


# --------------------------------------------------------------------------- #
# diffing
# --------------------------------------------------------------------------- #


def _normalise_group(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": payload.get("name") or payload["slug"],
        "description": payload.get("description"),
        "kind": payload.get("kind", GroupKind.GROUP.value),
        "internet_exit": bool(payload.get("internet_exit", False)),
        "session_lifetime_seconds": payload.get("session_lifetime_seconds"),
    }


def _normalise_rule(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": payload.get("name") or payload["ref"],
        "description": payload.get("description"),
        "priority": int(payload.get("priority", 100)),
        "enabled": bool(payload.get("enabled", True)),
        "action": payload["action"],
        "src_kind": payload.get("src_kind", EndpointKind.ANY.value),
        "src_group": payload.get("src_group"),
        "src_cidr": payload.get("src_cidr"),
        "dst_kind": payload.get("dst_kind", EndpointKind.ANY.value),
        "dst_group": payload.get("dst_group"),
        "dst_cidr": payload.get("dst_cidr"),
        "protocol": payload.get("protocol", Protocol.ANY.value),
        "dst_port_start": payload.get("dst_port_start"),
        "dst_port_end": payload.get("dst_port_end"),
    }


def _changes(current: dict[str, Any], desired: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {
        key: {"from": current.get(key), "to": desired.get(key)}
        for key in fields
        if current.get(key) != desired.get(key)
    }


def _validate_document(document: dict[str, Any], known_slugs: set[str]) -> None:
    errors: list[str] = []
    version = document.get("version")
    if version != POLICY_DOCUMENT_VERSION:
        errors.append(
            f"unsupported document version {version!r}, expected {POLICY_DOCUMENT_VERSION}"
        )

    slugs = {group["slug"] for group in document.get("groups", [])}
    seen_refs: set[str] = set()
    for rule in document.get("acl_rules", []):
        ref = rule.get("ref")
        if not ref:
            errors.append("acl rule without a 'ref'")
            continue
        if ref in seen_refs:
            errors.append(f"duplicate rule ref {ref!r}")
        seen_refs.add(ref)
        for side in ("src", "dst"):
            kind = rule.get(f"{side}_kind", EndpointKind.ANY.value)
            if kind == EndpointKind.GROUP.value:
                group_slug = rule.get(f"{side}_group")
                if not group_slug:
                    errors.append(f"rule {ref!r}: {side}_kind=group without {side}_group")
                elif group_slug not in slugs and group_slug not in known_slugs:
                    errors.append(f"rule {ref!r}: unknown {side}_group {group_slug!r}")
            elif kind == EndpointKind.CIDR.value and not rule.get(f"{side}_cidr"):
                errors.append(f"rule {ref!r}: {side}_kind=cidr without {side}_cidr")
    if errors:
        raise PolicyImportError(errors)


def compute_diff(
    session: Session, document: dict[str, Any], *, prune: bool = False
) -> PolicyDiff:
    """Compute what ``document`` would change. Performs no writes."""
    existing_groups = {
        group.slug: group for group in session.execute(select(Group)).scalars().all()
    }
    existing_rules = {
        rule.ref: rule for rule in session.execute(select(AclRule)).scalars().all()
    }
    _validate_document(document, set(existing_groups))

    diff = PolicyDiff()

    desired_group_slugs: set[str] = set()
    for payload in document.get("groups", []):
        slug = payload["slug"]
        desired_group_slugs.add(slug)
        desired = _normalise_group(payload)
        current = existing_groups.get(slug)
        if current is None:
            diff.groups_created.append(slug)
            continue
        changes = _changes(_group_to_dict(current), desired, _GROUP_FIELDS)
        if changes:
            diff.groups_updated.append({"slug": slug, "changes": changes})

    desired_rule_refs: set[str] = set()
    for payload in document.get("acl_rules", []):
        ref = payload["ref"]
        desired_rule_refs.add(ref)
        desired = _normalise_rule(payload)
        current = existing_rules.get(ref)
        if current is None:
            diff.rules_created.append(ref)
            continue
        changes = _changes(_rule_to_dict(current), desired, _RULE_FIELDS)
        if changes:
            diff.rules_updated.append({"ref": ref, "changes": changes})

    if prune:
        diff.rules_deleted = sorted(set(existing_rules) - desired_rule_refs)
        diff.groups_deleted = sorted(set(existing_groups) - desired_group_slugs)

    return diff


# --------------------------------------------------------------------------- #
# applying
# --------------------------------------------------------------------------- #


def apply_document(
    session: Session, document: dict[str, Any], *, prune: bool = False
) -> PolicyDiff:
    """Apply ``document`` to the session. The caller owns the transaction.

    Nothing is committed here on purpose: the route flushes, regenerates the nft
    ruleset and only then commits, so an import that would break the dataplane
    leaves no trace.
    """
    diff = compute_diff(session, document, prune=prune)

    groups = {group.slug: group for group in session.execute(select(Group)).scalars().all()}

    for payload in document.get("groups", []):
        slug = payload["slug"]
        desired = _normalise_group(payload)
        group = groups.get(slug)
        if group is None:
            group = Group(slug=slug, **{**desired, "kind": GroupKind(desired["kind"])})
            session.add(group)
            groups[slug] = group
        else:
            for key, value in desired.items():
                setattr(group, key, GroupKind(value) if key == "kind" else value)
    session.flush()

    rules = {rule.ref: rule for rule in session.execute(select(AclRule)).scalars().all()}
    for payload in document.get("acl_rules", []):
        ref = payload["ref"]
        desired = _normalise_rule(payload)
        src_group = groups.get(desired.pop("src_group") or "")
        dst_group = groups.get(desired.pop("dst_group") or "")
        values = {
            **desired,
            "action": Action(desired["action"]),
            "protocol": Protocol(desired["protocol"]),
            "src_kind": EndpointKind(desired["src_kind"]),
            "dst_kind": EndpointKind(desired["dst_kind"]),
            "src_group_id": src_group.id if src_group else None,
            "dst_group_id": dst_group.id if dst_group else None,
        }
        rule = rules.get(ref)
        if rule is None:
            rule = AclRule(ref=ref, **values)
            session.add(rule)
            rules[ref] = rule
        else:
            for key, value in values.items():
                setattr(rule, key, value)

    if prune:
        for ref in diff.rules_deleted:
            session.delete(rules[ref])
        for slug in diff.groups_deleted:
            session.delete(groups[slug])

    session.flush()
    return diff
