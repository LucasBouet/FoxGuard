"""Tests for the ACL import/export document.

The validation tests are pure. The round-trip tests need PostgreSQL and are
skipped unless ``FOXGUARD_TEST_DATABASE_URL`` is set (see ``conftest.py``).
"""

from __future__ import annotations

import pytest

from foxguard.services.policies import (
    POLICY_DOCUMENT_VERSION,
    PolicyImportError,
    _validate_document,
    apply_document,
    compute_diff,
    export_document,
)


def _document(**overrides) -> dict:
    document = {
        "version": POLICY_DOCUMENT_VERSION,
        "groups": [
            {"slug": "admin", "name": "Admins"},
            {"slug": "db", "name": "Databases"},
        ],
        "acl_rules": [
            {
                "ref": "admin-to-db",
                "name": "admins reach postgres",
                "action": "accept",
                "priority": 10,
                "src_kind": "group",
                "src_group": "admin",
                "dst_kind": "group",
                "dst_group": "db",
                "protocol": "tcp",
                "dst_port_start": 5432,
            }
        ],
    }
    document.update(overrides)
    return document


# --------------------------------------------------------------------------- #
# validation (pure)
# --------------------------------------------------------------------------- #


def test_a_valid_document_passes():
    _validate_document(_document(), set())


def test_unsupported_version_is_rejected():
    with pytest.raises(PolicyImportError, match="version"):
        _validate_document(_document(version=99), set())


def test_rule_referencing_an_unknown_group_is_rejected():
    document = _document(groups=[])
    with pytest.raises(PolicyImportError, match="unknown src_group"):
        _validate_document(document, set())


def test_rule_may_reference_a_group_that_already_exists_in_the_database():
    """An incremental document should not have to redeclare every group."""
    _validate_document(_document(groups=[]), {"admin", "db"})


def test_duplicate_rule_refs_are_rejected():
    document = _document()
    document["acl_rules"].append(dict(document["acl_rules"][0]))
    with pytest.raises(PolicyImportError, match="duplicate rule ref"):
        _validate_document(document, set())


def test_group_endpoint_without_a_group_is_rejected():
    document = _document()
    document["acl_rules"][0]["src_group"] = None
    with pytest.raises(PolicyImportError, match="without src_group"):
        _validate_document(document, set())


def test_cidr_endpoint_without_a_cidr_is_rejected():
    document = _document()
    document["acl_rules"][0]["dst_kind"] = "cidr"
    document["acl_rules"][0]["dst_group"] = None
    with pytest.raises(PolicyImportError, match="without dst_cidr"):
        _validate_document(document, set())


def test_all_problems_are_reported_together():
    document = _document(groups=[])
    document["acl_rules"].append(
        {"ref": "broken", "action": "accept", "dst_kind": "cidr"}
    )
    with pytest.raises(PolicyImportError) as excinfo:
        _validate_document(document, set())
    assert len(excinfo.value.errors) >= 2


# --------------------------------------------------------------------------- #
# round trip (needs PostgreSQL)
# --------------------------------------------------------------------------- #


def test_import_then_export_round_trips(db_session):
    apply_document(db_session, _document())
    db_session.flush()

    exported = export_document(db_session)
    assert [group["slug"] for group in exported["groups"]] == ["admin", "db"]
    assert exported["acl_rules"][0]["ref"] == "admin-to-db"
    assert exported["acl_rules"][0]["dst_port_start"] == 5432

    # Re-importing what we exported must be a no-op: that is what makes an ACL
    # repository safe to reapply after a gateway rebuild.
    assert compute_diff(db_session, exported).is_empty


def test_dry_run_diff_reports_creations(db_session):
    diff = compute_diff(db_session, _document())
    assert diff.groups_created == ["admin", "db"]
    assert diff.rules_created == ["admin-to-db"]
    assert not diff.is_empty


def test_compute_diff_performs_no_writes(db_session):
    compute_diff(db_session, _document())
    db_session.flush()
    assert export_document(db_session)["groups"] == []


def test_updates_are_detected_field_by_field(db_session):
    apply_document(db_session, _document())
    db_session.flush()

    changed = _document()
    changed["acl_rules"][0]["dst_port_start"] = 5433
    diff = compute_diff(db_session, changed)

    assert diff.groups_created == []
    assert diff.rules_updated == [
        {"ref": "admin-to-db", "changes": {"dst_port_start": {"from": 5432, "to": 5433}}}
    ]


def test_prune_removes_what_the_document_omits(db_session):
    apply_document(db_session, _document())
    db_session.flush()

    trimmed = _document(acl_rules=[])
    without_prune = compute_diff(db_session, trimmed, prune=False)
    assert without_prune.rules_deleted == []

    with_prune = compute_diff(db_session, trimmed, prune=True)
    assert with_prune.rules_deleted == ["admin-to-db"]


def test_import_is_idempotent(db_session):
    apply_document(db_session, _document())
    db_session.flush()
    apply_document(db_session, _document())
    db_session.flush()

    exported = export_document(db_session)
    assert len(exported["groups"]) == 2
    assert len(exported["acl_rules"]) == 1
