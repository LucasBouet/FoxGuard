"""Database -> dataplane projection tests.

These need PostgreSQL (see ``conftest.db_session``). They cover the seam the
pure generator tests cannot: that the ORM state is mapped onto the spec
faithfully, and that regeneration is genuinely idempotent.
"""

from __future__ import annotations

import uuid

import pytest

from foxguard.config import Settings
from foxguard.models import AclRule, Group, Peer, RulesetStatus, RulesetVersion
from foxguard.nftables import Action, EndpointKind, PeerState, PeerType, Protocol
from foxguard.services import ruleset as ruleset_service


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        dev_mode=True,
        wg_interface="wg0",
        wan_interface="eth0",
        wg_pool_v4="10.88.0.0/24",
        internal_cidrs=["10.0.0.0/8"],
        portal_port=8080,
    )


def _peer(session, name, ip, *, state=PeerState.ACTIVE, groups=(), peer_type=PeerType.USER):
    peer = Peer(
        name=name,
        peer_type=peer_type,
        state=state,
        wg_public_key=f"{uuid.uuid4().hex}{uuid.uuid4().hex[:11]}=",
        wg_interface="wg0",
        tunnel_ip=ip,
    )
    peer.groups = list(groups)
    session.add(peer)
    return peer


def test_build_spec_reflects_database_state(db_session, settings):
    admin = Group(slug="admin", name="Admins")
    db = Group(slug="db", name="Databases", internet_exit=False)
    db_session.add_all([admin, db])
    db_session.flush()

    _peer(db_session, "laptop", "10.88.0.2", groups=[admin])
    _peer(db_session, "server", "10.88.0.3", groups=[db], peer_type=PeerType.SERVER)
    _peer(db_session, "new", "10.88.0.4", state=PeerState.STAGING)
    db_session.flush()

    spec = ruleset_service.build_spec(db_session, settings)

    assert [group.slug for group in spec.groups] == ["admin", "db"]
    assert {peer.name for peer in spec.peers} == {"laptop", "server", "new"}
    staging = next(peer for peer in spec.peers if peer.name == "new")
    assert staging.state is PeerState.STAGING


def test_disabled_rules_are_excluded_from_the_ruleset(db_session, settings):
    admin = Group(slug="admin", name="Admins")
    db_session.add(admin)
    db_session.flush()

    db_session.add_all(
        [
            AclRule(
                ref="on", name="enabled rule", action=Action.ACCEPT, enabled=True,
                src_kind=EndpointKind.GROUP, src_group_id=admin.id,
                dst_kind=EndpointKind.ANY, protocol=Protocol.ANY,
            ),
            AclRule(
                ref="off", name="disabled rule", action=Action.ACCEPT, enabled=False,
                src_kind=EndpointKind.GROUP, src_group_id=admin.id,
                dst_kind=EndpointKind.ANY, protocol=Protocol.ANY,
            ),
        ]
    )
    db_session.flush()

    content = ruleset_service.render(db_session, settings)
    assert "fg:on:" in content
    assert "fg:off:" not in content


def test_regenerating_unchanged_state_is_a_no_op(db_session, settings):
    """Idempotence: no drift, and no version churn in the audit trail."""
    db_session.add(Group(slug="admin", name="Admins"))
    db_session.flush()

    first = ruleset_service.regenerate(db_session, settings)
    db_session.flush()
    second = ruleset_service.regenerate(db_session, settings)
    db_session.flush()

    assert first.id == second.id
    assert db_session.query(RulesetVersion).count() == 1


def test_a_change_produces_a_new_version_and_supersedes_the_previous(db_session, settings):
    first = ruleset_service.regenerate(db_session, settings)
    db_session.flush()

    db_session.add(Group(slug="admin", name="Admins"))
    db_session.flush()
    second = ruleset_service.regenerate(db_session, settings)
    db_session.flush()

    assert first.digest != second.digest
    assert first.status is RulesetStatus.SUPERSEDED
    assert second.status is RulesetStatus.PENDING


def test_quarantined_peers_leave_their_group_sets(db_session, settings):
    admin = Group(slug="admin", name="Admins")
    db_session.add(admin)
    db_session.flush()
    peer = _peer(db_session, "laptop", "10.88.0.2", groups=[admin])
    db_session.flush()

    active = ruleset_service.render(db_session, settings)
    assert "10.88.0.2" in active.split("set g_admin_v4")[1].split("}")[0]

    peer.state = PeerState.QUARANTINED
    db_session.flush()
    quarantined = ruleset_service.render(db_session, settings)

    assert "10.88.0.2" not in quarantined.split("set g_admin_v4")[1].split("}")[0]
    assert "10.88.0.2" in quarantined.split("set fg_quarantine_v4")[1].split("}")[0]
