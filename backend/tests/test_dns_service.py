"""Projection of database state onto a DNS zone.

Needs PostgreSQL (``FOXGUARD_TEST_DATABASE_URL``); the rendering itself is
covered without one in ``test_dns_generator.py``.
"""

from __future__ import annotations

import uuid

import pytest

from foxguard.config import Settings
from foxguard.dns import DnsValidationError, RecordKind
from foxguard.models import DnsRecord, Peer
from foxguard.nftables import PeerState, PeerType
from foxguard.services import dns as dns_service

ZONE = "fox.internal"


def settings(**overrides) -> Settings:
    defaults = dict(
        dev_mode=True,
        dns_enabled=True,
        dns_zone=ZONE,
        wg_pool_v4="10.88.0.0/24",
        wg_gateway_ip="10.88.0.1",
    )
    defaults.update(overrides)
    return Settings(**defaults)


def make_peer(session, name: str, ip: str | None, **overrides) -> Peer:
    defaults = dict(
        id=uuid.uuid4(),
        name=name,
        peer_type=PeerType.USER,
        state=PeerState.ACTIVE,
        wg_public_key=f"{uuid.uuid4().hex[:20]}{'A' * 23}=",
        wg_interface="wg0",
        tunnel_ip=ip,
        dns_label=name.lower().replace(" ", "-"),
    )
    defaults.update(overrides)
    peer = Peer(**defaults)
    session.add(peer)
    session.flush()
    return peer


def hosts_of(session, cfg: Settings) -> dict[str, tuple[str, ...]]:
    spec = dns_service.build_spec(session, cfg)
    return {host.address: host.names for host in spec.hosts}


# --------------------------------------------------------------------------- #
# what gets a name
# --------------------------------------------------------------------------- #


def test_the_gateway_always_has_a_name(db_session):
    assert hosts_of(db_session, settings())["10.88.0.1"] == (f"gw.{ZONE}",)


def test_the_gateway_label_is_configurable(db_session):
    cfg = settings(dns_gateway_label="firewall")
    assert hosts_of(db_session, cfg)["10.88.0.1"] == (f"firewall.{ZONE}",)


@pytest.mark.parametrize(
    "state", [PeerState.ACTIVE, PeerState.STAGING, PeerState.QUARANTINED]
)
def test_peers_that_can_be_on_the_tunnel_have_names(db_session, state):
    make_peer(db_session, "laptop", "10.88.0.5", state=state)
    assert hosts_of(db_session, settings())["10.88.0.5"] == (f"laptop.{ZONE}",)


@pytest.mark.parametrize("state", [PeerState.DISABLED, PeerState.REVOKED])
def test_peers_that_cannot_be_on_the_tunnel_lose_their_names(db_session, state):
    """A name resolving to an unreachable device is a wrong answer, not a stale one."""
    make_peer(db_session, "laptop", "10.88.0.5", state=state)
    assert "10.88.0.5" not in hosts_of(db_session, settings())


def test_a_peer_without_a_label_is_simply_absent(db_session):
    make_peer(db_session, "unnamed", "10.88.0.5", dns_label=None)
    assert "10.88.0.5" not in hosts_of(db_session, settings())


def test_a_dual_stack_peer_gets_both_records_under_one_name(db_session):
    make_peer(db_session, "laptop", "10.88.0.5", tunnel_ip6="fd00:88::5")
    hosts = hosts_of(db_session, settings(wg_pool_v6="fd00:88::/64"))
    assert hosts["10.88.0.5"] == (f"laptop.{ZONE}",)
    assert hosts["fd00:88::5"] == (f"laptop.{ZONE}",)


# --------------------------------------------------------------------------- #
# hand-authored records
# --------------------------------------------------------------------------- #


def test_an_a_record_can_name_something_off_the_tunnel(db_session):
    """Split-horizon for a service on the LAN behind the gateway."""
    db_session.add(DnsRecord(name="nas", kind=RecordKind.A, value="192.168.1.50"))
    db_session.flush()
    assert hosts_of(db_session, settings())["192.168.1.50"] == (f"nas.{ZONE}",)


def test_an_a_record_on_a_peer_address_becomes_a_second_name(db_session):
    """And the peer's own name stays first, so the reverse lookup is stable."""
    make_peer(db_session, "backup", "10.88.0.6")
    db_session.add(DnsRecord(name="files", kind=RecordKind.A, value="10.88.0.6"))
    db_session.flush()
    assert hosts_of(db_session, settings())["10.88.0.6"] == (
        f"backup.{ZONE}",
        f"files.{ZONE}",
    )


def test_a_cname_renders_as_an_alias(db_session):
    db_session.add(DnsRecord(name="portal", kind=RecordKind.CNAME, value="gw"))
    db_session.flush()
    spec = dns_service.build_spec(db_session, settings())
    assert [(c.alias, c.target) for c in spec.cnames] == [
        (f"portal.{ZONE}", f"gw.{ZONE}")
    ]


def test_revoking_a_peer_drops_its_aliases_instead_of_breaking_the_zone(db_session):
    """An access-control action must never take name resolution down.

    Revoking a peer removes its name, and any alias pointing at it loses its
    target. Treating that as an error would mean the kill switch -- which is
    supposed to only ever narrow access -- silently stops the whole fleet
    resolving anything.
    """
    peer = make_peer(db_session, "backup", "10.88.0.6")
    db_session.add(DnsRecord(name="files", kind=RecordKind.CNAME, value="backup"))
    db_session.flush()
    assert len(dns_service.build_spec(db_session, settings()).cnames) == 1

    peer.state = PeerState.REVOKED
    db_session.flush()

    spec = dns_service.build_spec(db_session, settings())
    assert spec.cnames == ()
    assert dns_service.render(db_session, settings())          # still renders
    assert dns_service.dangling_aliases(db_session, settings()) == [
        f"files.{ZONE} is not served: its target backup.{ZONE} no longer exists"
    ]


def test_an_alias_to_a_name_that_never_existed_is_still_catchable(db_session):
    """The typo case stays an error -- the endpoints ask before committing."""
    assert dns_service.target_exists(db_session, settings(), "ghost") is False
    make_peer(db_session, "real", "10.88.0.7")
    assert dns_service.target_exists(db_session, settings(), "real") is True


def test_a_disabled_record_is_not_served(db_session):
    db_session.add(
        DnsRecord(name="nas", kind=RecordKind.A, value="192.168.1.50", enabled=False)
    )
    db_session.flush()
    assert "192.168.1.50" not in hosts_of(db_session, settings())


def test_records_are_stored_relative_so_the_zone_can_be_renamed(db_session):
    db_session.add(DnsRecord(name="nas", kind=RecordKind.A, value="192.168.1.50"))
    db_session.flush()
    hosts = hosts_of(db_session, settings(dns_zone="example.lan"))
    assert hosts["192.168.1.50"] == ("nas.example.lan",)


def test_an_already_qualified_record_name_is_not_qualified_twice(db_session):
    db_session.add(DnsRecord(name=f"nas.{ZONE}", kind=RecordKind.A, value="192.168.1.50"))
    db_session.flush()
    assert hosts_of(db_session, settings())["192.168.1.50"] == (f"nas.{ZONE}",)


# --------------------------------------------------------------------------- #
# a broken zone must never break the dataplane
# --------------------------------------------------------------------------- #


def test_a_conflicting_record_makes_the_zone_refuse_to_render(db_session):
    make_peer(db_session, "laptop", "10.88.0.5")
    db_session.add(DnsRecord(name="laptop", kind=RecordKind.A, value="192.168.1.50"))
    db_session.flush()
    with pytest.raises(DnsValidationError):
        dns_service.render(db_session, settings())


def test_render_or_none_swallows_a_broken_zone(db_session):
    """A typo in a DNS record must not stop firewall rules reaching the kernel."""
    make_peer(db_session, "laptop", "10.88.0.5")
    db_session.add(DnsRecord(name="laptop", kind=RecordKind.A, value="192.168.1.50"))
    db_session.flush()
    assert dns_service.render_or_none(db_session, settings()) is None


def test_render_or_none_is_none_when_dns_is_off(db_session):
    assert dns_service.render_or_none(db_session, settings(dns_enabled=False)) is None


def test_render_or_none_returns_artefacts_and_a_digest(db_session):
    make_peer(db_session, "laptop", "10.88.0.5")
    result = dns_service.render_or_none(db_session, settings())
    assert result is not None
    hosts, conf, digest = result
    assert f"10.88.0.5\tlaptop.{ZONE}" in hosts
    assert f"local=/{ZONE}/" in conf
    assert len(digest) == 64


def test_the_digest_moves_when_a_peer_is_renamed(db_session):
    """Drift detection is the digest, so a rename has to move it."""
    peer = make_peer(db_session, "laptop", "10.88.0.5")
    before = dns_service.render_or_none(db_session, settings())
    peer.dns_label = "workstation"
    db_session.flush()
    after = dns_service.render_or_none(db_session, settings())
    assert before is not None and after is not None
    assert before[2] != after[2]


def test_the_digest_is_stable_when_nothing_changes(db_session):
    make_peer(db_session, "laptop", "10.88.0.5")
    first = dns_service.render_or_none(db_session, settings())
    second = dns_service.render_or_none(db_session, settings())
    assert first == second


# --------------------------------------------------------------------------- #
# reverse zones follow the pools
# --------------------------------------------------------------------------- #


def test_reverse_authority_follows_the_configured_pools(db_session):
    conf = dns_service.render(db_session, settings())[1]
    assert "local=/0.88.10.in-addr.arpa/" in conf


def test_the_staging_pool_is_covered_too(db_session):
    cfg = settings(wg_staging_pool_v4="10.89.0.0/24")
    conf = dns_service.render(db_session, cfg)[1]
    assert "local=/0.89.10.in-addr.arpa/" in conf
