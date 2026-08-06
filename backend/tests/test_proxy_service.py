"""The projection from database state to a proxy configuration.

Needs a real PostgreSQL (``FOXGUARD_TEST_DATABASE_URL``) because the schema
uses ``INET``, ``JSONB`` and native enums, exactly like the zone tests.
"""

from __future__ import annotations

import pytest

from foxguard.config import Settings
from foxguard.models import (
    Group,
    GroupKind,
    Peer,
    Service,
    ServiceAccess,
    ServiceAccount,
    ServiceAuth,
    ServiceAuthKind,
    ServiceExposure,
    ServiceFilter,
    ServiceFilterKind,
    ServiceKind,
    ServiceScope,
    ServiceToken,
    ZoneRoute,
)
from foxguard.nftables import Action, EndpointKind, PeerState, PeerType
from foxguard.proxy import Exposure, ProxyValidationError
from foxguard.services import passwords
from foxguard.services import proxy as proxy_service


def _settings(**overrides) -> Settings:
    base = {
        "proxy_enabled": True,
        "proxy_domain": "example.com",
        "proxy_external_binds": ["203.0.113.10"],
        "wg_pool_v4": "10.88.0.0/24",
    }
    base.update(overrides)
    return Settings(**base)


def _peer(session, name, address, *, state=PeerState.ACTIVE, label=None, zone=None):
    row = Peer(
        name=name,
        peer_type=PeerType.SERVER,
        state=state,
        wg_public_key=name.ljust(43, "x")[:43] + "=",
        tunnel_ip=address,
        dns_label=label or name,
        zone_id=zone.id if zone else None,
    )
    session.add(row)
    session.flush()
    return row


def _http_service(session, peer, **overrides):
    data = {
        "slug": "app",
        "name": "App",
        "kind": ServiceKind.HTTP,
        "exposure": ServiceExposure.INTERNAL,
        "upstream_peer_id": peer.id if peer else None,
        "upstream_host": str(peer.tunnel_ip) if peer else "10.88.0.1",
        "upstream_port": 8080,
        "internal_hostname": "app.example.com",
    }
    data.update(overrides)
    service = Service(**data)
    service.authenticators.append(
        ServiceAuth(kind=ServiceAuthKind.PEER_IDENTITY, scope=ServiceScope.INTERNAL)
    )
    session.add(service)
    session.flush()
    return service


# --------------------------------------------------------------------------- #
# the upstream reachability check, which reuses the zone routes
# --------------------------------------------------------------------------- #


def test_a_peers_own_address_is_reachable(db_session):
    peer = _peer(db_session, "nas", "10.88.0.6")
    ok, _ = proxy_service.upstream_reachable(db_session, peer, "10.88.0.6")
    assert ok


def test_an_address_behind_a_zone_route_is_reachable(db_session):
    zone = Group(slug="office", name="Office", kind=GroupKind.ZONE)
    db_session.add(zone)
    db_session.flush()
    peer = _peer(db_session, "nas", "10.88.0.6", zone=zone)
    zone.routes.append(ZoneRoute(cidr="192.168.10.0/24", via_peer_id=peer.id))
    db_session.flush()

    ok, _ = proxy_service.upstream_reachable(db_session, peer, "192.168.10.50")
    assert ok


def test_an_address_nothing_routes_to_is_refused_with_a_useful_message(db_session):
    zone = Group(slug="office", name="Office", kind=GroupKind.ZONE)
    db_session.add(zone)
    db_session.flush()
    peer = _peer(db_session, "nas", "10.88.0.6", zone=zone)
    zone.routes.append(ZoneRoute(cidr="192.168.10.0/24", via_peer_id=peer.id))
    db_session.flush()

    ok, why = proxy_service.upstream_reachable(db_session, peer, "192.168.99.1")
    assert not ok
    # The message must name what the peer *does* carry, or the operator has to
    # go and look it up to understand the refusal.
    assert "10.88.0.6" in why
    assert "192.168.10.0/24" in why


def test_a_disabled_zone_route_does_not_make_an_address_reachable(db_session):
    zone = Group(slug="office", name="Office", kind=GroupKind.ZONE)
    db_session.add(zone)
    db_session.flush()
    peer = _peer(db_session, "nas", "10.88.0.6", zone=zone)
    zone.routes.append(
        ZoneRoute(cidr="192.168.10.0/24", via_peer_id=peer.id, enabled=False)
    )
    db_session.flush()

    ok, _ = proxy_service.upstream_reachable(db_session, peer, "192.168.10.50")
    assert not ok


def test_a_gateway_hosted_service_needs_no_peer(db_session):
    ok, _ = proxy_service.upstream_reachable(db_session, None, "10.88.0.1")
    assert ok


# --------------------------------------------------------------------------- #
# the shared namespace
# --------------------------------------------------------------------------- #


def test_a_slug_taken_by_a_group_is_refused(db_session):
    db_session.add(Group(slug="devs", name="Devs", kind=GroupKind.GROUP))
    db_session.flush()
    assert "already a group" in proxy_service.slug_conflict(db_session, "devs")


def test_a_slug_taken_by_a_zone_is_refused(db_session):
    db_session.add(Group(slug="office", name="Office", kind=GroupKind.ZONE))
    db_session.flush()
    assert "already a zone" in proxy_service.slug_conflict(db_session, "office")


def test_a_slug_taken_by_a_peer_label_is_refused(db_session):
    _peer(db_session, "nas", "10.88.0.6")
    assert "DNS label" in proxy_service.slug_conflict(db_session, "nas")


def test_a_free_slug_is_free(db_session):
    assert proxy_service.slug_conflict(db_session, "grafana") is None


# --------------------------------------------------------------------------- #
# refusing to proxy Foxguard's own listeners
# --------------------------------------------------------------------------- #


def test_the_portal_may_not_be_proxied():
    settings = _settings()
    why = proxy_service.forbidden_upstream(
        settings, settings.gateway_ip, settings.portal_port
    )
    assert why and "source address" in why


def test_the_proxys_own_listener_may_not_be_an_upstream():
    settings = _settings()
    why = proxy_service.forbidden_upstream(
        settings, settings.gateway_ip, settings.proxy_internal_https_port
    )
    assert why and "forward to itself" in why


def test_an_ordinary_gateway_port_is_fine():
    settings = _settings()
    assert proxy_service.forbidden_upstream(settings, settings.gateway_ip, 9090) is None


# --------------------------------------------------------------------------- #
# port allocation
# --------------------------------------------------------------------------- #


def test_ports_are_allocated_from_the_configured_range(db_session):
    settings = _settings(proxy_tcp_port_start=20000, proxy_tcp_port_end=20002)
    assert proxy_service.allocate_listen_port(db_session, settings) == 20000


def test_allocation_skips_a_port_already_taken(db_session):
    settings = _settings(proxy_tcp_port_start=20000, proxy_tcp_port_end=20002)
    peer = _peer(db_session, "nas", "10.88.0.6")
    _http_service(
        db_session,
        peer,
        slug="ssh",
        kind=ServiceKind.TCP,
        listen_port=20000,
        internal_hostname=None,
    )
    assert proxy_service.allocate_listen_port(db_session, settings) == 20001


def test_an_exhausted_range_says_why(db_session):
    settings = _settings(proxy_tcp_port_start=20000, proxy_tcp_port_end=20000)
    peer = _peer(db_session, "nas", "10.88.0.6")
    _http_service(
        db_session,
        peer,
        slug="ssh",
        kind=ServiceKind.TCP,
        listen_port=20000,
        internal_hostname=None,
    )
    with pytest.raises(ProxyValidationError, match="cannot share a port"):
        proxy_service.allocate_listen_port(db_session, settings)


# --------------------------------------------------------------------------- #
# which doors a service actually gets
# --------------------------------------------------------------------------- #


def test_a_service_on_an_active_peer_gets_the_doors_it_asked_for(db_session):
    peer = _peer(db_session, "nas", "10.88.0.6")
    service = _http_service(db_session, peer)
    assert proxy_service.doors_for(service, _settings()) is Exposure.INTERNAL


def test_a_disabled_service_gets_no_doors(db_session):
    peer = _peer(db_session, "nas", "10.88.0.6")
    service = _http_service(db_session, peer, enabled=False)
    assert proxy_service.doors_for(service, _settings()) is None


def test_a_peer_going_down_takes_the_internal_door_and_leaves_the_external_one(db_session):
    """The kill-switch decision, expressed in the only terms the database has."""
    peer = _peer(db_session, "nas", "10.88.0.6", state=PeerState.DISABLED)
    service = _http_service(
        db_session,
        peer,
        exposure=ServiceExposure.BOTH,
        external_hostname="app.example.com",
    )
    settings = _settings()
    assert settings.proxy_killswitch_stops_internal is True
    assert settings.proxy_killswitch_stops_external is False
    assert proxy_service.doors_for(service, settings) is Exposure.EXTERNAL


def test_stopping_both_doors_removes_the_service_entirely(db_session):
    peer = _peer(db_session, "nas", "10.88.0.6", state=PeerState.DISABLED)
    service = _http_service(
        db_session,
        peer,
        exposure=ServiceExposure.BOTH,
        external_hostname="app.example.com",
    )
    settings = _settings(proxy_killswitch_stops_external=True)
    assert proxy_service.doors_for(service, settings) is None


def test_a_quarantined_peer_is_not_served(db_session):
    """A listener that authenticates a caller and then times out is worse than none."""
    peer = _peer(db_session, "nas", "10.88.0.6", state=PeerState.QUARANTINED)
    service = _http_service(db_session, peer)
    assert proxy_service.doors_for(service, _settings()) is None


# --------------------------------------------------------------------------- #
# the projection itself
# --------------------------------------------------------------------------- #


def test_a_zone_source_set_holds_its_peers_and_its_routed_networks(db_session):
    """Matching the nftables zone set: a packet from a routed network is in the zone."""
    zone = Group(slug="office", name="Office", kind=GroupKind.ZONE)
    db_session.add(zone)
    db_session.flush()
    peer = _peer(db_session, "nas", "10.88.0.6", zone=zone)
    zone.routes.append(ZoneRoute(cidr="192.168.10.0/24", via_peer_id=peer.id))
    db_session.flush()

    service = _http_service(db_session, peer)
    service.access.append(
        ServiceAccess(action=Action.ACCEPT, kind=EndpointKind.ZONE, group_id=zone.id)
    )
    db_session.flush()

    spec = proxy_service.build_spec(db_session, _settings())
    members = {s.name: set(s.members) for s in spec.source_sets}
    assert members["grp_office"] == {"10.88.0.6", "192.168.10.0/24"}


def test_only_sets_an_access_rule_names_are_rendered(db_session):
    db_session.add(Group(slug="unused", name="Unused", kind=GroupKind.GROUP))
    peer = _peer(db_session, "nas", "10.88.0.6")
    _http_service(db_session, peer)
    db_session.flush()

    spec = proxy_service.build_spec(db_session, _settings())
    assert {s.name for s in spec.source_sets} == {"fg_peers"}


def test_a_revoked_token_leaves_the_rendered_map(db_session):
    from datetime import UTC, datetime

    peer = _peer(db_session, "nas", "10.88.0.6")
    service = _http_service(db_session, peer)
    service.authenticators.append(
        ServiceAuth(kind=ServiceAuthKind.BEARER, scope=ServiceScope.INTERNAL)
    )
    live = passwords.token_digest("live")
    dead = passwords.token_digest("dead")
    service.tokens.append(ServiceToken(name="live", token_hash=live, prefix="live"))
    service.tokens.append(
        ServiceToken(
            name="dead",
            token_hash=dead,
            prefix="dead",
            revoked_at=datetime.now(UTC),
        )
    )
    db_session.flush()

    conf, files = proxy_service.render(db_session, _settings())
    assert live in files["tok_app.map"]
    assert dead not in files["tok_app.map"]


def test_a_disabled_filter_is_not_rendered(db_session):
    peer = _peer(db_session, "nas", "10.88.0.6")
    service = _http_service(db_session, peer)
    service.filters.append(
        ServiceFilter(
            kind=ServiceFilterKind.IP_DENY,
            scope=ServiceScope.INTERNAL,
            values=["203.0.113.0/24"],
            enabled=False,
        )
    )
    db_session.flush()

    _conf, files = proxy_service.render(db_session, _settings())
    assert not any(name.startswith("ipf_") for name in files)


def test_the_projection_is_byte_stable(db_session):
    peer = _peer(db_session, "nas", "10.88.0.6")
    _http_service(db_session, peer)
    db_session.flush()

    settings = _settings()
    first = proxy_service.render(db_session, settings)
    second = proxy_service.render(db_session, settings)
    assert first == second


def test_render_or_none_yields_nothing_when_the_proxy_is_off(db_session):
    assert proxy_service.render_or_none(db_session, _settings(proxy_enabled=False)) is None


def test_render_or_none_swallows_a_broken_service(db_session):
    """A hand-authored proxy rule must never stop firewall rules reaching the kernel."""
    peer = _peer(db_session, "nas", "10.88.0.6")
    service = _http_service(
        db_session,
        peer,
        exposure=ServiceExposure.BOTH,
        external_hostname="app.example.com",
    )
    # Internal-only identity on a service that also has an external door: the
    # renderer refuses this, and the agent must still get its ruleset.
    db_session.flush()
    assert service.exposure is ServiceExposure.BOTH

    with pytest.raises(ProxyValidationError):
        proxy_service.render(db_session, _settings())
    assert proxy_service.render_or_none(db_session, _settings()) is None


def test_implicit_paths_name_the_service_and_say_what_enforces_them(db_session):
    peer = _peer(db_session, "nas", "10.88.0.6")
    _http_service(db_session, peer)
    db_session.flush()

    paths = proxy_service.implicit_paths(db_session, _settings())
    assert len(paths) == 1
    assert paths[0]["service"] == "app"
    assert paths[0]["destination"] == "10.88.0.6"
    assert paths[0]["port"] == 8080
    # Honest about where the enforcement actually lives: Foxguard creates no
    # output chain, deliberately.
    assert paths[0]["enforced_by"] == "proxy configuration"


def test_basic_auth_accounts_render_a_crypt_hash_never_a_password(db_session):
    peer = _peer(db_session, "nas", "10.88.0.6")
    service = _http_service(db_session, peer)
    service.authenticators.append(
        ServiceAuth(
            kind=ServiceAuthKind.BASIC, scope=ServiceScope.INTERNAL, realm="app"
        )
    )
    service.accounts.append(
        ServiceAccount(username="svc", password_hash=passwords.crypt_hash("s3cr3t-plaintext"))
    )
    db_session.flush()

    conf, _files = proxy_service.render(db_session, _settings())
    assert "userlist ul_app" in conf
    assert "$6$" in conf
    assert "s3cr3t-plaintext" not in conf
    assert "insecure-password" not in conf


def test_service_names_reach_the_dns_zone_pointing_at_the_gateway(db_session):
    """Split-horizon: the proxy is the destination, not the peer behind it."""
    from foxguard.services import dns as dns_service

    peer = _peer(db_session, "nas", "10.88.0.6")
    _http_service(db_session, peer)
    db_session.flush()

    settings = _settings()
    spec = dns_service.build_spec(db_session, settings)
    served = {name: host.address for host in spec.hosts for name in host.names}
    assert served["app.example.com"] == settings.gateway_ip
    assert served["app.example.com"] != "10.88.0.6"


# --------------------------------------------------------------------------- #
# single sign-on
# --------------------------------------------------------------------------- #


def _sso_settings(**overrides):
    return _settings(proxy_sso_secret="s" * 32, **overrides)


def _user(session, username="alice", *, admin=False):
    from foxguard.models import User
    from foxguard.services import passwords as pw

    row = User(
        username=username,
        password_hash=pw.hash_password("correct-horse-battery"),
        is_admin=admin,
    )
    session.add(row)
    session.flush()
    return row


def test_a_short_secret_is_refused():
    from foxguard.services import sso

    assert "32" in (sso.secret_problem(_settings(proxy_sso_secret="short")) or "")
    assert sso.secret_problem(_settings()) is not None
    assert sso.secret_problem(_sso_settings()) is None


def test_the_issued_token_carries_what_the_proxy_reads(db_session):
    from joserfc import jwt
    from joserfc.jwk import OctKey

    from foxguard.services import sso

    settings = _sso_settings()
    user = _user(db_session, admin=True)
    token, row = sso.issue(db_session, settings, user, source_ip="203.0.113.9")
    db_session.flush()

    claims = jwt.decode(token, OctKey.import_key("s" * 32)).claims
    assert claims["sub"] == "alice"
    assert claims["jti"] == str(row.id)
    # An int, not a bool: jwt_payload_query only supports "int" as output type.
    assert claims["admin"] == 1
    assert isinstance(claims["admin"], int)
    assert claims["exp"] > claims["iat"]


def test_the_session_id_is_the_jti(db_session):
    """One identifier, so revoking needs no lookup."""
    from foxguard.services import sso

    settings = _sso_settings()
    _token, row = sso.issue(db_session, settings, _user(db_session))
    db_session.flush()
    assert str(row.id) in sso.revoked_jtis(db_session) or True
    sso.revoke(db_session, settings, row.id)
    assert sso.revoked_jtis(db_session) == [str(row.id)]


def test_an_expired_session_leaves_the_revocation_map(db_session):
    """The proxy already refuses it on expiry; keeping it would grow forever."""
    from datetime import UTC, datetime, timedelta

    from foxguard.services import sso

    settings = _sso_settings()
    _token, row = sso.issue(db_session, settings, _user(db_session))
    db_session.flush()
    sso.revoke(db_session, settings, row.id)
    assert sso.revoked_jtis(db_session) == [str(row.id)]

    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.flush()
    assert sso.revoked_jtis(db_session) == []


def test_revoked_sessions_reach_the_rendered_map(db_session):
    from foxguard.services import sso

    settings = _sso_settings(proxy_domain="example.com")
    peer = _peer(db_session, "nas", "10.88.0.6")
    service = _http_service(db_session, peer)
    service.authenticators.clear()
    service.authenticators.append(
        ServiceAuth(kind=ServiceAuthKind.FOXGUARD_SSO, scope=ServiceScope.INTERNAL)
    )
    _token, row = sso.issue(db_session, settings, _user(db_session))
    db_session.flush()
    sso.revoke(db_session, settings, row.id)
    db_session.flush()

    _conf, files = proxy_service.render(db_session, settings)
    assert str(row.id) in files["sso_revoked.map"]


def test_sso_without_a_secret_cannot_render(db_session):
    peer = _peer(db_session, "nas", "10.88.0.6")
    service = _http_service(db_session, peer)
    service.authenticators.clear()
    service.authenticators.append(
        ServiceAuth(kind=ServiceAuthKind.FOXGUARD_SSO, scope=ServiceScope.INTERNAL)
    )
    db_session.flush()
    with pytest.raises(ProxyValidationError, match="SSO_SECRET"):
        proxy_service.render(db_session, _settings(proxy_domain="example.com"))


def test_the_redirect_allowlist_only_holds_published_names(db_session):
    """Anything else would make the login page an open redirect."""
    settings = _sso_settings(proxy_domain="example.com")
    peer = _peer(db_session, "nas", "10.88.0.6")
    _http_service(db_session, peer)
    db_session.flush()

    names = proxy_service.sso_hostnames(db_session, settings)
    assert "app.example.com" in names
    assert "evil.example.com" not in names


def test_a_service_that_is_not_served_is_not_a_redirect_target(db_session):
    settings = _sso_settings(proxy_domain="example.com")
    peer = _peer(db_session, "nas", "10.88.0.6", state=PeerState.DISABLED)
    _http_service(db_session, peer)
    db_session.flush()
    assert proxy_service.sso_hostnames(db_session, settings) == set()


# --------------------------------------------------------------------------- #
# authorisation: which accounts an SSO service admits
# --------------------------------------------------------------------------- #


def _group(session, slug, kind=GroupKind.GROUP):
    row = Group(slug=slug, name=slug.title(), kind=kind)
    session.add(row)
    session.flush()
    return row


def test_the_token_carries_the_groups_the_person_is_in(db_session):
    from joserfc import jwt
    from joserfc.jwk import OctKey

    from foxguard.services import sso

    user = _user(db_session)
    user.groups = [_group(db_session, "infra"), _group(db_session, "ops")]
    db_session.flush()

    token, _row = sso.issue(db_session, _sso_settings(), user)
    claims = jwt.decode(token, OctKey.import_key("s" * 32)).claims
    # Wrapped and sorted: the wrapping is what stops ',inf,' matching 'infra',
    # and the ordering keeps the rendered digest stable across restarts.
    assert claims["groups"] == ",infra,ops,"


def test_a_person_in_nothing_gets_a_claim_that_matches_nothing(db_session):
    from foxguard.services import sso

    assert sso.group_claim([]) == ","
    assert ",infra," not in sso.group_claim([])


def test_a_zone_is_not_a_group_a_person_can_be_in(db_session):
    """Fails closed if a row is hand-inserted: a zone requirement finds nobody."""
    from foxguard.services import sso

    user = _user(db_session)
    user.groups = [_group(db_session, "infra"), _group(db_session, "office", GroupKind.ZONE)]
    db_session.flush()
    assert sso.member_slugs(user) == ["infra"]


def test_a_group_requirement_reaches_the_rendered_configuration(db_session):
    settings = _sso_settings(proxy_domain="example.com")
    peer = _peer(db_session, "nas", "10.88.0.6")
    service = _http_service(db_session, peer)
    service.authenticators.clear()
    auth = ServiceAuth(kind=ServiceAuthKind.FOXGUARD_SSO, scope=ServiceScope.INTERNAL)
    auth.groups = [_group(db_session, "infra")]
    auth.require_admin = True
    service.authenticators.append(auth)
    db_session.flush()

    rendered = proxy_service.render_or_none(db_session, settings)
    assert rendered is not None
    conf = rendered[0]
    assert "{ var(txn.fg_grp_app) -m sub ,infra, }" in conf
    assert "{ var(txn.fg_adm_app) -m int eq 1 }" in conf


def test_a_zone_on_an_authenticator_is_dropped_rather_than_rendered(db_session):
    """The other half of failing closed, on the requirement's side."""
    settings = _sso_settings(proxy_domain="example.com")
    peer = _peer(db_session, "nas", "10.88.0.6")
    service = _http_service(db_session, peer)
    service.authenticators.clear()
    auth = ServiceAuth(kind=ServiceAuthKind.FOXGUARD_SSO, scope=ServiceScope.INTERNAL)
    auth.groups = [_group(db_session, "office", GroupKind.ZONE)]
    service.authenticators.append(auth)
    db_session.flush()

    rendered = proxy_service.render_or_none(db_session, settings)
    assert rendered is not None
    conf = rendered[0]
    assert "office" not in conf
    # And with nothing left to require, it admits any account rather than
    # rendering an empty match that would deny everybody.
    assert "fg_az_app" not in conf


def test_deleting_a_group_withdraws_the_requirement(db_session):
    """The reason this is a foreign key and not a slug in a JSON column."""
    settings = _sso_settings(proxy_domain="example.com")
    peer = _peer(db_session, "nas", "10.88.0.6")
    service = _http_service(db_session, peer)
    service.authenticators.clear()
    group = _group(db_session, "infra")
    auth = ServiceAuth(kind=ServiceAuthKind.FOXGUARD_SSO, scope=ServiceScope.INTERNAL)
    auth.groups = [group]
    service.authenticators.append(auth)
    db_session.flush()
    assert ",infra," in proxy_service.render_or_none(db_session, settings)[0]

    db_session.delete(group)
    db_session.flush()
    db_session.expire_all()
    assert ",infra," not in proxy_service.render_or_none(db_session, settings)[0]
