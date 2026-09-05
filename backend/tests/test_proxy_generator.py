"""The HAProxy renderer: byte stability, refusals, and the two measured traps."""

from __future__ import annotations

import pytest

from foxguard.proxy import (
    AccessAction,
    AccessRule,
    Account,
    Authenticator,
    AuthKind,
    Backend,
    Exposure,
    Filter,
    FilterKind,
    PeerIdentity,
    ProxySpec,
    ProxyValidationError,
    Scope,
    Service,
    ServiceKind,
    SourceSet,
    proxy_digest,
    render_conf,
    render_files,
)
from foxguard.proxy.haproxy import MAX_SOCKET_PATH, PEER_SET

CRYPT = "$6$foxguard$" + "a" * 43
TOKEN = "f" * 64


def _peer_auth(scope=Scope.INTERNAL):
    return Authenticator(AuthKind.PEER_IDENTITY, scope)


def _service(**kwargs):
    base = {
        "slug": "app",
        "kind": ServiceKind.HTTP,
        "exposure": Exposure.INTERNAL,
        "backend": Backend("10.88.0.6", 8080),
        "internal_hostname": "app.example.com",
        "authenticators": (_peer_auth(),),
    }
    base.update(kwargs)
    return Service(**base)


def _spec(*services, **kwargs):
    base = {
        "domain": "example.com",
        "internal_binds": ("10.88.0.1",),
        "external_binds": ("203.0.113.10",),
        "services": services,
        "source_sets": (SourceSet(PEER_SET, ("10.88.0.5", "10.88.0.6")),),
        "peers": (PeerIdentity("10.88.0.5", "laptop", ("devs",)),),
    }
    base.update(kwargs)
    return ProxySpec(**base)


# --------------------------------------------------------------------------- #
# byte stability
# --------------------------------------------------------------------------- #


def test_the_same_spec_renders_the_same_bytes():
    spec = _spec(_service(), _service(slug="other", internal_hostname="b.example.com"))
    assert render_conf(spec) == render_conf(spec)
    assert render_files(spec) == render_files(spec)


def test_service_order_does_not_change_the_output():
    a = _service()
    b = _service(slug="other", internal_hostname="b.example.com")
    assert render_conf(_spec(a, b)) == render_conf(_spec(b, a))


def test_the_digest_covers_the_pattern_files_not_just_the_config():
    """A configuration referencing last state's token map must not look current."""
    spec = _spec(
        _service(
            authenticators=(_peer_auth(), Authenticator(AuthKind.BEARER, Scope.INTERNAL)),
            token_hashes=(TOKEN,),
        )
    )
    conf = render_conf(spec)
    files = render_files(spec)
    tampered = dict(files)
    tampered["tok_app.map"] = tampered["tok_app.map"] + "deadbeef 1\n"
    assert proxy_digest(conf, files) != proxy_digest(conf, tampered)


def test_addresses_are_sorted_numerically_not_lexically():
    spec = _spec(
        _service(),
        source_sets=(SourceSet(PEER_SET, ("10.88.0.10", "10.88.0.2", "10.88.0.1")),),
    )
    body = render_files(spec)[f"set_{PEER_SET}.lst"]
    addresses = [line for line in body.splitlines() if not line.startswith("#")]
    assert addresses == ["10.88.0.1", "10.88.0.2", "10.88.0.10"]


# --------------------------------------------------------------------------- #
# the two measured traps
# --------------------------------------------------------------------------- #


def test_the_bearer_expression_lowercases_the_digest():
    """HAProxy's hex converter emits uppercase; the map does not.

    Without ``,lower`` no token ever matches and the failure is a silent 403.
    """
    spec = _spec(
        _service(
            authenticators=(Authenticator(AuthKind.BEARER, Scope.INTERNAL),),
            token_hashes=(TOKEN,),
        )
    )
    conf = render_conf(spec)
    assert "sha2(256),hex,lower," in conf
    assert "sha2(256),hex,map_str" not in conf


def test_an_over_long_runtime_socket_is_refused():
    """97 characters, and HAProxy treats it as a fatal parse error."""
    spec = _spec(_service(), runtime_socket="/run/" + "x" * 200 + ".sock")
    with pytest.raises(ProxyValidationError, match=str(MAX_SOCKET_PATH)):
        render_conf(spec)


# --------------------------------------------------------------------------- #
# identity
# --------------------------------------------------------------------------- #


def test_peer_identity_may_not_apply_to_the_external_listener():
    with pytest.raises(ProxyValidationError, match="external listener"):
        render_conf(
            _spec(
                _service(
                    exposure=Exposure.EXTERNAL,
                    external_hostname="app.example.com",
                    internal_hostname=None,
                    authenticators=(_peer_auth(Scope.BOTH),),
                )
            )
        )


def test_a_door_with_no_applicable_authenticator_is_refused():
    """Otherwise the service is wide open or wholly shut depending on the fallback."""
    with pytest.raises(ProxyValidationError, match="no authenticator"):
        render_conf(
            _spec(
                _service(
                    exposure=Exposure.BOTH,
                    external_hostname="app.example.com",
                    authenticators=(_peer_auth(Scope.INTERNAL),),
                )
            )
        )


def test_identity_headers_are_deleted_before_any_rule_can_set_them():
    conf = render_conf(_spec(_service()))
    delete = conf.index("http-request del-header X-Foxguard-Peer")
    setter = conf.index("http-request set-header X-Foxguard-Peer")
    assert delete < setter, "a caller could forge the header we later trust"


def test_the_identity_header_is_only_set_on_the_internal_listener():
    spec = _spec(
        _service(
            exposure=Exposure.BOTH,
            external_hostname="app.example.com",
            authenticators=(
                _peer_auth(Scope.INTERNAL),
                Authenticator(AuthKind.BEARER, Scope.EXTERNAL),
            ),
            token_hashes=(TOKEN,),
        )
    )
    conf = render_conf(spec)
    external = conf[conf.index("frontend fg_ext_https") : conf.index("frontend fg_int_https")]
    assert "set-header X-Foxguard-Peer" not in external
    assert "del-header X-Foxguard-Peer" in external


def test_group_access_rules_are_dropped_on_the_external_listener():
    """A public source address cannot be a peer; evaluating it would deny everyone."""
    spec = _spec(
        _service(
            exposure=Exposure.BOTH,
            external_hostname="app.example.com",
            authenticators=(
                _peer_auth(Scope.INTERNAL),
                Authenticator(AuthKind.BEARER, Scope.EXTERNAL),
            ),
            token_hashes=(TOKEN,),
            access=(AccessRule(AccessAction.ALLOW, "grp_devs", is_set=True),),
        ),
        source_sets=(
            SourceSet(PEER_SET, ("10.88.0.5",)),
            SourceSet("grp_devs", ("10.88.0.5",)),
        ),
    )
    conf = render_conf(spec)
    external = conf[conf.index("frontend fg_ext_https") : conf.index("frontend fg_int_https")]
    internal = conf[conf.index("frontend fg_int_https") :]
    assert "set_grp_devs.lst" not in external
    assert "set_grp_devs.lst" in internal


# --------------------------------------------------------------------------- #
# passthrough is not HTTP
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("kind", [AuthKind.BEARER, AuthKind.BASIC])
def test_http_authenticators_are_refused_on_a_passthrough_service(kind):
    with pytest.raises(ProxyValidationError, match="never sees the plaintext"):
        render_conf(
            _spec(
                _service(
                    kind=ServiceKind.TCP,
                    listen_port=20000,
                    internal_hostname=None,
                    authenticators=(_peer_auth(), Authenticator(kind, Scope.INTERNAL)),
                    token_hashes=(TOKEN,),
                    accounts=(Account("svc", CRYPT),),
                )
            )
        )


def test_a_waf_filter_is_refused_on_a_passthrough_service():
    with pytest.raises(ProxyValidationError):
        render_conf(
            _spec(
                _service(
                    kind=ServiceKind.TCP,
                    listen_port=20000,
                    internal_hostname=None,
                    filters=(Filter(FilterKind.WAF, Scope.INTERNAL),),
                )
            )
        )


def test_a_plain_tcp_service_needs_a_port_or_an_sni_name():
    with pytest.raises(ProxyValidationError, match="nothing to route on"):
        render_conf(
            _spec(_service(kind=ServiceKind.TCP, internal_hostname=None))
        )


def test_two_services_may_not_claim_the_same_port():
    with pytest.raises(ProxyValidationError, match="claimed by both"):
        render_conf(
            _spec(
                _service(kind=ServiceKind.TCP, listen_port=20000, internal_hostname=None),
                _service(
                    slug="other",
                    kind=ServiceKind.TCP,
                    listen_port=20000,
                    internal_hostname=None,
                ),
            )
        )


def test_two_services_may_not_claim_the_same_hostname_on_one_door():
    with pytest.raises(ProxyValidationError, match="claimed by both"):
        render_conf(_spec(_service(), _service(slug="other")))


# --------------------------------------------------------------------------- #
# credentials never reach disk in the clear
# --------------------------------------------------------------------------- #


def test_a_plaintext_password_is_refused():
    with pytest.raises(ProxyValidationError, match="SHA-crypt"):
        render_conf(
            _spec(
                _service(
                    authenticators=(Authenticator(AuthKind.BASIC, Scope.INTERNAL),),
                    accounts=(Account("svc", "hunter2"),),
                )
            )
        )


def test_an_uppercase_token_digest_is_refused():
    """It would never match, because the config lowercases before the lookup."""
    with pytest.raises(ProxyValidationError, match="lowercase"):
        render_conf(
            _spec(
                _service(
                    authenticators=(Authenticator(AuthKind.BEARER, Scope.INTERNAL),),
                    token_hashes=("F" * 64,),
                )
            )
        )


def test_basic_auth_without_an_account_is_refused():
    with pytest.raises(ProxyValidationError, match="no service account"):
        render_conf(
            _spec(
                _service(authenticators=(Authenticator(AuthKind.BASIC, Scope.INTERNAL),))
            )
        )


def test_bearer_without_a_token_is_refused():
    with pytest.raises(ProxyValidationError, match="no token"):
        render_conf(
            _spec(
                _service(authenticators=(Authenticator(AuthKind.BEARER, Scope.INTERNAL),))
            )
        )


# --------------------------------------------------------------------------- #
# not implemented yet, and loud about it
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("kind", [FilterKind.CROWDSEC, FilterKind.WAF])
def test_unimplemented_filters_are_refused_rather_than_ignored(kind):
    """Geo left this list in phase D. CrowdSec and the WAF are one project and
    have not."""
    with pytest.raises(ProxyValidationError, match="not implemented"):
        render_conf(_spec(_service(filters=(Filter(kind, Scope.INTERNAL),))))


def test_mtls_is_still_refused_as_unimplemented():
    """SSO landed in Phase 7c; mTLS has not."""
    with pytest.raises(ProxyValidationError, match="not implemented"):
        render_conf(
            _spec(
                _service(
                    authenticators=(Authenticator(AuthKind.MTLS, Scope.INTERNAL),)
                )
            )
        )


def test_an_empty_ip_allow_list_is_refused():
    """It would deny everything, which is never what anyone typed."""
    with pytest.raises(ProxyValidationError, match="deny everything"):
        render_conf(
            _spec(_service(filters=(Filter(FilterKind.IP_ALLOW, Scope.INTERNAL, ()),)))
        )


# --------------------------------------------------------------------------- #
# rendered content
# --------------------------------------------------------------------------- #


def test_an_error_page_names_the_device_hosting_the_service():
    spec = _spec(_service(backend=Backend("10.88.0.6", 8080, peer_label="nas")))
    page = render_files(spec)["err_app_503.http"]
    assert "503" in page
    assert "nas" in page
    assert page.startswith("HTTP/1.1 503")


def test_a_slug_with_a_hyphen_produces_a_valid_variable_name():
    spec = _spec(
        _service(
            slug="nas-ui",
            authenticators=(Authenticator(AuthKind.BEARER, Scope.INTERNAL),),
            token_hashes=(TOKEN,),
        )
    )
    conf = render_conf(spec)
    assert "txn.fg_tok_nas_ui" in conf
    assert "txn.fg_tok_nas-ui" not in conf


def test_an_allow_any_rule_emits_no_catch_all_deny():
    conf = render_conf(_spec(_service(access=(AccessRule(AccessAction.ALLOW, None),))))
    body = conf[conf.index("--- app") :]
    assert "http-request deny if h_app !" not in body


def test_the_external_http_frontend_only_redirects():
    spec = _spec(
        _service(
            exposure=Exposure.EXTERNAL,
            internal_hostname=None,
            external_hostname="app.example.com",
            authenticators=(Authenticator(AuthKind.BEARER, Scope.EXTERNAL),),
            token_hashes=(TOKEN,),
        )
    )
    conf = render_conf(spec)
    block = conf[conf.index("frontend fg_ext_http\n") : conf.index("frontend fg_ext_https")]
    assert "redirect scheme https" in block
    assert "use_backend" not in block


def test_external_exposure_without_a_wan_bind_is_refused():
    with pytest.raises(ProxyValidationError, match="no external bind"):
        render_conf(
            _spec(
                _service(
                    exposure=Exposure.EXTERNAL,
                    internal_hostname=None,
                    external_hostname="app.example.com",
                    authenticators=(Authenticator(AuthKind.BEARER, Scope.EXTERNAL),),
                    token_hashes=(TOKEN,),
                ),
                external_binds=(),
            )
        )


def test_upstream_tls_verification_is_off_unless_asked_for():
    conf = render_conf(_spec(_service(backend=Backend("10.88.0.6", 443, tls=True))))
    assert "ssl verify none" in conf
    conf = render_conf(
        _spec(_service(backend=Backend("10.88.0.6", 443, tls=True, tls_verify=True)))
    )
    assert "verify required" in conf


def test_an_ipv6_bind_address_is_bracketed():
    spec = _spec(_service(), internal_binds=("fd00::1",))
    assert "bind [fd00::1]:443" in render_conf(spec)


# --------------------------------------------------------------------------- #
# single sign-on
# --------------------------------------------------------------------------- #


def _sso_spec(_auth=None, **kwargs):
    base = {
        "sso_secret": "s" * 32,
        "sso_hostname": "auth.example.com",
        "sso_cookie_domain": "example.com",
    }
    base.update(kwargs)
    return _spec(
        _service(
            authenticators=(
                _auth or Authenticator(AuthKind.FOXGUARD_SSO, Scope.INTERNAL),
            ),
        ),
        **base,
    )


def test_the_jwt_algorithm_is_pinned_never_read_from_the_token():
    """The whole reason ``_sso_setup`` sets a variable first.

    Measured on HAProxy 3.0.11: ``jwt_verify`` with the algorithm taken from the
    token's own header returns 1 for an unsigned ``alg:none`` token. The
    idiomatic snippet is forgeable, so it must not appear here.
    """
    conf = render_conf(_sso_spec())
    assert "jwt_header_query('$.alg')" not in conf
    assert "set-var(txn.fg_alg_app) str(HS256)" in conf
    assert "jwt_verify(txn.fg_alg_app," in conf


def test_expiry_is_compared_explicitly():
    """``jwt_verify`` ignores ``exp``; an expired token verifies happily."""
    conf = render_conf(_sso_spec())
    assert "jwt_payload_query('$.exp','int')" in conf
    assert "sub(txn.fg_now_app)" in conf
    assert "{ var(txn.fg_left_app) -m int gt 0 }" in conf


def test_only_a_verify_result_of_exactly_one_is_accepted():
    """The converter returns negatives for invalid tokens; -3 is truthy."""
    conf = render_conf(_sso_spec())
    assert "{ var(txn.fg_ok_app) -m int eq 1 }" in conf


def test_the_revocation_map_is_consulted():
    conf = render_conf(_sso_spec())
    assert "sso_revoked.map" in conf
    assert "!{ var(txn.fg_rev_app) -m found }" in conf


def test_the_revocation_map_exists_even_when_empty():
    """haproxy -c resolves -f at parse time: a missing map is a fatal error."""
    assert "sso_revoked.map" in render_files(_sso_spec())


def test_a_revoked_session_lands_in_the_map():
    jti = "11111111-1111-1111-1111-111111111111"
    files = render_files(_sso_spec(sso_revoked=(jti,)))
    assert jti in files["sso_revoked.map"]


def test_an_unauthenticated_browser_is_redirected_not_refused():
    conf = render_conf(_sso_spec())
    assert "http-request redirect location https://auth.example.com/api/v1/sso/login" in conf
    # The destination is passed url-encoded and validated server-side; a raw
    # Host header in a redirect would be an open redirect.
    assert "url_enc" in conf


def test_the_auth_vhost_only_routes_the_sso_paths():
    conf = render_conf(_sso_spec())
    assert "acl p_fg_sso path_beg /api/v1/sso/" in conf
    assert "http-request deny deny_status 404 if h_fg_sso !p_fg_sso" in conf


def test_the_auth_vhost_supplies_the_real_client_address():
    """Without it every sign-in attempt shares one throttle budget."""
    conf = render_conf(_sso_spec())
    assert "set-header X-Foxguard-Client-IP %[src] if h_fg_sso" in conf


def test_sso_without_a_secret_is_refused():
    with pytest.raises(ProxyValidationError, match="SSO_SECRET"):
        render_conf(_sso_spec(sso_secret=""))


def test_sso_without_a_login_hostname_is_refused():
    with pytest.raises(ProxyValidationError, match="login page"):
        render_conf(_sso_spec(sso_hostname=None))


def test_sso_is_refused_on_a_passthrough_service():
    with pytest.raises(ProxyValidationError, match="never sees the plaintext"):
        render_conf(
            _spec(
                _service(
                    kind=ServiceKind.TCP,
                    listen_port=20000,
                    internal_hostname=None,
                    authenticators=(
                        Authenticator(AuthKind.FOXGUARD_SSO, Scope.INTERNAL),
                    ),
                ),
                sso_secret="s" * 32,
                sso_hostname="auth.example.com",
            )
        )


# --------------------------------------------------------------------------- #
# SSO authorisation: signed in is not the same as allowed in
# --------------------------------------------------------------------------- #


def _sso_auth(**kwargs):
    return Authenticator(AuthKind.FOXGUARD_SSO, Scope.INTERNAL, **kwargs)


def test_no_requirement_emits_no_authorisation_at_all():
    """A service that admits any account renders what it did before this existed."""
    conf = render_conf(_sso_spec())
    assert "fg_az_app" not in conf
    assert "fg_grp_app" not in conf
    assert "jwt_payload_query('$.admin'" not in conf


def test_a_group_requirement_matches_on_the_wrapped_slug():
    """The delimiters are the whole defence against a prefix match.

    Measured on HAProxy 3.0.11: ``-m sub infra`` matches a member of
    ``infrastructure``; ``-m sub ,infra,`` does not.
    """
    conf = render_conf(_sso_spec(_sso_auth(groups=("infra",))))
    assert "set-var(txn.fg_grp_app) var(txn.fg_jwt_app),jwt_payload_query('$.groups')" in conf
    assert "{ var(txn.fg_grp_app) -m sub ,infra, }" in conf


def test_several_groups_are_an_or_on_one_condition():
    """Measured: multiple patterns on one match are an OR, which HAProxy's
    condition language cannot otherwise express."""
    conf = render_conf(_sso_spec(_sso_auth(groups=("infra", "ops"))))
    assert "{ var(txn.fg_grp_app) -m sub ,infra, ,ops, }" in conf


def test_admin_only_reads_the_claim_that_was_already_there():
    conf = render_conf(_sso_spec(_sso_auth(require_admin=True)))
    assert "jwt_payload_query('$.admin','int')" in conf
    assert "{ var(txn.fg_adm_app) -m int eq 1 }" in conf


def test_groups_and_admin_are_combined_by_and():
    conf = render_conf(_sso_spec(_sso_auth(groups=("infra",), require_admin=True)))
    line = next(
        row for row in conf.splitlines() if "set-var(txn.fg_az_app) int(1)" in row
    )
    assert "{ var(txn.fg_grp_app) -m sub ,infra, }" in line
    assert "{ var(txn.fg_adm_app) -m int eq 1 }" in line


def test_the_verdict_goes_through_a_variable_so_it_can_be_negated():
    """A conjunction's negation is a disjunction, and HAProxy has no OR.

    Reducing the requirement to an integer first is what lets the refusal branch
    ask for "not authorised" in one term.
    """
    conf = render_conf(_sso_spec(_sso_auth(groups=("infra",))))
    assert "set-var(txn.fg_az_app) int(0)" in conf
    assert "{ var(txn.fg_az_app) -m int eq 1 }" in conf
    assert "{ var(txn.fg_az_app) -m int eq 0 }" in conf


def test_a_signed_in_stranger_is_refused_not_redirected():
    """The loop this prevents is unbreakable from the browser.

    Redirecting somebody who already holds a valid cookie sends them to a login
    page that signs them in again, hands back the same cookie, and bounces them
    straight here -- forever, and reading as if the service were down.
    """
    conf = render_conf(_sso_spec(_sso_auth(groups=("infra",))))
    refusal = next(row for row in conf.splitlines() if "status 403" in row)
    redirect = next(row for row in conf.splitlines() if "http-request redirect" in row)
    # It must ask for a *valid* session, or it would swallow the redirect.
    assert "{ var(txn.fg_ok_app) -m int eq 1 }" in refusal
    assert "{ var(txn.fg_az_app) -m int eq 0 }" in refusal
    # And it must be evaluated first, or the redirect wins and the loop is back.
    assert conf.index(refusal) < conf.index(redirect)


def test_the_refusal_says_what_is_missing():
    conf = render_conf(_sso_spec(_sso_auth(groups=("infra", "ops"), require_admin=True)))
    refusal = next(row for row in conf.splitlines() if "status 403" in row)
    assert "an administrator account" in refusal
    assert "infra, ops" in refusal
    # Named, so the person reading it knows which account was refused.
    assert "var(txn.fg_sub_app)" in refusal


def test_a_bearer_token_cannot_carry_a_group_requirement():
    """It proves possession of a secret. It names nobody."""
    with pytest.raises(ProxyValidationError, match="names no person"):
        render_conf(
            _spec(
                _service(
                    authenticators=(
                        Authenticator(
                            AuthKind.BEARER, Scope.INTERNAL, groups=("infra",)
                        ),
                    ),
                    token_hashes=("a" * 64,),
                )
            )
        )


def test_a_group_slug_that_could_forge_a_membership_is_refused():
    """The delimiter is the contract; a slug containing one would break it."""
    with pytest.raises(ProxyValidationError, match="not a valid group slug"):
        render_conf(_sso_spec(_sso_auth(groups=("infra,ops",))))


def test_the_generator_and_the_issuer_agree_on_the_delimiter():
    """Duplicated across a module boundary on purpose, so it is asserted."""
    from foxguard.proxy.haproxy import GROUP_DELIMITER as rendered
    from foxguard.services.sso import GROUP_DELIMITER as issued

    assert rendered == issued


def test_no_auth_vhost_is_emitted_when_nothing_uses_sso():
    conf = render_conf(_spec(_service()))
    assert "h_fg_sso" not in conf
    assert "be_fg_sso" not in conf


def test_the_user_header_is_set_from_the_verified_claim():
    conf = render_conf(_sso_spec())
    assert "set-header X-Foxguard-User %[var(txn.fg_sub_app)]" in conf
    # And the client's own copy dies at the door, before any rule can set it.
    assert conf.index("del-header X-Foxguard-User") < conf.index(
        "set-header X-Foxguard-User"
    )


# --------------------------------------------------------------------------- #
# rate limiting
# --------------------------------------------------------------------------- #


def _rate_limited(rate=10, period=60):
    return _spec(
        _service(
            filters=(
                Filter(
                    FilterKind.RATE_LIMIT,
                    Scope.INTERNAL,
                    rate=rate,
                    period_seconds=period,
                ),
            ),
        )
    )


def test_a_rate_limit_gets_a_table_sized_to_its_own_window():
    conf = render_conf(_rate_limited(rate=10, period=60))
    assert "stick-table type ip size 100k expire 120s store http_req_rate(60s)" in conf
    assert "http-request track-sc0 src table" in conf
    assert "{ sc_http_req_rate(0) gt 10 }" in conf


def test_the_refusal_says_when_to_come_back():
    """A 429 with no Retry-After is a refusal a client cannot act on.

    Rendered as ``return`` rather than ``deny`` for exactly this: ``deny`` takes
    a status and nothing else, so the header would have nowhere to go.
    """
    conf = render_conf(_rate_limited(period=45))
    refusal = next(row for row in conf.splitlines() if "status 429" in row)
    assert 'hdr retry-after "45"' in refusal
    assert "retry in 45s" in refusal


def test_a_rate_limit_with_half_its_numbers_is_refused():
    with pytest.raises(ProxyValidationError, match="needs both a rate and a period"):
        render_conf(
            _spec(
                _service(
                    filters=(Filter(FilterKind.RATE_LIMIT, Scope.INTERNAL, rate=10),),
                )
            )
        )


# --------------------------------------------------------------------------- #
# geography
# --------------------------------------------------------------------------- #


def _geo(kind, *countries, scope=Scope.INTERNAL):
    return _spec(_service(filters=(Filter(kind, scope, values=countries),)))


def test_an_allow_list_denies_everyone_it_does_not_name():
    conf = render_conf(_geo(FilterKind.GEO_ALLOW, "FR", "CH"))
    line = next(row for row in conf.splitlines() if "map_ip" in row)
    # Negated: deny unless the lookup says one of these.
    assert "!{ src,map_ip(/etc/foxguard/proxy/maps/geo.map) -m str FR CH }" in line
    assert line.strip().startswith("http-request deny")


def test_a_deny_list_denies_only_who_it_names():
    conf = render_conf(_geo(FilterKind.GEO_DENY, "CN", "RU"))
    line = next(row for row in conf.splitlines() if "map_ip" in row)
    assert "{ src,map_ip(/etc/foxguard/proxy/maps/geo.map) -m str CN RU }" in line
    assert "!{" not in line


def test_every_service_shares_one_map():
    """Not a pattern file per service: the map is built from the union, and the
    union is what keeps it 47 MiB of memory instead of 367."""
    spec = _spec(
        _service(filters=(Filter(FilterKind.GEO_DENY, Scope.INTERNAL, values=("CN",)),)),
        _service(
            slug="other",
            internal_hostname="b.example.com",
            filters=(Filter(FilterKind.GEO_ALLOW, Scope.INTERNAL, values=("FR",)),),
        ),
    )
    conf = render_conf(spec)
    assert conf.count("geo.map") == 2
    assert "geo_app" not in conf and "geo_other" not in conf


def test_the_countries_the_gateway_must_cover_are_the_union():
    spec = _spec(
        _service(
            filters=(Filter(FilterKind.GEO_DENY, Scope.INTERNAL, values=("RU", "CN")),)
        ),
        _service(
            slug="other",
            internal_hostname="b.example.com",
            filters=(
                Filter(FilterKind.GEO_ALLOW, Scope.INTERNAL, values=("FR", "CN")),
            ),
        ),
    )
    assert spec.geo_countries == ("CN", "FR", "RU")
    assert spec.uses_geo


def test_a_spec_with_no_geo_filter_asks_for_no_countries():
    spec = _spec(_service())
    assert spec.geo_countries == ()
    assert not spec.uses_geo
    assert "geo.map" not in render_conf(spec)


@pytest.mark.parametrize("code", ["fr", "FRA", "F", "F1", "", "FR,CH"])
def test_a_value_that_is_not_a_country_code_is_refused(code):
    with pytest.raises(ProxyValidationError, match="ISO 3166-1"):
        render_conf(_geo(FilterKind.GEO_ALLOW, code))


def test_an_empty_allow_list_is_refused_for_what_it_would_do():
    with pytest.raises(ProxyValidationError, match="would deny everything"):
        render_conf(_geo(FilterKind.GEO_ALLOW))


def test_an_empty_deny_list_is_refused_for_what_it_would_not_do():
    """The other half of "a filter that does nothing is worse than one that
    refuses to save"."""
    with pytest.raises(ProxyValidationError, match="would do nothing at all"):
        render_conf(_geo(FilterKind.GEO_DENY))


def test_geo_applies_to_a_passthrough_service_too():
    """Unlike the WAF: this reads a source address, not a request."""
    conf = render_conf(
        _spec(
            _service(
                kind=ServiceKind.TCP,
                listen_port=20000,
                internal_hostname=None,
                filters=(
                    Filter(FilterKind.GEO_DENY, Scope.INTERNAL, values=("CN",)),
                ),
            )
        )
    )
    assert "tcp-request content reject if { src,map_ip" in conf


# --------------------------------------------------------------------------- #
# public services
# --------------------------------------------------------------------------- #


def _public_site(**kwargs):
    base = {
        "slug": "site",
        "exposure": Exposure.EXTERNAL,
        "internal_hostname": None,
        "external_hostname": "site.example.com",
        "authenticators": (Authenticator(AuthKind.PUBLIC, Scope.EXTERNAL),),
    }
    base.update(kwargs)
    return _service(**base)


def test_a_public_service_renders_no_authentication_at_all():
    """The point of the feature: a web site anyone may read.

    Asserted on the absence of a refusal rather than on the presence of some
    marker, because that absence *is* the behaviour -- and it is what separates
    this from every other authenticator.
    """
    conf = render_conf(_spec(_public_site()))
    body = "\n".join(
        line for line in conf.splitlines() if "site" in line or "fg_auth" in line
    )
    assert "http-request deny" not in body
    assert "http-request auth" not in body
    assert "txn.fg_auth" not in body


def test_a_public_service_still_gets_its_filters():
    """Public removes the identity question, not the rest of the policy.

    The regression this guards against is an implementation that returns early
    on PUBLIC before writing the filters, which would silently drop a rate limit
    an operator believes is in force.
    """
    service = _public_site(
        filters=(
            Filter(
                FilterKind.GEO_DENY,
                scope=Scope.EXTERNAL,
                values=("RU", "KP"),
            ),
        ),
    )
    conf = render_conf(_spec(service))
    assert "geo.map" in conf
    assert "http-request deny" in conf


def test_an_empty_authenticator_list_is_still_refused():
    """Forgetting to guard a service must not look like opening it on purpose."""
    with pytest.raises(ProxyValidationError, match="no authenticator"):
        render_conf(_spec(_public_site(authenticators=())))


def test_public_cannot_sit_next_to_another_way_in():
    """An OR with public is public, so the other one is a lie in the config."""
    service = _public_site(
        authenticators=(
            Authenticator(AuthKind.PUBLIC, Scope.EXTERNAL),
            Authenticator(AuthKind.BEARER, Scope.EXTERNAL),
        ),
        token_hashes=(TOKEN,),
    )
    with pytest.raises(ProxyValidationError, match="public and also carries bearer"):
        render_conf(_spec(service))


def test_public_on_one_door_leaves_the_other_guarded():
    """Split horizon, the case the model was built for: open outside, named inside."""
    service = _public_site(
        exposure=Exposure.BOTH,
        internal_hostname="site.example.com",
        authenticators=(
            Authenticator(AuthKind.PUBLIC, Scope.EXTERNAL),
            _peer_auth(),
        ),
    )
    conf = render_conf(_spec(service))
    assert PEER_SET in conf


def test_a_tcp_service_may_be_public():
    """PUBLIC reads nothing, so passthrough carries it honestly."""
    service = _service(
        slug="game",
        kind=ServiceKind.TCP,
        exposure=Exposure.EXTERNAL,
        internal_hostname=None,
        listen_port=25565,
        authenticators=(Authenticator(AuthKind.PUBLIC, Scope.EXTERNAL),),
    )
    conf = render_conf(_spec(service))
    assert "tcp-request content reject" not in conf


# --------------------------------------------------------------------------- #
# the admin dashboard vhost
# --------------------------------------------------------------------------- #


def _with_dashboard(*services, **kwargs):
    kwargs.setdefault("dashboard_hostname", "admin.example.com")
    kwargs.setdefault("dashboard_address", "10.88.0.1")
    return _spec(*services, **kwargs)


def test_the_dashboard_is_not_published_unless_asked():
    conf = render_conf(_spec(_service()))
    assert "be_fg_dashboard" not in conf


def test_the_dashboard_answers_on_the_tunnel_door_only():
    """The whole security argument for adding no authenticator to that vhost."""
    service = _service(
        exposure=Exposure.BOTH,
        external_hostname="app.example.com",
        authenticators=(_peer_auth(), Authenticator(AuthKind.BEARER, Scope.EXTERNAL)),
        token_hashes=(TOKEN,),
    )
    conf = render_conf(_with_dashboard(service))
    # The external frontend is rendered first, so slice on the internal one
    # rather than assuming an order.
    external, internal = conf.split("frontend fg_int_https", 1)
    assert "frontend fg_ext_https" in external
    assert "h_fg_dashboard" in internal
    assert "h_fg_dashboard" not in external


def test_publishing_only_the_dashboard_still_builds_an_internal_frontend():
    """A deployment whose only published thing is the dashboard.

    ``has_internal`` used to be "any service exposed internally", so this
    rendered a name with no listener behind it.
    """
    conf = render_conf(_with_dashboard())
    assert "frontend fg_int_https" in conf
    assert "use_backend be_fg_dashboard if h_fg_dashboard" in conf
    assert "server s1 10.88.0.1:3000" in conf


def test_a_service_may_not_steal_the_dashboards_name():
    """The dashboard's use_backend is emitted first and would win every request."""
    service = _service(internal_hostname="admin.example.com")
    with pytest.raises(ProxyValidationError, match="the admin dashboard"):
        render_conf(_with_dashboard(service))


def test_the_dashboard_may_not_take_the_sign_in_name():
    spec = _with_dashboard(
        _service(authenticators=(Authenticator(AuthKind.FOXGUARD_SSO, Scope.INTERNAL),)),
        dashboard_hostname="auth.example.com",
        sso_secret="s" * 32,
        sso_hostname="auth.example.com",
    )
    with pytest.raises(ProxyValidationError, match="both the dashboard and the sign-in"):
        render_conf(spec)


def test_the_dashboard_may_not_point_at_the_proxy_itself():
    """Same trap `forbidden_upstream` catches for ordinary services."""
    with pytest.raises(ProxyValidationError, match="forward to itself"):
        render_conf(_with_dashboard(dashboard_port=443))


def test_the_sign_in_backend_follows_a_relocated_control_plane():
    """The portal and the admin API are one listener, so moving one moves both.

    Without this the sign-in vhost kept dialling the address the API used to be
    on, and every redirect to the login page ended in a 503 that looked like an
    SSO fault rather than a moved listener.
    """
    spec = _spec(
        _service(authenticators=(Authenticator(AuthKind.FOXGUARD_SSO, Scope.INTERNAL),)),
        sso_secret="s" * 32,
        sso_hostname="auth.example.com",
        sso_api_address="10.88.0.254",
        sso_api_port=443,
        sso_api_tls=True,
    )
    conf = render_conf(spec)
    assert "server s1 10.88.0.254:443 ssl verify none" in conf


def test_the_sign_in_backend_still_defaults_to_the_internal_bind():
    spec = _spec(
        _service(authenticators=(Authenticator(AuthKind.FOXGUARD_SSO, Scope.INTERNAL),)),
        sso_secret="s" * 32,
        sso_hostname="auth.example.com",
    )
    conf = render_conf(spec)
    assert "server s1 10.88.0.1:8080" in conf
    assert "ssl verify none" not in conf
