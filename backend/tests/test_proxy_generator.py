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


@pytest.mark.parametrize(
    "kind", [FilterKind.GEO_ALLOW, FilterKind.GEO_DENY, FilterKind.CROWDSEC]
)
def test_unimplemented_filters_are_refused_rather_than_ignored(kind):
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
