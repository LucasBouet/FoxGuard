"""A rendered SSO service, running in real HAProxy, under attack.

Skipped unless ``FOXGUARD_LIVE_PROXY=1`` and HAProxy is installed. These are the
tests that justify the shape of ``_sso_setup``: every line it emits is there
because one of these fails without it.

The one that matters most is ``test_an_alg_none_forgery_is_refused``. HAProxy's
``jwt_verify`` returns **1** for a completely unsigned token when the algorithm
is read from the token's own header, which is how the idiomatic snippet is
written. Foxguard pins the algorithm instead, and this is what holds that in
place.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest
from joserfc import jwt
from joserfc.jwk import OctKey

from foxguard.proxy import (
    AccessAction,
    AccessRule,
    Authenticator,
    AuthKind,
    Backend,
    Exposure,
    PeerIdentity,
    ProxySpec,
    Scope,
    Service,
    ServiceKind,
    SourceSet,
    render_conf,
    render_files,
)
from foxguard.proxy.haproxy import PEER_SET

HAPROXY = "/usr/sbin/haproxy" if Path("/usr/sbin/haproxy").exists() else "haproxy"

pytestmark = pytest.mark.skipif(
    os.environ.get("FOXGUARD_LIVE_PROXY") != "1"
    or (shutil.which("haproxy") is None and not Path("/usr/sbin/haproxy").exists()),
    reason="set FOXGUARD_LIVE_PROXY=1 and install haproxy to run these",
)

SECRET = "s" * 32
REVOKED_JTI = "11111111-1111-1111-1111-111111111111"


def _token(
    *,
    jti: str | None = None,
    sub="alice",
    offset=3600,
    key=SECRET,
    alg="HS256",
    groups=",",
    admin=1,
):
    now = int(time.time())
    claims = {
        "sub": sub,
        "jti": jti or str(uuid.uuid4()),
        "exp": now + offset,
        "iat": now,
        "admin": admin,
        "groups": groups,
    }
    if alg == "none":
        # The classic forgery: no signature, and the token asks to be trusted.
        def enc(payload):
            return (
                base64.urlsafe_b64encode(json.dumps(payload).encode())
                .decode()
                .rstrip("=")
            )

        return f"{enc({'alg': 'none', 'typ': 'JWT'})}.{enc(claims)}."
    return jwt.encode({"alg": alg, "typ": "JWT"}, claims, OctKey.import_key(key))


@pytest.fixture(scope="module")
def sso_proxy(tmp_path_factory):
    """A real HAProxy serving one SSO-protected service."""
    out = tmp_path_factory.mktemp("sso")
    base = 15000 + (os.getpid() % 700)
    https_port, api_port, upstream_port = base, base + 1, base + 2

    spec = ProxySpec(
        domain="example.com",
        external_binds=("127.0.0.1",),
        external_https_port=https_port,
        external_http_port=base + 3,
        certs_dir=str(out / "certs"),
        maps_dir=str(out / "maps"),
        runtime_socket=f"/tmp/fgssot{os.getpid()}.sock",
        sso_secret=SECRET,
        sso_hostname="auth.example.com",
        sso_cookie_domain="example.com",
        sso_api_port=api_port,
        sso_revoked=(REVOKED_JTI,),
        peers=(PeerIdentity("127.0.0.1", "laptop", ()),),
        source_sets=(SourceSet(PEER_SET, ("127.0.0.1",)),),
        services=(
            Service(
                slug="wiki",
                kind=ServiceKind.HTTP,
                exposure=Exposure.EXTERNAL,
                backend=Backend("127.0.0.1", upstream_port, peer_label="nas"),
                external_hostname="wiki.example.com",
                authenticators=(Authenticator(AuthKind.FOXGUARD_SSO, Scope.EXTERNAL),),
                access=(AccessRule(AccessAction.ALLOW, None),),
            ),
            # The same service, narrowed three different ways. Separate
            # hostnames rather than separate fixtures: one HAProxy, one set of
            # measurements, and the "no requirement" case above stays the
            # control that proves the narrowing is what changed the answer.
            Service(
                slug="infra",
                kind=ServiceKind.HTTP,
                exposure=Exposure.EXTERNAL,
                backend=Backend("127.0.0.1", upstream_port, peer_label="nas"),
                external_hostname="infra.example.com",
                authenticators=(
                    Authenticator(
                        AuthKind.FOXGUARD_SSO, Scope.EXTERNAL, groups=("infra", "ops")
                    ),
                ),
                access=(AccessRule(AccessAction.ALLOW, None),),
            ),
            Service(
                slug="panel",
                kind=ServiceKind.HTTP,
                exposure=Exposure.EXTERNAL,
                backend=Backend("127.0.0.1", upstream_port, peer_label="nas"),
                external_hostname="panel.example.com",
                authenticators=(
                    Authenticator(
                        AuthKind.FOXGUARD_SSO, Scope.EXTERNAL, require_admin=True
                    ),
                ),
                access=(AccessRule(AccessAction.ALLOW, None),),
            ),
            Service(
                slug="vault",
                kind=ServiceKind.HTTP,
                exposure=Exposure.EXTERNAL,
                backend=Backend("127.0.0.1", upstream_port, peer_label="nas"),
                external_hostname="vault.example.com",
                authenticators=(
                    Authenticator(
                        AuthKind.FOXGUARD_SSO,
                        Scope.EXTERNAL,
                        groups=("infra",),
                        require_admin=True,
                    ),
                ),
                access=(AccessRule(AccessAction.ALLOW, None),),
            ),
        ),
    )

    (out / "maps").mkdir()
    (out / "certs").mkdir()
    for name, body in render_files(spec).items():
        (out / "maps" / name).write_text(body)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(out / "k"),
         "-out", str(out / "c"), "-days", "2", "-nodes", "-subj", "/CN=example.com",
         "-addext", "subjectAltName=DNS:*.example.com"],
        check=True, capture_output=True,
    )
    (out / "certs" / "s.pem").write_text(
        (out / "c").read_text() + (out / "k").read_text()
    )
    cfg = out / "haproxy.cfg"
    cfg.write_text(render_conf(spec))

    # An upstream that reports back whatever identity the proxy gave it.
    upstream = out / "up.py"
    upstream.write_text(
        "import http.server,json\n"
        "class H(http.server.BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        b=json.dumps({k.lower():v for k,v in self.headers.items()"
        " if k.lower().startswith('x-foxguard')},sort_keys=True).encode()\n"
        "        self.send_response(200); self.send_header('Content-Length',str(len(b)))\n"
        "        self.end_headers(); self.wfile.write(b)\n"
        "    def log_message(self,*a): pass\n"
        f"http.server.ThreadingHTTPServer(('127.0.0.1',{upstream_port}),H).serve_forever()\n"
    )
    server = subprocess.Popen(
        ["python3", str(upstream)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    subprocess.run(
        [HAPROXY, "-W", "-D", "-p", str(out / "h.pid"), "-f", str(cfg)],
        capture_output=True, check=True,
    )
    time.sleep(1)

    yield https_port

    subprocess.run(["kill", (out / "h.pid").read_text().strip()], check=False)
    server.terminate()
    server.wait(timeout=5)
    Path(spec.runtime_socket).unlink(missing_ok=True)


HOSTS = ("wiki", "infra", "panel", "vault", "auth")


def _resolve(port: int) -> list[str]:
    return [
        arg
        for host in HOSTS
        for arg in ("--resolve", f"{host}.example.com:{port}:127.0.0.1")
    ]


def _curl(port: int, *extra: str, host="wiki.example.com", path="/"):
    argv = [
        "curl", "-s", "-k", *_resolve(port),
        "-o", "/dev/null", "-w", "%{http_code}",
        *extra,
        f"https://{host}:{port}{path}",
    ]
    return subprocess.run(argv, capture_output=True, text=True, check=False).stdout.strip()


def _body(port: int, *extra: str, host="wiki.example.com"):
    argv = [
        "curl", "-s", "-k", *_resolve(port),
        *extra, f"https://{host}:{port}/",
    ]
    return subprocess.run(argv, capture_output=True, text=True, check=False).stdout.strip()


def test_a_valid_session_gets_in(sso_proxy):
    assert _curl(sso_proxy, "-b", f"fg_sso={_token()}") == "200"


def test_no_cookie_is_sent_to_sign_in(sso_proxy):
    assert _curl(sso_proxy) == "302"


def test_an_expired_session_is_sent_back(sso_proxy):
    """``jwt_verify`` ignores ``exp`` entirely -- the renderer compares it itself."""
    assert _curl(sso_proxy, "-b", f"fg_sso={_token(offset=-60)}") == "302"


def test_a_token_signed_with_another_key_is_refused(sso_proxy):
    assert _curl(sso_proxy, "-b", f"fg_sso={_token(key='x' * 32)}") == "302"


def test_an_alg_none_forgery_is_refused(sso_proxy):
    """The reason the algorithm is pinned rather than read from the token.

    Measured on HAProxy 3.0.11: with ``jwt_verify(<alg from the token>, ...)``
    this exact token verifies as 1 and the caller is admitted with claims it
    wrote itself.
    """
    assert _curl(sso_proxy, "-b", f"fg_sso={_token(alg='none')}") == "302"


def test_a_revoked_session_is_refused(sso_proxy):
    """Its signature is perfect; the denylist map is what stops it."""
    assert _curl(sso_proxy, "-b", f"fg_sso={_token(jti=REVOKED_JTI)}") == "302"


def test_garbage_in_the_cookie_is_refused(sso_proxy):
    assert _curl(sso_proxy, "-b", "fg_sso=not-a-jwt") == "302"


def test_the_identity_header_comes_from_the_verified_claim(sso_proxy):
    body = _body(sso_proxy, "-b", f"fg_sso={_token(sub='alice')}")
    assert json.loads(body) == {"x-foxguard-user": "alice"}


def test_a_forged_identity_header_is_overwritten(sso_proxy):
    body = _body(
        sso_proxy,
        "-b", f"fg_sso={_token(sub='alice')}",
        "-H", "X-Foxguard-User: root",
    )
    assert json.loads(body) == {"x-foxguard-user": "alice"}


# --------------------------------------------------------------------------- #
# Authorisation: signing in is not the same as being allowed in
# --------------------------------------------------------------------------- #


def test_a_service_with_no_requirement_admits_any_account(sso_proxy):
    """The control for everything below: ``wiki`` asks for nothing."""
    assert _curl(sso_proxy, "-b", f"fg_sso={_token(groups=',')}") == "200"


@pytest.mark.parametrize("groups", [",infra,", ",ops,", ",sales,ops,"])
def test_a_member_of_a_required_group_gets_in(sso_proxy, groups):
    assert _curl(
        sso_proxy, "-b", f"fg_sso={_token(groups=groups)}", host="infra.example.com"
    ) == "200"


@pytest.mark.parametrize(
    "groups",
    [
        ",",  # in nothing at all
        ",sales,",  # in the wrong group
        ",inf,",  # a prefix of a required one
        ",infrastructure,",  # a required one is a prefix of this
    ],
)
def test_a_stranger_is_refused_and_not_sent_round_the_loop(sso_proxy, groups):
    """403, never 302.

    A redirect here would send a browser that already holds a valid cookie to a
    login page, which would sign it in, hand back the very same cookie, and
    bounce it straight back -- a loop nothing on the client can break, and one
    that reads as the service being broken rather than forbidden.

    The two near-miss slugs are the delimiters earning their keep: measured on
    HAProxy 3.0.11, an unwrapped ``-m sub infra`` admits ``infrastructure``.
    """
    assert _curl(
        sso_proxy, "-b", f"fg_sso={_token(groups=groups)}", host="infra.example.com"
    ) == "403"


def test_the_refusal_names_the_account_and_what_it_lacks(sso_proxy):
    body = _body(
        sso_proxy,
        "-b", f"fg_sso={_token(sub='alice', groups=',sales,')}",
        host="infra.example.com",
    )
    assert "alice" in body
    assert "infra, ops" in body


def test_no_cookie_still_goes_to_the_login_page(sso_proxy):
    """The refusal above must not have swallowed the redirect."""
    assert _curl(sso_proxy, host="infra.example.com") == "302"


def test_an_expired_session_goes_to_the_login_page_not_a_refusal(sso_proxy):
    """Its groups are irrelevant: it is not a session any more."""
    assert _curl(
        sso_proxy,
        "-b", f"fg_sso={_token(groups=',infra,', offset=-60)}",
        host="infra.example.com",
    ) == "302"


def test_the_admin_flag_does_not_bypass_a_group(sso_proxy):
    assert _curl(
        sso_proxy,
        "-b", f"fg_sso={_token(groups=',sales,', admin=1)}",
        host="infra.example.com",
    ) == "403"


def test_admin_only_admits_an_administrator(sso_proxy):
    assert _curl(
        sso_proxy, "-b", f"fg_sso={_token(admin=1)}", host="panel.example.com"
    ) == "200"


def test_admin_only_refuses_everyone_else(sso_proxy):
    assert _curl(
        sso_proxy,
        "-b", f"fg_sso={_token(admin=0, groups=',infra,')}",
        host="panel.example.com",
    ) == "403"


@pytest.mark.parametrize(
    ("groups", "admin", "expected"),
    [
        (",infra,", 1, "200"),
        (",infra,", 0, "403"),  # the group without the flag
        (",", 1, "403"),  # the flag without the group
    ],
)
def test_a_group_and_admin_are_required_together(sso_proxy, groups, admin, expected):
    """AND, not OR. Either half alone is a refusal."""
    assert _curl(
        sso_proxy,
        "-b", f"fg_sso={_token(groups=groups, admin=admin)}",
        host="vault.example.com",
    ) == expected


def test_a_forged_membership_is_worth_nothing(sso_proxy):
    """The claim is only as good as the signature over it.

    302 rather than 403: the token never became a session, so the caller is
    unauthenticated rather than unauthorised, and being sent to sign in is the
    correct answer.
    """
    forged = _token(groups=",infra,", admin=1, key="x" * 32)
    assert _curl(sso_proxy, "-b", f"fg_sso={forged}", host="vault.example.com") == "302"


def test_an_alg_none_forgery_cannot_grant_itself_a_group(sso_proxy):
    assert _curl(
        sso_proxy,
        "-b", f"fg_sso={_token(groups=',infra,', alg='none')}",
        host="vault.example.com",
    ) == "302"


def _who_answered(port: int, path: str) -> str:
    """HAProxy itself, or something behind it?

    Worth distinguishing: an upstream 404 and a proxy 404 look identical to a
    status-code assertion, and only one of them means the path was refused.
    """
    argv = [
        "curl", "-s", "-k", "--resolve", f"auth.example.com:{port}:127.0.0.1",
        "-D-", "-o", "/dev/null", f"https://auth.example.com:{port}{path}",
    ]
    out = subprocess.run(argv, capture_output=True, text=True, check=False).stdout
    code = out.splitlines()[0].split()[1] if out else "?"
    from_upstream = any(line.lower().startswith("server:") for line in out.splitlines())
    return f"{code}/{'upstream' if from_upstream else 'haproxy'}"


def test_the_login_path_is_routed_to_the_api(sso_proxy):
    # Nothing listens on the API port in this fixture, so a routed request
    # reaches HAProxy's own 503 -- which is how routing is told from refusal.
    assert _who_answered(sso_proxy, "/api/v1/sso/login") == "503/haproxy"


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/peers",
        "/api/v1/killswitch",
        "/api/v1/portal/status",
        "/api/v1/enroll",
        "/api/v1/agent/state",
        "/",
    ],
)
def test_nothing_else_on_the_auth_host_reaches_the_api(sso_proxy, path):
    """The vhost exists to serve a login page, not to publish the control plane.

    The portal and enrollment entries matter most: they identify their caller by
    source address, and a proxy in front of them destroys that identity.
    """
    assert _who_answered(sso_proxy, path) == "404/haproxy"
