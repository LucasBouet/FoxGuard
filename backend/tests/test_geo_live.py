"""A rendered geo filter, in real HAProxy, asked from real addresses.

Skipped unless ``FOXGUARD_LIVE_PROXY=1`` and HAProxy is installed.

What only a live test can settle: ``map_ip`` is a longest-prefix matcher over a
file the renderer never sees, so "the condition looks right" and "the condition
decides right" are different claims. These source requests from several loopback
addresses, each placed in a different country by the map, and check who gets in.

The measurements that shaped the design are recorded in
``foxguard_agent.geo``; this file only proves the result behaves.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from foxguard.proxy import (
    AccessAction,
    AccessRule,
    Authenticator,
    AuthKind,
    Backend,
    Exposure,
    Filter,
    FilterKind,
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

#: Loopback addresses, and where the map says each of them is. 127.0.0.5 is in
#: no country at all -- the case that decides what a partial map means.
WHERE = {
    "127.0.0.1": "FR",
    "127.0.0.2": "CH",
    "127.0.0.3": "CN",
    "127.0.0.4": "RU",
    "127.0.0.5": None,
}


def _service(slug, hostname, kind, countries):
    return Service(
        slug=slug,
        kind=ServiceKind.HTTP,
        exposure=Exposure.INTERNAL,
        backend=Backend("127.0.0.1", _UPSTREAM, peer_label="nas"),
        internal_hostname=hostname,
        authenticators=(Authenticator(AuthKind.PEER_IDENTITY, Scope.INTERNAL),),
        filters=(Filter(kind, Scope.INTERNAL, values=countries),),
        access=(AccessRule(AccessAction.ALLOW, None),),
    )


_BASE = 15900 + (os.getpid() % 300)
_UPSTREAM = _BASE + 1


@pytest.fixture(scope="module")
def geo_proxy(tmp_path_factory):
    out = tmp_path_factory.mktemp("geo")
    spec = ProxySpec(
        domain="example.com",
        internal_binds=("127.0.0.1",),
        internal_https_port=_BASE,
        certs_dir=str(out / "certs"),
        maps_dir=str(out / "maps"),
        runtime_socket=f"/tmp/fggeo{os.getpid()}.sock",
        peers=tuple(PeerIdentity(a, f"p{i}", ()) for i, a in enumerate(WHERE)),
        source_sets=(SourceSet(PEER_SET, tuple(WHERE)),),
        services=(
            _service("only", "only.example.com", FilterKind.GEO_ALLOW, ("FR", "CH")),
            _service("never", "never.example.com", FilterKind.GEO_DENY, ("CN", "RU")),
        ),
    )

    (out / "maps").mkdir()
    (out / "certs").mkdir()
    for name, body in render_files(spec).items():
        (out / "maps" / name).write_text(body)
    # What the gateway's GeoBuilder would have produced, in miniature.
    (out / "maps" / spec.geo_map).write_text(
        "# Foxguard generated -- DO NOT EDIT BY HAND.\n"
        + "".join(f"{a}/32 {cc}\n" for a, cc in WHERE.items() if cc)
    )

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

    upstream = out / "up.py"
    upstream.write_text(
        "import http.server\n"
        "class H(http.server.BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        self.send_response(200); self.send_header('Content-Length','2')\n"
        "        self.end_headers(); self.wfile.write(b'ok')\n"
        "    def log_message(self,*a): pass\n"
        f"http.server.ThreadingHTTPServer(('127.0.0.1',{_UPSTREAM}),H).serve_forever()\n"
    )
    server = subprocess.Popen(
        ["python3", str(upstream)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(1)
    subprocess.run(
        [HAPROXY, "-W", "-D", "-p", str(out / "h.pid"), "-f", str(cfg)],
        capture_output=True, check=True,
    )
    time.sleep(1)

    yield _BASE

    subprocess.run(["kill", (out / "h.pid").read_text().strip()], check=False)
    server.terminate()
    server.wait(timeout=5)
    Path(spec.runtime_socket).unlink(missing_ok=True)


def _hit(port: int, host: str, source: str) -> str:
    argv = [
        "curl", "-s", "-k", "--interface", source,
        "--resolve", f"{host}:{port}:127.0.0.1",
        "-o", "/dev/null", "-w", "%{http_code}",
        f"https://{host}:{port}/",
    ]
    return subprocess.run(argv, capture_output=True, text=True, check=False).stdout.strip()


@pytest.mark.parametrize("source", ["127.0.0.1", "127.0.0.2"])
def test_an_allow_list_admits_the_countries_it_names(geo_proxy, source):
    assert _hit(geo_proxy, "only.example.com", source) == "200"


@pytest.mark.parametrize("source", ["127.0.0.3", "127.0.0.4"])
def test_an_allow_list_refuses_every_other_country(geo_proxy, source):
    assert _hit(geo_proxy, "only.example.com", source) == "403"


def test_an_allow_list_refuses_an_address_the_map_does_not_cover(geo_proxy):
    """The half of "a partial map is correct" that an allow list depends on.

    The gateway builds a map holding only the countries somebody named -- the
    whole world costs 367 MiB of HAProxy memory and the useful subset costs 47 --
    so most of the internet is simply absent from it. An allow list must treat
    absent as "not one of mine".
    """
    assert _hit(geo_proxy, "only.example.com", "127.0.0.5") == "403"


@pytest.mark.parametrize("source", ["127.0.0.3", "127.0.0.4"])
def test_a_deny_list_refuses_the_countries_it_names(geo_proxy, source):
    assert _hit(geo_proxy, "never.example.com", source) == "403"


def test_a_deny_list_admits_a_country_it_does_not_name(geo_proxy):
    assert _hit(geo_proxy, "never.example.com", "127.0.0.1") == "200"


def test_a_deny_list_admits_an_address_the_map_does_not_cover(geo_proxy):
    """And the other half: absent means "not one of the banned ones"."""
    assert _hit(geo_proxy, "never.example.com", "127.0.0.5") == "200"
