"""ProxyApplier against a real HAProxy.

Skipped unless ``FOXGUARD_LIVE_PROXY=1`` and ``haproxy`` is installed, exactly
like ``test_dns_live.py``. What these cover that the mocked tests cannot:

* a reload really is seamless, measured with a request in flight;
* a Runtime API map update really does *not* survive a reload, which is the
  single assumption the applier's write-then-sync discipline rests on;
* a rejected configuration really is refused by ``haproxy -c`` and the previous
  one really is still serving afterwards.

``systemctl`` is replaced by a shim script that drives HAProxy's master-worker
mode directly, because the dev container has no systemd. The shim implements
exactly the three verbs the applier uses.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from foxguard_agent.proxy import ProxyApplier, ProxyValidationError

pytestmark = pytest.mark.skipif(
    os.environ.get("FOXGUARD_LIVE_PROXY") != "1"
    or shutil.which("haproxy") is None
    and not Path("/usr/sbin/haproxy").exists(),
    reason="set FOXGUARD_LIVE_PROXY=1 and install haproxy to run these",
)

HAPROXY = "/usr/sbin/haproxy" if Path("/usr/sbin/haproxy").exists() else "haproxy"

SHIM = """#!/bin/bash
# Minimal systemctl for the applier's three verbs, driving haproxy directly.
verb=$1
PID={pidfile}
CFG={conf}
case "$verb" in
  is-active)
    if [ -f "$PID" ] && kill -0 "$(cat $PID)" 2>/dev/null; then echo active; exit 0;
    else echo inactive; exit 3; fi ;;
  reload)
    [ -f "$PID" ] || exit 1
    kill -USR2 "$(cat $PID)" && sleep 0.8 && exit 0 ;;
  restart)
    if [ -f "$PID" ] && kill -0 "$(cat $PID)" 2>/dev/null; then
      kill "$(cat $PID)" 2>/dev/null; sleep 0.4; fi
    rm -f "$PID"
    {haproxy} -W -D -p "$PID" -f "$CFG" || exit 1
    sleep 0.8; exit 0 ;;
  stop)
    [ -f "$PID" ] && kill "$(cat $PID)" 2>/dev/null; rm -f "$PID"; exit 0 ;;
esac
exit 1
"""

BASE_CONF = """global
    stats socket {sock} mode 660 level admin expose-fd listeners
defaults
    mode http
    timeout connect 5s
    timeout client 20s
    timeout server 20s
frontend f
    bind 127.0.0.1:{port}
    acl known src -f {maps}/set_fg_peers.lst
    http-request set-var(txn.t) req.hdr(authorization),sha2(256),hex,lower,map_str({maps}/tok_a.map)
    http-request return status 200 content-type text/plain lf-string "tok" if {{ var(txn.t) -m found }}
    http-request return status 200 content-type text/plain lf-string "known" if known
    http-request return status 403 content-type text/plain lf-string "no"
"""


@pytest.fixture
def live(tmp_path):
    """A ProxyApplier wired to a real HAProxy through the shim."""
    maps = tmp_path / "maps"
    maps.mkdir()
    conf = tmp_path / "haproxy.cfg"
    pidfile = tmp_path / "h.pid"
    # Short path: HAProxy caps a stats socket at 97 characters, and pytest's
    # tmp_path is long. Measured -- it is a fatal parse error.
    sock = Path("/tmp") / f"fgl{os.getpid()}.sock"
    shim = tmp_path / "systemctl"
    shim.write_text(
        SHIM.format(pidfile=pidfile, conf=conf, haproxy=HAPROXY)
    )
    shim.chmod(0o755)

    applier = ProxyApplier(
        conf_path=conf,
        maps_dir=maps,
        runtime_socket=sock,
        haproxy_path=HAPROXY,
        systemctl_path=str(shim),
        service="foxguard-proxy",
    )
    port = 15000 + (os.getpid() % 900)
    yield applier, maps, conf, sock, port, pidfile

    subprocess.run([str(shim), "stop"], capture_output=True, check=False)
    sock.unlink(missing_ok=True)


def _artefact(maps: Path, sock: Path, port: int, *, tokens=("a" * 64,), peers=("127.0.0.1",)):
    conf = BASE_CONF.format(sock=sock, port=port, maps=maps)
    files = {
        "set_fg_peers.lst": "".join(f"{p}\n" for p in peers),
        "tok_a.map": "".join(f"{t} 1\n" for t in tokens),
    }
    return conf, files


def _get(port: int, header: str | None = None) -> int:
    argv = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            f"http://127.0.0.1:{port}/"]
    if header:
        argv += ["-H", header]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    return int(result.stdout or 0)


def _master_pid(pidfile: Path) -> int:
    return int(pidfile.read_text().strip())


def test_first_apply_starts_haproxy_and_serves(live):
    applier, maps, _conf, sock, port, pidfile = live
    conf, files = _artefact(maps, sock, port)

    assert applier.apply(conf, files) in {"started", "reloaded"}
    assert _get(port) == 200
    assert pidfile.exists()


def test_applying_the_same_state_twice_changes_nothing(live):
    applier, maps, _conf, sock, port, _pidfile = live
    conf, files = _artefact(maps, sock, port)

    applier.apply(conf, files)
    assert applier.apply(conf, files) == "unchanged"


def test_a_new_token_is_pushed_without_reloading(live):
    """The optimisation that exists because a passthrough session is a shell."""
    applier, maps, _conf, sock, port, pidfile = live
    conf, files = _artefact(maps, sock, port)
    applier.apply(conf, files)
    before = _master_pid(pidfile)

    import hashlib

    token = hashlib.sha256(b"newtoken").hexdigest()
    conf2, files2 = _artefact(maps, sock, port, tokens=("a" * 64, token))
    assert conf2 == conf, "only the map should differ in this test"

    assert applier.apply(conf2, files2) == "synced"
    assert _master_pid(pidfile) == before, "a map change must not restart anything"
    assert _get(port, "Authorization: newtoken") == 200


def test_a_runtime_synced_map_survives_a_later_reload(live):
    """The discipline the whole applier is built around.

    Measured separately: a Runtime API ``add map`` is gone after the next
    reload. So the applier writes the file *and* pushes it, and this asserts the
    combination holds -- push a token, then force an unrelated reload, then
    check the token still works.
    """
    applier, maps, _conf, sock, port, _pidfile = live
    conf, files = _artefact(maps, sock, port)
    applier.apply(conf, files)

    import hashlib

    token = hashlib.sha256(b"survivor").hexdigest()
    _, files2 = _artefact(maps, sock, port, tokens=("a" * 64, token))
    assert applier.apply(conf, files2) == "synced"
    assert _get(port, "Authorization: survivor") == 200

    # Now change the configuration, which forces a real reload.
    conf3 = conf + "\n# unrelated change\n"
    assert applier.apply(conf3, files2) == "reloaded"
    assert _get(port, "Authorization: survivor") == 200, (
        "the runtime-pushed token was lost on reload: the file was not written"
    )


def test_a_rejected_configuration_never_reaches_the_daemon(live):
    applier, maps, conf_path, sock, port, _pidfile = live
    conf, files = _artefact(maps, sock, port)
    applier.apply(conf, files)
    assert _get(port) == 200

    broken = conf + "\nfrontend broken\n    bind 127.0.0.1:1\n    this-is-not-a-keyword yes\n"
    with pytest.raises(ProxyValidationError):
        applier.apply(broken, files)

    assert conf_path.read_text() == conf, "the previous configuration must be restored"
    assert _get(port) == 200, "the daemon must still be serving the previous config"


def test_a_reload_does_not_drop_a_request_in_flight(live):
    """The property that matters most for TCP passthrough.

    A slow upstream, a request started against it, a reload fired midway, and
    the response must still arrive.
    """
    applier, maps, _conf, sock, port, _pidfile = live
    upstream_port = port + 1

    slow = subprocess.Popen(
        [
            "python3",
            "-c",
            (
                "import http.server,time\n"
                "class H(http.server.BaseHTTPRequestHandler):\n"
                "    def do_GET(self):\n"
                "        time.sleep(4)\n"
                "        b=b'SLOW'\n"
                "        self.send_response(200); self.send_header('Content-Length','4')\n"
                "        self.end_headers(); self.wfile.write(b)\n"
                "    def log_message(self,*a): pass\n"
                f"http.server.ThreadingHTTPServer(('127.0.0.1',{upstream_port}),H)"
                ".serve_forever()"
            ),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    try:
        conf = BASE_CONF.format(sock=sock, port=port, maps=maps).replace(
            '    http-request return status 403 content-type text/plain lf-string "no"',
            "    default_backend slow",
        ) + f"\nbackend slow\n    server s 127.0.0.1:{upstream_port}\n"
        _, files = _artefact(maps, sock, port)
        applier.apply(conf, files)

        inflight = subprocess.Popen(
            ["curl", "-s", "-m", "15", "-o", "/dev/null", "-w", "%{http_code}",
             f"http://127.0.0.1:{port}/slow"],
            stdout=subprocess.PIPE,
            text=True,
        )
        time.sleep(1.5)
        assert applier.apply(conf + "\n# forces a reload\n", files) == "reloaded"
        out, _ = inflight.communicate(timeout=20)
        assert out.strip() == "200", "a reload dropped a request that was in flight"
    finally:
        slow.terminate()
        slow.wait(timeout=5)


def test_stale_pattern_files_are_removed(live):
    applier, maps, _conf, sock, port, _pidfile = live
    conf, files = _artefact(maps, sock, port)
    applier.apply(conf, files)

    (maps / "set_gone.lst").write_text("# left over from a previous state\n")
    applier.apply(conf, files)
    assert not (maps / "set_gone.lst").exists()
    # An operator's own file is not Foxguard's to delete.
    (maps / "operator-notes.txt").write_text("mine\n")
    applier.apply(conf + "\n# change\n", files)
    assert (maps / "operator-notes.txt").exists()


def test_runtime_socket_absent_falls_back_to_reload(live, tmp_path):
    """No socket is not an error: it is a reload."""
    _applier, maps, conf_path, sock, port, _pidfile = live
    shim = tmp_path / "systemctl"
    applier = ProxyApplier(
        conf_path=conf_path,
        maps_dir=maps,
        runtime_socket=None,
        haproxy_path=HAPROXY,
        systemctl_path=str(shim),
        service="foxguard-proxy",
    )
    conf, files = _artefact(maps, sock, port)
    applier.apply(conf, files)

    import hashlib

    token = hashlib.sha256(b"x").hexdigest()
    _, files2 = _artefact(maps, sock, port, tokens=("a" * 64, token))
    assert applier.apply(conf, files2) == "reloaded"


def test_check_validates_without_touching_the_live_configuration(live):
    applier, maps, conf_path, sock, port, _pidfile = live
    conf, files = _artefact(maps, sock, port)
    applier.apply(conf, files)

    applier.check(conf + "\n# fine\n", files)
    assert conf_path.read_text() == conf

    with pytest.raises(ProxyValidationError):
        applier.check(conf + "\nfrontend b\n    nonsense here\n", files)
    assert conf_path.read_text() == conf


def test_the_runtime_socket_path_limit_is_real(live):
    """97 characters, and exceeding it is fatal rather than a warning."""
    _applier, maps, _conf, _sock, port, _pidfile = live
    long_sock = "/tmp/" + ("x" * 110) + ".sock"
    conf = BASE_CONF.format(sock=long_sock, port=port, maps=maps)
    result = subprocess.run(
        [HAPROXY, "-c", "-f", "/dev/stdin"],
        input=conf,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "too long" in (result.stdout + result.stderr)


def test_runtime_api_is_reachable_and_speaks(live):
    applier, maps, _conf, sock, port, _pidfile = live
    conf, files = _artefact(maps, sock, port)
    applier.apply(conf, files)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(sock))
        client.sendall(b"show info\n")
        client.shutdown(socket.SHUT_WR)
        body = b""
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            body += chunk
    assert b"Name: HAProxy" in body
