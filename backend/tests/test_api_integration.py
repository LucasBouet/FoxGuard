"""End-to-end tests against a running API.

Opt-in: set ``FOXGUARD_TEST_API_URL`` (and ``FOXGUARD_TEST_API_TOKEN`` if the
server is not in dev mode). Start a server first::

    FOXGUARD_DEV_MODE=true FOXGUARD_WAN_INTERFACE=eth0 \
      uvicorn foxguard.main:app --port 8000
    FOXGUARD_TEST_API_URL=http://127.0.0.1:8000 pytest tests/test_api_integration.py

Why these cannot be unit tests: they cover failures that only exist once a real
request cycle and a real database driver are involved --

* transaction visibility (committing in a ``yield`` dependency runs *after* the
  response is sent, so a read straight after a write saw stale data);
* response serialisation of real rows (psycopg returns ``INET`` columns as
  ``ipaddress`` objects, which a ``str``-annotated model rejects with a 500).

Both were live bugs. Neither was catchable without a server and PostgreSQL.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

httpx = pytest.importorskip("httpx")
pyotp = pytest.importorskip("pyotp")
jwt = pytest.importorskip("joserfc.jwt")
RSAKey = pytest.importorskip("joserfc.jwk").RSAKey

API_URL = os.environ.get("FOXGUARD_TEST_API_URL")
pytestmark = pytest.mark.skipif(
    not API_URL, reason="FOXGUARD_TEST_API_URL is not set; skipping API tests"
)


@pytest.fixture(scope="module")
def api():
    token = os.environ.get("FOXGUARD_TEST_API_TOKEN", "dev")
    with httpx.Client(
        base_url=API_URL, headers={"Authorization": f"Bearer {token}"}, timeout=30
    ) as client:
        response = client.get("/healthz")
        response.raise_for_status()
        yield client


@pytest.fixture()
def tag() -> str:
    """Unique suffix so tests do not collide with each other or with real data."""
    return secrets.token_hex(3)


def wg_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


def _group(api, tag: str, slug_prefix: str = "it", **extra) -> dict:
    slug = f"{slug_prefix}-{tag}"
    response = api.post("/api/v1/groups", json={"slug": slug, "name": slug, **extra})
    assert response.status_code == 201, response.text
    return response.json()


# --------------------------------------------------------------------------- #
# transaction visibility
# --------------------------------------------------------------------------- #


def test_a_write_is_visible_to_the_very_next_read(api, tag):
    """Regression: committing in the get_db teardown ran after the response.

    Every single create was invisible to the immediately following list call
    (measured 40/40). Any provisioning script or UI refresh hit it.
    """
    for index in range(5):
        slug = f"raw-{tag}-{index}"
        created = api.post("/api/v1/groups", json={"slug": slug, "name": slug})
        assert created.status_code == 201, created.text

        listed = {group["slug"] for group in api.get("/api/v1/groups").json()}
        assert slug in listed, f"group {slug} not visible right after creation"


def test_a_deletion_is_visible_to_the_very_next_read(api, tag):
    group = _group(api, tag, "del")
    assert api.delete(f"/api/v1/groups/{group['id']}").status_code == 204
    listed = {g["slug"] for g in api.get("/api/v1/groups").json()}
    assert group["slug"] not in listed


# --------------------------------------------------------------------------- #
# response serialisation of real rows
# --------------------------------------------------------------------------- #


def test_audit_log_serialises_inet_columns(api, tag):
    """Regression: psycopg returns INET as ipaddress objects -> 500 on response."""
    _group(api, tag, "audit")
    response = api.get("/api/v1/audit-log", params={"action": "group.create"})
    assert response.status_code == 200, response.text
    entries = response.json()
    assert entries
    for entry in entries:
        assert entry["source_ip"] is None or isinstance(entry["source_ip"], str)


def test_peer_addresses_serialise_as_strings(api, tag):
    peer = _create_peer(api, tag)
    assert isinstance(peer["tunnel_ip"], str)


# --------------------------------------------------------------------------- #
# peer lifecycle
# --------------------------------------------------------------------------- #


def _create_peer(api, tag: str, *, peer_type: str = "server", **extra) -> dict:
    response = api.post(
        "/api/v1/peers",
        json={
            "name": f"peer-{tag}",
            "peer_type": peer_type,
            "wg_public_key": wg_key(),
            **extra,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_a_new_peer_lands_in_staging(api, tag):
    """A registered public key on its own must grant nothing."""
    assert _create_peer(api, tag)["state"] == "staging"


def test_ipam_never_reuses_an_address(api, tag):
    addresses = {_create_peer(api, f"{tag}-{i}")["tunnel_ip"] for i in range(4)}
    assert len(addresses) == 4


def test_enrollment_key_is_shown_once_and_never_again(api, tag):
    peer = _create_peer(api, tag)
    created = api.post(f"/api/v1/peers/{peer['id']}/enrollment-key", json={})
    assert created.status_code == 201, created.text
    secret = created.json()["enrollment_key"]
    assert secret.startswith("fgk_")

    fetched = api.get(f"/api/v1/peers/{peer['id']}")
    assert fetched.status_code == 200
    assert secret not in fetched.text
    assert "enrollment_key" not in fetched.json()


def test_enrollment_keys_are_refused_on_user_peers(api, tag):
    user = api.post(
        "/api/v1/users",
        json={"username": f"u-{tag}", "password": "correct-horse-battery-staple"},
    )
    assert user.status_code == 201, user.text
    peer = _create_peer(api, tag, peer_type="user", owner_user_id=user.json()["id"])
    response = api.post(f"/api/v1/peers/{peer['id']}/enrollment-key", json={})
    assert response.status_code == 409


def test_revoking_a_key_quarantines_the_peer_immediately(api, tag):
    """Revocation that only applies "next time" is not revocation."""
    group = _group(api, tag, "revoke")
    peer = _create_peer(api, tag, group_slugs=[group["slug"]])
    api.post(f"/api/v1/peers/{peer['id']}/enrollment-key", json={})
    api.patch(f"/api/v1/peers/{peer['id']}", json={"state": "active"})

    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    set_name = "g_" + group["slug"].replace("-", "_") + "_v4"
    assert peer["tunnel_ip"] in _set_body(ruleset, set_name)

    revoked = api.delete(f"/api/v1/peers/{peer['id']}/enrollment-key")
    assert revoked.status_code == 200
    assert revoked.json()["state"] == "quarantined"

    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    assert peer["tunnel_ip"] not in _set_body(ruleset, set_name)
    assert peer["tunnel_ip"] in _set_body(ruleset, "fg_quarantine_v4")


def _set_body(ruleset: str, set_name: str) -> str:
    return ruleset.split(f"set {set_name} {{")[1].split("}")[0]


# --------------------------------------------------------------------------- #
# policy import
# --------------------------------------------------------------------------- #


def _document(tag: str) -> dict:
    return {
        "version": 1,
        "groups": [{"slug": f"src-{tag}", "name": "src"}, {"slug": f"dst-{tag}", "name": "dst"}],
        "acl_rules": [
            {
                "ref": f"rule-{tag}",
                "name": "src reaches dst",
                "action": "accept",
                "src_kind": "group",
                "src_group": f"src-{tag}",
                "dst_kind": "group",
                "dst_group": f"dst-{tag}",
                "protocol": "tcp",
                "dst_port_start": 5432,
            }
        ],
    }


def test_dry_run_reports_changes_without_making_them(api, tag):
    document = _document(tag)
    response = api.post("/api/v1/policies/import", json={"document": document, "dry_run": True})
    assert response.status_code == 200, response.text
    assert response.json()["applied"] is False
    assert response.json()["groups_created"] == [f"src-{tag}", f"dst-{tag}"]

    listed = {group["slug"] for group in api.get("/api/v1/groups").json()}
    assert f"src-{tag}" not in listed


def test_applying_then_reimporting_is_a_no_op(api, tag):
    """The property that makes a git-versioned ACL repo trustworthy."""
    document = _document(tag)
    applied = api.post("/api/v1/policies/import", json={"document": document, "dry_run": False})
    assert applied.status_code == 200, applied.text
    assert applied.json()["applied"] is True

    again = api.post("/api/v1/policies/import", json={"document": document, "dry_run": True})
    assert again.status_code == 200, again.text
    assert again.json()["summary"] == "groups +0 ~0 -0, rules +0 ~0 -0"


def test_export_reimports_cleanly(api, tag):
    api.post("/api/v1/policies/import", json={"document": _document(tag), "dry_run": False})
    exported = api.get("/api/v1/policies/export").json()
    response = api.post("/api/v1/policies/import", json={"document": exported, "dry_run": True})
    assert response.status_code == 200, response.text
    assert response.json()["summary"] == "groups +0 ~0 -0, rules +0 ~0 -0"


def test_a_rule_that_cannot_be_expressed_in_nftables_is_rejected(api, tag):
    response = api.post(
        "/api/v1/acl-rules",
        json={
            "ref": f"bad-{tag}",
            "name": "ports on icmp",
            "action": "accept",
            "src": {"kind": "any"},
            "dst": {"kind": "any"},
            "protocol": "icmp",
            "dst_port_start": 80,
        },
    )
    assert response.status_code == 422
    refs = {rule["ref"] for rule in api.get("/api/v1/acl-rules").json()}
    assert f"bad-{tag}" not in refs


# --------------------------------------------------------------------------- #
# ruleset + agent
# --------------------------------------------------------------------------- #


def test_the_rendered_ruleset_keeps_its_safety_properties(api):
    content = api.get("/api/v1/ruleset/preview").json()["content"]

    assert "flush ruleset" not in content
    assert content.count("delete table") == 1
    assert "delete table inet foxguard" in content
    assert "hook input priority filter; policy accept;" in content
    assert "hook forward priority filter; policy accept;" in content
    assert 'counter drop comment "fg:default-deny"' in content
    assert 'iifname != "wg0" accept' in content


def test_regeneration_is_idempotent(api):
    first = api.post("/api/v1/ruleset/regenerate")
    second = api.post("/api/v1/ruleset/regenerate")
    assert first.status_code == second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert first.json()["digest"] == second.json()["digest"]


def test_the_agent_sees_the_same_digest_as_the_preview(api):
    preview = api.get("/api/v1/ruleset/preview").json()
    state = api.get("/api/v1/agent/state").json()
    assert state["digest"] == preview["digest"]
    assert state["ruleset"] == preview["content"]


def test_confined_peers_stay_on_the_wireguard_interface(api, tag):
    """Confinement is enforced by nftables, not by removing the wg peer --
    otherwise a quarantined peer could not reach the portal at all."""
    peer = _create_peer(api, tag)
    state = api.get("/api/v1/agent/state").json()
    keys = {entry["public_key"] for entry in state["wg_peers"]}
    assert peer["wg_public_key"] in keys


def test_reporting_an_apply_marks_the_version_applied(api):
    state = api.get("/api/v1/agent/state").json()
    response = api.post(
        "/api/v1/agent/report", json={"digest": state["digest"], "success": True}
    )
    assert response.status_code == 204
    versions = api.get("/api/v1/ruleset/versions").json()
    matching = [v for v in versions if v["digest"] == state["digest"]]
    assert matching and matching[0]["status"] == "applied"


# --------------------------------------------------------------------------- #
# Phase 2: enrollment and the captive portal
#
# These endpoints have no bearer token: they identify their caller by the
# tunnel address it sends from. Testing that for real means *sending from* the
# peer's address, which is why `make test-api` allocates the pool inside
# 127.0.0.0/8 -- every address in it is already local, so a client can bind to
# one and the server sees exactly what it would see through wg0.
# --------------------------------------------------------------------------- #


PASSWORD = "correct-horse-battery-staple"


def as_peer(tunnel_ip: str) -> httpx.Client:
    """An *unauthenticated* client that sends from ``tunnel_ip``."""
    return httpx.Client(
        base_url=API_URL,
        transport=httpx.HTTPTransport(local_address=tunnel_ip),
        timeout=30,
    )


def _user(api, tag: str, *, suffix: str = "", **extra) -> dict:
    response = api.post(
        "/api/v1/users",
        json={"username": f"user-{tag}{suffix}", "password": PASSWORD, **extra},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _user_peer(api, tag: str, owner: dict, **extra) -> dict:
    return _create_peer(api, tag, peer_type="user", owner_user_id=owner["id"], **extra)


def _enrolled_key(api, peer: dict) -> str:
    response = api.post(f"/api/v1/peers/{peer['id']}/enrollment-key", json={})
    assert response.status_code == 201, response.text
    return response.json()["enrollment_key"]


def _state_of(api, peer: dict) -> str:
    return api.get(f"/api/v1/peers/{peer['id']}").json()["state"]


# --------------------------------- enrollment ------------------------------ #


def test_a_server_peer_enrolls_with_its_key_and_reaches_its_groups(api, tag):
    group = _group(api, tag, "enr")
    peer = _create_peer(api, tag, group_slugs=[group["slug"]])
    key = _enrolled_key(api, peer)

    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    set_name = "g_" + group["slug"].replace("-", "_") + "_v4"
    assert peer["tunnel_ip"] in _set_body(ruleset, "fg_quarantine_v4")
    assert peer["tunnel_ip"] not in _set_body(ruleset, set_name)

    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post("/api/v1/enroll", json={"enrollment_key": key})
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "active"
    assert response.json()["enrolled_at"] is not None

    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    assert peer["tunnel_ip"] in _set_body(ruleset, set_name)
    assert peer["tunnel_ip"] not in _set_body(ruleset, "fg_quarantine_v4")


def test_a_registered_public_key_alone_grants_nothing(api, tag):
    """Enrollment must fail without the key, not merely be inconvenient."""
    peer = _create_peer(api, tag)
    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post("/api/v1/enroll", json={"enrollment_key": "fgk_guess"})
    assert response.status_code == 403
    assert _state_of(api, peer) == "staging"


def test_enrolling_from_outside_the_tunnel_is_refused(api, tag):
    """127.0.0.1 is not in the pool, so it is not a peer address."""
    peer = _create_peer(api, tag)
    key = _enrolled_key(api, peer)
    with as_peer("127.0.0.1") as outsider:
        response = outsider.post("/api/v1/enroll", json={"enrollment_key": key})
    assert response.status_code == 403
    assert _state_of(api, peer) == "staging"


def test_one_peers_key_cannot_enroll_another_peer(api, tag):
    """The key is checked against the peer holding the source address only."""
    victim = _create_peer(api, f"{tag}-victim")
    attacker = _create_peer(api, f"{tag}-attacker")
    victim_key = _enrolled_key(api, victim)

    with as_peer(attacker["tunnel_ip"]) as device:
        response = device.post("/api/v1/enroll", json={"enrollment_key": victim_key})
    assert response.status_code == 403
    assert _state_of(api, attacker) == "staging"
    assert _state_of(api, victim) == "staging"


def test_a_mismatched_public_key_cross_check_is_refused(api, tag):
    peer = _create_peer(api, tag)
    key = _enrolled_key(api, peer)
    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post(
            "/api/v1/enroll", json={"enrollment_key": key, "wg_public_key": wg_key()}
        )
    assert response.status_code == 403
    assert _state_of(api, peer) == "staging"


def test_a_revoked_key_stops_working_immediately(api, tag):
    peer = _create_peer(api, tag)
    key = _enrolled_key(api, peer)
    assert api.delete(f"/api/v1/peers/{peer['id']}/enrollment-key").status_code == 200

    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post("/api/v1/enroll", json={"enrollment_key": key})
    assert response.status_code == 403
    assert _state_of(api, peer) == "quarantined"


def test_a_valid_key_cannot_resurrect_a_disabled_peer(api, tag):
    """An administrative stop outranks any credential the device holds."""
    peer = _create_peer(api, tag)
    key = _enrolled_key(api, peer)
    assert api.patch(f"/api/v1/peers/{peer['id']}", json={"state": "disabled"}).status_code == 200

    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post("/api/v1/enroll", json={"enrollment_key": key})
    assert response.status_code == 403
    assert _state_of(api, peer) == "disabled"


def test_a_user_peer_cannot_use_the_enrollment_endpoint(api, tag):
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post(
            "/api/v1/enroll", json={"enrollment_key": "fgk_not_a_real_key"}
        )
    assert response.status_code == 403


def test_enrollment_attempts_are_throttled(api, tag):
    """A confined peer can already reach this endpoint, so it must be rate limited."""
    peer = _create_peer(api, tag)
    _enrolled_key(api, peer)
    codes = []
    with as_peer(peer["tunnel_ip"]) as device:
        for _ in range(8):
            codes.append(
                device.post("/api/v1/enroll", json={"enrollment_key": "fgk_wrong"}).status_code
            )
    assert 429 in codes, codes
    assert codes[-1] == 429


def test_a_denied_enrollment_is_recorded(api, tag):
    peer = _create_peer(api, tag)
    with as_peer(peer["tunnel_ip"]) as device:
        device.post("/api/v1/enroll", json={"enrollment_key": "fgk_wrong"})
    entries = api.get(
        "/api/v1/audit-log", params={"action": "peer.enroll.denied"}
    ).json()
    assert any(entry["object_id"] == peer["id"] for entry in entries)


# ----------------------------------- portal -------------------------------- #


def test_the_portal_describes_the_peer_it_is_talking_to(api, tag):
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    with as_peer(peer["tunnel_ip"]) as device:
        response = device.get("/api/v1/portal/status")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["peer_id"] == peer["id"]
    assert body["username"] == owner["username"]
    assert body["authenticated"] is False
    assert body["auth_methods"] == ["local"]
    assert body["totp_required"] is False


def test_logging_in_moves_a_user_peer_into_its_groups(api, tag):
    group = _group(api, tag, "portal")
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner, group_slugs=[group["slug"]])
    set_name = "g_" + group["slug"].replace("-", "_") + "_v4"

    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post(
            "/api/v1/portal/login",
            json={"username": owner["username"], "password": PASSWORD},
        )
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "active"
    assert response.json()["session_expires_at"] is not None

    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    assert peer["tunnel_ip"] in _set_body(ruleset, set_name)
    assert peer["tunnel_ip"] not in _set_body(ruleset, "fg_quarantine_v4")


def test_a_wrong_password_leaves_the_peer_in_quarantine(api, tag):
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post(
            "/api/v1/portal/login",
            json={"username": owner["username"], "password": "wrong-password-here"},
        )
    assert response.status_code == 401
    assert _state_of(api, peer) == "staging"


def test_another_users_valid_credentials_do_not_unlock_this_device(api, tag):
    """ACL groups belong to the *peer*, so any-credential-unlocks-any-device
    would let a low-privilege account inherit a stolen laptop's access."""
    owner = _user(api, tag, suffix="-owner")
    stranger = _user(api, tag, suffix="-stranger")
    peer = _user_peer(api, tag, owner)

    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post(
            "/api/v1/portal/login",
            json={"username": stranger["username"], "password": PASSWORD},
        )
    assert response.status_code == 401
    assert _state_of(api, peer) == "staging"


def test_a_deactivated_account_cannot_log_in(api, tag):
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    api.patch(f"/api/v1/users/{owner['id']}", json={"is_active": False})
    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post(
            "/api/v1/portal/login",
            json={"username": owner["username"], "password": PASSWORD},
        )
    assert response.status_code == 401
    assert _state_of(api, peer) == "staging"


def test_logging_out_returns_the_peer_to_quarantine(api, tag):
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    with as_peer(peer["tunnel_ip"]) as device:
        device.post(
            "/api/v1/portal/login",
            json={"username": owner["username"], "password": PASSWORD},
        )
        response = device.post("/api/v1/portal/logout")
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "quarantined"

    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    assert peer["tunnel_ip"] in _set_body(ruleset, "fg_quarantine_v4")


def test_a_server_peer_cannot_log_in_on_the_portal(api, tag):
    peer = _create_peer(api, tag)
    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post(
            "/api/v1/portal/login", json={"username": "whoever", "password": PASSWORD}
        )
    assert response.status_code == 401


def test_a_forwarded_header_is_refused_rather_than_ignored(api, tag):
    """Regression: uvicorn's ProxyHeadersMiddleware is ON by default and trusts
    127.0.0.1, rewriting request.client from X-Forwarded-For *before* the app
    runs. Anything able to connect from localhost -- a process or container on
    the gateway -- could therefore name a peer's tunnel address in a header and
    be believed: a 403 became a 200 carrying that peer's identity.

    `foxguard-serve` disables the middleware; this asserts the second line of
    defence, which survives someone running plain uvicorn.
    """
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)

    with as_peer("127.0.0.1") as outsider:
        for header in ("X-Forwarded-For", "Forwarded", "X-Real-IP"):
            response = outsider.get(
                "/api/v1/portal/status", headers={header: peer["tunnel_ip"]}
            )
            assert response.status_code == 403, header
            assert "proxy" in response.json()["detail"]


def test_a_peer_cannot_impersonate_another_with_a_forwarded_header(api, tag):
    victim = _user_peer(api, f"{tag}-v", _user(api, f"{tag}-v"))
    attacker = _user_peer(api, f"{tag}-a", _user(api, f"{tag}-a"))

    with as_peer(attacker["tunnel_ip"]) as device:
        # Sanity: the attacker is correctly identified as itself.
        assert device.get("/api/v1/portal/status").json()["peer_id"] == attacker["id"]

        spoofed = device.get(
            "/api/v1/portal/status",
            headers={"X-Forwarded-For": victim["tunnel_ip"]},
        )
    assert spoofed.status_code == 403


def test_enrollment_also_refuses_forwarded_headers(api, tag):
    peer = _create_peer(api, tag)
    key = _enrolled_key(api, peer)
    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post(
            "/api/v1/enroll",
            json={"enrollment_key": key},
            headers={"X-Forwarded-For": peer["tunnel_ip"]},
        )
    assert response.status_code == 403
    assert _state_of(api, peer) == "staging"


def test_the_portal_is_unreachable_from_outside_the_tunnel(api, tag):
    owner = _user(api, tag)
    _user_peer(api, tag, owner)
    with as_peer("127.0.0.1") as outsider:
        assert outsider.get("/api/v1/portal/status").status_code == 403
        assert (
            outsider.post(
                "/api/v1/portal/login",
                json={"username": owner["username"], "password": PASSWORD},
            ).status_code
            == 403
        )


def test_login_attempts_are_throttled(api, tag):
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    codes = []
    with as_peer(peer["tunnel_ip"]) as device:
        for _ in range(8):
            codes.append(
                device.post(
                    "/api/v1/portal/login",
                    json={"username": owner["username"], "password": "nope-nope-nope"},
                ).status_code
            )
    assert 429 in codes, codes
    assert codes[-1] == 429


def test_throttling_survives_a_correct_password_arriving_late(api, tag):
    """Once the budget is spent the right password must not open the door."""
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    with as_peer(peer["tunnel_ip"]) as device:
        for _ in range(8):
            device.post(
                "/api/v1/portal/login",
                json={"username": owner["username"], "password": "nope-nope-nope"},
            )
        response = device.post(
            "/api/v1/portal/login",
            json={"username": owner["username"], "password": PASSWORD},
        )
    assert response.status_code == 429
    assert _state_of(api, peer) == "staging"


# ------------------------------------ TOTP --------------------------------- #


def totp_code(secret: str, *, steps_ahead: int = 0) -> str:
    """A code for a chosen time step.

    Tests need distinct steps without sleeping 30 seconds. ``steps_ahead=1``
    lands inside the server's +/-1 skew window while still being a *different*
    step from the one confirmation just spent -- which is exactly what the
    replay guard requires.
    """
    return pyotp.TOTP(secret).at(time.time() + steps_ahead * 30)


def _enable_totp(api, user: dict) -> str:
    provisioned = api.post(f"/api/v1/users/{user['id']}/totp", json={})
    assert provisioned.status_code == 201, provisioned.text
    secret = provisioned.json()["secret"]
    assert provisioned.json()["enabled"] is False

    confirmed = api.post(
        f"/api/v1/users/{user['id']}/totp/confirm", json={"code": totp_code(secret)}
    )
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["totp_enabled"] is True
    return secret


def test_provisioning_totp_does_not_enable_it_until_a_code_is_proven(api, tag):
    """Enabling on provisioning locks the user out if the QR never scanned."""
    user = _user(api, tag)
    provisioned = api.post(f"/api/v1/users/{user['id']}/totp", json={})
    assert provisioned.status_code == 201
    assert provisioned.json()["enabled"] is False
    assert api.get(f"/api/v1/users/{user['id']}").json()["totp_enabled"] is False


def test_a_totp_account_needs_the_code_as_well_as_the_password(api, tag):
    owner = _user(api, tag)
    secret = _enable_totp(api, owner)
    peer = _user_peer(api, tag, owner)

    with as_peer(peer["tunnel_ip"]) as device:
        without = device.post(
            "/api/v1/portal/login",
            json={"username": owner["username"], "password": PASSWORD},
        )
        assert without.status_code == 401
        assert _state_of(api, peer) == "staging"

        with_code = device.post(
            "/api/v1/portal/login",
            json={
                "username": owner["username"],
                "password": PASSWORD,
                "totp_code": totp_code(secret, steps_ahead=1),
            },
        )
    assert with_code.status_code == 200, with_code.text
    assert with_code.json()["state"] == "active"


def test_the_code_that_enabled_totp_cannot_then_be_used_to_log_in(api, tag):
    """Confirmation spends its code, so it is not left lying around reusable."""
    owner = _user(api, tag)
    provisioned = api.post(f"/api/v1/users/{owner['id']}/totp", json={})
    secret = provisioned.json()["secret"]
    code = totp_code(secret)
    api.post(f"/api/v1/users/{owner['id']}/totp/confirm", json={"code": code})
    peer = _user_peer(api, tag, owner)

    with as_peer(peer["tunnel_ip"]) as device:
        response = device.post(
            "/api/v1/portal/login",
            json={"username": owner["username"], "password": PASSWORD, "totp_code": code},
        )
    assert response.status_code == 401
    assert _state_of(api, peer) == "staging"


def test_a_totp_code_cannot_be_replayed(api, tag):
    """RFC 6238 5.2: a code that was accepted once must not work again."""
    owner = _user(api, tag)
    secret = _enable_totp(api, owner)
    peer = _user_peer(api, tag, owner)
    code = totp_code(secret, steps_ahead=1)

    with as_peer(peer["tunnel_ip"]) as device:
        first = device.post(
            "/api/v1/portal/login",
            json={"username": owner["username"], "password": PASSWORD, "totp_code": code},
        )
        assert first.status_code == 200, first.text
        device.post("/api/v1/portal/logout")

        second = device.post(
            "/api/v1/portal/login",
            json={"username": owner["username"], "password": PASSWORD, "totp_code": code},
        )
    assert second.status_code == 401
    assert _state_of(api, peer) == "quarantined"


def test_disabling_totp_destroys_the_secret(api, tag):
    owner = _user(api, tag)
    _enable_totp(api, owner)
    response = api.delete(f"/api/v1/users/{owner['id']}/totp")
    assert response.status_code == 200, response.text
    assert response.json()["totp_enabled"] is False
    # Re-provisioning must hand out a different seed, never the old one back.
    assert api.post(f"/api/v1/users/{owner['id']}/totp", json={}).status_code == 201


def test_totp_is_refused_on_an_account_with_no_password(api, tag):
    """TOTP is a second factor for a local password; OIDC MFA is the IdP's job."""
    response = api.post(
        "/api/v1/users",
        json={
            "username": f"oidc-{tag}",
            "external_idp_issuer": "https://idp.example",
            "external_idp_subject": f"sub-{tag}",
        },
    )
    assert response.status_code == 201, response.text
    assert api.post(f"/api/v1/users/{response.json()['id']}/totp", json={}).status_code == 409


# ------------------------------- state machine ----------------------------- #


def test_a_revoked_peer_cannot_be_brought_back(api, tag):
    """Revocation that can be undone by editing a field is not revocation."""
    peer = _create_peer(api, tag)
    assert api.patch(f"/api/v1/peers/{peer['id']}", json={"state": "revoked"}).status_code == 200
    for target in ("active", "quarantined", "staging", "disabled"):
        response = api.patch(f"/api/v1/peers/{peer['id']}", json={"state": target})
        assert response.status_code == 409, (target, response.text)
    assert _state_of(api, peer) == "revoked"


def test_revoking_a_key_on_a_revoked_peer_leaves_it_revoked(api, tag):
    peer = _create_peer(api, tag)
    _enrolled_key(api, peer)
    api.patch(f"/api/v1/peers/{peer['id']}", json={"state": "revoked"})
    response = api.delete(f"/api/v1/peers/{peer['id']}/enrollment-key")
    assert response.status_code == 200
    assert response.json()["state"] == "revoked"


def test_an_admin_granting_active_directly_is_audited_as_an_override(api, tag):
    peer = _create_peer(api, tag)
    api.patch(f"/api/v1/peers/{peer['id']}", json={"state": "active"})
    entries = api.get("/api/v1/audit-log", params={"action": "peer.state.override"}).json()
    assert any(entry["object_id"] == peer["id"] for entry in entries)


# --------------------------------------------------------------------------- #
# OIDC, against a throwaway identity provider
#
# The IdP below is real enough to matter: it publishes a discovery document and
# a JWKS, and it signs tokens with an actual RSA key. That means the API does
# genuine discovery, a genuine token exchange and a genuine signature check --
# a mocked IdP would prove none of that.
# --------------------------------------------------------------------------- #


IDP_PORT = int(os.environ.get("FOXGUARD_TEST_IDP_PORT", "8766"))
IDP_ISSUER = f"http://127.0.0.1:{IDP_PORT}"
IDP_CLIENT_ID = "foxguard-test"


class FakeIdp:
    """Minimal OIDC provider. ``next_claims`` is what the next /token call mints."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.key = RSAKey.generate_key(
            2048, parameters={"kid": "idp-key", "use": "sig", "alg": "RS256"}
        )
        self.next_claims: dict = {}
        self.token_requests: list[dict] = []
        self._server: ThreadingHTTPServer | None = None

    # -- wire format ------------------------------------------------------- #

    def _discovery(self) -> dict:
        return {
            "issuer": IDP_ISSUER,
            "authorization_endpoint": f"{IDP_ISSUER}/authorize",
            "token_endpoint": f"{IDP_ISSUER}/token",
            "jwks_uri": f"{IDP_ISSUER}/jwks",
        }

    def _jwks(self) -> dict:
        return {"keys": [self.key.as_dict(private=False)]}

    def mint(self, **overrides) -> str:
        claims = {
            "iss": IDP_ISSUER,
            "aud": IDP_CLIENT_ID,
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        } | self.next_claims | overrides
        return jwt.encode({"alg": "RS256", "kid": "idp-key"}, claims, self.key)

    # -- lifecycle --------------------------------------------------------- #

    def __enter__(self) -> FakeIdp:
        idp = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _send(self, payload: dict, code: int = 200) -> None:
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's contract
                if self.path.startswith("/.well-known/openid-configuration"):
                    self._send(idp._discovery())
                elif self.path.startswith("/jwks"):
                    self._send(idp._jwks())
                else:
                    self._send({"error": "not_found"}, 404)

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length).decode()
                idp.token_requests.append(
                    {k: v[0] for k, v in parse_qs(raw).items()}
                )
                self._send({"id_token": idp.mint(), "token_type": "Bearer"})

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()


@pytest.fixture(scope="module")
def idp():
    with FakeIdp(IDP_PORT) as fake:
        yield fake


@pytest.fixture()
def oidc_user(api, tag) -> dict:
    """An account bound to the fake IdP rather than to a password."""
    response = api.post(
        "/api/v1/users",
        json={
            "username": f"sso-{tag}",
            "external_idp_issuer": IDP_ISSUER,
            "external_idp_subject": f"subject-{tag}",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _start_flow(device, idp: FakeIdp, subject: str) -> tuple[str, str]:
    """Run the authorize step and tell the IdP what to mint. Returns (state, code)."""
    started = device.get("/api/v1/portal/oidc/start")
    if started.status_code == 501:
        pytest.skip("no OIDC provider configured for this server")
    assert started.status_code == 200, started.text

    query = parse_qs(urlparse(started.json()["authorization_url"]).query)
    # The IdP echoes back the nonce Foxguard generated -- that is the binding
    # between the token and this specific authorization request.
    idp.next_claims = {"sub": subject, "nonce": query["nonce"][0]}
    return started.json()["state"], "authorization-code-123"


def test_an_oidc_login_activates_the_peer(api, tag, idp, oidc_user):
    group = _group(api, tag, "sso")
    peer = _user_peer(api, tag, oidc_user, group_slugs=[group["slug"]])

    with as_peer(peer["tunnel_ip"]) as device:
        state, code = _start_flow(device, idp, oidc_user["username"].replace("sso-", "subject-"))
        response = device.get(
            "/api/v1/portal/oidc/callback", params={"state": state, "code": code}
        )
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "active"
    assert response.json()["auth_method"] == "oidc"

    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    set_name = "g_" + group["slug"].replace("-", "_") + "_v4"
    assert peer["tunnel_ip"] in _set_body(ruleset, set_name)


def test_the_token_exchange_uses_pkce_and_the_client_secret(api, tag, idp, oidc_user):
    peer = _user_peer(api, tag, oidc_user)
    with as_peer(peer["tunnel_ip"]) as device:
        state, code = _start_flow(device, idp, f"subject-{tag}")
        idp.token_requests.clear()
        device.get("/api/v1/portal/oidc/callback", params={"state": state, "code": code})

    assert idp.token_requests, "the API never called the token endpoint"
    sent = idp.token_requests[-1]
    assert sent["grant_type"] == "authorization_code"
    assert sent["code"] == code
    assert sent["client_secret"] == "test-client-secret"
    assert 43 <= len(sent["code_verifier"]) <= 128


def test_a_callback_cannot_be_replayed(api, tag, idp, oidc_user):
    """State is single-use, so a captured callback URL is worthless afterwards."""
    peer = _user_peer(api, tag, oidc_user)
    with as_peer(peer["tunnel_ip"]) as device:
        state, code = _start_flow(device, idp, f"subject-{tag}")
        first = device.get(
            "/api/v1/portal/oidc/callback", params={"state": state, "code": code}
        )
        assert first.status_code == 200, first.text
        device.post("/api/v1/portal/logout")

        second = device.get(
            "/api/v1/portal/oidc/callback", params={"state": state, "code": code}
        )
    assert second.status_code == 401
    assert _state_of(api, peer) == "quarantined"


def test_another_peer_cannot_finish_a_flow_it_did_not_start(api, tag, idp, oidc_user):
    """Otherwise a peer could hijack the session an authorised device earned."""
    victim = _user_peer(api, f"{tag}-v", oidc_user)
    other_owner = _user(api, f"{tag}-o")
    attacker = _user_peer(api, f"{tag}-a", other_owner)

    with as_peer(victim["tunnel_ip"]) as device:
        state, code = _start_flow(device, idp, f"subject-{tag}")

    with as_peer(attacker["tunnel_ip"]) as thief:
        response = thief.get(
            "/api/v1/portal/oidc/callback", params={"state": state, "code": code}
        )
    assert response.status_code == 401
    assert _state_of(api, attacker) == "staging"
    assert _state_of(api, victim) == "staging"


def test_a_token_for_an_unknown_subject_is_refused(api, tag, idp, oidc_user):
    peer = _user_peer(api, tag, oidc_user)
    with as_peer(peer["tunnel_ip"]) as device:
        state, code = _start_flow(device, idp, "nobody-we-know")
        response = device.get(
            "/api/v1/portal/oidc/callback", params={"state": state, "code": code}
        )
    assert response.status_code == 401
    assert _state_of(api, peer) == "staging"


def test_a_token_for_a_different_account_does_not_unlock_this_device(api, tag, idp):
    """The same binding rule as local login: the account must own the peer."""
    owner = api.post(
        "/api/v1/users",
        json={
            "username": f"sso-owner-{tag}",
            "external_idp_issuer": IDP_ISSUER,
            "external_idp_subject": f"owner-{tag}",
        },
    ).json()
    stranger = api.post(
        "/api/v1/users",
        json={
            "username": f"sso-stranger-{tag}",
            "external_idp_issuer": IDP_ISSUER,
            "external_idp_subject": f"stranger-{tag}",
        },
    ).json()
    assert stranger["id"]
    peer = _user_peer(api, tag, owner)

    with as_peer(peer["tunnel_ip"]) as device:
        state, code = _start_flow(device, idp, f"stranger-{tag}")
        response = device.get(
            "/api/v1/portal/oidc/callback", params={"state": state, "code": code}
        )
    assert response.status_code == 401
    assert _state_of(api, peer) == "staging"


def test_an_unknown_state_is_refused(api, tag, idp, oidc_user):
    peer = _user_peer(api, tag, oidc_user)
    with as_peer(peer["tunnel_ip"]) as device:
        response = device.get(
            "/api/v1/portal/oidc/callback",
            params={"state": "never-issued", "code": "whatever"},
        )
    assert response.status_code == 401


def test_an_error_from_the_identity_provider_is_refused(api, tag, idp, oidc_user):
    peer = _user_peer(api, tag, oidc_user)
    with as_peer(peer["tunnel_ip"]) as device:
        state, _ = _start_flow(device, idp, f"subject-{tag}")
        response = device.get(
            "/api/v1/portal/oidc/callback",
            params={"state": state, "error": "access_denied"},
        )
    assert response.status_code == 401
    assert _state_of(api, peer) == "staging"


def test_the_oidc_flow_is_unreachable_from_outside_the_tunnel(api):
    with as_peer("127.0.0.1") as outsider:
        assert outsider.get("/api/v1/portal/oidc/start").status_code == 403


def test_a_password_account_cannot_start_an_oidc_flow(api, tag):
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    with as_peer(peer["tunnel_ip"]) as device:
        response = device.get("/api/v1/portal/oidc/start")
    assert response.status_code in (409, 501)


# --------------------------------------------------------------------------- #
# Phase 3: session expiry
#
# `make test-api` runs the server with a one-second default lifetime and a
# background sweeper parked at one hour, so these drive POST /sessions/sweep
# themselves and nothing fires behind their back.
# --------------------------------------------------------------------------- #


def _login(device, owner: dict) -> httpx.Response:
    return device.post(
        "/api/v1/portal/login",
        json={"username": owner["username"], "password": PASSWORD},
    )


def _sweep(api) -> dict:
    response = api.post("/api/v1/sessions/sweep")
    assert response.status_code == 200, response.text
    return response.json()


def test_an_expired_session_returns_the_peer_to_quarantine(api, tag):
    group = _group(api, tag, "exp")
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner, group_slugs=[group["slug"]])
    set_name = "g_" + group["slug"].replace("-", "_") + "_v4"

    with as_peer(peer["tunnel_ip"]) as device:
        assert _login(device, owner).status_code == 200
    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    assert peer["tunnel_ip"] in _set_body(ruleset, set_name)

    time.sleep(1.2)
    result = _sweep(api)
    assert peer["id"] in [item["peer_id"] for item in result["expired"]]
    assert result["regenerated"] is True

    assert _state_of(api, peer) == "quarantined"
    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    assert peer["tunnel_ip"] not in _set_body(ruleset, set_name)
    assert peer["tunnel_ip"] in _set_body(ruleset, "fg_quarantine_v4")


def test_a_server_peer_is_never_expired(api, tag):
    """A backup job must not be logged out at 3am; that is why peer types exist."""
    group = _group(api, tag, "srv")
    peer = _create_peer(api, tag, group_slugs=[group["slug"]])
    key = _enrolled_key(api, peer)
    with as_peer(peer["tunnel_ip"]) as device:
        assert device.post("/api/v1/enroll", json={"enrollment_key": key}).status_code == 200

    time.sleep(1.2)
    result = _sweep(api)
    assert peer["id"] not in [item["peer_id"] for item in result["expired"]]
    assert _state_of(api, peer) == "active"


def test_a_group_lifetime_overrides_the_default(api, tag):
    """Positive control: with an explicit lifetime the peer survives the sweep."""
    group = _group(api, tag, "long", session_lifetime_seconds=86400)
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner, group_slugs=[group["slug"]])

    with as_peer(peer["tunnel_ip"]) as device:
        assert _login(device, owner).status_code == 200

    time.sleep(1.2)
    result = _sweep(api)
    assert peer["id"] not in [item["peer_id"] for item in result["expired"]]
    assert _state_of(api, peer) == "active"


def test_moving_a_peer_to_a_stricter_group_expires_a_live_session(api, tag):
    """The deadline is recomputed from current membership, not read back."""
    lenient = _group(api, tag, "lenient", session_lifetime_seconds=86400)
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner, group_slugs=[lenient["slug"]])

    with as_peer(peer["tunnel_ip"]) as device:
        assert _login(device, owner).status_code == 200
    time.sleep(1.2)
    assert peer["id"] not in [i["peer_id"] for i in _sweep(api)["expired"]]

    # Drop the override; the one-second default now applies to the live session.
    assert api.patch(
        f"/api/v1/peers/{peer['id']}", json={"group_slugs": []}
    ).status_code == 200
    assert peer["id"] in [i["peer_id"] for i in _sweep(api)["expired"]]
    assert _state_of(api, peer) == "quarantined"


def test_re_authenticating_after_an_expiry_works(api, tag):
    """Expiry is not a punishment: the peer logs back in and carries on."""
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)

    with as_peer(peer["tunnel_ip"]) as device:
        assert _login(device, owner).status_code == 200
        time.sleep(1.2)
        _sweep(api)
        assert _state_of(api, peer) == "quarantined"

        assert _login(device, owner).status_code == 200
    assert _state_of(api, peer) == "active"


def test_sweeping_twice_is_a_no_op_the_second_time(api, tag):
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    with as_peer(peer["tunnel_ip"]) as device:
        _login(device, owner)

    time.sleep(1.2)
    assert peer["id"] in [i["peer_id"] for i in _sweep(api)["expired"]]
    assert peer["id"] not in [i["peer_id"] for i in _sweep(api)["expired"]]


def test_an_expiry_is_recorded_in_the_audit_log(api, tag):
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    with as_peer(peer["tunnel_ip"]) as device:
        _login(device, owner)

    time.sleep(1.2)
    _sweep(api)
    entries = api.get("/api/v1/audit-log", params={"action": "session.expired"}).json()
    assert any(entry["object_id"] == peer["id"] for entry in entries)


def test_live_sessions_are_listed_with_their_deadline(api, tag):
    group = _group(api, tag, "live", session_lifetime_seconds=86400)
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner, group_slugs=[group["slug"]])
    with as_peer(peer["tunnel_ip"]) as device:
        assert _login(device, owner).status_code == 200

    listed = api.get("/api/v1/sessions").json()
    mine = [row for row in listed if row["peer_id"] == peer["id"]]
    assert mine, "the session just created is not listed"
    assert mine[0]["username"] == owner["username"]
    assert mine[0]["auth_method"] == "local"
    assert 0 < mine[0]["seconds_remaining"] <= 86400


def test_logging_out_ends_the_listed_session(api, tag):
    group = _group(api, tag, "out", session_lifetime_seconds=86400)
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner, group_slugs=[group["slug"]])
    with as_peer(peer["tunnel_ip"]) as device:
        _login(device, owner)
        device.post("/api/v1/portal/logout")

    active = api.get("/api/v1/sessions").json()
    assert peer["id"] not in [row["peer_id"] for row in active]


def test_an_admin_cannot_declare_a_user_peer_active(api, tag):
    """`active` on a user peer must mean a human authenticated, or the expiry
    job has nothing to reason about."""
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    response = api.patch(f"/api/v1/peers/{peer['id']}", json={"state": "active"})
    assert response.status_code == 409, response.text
    assert _state_of(api, peer) == "staging"


# --------------------------------------------------------------------------- #
# Administrator sign-in, and the attribution it buys
# --------------------------------------------------------------------------- #


def _admin_account(api, tag: str, *, admin: bool = True) -> dict:
    response = api.post(
        "/api/v1/users",
        json={"username": f"op-{tag}", "password": PASSWORD, "is_admin": admin},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _signed_in(username: str, password: str = PASSWORD) -> httpx.Client:
    with httpx.Client(base_url=API_URL, timeout=30) as anon:
        response = anon.post(
            "/api/v1/admin/login", json={"username": username, "password": password}
        )
    assert response.status_code == 200, response.text
    return httpx.Client(
        base_url=API_URL,
        headers={"Authorization": f"Bearer {response.json()['token']}"},
        timeout=30,
    )


def test_an_administrator_can_sign_in_and_is_named(api, tag):
    account = _admin_account(api, tag)
    with _signed_in(account["username"]) as operator:
        me = operator.get("/api/v1/admin/me").json()
    assert me["username"] == account["username"]
    assert me["via"] == "session"
    assert me["user_id"] == account["id"]


def test_the_static_token_is_reported_as_a_machine(api):
    """So an audit reader can tell a person from a provisioning script."""
    me = api.get("/api/v1/admin/me").json()
    assert me["via"] == "token"
    assert me["user_id"] is None


def test_a_non_admin_account_cannot_sign_in(api, tag):
    account = _admin_account(api, tag, admin=False)
    with httpx.Client(base_url=API_URL, timeout=30) as anon:
        response = anon.post(
            "/api/v1/admin/login",
            json={"username": account["username"], "password": PASSWORD},
        )
    assert response.status_code == 401


def test_a_session_token_actually_authorises_the_admin_api(api, tag):
    account = _admin_account(api, tag)
    with _signed_in(account["username"]) as operator:
        assert operator.get("/api/v1/peers").status_code == 200


def test_actions_are_attributed_to_the_person_who_took_them(api, tag):
    """The point of the whole exercise: the audit log names a human."""
    account = _admin_account(api, tag)
    with _signed_in(account["username"]) as operator:
        created = operator.post(
            "/api/v1/groups", json={"slug": f"att-{tag}", "name": "attributed"}
        )
        assert created.status_code == 201, created.text

    entries = api.get("/api/v1/audit-log", params={"action": "group.create"}).json()
    mine = [e for e in entries if e["object_id"] == created.json()["id"]]
    assert mine, "the group creation was not audited"
    assert mine[0]["actor_label"] == account["username"]
    assert mine[0]["actor_type"] == "admin"


def test_the_kill_switch_names_the_person_who_fired_it(api, tag):
    account = _admin_account(api, tag)
    with _signed_in(account["username"]) as operator:
        assert operator.post(
            "/api/v1/kill-switch", json={"confirm": "QUARANTINE ALL PEERS"}
        ).status_code == 200

    entry = api.get(
        "/api/v1/audit-log", params={"action": "killswitch.trigger"}
    ).json()[0]
    assert entry["actor_label"] == account["username"]


def test_signing_out_stops_the_token_working(api, tag):
    account = _admin_account(api, tag)
    operator = _signed_in(account["username"])
    try:
        assert operator.post("/api/v1/admin/logout").status_code == 204
        assert operator.get("/api/v1/peers").status_code == 401
    finally:
        operator.close()


def test_deactivating_an_account_cuts_its_live_session(api, tag):
    """Checked on every request, so it takes effect now rather than at expiry."""
    account = _admin_account(api, tag)
    operator = _signed_in(account["username"])
    try:
        assert operator.get("/api/v1/peers").status_code == 200
        api.patch(f"/api/v1/users/{account['id']}", json={"is_active": False})
        assert operator.get("/api/v1/peers").status_code == 401
    finally:
        operator.close()


def test_removing_admin_rights_cuts_its_live_session(api, tag):
    account = _admin_account(api, tag)
    operator = _signed_in(account["username"])
    try:
        assert operator.get("/api/v1/peers").status_code == 200
        api.patch(f"/api/v1/users/{account['id']}", json={"is_admin": False})
        assert operator.get("/api/v1/peers").status_code == 401
    finally:
        operator.close()


def test_changing_the_password_cuts_its_live_session(api, tag):
    account = _admin_account(api, tag)
    operator = _signed_in(account["username"])
    try:
        api.patch(
            f"/api/v1/users/{account['id']}", json={"password": "an-entirely-new-password"}
        )
        assert operator.get("/api/v1/peers").status_code == 401
    finally:
        operator.close()


def test_a_denied_sign_in_is_recorded(api, tag):
    account = _admin_account(api, tag)
    with httpx.Client(base_url=API_URL, timeout=30) as anon:
        anon.post(
            "/api/v1/admin/login",
            json={"username": account["username"], "password": "wrong-password-here"},
        )
    entries = api.get("/api/v1/audit-log", params={"action": "admin.login.denied"}).json()
    assert any(e["actor_label"] == account["username"] for e in entries)


def test_admin_sessions_are_listed_and_the_current_one_is_marked(api, tag):
    account = _admin_account(api, tag)
    with _signed_in(account["username"]) as operator:
        rows = operator.get("/api/v1/admin/sessions").json()
        mine = [row for row in rows if row["username"] == account["username"]]
        assert mine, "the session just created is not listed"
        assert mine[0]["current"] is True
        assert mine[0]["source_ip"]


def test_one_session_can_be_revoked_without_touching_the_account(api, tag):
    """The lighter tool: 'that laptop should not still be signed in'."""
    account = _admin_account(api, tag)
    first = _signed_in(account["username"])
    second = _signed_in(account["username"])
    try:
        rows = second.get("/api/v1/admin/sessions").json()
        target = next(
            row
            for row in rows
            if row["username"] == account["username"] and not row["current"]
        )
        assert second.delete(f"/api/v1/admin/sessions/{target['id']}").status_code == 204

        assert first.get("/api/v1/peers").status_code == 401
        assert second.get("/api/v1/peers").status_code == 200
    finally:
        first.close()
        second.close()


def test_revoking_a_session_is_audited(api, tag):
    account = _admin_account(api, tag)
    doomed = _signed_in(account["username"])
    keeper = _signed_in(account["username"])
    try:
        rows = keeper.get("/api/v1/admin/sessions").json()
        target = next(
            r for r in rows if r["username"] == account["username"] and not r["current"]
        )
        keeper.delete(f"/api/v1/admin/sessions/{target['id']}")
    finally:
        doomed.close()
        keeper.close()

    entries = api.get(
        "/api/v1/audit-log", params={"action": "admin.session.revoke"}
    ).json()
    assert any(e["actor_label"] == account["username"] for e in entries)


def test_revoking_an_unknown_session_is_a_404(api):
    assert api.delete(f"/api/v1/admin/sessions/{uuid.uuid4()}").status_code == 404


def test_admin_sso_reports_when_it_is_not_configured(api):
    """`make test-api` configures the portal's IdP but no admin redirect URL,
    so admin SSO must be off rather than half-working."""
    with httpx.Client(base_url=API_URL, timeout=30) as anon:
        assert anon.get("/api/v1/admin/oidc/start").status_code == 501


def test_a_portal_oidc_state_cannot_buy_an_admin_session(api, tag, idp, oidc_user):
    """Redeeming a device's login as an administrator session would be a
    straight privilege escalation."""
    peer = _user_peer(api, tag, oidc_user)
    with as_peer(peer["tunnel_ip"]) as device:
        state, code = _start_flow(device, idp, f"subject-{tag}")

    with httpx.Client(base_url=API_URL, timeout=30) as anon:
        response = anon.post(
            "/api/v1/admin/oidc/complete", json={"state": state, "code": code}
        )
    # 501 when admin SSO is unconfigured, 401 when it is: either way, refused.
    assert response.status_code in (401, 501)


def test_an_invalid_session_token_is_refused(api):
    with httpx.Client(
        base_url=API_URL, headers={"Authorization": "Bearer fga_not-a-real-token"}, timeout=30
    ) as impostor:
        assert impostor.get("/api/v1/peers").status_code == 401


# --------------------------------------------------------------------------- #
# Phase 4: dashboard aggregates, policy matrix, kill switch
# --------------------------------------------------------------------------- #


def test_the_dashboard_counts_what_exists(api, tag):
    _group(api, tag, "dash")
    peer = _create_peer(api, tag)

    body = api.get("/api/v1/dashboard").json()
    assert body["peers_total"] >= 1
    assert body["peers_by_state"]["staging"] >= 1
    assert body["peers_by_type"]["server"] >= 1
    assert body["groups"] >= 1
    assert peer["id"]


def test_the_dashboard_reports_whether_the_dataplane_is_in_sync(api, tag):
    """The one number on that screen that is not inventory."""
    _create_peer(api, tag)
    assert api.get("/api/v1/dashboard").json()["ruleset"]["in_sync"] is False

    state = api.get("/api/v1/agent/state").json()
    api.post("/api/v1/agent/report", json={"digest": state["digest"], "success": True})

    ruleset = api.get("/api/v1/dashboard").json()["ruleset"]
    assert ruleset["in_sync"] is True
    assert ruleset["applied_digest"] == ruleset["digest"]


def test_the_dashboard_carries_the_latest_audit_entries(api, tag):
    _group(api, tag, "recent")
    entries = api.get("/api/v1/dashboard", params={"audit_limit": 5}).json()["recent_audit"]
    assert 0 < len(entries) <= 5
    assert all("action" in entry for entry in entries)


def test_the_policy_matrix_reflects_the_rules(api, tag):
    document = _document(tag)
    assert api.post(
        "/api/v1/policies/import", json={"document": document, "dry_run": False}
    ).status_code == 200

    matrix = api.get("/api/v1/policies/matrix").json()
    assert f"src-{tag}" in matrix["sources"]
    assert f"dst-{tag}" in matrix["destinations"]
    cell = [
        c for c in matrix["cells"] if c["src"] == f"src-{tag}" and c["dst"] == f"dst-{tag}"
    ]
    assert cell and cell[0]["action"] == "accept"
    assert f"rule-{tag}" in cell[0]["rule_refs"]


def test_a_group_with_no_rules_still_appears_on_the_axes(api, tag):
    """An empty row is the useful observation that a group can reach nothing."""
    group = _group(api, tag, "lonely")
    matrix = api.get("/api/v1/policies/matrix").json()
    assert group["slug"] in matrix["sources"]
    assert not [c for c in matrix["cells"] if c["src"] == group["slug"]]


def test_the_matrix_shows_the_rule_that_actually_decides(api, tag):
    """A later accept behind an earlier drop never fires; showing "allowed"
    would be a lie a reader might act on."""
    src, dst = f"ms-{tag}", f"md-{tag}"
    document = {
        "version": 1,
        "groups": [{"slug": src, "name": src}, {"slug": dst, "name": dst}],
        "acl_rules": [
            {
                "ref": f"deny-{tag}", "name": "deny first", "action": "drop", "priority": 10,
                "src_kind": "group", "src_group": src, "dst_kind": "group", "dst_group": dst,
            },
            {
                "ref": f"allow-{tag}", "name": "allow later", "action": "accept", "priority": 90,
                "src_kind": "group", "src_group": src, "dst_kind": "group", "dst_group": dst,
            },
        ],
    }
    assert api.post(
        "/api/v1/policies/import", json={"document": document, "dry_run": False}
    ).status_code == 200

    cell = [
        c
        for c in api.get("/api/v1/policies/matrix").json()["cells"]
        if c["src"] == src and c["dst"] == dst
    ]
    assert cell and cell[0]["action"] == "drop"
    assert set(cell[0]["rule_refs"]) == {f"deny-{tag}", f"allow-{tag}"}


def test_tags_are_listed_for_the_filter_ui(api, tag):
    _create_peer(api, tag, tags=[f"env-{tag}"])
    assert f"env-{tag}" in [row["name"] for row in api.get("/api/v1/tags").json()]


def test_peers_can_be_filtered_by_tag(api, tag):
    peer = _create_peer(api, tag, tags=[f"only-{tag}"])
    listed = api.get("/api/v1/peers", params={"tag": f"only-{tag}"}).json()
    assert [row["id"] for row in listed] == [peer["id"]]


# ---------------------------------- kill switch ---------------------------- #


def test_the_kill_switch_needs_its_exact_phrase(api, tag):
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    with as_peer(peer["tunnel_ip"]) as device:
        _login(device, owner)

    for wrong in ({"confirm": "yes"}, {"confirm": ""}, {"confirm": "quarantine all peers"}):
        assert api.post("/api/v1/kill-switch", json=wrong).status_code == 422
    assert _state_of(api, peer) == "active"


def test_the_quarantine_phrase_cannot_fire_a_lockdown(api):
    response = api.post(
        "/api/v1/kill-switch",
        json={"mode": "lockdown", "confirm": "QUARANTINE ALL PEERS"},
    )
    assert response.status_code == 422


def test_the_kill_switch_cuts_everyone_including_server_peers(api, tag):
    group = _group(api, tag, "kill")
    owner = _user(api, tag)
    laptop = _user_peer(api, tag, owner, group_slugs=[group["slug"]])
    server = _create_peer(api, f"{tag}-srv", group_slugs=[group["slug"]])
    key = _enrolled_key(api, server)

    with as_peer(laptop["tunnel_ip"]) as device:
        assert _login(device, owner).status_code == 200
    with as_peer(server["tunnel_ip"]) as device:
        assert device.post("/api/v1/enroll", json={"enrollment_key": key}).status_code == 200

    response = api.post(
        "/api/v1/kill-switch", json={"confirm": "QUARANTINE ALL PEERS"}
    )
    assert response.status_code == 200, response.text
    cut = {item["peer_id"] for item in response.json()["affected"]}
    assert {laptop["id"], server["id"]} <= cut

    assert _state_of(api, laptop) == "quarantined"
    assert _state_of(api, server) == "quarantined"

    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    set_name = "g_" + group["slug"].replace("-", "_") + "_v4"
    for entry in (laptop, server):
        assert entry["tunnel_ip"] not in _set_body(ruleset, set_name)
        assert entry["tunnel_ip"] in _set_body(ruleset, "fg_quarantine_v4")


def test_after_a_quarantine_kill_switch_a_server_peer_can_come_straight_back(api, tag):
    """Documented consequence, asserted so it cannot change silently: quarantine
    is the state peers authenticate *out of*, so a valid key still works."""
    server = _create_peer(api, tag)
    key = _enrolled_key(api, server)
    with as_peer(server["tunnel_ip"]) as device:
        device.post("/api/v1/enroll", json={"enrollment_key": key})
        api.post("/api/v1/kill-switch", json={"confirm": "QUARANTINE ALL PEERS"})
        assert _state_of(api, server) == "quarantined"

        again = device.post("/api/v1/enroll", json={"enrollment_key": key})
    assert again.status_code == 200
    assert _state_of(api, server) == "active"


def test_lockdown_is_what_stops_it(api, tag):
    server = _create_peer(api, tag)
    key = _enrolled_key(api, server)
    with as_peer(server["tunnel_ip"]) as device:
        device.post("/api/v1/enroll", json={"enrollment_key": key})
        assert api.post(
            "/api/v1/kill-switch", json={"mode": "lockdown", "confirm": "DISABLE ALL PEERS"}
        ).status_code == 200
        assert _state_of(api, server) == "disabled"

        again = device.post("/api/v1/enroll", json={"enrollment_key": key})
    assert again.status_code == 403
    assert _state_of(api, server) == "disabled"


def test_a_revoked_peer_is_not_resurrected_by_the_kill_switch(api, tag):
    """Quarantine would put it back in fg_quarantine and hand it the portal."""
    peer = _create_peer(api, tag)
    api.patch(f"/api/v1/peers/{peer['id']}", json={"state": "revoked"})
    api.post("/api/v1/kill-switch", json={"confirm": "QUARANTINE ALL PEERS"})

    assert _state_of(api, peer) == "revoked"
    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    assert peer["tunnel_ip"] not in _set_body(ruleset, "fg_quarantine_v4")


def test_the_kill_switch_is_traced_in_the_audit_log(api, tag):
    _create_peer(api, tag)
    api.post("/api/v1/kill-switch", json={"confirm": "QUARANTINE ALL PEERS"})
    entries = api.get("/api/v1/audit-log", params={"action": "killswitch.trigger"}).json()
    assert entries
    assert entries[0]["detail"]["mode"] == "quarantine"


def test_an_admin_can_still_quarantine_a_user_peer(api, tag):
    """Taking access away is always allowed; only granting it is restricted."""
    owner = _user(api, tag)
    peer = _user_peer(api, tag, owner)
    with as_peer(peer["tunnel_ip"]) as device:
        _login(device, owner)

    assert api.patch(
        f"/api/v1/peers/{peer['id']}", json={"state": "quarantined"}
    ).status_code == 200
    assert _state_of(api, peer) == "quarantined"
    assert peer["id"] not in [row["peer_id"] for row in api.get("/api/v1/sessions").json()]


# --------------------------------------------------------------------------- #
# zones
# --------------------------------------------------------------------------- #


def _net(tag: str, index: int = 0) -> str:
    """A routed network unique to this test run.

    Fixed CIDRs would be a trap here: the end-to-end database is not reset
    between runs, and two zones routing the same prefix through *different*
    peers is exactly what the generator refuses -- so the second run would
    poison the dataset for every later test. Derived from the tag instead.
    """
    return f"10.{int(tag[:2], 16)}.{(int(tag[2:4], 16) + index) % 256}.0/24"


def _off_tunnel_ip(tag: str, index: int = 0) -> str:
    """An address outside the pool, unique to this run.

    A fixed one collides across runs of this suite, and the collision is not a
    bug: several names on one address legitimately merge onto a single hosts
    line. Unique addresses keep the assertions about that line meaningful.
    """
    return f"192.168.{int(tag[:2], 16)}.{(int(tag[2:4], 16) + index) % 254 + 1}"


def _zone(api, tag: str, slug_prefix: str = "zn", **extra) -> dict:
    slug = f"{slug_prefix}-{tag}"
    response = api.post("/api/v1/zones", json={"slug": slug, "name": slug, **extra})
    assert response.status_code == 201, response.text
    return response.json()


def test_a_zone_is_not_listed_among_the_groups(api, tag):
    """They share a table; conflating them in the UI would let a zone be
    attached to a peer as a group, which silently drops its routes."""
    zone = _zone(api, tag)
    slugs = {group["slug"] for group in api.get("/api/v1/groups").json()}
    assert zone["slug"] not in slugs
    assert zone["slug"] in {z["slug"] for z in api.get("/api/v1/zones").json()}


def test_a_zone_cannot_be_created_through_the_groups_endpoint(api, tag):
    response = api.post(
        "/api/v1/groups", json={"slug": f"gz-{tag}", "name": "x", "kind": "zone"}
    )
    assert response.status_code == 422
    assert "/api/v1/zones" in response.text


def test_a_zone_and_a_group_cannot_share_a_slug(api, tag):
    """An ACL rule naming it must never be ambiguous."""
    group = _group(api, tag)
    response = api.post(
        "/api/v1/zones", json={"slug": group["slug"], "name": "clash"}
    )
    assert response.status_code == 409


def test_a_peer_belongs_to_one_zone_and_several_groups(api, tag):
    zone = _zone(api, tag)
    first, second = _group(api, tag, "ga"), _group(api, tag, "gb")
    peer = _create_peer(
        api,
        tag,
        zone_slug=zone["slug"],
        group_slugs=[first["slug"], second["slug"]],
    )
    assert peer["zone_slug"] == zone["slug"]
    assert sorted(peer["group_slugs"]) == sorted([first["slug"], second["slug"]])


def test_a_zone_cannot_be_attached_as_a_group(api, tag):
    zone = _zone(api, tag)
    response = api.post(
        "/api/v1/peers",
        json={
            "name": f"peer-{tag}",
            "peer_type": "server",
            "wg_public_key": wg_key(),
            "group_slugs": [zone["slug"]],
        },
    )
    assert response.status_code == 422
    assert "zone_slug" in response.text


def test_a_zone_route_reaches_the_zones_nftables_set(api, tag):
    zone = _zone(api, tag)
    peer = _create_peer(api, tag, zone_slug=zone["slug"])
    api.patch(f"/api/v1/peers/{peer['id']}", json={"state": "active"})

    created = api.post(
        f"/api/v1/zones/{zone['id']}/routes", json={"cidr": _net(tag)}
    )
    assert created.status_code == 201, created.text

    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    elements = _set_body(ruleset, f"z_{zone['slug'].replace('-', '_')}_v4")
    assert _net(tag) in elements
    assert f"{peer['tunnel_ip']}/32" in elements


def test_a_refused_route_leaves_no_row_behind(api, tag):
    """The regression that made this test exist.

    ``Group.routes`` is already loaded when the endpoint validates, so inserting
    by foreign key left the validator looking at a stale collection: a route the
    generator rejects was accepted, committed, and then every *later*
    regeneration in the whole application failed with the same error. One bad
    POST poisoned the dataset until somebody deleted the row by hand.
    """
    zone_a, zone_b = _zone(api, tag, "ra"), _zone(api, tag, "rb")
    first = _create_peer(api, f"{tag}-a", zone_slug=zone_a["slug"])
    second = _create_peer(api, f"{tag}-b", zone_slug=zone_b["slug"])
    cidr = _net(tag, 7)

    assert api.post(
        f"/api/v1/zones/{zone_a['id']}/routes",
        json={"cidr": cidr, "via_peer_id": first["id"]},
    ).status_code == 201

    # The same network through a different peer: WireGuard would hand it to
    # whichever was configured last, so the generator refuses it.
    refused = api.post(
        f"/api/v1/zones/{zone_b['id']}/routes",
        json={"cidr": cidr, "via_peer_id": second["id"]},
    )
    assert refused.status_code == 422, refused.text
    assert "carried by two different peers" in refused.text

    # Nothing persisted, and unrelated writes still work.
    assert [r["cidr"] for r in api.get(f"/api/v1/zones/{zone_b['id']}/routes").json()] == []
    assert _create_peer(api, f"{tag}-c")["state"] == "staging"


def test_a_default_route_in_a_zone_is_refused(api, tag):
    """It would replace the gateway's own and cut every remote session."""
    zone = _zone(api, tag)
    response = api.post(
        f"/api/v1/zones/{zone['id']}/routes", json={"cidr": "0.0.0.0/0"}
    )
    assert response.status_code == 422
    assert "default route" in response.text


def test_the_agent_is_told_which_routes_to_install(api, tag):
    zone = _zone(api, tag)
    router = _create_peer(api, tag, zone_slug=zone["slug"])
    api.post(
        f"/api/v1/zones/{zone['id']}/routes",
        json={"cidr": _net(tag), "via_peer_id": router["id"]},
    )

    state = api.get("/api/v1/agent/state").json()
    assert _net(tag) in [route["cidr"] for route in state["routes"]]

    # Both halves: cryptokey routing decides which peer, the kernel route
    # decides that it reaches the interface at all.
    entry = next(
        p for p in state["wg_peers"] if p["public_key"] == router["wg_public_key"]
    )
    assert _net(tag) in entry["allowed_ips"]
    assert f"{router['tunnel_ip']}/32" in entry["allowed_ips"]


def test_a_route_the_gateway_reaches_itself_needs_no_kernel_route(api, tag):
    zone = _zone(api, tag)
    api.post(f"/api/v1/zones/{zone['id']}/routes", json={"cidr": _net(tag)})
    state = api.get("/api/v1/agent/state").json()
    assert _net(tag) not in [route["cidr"] for route in state["routes"]]


def test_a_disabled_route_leaves_the_dataplane(api, tag):
    zone = _zone(api, tag)
    route = api.post(
        f"/api/v1/zones/{zone['id']}/routes", json={"cidr": _net(tag)}
    ).json()
    set_name = f"z_{zone['slug'].replace('-', '_')}_v4"
    assert _net(tag) in _set_body(
        api.get("/api/v1/ruleset/preview").json()["content"], set_name
    )

    api.patch(
        f"/api/v1/zones/{zone['id']}/routes/{route['id']}", json={"enabled": False}
    )
    assert _net(tag) not in _set_body(
        api.get("/api/v1/ruleset/preview").json()["content"], set_name
    )


def test_deleting_a_zone_unassigns_its_peers_without_deleting_them(api, tag):
    """Deleting narrows access. It must never delete the devices themselves."""
    zone = _zone(api, tag)
    peer = _create_peer(api, tag, zone_slug=zone["slug"])
    assert api.delete(f"/api/v1/zones/{zone['id']}").status_code == 204

    after = api.get(f"/api/v1/peers/{peer['id']}")
    assert after.status_code == 200
    assert after.json()["zone_slug"] is None


def test_a_rule_can_name_a_zone_on_either_side(api, tag):
    source, destination = _zone(api, tag, "za"), _zone(api, tag, "zb")
    response = api.post(
        "/api/v1/acl-rules",
        json={
            "ref": f"z2z-{tag}",
            "name": "zone to zone",
            "action": "accept",
            "src": {"kind": "zone", "zone_slug": source["slug"]},
            "dst": {"kind": "zone", "zone_slug": destination["slug"]},
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["src"]["zone_slug"] == source["slug"]
    assert response.json()["src"]["group_slug"] is None

    ruleset = api.get("/api/v1/ruleset/preview").json()["content"]
    src_set = f"z_{source['slug'].replace('-', '_')}_v4"
    dst_set = f"z_{destination['slug'].replace('-', '_')}_v4"
    assert f"ip saddr @{src_set} ip daddr @{dst_set}" in ruleset


def test_a_rule_naming_a_group_as_a_zone_is_refused(api, tag):
    """It would render against a set that is never populated -- a rule that
    silently matches nothing is worse than one that is refused."""
    group = _group(api, tag)
    response = api.post(
        "/api/v1/acl-rules",
        json={
            "ref": f"bad-{tag}",
            "name": "mislabelled",
            "action": "accept",
            "src": {"kind": "zone", "zone_slug": group["slug"]},
            "dst": {"kind": "any"},
        },
    )
    assert response.status_code == 422
    assert "is a group, not a zone" in response.text


def test_intra_zone_traffic_is_off_until_asked_for(api, tag):
    zone = _zone(api, tag)
    assert zone["intra_zone"] is False
    assert f"fg:intra-zone:{zone['slug']}" not in (
        api.get("/api/v1/ruleset/preview").json()["content"]
    )

    api.patch(f"/api/v1/zones/{zone['id']}", json={"intra_zone": True})
    assert f"fg:intra-zone:{zone['slug']}" in (
        api.get("/api/v1/ruleset/preview").json()["content"]
    )


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #


def test_a_peer_gets_a_dns_name_derived_from_its_own(api, tag):
    peer = _create_peer(api, tag)
    assert peer["dns_label"] == f"peer-{tag}"


def test_two_peers_cannot_take_the_same_name(api, tag):
    """Refused, never silently numbered: a name nobody can predict from the
    dashboard is worse than an error."""
    _create_peer(api, tag, dns_label=f"dup-{tag}")
    response = api.post(
        "/api/v1/peers",
        json={
            "name": f"other-{tag}",
            "peer_type": "server",
            "wg_public_key": wg_key(),
            "dns_label": f"dup-{tag}",
        },
    )
    assert response.status_code == 409


def test_the_zone_endpoint_reports_what_would_be_served(api, tag):
    peer = _create_peer(api, tag, dns_label=f"host-{tag}")
    zone = api.get("/api/v1/dns").json()
    assert zone["errors"] == []
    assert f"{peer['tunnel_ip']}\t{peer['dns_label']}.{zone['zone']}" in zone["hosts"]
    assert f"local=/{zone['zone']}/" in zone["conf"]


def test_an_a_record_can_name_something_off_the_tunnel(api, tag):
    response = api.post(
        "/api/v1/dns/records",
        json={"name": f"nas-{tag}", "kind": "A", "value": _off_tunnel_ip(tag)},
    )
    assert response.status_code == 201, response.text
    zone = api.get("/api/v1/dns").json()
    assert f"{_off_tunnel_ip(tag)}\tnas-{tag}.{zone['zone']}" in zone["hosts"]


def test_a_cname_must_point_at_something_that_exists(api, tag):
    """An alias to an unknown target is a silently dead record, so the API
    refuses it rather than letting the agent skip the whole zone."""
    response = api.post(
        "/api/v1/dns/records",
        json={"name": f"alias-{tag}", "kind": "CNAME", "value": f"ghost-{tag}"},
    )
    assert response.status_code == 409
    assert "not a name this resolver knows" in response.text


def test_a_cname_to_a_real_name_is_accepted_and_served(api, tag):
    peer = _create_peer(api, tag, dns_label=f"target-{tag}")
    response = api.post(
        "/api/v1/dns/records",
        json={"name": f"alias-{tag}", "kind": "CNAME", "value": peer["dns_label"]},
    )
    assert response.status_code == 201, response.text
    zone = api.get("/api/v1/dns").json()
    assert f"cname=alias-{tag}.{zone['zone']},target-{tag}.{zone['zone']}" in zone["conf"]


def test_a_record_fighting_a_peer_for_a_name_is_refused(api, tag):
    peer = _create_peer(api, tag, dns_label=f"taken-{tag}")
    response = api.post(
        "/api/v1/dns/records",
        json={"name": peer["dns_label"], "kind": "A", "value": _off_tunnel_ip(tag, 1)},
    )
    assert response.status_code == 409


def test_an_a_record_rejects_an_ipv6_value(api, tag):
    response = api.post(
        "/api/v1/dns/records",
        json={"name": f"v6-{tag}", "kind": "A", "value": "fd00::1"},
    )
    assert response.status_code == 422


def test_a_revoked_peer_loses_its_name(api, tag):
    """A name resolving to a device that cannot be on the tunnel is a wrong
    answer, not a stale one."""
    peer = _create_peer(api, tag, dns_label=f"gone-{tag}")
    assert f"gone-{tag}." in api.get("/api/v1/dns").json()["hosts"]

    api.patch(f"/api/v1/peers/{peer['id']}", json={"state": "revoked"})
    assert f"gone-{tag}." not in api.get("/api/v1/dns").json()["hosts"]


# --------------------------------------------------------------------------- #
# client configuration profiles
# --------------------------------------------------------------------------- #


def test_a_profile_carries_everything_but_the_key(api, tag):
    peer = _create_peer(api, tag)
    profile = api.get(f"/api/v1/peers/{peer['id']}/config-profile").json()

    assert profile["addresses"] == [f"{peer['tunnel_ip']}/32"]
    assert profile["server_public_key"]
    assert profile["endpoint"]
    assert profile["complete"] is True
    assert any(address.startswith("127.30.") for address in profile["allowed_ips"])


def test_a_profile_never_returns_key_material(api, tag):
    """The endpoint that provisions a device is the one place a well-meaning
    change would add ``private_key`` to the response. Nothing in the body may
    look like a secret -- not the peer's, and not the gateway's."""
    peer = _create_peer(api, tag)
    body = api.get(f"/api/v1/peers/{peer['id']}/config-profile").text.lower()
    for forbidden in ("private", "privatekey", "secret", "presharedkey"):
        assert forbidden not in body, f"the profile mentions {forbidden}"


def test_the_routing_peer_does_not_route_its_own_network(api, tag):
    """A device carrying a network must not pull that network into the tunnel:
    it would lose the LAN it exists to serve, and the tunnel would still come
    up, so nothing would point at the config."""
    zone = _zone(api, tag)
    router = _create_peer(api, f"{tag}-r", zone_slug=zone["slug"])
    laptop = _create_peer(api, f"{tag}-l", zone_slug=zone["slug"])
    api.post(
        f"/api/v1/zones/{zone['id']}/routes",
        json={"cidr": _net(tag), "via_peer_id": router["id"]},
    )

    carrier = api.get(f"/api/v1/peers/{router['id']}/config-profile").json()
    assert _net(tag) not in carrier["allowed_ips"]
    assert carrier["excluded_routes"] == [_net(tag)]
    assert any("carries those networks" in w for w in carrier["warnings"])

    other = api.get(f"/api/v1/peers/{laptop['id']}/config-profile").json()
    assert _net(tag) in other["allowed_ips"]
    assert other["excluded_routes"] == []


def test_the_allowed_ips_mode_can_be_chosen_per_request(api, tag):
    zone = _zone(api, tag)
    peer = _create_peer(api, tag, zone_slug=zone["slug"])
    api.post(f"/api/v1/zones/{zone['id']}/routes", json={"cidr": _net(tag)})

    def profile(**params):
        return api.get(
            f"/api/v1/peers/{peer['id']}/config-profile", params=params
        ).json()

    assert _net(tag) not in profile(allowed_ips="tunnel")["allowed_ips"]
    assert _net(tag) in profile(allowed_ips="zone")["allowed_ips"]
    assert _net(tag) in profile(allowed_ips="routed")["allowed_ips"]
    assert profile(allowed_ips="full")["allowed_ips"] == ["0.0.0.0/0"]


def test_full_tunnel_warns_when_nothing_grants_an_exit(api, tag):
    peer = _create_peer(api, tag)
    profile = api.get(
        f"/api/v1/peers/{peer['id']}/config-profile", params={"allowed_ips": "full"}
    ).json()
    assert any("no internet at all" in w for w in profile["warnings"])

    exit_group = _group(api, tag, slug_prefix="ex", internet_exit=True)
    api.patch(
        f"/api/v1/peers/{peer['id']}", json={"group_slugs": [exit_group["slug"]]}
    )
    profile = api.get(
        f"/api/v1/peers/{peer['id']}/config-profile", params={"allowed_ips": "full"}
    ).json()
    assert not any("no internet at all" in w for w in profile["warnings"])


def test_the_dns_line_can_be_declined(api, tag):
    peer = _create_peer(api, tag)
    with_dns = api.get(f"/api/v1/peers/{peer['id']}/config-profile").json()
    without = api.get(
        f"/api/v1/peers/{peer['id']}/config-profile", params={"dns": "false"}
    ).json()
    assert without["dns"] == []
    # The suite runs with the resolver off, so `with_dns` is empty too; what is
    # asserted is that declining never *adds* anything.
    assert len(without["dns"]) <= len(with_dns["dns"])


def test_an_unknown_peer_has_no_profile(api):
    response = api.get(f"/api/v1/peers/{uuid.uuid4()}/config-profile")
    assert response.status_code == 404


def test_a_nonsense_mode_is_refused(api, tag):
    peer = _create_peer(api, tag)
    response = api.get(
        f"/api/v1/peers/{peer['id']}/config-profile", params={"allowed_ips": "sideways"}
    )
    assert response.status_code == 422


def test_reading_a_profile_is_audited(api, tag):
    """It is the moment a device becomes provisionable, so "who set this laptop
    up" has to be answerable later."""
    peer = _create_peer(api, tag)
    api.get(f"/api/v1/peers/{peer['id']}/config-profile")

    entries = api.get(
        "/api/v1/audit-log", params={"action": "peer.config_profile.read"}
    ).json()
    assert any(entry["object_id"] == peer["id"] for entry in entries)


# --------------------------------------------------------------------------- #
# published services (Phase 6)
# --------------------------------------------------------------------------- #


def _service(api, tag: str, peer: dict, **extra) -> dict:
    body = {
        "slug": f"svc-{tag}",
        "name": f"svc-{tag}",
        "kind": "http",
        "exposure": "internal",
        "upstream_peer_id": peer["id"],
        "upstream_host": peer["tunnel_ip"],
        "upstream_port": 8080,
        # A service and the way in are one request: a listener with no
        # applicable authenticator is refused, so there is no valid two-step.
        "authenticators": [{"kind": "peer_identity", "scope": "internal"}],
    }
    body.update(extra)
    return api.post("/api/v1/services", json=body)


def _active_peer(api, tag: str, **extra) -> dict:
    """A peer the proxy will actually serve: only ``active`` counts."""
    peer = _create_peer(api, tag, **extra)
    response = api.patch(f"/api/v1/peers/{peer['id']}", json={"state": "active"})
    assert response.status_code == 200, response.text
    return response.json()


def test_a_service_is_created_and_gets_a_default_hostname(api, tag):
    peer = _active_peer(api, tag)
    response = _service(api, tag, peer)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["internal_hostname"] == f"svc-{tag}.example.test"
    # Internal only: no external name is invented for a door that does not exist.
    assert body["external_hostname"] is None
    assert body["active_doors"] == "internal"


def test_an_upstream_no_peer_routes_to_is_refused(api, tag):
    """The validator that turns a timeout into a message."""
    peer = _active_peer(api, tag)
    response = _service(api, tag, peer, upstream_host=_off_tunnel_ip(tag))
    assert response.status_code == 422, response.text
    assert "not reachable through" in response.text


def test_a_service_pointing_at_the_portal_is_refused(api, tag):
    """A proxy in front of the portal destroys the identity it runs on."""
    peer = _active_peer(api, tag)
    gateway = api.get("/api/v1/proxy").json()["internal_binds"][0]
    response = _service(
        api, tag, peer, upstream_host=gateway, upstream_port=8080, upstream_peer_id=None
    )
    assert response.status_code == 422, response.text
    assert "source address" in response.text


def test_a_slug_colliding_with_a_group_is_refused(api, tag):
    group = _group(api, tag)
    peer = _active_peer(api, tag)
    response = _service(api, tag, peer, slug=group["slug"])
    assert response.status_code == 409, response.text
    assert "already a group" in response.text


def test_a_plain_tcp_service_is_allocated_a_port(api, tag):
    peer = _active_peer(api, tag)
    response = _service(api, tag, peer, kind="tcp", upstream_port=22)
    assert response.status_code == 201, response.text
    port = response.json()["listen_port"]
    assert port is not None

    other = _service(api, f"{tag}b", peer, kind="tcp", upstream_port=22)
    assert other.status_code == 201, other.text
    assert other.json()["listen_port"] != port


def test_a_service_with_no_authenticator_is_refused_at_creation(api, tag):
    """A door Foxguard cannot describe is not opened.

    Refused at creation rather than left to fail later, which is also why the
    policy travels in the same request: there is no valid intermediate state
    where the service exists and nothing guards it.
    """
    peer = _active_peer(api, tag)
    created = _service(api, tag, peer, authenticators=[])
    assert created.status_code == 422, created.text
    assert "no authenticator" in created.text


def test_peer_identity_scoped_externally_is_refused(api, tag):
    peer = _active_peer(api, tag)
    service = _service(api, tag, peer).json()
    response = api.post(
        f"/api/v1/services/{service['id']}/auth",
        json={"kind": "peer_identity", "scope": "external"},
    )
    assert response.status_code == 422, response.text
    assert "external listener" in response.text
    api.delete(f"/api/v1/services/{service['id']}")


def test_a_refused_authenticator_leaves_no_row_behind(api, tag):
    """The Phase 5 stale-collection bug, guarded against in its new home.

    A rejected child row that commits anyway poisons every later regeneration
    anywhere in the application, so the check is that the *next* unrelated
    write still works.
    """
    peer = _active_peer(api, tag)
    service = _service(api, tag, peer).json()
    api.post(
        f"/api/v1/services/{service['id']}/auth",
        json={"kind": "peer_identity", "scope": "internal"},
    )

    bad = api.post(
        f"/api/v1/services/{service['id']}/auth",
        json={"kind": "basic", "scope": "internal"},
    )
    assert bad.status_code == 422, bad.text

    fetched = api.get(f"/api/v1/services/{service['id']}").json()
    kinds = [row["kind"] for row in fetched["authenticators"]]
    assert "basic" not in kinds, "a refused authenticator was committed anyway"

    # And the ruleset still regenerates from an unrelated endpoint.
    assert _group(api, f"{tag}after")["slug"].endswith(f"{tag}after")
    api.delete(f"/api/v1/services/{service['id']}")


def test_a_token_is_shown_once_and_lands_in_the_rendered_map(api, tag):
    import hashlib

    peer = _active_peer(api, tag)
    service = _service(api, tag, peer).json()
    api.post(
        f"/api/v1/services/{service['id']}/auth",
        json={"kind": "bearer", "scope": "internal"},
    )
    created = api.post(
        f"/api/v1/services/{service['id']}/tokens", json={"name": "ci"}
    )
    assert created.status_code == 201, created.text
    plaintext = created.json()["token"]

    listed = api.get(f"/api/v1/services/{service['id']}/tokens").json()
    assert all("token" not in row for row in listed)

    digest = hashlib.sha256(plaintext.encode()).hexdigest()
    files = api.get("/api/v1/proxy").json()["files"]
    assert digest in files[f"tok_svc-{tag}.map"]
    # Lowercase, because the rendered config lowercases before the lookup.
    assert digest == digest.lower()
    api.delete(f"/api/v1/services/{service['id']}")


def test_revoking_a_token_removes_it_from_the_map(api, tag):
    import hashlib

    peer = _active_peer(api, tag)
    service = _service(api, tag, peer).json()
    api.post(
        f"/api/v1/services/{service['id']}/auth",
        json={"kind": "bearer", "scope": "internal"},
    )
    keep = api.post(f"/api/v1/services/{service['id']}/tokens", json={"name": "keep"})
    drop = api.post(f"/api/v1/services/{service['id']}/tokens", json={"name": "drop"})
    kept = hashlib.sha256(keep.json()["token"].encode()).hexdigest()
    dropped = hashlib.sha256(drop.json()["token"].encode()).hexdigest()

    assert api.delete(
        f"/api/v1/services/{service['id']}/tokens/{drop.json()['id']}"
    ).status_code == 204

    body = api.get("/api/v1/proxy").json()["files"][f"tok_svc-{tag}.map"]
    assert kept in body
    assert dropped not in body
    api.delete(f"/api/v1/services/{service['id']}")


def test_a_service_account_password_is_generated_and_shown_once(api, tag):
    peer = _active_peer(api, tag)
    service = _service(api, tag, peer).json()
    api.post(
        f"/api/v1/services/{service['id']}/auth",
        json={"kind": "basic", "scope": "internal", "realm": "x"},
    )
    created = api.post(
        f"/api/v1/services/{service['id']}/accounts", json={"username": "svc"}
    )
    assert created.status_code == 201, created.text
    password = created.json()["password"]
    assert len(password) >= 24

    listed = api.get(f"/api/v1/services/{service['id']}/accounts").json()
    assert all("password" not in row for row in listed)

    conf = api.get("/api/v1/proxy").json()["config"]
    assert password not in conf, "a plaintext password reached the gateway config"
    assert "$6$" in conf
    api.delete(f"/api/v1/services/{service['id']}")


def test_a_published_service_appears_as_an_implicit_path(api, tag):
    peer = _active_peer(api, tag)
    service = _service(api, tag, peer).json()
    api.post(
        f"/api/v1/services/{service['id']}/auth",
        json={"kind": "peer_identity", "scope": "internal"},
    )
    paths = api.get("/api/v1/proxy").json()["implicit_paths"]
    mine = [p for p in paths if p["service"] == f"svc-{tag}"]
    assert mine, "publishing a service must never open an invisible path"
    assert mine[0]["destination"] == peer["tunnel_ip"]
    assert mine[0]["enforced_by"] == "proxy configuration"
    api.delete(f"/api/v1/services/{service['id']}")


def test_a_service_name_resolves_to_the_gateway_not_the_peer(api, tag):
    """Split-horizon: the proxy is the destination."""
    peer = _active_peer(api, tag)
    service = _service(api, tag, peer).json()
    api.post(
        f"/api/v1/services/{service['id']}/auth",
        json={"kind": "peer_identity", "scope": "internal"},
    )
    zone = api.get("/api/v1/dns").json()
    hosts = zone.get("hosts") or ""
    if hosts:
        line = [ln for ln in hosts.splitlines() if f"svc-{tag}.example.test" in ln]
        assert line, hosts
        assert peer["tunnel_ip"] not in line[0]
    api.delete(f"/api/v1/services/{service['id']}")


def test_the_agent_receives_the_proxy_configuration(api, tag):
    peer = _active_peer(api, tag)
    service = _service(api, tag, peer).json()
    api.post(
        f"/api/v1/services/{service['id']}/auth",
        json={"kind": "peer_identity", "scope": "internal"},
    )
    state = api.get("/api/v1/agent/state").json()
    assert state["proxy"] is not None
    assert state["proxy"]["digest"] == api.get("/api/v1/proxy").json()["digest"]
    assert f"svc-{tag}" in state["proxy"]["conf"]
    # The pattern files travel with it: haproxy -c resolves -f at parse time.
    assert state["proxy"]["files"]
    api.delete(f"/api/v1/services/{service['id']}")


def test_deleting_a_service_removes_it_from_the_rendered_config(api, tag):
    peer = _active_peer(api, tag)
    service = _service(api, tag, peer).json()
    api.post(
        f"/api/v1/services/{service['id']}/auth",
        json={"kind": "peer_identity", "scope": "internal"},
    )
    assert f"svc-{tag}" in api.get("/api/v1/proxy").json()["config"]

    assert api.delete(f"/api/v1/services/{service['id']}").status_code == 204
    assert f"svc-{tag}" not in (api.get("/api/v1/proxy").json()["config"] or "")


def test_a_tcp_service_refuses_an_http_authenticator(api, tag):
    peer = _active_peer(api, tag)
    service = _service(api, tag, peer, kind="tcp", upstream_port=22).json()
    assert "id" in service, service
    response = api.post(
        f"/api/v1/services/{service['id']}/auth",
        json={"kind": "bearer", "scope": "internal"},
    )
    assert response.status_code == 422, response.text
    assert "plaintext" in response.text
    api.delete(f"/api/v1/services/{service['id']}")


# --------------------------------------------------------------------------- #
# single sign-on (Phase 7c)
# --------------------------------------------------------------------------- #


def _sso_enabled(api) -> bool:
    """The e2e server only configures SSO when the environment says so."""
    body = api.get("/api/v1/proxy").json()
    return bool(body.get("domain"))


def test_the_login_page_renders_without_a_session(api):
    response = api.get("/api/v1/sso/login")
    if response.status_code == 503:
        pytest.skip("FOXGUARD_PROXY_SSO_SECRET is not set on this server")
    assert response.status_code == 200
    assert "Sign in" in response.text
    # The page must not leak whether a destination exists before sign-in.
    assert "password" in response.text


def test_an_unknown_redirect_target_is_refused(api, tag):
    """A login page that redirects wherever ?h= says is a phishing hop."""
    response = api.get("/api/v1/sso/login", params={"h": "evil.example.net", "p": "/"})
    if response.status_code == 503:
        pytest.skip("SSO is not configured on this server")
    assert response.status_code == 200
    assert "not a published service" in response.text


def test_signing_in_with_bad_credentials_says_nothing_useful(api, tag):
    response = api.post(
        "/api/v1/sso/login",
        data={"username": f"ghost-{tag}", "password": "wrong", "totp": "", "h": "", "p": ""},
    )
    if response.status_code == 503:
        pytest.skip("SSO is not configured on this server")
    assert response.status_code == 401
    # One message for a bad password, a bad code and an unknown account.
    assert "did not work" in response.text
    assert "no such account" not in response.text


def test_a_non_admin_can_sign_in_for_services_but_gets_no_admin_session(api, tag):
    """The point of SSO: an ordinary account, and a cookie that is not an admin token."""
    username = f"person-{tag}"
    password = "correct-horse-battery-staple"
    created = api.post(
        "/api/v1/users",
        json={"username": username, "password": password, "is_admin": False},
    )
    assert created.status_code == 201, created.text

    response = api.post(
        "/api/v1/sso/login",
        data={"username": username, "password": password, "totp": "", "h": "", "p": ""},
        follow_redirects=False,
    )
    if response.status_code == 503:
        pytest.skip("SSO is not configured on this server")
    assert response.status_code == 303, response.text
    cookie = response.headers.get("set-cookie", "")
    assert "fg_sso=" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie

    # The same account is still refused an *admin* session.
    admin = api.post(
        "/api/v1/admin/login", json={"username": username, "password": password}
    )
    assert admin.status_code in (401, 403), admin.text


def test_a_session_appears_and_can_be_revoked(api, tag):
    username = f"revme-{tag}"
    password = "correct-horse-battery-staple"
    api.post(
        "/api/v1/users",
        json={"username": username, "password": password, "is_admin": False},
    )
    login = api.post(
        "/api/v1/sso/login",
        data={"username": username, "password": password, "totp": "", "h": "", "p": ""},
        follow_redirects=False,
    )
    if login.status_code == 503:
        pytest.skip("SSO is not configured on this server")
    assert login.status_code == 303

    sessions = api.get("/api/v1/proxy/sso-sessions").json()
    mine = [row for row in sessions if row["username"] == username]
    assert mine, sessions
    # Nothing resembling a token is stored or shown: the proxy verifies the
    # signature itself, so there is nothing here to leak.
    assert "token" not in mine[0]

    assert api.delete(f"/api/v1/proxy/sso-sessions/{mine[0]['id']}").status_code == 204
    after = api.get("/api/v1/proxy/sso-sessions").json()
    assert not [row for row in after if row["username"] == username]
