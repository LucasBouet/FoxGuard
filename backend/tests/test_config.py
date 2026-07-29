"""Settings parsing tests.

These exist because a bad env-var parse is a *startup crash*, not a runtime
error: `Settings()` is called at import time by `foxguard.db`, so the API never
comes up and the failure is a stack trace rather than a message.
"""

from __future__ import annotations

import pytest

from foxguard.config import Settings
from foxguard.nftables import GatewayInputPolicy


def _settings(**overrides) -> Settings:
    base = {"dev_mode": True, "_env_file": None}
    base.update(overrides)
    return Settings(**base)


def test_internal_cidrs_accepts_the_documented_comma_separated_form(monkeypatch):
    """`.env.example` documents `a,b,c`; pydantic-settings would JSON-decode it."""
    monkeypatch.setenv("FOXGUARD_DEV_MODE", "true")
    monkeypatch.setenv("FOXGUARD_INTERNAL_CIDRS", "10.0.0.0/8,192.168.0.0/16")
    assert Settings(_env_file=None).internal_cidrs == ["10.0.0.0/8", "192.168.0.0/16"]


def test_internal_cidrs_accepts_json(monkeypatch):
    monkeypatch.setenv("FOXGUARD_DEV_MODE", "true")
    monkeypatch.setenv("FOXGUARD_INTERNAL_CIDRS", '["10.0.0.0/8"]')
    assert Settings(_env_file=None).internal_cidrs == ["10.0.0.0/8"]


def test_internal_cidrs_tolerates_spaces_and_empty_entries(monkeypatch):
    monkeypatch.setenv("FOXGUARD_DEV_MODE", "true")
    monkeypatch.setenv("FOXGUARD_INTERNAL_CIDRS", " 10.0.0.0/8 , ,192.168.0.0/16 ")
    assert Settings(_env_file=None).internal_cidrs == ["10.0.0.0/8", "192.168.0.0/16"]


def test_an_invalid_cidr_is_rejected_at_startup(monkeypatch):
    monkeypatch.setenv("FOXGUARD_DEV_MODE", "true")
    monkeypatch.setenv("FOXGUARD_INTERNAL_CIDRS", "10.0.0.0/8,nonsense")
    with pytest.raises(ValueError):
        Settings(_env_file=None)


def test_production_mode_requires_both_tokens(monkeypatch):
    for name in ("FOXGUARD_ADMIN_API_TOKEN", "FOXGUARD_AGENT_API_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FOXGUARD_DEV_MODE", "false")
    with pytest.raises(ValueError, match="ADMIN_API_TOKEN"):
        Settings(_env_file=None)


def test_dev_mode_starts_without_tokens():
    assert _settings().admin_api_token is None


def test_gateway_ip_defaults_to_the_first_host_of_the_pool():
    assert _settings(wg_pool_v4="10.88.0.0/24").gateway_ip == "10.88.0.1"


def test_gateway_ip_can_be_overridden():
    settings = _settings(wg_pool_v4="10.88.0.0/24", wg_gateway_ip="10.88.0.254")
    assert settings.gateway_ip == "10.88.0.254"


def test_gateway_spec_projection_carries_every_dataplane_setting():
    settings = _settings(
        wg_interface="wg1",
        wan_interface="eth1",
        portal_port=9443,
        internal_cidrs=["172.16.0.0/12"],
        gateway_input_policy="restricted",
        allow_dns_in_quarantine=False,
    )
    spec = settings.gateway_spec()

    assert spec.wg_interface == "wg1"
    assert spec.wan_interface == "eth1"
    assert spec.portal_port == 9443
    assert spec.internal_cidrs == ("172.16.0.0/12",)
    assert spec.gateway_input_policy is GatewayInputPolicy.RESTRICTED
    assert spec.allow_dns_in_quarantine is False


def test_a_v6_pool_in_the_v4_slot_is_rejected():
    with pytest.raises(ValueError, match="not an IPv4 network"):
        _settings(wg_pool_v4="fd00::/64")


def test_a_v4_pool_in_the_v6_slot_is_rejected():
    with pytest.raises(ValueError, match="not an IPv6 network"):
        _settings(wg_pool_v6="10.88.0.0/24")
