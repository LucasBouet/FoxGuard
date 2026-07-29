"""TOTP: skew tolerance, and the replay guard that skew tolerance makes necessary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pyotp
import pytest

from foxguard.services import totp as totp_service

NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)


@pytest.fixture()
def secret() -> str:
    return totp_service.generate_secret()


def code_at(secret: str, moment: datetime) -> str:
    return pyotp.TOTP(secret, interval=totp_service.INTERVAL_SECONDS).at(moment)


# --------------------------------------------------------------------------- #
# the happy path and the obvious failures
# --------------------------------------------------------------------------- #


def test_the_current_code_verifies(secret):
    assert totp_service.verify(secret, code_at(secret, NOW), now=NOW) is not None


def test_a_wrong_code_does_not(secret):
    assert totp_service.verify(secret, "000000", now=NOW) is None


@pytest.mark.parametrize("code", [None, "", "   ", "abcdef", "12 34 56x"])
def test_junk_is_rejected_without_raising(secret, code):
    assert totp_service.verify(secret, code, now=NOW) is None


def test_no_secret_means_no_verification(secret):
    assert totp_service.verify(None, code_at(secret, NOW), now=NOW) is None


def test_a_code_from_another_secret_is_rejected(secret):
    other = totp_service.generate_secret()
    assert totp_service.verify(secret, code_at(other, NOW), now=NOW) is None


# --------------------------------------------------------------------------- #
# clock skew
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("offset", [-30, 0, 30])
def test_one_step_of_drift_each_way_is_tolerated(secret, offset):
    """A phone whose clock is half a minute out must still work."""
    moment = NOW + timedelta(seconds=offset)
    assert totp_service.verify(secret, code_at(secret, moment), now=NOW) is not None


@pytest.mark.parametrize("offset", [-90, -60, 60, 90])
def test_further_drift_is_not(secret, offset):
    moment = NOW + timedelta(seconds=offset)
    assert totp_service.verify(secret, code_at(secret, moment), now=NOW) is None


# --------------------------------------------------------------------------- #
# replay (RFC 6238 section 5.2)
# --------------------------------------------------------------------------- #


def test_a_code_cannot_be_used_twice(secret):
    """Without this a code stays usable for the whole ~90s skew window."""
    code = code_at(secret, NOW)
    step = totp_service.verify(secret, code, now=NOW)
    assert step is not None
    assert totp_service.verify(secret, code, last_used_step=step, now=NOW) is None


def test_an_older_code_cannot_be_replayed_after_a_newer_one(secret):
    """Accepting step-1 after step has been spent would reopen the window."""
    previous = code_at(secret, NOW - timedelta(seconds=30))
    current_step = totp_service.verify(secret, code_at(secret, NOW), now=NOW)
    assert totp_service.verify(secret, previous, last_used_step=current_step, now=NOW) is None


def test_the_next_code_still_works_after_one_is_spent(secret):
    """The replay guard must not lock the account until the window rolls over."""
    step = totp_service.verify(secret, code_at(secret, NOW), now=NOW)
    later = NOW + timedelta(seconds=30)
    assert totp_service.verify(secret, code_at(secret, later), last_used_step=step, now=later)


def test_the_returned_step_is_the_one_that_matched(secret):
    later = NOW + timedelta(seconds=30)
    assert totp_service.verify(secret, code_at(secret, later), now=NOW) == totp_service.current_step(later)


# --------------------------------------------------------------------------- #
# provisioning
# --------------------------------------------------------------------------- #


def test_secrets_are_not_reused():
    assert len({totp_service.generate_secret() for _ in range(50)}) == 50


def test_the_provisioning_uri_identifies_the_account_and_the_gateway(secret):
    uri = totp_service.provisioning_uri(secret, username="ada", issuer="Foxguard")
    assert uri.startswith("otpauth://totp/")
    assert "ada" in uri
    assert "issuer=Foxguard" in uri
    assert secret in uri


def test_a_provisioned_secret_produces_codes_this_module_accepts(secret):
    """Guards against the URI and the verifier disagreeing about the interval."""
    uri = totp_service.provisioning_uri(secret, username="ada", issuer="Foxguard")
    parsed = pyotp.parse_uri(uri)
    assert totp_service.verify(secret, parsed.at(NOW), now=NOW) is not None
