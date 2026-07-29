"""Enrollment key generation, hashing, verification and expiry."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from foxguard.services import enrollment

NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# generation
# --------------------------------------------------------------------------- #


def test_keys_are_prefixed_so_a_leaked_one_is_recognisable():
    assert enrollment.generate_key().startswith("fgk_")


def test_keys_are_not_reused():
    assert len({enrollment.generate_key() for _ in range(200)}) == 200


def test_keys_carry_enough_entropy_to_be_unguessable():
    # token_urlsafe(32) is 32 random bytes -> 43 base64url characters.
    assert len(enrollment.generate_key(32)) - len("fgk_") >= 43


# --------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------- #


def test_the_plaintext_key_never_appears_in_what_is_stored():
    """A database dump must not yield working keys."""
    key = enrollment.generate_key()
    assert key not in enrollment.hash_key(key)


def test_the_same_key_hashes_differently_every_time():
    """Per-key salt: identical keys on two peers must not look identical."""
    key = enrollment.generate_key()
    assert enrollment.hash_key(key) != enrollment.hash_key(key)


def test_a_hash_records_its_algorithm():
    assert enrollment.hash_key("k").startswith("sha256$")


# --------------------------------------------------------------------------- #
# verification
# --------------------------------------------------------------------------- #


def test_the_right_key_verifies():
    key = enrollment.generate_key()
    assert enrollment.verify_key(key, enrollment.hash_key(key)) is True


def test_a_different_key_does_not():
    assert enrollment.verify_key("fgk_nope", enrollment.hash_key(enrollment.generate_key())) is False


@pytest.mark.parametrize("stored", [None, "", "garbage", "sha256$only-one-field", "md5$a$b"])
def test_a_missing_or_malformed_hash_is_a_failure_not_a_crash(stored):
    """A peer with no key must refuse enrollment, not 500."""
    assert enrollment.verify_key("fgk_anything", stored) is False


def test_verification_of_an_empty_key_fails():
    key = enrollment.generate_key()
    assert enrollment.verify_key("", enrollment.hash_key(key)) is False


# --------------------------------------------------------------------------- #
# expiry
# --------------------------------------------------------------------------- #


def test_no_expiry_means_never_expires():
    assert enrollment.is_expired(None, now=NOW) is False


def test_a_future_expiry_has_not_passed():
    assert enrollment.is_expired(NOW + timedelta(seconds=1), now=NOW) is False


def test_a_past_expiry_has():
    assert enrollment.is_expired(NOW - timedelta(seconds=1), now=NOW) is True


def test_expiry_is_inclusive_at_the_boundary():
    """A key that expires "now" is spent, not still usable for one more call."""
    assert enrollment.is_expired(NOW, now=NOW) is True


def test_a_naive_timestamp_is_read_as_utc():
    """PostgreSQL can hand back a naive datetime; treating it as local time
    would silently shift every expiry by the box's offset."""
    assert enrollment.is_expired(NOW.replace(tzinfo=None) - timedelta(hours=1), now=NOW) is True
    assert enrollment.is_expired(NOW.replace(tzinfo=None) + timedelta(hours=1), now=NOW) is False
