"""Enrollment keys for *server* peers.

Threat model: the key is a bearer secret provisioned once onto a machine that
has no human behind it. Therefore:

* it is generated with :mod:`secrets`, never from a PRNG seeded by time;
* only a hash is stored, so a database dump does not yield working keys;
* verification is constant-time and always hashes, even for unknown peers, so
  timing does not reveal which peer ids exist;
* an optional expiry makes short-lived machines (a lab / CTF box) safe by
  default without requiring the admin to remember a manual revocation.

The hash is a plain salted SHA-256 rather than argon2 because the input is a
256-bit random secret, not a human password: there is nothing to brute force.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime

__all__ = [
    "generate_key",
    "hash_key",
    "verify_key",
    "is_expired",
]

_PREFIX = "fgk_"
_HASH_PREFIX = "sha256$"


def generate_key(nbytes: int = 32) -> str:
    """Return a fresh enrollment key. Shown to the admin exactly once."""
    return _PREFIX + secrets.token_urlsafe(nbytes)


def hash_key(key: str, *, salt: str | None = None) -> str:
    """Return ``sha256$<salt>$<digest>`` for storage."""
    salt = salt or secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt}{key}".encode()).hexdigest()
    return f"{_HASH_PREFIX}{salt}${digest}"


def verify_key(key: str, stored: str | None) -> bool:
    """Constant-time verification. Returns False for missing/malformed hashes."""
    if not stored or not stored.startswith(_HASH_PREFIX):
        # Still burn a hash so the timing profile matches the success path.
        hash_key(key or "", salt="00000000000000000000000000000000")
        return False
    try:
        _, salt, digest = stored.split("$", 2)
    except ValueError:
        return False
    candidate = hashlib.sha256(f"{salt}{key}".encode()).hexdigest()
    return hmac.compare_digest(candidate, digest)


def is_expired(expires_at: datetime | None, *, now: datetime | None = None) -> bool:
    if expires_at is None:
        return False
    now = now or datetime.now(UTC)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at <= now
