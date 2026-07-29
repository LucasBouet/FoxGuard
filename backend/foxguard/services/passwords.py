"""Local-account password hashing.

Argon2id via ``argon2-cffi``. Kept behind a tiny module so the algorithm can be
swapped without touching routes, and so hashes carry their own parameters
(``$argon2id$v=19$m=...``) and can be rehashed on login when the cost changes.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

__all__ = ["burn", "hash_password", "verify_password", "needs_rehash"]

# Defaults follow the argon2-cffi recommendations; ~64 MiB is fine for a
# gateway that authenticates a handful of humans per hour.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

#: A real hash of a value nobody knows, used to spend the same ~100ms on a
#: request for an account that does not exist as on one that does.
_DUMMY_HASH = _hasher.hash("foxguard-timing-equalisation-placeholder")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str | None) -> bool:
    if not stored_hash:
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def burn(password: str | None = None) -> None:
    """Verify against a throwaway hash so failures cost what successes cost.

    Argon2 is deliberately slow, which makes "user not found" (instant) trivially
    distinguishable from "wrong password" (~100ms) by anyone with a stopwatch.
    On a captive portal that difference is a username oracle, so the login path
    calls this whenever it has no hash to check.
    """
    verify_password(password or "", _DUMMY_HASH)


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True
