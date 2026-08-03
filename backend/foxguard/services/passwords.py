"""Local-account password hashing.

Argon2id via ``argon2-cffi``. Kept behind a tiny module so the algorithm can be
swapped without touching routes, and so hashes carry their own parameters
(``$argon2id$v=19$m=...``) and can be rehashed on login when the cost changes.
"""

from __future__ import annotations

import hashlib

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from passlib.hash import sha512_crypt

__all__ = [
    "CRYPT_ROUNDS",
    "burn",
    "crypt_hash",
    "hash_password",
    "needs_rehash",
    "token_digest",
    "verify_password",
]

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


# --------------------------------------------------------------------------- #
# credentials the gateway verifies itself (Phase 6)
# --------------------------------------------------------------------------- #

#: sha-512-crypt rounds for service accounts. **Not** a security parameter here,
#: and deliberately the crypt(3) default rather than passlib's.
#:
#: HAProxy re-verifies the hash on *every request*, and passlib's default of
#: 656000 rounds is ruinous there. Measured against real HAProxy 3.0.11:
#: 656000 rounds costs 267 ms per request -- a 3 req/s ceiling -- against 15 ms
#: at 5000. Stretching buys nothing anyway, because the password is a generated
#: 192-bit secret with no dictionary behind it; rounds defend low-entropy human
#: passwords, which is exactly why those are not allowed to reach this table.
CRYPT_ROUNDS = 5000


def crypt_hash(password: str) -> str:
    """A ``$6$`` sha-512-crypt hash HAProxy's ``userlist`` can verify.

    Only ever called with a generated password -- see the note above and
    ``api/routes/services.create_account``.
    """
    return sha512_crypt.using(rounds=CRYPT_ROUNDS).hash(password)


def token_digest(token: str) -> str:
    """Lowercase SHA-256 hex of a bearer token, **unsalted**.

    The one unsalted secret digest in Foxguard, and it has to be: verification
    happens inside HAProxy, which computes ``sha2(256)`` over the presented
    token and looks the result up in a map. There is no way to give it a salt.

    Acceptable because the token is a generated 256-bit secret: a salt defends
    against precomputation across a corpus of guessable secrets, and there is
    no guessing this. Lowercase because HAProxy's ``hex`` converter emits
    uppercase and the rendered configuration appends ``,lower`` to match --
    measured, and the failure mode without it is a silent 403.
    """
    return hashlib.sha256(token.encode()).hexdigest()
