"""TOTP (RFC 6238) for local accounts.

Optional, per user, and only meaningful for local passwords: an OIDC account's
second factor is the IdP's business, and asking for two would be theatre.

Two things here are not just "call pyotp":

**Enrolment is confirmed before it is enforced.** ``provision`` stores a secret
but leaves ``totp_enabled`` false. Only a correct code flips the flag. Skipping
that step is how an admin locks a user out of their own account with a secret
that never made it into an authenticator app.

**A code cannot be replayed.** RFC 6238 §5.2 requires it, and it is the
difference between "the attacker needs the current code" and "the attacker
needs a code from the last ~90 seconds". :func:`verify` returns the time step it
matched so the caller can persist it in ``users.totp_last_used_step`` and refuse
anything at or below that step next time.
"""

from __future__ import annotations

import hmac
from datetime import UTC, datetime

import pyotp

__all__ = [
    "INTERVAL_SECONDS",
    "current_step",
    "generate_secret",
    "provisioning_uri",
    "verify",
]

#: Standard 30-second step. Changing it would invalidate every enrolled device.
INTERVAL_SECONDS = 30

#: How many steps either side of "now" are accepted, to absorb clock skew
#: between the gateway and a phone. One step each way is the usual compromise:
#: it tolerates ~30s of drift while keeping the replay window short.
_SKEW_STEPS = 1


def generate_secret() -> str:
    """A fresh base32 secret. Shown once, at provisioning time."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, *, username: str, issuer: str) -> str:
    """``otpauth://`` URI for a QR code or manual entry."""
    return pyotp.TOTP(secret, interval=INTERVAL_SECONDS).provisioning_uri(
        name=username, issuer_name=issuer
    )


def current_step(now: datetime | None = None) -> int:
    now = now or datetime.now(UTC)
    return int(now.timestamp()) // INTERVAL_SECONDS


def verify(
    secret: str | None,
    code: str | None,
    *,
    last_used_step: int | None = None,
    now: datetime | None = None,
) -> int | None:
    """Return the time step ``code`` matched, or ``None`` if it does not.

    ``last_used_step`` makes verification single-use: a code is refused if its
    step was already spent, even while it is still within the skew window.
    """
    if not secret or not code:
        return None
    candidate = code.strip().replace(" ", "")
    if not candidate.isdigit():
        return None

    totp = pyotp.TOTP(secret, interval=INTERVAL_SECONDS)
    step = current_step(now)
    for offset in range(-_SKEW_STEPS, _SKEW_STEPS + 1):
        tested = step + offset
        if last_used_step is not None and tested <= last_used_step:
            continue
        expected = totp.at(tested * INTERVAL_SECONDS)
        # compare_digest rather than ==: the comparison is against a secret-derived
        # value, and short-circuiting on the first differing digit leaks it.
        if hmac.compare_digest(expected, candidate):
            return tested
    return None
