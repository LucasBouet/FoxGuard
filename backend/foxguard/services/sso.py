"""Single sign-on for published services.

A person opens `grafana.example.com`, has no session, is sent to a Foxguard
login page, signs in with the account they already have, and comes back with a
cookie every published service accepts.

**The proxy verifies the cookie itself.** It is a signed JWT and HAProxy checks
the signature natively, so a request to a published service costs no round trip
to the control plane and keeps working while the API is restarting. That is a
deliberate departure from "forward-auth" as first sketched: the login page and
the redirect still need Foxguard, but per-request validation does not, and
coupling every request on a published service to the API's availability was a
worse trade than it looked.

What that costs is revocation, and it is bought back explicitly: the session's
``jti`` goes into a HAProxy map on revoke, pushed over the runtime socket, so
"sign this person out" means now rather than "within the token lifetime".

Three things about the verification are **measured, not assumed**, and all three
shape what :mod:`foxguard.proxy.haproxy` emits.

1.  **The algorithm is pinned, never read from the token.** Measured against
    HAProxy 3.0.11: a token carrying ``{"alg":"none"}`` and no signature at all
    is accepted with ``jwt_verify(<alg from the token's own header>, ...)``
    returning **1**. Pinning the algorithm to a value we set makes the same
    token return -3. The idiomatic snippet is forgeable; this is not a
    stylistic preference.
2.  **``jwt_verify`` does not look at ``exp``.** An expired token verifies
    happily. Expiry is compared against ``date()`` as a separate condition.
3.  **Only ``1`` means verified.** The converter returns negative values for
    "invalid token", "unknown algorithm" and so on, and a bare truthiness test
    would accept those.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from joserfc import jwt
from joserfc.jwk import OctKey
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import SsoSession, User

logger = logging.getLogger(__name__)

__all__ = [
    "ALGORITHM",
    "MIN_SECRET_LENGTH",
    "issue",
    "revoke",
    "revoked_jtis",
    "secret_problem",
    "sweep_expired",
]

#: The one algorithm Foxguard issues and the one the proxy is told to expect.
#: Symmetric because the same box does both; there is no third party to verify.
ALGORITHM = "HS256"

#: HS256 keys shorter than the hash are trivially weaker than the construction
#: allows. Enforced at startup rather than discovered by an attacker.
MIN_SECRET_LENGTH = 32


def secret_problem(settings: Settings) -> str | None:
    """Why SSO cannot be enabled, or ``None``.

    Checked wherever SSO is switched on rather than at import time: the proxy
    can be perfectly useful with no SSO service on it, and refusing to start the
    whole control plane over an unset optional secret would be wrong.
    """
    secret = settings.proxy_sso_secret_value
    if not secret:
        return (
            "FOXGUARD_PROXY_SSO_SECRET is unset. Foxguard signs the session "
            "cookie with it and the proxy verifies with the same value, so "
            "there is nothing to sign with"
        )
    if len(secret) < MIN_SECRET_LENGTH:
        return (
            f"FOXGUARD_PROXY_SSO_SECRET is {len(secret)} characters; "
            f"HS256 wants at least {MIN_SECRET_LENGTH}"
        )
    return None


def _key(settings: Settings) -> OctKey:
    return OctKey.import_key(settings.proxy_sso_secret_value)


def issue(
    session: Session,
    settings: Settings,
    user: User,
    *,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, SsoSession]:
    """Create a session row and the signed cookie value that names it.

    The row's id *is* the ``jti``. One identifier, so revoking needs no lookup
    and the map entry the proxy reads is the primary key.
    """
    problem = secret_problem(settings)
    if problem:
        raise ValueError(problem)

    now = datetime.now(UTC)
    expires = now + timedelta(seconds=settings.proxy_sso_lifetime_seconds)
    row = SsoSession(
        id=uuid.uuid4(),
        user_id=user.id,
        source_ip=source_ip,
        user_agent=(user_agent or "")[:255] or None,
        expires_at=expires,
    )
    session.add(row)

    claims = {
        "sub": user.username,
        "jti": str(row.id),
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        # An int, not a bool: HAProxy's jwt_payload_query only supports "int" as
        # an output type. Measured -- 'bool' is a config parse error.
        "admin": 1 if user.is_admin else 0,
    }
    token = jwt.encode({"alg": ALGORITHM, "typ": "JWT"}, claims, _key(settings))
    return token, row


def revoke(session: Session, settings: Settings, session_id: uuid.UUID) -> bool:
    """End one session now.

    Returns whether anything changed. The caller regenerates the proxy
    configuration afterwards, which puts the ``jti`` in the denylist map; the
    agent pushes that map over the runtime socket without a reload.
    """
    result = session.execute(
        update(SsoSession)
        .where(SsoSession.id == session_id, SsoSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    return result.rowcount > 0


def revoke_for_user(session: Session, user_id: uuid.UUID) -> int:
    """End every session a person holds. Used when an account is disabled."""
    result = session.execute(
        update(SsoSession)
        .where(SsoSession.user_id == user_id, SsoSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    return result.rowcount


def revoked_jtis(session: Session) -> list[str]:
    """Session ids the proxy must refuse, even though their signature is good.

    Only sessions that have been revoked **and have not expired yet**. An
    expired one is already refused by the expiry comparison, and keeping it here
    would grow the map forever for no effect.
    """
    rows = (
        session.execute(
            select(SsoSession.id)
            .where(
                SsoSession.revoked_at.is_not(None),
                SsoSession.expires_at > datetime.now(UTC),
            )
            .order_by(SsoSession.id)
        )
        .scalars()
        .all()
    )
    return [str(row) for row in rows]


def sweep_expired(session: Session) -> int:
    """Delete sessions past their expiry.

    Safe precisely because the token carries its own ``exp`` and the proxy
    checks it: deleting the row cannot resurrect anything.
    """
    rows = (
        session.execute(select(SsoSession).where(SsoSession.expires_at < datetime.now(UTC)))
        .scalars()
        .all()
    )
    for row in rows:
        session.delete(row)
    return len(rows)
