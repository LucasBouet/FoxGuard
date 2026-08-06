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

Authentication is not authorization, and for one release it was: any account
that could sign in reached every SSO-protected service. The token now carries
the caller's groups so the proxy can require membership, and the shape of that
claim is measured too -- see :func:`group_claim`.
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
from ..models import GroupKind, SsoSession, User

logger = logging.getLogger(__name__)

__all__ = [
    "ALGORITHM",
    "GROUP_DELIMITER",
    "MIN_SECRET_LENGTH",
    "group_claim",
    "issue",
    "member_slugs",
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

#: Separates group slugs in the ``groups`` claim, and wraps the whole value.
#: Safe because ``ck_groups_slug_format`` restricts a slug to
#: ``[a-z0-9][a-z0-9_-]{0,23}``, so a slug can never contain one.
GROUP_DELIMITER = ","


def group_claim(slugs: list[str]) -> str:
    """Group membership, in the one shape HAProxy can match cheaply.

    A delimited string rather than the obvious JSON array, and both halves of
    that are measured against HAProxy 3.0.11:

    * ``jwt_payload_query('$.groups')`` on an array claim returns the **raw
      JSON text**, quotes and brackets included -- ``["infra","ops"]``. Matching
      membership in that means embedding quotes in config patterns.
    * ``$.groups[0]`` works but yields only the first element, which answers a
      question nobody asked.
    * A value wrapped and separated by commas answers it in one condition:
      ``-m sub ,infra,`` matches, several patterns on one condition are an
      **OR**, and the wrapping is what stops the false positives -- measured,
      ``,inf,`` does not match ``,infra,ops,`` and ``,infra,`` does not match
      ``,infrastructure,``.

    A person in no groups gets a lone delimiter, which matches no requirement.
    """
    if not slugs:
        return GROUP_DELIMITER
    joined = GROUP_DELIMITER.join(slugs)
    return f"{GROUP_DELIMITER}{joined}{GROUP_DELIMITER}"


def member_slugs(user: User) -> list[str]:
    """The groups a person is in, sorted, zones excluded.

    Zones are filtered here as well as refused by the API, so a hand-inserted
    row fails closed: a zone is a routed segment and a person does not sit in
    one, so a service asking for one must find nobody rather than everybody.
    """
    return sorted(
        group.slug for group in user.groups if group.kind is GroupKind.GROUP
    )


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
        # Baked in at issue time, which is why changing somebody's membership
        # revokes their sessions: see revoke_for_user's callers.
        "groups": group_claim(member_slugs(user)),
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
    """End every session a person holds.

    Used when an account is disabled, and when its **group membership changes**.
    The second is not optional: the groups are a claim inside a token the proxy
    verifies without asking anyone, so removing somebody from a group would
    otherwise keep letting them in until their cookie happened to expire. Taking
    an access away has to mean now.
    """
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
