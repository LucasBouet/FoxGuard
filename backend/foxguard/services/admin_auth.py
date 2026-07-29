"""Administrator sign-in.

Phase 1 shipped a single shared bearer token, which made every audit entry say
``admin-api``. That is fine for a machine and useless for a person: "who fired
the kill switch" had no answer.

This module issues per-person sessions against the same ``users`` table the
portal uses, so one account can be both a device owner and an administrator, and
`is_admin` is finally an authorisation boundary rather than a label.

Session tokens are high-entropy random secrets, so they are stored as a salted
SHA-256 -- the same reasoning as enrollment keys, and the same reason human
passwords are *not* stored that way. Lookup is by hash, and the plaintext exists
only in the response to a successful login.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..models import ActorType, AdminSession, User
from . import passwords
from . import totp as totp_service

logger = logging.getLogger(__name__)

__all__ = [
    "AdminIdentity",
    "AuthOutcome",
    "authenticate",
    "hash_token",
    "issue",
    "resolve",
    "revoke",
    "revoke_all_for_user",
]

_PREFIX = "fga_"
_HASH_PREFIX = "sha256$"


@dataclass(frozen=True, slots=True)
class AdminIdentity:
    """Who is making an admin request, for authorisation and for the audit log."""

    actor_type: ActorType
    user_id: object | None = None
    label: str = "admin-api"

    @property
    def is_person(self) -> bool:
        return self.user_id is not None

    @classmethod
    def machine(cls) -> AdminIdentity:
        """The static token: automation, provisioning scripts, CI."""
        return cls(actor_type=ActorType.SYSTEM, label="admin-token")

    @classmethod
    def person(cls, user: User) -> AdminIdentity:
        return cls(actor_type=ActorType.ADMIN, user_id=user.id, label=user.username)


@dataclass(frozen=True, slots=True)
class AuthOutcome:
    """Result of a login attempt. ``reason`` is for the audit log, never the caller."""

    user: User | None = None
    reason: str = ""

    def __bool__(self) -> bool:
        return self.user is not None


def hash_token(token: str, *, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt}{token}".encode()).hexdigest()
    return f"{_HASH_PREFIX}{salt}${digest}"


def _verify_hash(token: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split("$", 2)
    except ValueError:
        return False
    candidate = hashlib.sha256(f"{salt}{token}".encode()).hexdigest()
    return hmac.compare_digest(candidate, digest)


def authenticate(
    session: Session, *, username: str, password: str, totp_code: str | None
) -> AuthOutcome:
    """Check an administrator's credentials. Does not create a session.

    Every failure costs the same argon2 work as a success, so response timing
    does not reveal which usernames exist or which of them are administrators.
    """
    user = session.execute(
        select(User).where(User.username == username).limit(1)
    ).scalar_one_or_none()

    if user is None:
        passwords.burn(password)
        return AuthOutcome(reason="no such account")
    if not user.is_active:
        passwords.burn(password)
        return AuthOutcome(reason="account disabled")
    if not user.is_admin:
        # Burn anyway: otherwise a non-admin account answers faster than an
        # admin one, which maps out who the administrators are.
        passwords.burn(password)
        return AuthOutcome(reason="not an administrator")
    if not passwords.verify_password(password, user.password_hash):
        return AuthOutcome(reason="wrong password")

    if user.totp_enabled:
        step = totp_service.verify(
            user.totp_secret, totp_code, last_used_step=user.totp_last_used_step
        )
        if step is None:
            return AuthOutcome(reason="missing or invalid TOTP code")
        # Spend the step immediately: a code must not survive to a second
        # attempt even if what follows fails.
        user.totp_last_used_step = step

    if user.password_hash and passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(password)

    return AuthOutcome(user=user)


def issue(
    session: Session,
    user: User,
    *,
    lifetime_seconds: int,
    source_ip: str | None = None,
    user_agent: str | None = None,
    now: datetime | None = None,
) -> tuple[AdminSession, str]:
    """Create a session. Returns the row and the **plaintext token, shown once**."""
    now = now or datetime.now(UTC)
    token = _PREFIX + secrets.token_urlsafe(32)
    row = AdminSession(
        user_id=user.id,
        token_hash=hash_token(token),
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(seconds=lifetime_seconds),
        source_ip=source_ip,
        user_agent=(user_agent or "")[:255] or None,
    )
    session.add(row)
    user.last_login_at = now
    session.flush()
    return row, token


def resolve(
    session: Session, token: str, *, now: datetime | None = None
) -> AdminSession | None:
    """Return the live session a token names, refreshing ``last_seen_at``.

    Returns ``None`` for anything not currently usable -- unknown, expired,
    revoked, or belonging to an account that has since been deactivated or had
    its admin rights removed. Checking the *account* on every request rather
    than only at login is what makes "remove admin" take effect immediately
    instead of whenever the session happens to expire.
    """
    if not token or not token.startswith(_PREFIX):
        return None
    now = now or datetime.now(UTC)

    # Candidates are narrowed in SQL, then the hash is compared in constant time.
    # The salt is per-token, so the hash cannot be recomputed for a direct lookup.
    rows = (
        session.execute(
            select(AdminSession).where(
                AdminSession.revoked_at.is_(None), AdminSession.expires_at > now
            )
        )
        .scalars()
        .all()
    )
    for row in rows:
        if _verify_hash(token, row.token_hash):
            if not row.user.is_active or not row.user.is_admin:
                logger.warning(
                    "admin session %s belongs to an account that is no longer an "
                    "active administrator; refusing it",
                    row.id,
                )
                return None
            row.last_seen_at = now
            return row
    return None


def revoke(session: Session, row: AdminSession, *, now: datetime | None = None) -> None:
    row.revoked_at = now or datetime.now(UTC)


def revoke_all_for_user(
    session: Session, user_id: object, *, now: datetime | None = None
) -> int:
    """Cut every session an account holds. Used when it is deactivated or demoted."""
    return (
        session.execute(
            update(AdminSession)
            .where(AdminSession.user_id == user_id, AdminSession.revoked_at.is_(None))
            .values(revoked_at=now or datetime.now(UTC)),
            execution_options={"synchronize_session": "fetch"},
        ).rowcount
        or 0
    )
