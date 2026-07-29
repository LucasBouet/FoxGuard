"""Administrator sign-in: who gets a session, and when it stops working."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pyotp
import pytest

from foxguard.models import ActorType, AdminSession, User
from foxguard.services import admin_auth, passwords
from foxguard.services import totp as totp_service

PASSWORD = "correct-horse-battery-staple"
NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)


@pytest.fixture()
def db(db_session):
    return db_session


def make_user(db, username="ada", *, admin=True, active=True, password=PASSWORD) -> User:
    user = User(
        username=username,
        password_hash=passwords.hash_password(password) if password else None,
        # An account needs at least one credential (ck_users_has_credential), so
        # a passwordless one is by definition an IdP-linked one.
        external_idp_issuer=None if password else "https://idp.example",
        external_idp_subject=None if password else f"sub-{username}",
        is_admin=admin,
        is_active=active,
    )
    db.add(user)
    db.flush()
    return user


# --------------------------------------------------------------------------- #
# who may sign in
# --------------------------------------------------------------------------- #


def test_an_administrator_signs_in(db):
    user = make_user(db)
    outcome = admin_auth.authenticate(db, username="ada", password=PASSWORD, totp_code=None)
    assert outcome
    assert outcome.user is user


def test_a_wrong_password_does_not(db):
    make_user(db)
    assert not admin_auth.authenticate(db, username="ada", password="nope", totp_code=None)


def test_an_unknown_account_does_not(db):
    assert not admin_auth.authenticate(db, username="nobody", password=PASSWORD, totp_code=None)


def test_a_non_admin_account_does_not(db):
    """`is_admin` is finally an authorisation boundary, not a label."""
    make_user(db, "bob", admin=False)
    outcome = admin_auth.authenticate(db, username="bob", password=PASSWORD, totp_code=None)
    assert not outcome
    assert outcome.reason == "not an administrator"


def test_a_deactivated_administrator_does_not(db):
    make_user(db, "gone", active=False)
    assert not admin_auth.authenticate(db, username="gone", password=PASSWORD, totp_code=None)


def test_an_oidc_only_account_cannot_sign_in_here(db):
    """There is no admin OIDC flow yet; an account with no password has no way in."""
    make_user(db, "sso", password=None)
    assert not admin_auth.authenticate(db, username="sso", password=PASSWORD, totp_code=None)


# --------------------------------------------------------------------------- #
# TOTP on the admin path
# --------------------------------------------------------------------------- #


def test_totp_is_required_when_enabled(db):
    user = make_user(db)
    user.totp_secret = totp_service.generate_secret()
    user.totp_enabled = True
    db.flush()

    assert not admin_auth.authenticate(db, username="ada", password=PASSWORD, totp_code=None)
    assert not admin_auth.authenticate(db, username="ada", password=PASSWORD, totp_code="000000")
    code = pyotp.TOTP(user.totp_secret).now()
    assert admin_auth.authenticate(db, username="ada", password=PASSWORD, totp_code=code)


def test_an_admin_totp_code_cannot_be_replayed(db):
    user = make_user(db)
    user.totp_secret = totp_service.generate_secret()
    user.totp_enabled = True
    db.flush()

    code = pyotp.TOTP(user.totp_secret).now()
    assert admin_auth.authenticate(db, username="ada", password=PASSWORD, totp_code=code)
    assert not admin_auth.authenticate(db, username="ada", password=PASSWORD, totp_code=code)


# --------------------------------------------------------------------------- #
# sessions
# --------------------------------------------------------------------------- #


def test_a_session_token_resolves_to_its_owner(db):
    user = make_user(db)
    _, token = admin_auth.issue(db, user, lifetime_seconds=3600)
    resolved = admin_auth.resolve(db, token)
    assert resolved is not None
    assert resolved.user_id == user.id


def test_the_plaintext_token_is_never_stored(db):
    """A database dump must not yield working admin sessions."""
    user = make_user(db)
    row, token = admin_auth.issue(db, user, lifetime_seconds=3600)
    assert token not in row.token_hash
    assert row.token_hash.startswith("sha256$")


def test_tokens_are_prefixed_and_unique(db):
    user = make_user(db)
    tokens = {admin_auth.issue(db, user, lifetime_seconds=3600)[1] for _ in range(25)}
    assert len(tokens) == 25
    assert all(token.startswith("fga_") for token in tokens)


@pytest.mark.parametrize("token", ["", "nonsense", "fga_wrong", "Bearer fga_x"])
def test_a_bad_token_resolves_to_nothing(db, token):
    make_user(db)
    assert admin_auth.resolve(db, token) is None


def test_an_expired_session_stops_working(db):
    user = make_user(db)
    _, token = admin_auth.issue(db, user, lifetime_seconds=3600, now=NOW)
    assert admin_auth.resolve(db, token, now=NOW + timedelta(minutes=59)) is not None
    assert admin_auth.resolve(db, token, now=NOW + timedelta(hours=2)) is None


def test_a_revoked_session_stops_working(db):
    user = make_user(db)
    row, token = admin_auth.issue(db, user, lifetime_seconds=3600)
    admin_auth.revoke(db, row)
    assert admin_auth.resolve(db, token) is None


def test_using_a_session_refreshes_last_seen(db):
    user = make_user(db)
    row, token = admin_auth.issue(db, user, lifetime_seconds=3600, now=NOW)
    later = NOW + timedelta(minutes=5)
    admin_auth.resolve(db, token, now=later)
    assert row.last_seen_at == later


# --------------------------------------------------------------------------- #
# the account can be cut out from under a live session
# --------------------------------------------------------------------------- #


def test_deactivating_the_account_kills_a_live_session(db):
    """Checked on every request, not only at login, so 'deactivate' is immediate."""
    user = make_user(db)
    _, token = admin_auth.issue(db, user, lifetime_seconds=3600)
    assert admin_auth.resolve(db, token) is not None

    user.is_active = False
    db.flush()
    assert admin_auth.resolve(db, token) is None


def test_removing_admin_rights_kills_a_live_session(db):
    user = make_user(db)
    _, token = admin_auth.issue(db, user, lifetime_seconds=3600)
    user.is_admin = False
    db.flush()
    assert admin_auth.resolve(db, token) is None


def test_revoking_every_session_of_a_user(db):
    user = make_user(db)
    tokens = [admin_auth.issue(db, user, lifetime_seconds=3600)[1] for _ in range(3)]
    assert admin_auth.revoke_all_for_user(db, user.id) == 3
    assert all(admin_auth.resolve(db, token) is None for token in tokens)


def test_one_users_revocation_does_not_touch_another(db):
    ada, bob = make_user(db, "ada"), make_user(db, "bob")
    _, bobs = admin_auth.issue(db, bob, lifetime_seconds=3600)
    admin_auth.revoke_all_for_user(db, ada.id)
    assert admin_auth.resolve(db, bobs) is not None


def test_deleting_the_account_takes_its_sessions_with_it(db):
    user = make_user(db)
    admin_auth.issue(db, user, lifetime_seconds=3600)
    db.delete(user)
    db.flush()
    assert db.query(AdminSession).count() == 0


# --------------------------------------------------------------------------- #
# identity
# --------------------------------------------------------------------------- #


def test_a_person_is_recorded_as_themselves(db):
    user = make_user(db)
    identity = admin_auth.AdminIdentity.person(user)
    assert identity.actor_type is ActorType.ADMIN
    assert identity.label == "ada"
    assert identity.is_person


def test_the_static_token_is_recorded_as_a_machine():
    """So an audit reader can tell a person from a provisioning script."""
    identity = admin_auth.AdminIdentity.machine()
    assert identity.actor_type is ActorType.SYSTEM
    assert identity.label == "admin-token"
    assert not identity.is_person
