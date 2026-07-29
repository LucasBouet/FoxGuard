"""OIDC: the transaction store, and everything that makes an ID token trustworthy.

No live IdP. A real RSA key pair is generated here and used to mint tokens, so
the signature path is exercised for real rather than mocked away -- the point of
these tests is that a *wrong* token is rejected, and a mock cannot demonstrate
that.
"""

from __future__ import annotations

import time
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey

from foxguard.config import Settings
from foxguard.services.oidc import (
    OidcClient,
    OidcError,
    TransactionStore,
    code_challenge,
)

ISSUER = "https://idp.example"
CLIENT_ID = "foxguard-portal"


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture(scope="module")
def signing_key() -> RSAKey:
    return RSAKey.generate_key(2048, parameters={"kid": "test-key", "use": "sig", "alg": "RS256"})


@pytest.fixture(scope="module")
def jwks(signing_key: RSAKey) -> dict:
    return {"keys": [signing_key.as_dict(private=False)]}


def settings(**overrides) -> Settings:
    base = {
        "dev_mode": True,
        "oidc_issuer": ISSUER,
        "oidc_client_id": CLIENT_ID,
        "oidc_client_secret": "s3cret",
        "oidc_redirect_url": "https://portal.tunnel/callback",
    }
    return Settings(**(base | overrides))


class StubClient(OidcClient):
    """An OidcClient with discovery and JWKS pre-loaded, so no HTTP happens."""

    def __init__(self, jwks: dict, **overrides):
        super().__init__(settings=settings(**overrides))
        from foxguard.services.oidc import ProviderMetadata

        self._metadata = ProviderMetadata(
            issuer=ISSUER,
            authorization_endpoint=f"{ISSUER}/authorize",
            token_endpoint=f"{ISSUER}/token",
            jwks_uri=f"{ISSUER}/jwks",
        )
        self._jwks = jwks


@pytest.fixture()
def client(jwks: dict) -> StubClient:
    return StubClient(jwks)


def mint(signing_key: RSAKey, **claims) -> str:
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-subject-1",
        "nonce": "the-nonce",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    } | claims
    return jwt.encode({"alg": "RS256", "kid": "test-key"}, payload, signing_key)


# --------------------------------------------------------------------------- #
# PKCE
# --------------------------------------------------------------------------- #


def test_the_code_challenge_is_unpadded_base64url_sha256():
    # RFC 7636 appendix B's worked example.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_the_challenge_never_reveals_the_verifier():
    verifier = "a" * 64
    assert verifier not in code_challenge(verifier)


# --------------------------------------------------------------------------- #
# transaction store
# --------------------------------------------------------------------------- #


def test_a_transaction_carries_the_peer_that_started_it():
    peer_id = uuid.uuid4()
    store = TransactionStore()
    transaction = store.start(peer_id)
    assert store.consume(transaction.state).subject == peer_id


def test_an_administrator_transaction_carries_no_peer():
    """Which is what keeps the two flows from redeeming each other's states: a
    portal callback compares the subject to a peer id, and an admin callback
    requires it to be absent."""
    store = TransactionStore()
    transaction = store.start(None)
    assert store.consume(transaction.state).subject is None


def test_a_callback_can_only_be_used_once():
    """A replayed callback must find nothing, even inside the TTL."""
    store = TransactionStore()
    transaction = store.start(uuid.uuid4())
    assert store.consume(transaction.state) is not None
    assert store.consume(transaction.state) is None


def test_an_unknown_state_resolves_to_nothing():
    assert TransactionStore().consume("never-issued") is None


def test_a_transaction_expires():
    clock = FakeClock()
    store = TransactionStore(ttl_seconds=600, clock=clock)
    transaction = store.start(uuid.uuid4())
    clock.advance(601)
    assert store.consume(transaction.state) is None


def test_expired_transactions_do_not_accumulate():
    clock = FakeClock()
    store = TransactionStore(ttl_seconds=600, clock=clock)
    for _ in range(100):
        store.start(uuid.uuid4())
    clock.advance(601)
    store.start(uuid.uuid4())
    assert len(store) == 1


def test_states_verifiers_and_nonces_are_all_unpredictable():
    store = TransactionStore()
    transactions = [store.start(uuid.uuid4()) for _ in range(50)]
    for attribute in ("state", "code_verifier", "nonce"):
        assert len({getattr(t, attribute) for t in transactions}) == 50


def test_the_verifier_length_is_within_rfc_7636():
    verifier = TransactionStore().start(uuid.uuid4()).code_verifier
    assert 43 <= len(verifier) <= 128


# --------------------------------------------------------------------------- #
# authorization URL
# --------------------------------------------------------------------------- #


def test_the_authorization_url_carries_pkce_state_and_nonce(client):
    transaction = TransactionStore().start(uuid.uuid4())
    url = client.authorization_url(transaction)
    assert url.startswith(f"{ISSUER}/authorize?")

    query = {key: values[0] for key, values in parse_qs(urlparse(url).query).items()}
    assert query["response_type"] == "code"
    assert query["client_id"] == CLIENT_ID
    assert query["redirect_uri"] == "https://portal.tunnel/callback"
    assert query["scope"] == "openid profile email"
    assert query["state"] == transaction.state
    assert query["nonce"] == transaction.nonce
    assert query["code_challenge_method"] == "S256"
    assert query["code_challenge"] == code_challenge(transaction.code_verifier)


def test_the_verifier_itself_is_never_put_in_the_url(client):
    """Sending the verifier instead of the challenge would defeat PKCE entirely."""
    transaction = TransactionStore().start(uuid.uuid4())
    assert transaction.code_verifier not in client.authorization_url(transaction)


# --------------------------------------------------------------------------- #
# ID token verification -- the part that matters
# --------------------------------------------------------------------------- #


def test_a_correctly_signed_token_is_accepted(client, signing_key):
    claims = client.verify_id_token(mint(signing_key), nonce="the-nonce")
    assert claims["sub"] == "user-subject-1"


def test_a_token_signed_by_someone_else_is_rejected(client):
    """The whole point: possession of a token is not proof it came from the IdP."""
    impostor = RSAKey.generate_key(2048, parameters={"kid": "test-key", "alg": "RS256"})
    with pytest.raises(OidcError):
        client.verify_id_token(mint(impostor), nonce="the-nonce")


def test_a_tampered_token_is_rejected(client, signing_key):
    token = mint(signing_key)
    header, payload, signature = token.split(".")
    with pytest.raises(OidcError):
        client.verify_id_token(f"{header}.{payload}x.{signature}", nonce="the-nonce")


def test_an_unsigned_token_is_rejected(client, signing_key):
    """`alg: none` is the oldest JWT attack there is."""
    token = mint(signing_key)
    header, payload, _ = token.split(".")
    with pytest.raises(OidcError):
        client.verify_id_token(f"{header}.{payload}.", nonce="the-nonce")


def test_an_hmac_token_signed_with_the_public_key_is_rejected(client, jwks):
    """Algorithm confusion: a JWKS is public, so HMAC must never be allowed."""
    from joserfc.jwk import OctKey

    forged = jwt.encode(
        {"alg": "HS256", "kid": "test-key"},
        {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "attacker",
            "nonce": "the-nonce",
            "exp": int(time.time()) + 300,
        },
        OctKey.import_key(jwks["keys"][0]["n"]),
    )
    with pytest.raises(OidcError):
        client.verify_id_token(forged, nonce="the-nonce")


def test_a_token_from_a_different_issuer_is_rejected(client, signing_key):
    with pytest.raises(OidcError, match="claims"):
        client.verify_id_token(mint(signing_key, iss="https://evil.example"), nonce="the-nonce")


def test_a_token_for_a_different_client_is_rejected(client, signing_key):
    """Otherwise any app on the same IdP could mint logins for Foxguard."""
    with pytest.raises(OidcError, match="claims"):
        client.verify_id_token(mint(signing_key, aud="some-other-app"), nonce="the-nonce")


def test_an_expired_token_is_rejected(client, signing_key):
    stale = mint(signing_key, exp=int(time.time()) - 3600, iat=int(time.time()) - 7200)
    with pytest.raises(OidcError, match="claims"):
        client.verify_id_token(stale, nonce="the-nonce")


def test_a_token_with_no_expiry_is_rejected(client, signing_key):
    payload = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u", "nonce": "the-nonce"}
    token = jwt.encode({"alg": "RS256", "kid": "test-key"}, payload, signing_key)
    with pytest.raises(OidcError, match="claims"):
        client.verify_id_token(token, nonce="the-nonce")


def test_a_token_with_no_subject_is_rejected(client, signing_key):
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "nonce": "the-nonce",
        "exp": int(time.time()) + 300,
    }
    token = jwt.encode({"alg": "RS256", "kid": "test-key"}, payload, signing_key)
    with pytest.raises(OidcError, match="claims"):
        client.verify_id_token(token, nonce="the-nonce")


def test_a_token_minted_for_another_login_is_rejected(client, signing_key):
    """The nonce binds the token to the authorization request we started."""
    with pytest.raises(OidcError, match="nonce"):
        client.verify_id_token(mint(signing_key, nonce="someone-elses"), nonce="the-nonce")


def test_a_token_with_no_nonce_at_all_is_rejected(client, signing_key):
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "u",
        "exp": int(time.time()) + 300,
    }
    token = jwt.encode({"alg": "RS256", "kid": "test-key"}, payload, signing_key)
    with pytest.raises(OidcError, match="nonce"):
        client.verify_id_token(token, nonce="the-nonce")


def test_small_clock_skew_is_tolerated(client, signing_key):
    """A token that expired 10s ago still passes; IdP and gateway clocks drift."""
    recent = mint(signing_key, exp=int(time.time()) - 10)
    assert client.verify_id_token(recent, nonce="the-nonce")["sub"] == "user-subject-1"


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #


def test_oidc_is_off_until_every_field_is_set():
    assert settings().oidc_enabled is True
    for missing in ("oidc_issuer", "oidc_client_id", "oidc_client_secret", "oidc_redirect_url"):
        assert settings(**{missing: None}).oidc_enabled is False, missing


def test_a_provider_that_advertises_a_different_issuer_is_refused(jwks):
    """Guards against pointing at a discovery document someone else controls."""

    class Mismatched(StubClient):
        def _get_json(self, url: str) -> dict:
            return {
                "issuer": "https://somewhere.else",
                "authorization_endpoint": "https://somewhere.else/a",
                "token_endpoint": "https://somewhere.else/t",
                "jwks_uri": "https://somewhere.else/jwks",
            }

    client = Mismatched(jwks)
    client._metadata = None
    with pytest.raises(OidcError, match="does not match"):
        client.metadata()
