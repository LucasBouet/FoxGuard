"""OIDC authorization-code flow with PKCE, for portal logins against an IdP.

Entirely optional. Foxguard has to stay usable on a box with no Authentik and no
Keycloak, so nothing here is imported at startup unless
:attr:`Settings.oidc_enabled` is true, and a half-configured IdP is treated as
"off" rather than as a fatal error.

What this module is careful about:

**The ID token is verified, not merely decoded.** Signature against the
provider's JWKS, then ``iss``/``aud``/``exp``/``nonce``. An unverified
``id_token`` is an attacker-supplied JSON document, and "log in as whoever the
``sub`` claim says" is the classic way to turn SSO into an open door.

**PKCE on a confidential client anyway.** The redirect lands on a portal inside
the tunnel, so an authorization code could in principle be observed by another
peer on the same segment. PKCE makes a stolen code useless without the verifier,
which never leaves this process.

**The transaction is bound to the peer that started it.** ``state`` is not just
CSRF protection here: it carries which peer asked. A callback arriving from a
*different* tunnel address than the one that began the flow is rejected, so a
peer cannot finish someone else's login and inherit their session.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from ..config import Settings

logger = logging.getLogger(__name__)

__all__ = [
    "OidcError",
    "OidcClient",
    "OidcTransaction",
    "ProviderMetadata",
    "TransactionStore",
    "code_challenge",
]

#: Clock skew tolerated when checking ``exp``/``iat``. IdPs and gateways drift.
_LEEWAY_SECONDS = 60

#: Asymmetric signatures only, and an explicit list rather than "whatever the
#: header asks for". A JWKS holds *public* keys, so allowing an HMAC algorithm
#: would let anyone who can read it sign their own tokens with the key we
#: verify against -- the classic algorithm-confusion attack. ``none`` is
#: excluded for the same reason, more obviously.
_ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")


class OidcError(RuntimeError):
    """Anything that makes an OIDC login impossible or untrustworthy."""


def code_challenge(verifier: str) -> str:
    """S256 PKCE challenge: base64url(sha256(verifier)), unpadded."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


@dataclass(frozen=True, slots=True)
class OidcTransaction:
    """One in-flight authorization request.

    ``subject`` is the peer that started a *portal* login, and ``None`` for an
    *administrator* login, which has no peer. Each callback checks the value it
    expects, so a transaction started for one flow cannot be completed in the
    other -- a portal state carries a peer id an admin callback refuses, and an
    admin state carries ``None``, which never equals a peer's id.
    """

    state: str
    subject: uuid.UUID | None
    code_verifier: str
    nonce: str
    created_at: float


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


class TransactionStore:
    """Short-lived, single-use, in-process store for in-flight logins.

    In-process is deliberate. The alternative -- a signed cookie -- would have to
    survive a round trip through the IdP's browser redirect, and the whole flow
    lasts seconds on a gateway that serves one portal. The same single-worker
    caveat as :mod:`foxguard.services.ratelimit` applies: with several uvicorn
    workers the callback may land on a process that never saw the ``start``.
    """

    def __init__(self, *, ttl_seconds: float = 600.0, clock=time.monotonic) -> None:
        self._ttl = float(ttl_seconds)
        self._clock = clock
        self._entries: dict[str, OidcTransaction] = {}
        self._lock = threading.Lock()

    def _sweep(self, now: float) -> None:
        for state in [s for s, t in self._entries.items() if now - t.created_at > self._ttl]:
            del self._entries[state]

    def start(self, subject: uuid.UUID | None = None) -> OidcTransaction:
        transaction = OidcTransaction(
            state=secrets.token_urlsafe(32),
            subject=subject,
            # 64 bytes -> 86 chars, inside RFC 7636's 43..128 range.
            code_verifier=secrets.token_urlsafe(64),
            nonce=secrets.token_urlsafe(24),
            created_at=self._clock(),
        )
        with self._lock:
            now = self._clock()
            self._sweep(now)
            self._entries[transaction.state] = transaction
        return transaction

    def consume(self, state: str) -> OidcTransaction | None:
        """Return and *remove* the transaction. A replayed callback finds nothing."""
        with self._lock:
            now = self._clock()
            self._sweep(now)
            transaction = self._entries.pop(state, None)
        if transaction is None:
            return None
        if now - transaction.created_at > self._ttl:
            return None
        return transaction

    def __len__(self) -> int:
        return len(self._entries)


@dataclass
class OidcClient:
    """Thin, explicit OIDC client. The HTTP client is injectable for tests."""

    settings: Settings
    http: httpx.Client | None = None
    _metadata: ProviderMetadata | None = field(default=None, init=False, repr=False)
    _jwks: dict | None = field(default=None, init=False, repr=False)

    # ------------------------------------------------------------------ helpers

    def _client(self) -> httpx.Client:
        return self.http or httpx.Client(timeout=10.0)

    def _get_json(self, url: str) -> dict:
        try:
            response = self._client().get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise OidcError(f"could not fetch {url}: {exc}") from exc

    # ----------------------------------------------------------------- metadata

    def metadata(self) -> ProviderMetadata:
        """Discovery document, fetched once per process."""
        if self._metadata is not None:
            return self._metadata

        issuer = (self.settings.oidc_issuer or "").rstrip("/")
        document = self._get_json(f"{issuer}/.well-known/openid-configuration")
        try:
            metadata = ProviderMetadata(
                issuer=document["issuer"],
                authorization_endpoint=document["authorization_endpoint"],
                token_endpoint=document["token_endpoint"],
                jwks_uri=document["jwks_uri"],
            )
        except KeyError as exc:
            raise OidcError(f"discovery document is missing {exc}") from exc

        # A provider whose advertised issuer differs from the URL we fetched it
        # from is either misconfigured or someone else's; either way the `iss`
        # check later would be meaningless if we just took its word for it.
        if metadata.issuer.rstrip("/") != issuer:
            raise OidcError(
                f"discovery issuer {metadata.issuer!r} does not match "
                f"FOXGUARD_OIDC_ISSUER {issuer!r}"
            )
        self._metadata = metadata
        return metadata

    def jwks(self, *, refresh: bool = False) -> dict:
        if self._jwks is None or refresh:
            self._jwks = self._get_json(self.metadata().jwks_uri)
        return self._jwks

    # ------------------------------------------------------------------- step 1

    def authorization_url(
        self, transaction: OidcTransaction, *, redirect_uri: str | None = None
    ) -> str:
        # The administrator flow redirects to the dashboard rather than to the
        # API, so the exchange can finish server-side and the session token can
        # go straight into an httpOnly cookie.
        query = {
            "response_type": "code",
            "client_id": self.settings.oidc_client_id,
            "redirect_uri": redirect_uri or self.settings.oidc_redirect_url,
            "scope": self.settings.oidc_scopes,
            "state": transaction.state,
            "nonce": transaction.nonce,
            "code_challenge": code_challenge(transaction.code_verifier),
            "code_challenge_method": "S256",
        }
        return f"{self.metadata().authorization_endpoint}?{urlencode(query)}"

    # ------------------------------------------------------------------- step 2

    def exchange_code(
        self, code: str, transaction: OidcTransaction, *, redirect_uri: str | None = None
    ) -> dict:
        secret = self.settings.oidc_client_secret
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            # Must match the one sent to /authorize, or the IdP rejects it.
            "redirect_uri": redirect_uri or self.settings.oidc_redirect_url,
            "client_id": self.settings.oidc_client_id,
            "client_secret": secret.get_secret_value() if secret else "",
            "code_verifier": transaction.code_verifier,
        }
        try:
            response = self._client().post(
                self.metadata().token_endpoint,
                data=payload,
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise OidcError(f"token endpoint unreachable: {exc}") from exc
        if response.status_code >= 400:
            # The body can carry the client secret back in an error echo, so log
            # the status and the error code only.
            raise OidcError(f"token endpoint returned {response.status_code}")
        tokens = response.json()
        if "id_token" not in tokens:
            raise OidcError("token response carried no id_token")
        return tokens

    def verify_id_token(self, id_token: str, *, nonce: str, now: int | None = None) -> dict:
        """Validate signature *and* claims, returning the claim set.

        An ``id_token`` that has only been decoded is an attacker-supplied JSON
        document. Everything below has to pass before its ``sub`` is allowed to
        name a local account.

        Retries once against a refreshed JWKS: providers rotate signing keys,
        and a stale cached key set is the usual cause of a sudden unknown ``kid``.
        """
        last_error: Exception | None = None
        for refresh in (False, True):
            try:
                token = jwt.decode(
                    id_token,
                    KeySet.import_key_set(self.jwks(refresh=refresh)),
                    algorithms=list(_ALLOWED_ALGORITHMS),
                )
            except Exception as exc:  # noqa: BLE001 - joserfc raises a wide family
                last_error = exc
                continue

            claims = dict(token.claims)
            registry = JWTClaimsRegistry(
                now=now,
                leeway=_LEEWAY_SECONDS,
                iss={"essential": True, "value": self.metadata().issuer},
                aud={"essential": True, "value": self.settings.oidc_client_id},
                sub={"essential": True},
                exp={"essential": True},
            )
            try:
                registry.validate(claims)
            except Exception as exc:  # noqa: BLE001
                raise OidcError(f"id_token claims rejected: {exc}") from exc

            # Checked by hand because it is not a registered JWT claim: it ties
            # this token to the authorization request *we* started, so a token
            # replayed from another login does not pass.
            if claims.get("nonce") != nonce:
                raise OidcError("id_token nonce does not match the authorization request")
            return claims

        logger.warning("id_token signature rejected: %s", last_error)
        raise OidcError(f"id_token signature verification failed: {last_error}")
