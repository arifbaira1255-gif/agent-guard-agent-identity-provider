"""OIDC federation boundary for Step 8 (enterprise SSO).

Deliberately a **clean, self-contained boundary** so Step 9 can add another protocol (SAML) behind
the same surface without touching the authentication service:

  * ``validate_id_token`` — a PURE function that validates a JWT id_token completely: fixed set of
    signature algorithms, signature checked against the provider JWKS (selected by ``kid``), and
    explicit ``iss`` / ``aud`` / ``azp`` / ``exp`` / ``nbf`` / ``iat`` / ``nonce`` checks. It never
    accepts ``alg=none`` or an attacker-chosen algorithm, and it never trusts the token's own claims
    about where it came from.
  * ``OidcClient`` — discovery (cached), authorization-URL construction with **PKCE S256** +
    ``state`` + ``nonce``, and the authorization-code exchange. The client secret is resolved from
    an environment variable referenced by *name* (``IdpConfig.client_secret_ref``) and never stored
    or logged.
  * ``LoginTxnStore`` — server-side, single-use, tenant-namespaced login transactions (Redis) that
    bind ``state`` → verifier + nonce + return path. Consuming one is atomic, which is what defeats
    login-CSRF and code/state substitution: a forged or replayed callback has no live transaction.

All network I/O goes through an injected ``fetcher`` callable, so the whole flow is unit-testable
with a fake IdP and no live provider.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ..core.errors import AuthenticationError, ValidationError
from .ids import new_id
from .models import IdpConfig, LoginTransaction
from .redis_keys import SecurityKeys
from .tokens import random_token

_log = logging.getLogger("agentguard.identity.security")

ALLOWED_ALGS = ("RS256", "RS384", "ES256", "ES384")
_MAX_FETCH_BYTES = 512 * 1024
_FETCH_TIMEOUT_S = 5.0

# normalization of email -> lowercase, trimmed
def _norm_email(email: str) -> str:
    return (email or "").strip().lower()


class OidcError(AuthenticationError):
    """Any failure in the OIDC boundary. Message is safe to surface (never contains token material)."""


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def make_pkce_pair() -> Tuple[str, str]:
    verifier = random_token(32)
    challenge = _b64u(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _is_local(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1")


def assert_safe_url(url: str, *, allow_http_local: bool = True) -> None:
    """SSRF guard: only https, or http for loopback (dev/test). Rejects creds/userinfo tricks."""
    try:
        p = urllib.parse.urlsplit(url)
    except Exception:
        raise ValidationError("invalid url")
    if p.scheme not in ("https", "http") or not p.netloc:
        raise ValidationError("url must be absolute http(s)")
    if p.username or p.password:
        raise ValidationError("url must not contain credentials")
    if p.scheme == "http" and not (allow_http_local and _is_local(p.hostname or "")):
        raise ValidationError("insecure url scheme")


def _default_fetcher(url: str) -> dict:
    assert_safe_url(url)
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "agentguard-step8/1.0"})
    with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT_S) as resp:     # noqa: S310 (https-guarded)
        raw = resp.read(_MAX_FETCH_BYTES + 1)
    if len(raw) > _MAX_FETCH_BYTES:
        raise OidcError("provider response too large")
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        raise OidcError("provider returned invalid JSON")


def _post_form(url: str, form: dict, headers: dict) -> dict:
    assert_safe_url(url)
    data = urllib.parse.urlencode(form).encode("ascii")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT_S) as resp:     # noqa: S310 (https-guarded)
        raw = resp.read(_MAX_FETCH_BYTES + 1)
    if len(raw) > _MAX_FETCH_BYTES:
        raise OidcError("token response too large")
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        raise OidcError("token endpoint returned invalid JSON")


# ------------------------------------------------------------------------------- pure validation
def validate_id_token(id_token: str, *, issuer: str, audience: str, jwks: dict, nonce: str,
                      now: float, skew: int = 60, allowed_email_domains: Tuple[str, ...] = (),
                      require_verified_email: bool = True,
                      allowed_organizations: Tuple[str, ...] = ()) -> dict:
    """Validate an OIDC id_token and return the checked claims. Pure; raises ``OidcError`` on ANY
    failure with a non-sensitive reason."""
    if not id_token or not isinstance(id_token, str) or len(id_token) > 16 * 1024:
        raise OidcError("missing or oversized id_token")
    try:
        import jwt                                     # PyJWT
    except Exception:                                  # pragma: no cover
        raise OidcError("PyJWT is required for OIDC")

    # 1) header: algorithm must be in the closed allow-list and 'none' is never accepted
    try:
        header = jwt.get_unverified_header(id_token)
    except Exception:
        raise OidcError("malformed id_token header")
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise OidcError("unsupported id_token signing algorithm")
    kid = header.get("kid")

    # 2) select the verification key from the provider JWKS by kid (never from the token itself)
    key = _select_jwk(jwks, kid, alg)
    if key is None:
        raise OidcError("no matching verification key")

    # 3) signature only — ALL temporal claims are checked below against the INJECTED clock, so
    #    validation is deterministic and never depends on the host's wall clock.
    try:
        claims = jwt.decode(
            id_token, key, algorithms=[alg],
            options={"verify_signature": True, "verify_exp": False, "verify_nbf": False,
                     "verify_iat": False, "verify_aud": False, "verify_iss": False,
                     "require": ["exp", "iat", "sub", "aud"]},
            leeway=skew)
    except Exception as exc:
        raise OidcError(f"id_token verification failed: {type(exc).__name__}")

    # 4) issuer: exact match (no substring/prefix trickery)
    if claims.get("iss") != issuer:
        raise OidcError("id_token issuer mismatch")

    # 5) audience: must contain our client_id; if the token targets several audiences, azp is required
    aud = claims.get("aud")
    aud_list = aud if isinstance(aud, list) else [aud]
    if audience not in aud_list:
        raise OidcError("id_token audience mismatch")
    if len([a for a in aud_list if a]) > 1:
        if claims.get("azp") != audience:
            raise OidcError("id_token azp mismatch for multi-audience token")
    elif "azp" in claims and claims.get("azp") not in (None, audience):
        raise OidcError("id_token azp mismatch")

    # 6) nonce: binds this token to THIS authorization request (defeats replay/substitution)
    if not nonce or claims.get("nonce") != nonce:
        raise OidcError("id_token nonce mismatch")

    # 7) freshness: reject absurdly old/future tokens beyond skew (checked against `now`, not wall clock)
    if int(claims.get("exp", 0)) <= int(now) - skew:
        raise OidcError("id_token expired")
    if int(claims.get("iat", 0)) > int(now) + skew:
        raise OidcError("id_token issued in the future")
    if "nbf" in claims and int(claims.get("nbf", 0)) > int(now) + skew:
        raise OidcError("id_token not yet valid")

    # 8) email policy
    email = _norm_email(claims.get("email") or claims.get("preferred_username") or "")
    if not email:
        raise OidcError("id_token has no email claim")
    if require_verified_email and claims.get("email_verified") is False:
        raise OidcError("id_token email is not verified")
    if allowed_email_domains:
        dom = email.split("@")[-1]
        if dom not in tuple(d.lower() for d in allowed_email_domains):
            raise OidcError("email domain is not permitted for this provider")
    if allowed_organizations:
        org_claim = claims.get("org") or claims.get("organizations") or claims.get("tid") or []
        orgs = org_claim if isinstance(org_claim, list) else [org_claim]
        if not set(o for o in orgs if o) & set(allowed_organizations):
            raise OidcError("id_token organization is not permitted for this provider")

    claims["_email"] = email
    return claims


def _select_jwk(jwks: dict, kid: Optional[str], alg: str):
    """Pick the signing key from a JWKS document. Returns a cryptography key object or None."""
    try:
        import jwt
    except Exception:                                  # pragma: no cover
        return None
    keys = (jwks or {}).get("keys") or []
    want_kty = "RSA" if alg.startswith("RS") else "EC"
    for k in keys:
        if kid is not None and k.get("kid") != kid:
            continue
        if k.get("kty") != want_kty:
            continue
        if k.get("use") not in (None, "sig"):
            continue
        try:
            return jwt.PyJWK(k).key
        except Exception:
            continue
    return None


# ------------------------------------------------------------------------------- login transactions
@dataclass
class LoginTxnStore:
    """Server-side, single-use OIDC login transactions in Redis, tenant-namespaced."""

    backend: object
    keys: SecurityKeys

    def create(self, idp: IdpConfig, *, code_verifier: str, nonce: str, redirect_uri: str,
               return_to: Optional[str], ip: Optional[str], user_agent: Optional[str],
               now: float, ttl_s: int) -> LoginTransaction:
        state = random_token(32)
        txn = LoginTransaction(txn_id=state, idp_id=idp.idp_id, org_id=idp.org_id,
                               code_verifier=code_verifier, nonce=nonce, redirect_uri=redirect_uri,
                               return_to=return_to, created_at=now, expires_at=now + ttl_s,
                               ip=ip, user_agent=user_agent)
        self._put(state, txn, ttl_s)
        return txn

    def _put(self, state: str, txn: LoginTransaction, ttl_s: int) -> None:
        payload = json.dumps({"idp_id": txn.idp_id, "org_id": txn.org_id,
                              "code_verifier": txn.code_verifier, "nonce": txn.nonce,
                              "redirect_uri": txn.redirect_uri, "return_to": txn.return_to,
                              "created_at": txn.created_at, "expires_at": txn.expires_at,
                              "ip": txn.ip, "user_agent": txn.user_agent}).encode("utf-8")
        ok = self.backend.set_if_absent(self.keys.login_txn(txn.org_id, state), payload,
                                        int(ttl_s * 1000))
        if not ok:                                     # astronomically unlikely; fail closed
            raise OidcError("could not allocate login transaction")

    def consume_for(self, org_id: Optional[str], state: str, *, now: float) -> LoginTransaction:
        """Consume a login transaction in a specific tenant namespace (single-use).

        The caller knows the tenant because the callback route carries the ``idp_id`` (which maps to
        an org), so the state is looked up in exactly the right namespace — one tenant's state can
        never be consumed from another tenant's namespace.
        """
        if not state or not isinstance(state, str) or len(state) > 512:
            raise OidcError("invalid login state")
        key = self.keys.login_txn(org_id, state)
        raw = self.backend.get(key)
        if raw is None:
            raise OidcError("unknown or expired login state")
        if not self.backend.compare_and_delete(key, raw):
            raise OidcError("login state already used")
        try:
            d = json.loads(raw.decode("utf-8"))
        except Exception:
            raise OidcError("corrupt login state")
        if now >= float(d.get("expires_at", 0)):
            raise OidcError("login state expired")
        return LoginTransaction(txn_id=state, idp_id=d["idp_id"], org_id=d.get("org_id"),
                                code_verifier=d["code_verifier"], nonce=d["nonce"],
                                redirect_uri=d["redirect_uri"], return_to=d.get("return_to"),
                                created_at=d["created_at"], expires_at=d["expires_at"],
                                ip=d.get("ip"), user_agent=d.get("user_agent"))


# ------------------------------------------------------------------------------- client
class OidcClient:
    """Mechanics of the OIDC authorization-code + PKCE flow. Network access is injected."""

    def __init__(self, *, fetcher: Optional[Callable[[str], dict]] = None, clock=None,
                 metadata_cache=None, metadata_ttl_s: int = 3600,
                 jwks_cache=None, jwks_ttl_s: int = 3600, environment: str = "development",
                 poster: Optional[Callable[[str, dict, dict], dict]] = None):
        self._fetch = fetcher or _default_fetcher
        self._post = poster or _post_form
        self._clock = clock
        self._meta_cache = metadata_cache          # optional StateBackend
        self._meta_ttl = metadata_ttl_s
        self._jwks_cache = jwks_cache
        self._jwks_ttl = jwks_ttl_s
        self.environment = environment
        self._keys = SecurityKeys(environment)

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ---- discovery --------------------------------------------------------------------------
    def metadata(self, idp: IdpConfig) -> dict:
        if idp.authorization_endpoint and idp.token_endpoint and (idp.jwks_uri or True):
            base = {"authorization_endpoint": idp.authorization_endpoint,
                    "token_endpoint": idp.token_endpoint, "jwks_uri": idp.jwks_uri,
                    "issuer": idp.issuer}
            if base["authorization_endpoint"] and base["token_endpoint"] and base["jwks_uri"]:
                return base
        url = idp.issuer.rstrip("/") + "/.well-known/openid-configuration"
        key = self._keys.discovery(idp.issuer)
        if self._meta_cache is not None:
            raw = self._meta_cache.get(key)
            if raw:
                try:
                    return json.loads(raw.decode("utf-8"))
                except Exception:
                    pass
        meta = self._fetch(url)
        if not isinstance(meta, dict) or not meta.get("issuer"):
            raise OidcError("provider discovery document is invalid")
        # issuer in discovery MUST match the configured issuer (mix-up attack guard)
        if meta.get("issuer").rstrip("/") != idp.issuer.rstrip("/"):
            raise OidcError("provider issuer does not match configuration")
        for needed in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not meta.get(needed):
                raise OidcError(f"provider discovery missing {needed}")
        if self._meta_cache is not None:
            try:
                self._meta_cache.set(key, json.dumps(meta).encode("utf-8"), int(self._meta_ttl * 1000))
            except Exception:
                pass
        return meta

    # ---- jwks --------------------------------------------------------------------------------
    def jwks(self, idp: IdpConfig, *, force_refresh: bool = False) -> dict:
        meta = self.metadata(idp)
        jwks_uri = idp.jwks_uri or meta["jwks_uri"]
        key = self._keys.jwks(jwks_uri)
        if not force_refresh and self._jwks_cache is not None:
            raw = self._jwks_cache.get(key)
            if raw:
                try:
                    return json.loads(raw.decode("utf-8"))
                except Exception:
                    pass
        doc = self._fetch(jwks_uri)
        if not isinstance(doc, dict) or not doc.get("keys"):
            raise OidcError("provider JWKS is invalid")
        if self._jwks_cache is not None:
            try:
                self._jwks_cache.set(key, json.dumps(doc).encode("utf-8"), int(self._jwks_ttl * 1000))
            except Exception:
                pass
        return doc

    # ---- authorization url --------------------------------------------------------------------
    def authorization_url(self, idp: IdpConfig, *, state: str, nonce: str, code_challenge: str,
                          extra_params: Optional[dict] = None) -> str:
        meta = self.metadata(idp)
        params = {
            "response_type": "code", "client_id": idp.client_id, "redirect_uri": idp.redirect_uri,
            "scope": " ".join(idp.scopes or ("openid", "profile", "email")),
            "state": state, "nonce": nonce,
            "code_challenge": code_challenge, "code_challenge_method": "S256",
        }
        if extra_params:
            params.update({k: v for k, v in extra_params.items() if k not in ("state", "nonce")})
        return meta["authorization_endpoint"] + ("&" if "?" in meta["authorization_endpoint"] else "?") \
            + urllib.parse.urlencode(params)

    def _client_secret(self, idp: IdpConfig) -> str:
        secret = os.environ.get(idp.client_secret_ref or "", "")
        if not secret:
            raise OidcError("identity provider client secret is not configured")
        return secret

    # ---- code exchange ------------------------------------------------------------------------
    def exchange_code(self, idp: IdpConfig, *, code: str, code_verifier: str) -> dict:
        meta = self.metadata(idp)
        if not code or not isinstance(code, str):
            raise OidcError("missing authorization code")
        form = {"grant_type": "authorization_code", "code": code,
                "redirect_uri": idp.redirect_uri, "client_id": idp.client_id,
                "code_verifier": code_verifier}
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        secret = self._client_secret(idp)
        # client_secret_post (portable across providers); the secret is never logged
        form["client_secret"] = secret
        resp = self._post(meta["token_endpoint"], form, headers)
        if not isinstance(resp, dict) or not resp.get("id_token"):
            raise OidcError("token endpoint did not return an id_token")
        if resp.get("token_type", "Bearer").lower() != "bearer":
            raise OidcError("unexpected token type")
        return resp

    # ---- full id_token verification (with one JWKS refresh on kid miss) -----------------------
    def verify(self, idp: IdpConfig, id_token: str, *, nonce: str) -> dict:
        jwks = self.jwks(idp)
        try:
            return validate_id_token(
                id_token, issuer=idp.issuer, audience=idp.client_id, jwks=jwks, nonce=nonce,
                now=self._now(), allowed_email_domains=idp.allowed_email_domains,
                require_verified_email=idp.require_verified_email,
                allowed_organizations=idp.allowed_organizations)
        except OidcError as exc:
            if "no matching verification key" in str(exc):
                jwks = self.jwks(idp, force_refresh=True)          # key rotation: refresh once
                return validate_id_token(
                    id_token, issuer=idp.issuer, audience=idp.client_id, jwks=jwks, nonce=nonce,
                    now=self._now(), allowed_email_domains=idp.allowed_email_domains,
                    require_verified_email=idp.require_verified_email,
                    allowed_organizations=idp.allowed_organizations)
            raise
