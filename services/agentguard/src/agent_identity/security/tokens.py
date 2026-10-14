"""Token cryptography for Step 8: opaque session ids, and self-contained HMAC-SHA256 access tokens.

Why HMAC and not a JWT library?
-------------------------------
Step 8 introduces a *short-lived access token* that authorizes API calls. Unlike the Agent Passport
(an Ed25519, third-party-verifiable artifact), the access token here is produced and consumed by the
same control plane. A compact, domain-separated HS256 token gives:
  * fixed algorithm (no ``alg`` header -> no algorithm-confusion / ``alg=none`` attack),
  * explicit issuer/audience/expiry claims that are always checked,
  * a `sid` binding back to the server-side session (so revocation is immediate),
  * simple, auditable verification with no dependency on a JWT library's defaults.

The signing key is a dedicated secret (never the keystore master key). If the secret is missing in a
non-development environment, construction fails closed.

Refresh tokens are *random, opaque* strings; only their SHA-256 digest is persisted. Sessions ids
and CSRF tokens are likewise random (>= 256 bits). Nothing here returns plaintext passwords or keys,
and ``digest``/``redact`` helpers make accidental logging of bearer material easy to avoid.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from typing import Optional

from ..core.errors import AuthenticationError

ACCESS_PREFIX = "aga1"                      # AgentGuard Access token v1
DEFAULT_AUDIENCE = "agentguard-control-plane"
DEFAULT_ISSUER = "agentguard"


def _b64u(b: bytes) -> str:
    return urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64u(s: str) -> bytes:
    return urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def redact(value: Optional[str]) -> str:
    """Never print bearer material; keep only a short fingerprint for correlation."""
    if not value:
        return "<none>"
    return "sha256:" + digest(value)[:12]


class TokenSigner:
    """HMAC-SHA256 signer for access tokens. The secret is read from the environment by default."""

    ENV_VAR = "AGENTGUARD_SESSION_SECRET"

    def __init__(self, secret: Optional[bytes] = None, *, issuer: str = DEFAULT_ISSUER,
                 audience: str = DEFAULT_AUDIENCE, environment: str = ""):
        if secret is None:
            raw = os.environ.get(self.ENV_VAR, "")
            secret = raw.encode("utf-8") if raw else None
        env = (environment or os.environ.get("AGENTGUARD_ENV", "")).strip().lower()
        if secret is None:
            if env in ("staging", "production"):
                raise AuthenticationError("AGENTGUARD_SESSION_SECRET is required outside development")
            secret = secrets.token_bytes(32)          # ephemeral dev key: tokens die with the process
        if len(secret) < 32:
            raise AuthenticationError("session signing secret must be at least 32 bytes")
        self._key = secret
        self.issuer = issuer
        self.audience = audience

    def issue(self, *, user_id: str, session_id: str, org_id: Optional[str], roles: tuple,
              is_platform_admin: bool, ttl_seconds: int, now: float,
              token_id: Optional[str] = None, amr: tuple = ()) -> str:
        claims = {
            "iss": self.issuer, "aud": self.audience, "sub": user_id, "sid": session_id,
            "org": org_id, "roles": list(roles), "padmin": bool(is_platform_admin),
            "amr": list(amr), "iat": int(now), "nbf": int(now), "exp": int(now) + int(ttl_seconds),
            "jti": token_id or random_token(12), "v": 1,
        }
        body = _b64u(_canon(claims))
        sig = hmac.new(self._key, f"{ACCESS_PREFIX}.{body}".encode("ascii"), hashlib.sha256).digest()
        return f"{ACCESS_PREFIX}.{body}.{_b64u(sig)}"

    def verify(self, token: str, *, now: float, audience: Optional[str] = None) -> dict:
        """Return verified claims, or raise ``AuthenticationError``. Fixed algorithm, all claims
        checked (iss/aud/exp/nbf), signature compared in constant time."""
        if not isinstance(token, str) or len(token) > 8192:
            raise AuthenticationError("malformed access token")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != ACCESS_PREFIX:
            raise AuthenticationError("malformed access token")
        body, sig = parts[1], parts[2]
        expected = hmac.new(self._key, f"{ACCESS_PREFIX}.{body}".encode("ascii"), hashlib.sha256).digest()
        try:
            got = _unb64u(sig)
        except Exception:
            raise AuthenticationError("malformed access token")
        if not hmac.compare_digest(got, expected):
            raise AuthenticationError("invalid access token signature")
        try:
            claims = json.loads(_unb64u(body).decode("utf-8"))
        except Exception:
            raise AuthenticationError("malformed access token")
        if not isinstance(claims, dict) or claims.get("v") != 1:
            raise AuthenticationError("malformed access token")
        if claims.get("iss") != self.issuer:
            raise AuthenticationError("invalid access token issuer")
        aud = audience or self.audience
        if claims.get("aud") != aud:
            raise AuthenticationError("invalid access token audience")
        now_i = int(now)
        if now_i < int(claims.get("nbf", 0)) - 5:
            raise AuthenticationError("access token not yet valid")
        if now_i >= int(claims.get("exp", 0)):
            raise AuthenticationError("access token expired")
        for k in ("sub", "sid"):
            if not isinstance(claims.get(k), str) or not claims[k]:
                raise AuthenticationError("malformed access token")
        return claims


@dataclass(frozen=True)
class AccessClaims:
    user_id: str
    session_id: str
    org_id: Optional[str]
    roles: tuple
    is_platform_admin: bool
    amr: tuple
    exp: int
    jti: str

    @classmethod
    def from_claims(cls, c: dict) -> "AccessClaims":
        return cls(c["sub"], c["sid"], c.get("org"), tuple(c.get("roles") or ()),
                   bool(c.get("padmin")), tuple(c.get("amr") or ()), int(c["exp"]), str(c["jti"]))
