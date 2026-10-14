"""JWT-SVID validation (SPIFFE JWT-SVID spec) using PyJWT for signature verification.

Never accepts a token just because it parses: alg allow-list (asymmetric only), kid must exist
in the bundle of the trust domain named by `sub`, audience / expiry / lifetime enforced, optional
issuer pin, optional single-use (replay) enforcement.
"""
import hashlib
from dataclasses import dataclass, field
from typing import Iterable, Optional

import jwt as pyjwt

from .bundle import TrustBundleStore
from .errors import R, SvidError, SpiffeIdError
from .ids import SpiffeId, parse_spiffe_id


@dataclass(frozen=True)
class JwtSvid:
    spiffe_id: SpiffeId
    audience: tuple
    expiry: float
    issued_at: Optional[float]
    token: str = field(repr=False, default="")      # bearer secret: never in repr/logs

    def __repr__(self):
        return f"JwtSvid(spiffe_id={str(self.spiffe_id)!r}, expiry={self.expiry}, token=<redacted>)"


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def verify_jwt_svid(token, expected_audience: str, bundles: TrustBundleStore, now: float, *,
                    allowed_algs: Iterable[str], skew_seconds: int = 0, max_ttl_seconds: int = 3600,
                    expected_issuer: str = "", max_token_bytes: int = 8192,
                    replay_cache=None) -> JwtSvid:
    if not isinstance(token, str) or not token or len(token) > max_token_bytes:
        raise SvidError("bad token size", R.MALFORMED)
    if not isinstance(expected_audience, str) or not expected_audience:
        raise SvidError("expected audience is required", R.BAD_AUDIENCE)
    allowed = tuple(allowed_algs)
    try:
        header = pyjwt.get_unverified_header(token)
        unverified = pyjwt.decode(token, options={"verify_signature": False})
    except Exception:
        raise SvidError("malformed JWT", R.MALFORMED)
    alg, kid = header.get("alg"), header.get("kid")
    if alg not in allowed:                         # blocks none / HS* / alg-confusion
        raise SvidError("algorithm not allowed", R.BAD_ALG)
    if header.get("typ") not in (None, "JWT", "JOSE"):
        raise SvidError("bad typ", R.MALFORMED)
    if not isinstance(kid, str) or not kid:
        raise SvidError("missing kid", R.UNKNOWN_KEY)
    sub = unverified.get("sub")
    sid = parse_spiffe_id(sub)                     # raises SpiffeIdError
    if not sid.path:
        raise SpiffeIdError("sub must be a workload id")
    bundle = bundles.get(sid.trust_domain)         # unknown / stale trust domain => error
    key = bundle.jwt_keys.get(kid)
    if key is None:
        raise SvidError("signing key not in trust bundle", R.UNKNOWN_KEY)
    try:
        claims = pyjwt.decode(token, key=key, algorithms=[alg], options={
            "verify_signature": True, "verify_exp": False, "verify_nbf": False,
            "verify_iat": False, "verify_aud": False, "verify_iss": False,
            "require": ["exp", "sub", "aud"]})
    except pyjwt.InvalidSignatureError:
        raise SvidError("invalid signature", R.BAD_SIGNATURE)
    except pyjwt.PyJWTError:
        raise SvidError("token rejected", R.MALFORMED)
    except Exception:
        raise SvidError("token rejected", R.BAD_SIGNATURE)
    exp = claims["exp"]
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise SvidError("bad exp", R.MALFORMED)
    if now - skew_seconds >= exp:
        raise SvidError("JWT-SVID expired", R.EXPIRED)
    nbf = claims.get("nbf")
    if nbf is not None and (isinstance(nbf, bool) or not isinstance(nbf, (int, float))
                            or now + skew_seconds < nbf):
        raise SvidError("not yet valid", R.NOT_YET_VALID)
    iat = claims.get("iat")
    if iat is not None:
        if isinstance(iat, bool) or not isinstance(iat, (int, float)) or now + skew_seconds < iat:
            raise SvidError("iat in the future", R.NOT_YET_VALID)
    if exp - now > max_ttl_seconds + skew_seconds:
        raise SvidError("token lifetime exceeds policy", R.TTL_TOO_LONG)
    aud = claims["aud"]
    auds = (aud,) if isinstance(aud, str) else tuple(aud) if isinstance(aud, list) else None
    if not auds or not all(isinstance(a, str) for a in auds) or expected_audience not in auds:
        raise SvidError("audience mismatch", R.BAD_AUDIENCE)
    if expected_issuer and claims.get("iss") not in (None, expected_issuer):
        raise SvidError("issuer mismatch", R.BAD_ISSUER)
    if expected_issuer and "iss" not in claims:
        raise SvidError("issuer required", R.BAD_ISSUER)
    if replay_cache is not None:
        ttl = max(1.0, exp - now + skew_seconds)
        if not replay_cache.check_and_store("jwtsvid:" + token_fingerprint(token), ttl, now):
            raise SvidError("replayed token", R.REPLAY)
    return JwtSvid(sid, auds, float(exp), float(iat) if iat is not None else None, token)
