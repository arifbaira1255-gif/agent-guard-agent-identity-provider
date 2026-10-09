"""Trust bundle store: per-trust-domain X.509 roots + JWT authorities, atomically updated.

Rules: unknown trust domain => error (never trusted implicitly); stale bundle => error;
an update that fails validation is rejected and the previous good bundle is kept
(but still ages out, so a permanently-broken refresh ends in DENY, not in silent trust).
"""
import base64
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from .errors import (BundleStaleError, R, SvidError, UnknownTrustDomainError)
from . import metrics as M


def split_der(data: bytes) -> List[bytes]:
    """Split concatenated DER certificates (the Workload API 'bundle'/'x509_svid' encoding)."""
    out, i, n = [], 0, len(data)
    if n == 0:
        raise SvidError("empty certificate bundle", R.MALFORMED)
    while i < n:
        if data[i] != 0x30 or i + 1 >= n:
            raise SvidError("not DER", R.MALFORMED)
        first = data[i + 1]
        if first < 0x80:
            hdr, ln = 2, first
        else:
            k = first & 0x7F
            if k == 0 or k > 4 or i + 2 + k > n:
                raise SvidError("bad DER length", R.MALFORMED)
            hdr, ln = 2 + k, int.from_bytes(data[i + 2:i + 2 + k], "big")
        end = i + hdr + ln
        if end > n:
            raise SvidError("truncated DER", R.MALFORMED)
        out.append(data[i:end])
        i = end
    return out


def load_certs(der_concat: bytes) -> List[x509.Certificate]:
    try:
        return [x509.load_der_x509_certificate(d) for d in split_der(der_concat)]
    except SvidError:
        raise
    except Exception:
        raise SvidError("unparseable certificate", R.MALFORMED)


def _b64u(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        raise SvidError("bad base64url", R.MALFORMED)


_CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}


def parse_jwks(data: bytes) -> Dict[str, object]:
    """JWKS (RFC 7517) -> {kid: public_key}. Only EC / RSA(>=2048) keys; kid mandatory."""
    try:
        doc = json.loads(data)
        keys = doc["keys"]
        if not isinstance(keys, list):
            raise ValueError
    except Exception:
        raise SvidError("malformed JWKS", R.MALFORMED)
    out: Dict[str, object] = {}
    for k in keys:
        try:
            if k.get("use") not in (None, "jwt-svid"):
                continue                      # x509-svid keys are not JWT authorities
            kid = k["kid"]
            if not isinstance(kid, str) or not kid or kid in out:
                raise ValueError
            if k["kty"] == "EC":
                curve = _CURVES[k["crv"]]()
                pub = ec.EllipticCurvePublicNumbers(int.from_bytes(_b64u(k["x"]), "big"),
                                                    int.from_bytes(_b64u(k["y"]), "big"),
                                                    curve).public_key()
            elif k["kty"] == "RSA":
                pub = rsa.RSAPublicNumbers(int.from_bytes(_b64u(k["e"]), "big"),
                                           int.from_bytes(_b64u(k["n"]), "big")).public_key()
                if pub.key_size < 2048:
                    raise ValueError
            else:
                raise ValueError
            out[kid] = pub
        except SvidError:
            raise
        except Exception:
            raise SvidError("invalid JWKS entry", R.MALFORMED)
    return out


def _now_dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def validate_root(cert: x509.Certificate, now: float) -> None:
    """A trust anchor must be a CA, currently valid, and self-signature must verify."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise SvidError("root without BasicConstraints", R.BAD_CHAIN)
    if not bc.ca:
        raise SvidError("root is not a CA", R.BAD_CHAIN)
    if not (cert.not_valid_before_utc <= _now_dt(now) < cert.not_valid_after_utc):
        raise SvidError("root outside validity", R.EXPIRED)
    pub = cert.public_key()
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes,
                       ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(pub, rsa.RSAPublicKey):
            from cryptography.hazmat.primitives.asymmetric import padding
            pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(),
                       cert.signature_hash_algorithm)
        else:
            raise SvidError("unsupported root key", R.BAD_CHAIN)
    except InvalidSignature:
        raise SvidError("root is not self-signed", R.BAD_CHAIN)
    except SvidError:
        raise
    except Exception:
        raise SvidError("root signature check failed", R.BAD_CHAIN)


@dataclass(frozen=True)
class TrustBundle:
    trust_domain: str
    x509_roots: tuple
    jwt_keys: Dict[str, object]
    updated_at: float


class TrustBundleStore:
    def __init__(self, own_trust_domain: str, federated: Iterable[str] = (), *, clock,
                 max_age_seconds: int, metrics: Optional[M.Metrics] = None):
        self.own = own_trust_domain
        self._allowed = {own_trust_domain, *federated}
        self._clock = clock
        self._max_age = max_age_seconds
        self._m = metrics or M.Metrics()
        self._b: Dict[str, TrustBundle] = {}
        self._l = threading.RLock()

    def is_allowed(self, td: str) -> bool:
        return td in self._allowed

    def update(self, td: str, *, x509_der: Optional[bytes] = None,
               jwks: Optional[bytes] = None) -> None:
        """Atomically merge new material for ONE trust domain. Rejects unknown domains and
        any invalid input without touching the stored bundle."""
        if td not in self._allowed:
            self._m.inc(M.BUNDLE_REJECTED, R.UNKNOWN_TRUST_DOMAIN)
            raise UnknownTrustDomainError("trust domain not configured")
        now = self._clock.now()
        try:
            with self._l:
                cur = self._b.get(td)
                roots = cur.x509_roots if cur else ()
                jkeys = cur.jwt_keys if cur else {}
                if x509_der is not None:
                    certs = load_certs(x509_der)
                    for c in certs:
                        validate_root(c, now)
                    roots = tuple(certs)
                if jwks is not None:
                    jkeys = parse_jwks(jwks)
                if not roots and not jkeys:
                    raise SvidError("empty trust bundle", R.MALFORMED)
                self._b[td] = TrustBundle(td, roots, jkeys, now)
        except SvidError as e:
            self._m.inc(M.BUNDLE_REJECTED, e.reason)
            raise
        self._m.inc(M.BUNDLE_UPDATES)

    def get(self, td: str) -> TrustBundle:
        if td not in self._allowed:
            raise UnknownTrustDomainError("trust domain not configured")
        with self._l:
            b = self._b.get(td)
        if b is None:
            raise UnknownTrustDomainError("no trust bundle loaded for trust domain")
        if self._clock.now() - b.updated_at > self._max_age:
            raise BundleStaleError("trust bundle is stale")
        return b

    def has_fresh(self, td: str) -> bool:
        try:
            self.get(td)
            return True
        except SvidError:
            return False
