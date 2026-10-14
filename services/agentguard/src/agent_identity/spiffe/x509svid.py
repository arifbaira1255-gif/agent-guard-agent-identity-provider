"""X.509-SVID parsing and verification (SPIFFE X509-SVID spec) on top of `cryptography`.

Chain building/validation is delegated to cryptography.x509.verification (WebPKI-grade
path validation); we add the SPIFFE-specific leaf rules and per-trust-domain root isolation.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from .bundle import TrustBundleStore, load_certs
from .errors import R, SvidError, SpiffeIdError
from .ids import SpiffeId, parse_spiffe_id


@dataclass(frozen=True)
class X509Svid:
    spiffe_id: SpiffeId
    chain: tuple                                   # leaf first
    not_before: float
    not_after: float
    _key: object = field(default=None, repr=False, compare=False)

    @property
    def leaf(self) -> x509.Certificate:
        return self.chain[0]

    def chain_der(self) -> List[bytes]:
        return [c.public_bytes(serialization.Encoding.DER) for c in self.chain]

    def has_private_key(self) -> bool:
        return self._key is not None

    def private_key_pkcs8_der(self) -> bytes:
        """Explicit, deliberate accessor (for TLS context building); never called by logging."""
        if self._key is None:
            raise SvidError("no private key", R.MALFORMED)
        return self._key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption())

    def lifetime(self) -> float:
        return self.not_after - self.not_before

    def __repr__(self):
        return f"X509Svid(spiffe_id={str(self.spiffe_id)!r}, not_after={self.not_after}, key=<redacted>)"


def _leaf_id(leaf: x509.Certificate) -> SpiffeId:
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        raise SpiffeIdError("leaf has no SAN")
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        raise SpiffeIdError("leaf must have exactly one URI SAN")
    sid = parse_spiffe_id(uris[0])
    if not sid.path:
        raise SpiffeIdError("SVID must identify a workload, not a trust domain")
    return sid


def _check_leaf(leaf: x509.Certificate) -> None:
    try:
        bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            raise SvidError("leaf SVID must not be a CA", R.BAD_CHAIN)
    except x509.ExtensionNotFound:
        pass
    try:
        ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        raise SvidError("leaf SVID requires KeyUsage", R.BAD_CHAIN)
    if not ku.digital_signature or ku.key_cert_sign or ku.crl_sign:
        raise SvidError("invalid KeyUsage for leaf SVID", R.BAD_CHAIN)
    pub = leaf.public_key()
    if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
        raise SvidError("weak RSA key", R.BAD_CHAIN)
    if not isinstance(pub, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise SvidError("unsupported key type", R.BAD_CHAIN)


def _ts(dt: datetime) -> float:
    return dt.timestamp()


def parse_x509_svid(chain_der: bytes, key_der: Optional[bytes] = None) -> X509Svid:
    """Parse (no trust decision). Validates SPIFFE leaf rules and key/cert match."""
    certs = load_certs(chain_der)
    leaf = certs[0]
    sid = _leaf_id(leaf)
    _check_leaf(leaf)
    key = None
    if key_der:
        try:
            key = serialization.load_der_private_key(key_der, None)
        except Exception:
            raise SvidError("unparseable private key", R.MALFORMED)       # message has no key data
        enc = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        if key.public_key().public_bytes(*enc) != leaf.public_key().public_bytes(*enc):
            raise SvidError("private key does not match certificate", R.BINDING_MISMATCH)
    return X509Svid(sid, tuple(certs), _ts(leaf.not_valid_before_utc), _ts(leaf.not_valid_after_utc), key)


def verify_x509_svid(chain: Sequence[bytes], bundles: TrustBundleStore, now: float, *,
                     max_depth: int = 5, skew_seconds: int = 0) -> X509Svid:
    """Full verification. Trust anchors come ONLY from the bundle of the trust domain named in
    the leaf's SPIFFE ID, so a CA of domain A can never vouch for an ID in domain B."""
    if not chain:
        raise SvidError("empty chain", R.MALFORMED)
    try:
        certs = [x509.load_der_x509_certificate(d) for d in chain]
    except Exception:
        raise SvidError("unparseable certificate", R.MALFORMED)
    svid = parse_x509_svid(b"".join(chain))
    if now + skew_seconds < svid.not_before:
        raise SvidError("SVID not yet valid", R.NOT_YET_VALID)
    if now - skew_seconds >= svid.not_after:
        raise SvidError("SVID expired", R.EXPIRED)
    bundle = bundles.get(svid.spiffe_id.trust_domain)       # unknown/stale => error
    if not bundle.x509_roots:
        raise SvidError("trust domain has no X.509 authorities", R.UNKNOWN_TRUST_DOMAIN)
    try:
        verifier = (PolicyBuilder().store(Store(list(bundle.x509_roots)))
                    .time(datetime.fromtimestamp(now, tz=timezone.utc).replace(tzinfo=None))
                    .max_chain_depth(max_depth).build_client_verifier())
        verifier.verify(certs[0], certs[1:])
    except VerificationError:
        raise SvidError("certificate chain verification failed", R.BAD_CHAIN)
    except SvidError:
        raise
    except Exception:
        raise SvidError("certificate chain verification error", R.BAD_CHAIN)
    return svid
