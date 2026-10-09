"""DEVELOPMENT-ONLY SPIFFE material + mock Workload API (local test CA).

Never usable in staging/production: DevWorkloadTransport refuses to construct unless the config
says `development` AND the process environment (AGENTGUARD_ENV) is unset or `development`.
It speaks the same wire protocol as SPIRE, so the production client code path is what runs.
"""
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional

import base64
import jwt as pyjwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import wire
from .config import ENV_VAR, Environment, SpireConfig
from .errors import DevModeError, R, SvidError, WorkloadApiUnavailable
from .workload_api import M_JWT, M_JWT_BUNDLES, M_X509, M_X509_BUNDLES

_DER = serialization.Encoding.DER


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _dt(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _b64u(n: int, ln: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(ln, "big")).rstrip(b"=").decode()


class DevSpireCA:
    """Local SPIRE-like CA for one trust domain: root (+ optional intermediate), JWT keys."""

    def __init__(self, trust_domain: str, clock, *, x509_ttl: int = 3600, jwt_ttl: int = 300,
                 with_intermediate: bool = True, name: str = "dev"):
        self.td, self.clock, self.x509_ttl, self.jwt_ttl = trust_domain, clock, x509_ttl, jwt_ttl
        self.with_intermediate, self.name = with_intermediate, name
        self._serial = 100
        self.roots: List[x509.Certificate] = []
        self._signer = None                    # (cert, key) that signs leaves
        self.jwt_keys: Dict[str, ec.EllipticCurvePrivateKey] = {}
        self.active_kid = None
        self.rotate_root()
        self.rotate_jwt_key()

    def _next_serial(self):
        self._serial += 1
        return self._serial

    def _ca_cert(self, subject, key, issuer_cert, issuer_key, pathlen):
        now = self.clock.now()
        b = (x509.CertificateBuilder().subject_name(_name(subject))
             .issuer_name(issuer_cert.subject if issuer_cert else _name(subject))
             .public_key(key.public_key()).serial_number(self._next_serial())
             .not_valid_before(_dt(now - 3600)).not_valid_after(_dt(now + 10 * 365 * 86400))
             .add_extension(x509.BasicConstraints(True, pathlen), True)
             .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False))
        if issuer_cert:
            b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)
        return b.sign(issuer_key or key, hashes.SHA256())

    def rotate_root(self, keep_old: bool = True):
        k = ec.generate_private_key(ec.SECP256R1())
        root = self._ca_cert(f"{self.name} root {self._serial}", k, None, None, None)
        self.roots = (self.roots if keep_old else []) + [root]
        if self.with_intermediate:
            ik = ec.generate_private_key(ec.SECP256R1())
            inter = self._ca_cert(f"{self.name} intermediate {self._serial}", ik, root, k, 0)
            self._signer = (inter, ik, [inter])
        else:
            self._signer = (root, k, [])

    def drop_old_roots(self):
        self.roots = self.roots[-1:]

    def rotate_jwt_key(self, keep_old: bool = True):
        kid = f"kid-{len(self.jwt_keys) + 1}-{self._next_serial()}"
        if not keep_old:
            self.jwt_keys = {}
        self.jwt_keys[kid] = ec.generate_private_key(ec.SECP256R1())
        self.active_kid = kid

    def issue_x509(self, spiffe_id: str, ttl: Optional[int] = None, *, not_before: Optional[float] = None):
        cert, key, inters = self._signer
        now = self.clock.now() if not_before is None else not_before
        lk = ec.generate_private_key(ec.SECP256R1())
        leaf = (x509.CertificateBuilder().subject_name(_name("workload")).issuer_name(cert.subject)
                .public_key(lk.public_key()).serial_number(self._next_serial())
                .not_valid_before(_dt(now - 1)).not_valid_after(_dt(now + (ttl or self.x509_ttl)))
                .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]), False)
                .add_extension(x509.BasicConstraints(False, None), True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                                      ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(lk.public_key()), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
                .sign(key, hashes.SHA256()))
        chain = leaf.public_bytes(_DER) + b"".join(c.public_bytes(_DER) for c in inters)
        kd = lk.private_bytes(_DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        return chain, kd

    def issue_jwt(self, spiffe_id: str, audiences, ttl: Optional[int] = None, *, claims: Optional[dict] = None,
                  kid: Optional[str] = None, key=None, alg: str = "ES256", headers: Optional[dict] = None) -> str:
        now = self.clock.now()
        c = {"sub": spiffe_id, "aud": list(audiences) if not isinstance(audiences, str) else audiences,
             "iat": int(now), "exp": int(now + (ttl or self.jwt_ttl))}
        c.update(claims or {})
        h = {"kid": kid or self.active_kid, "typ": "JWT"}
        h.update(headers or {})
        return pyjwt.encode(c, key or self.jwt_keys[self.active_kid], algorithm=alg, headers=h)

    def bundle_der(self) -> bytes:
        return b"".join(r.public_bytes(_DER) for r in self.roots)

    def jwks(self) -> bytes:
        keys = []
        for kid, k in self.jwt_keys.items():
            n = k.public_key().public_numbers()
            keys.append({"kty": "EC", "use": "jwt-svid", "crv": "P-256", "kid": kid,
                         "x": _b64u(n.x, 32), "y": _b64u(n.y, 32)})
        return json.dumps({"keys": keys}).encode()


def assert_dev_allowed(config: SpireConfig) -> None:
    proc = os.environ.get(ENV_VAR, "").strip().lower()
    if config.environment != Environment.DEVELOPMENT or config.provider != "dev" or \
            proc in ("staging", "production"):
        raise DevModeError("development Workload API refused: not a development environment")


class DevWorkloadTransport:
    """Mock SPIRE Workload API. `entitled` models SPIRE's attestation result: the SPIFFE IDs this
    workload may obtain. Test knobs: available, fail_next, tamper (response mutator)."""

    def __init__(self, config: SpireConfig, ca: DevSpireCA, entitled: Optional[List[str]] = None,
                 federated_cas: Optional[Dict[str, DevSpireCA]] = None):
        assert_dev_allowed(config.validate())
        self.ca, self.entitled = ca, list(entitled or [])
        self.federated = federated_cas or {}
        self.available = True
        self.fail_next = 0
        self.tamper: Optional[Callable[[str, bytes], bytes]] = None
        self.calls: Dict[str, int] = {}

    def _gate(self, method):
        self.calls[method] = self.calls.get(method, 0) + 1
        if not self.available:
            raise WorkloadApiUnavailable("dev workload api unavailable")
        if self.fail_next > 0:
            self.fail_next -= 1
            raise WorkloadApiUnavailable("dev workload api transient failure")

    def _out(self, method, data):
        return self.tamper(method, data) if self.tamper else data

    def first_stream_message(self, method, request, timeout):
        self._gate(method)
        if method == M_X509:
            svids = []
            for sid in self.entitled:
                chain, kd = self.ca.issue_x509(sid)
                svids.append({"spiffe_id": sid, "x509_svid": chain, "x509_svid_key": kd,
                              "bundle": self.ca.bundle_der()})
            fed = {td: c.bundle_der() for td, c in self.federated.items()}
            return self._out(method, wire.encode_x509_svid_response(svids, fed))
        if method == M_X509_BUNDLES:
            b = {self.ca.td: self.ca.bundle_der()}
            b.update({td: c.bundle_der() for td, c in self.federated.items()})
            return self._out(method, wire.encode_x509_bundles_response(b))
        if method == M_JWT_BUNDLES:
            b = {self.ca.td: self.ca.jwks()}
            b.update({td: c.jwks() for td, c in self.federated.items()})
            return self._out(method, wire.encode_jwt_bundles_response(b))
        raise WorkloadApiUnavailable("unknown method")

    def unary(self, method, request, timeout):
        self._gate(method)
        if method != M_JWT:
            raise WorkloadApiUnavailable("unknown method")
        aud, sid = wire.decode_jwt_svid_request(request)
        sid = sid or (self.entitled[0] if self.entitled else "")
        if sid not in self.entitled:
            raise SvidError("workload not entitled to requested SPIFFE ID", R.UNBOUND)
        return self._out(method, wire.encode_jwt_svid_response(
            [{"spiffe_id": sid, "svid": self.ca.issue_jwt(sid, aud)}]))

    def close(self):
        pass
