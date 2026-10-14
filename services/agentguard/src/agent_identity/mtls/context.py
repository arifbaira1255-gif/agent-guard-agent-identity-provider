"""Rotating TLS contexts built from the workload's REAL X.509-SVID (spiffe.X509Source) and the
trust bundle (spiffe.TrustBundleStore). No second identity system: SPIRE issues and rotates, this
layer only re-materialises SSLContexts when the SVID or the bundle actually changes.

Graceful renewal: every NEW connection gets the context for the CURRENT SVID/bundle; connections
already established keep their negotiated session and are never torn down by a rotation.
Fail closed: if our own SVID is expired/unavailable, or a bundle is missing/stale, no context is
returned (-> handshakes are refused) rather than serving with outdated trust.
"""
import hashlib
import ssl
import threading
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import serialization

from ..spiffe import tlsutil
from ..spiffe.errors import SpiffeError
from . import metrics as MM
from .errors import M, MtlsError


@dataclass(frozen=True)
class _Snapshot:
    key: tuple
    server: ssl.SSLContext
    client: ssl.SSLContext
    serial: int
    not_after: float
    roots_fp: str


class RotatingTlsContext:
    def __init__(self, cfg, provider, policy_holder, clock, metrics: MM.MtlsMetrics, logger=None):
        self.cfg, self.provider, self.policies = cfg, provider, policy_holder
        self.clock, self.m, self.log = clock, metrics, logger
        self._source = provider.x509_source(cfg.workload_spiffe_id)
        self._snap: Optional[_Snapshot] = None
        self._l = threading.Lock()
        self._warned_serial = None

    def _roots(self):
        """Union of roots for accepted trust domains; own domain is mandatory, federated best-effort.
        (OpenSSL's chain check is a first filter; per-domain isolation is re-enforced by
        verify_x509_svid in the authenticator.)"""
        bundles, td = self.provider.bundles, self.cfg.own_trust_domain
        try:
            policy_domains = set(self.policies.current().accepted_trust_domains)
        except MtlsError:
            policy_domains = set()      # no policy: only own roots; authenticator denies everyone anyway
        roots = list(bundles.get(td).x509_roots)                  # raises if missing/stale -> deny
        for other in sorted(policy_domains - {td}):
            if bundles.is_allowed(other):
                try:
                    roots += list(bundles.get(other).x509_roots)
                except SpiffeError:
                    continue                                      # that domain is simply unusable
        if not roots:
            raise MtlsError("no trust anchors", M.TRUST_UNAVAILABLE)
        return roots

    def snapshot(self) -> _Snapshot:
        try:
            svid = self._source.current()                         # rotates before expiry; raises if expired
        except SpiffeError as e:
            self.m.inc(MM.WORKLOAD_API_FAIL, e.reason)
            raise MtlsError("own identity unavailable", M.IDENTITY_UNAVAILABLE) from None
        if str(svid.spiffe_id) != self.cfg.workload_spiffe_id:
            raise MtlsError("workload SVID is not the configured service identity", M.IDENTITY_UNAVAILABLE)
        try:
            roots = self._roots()
        except SpiffeError as e:
            raise MtlsError("trust bundle unavailable", M.TRUST_UNAVAILABLE) from None
        fp = hashlib.sha256(b"".join(r.public_bytes(serialization.Encoding.DER) for r in roots)).hexdigest()
        key = (svid.leaf.serial_number, fp, self.cfg.min_tls_version, self.cfg.tls12_ciphers)
        remaining = svid.not_after - self.clock.now()
        self.m.set_gauge(MM.G_CERT_EXPIRY, remaining)
        if remaining < self.cfg.expiry_warning_seconds and self._warned_serial != svid.leaf.serial_number:
            self._warned_serial = svid.leaf.serial_number
            if self.log:
                self.log.emit("mtls.cert.expiring", result="warn", expires_at=str(int(svid.not_after)))
        snap = self._snap
        if snap is not None and snap.key == key:
            return snap
        with self._l:
            snap = self._snap
            if snap is not None and snap.key == key:
                return snap
            ciphers = ":".join(self.cfg.tls12_ciphers)
            new = _Snapshot(key, tlsutil.server_context(svid, roots, self.cfg.min_tls_version, ciphers),
                            tlsutil.client_context(svid, roots, self.cfg.min_tls_version, ciphers),
                            svid.leaf.serial_number, svid.not_after, fp)
            if snap is not None:
                if snap.serial != new.serial:
                    self.m.inc(MM.CERT_ROTATIONS)
                    if self.log:
                        self.log.emit("mtls.cert.rotated", result="ok")
                if snap.roots_fp != new.roots_fp:
                    self.m.inc(MM.BUNDLE_ROTATIONS)
                    if self.log:
                        self.log.emit("mtls.bundle.rotated", result="ok")
            self._snap = new
            return new

    def server_context(self) -> ssl.SSLContext:
        return self.snapshot().server

    def client_context(self) -> ssl.SSLContext:
        return self.snapshot().client
