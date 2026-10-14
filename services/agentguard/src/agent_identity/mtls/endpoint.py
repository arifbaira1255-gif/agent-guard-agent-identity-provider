"""MtlsEndpoint: the one object services use for authenticated, encrypted peer connections.

    ep = MtlsEndpoint(cfg, provider, policy_holder)        # provider = SpiffeIdentityProvider (real SPIRE)
    ep.start()                                              # background trust-bundle refresh
    tls_sock, peer = ep.accept(raw_sock)                    # server side: handshake + authenticate
    tls_sock, peer = ep.connect(host, port, expected_spiffe_id=...)   # client side: pinned service

There is no plaintext code path in this class: every method either returns an authenticated TLS
socket or raises (and closes the socket).
"""
import ipaddress
import socket
import ssl
import threading
import time
from typing import Callable, Optional, Tuple

from ..core.clock import Clock
from ..observability.logging import SecurityLogger
from ..spiffe import tlsutil
from ..spiffe.errors import SpiffeError
from . import metrics as MM
from .authenticator import CertDenylist, PeerAuthenticator, PeerIdentity
from .config import MtlsConfig
from .context import RotatingTlsContext
from .errors import M, MtlsError, PeerRejected
from .policy import PolicyHolder


def _classify(e: BaseException) -> str:
    if isinstance(e, (socket.timeout, TimeoutError)):
        return M.HANDSHAKE_TIMEOUT
    if isinstance(e, ssl.SSLCertVerificationError):
        return M.PEER_CHAIN
    if isinstance(e, ssl.SSLError):
        lib = getattr(e, "reason", "") or ""
        if "CERTIFICATE_REQUIRED" in lib or "PEER_DID_NOT_RETURN" in lib or "NO_CERTIFICATE" in lib:
            return M.NO_PEER_CERT
        return M.HANDSHAKE
    return M.HANDSHAKE


class MtlsEndpoint:
    def __init__(self, cfg: MtlsConfig, provider, policies: PolicyHolder, *,
                 clock: Optional[Clock] = None, metrics: Optional[MM.MtlsMetrics] = None,
                 logger: Optional[SecurityLogger] = None, denylist: Optional[CertDenylist] = None,
                 kms_health: Optional[Callable[[], bool]] = None, kms_required: bool = False):
        self.cfg = cfg.validate()
        if provider.cfg.trust_domain != cfg.own_trust_domain:
            raise MtlsError("mTLS workload identity is outside the provider's trust domain", M.CONFIG)
        self.provider, self.policies = provider, policies
        self.clock = clock or provider.clock
        self.metrics = metrics or MM.MtlsMetrics()
        self.log = logger or provider.svc.log
        self.contexts = RotatingTlsContext(self.cfg, provider, policies, self.clock, self.metrics, self.log)
        self.auth = PeerAuthenticator(provider, policies, self.cfg, self.clock, self.metrics, self.log, denylist)
        self._kms_health, self._kms_required = kms_health, kms_required
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> "MtlsEndpoint":
        if self._thread is None:
            self._thread = threading.Thread(target=self._refresh_loop, name="mtls-bundles", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def refresh_once(self) -> bool:
        """Poll SPIRE for bundle + SVID changes. A failure never relaxes anything: staleness is
        enforced by the bundle store (max age) and SVID expiry, both of which deny."""
        try:
            self.provider.refresh_bundles()
            self.contexts.snapshot()
            return True
        except Exception as e:  # noqa: BLE001
            self.metrics.inc(MM.WORKLOAD_API_FAIL, getattr(e, "reason", M.INTERNAL))
            if self.log:
                self.log.emit("mtls.refresh", result="failed", reason=getattr(e, "reason", M.INTERNAL))
            return False

    def _refresh_loop(self):
        while not self._stop.wait(self.cfg.bundle_refresh_interval_seconds):
            self.refresh_once()

    # ------------------------------------------------------------------ server side
    def accept(self, raw: socket.socket) -> Tuple[ssl.SSLSocket, PeerIdentity]:
        t0 = time.perf_counter()
        tls = None
        try:
            self.policies.current()                    # no/expired policy => nobody is trusted: refuse early
            ctx = self.contexts.server_context()
            raw.settimeout(self.cfg.handshake_timeout_seconds)
            tls = ctx.wrap_socket(raw, server_side=True)
            peer = self.auth.authenticate(tlsutil.peer_chain_der(tls), direction="inbound")
            tls.settimeout(None)
        except PeerRejected:
            self._fail(raw, tls, None, t0)        # reason already counted by the authenticator
            raise
        except BaseException as e:
            reason = e.reason if isinstance(e, MtlsError) else _classify(e)
            self._fail(raw, tls, reason, t0)
            raise MtlsError("handshake refused", reason) from None
        self.metrics.inc(MM.HANDSHAKES, "inbound")
        self.metrics.observe(MM.HANDSHAKE_LATENCY, time.perf_counter() - t0)
        return tls, peer

    # ------------------------------------------------------------------ client side
    def connect(self, host: str, port: int, *, expected_spiffe_id: str) -> Tuple[ssl.SSLSocket, PeerIdentity]:
        if not expected_spiffe_id:
            raise MtlsError("expected_spiffe_id is mandatory", M.PEER_MISMATCH)
        t0 = time.perf_counter()
        raw = tls = None
        try:
            self.policies.current()
            ctx = self.contexts.client_context()
            raw = socket.create_connection((host, port), timeout=self.cfg.connect_timeout_seconds)
            raw.settimeout(self.cfg.handshake_timeout_seconds)
            try:
                ipaddress.ip_address(host)
                sni = None
            except ValueError:
                sni = host
            tls = ctx.wrap_socket(raw, server_hostname=sni)
            peer = self.auth.authenticate(tlsutil.peer_chain_der(tls), direction="outbound",
                                          expected_spiffe_id=expected_spiffe_id)
            tls.settimeout(None)
        except PeerRejected:
            self._fail(raw, tls, None, t0, conn=True)
            raise
        except BaseException as e:
            if raw is None:
                reason = M.HANDSHAKE_TIMEOUT if isinstance(e, (socket.timeout, TimeoutError)) \
                    else e.reason if isinstance(e, MtlsError) else "connect_failed"
                self.metrics.inc(MM.CONN_FAIL, reason)
                if self.log:
                    self.log.emit("mtls.connect", result="failed", reason=reason, endpoint="outbound")
                raise MtlsError("connection failed", reason) from None
            reason = e.reason if isinstance(e, MtlsError) else _classify(e)
            self._fail(raw, tls, reason, t0, conn=True)
            raise MtlsError("handshake refused", reason) from None
        self.metrics.inc(MM.HANDSHAKES, "outbound")
        self.metrics.observe(MM.HANDSHAKE_LATENCY, time.perf_counter() - t0)
        return tls, peer

    def _fail(self, raw, tls, reason, t0, conn=False):
        for s in (tls, raw):
            try:
                if s is not None:
                    s.close()
            except Exception:  # noqa: BLE001
                pass
        if reason:
            self.metrics.inc(MM.HANDSHAKE_FAIL, reason)
            if self.log:
                self.log.emit("mtls.handshake", result="failed", reason=reason,
                              endpoint="outbound" if conn else "inbound")
        self.metrics.observe(MM.HANDSHAKE_LATENCY, time.perf_counter() - t0)

    # ------------------------------------------------------------------ health
    def liveness(self) -> dict:
        return {"status": "alive"}

    def readiness(self) -> dict:
        """Public-safe: coarse ok/fail per capability. No identities, paths, versions or timings."""
        checks = {}
        remaining = None
        try:
            snap = self.contexts.snapshot()
            remaining = snap.not_after - self.clock.now()
            checks["identity"] = remaining >= self.cfg.min_ready_remaining_seconds
        except MtlsError as e:
            checks["identity"] = False
            if e.reason == M.TRUST_UNAVAILABLE:
                checks["trust_bundle"] = False
        checks.setdefault("trust_bundle", checks["identity"] or self.provider.bundles.has_fresh(self.cfg.own_trust_domain))
        checks["policy"] = self.policies.loaded()
        if self._kms_health is not None:
            try:
                ok = bool(self._kms_health())
            except Exception:  # noqa: BLE001
                ok = False
            checks["kms"] = ok if self._kms_required else True
        ready = all(checks.values())
        return {"status": "ready" if ready else "not_ready",
                "checks": {k: ("ok" if v else "fail") for k, v in checks.items()}}

    def diagnostics(self) -> dict:
        """For authenticated operators only (not for public probes)."""
        out = {"readiness": self.readiness(), "policy_version": None, "tls_min": self.cfg.min_tls_version}
        try:
            out["policy_version"] = self.policies.current().version
        except MtlsError:
            pass
        out["cert_expiry_seconds"] = round(self.metrics.gauge(MM.G_CERT_EXPIRY), 1)
        return out
