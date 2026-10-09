"""SPIFFE Workload API client (gRPC over a local unix socket).

Transport is pluggable: GrpcTransport talks to a real SPIRE agent (needs `grpcio`);
the same client code is exercised against the dev Workload API (dev.py) and the real SPIRE
integration test. Every failure path is DENY: unavailable API, malformed/expired material,
bad chain and unknown trust domains all raise and never return partial identities.
"""
import random
import time
from typing import Callable, List, Optional, Protocol

from . import metrics as M
from . import wire
from .bundle import TrustBundleStore
from .config import SpireConfig
from .errors import (R, SvidError, UnknownTrustDomainError, WorkloadApiUnavailable)
from .jwtsvid import JwtSvid, verify_jwt_svid
from .x509svid import X509Svid, parse_x509_svid, verify_x509_svid

M_X509 = "/SpiffeWorkloadAPI/FetchX509SVID"
M_JWT = "/SpiffeWorkloadAPI/FetchJWTSVID"
M_JWT_BUNDLES = "/SpiffeWorkloadAPI/FetchJWTBundles"
M_X509_BUNDLES = "/SpiffeWorkloadAPI/FetchX509Bundles"
_SECURITY_HEADER = (("workload.spiffe.io", "true"),)     # required by the Workload API spec


class WorkloadTransport(Protocol):
    def unary(self, method: str, request: bytes, timeout: float) -> bytes: ...
    def first_stream_message(self, method: str, request: bytes, timeout: float) -> bytes: ...
    def close(self) -> None: ...


class GrpcTransport:
    """Real transport. The Workload API is served on a local UDS and the SPIRE agent attests the
    caller from kernel peer credentials, so there is no TLS/credential to configure on this hop;
    protect the socket with filesystem permissions."""

    def __init__(self, socket_path: str, connect_timeout: float = 5.0):
        try:
            import grpc
        except ImportError:
            raise WorkloadApiUnavailable("grpcio is not installed (pip install agentguard-agent-identity[spire])")
        if not socket_path.startswith("unix:"):
            raise WorkloadApiUnavailable("only unix sockets are supported")
        self._grpc = grpc
        self._channel = grpc.insecure_channel(socket_path)
        self._connect_timeout = connect_timeout

    def _err(self, e):
        code = getattr(e, "code", lambda: None)()
        name = getattr(code, "name", "UNKNOWN")
        if name in ("PERMISSION_DENIED", "INVALID_ARGUMENT"):
            return SvidError(f"workload api rejected request ({name})", R.UNBOUND)
        return WorkloadApiUnavailable(f"workload api error ({name})")

    def unary(self, method, request, timeout):
        call = self._channel.unary_unary(method, request_serializer=lambda x: x,
                                         response_deserializer=lambda x: x)
        try:
            return call(request, timeout=timeout, metadata=_SECURITY_HEADER)
        except self._grpc.RpcError as e:
            raise self._err(e)

    def first_stream_message(self, method, request, timeout):
        call = self._channel.unary_stream(method, request_serializer=lambda x: x,
                                          response_deserializer=lambda x: x)
        it = call(request, timeout=timeout, metadata=_SECURITY_HEADER)
        try:
            return next(it)
        except StopIteration:
            raise WorkloadApiUnavailable("workload api closed stream without data")
        except self._grpc.RpcError as e:
            raise self._err(e)
        finally:
            it.cancel()

    def close(self):
        self._channel.close()


class WorkloadApiClient:
    def __init__(self, config: SpireConfig, transport: WorkloadTransport, bundles: TrustBundleStore,
                 clock, metrics: Optional[M.Metrics] = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.cfg = config
        self.transport = transport
        self.bundles = bundles
        self.clock = clock
        self.m = metrics or M.Metrics()
        self._sleep = sleep

    # -------------------------------------------------------------- retry policy
    def _call(self, fn):
        delay, last = self.cfg.retry_initial_backoff_seconds, None
        for attempt in range(self.cfg.retry_max_attempts):
            try:
                return fn()
            except WorkloadApiUnavailable as e:
                last = e
                self.m.inc(M.SPIRE_CONN_FAIL)
                if attempt + 1 < self.cfg.retry_max_attempts:
                    self._sleep(min(delay, self.cfg.retry_max_backoff_seconds) * (0.5 + random.random() / 2))
                    delay *= 2
        raise last

    # -------------------------------------------------------------- X.509
    def fetch_x509_svids(self) -> List[X509Svid]:
        raw = self._call(lambda: self.transport.first_stream_message(
            M_X509, b"", self.cfg.rpc_timeout_seconds))
        resp = wire.decode_x509_svid_response(raw)
        if not resp["svids"]:
            raise SvidError("workload api returned no SVIDs", R.UNBOUND)
        own = self.cfg.trust_domain
        parsed = []
        for s in resp["svids"]:
            svid = parse_x509_svid(s["x509_svid"], s["x509_svid_key"])
            if not svid.has_private_key():
                raise SvidError("SVID without private key", R.MALFORMED)
            if str(svid.spiffe_id) != s["spiffe_id"]:
                raise SvidError("SVID id differs from advertised id", R.BINDING_MISMATCH)
            if svid.spiffe_id.trust_domain != own:         # trust-domain isolation
                raise UnknownTrustDomainError("SVID from foreign trust domain")
            parsed.append((svid, s))
        # Bundles come from the local SPIRE agent (the root of trust on this host).
        for svid, s in parsed:
            self.bundles.update(own, x509_der=s["bundle"])
        for td, der in resp["federated_bundles"].items():
            if self.bundles.is_allowed(td) and td != own:
                self.bundles.update(td, x509_der=der)
            else:
                self.m.inc(M.BUNDLE_REJECTED, R.UNKNOWN_TRUST_DOMAIN)   # ignored, never trusted
        out = []
        for svid, _ in parsed:
            out.append(verify_x509_svid(svid.chain_der(), self.bundles, self.clock.now(),
                                        max_depth=self.cfg.max_x509_chain_depth,
                                        skew_seconds=self.cfg.clock_skew_seconds))
            out[-1] = X509Svid(out[-1].spiffe_id, out[-1].chain, out[-1].not_before,
                               out[-1].not_after, svid._key)
        return out

    def fetch_x509_svid(self, spiffe_id: Optional[str] = None) -> X509Svid:
        svids = self.fetch_x509_svids()
        if spiffe_id is None:
            return svids[0]
        for s in svids:
            if str(s.spiffe_id) == spiffe_id:
                return s
        raise SvidError("requested SPIFFE ID not issued to this workload", R.UNBOUND)

    def _decode_bundles(self, decoder, raw):
        """Corrupted bundle payloads are rejected (and counted); stored bundles stay untouched."""
        try:
            return decoder(raw)
        except Exception:
            self.m.inc(M.BUNDLE_REJECTED, R.MALFORMED)
            raise SvidError("malformed trust bundle response", R.MALFORMED)

    def refresh_x509_bundles(self) -> None:
        """Verifier-side refresh (needs no SVID entitlement)."""
        raw = self._call(lambda: self.transport.first_stream_message(
            M_X509_BUNDLES, b"", self.cfg.rpc_timeout_seconds))
        for td, der in self._decode_bundles(wire.decode_x509_bundles_response, raw).items():
            if self.bundles.is_allowed(td):
                self.bundles.update(td, x509_der=der)
            else:
                self.m.inc(M.BUNDLE_REJECTED, R.UNKNOWN_TRUST_DOMAIN)

    # -------------------------------------------------------------- JWT
    def refresh_jwt_bundles(self) -> None:
        raw = self._call(lambda: self.transport.first_stream_message(
            M_JWT_BUNDLES, b"", self.cfg.rpc_timeout_seconds))
        for td, jwks in self._decode_bundles(wire.decode_jwt_bundles_response, raw).items():
            if self.bundles.is_allowed(td):
                self.bundles.update(td, jwks=jwks)
            else:
                self.m.inc(M.BUNDLE_REJECTED, R.UNKNOWN_TRUST_DOMAIN)

    def _verify_jwt(self, token, audiences):
        j = verify_jwt_svid(token, audiences[0], self.bundles, self.clock.now(),
                            allowed_algs=self.cfg.jwt_allowed_algorithms,
                            skew_seconds=self.cfg.clock_skew_seconds,
                            max_ttl_seconds=self.cfg.jwt_max_ttl_seconds,
                            expected_issuer=self.cfg.jwt_expected_issuer,
                            max_token_bytes=self.cfg.max_token_bytes)
        if not set(audiences) <= set(j.audience):
            raise SvidError("issued token lacks requested audience", R.BAD_AUDIENCE)
        if j.spiffe_id.trust_domain != self.cfg.trust_domain:
            raise UnknownTrustDomainError("JWT-SVID from foreign trust domain")
        return j

    def fetch_jwt_svid(self, audiences, spiffe_id: Optional[str] = None) -> JwtSvid:
        audiences = [audiences] if isinstance(audiences, str) else list(audiences)
        if not audiences or not all(isinstance(a, str) and a for a in audiences):
            raise SvidError("audience required", R.BAD_AUDIENCE)
        req = wire.encode_jwt_svid_request(audiences, spiffe_id or "")
        raw = self._call(lambda: self.transport.unary(M_JWT, req, self.cfg.rpc_timeout_seconds))
        svids = wire.decode_jwt_svid_response(raw)
        if not svids:
            raise SvidError("workload api returned no JWT-SVID", R.UNBOUND)
        pick = svids[0]
        if spiffe_id is not None:
            pick = next((s for s in svids if s["spiffe_id"] == spiffe_id), None)
            if pick is None:
                raise SvidError("requested SPIFFE ID not issued", R.UNBOUND)
        if not self.bundles.has_fresh(self.cfg.trust_domain) or \
                not self.bundles.get(self.cfg.trust_domain).jwt_keys:
            self.refresh_jwt_bundles()
        try:
            j = self._verify_jwt(pick["svid"], audiences)
        except SvidError as e:
            if e.reason != R.UNKNOWN_KEY:
                raise
            self.refresh_jwt_bundles()                    # key rotation: refetch once, then retry
            j = self._verify_jwt(pick["svid"], audiences)
        if str(j.spiffe_id) != pick["spiffe_id"]:
            raise SvidError("JWT sub differs from advertised id", R.BINDING_MISMATCH)
        return j

    def close(self):
        self.transport.close()
