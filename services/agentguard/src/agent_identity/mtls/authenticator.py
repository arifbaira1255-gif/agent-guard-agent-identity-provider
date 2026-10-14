"""Peer authentication: turns a presented certificate chain into a verified PeerIdentity, or DENY.

Order (every step fails closed, none is skippable):
  1. SPIFFE X.509-SVID verification against the bundle of the SVID's OWN trust domain
     (chain, validity window incl. skew, leaf profile) - reuses spiffe.x509svid.verify_x509_svid
  2. certificate purpose (EKU) for the peer's role
  3. trust policy (accepted trust domains, allowed identities, explicit denies)
  4. per-certificate denylist (revoked leaf certificates)
  5. AgentGuard agent identities additionally pass SpiffeIdentityProvider.verify_x509
     (binding, org/agent/instance status, delegation, ancestors, revocation - re-checked each time)
  6. optional exact pin (client side): the server MUST be exactly the expected service
This is authentication only. What the peer may *do* is decided by application authorization.
"""
import hashlib
import threading
from dataclasses import dataclass
from typing import List, Optional

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from ..spiffe.errors import R, SpiffeError, SpiffeIdError, SvidError
from ..spiffe.ids import SpiffeId, parse_agent_spiffe_id
from ..spiffe.x509svid import verify_x509_svid
from . import metrics as MM
from .errors import M, PeerRejected

_SVID_TO_MTLS = {R.UNKNOWN_TRUST_DOMAIN: M.PEER_DOMAIN, R.BUNDLE_STALE: M.TRUST_UNAVAILABLE,
                 R.EXPIRED: M.PEER_CHAIN, R.NOT_YET_VALID: M.PEER_CHAIN, R.BAD_CHAIN: M.PEER_CHAIN,
                 R.MALFORMED: M.PEER_CHAIN, R.BAD_SPIFFE_ID: M.PEER_CHAIN}


@dataclass(frozen=True)
class PeerIdentity:
    spiffe_id: str
    trust_domain: str
    cert_fingerprint: str
    not_after: float
    is_agent: bool = False
    org_id: Optional[str] = None
    agent_id: Optional[str] = None
    instance_id: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"spiffe_id": self.spiffe_id, "trust_domain": self.trust_domain,
             "not_after": self.not_after, "is_agent": self.is_agent}
        if self.is_agent:
            d.update(org_id=self.org_id, agent_id=self.agent_id, instance_id=self.instance_id)
        return d


class CertDenylist:
    """Revoked leaf certificates (by SHA-256 of the DER). Entries expire with the certificate."""

    def __init__(self, clock):
        self._clock, self._d, self._l = clock, {}, threading.Lock()

    @staticmethod
    def fingerprint(leaf_der: bytes) -> str:
        return hashlib.sha256(leaf_der).hexdigest()

    def deny(self, leaf_der: bytes, until: float) -> None:
        with self._l:
            self._d[self.fingerprint(leaf_der)] = until

    def denied(self, fp: str) -> bool:
        now = self._clock.now()
        with self._l:
            for k in [k for k, v in self._d.items() if v <= now]:
                del self._d[k]
            return fp in self._d


class PeerAuthenticator:
    def __init__(self, provider, policy_holder, cfg, clock, metrics: MM.MtlsMetrics, logger=None,
                 denylist: Optional[CertDenylist] = None):
        self.provider, self.policies, self.cfg = provider, policy_holder, cfg
        self.clock, self.m, self.log = clock, metrics, logger
        self.denylist = denylist or CertDenylist(clock)

    def _reject(self, reason: str, endpoint: str, sid: Optional[str] = None):
        self.m.inc(MM.PEER_REJECTED, reason)
        if self.log:
            self.log.emit("mtls.peer.rejected", result="denied", reason=reason, endpoint=endpoint,
                          peer_spiffe_id=sid)
        raise PeerRejected("peer rejected", reason)

    def authenticate(self, chain_der: List[bytes], *, direction: str,
                     expected_spiffe_id: Optional[str] = None) -> PeerIdentity:
        """direction='inbound': we are the server authenticating a client; 'outbound': we are the
        client authenticating a server."""
        if direction not in ("inbound", "outbound"):
            raise ValueError("direction")
        if direction == "outbound" and not expected_spiffe_id:
            self._reject(M.PEER_MISMATCH, direction)           # clients must always pin a service
        if not chain_der:
            self._reject(M.NO_PEER_CERT, direction)
        sid_s = None
        try:
            policy = self.policies.current()
            svid = verify_x509_svid(chain_der, self.provider.bundles, self.clock.now(),
                                    max_depth=self.provider.cfg.max_x509_chain_depth,
                                    skew_seconds=self.provider.cfg.clock_skew_seconds)
            sid: SpiffeId = svid.spiffe_id
            sid_s = str(sid)
            self._check_purpose(svid.leaf, direction)
            why = policy.decide(sid, direction)
            if why:
                self._reject(why, direction, sid_s)
            fp = CertDenylist.fingerprint(chain_der[0])
            if self.denylist.denied(fp):
                self._reject(M.PEER_REVOKED, direction, sid_s)
            if expected_spiffe_id and sid_s != expected_spiffe_id:
                self._reject(M.PEER_MISMATCH, direction, sid_s)
            parts = None
            try:
                parts = parse_agent_spiffe_id(sid)
            except SpiffeIdError:
                pass
            if parts is not None:
                res = self.provider.verify_x509(chain_der)      # registry / revocation / delegation
                if not res.valid:
                    self._reject(M.PEER_INACTIVE, direction, sid_s)
            return PeerIdentity(sid_s, sid.trust_domain, fp, svid.not_after, parts is not None,
                                parts.org_id if parts else None, parts.agent_id if parts else None,
                                parts.instance_id if parts else None)
        except PeerRejected:
            raise
        except SvidError as e:
            self._reject(_SVID_TO_MTLS.get(e.reason, M.PEER_CHAIN), direction, sid_s)
        except SpiffeError:
            self._reject(M.PEER_CHAIN, direction, sid_s)
        except Exception as e:  # noqa: BLE001 - incl. MtlsError (no policy): never fail open
            reason = getattr(e, "reason", M.INTERNAL)
            self._reject(reason, direction, sid_s)

    def _check_purpose(self, leaf: x509.Certificate, direction: str) -> None:
        need = ExtendedKeyUsageOID.CLIENT_AUTH if direction == "inbound" else ExtendedKeyUsageOID.SERVER_AUTH
        try:
            eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            if self.cfg.require_eku:
                self._reject(M.PEER_PURPOSE, direction)
            return
        if need not in eku and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in eku:
            self._reject(M.PEER_PURPOSE, direction)
        if ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in eku and self.cfg.require_eku:
            if need not in eku:        # anyEKU is not an acceptable substitute when EKU is required
                self._reject(M.PEER_PURPOSE, direction)
