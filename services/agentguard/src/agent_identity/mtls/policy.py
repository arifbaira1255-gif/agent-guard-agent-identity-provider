"""Trust policy: WHICH authenticated peers may talk to this service. Authentication only.

This layer answers "is this peer one of the identities we agreed to talk to?" - it deliberately
does NOT decide what a peer may do once connected (that is application authorization, Step 8).
Rules are deny-by-default: an empty rule set trusts nobody. Matching is exact, or by
segment-bounded prefix (`spiffe://td/service/` matches `spiffe://td/service/api` but never
`spiffe://td/service-evil/...` or `spiffe://td/servicefoo`). There are no wildcards or regexes.
"""
import base64
import json
import threading
from dataclasses import dataclass, field
from typing import Iterable, Optional, Tuple

from ..crypto import keys
from ..spiffe.errors import SpiffeIdError
from ..spiffe.ids import SpiffeId, parse_agent_spiffe_id, parse_spiffe_id
from .errors import M, MtlsConfigError, MtlsError

POLICY_DOMAIN = b"agentguard-mtls-trust-policy-v1\n"


def _ids(values: Iterable[str]) -> Tuple[str, ...]:
    out = []
    for v in values or ():
        try:
            sid = parse_spiffe_id(v)
        except SpiffeIdError:
            raise MtlsConfigError("policy contains an invalid SPIFFE ID", M.POLICY) from None
        if not sid.path:
            raise MtlsConfigError("policy IDs must name workloads, not trust domains", M.POLICY)
        out.append(str(sid))
    return tuple(sorted(set(out)))


def _prefixes(values: Iterable[str]) -> Tuple[str, ...]:
    out = []
    for v in values or ():
        if not isinstance(v, str) or not v.endswith("/") or v.count("/") < 4:
            raise MtlsConfigError("prefix rules must end with '/' and include a path segment", M.POLICY)
        try:
            sid = parse_spiffe_id(v[:-1])
        except SpiffeIdError:
            raise MtlsConfigError("policy contains an invalid SPIFFE prefix", M.POLICY) from None
        if not sid.path:
            raise MtlsConfigError("prefix must include a path segment", M.POLICY)
        out.append(str(sid) + "/")
    return tuple(sorted(set(out)))


@dataclass(frozen=True)
class PeerRules:
    exact: Tuple[str, ...] = ()
    prefixes: Tuple[str, ...] = ()
    allow_agents: bool = False          # AgentGuard-bound agent identities (registry-verified)

    def __post_init__(self):
        object.__setattr__(self, "exact", _ids(self.exact))
        object.__setattr__(self, "prefixes", _prefixes(self.prefixes))

    def matches(self, sid: SpiffeId) -> bool:
        s = str(sid)
        if s in self.exact:
            return True
        if any(s.startswith(p) and len(s) > len(p) for p in self.prefixes):
            return True
        if self.allow_agents:
            try:
                parse_agent_spiffe_id(sid)
                return True
            except SpiffeIdError:
                return False
        return False


@dataclass(frozen=True)
class TrustPolicy:
    version: int
    accepted_trust_domains: Tuple[str, ...]
    inbound: PeerRules = field(default_factory=PeerRules)     # who may connect TO us
    outbound: PeerRules = field(default_factory=PeerRules)    # which servers WE may connect to
    denied: Tuple[str, ...] = ()                               # explicit deny always wins
    not_after: int = 0                                         # 0 = no expiry

    def __post_init__(self):
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise MtlsConfigError("policy version must be a positive integer", M.POLICY)
        if not self.accepted_trust_domains:
            raise MtlsConfigError("policy must accept at least one trust domain", M.POLICY)
        for td in self.accepted_trust_domains:
            try:
                if parse_spiffe_id(f"spiffe://{td}").path:
                    raise SpiffeIdError("x")
            except SpiffeIdError:
                raise MtlsConfigError("invalid trust domain in policy", M.POLICY) from None
        object.__setattr__(self, "accepted_trust_domains", tuple(sorted(set(self.accepted_trust_domains))))
        object.__setattr__(self, "denied", _ids(self.denied))

    def decide(self, sid: SpiffeId, direction: str) -> Optional[str]:
        """Return None if allowed, else a stable denial reason. direction: inbound|outbound."""
        if sid.trust_domain not in self.accepted_trust_domains:
            return M.PEER_DOMAIN
        if str(sid) in self.denied:
            return M.PEER_NOT_ALLOWED
        rules = self.inbound if direction == "inbound" else self.outbound if direction == "outbound" else None
        if rules is None or not rules.matches(sid):
            return M.PEER_NOT_ALLOWED
        return None

    def to_dict(self) -> dict:
        r = lambda x: {"exact": list(x.exact), "prefixes": list(x.prefixes), "allow_agents": x.allow_agents}
        return {"version": self.version, "accepted_trust_domains": list(self.accepted_trust_domains),
                "inbound": r(self.inbound), "outbound": r(self.outbound), "denied": list(self.denied),
                "not_after": self.not_after}

    @classmethod
    def from_dict(cls, d: dict) -> "TrustPolicy":
        known = {"version", "accepted_trust_domains", "inbound", "outbound", "denied", "not_after"}
        if not isinstance(d, dict) or set(d) - known:
            raise MtlsConfigError("unknown or malformed policy keys", M.POLICY)

        def rules(x):
            if not isinstance(x, dict) or set(x) - {"exact", "prefixes", "allow_agents"}:
                raise MtlsConfigError("malformed rules", M.POLICY)
            if not isinstance(x.get("allow_agents", False), bool):
                raise MtlsConfigError("allow_agents must be boolean", M.POLICY)
            return PeerRules(tuple(x.get("exact", ())), tuple(x.get("prefixes", ())),
                             x.get("allow_agents", False))
        try:
            return cls(version=d.get("version"), accepted_trust_domains=tuple(d.get("accepted_trust_domains", ())),
                       inbound=rules(d.get("inbound", {})), outbound=rules(d.get("outbound", {})),
                       denied=tuple(d.get("denied", ())), not_after=int(d.get("not_after", 0)))
        except (TypeError, ValueError):
            raise MtlsConfigError("malformed policy", M.POLICY) from None


class PolicyHolder:
    """Atomic, monotonic holder. With no policy loaded, current() raises: nobody is trusted."""

    def __init__(self, clock, metrics=None, logger=None):
        self._clock, self._m, self._log = clock, metrics, logger
        self._p: Optional[TrustPolicy] = None
        self._l = threading.Lock()

    def set(self, policy: TrustPolicy, *, allow_same_version: bool = False) -> None:
        with self._l:
            cur = self._p
            if cur is not None and (policy.version < cur.version or
                                    (policy.version == cur.version and not allow_same_version)):
                self._reject(M.POLICY_ROLLBACK)
                raise MtlsError("policy version must increase", M.POLICY_ROLLBACK)
            if policy.not_after and policy.not_after <= self._clock.now():
                self._reject(M.POLICY_EXPIRED)
                raise MtlsError("policy already expired", M.POLICY_EXPIRED)
            self._p = policy
        if self._m:
            from . import metrics as MM
            self._m.inc(MM.POLICY_UPDATES)
        if self._log:
            self._log.emit("mtls.policy.update", result="ok", key_id_version=str(policy.version))

    def _reject(self, reason):
        if self._m:
            from . import metrics as MM
            self._m.inc(MM.POLICY_REJECTED, reason)

    def current(self) -> TrustPolicy:
        p = self._p
        if p is None:
            raise MtlsError("no trust policy loaded", M.POLICY)
        if p.not_after and p.not_after <= self._clock.now():
            self._reject(M.POLICY_EXPIRED)
            raise MtlsError("trust policy expired", M.POLICY_EXPIRED)
        return p

    def loaded(self) -> bool:
        try:
            self.current()
            return True
        except MtlsError:
            return False


# ----------------------------------------------------------------- signed policy distribution
def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def sign_policy(provider, key_id: str, policy: TrustPolicy, *, issued_at: int) -> dict:
    """Sign a policy with a KMS/HSM-held Ed25519 key via the EXISTING KeyManagementProvider
    (sign-only; the private key never leaves the provider). Fails closed if the KMS is down."""
    from ..kms.errors import KmsError
    body = _canon({"issued_at": int(issued_at), "policy": policy.to_dict()})
    try:
        sig = provider.sign(key_id, POLICY_DOMAIN, body)
        _, pub_b64, _ = provider.public_key(key_id)
    except KmsError as e:
        raise MtlsError("KMS unavailable or refused signing", M.KMS_UNAVAILABLE) from e
    return {"body": base64.urlsafe_b64encode(body).decode(),
            "signature": base64.urlsafe_b64encode(sig).decode(), "signer": pub_b64}


def load_signed_policy(bundle: dict, trusted_signers: Iterable[str]) -> TrustPolicy:
    """Verify (local Ed25519; no KMS round-trip needed) and parse. Unknown signer, bad signature,
    malformed body => reject. The caller then PolicyHolder.set(), which enforces monotonic version."""
    try:
        body = base64.urlsafe_b64decode(bundle["body"].encode())
        sig = base64.urlsafe_b64decode(bundle["signature"].encode())
        signer = bundle["signer"]
    except Exception:
        raise MtlsError("malformed signed policy", M.POLICY_SIGNATURE) from None
    if signer not in set(trusted_signers):
        raise MtlsError("policy signer is not trusted", M.POLICY_SIGNATURE)
    try:
        ok = keys.verify(signer, POLICY_DOMAIN, body, sig)
    except Exception:
        ok = False
    if not ok:
        raise MtlsError("policy signature invalid", M.POLICY_SIGNATURE)
    try:
        doc = json.loads(body.decode())
        return TrustPolicy.from_dict(doc["policy"])
    except MtlsError:
        raise
    except Exception:
        raise MtlsError("malformed policy body", M.POLICY) from None
