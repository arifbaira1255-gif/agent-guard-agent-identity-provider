"""SpiffeIdentityProvider: the real SPIFFE/SPIRE adapter behind AgentGuard's IdentityProvider.

SPIRE replaces the *issuer/root of trust*; AgentGuard's registry, revocation, delegation and
capability layers stay authoritative. Chain of identity (all links explicit and checked):

    AgentGuard agent --(deterministic, immutable Binding)--> SPIFFE ID
        --(SPIRE attestation: selectors)--> runtime workload --> instance (+ session)

Security invariants (each has tests in tests/test_spiffe_*.py):
 I1  Unknown / stale trust domain, bad chain, bad signature, expired, malformed  => DENY
 I2  A SPIFFE ID verifies only if it is bound (once, immutably) to an AgentGuard identity
 I3  The SPIFFE ID path must equal the binding (no prefix matching, no re-pointing)
 I4  Agent/instance/org status, revocation and ancestor state are re-checked on EVERY verify
 I5  A sub-agent is only bound through an authorized spawn by a verified parent; self-declared
     children are unbound => DENY; capabilities can only narrow
 I6  Private keys never appear in repr/logs/metrics/API responses
 I7  Any unexpected exception during verification => DENY (never fail open)
"""
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from ..adapters.spiffe import IdentityProvider
from ..api.service import SPAWN_AUDIENCE, IdentityService, SpawnResult
from ..core.clock import Clock
from ..core.errors import NotFoundError, UnauthorizedError
from ..core.models import Reason, Status, TargetType, VerificationResult, iso
from ..storage.memory import MemoryReplayCache
from . import metrics as M
from .bindings import Binding, BindingRegistry, MemoryBindingRegistry
from .bundle import TrustBundleStore
from .config import SpireConfig
from .errors import (R, SpiffeError, SpiffeIdError, SvidError, UnknownTrustDomainError)
from .ids import SpiffeId, agent_spiffe_id, parse_agent_spiffe_id, parse_spiffe_id
from .jwtsvid import JwtSvid, verify_jwt_svid
from .source import JwtSource, X509Source
from .workload_api import WorkloadApiClient, WorkloadTransport
from .x509svid import X509Svid, verify_x509_svid

_REFRESHABLE = {R.BUNDLE_STALE, R.UNKNOWN_KEY, R.BAD_CHAIN, R.UNKNOWN_TRUST_DOMAIN}
_MIN_FORCED_REFRESH_GAP = 5.0       # seconds; stops garbage tokens from causing refresh storms


@dataclass(frozen=True)
class SpiffeIdentity:
    """What issue() returns. Contains NO private key; the JWT is a bearer secret (redacted repr)."""
    agent_id: str
    instance_id: Optional[str]
    spiffe_id: str
    x509_not_after: float
    jwt_svid: Optional[JwtSvid] = field(default=None, repr=False)

    def to_dict(self, include_token: bool = False) -> dict:
        d = {"agent_id": self.agent_id, "instance_id": self.instance_id,
             "spiffe_id": self.spiffe_id, "x509_expires_at": iso(self.x509_not_after)}
        if include_token and self.jwt_svid:
            d["jwt_svid"] = self.jwt_svid.token
        return d


def _deny(reason: str, **kw) -> VerificationResult:
    return VerificationResult(valid=False, reason=reason, **kw)


class SpiffeIdentityProvider(IdentityProvider):
    def __init__(self, service: IdentityService, config: SpireConfig, transport: WorkloadTransport, *,
                 bindings: Optional[BindingRegistry] = None, metrics: Optional[M.Metrics] = None,
                 clock: Optional[Clock] = None, replay=None, bundles: Optional[TrustBundleStore] = None,
                 sleep=time.sleep):
        self.cfg = config.validate()
        self.svc = service
        self.clock = clock or service.clock
        self.metrics = metrics or M.Metrics()
        self.bindings = bindings or MemoryBindingRegistry()
        from ..storage.postgres.factory import require_durable_or_raise
        require_durable_or_raise(bindings=self.bindings)
        self.replay = replay or MemoryReplayCache(100_000)
        self.bundles = bundles or TrustBundleStore(
            config.trust_domain, config.federated_trust_domains, clock=self.clock,
            max_age_seconds=config.bundle_max_age_seconds, metrics=self.metrics)
        self.client = WorkloadApiClient(config, transport, self.bundles, self.clock, self.metrics, sleep)
        self._sources = {}
        self._jwt = JwtSource(self.client, config, self.clock, self.metrics)
        self._lock = threading.Lock()
        self._last_forced_refresh = -1e18

    # ------------------------------------------------------------ binding (mapping)
    def bind_agent(self, agent_id: str) -> Binding:
        a = self.svc.agents.get_agent(agent_id)
        if a is None:
            raise NotFoundError("unknown agent")
        if a.parent_agent_id is not None:
            raise UnauthorizedError("sub-agents can only be bound through an authorized spawn")
        return self._put(a.org_id, a.agent_id, None)

    def bind_instance(self, agent_id: str, instance_id: str) -> Binding:
        a = self.svc.agents.get_agent(agent_id)
        inst = self.svc.agents.get_instance(instance_id)
        if a is None or inst is None or inst.agent_id != a.agent_id:
            raise NotFoundError("unknown agent/instance pair")
        if a.parent_agent_id is not None and self.bindings.find(agent_id, None) is None:
            raise UnauthorizedError("sub-agent has no authorized agent binding")
        return self._put(a.org_id, a.agent_id, instance_id, **self._delegation(a))

    def _delegation(self, a) -> dict:
        if a.parent_agent_id is None:
            return {}
        b = self.bindings.find(a.agent_id, None)
        return {"delegated_by_agent": b.delegated_by_agent,
                "delegated_by_instance": b.delegated_by_instance}

    def _put(self, org_id, agent_id, instance_id, **kw) -> Binding:
        sid = agent_spiffe_id(self.cfg.trust_domain, org_id, agent_id, instance_id)
        b = self.bindings.put(Binding(sid, org_id, agent_id, instance_id, self.clock.now(), **kw))
        self.svc.log.emit("spiffe.bind", agent_id=agent_id, instance_id=instance_id, org_id=org_id,
                          spiffe_id=sid, result="ok")
        return b

    def revoke_binding(self, spiffe_id: str) -> None:
        self.bindings.revoke(spiffe_id)

    def registration_entry(self, binding: Binding, parent_id: str, selectors: Iterable[str],
                           x509_ttl: int = 3600, jwt_ttl: int = 300) -> str:
        """Exact `spire-server entry create` command for this binding (operator runs it)."""
        sel = " ".join(f"-selector {s}" for s in selectors)
        if not sel:
            raise SpiffeError("at least one workload selector is required", "no_selectors")
        return (f"spire-server entry create -parentID {parent_id} -spiffeID {binding.spiffe_id} "
                f"{sel} -x509SVIDTTL {x509_ttl} -jwtSVIDTTL {jwt_ttl}")

    # ------------------------------------------------------------ state checks (I4, I5)
    def _registry_reason(self, b: Binding, now: float) -> Optional[str]:
        agents, rev = self.svc.agents, self.svc.revocations
        org = agents.get_org(b.org_id)
        if org is None or org.status != Status.ACTIVE:
            return Reason.ORG_NOT_ACTIVE
        a = agents.get_agent(b.agent_id)
        if a is None:
            return Reason.UNKNOWN_AGENT
        if a.org_id != b.org_id:
            return Reason.REGISTRY_MISMATCH
        if a.status != Status.ACTIVE:
            return Reason.AGENT_NOT_ACTIVE
        if rev.is_revoked(TargetType.AGENT, a.agent_id, now):
            return Reason.REVOKED
        if a.parent_agent_id is not None:
            sp = agents.get_spawn(a.agent_id)
            if (sp is None or sp.parent_agent_id != a.parent_agent_id or sp.status != Status.ACTIVE
                    or b.delegated_by_agent != a.parent_agent_id):
                return R.BAD_DELEGATION
        for anc in a.lineage:
            p = agents.get_agent(anc)
            if p is None or p.status != Status.ACTIVE or rev.is_revoked(TargetType.AGENT, anc, now):
                return Reason.ANCESTOR_NOT_ACTIVE
        if b.instance_id is not None:
            inst = agents.get_instance(b.instance_id)
            if inst is None:
                return Reason.UNKNOWN_INSTANCE
            if inst.agent_id != a.agent_id:
                return Reason.INSTANCE_MISMATCH
            if inst.status != Status.ACTIVE:
                return Reason.INSTANCE_NOT_ACTIVE
            if rev.is_revoked(TargetType.INSTANCE, inst.instance_id, now):
                return Reason.REVOKED
        return None

    def _authorize(self, sid: SpiffeId, expiry: float) -> VerificationResult:
        now = self.clock.now()
        if sid.trust_domain != self.cfg.trust_domain:
            return _deny(R.UNKNOWN_TRUST_DOMAIN)
        b = self.bindings.get(str(sid))
        if b is None or b.status != "active":
            return _deny(R.UNBOUND)
        try:
            parts = parse_agent_spiffe_id(sid)
        except SpiffeIdError:
            return _deny(R.BAD_SPIFFE_ID)
        if (parts.org_id, parts.agent_id, parts.instance_id) != (b.org_id, b.agent_id, b.instance_id):
            return _deny(R.BINDING_MISMATCH)
        if b.instance_id is None and self.cfg.require_instance_identity:
            return _deny(R.INSTANCE_REQUIRED, agent_id=b.agent_id)
        why = self._registry_reason(b, now)
        if why:
            return _deny(why, agent_id=b.agent_id, instance_id=b.instance_id)
        a = self.svc.agents.get_agent(b.agent_id)
        return VerificationResult(
            valid=True, agent_id=a.agent_id, instance_id=b.instance_id, credential_id=None,
            issuer=f"spiffe://{sid.trust_domain}", expires_at=iso(expiry), org_id=a.org_id,
            capabilities=tuple(a.capabilities), parent_agent_id=a.parent_agent_id,
            is_sub_agent=a.parent_agent_id is not None, key_fingerprint=a.fingerprint)

    # ------------------------------------------------------------ verification (I1-I3, I7)
    def _maybe_refresh_bundles(self) -> bool:
        now = self.clock.now()
        with self._lock:
            if now - self._last_forced_refresh < _MIN_FORCED_REFRESH_GAP:
                return False
            self._last_forced_refresh = now
        try:
            self.client.refresh_x509_bundles()
            self.client.refresh_jwt_bundles()
            return True
        except Exception:
            return False

    def refresh_bundles(self) -> None:
        self.client.refresh_x509_bundles()
        self.client.refresh_jwt_bundles()

    def _run(self, fn) -> VerificationResult:
        t0 = time.perf_counter()
        try:
            try:
                res = fn()
            except SvidError as e:
                if e.reason in _REFRESHABLE and self._maybe_refresh_bundles():
                    res = fn()              # one retry after refreshing trust material
                else:
                    raise
        except SpiffeError as e:
            res = _deny(e.reason)
        except Exception:                   # I7: never fail open
            res = _deny(R.INTERNAL)
        self.metrics.inc(M.VERIFICATIONS)
        if not res.valid:
            self.metrics.inc(M.VERIFY_FAILURES, res.reason or R.INTERNAL)
            if res.reason in (R.EXPIRED,):
                self.metrics.inc(M.EXPIRED, "verify")
        self.metrics.observe(M.AUTH_LATENCY, time.perf_counter() - t0)
        self.svc.log.emit("spiffe.verify", agent_id=res.agent_id, instance_id=res.instance_id,
                          result="ok" if res.valid else "denied", reason=res.reason)
        return res

    def verify(self, token, *, audience: str, single_use: Optional[bool] = None, **kw) -> VerificationResult:
        """Verify a JWT-SVID presented by a peer (audience = THIS service's identifier)."""
        su = self.cfg.jwt_single_use if single_use is None else single_use

        def go():
            j = verify_jwt_svid(token, audience, self.bundles, self.clock.now(),
                                allowed_algs=self.cfg.jwt_allowed_algorithms,
                                skew_seconds=self.cfg.clock_skew_seconds,
                                max_ttl_seconds=self.cfg.jwt_max_ttl_seconds,
                                expected_issuer=self.cfg.jwt_expected_issuer,
                                max_token_bytes=self.cfg.max_token_bytes,
                                replay_cache=self.replay if su else None)
            return self._authorize(j.spiffe_id, j.expiry)
        return self._run(go)

    def verify_x509(self, chain_der: List[bytes]) -> VerificationResult:
        """Verify a peer's X.509-SVID chain (e.g. from an mTLS handshake)."""
        def go():
            s = verify_x509_svid(chain_der, self.bundles, self.clock.now(),
                                 max_depth=self.cfg.max_x509_chain_depth,
                                 skew_seconds=self.cfg.clock_skew_seconds)
            return self._authorize(s.spiffe_id, s.not_after)
        return self._run(go)

    # ------------------------------------------------------------ issuance (workload side)
    def _expected_binding(self, agent_id, instance_id) -> Binding:
        b = self.bindings.find(agent_id, instance_id)
        if b is None or b.status != "active":
            raise UnauthorizedError("no active SPIFFE binding for this agent/instance")
        why = self._registry_reason(b, self.clock.now())
        if why:
            raise UnauthorizedError(f"identity not active: {why}")
        return b

    def x509_source(self, spiffe_id: str) -> X509Source:
        with self._lock:
            s = self._sources.get(spiffe_id)
            if s is None:
                s = self._sources[spiffe_id] = X509Source(self.client, spiffe_id, self.cfg, self.clock,
                                                          self.metrics, self.svc.log)
            return s

    def issue(self, agent_id: str, instance_id: Optional[str] = None, *,
              audience: Optional[str] = None, **kw) -> SpiffeIdentity:
        """Obtain the identity SPIRE attested for THIS workload and prove it matches the requested
        agent/instance binding. A workload that SPIRE did not entitle to that SPIFFE ID gets an error."""
        b = self._expected_binding(agent_id, instance_id)
        svid = self.x509_source(b.spiffe_id).current()
        if str(svid.spiffe_id) != b.spiffe_id:
            raise SvidError("workload SVID does not match requested identity", R.BINDING_MISMATCH)
        jwt = self._jwt.get(audience, b.spiffe_id) if audience else None
        self.metrics.inc(M.SVID_ISSUED, "x509")
        if jwt:
            self.metrics.inc(M.SVID_ISSUED, "jwt")
        return SpiffeIdentity(b.agent_id, b.instance_id, b.spiffe_id, svid.not_after, jwt)

    # ------------------------------------------------------------ sub-agents (I5)
    def spawn_sub_agent(self, parent_jwt_svid: str, *, agent_name: str, agent_type: str,
                        description: str = "", capabilities: Optional[Iterable[str]] = None,
                        metadata: Optional[dict] = None) -> dict:
        """Parent proves itself with a single-use JWT-SVID whose audience is SPAWN_AUDIENCE.
        The child is bound (agent + first instance) only here, recording the delegating parent."""
        v = self.verify(parent_jwt_svid, audience=SPAWN_AUDIENCE, single_use=True)
        if not v.valid:
            raise UnauthorizedError(f"parent identity rejected: {v.reason}")
        if v.instance_id is None:
            raise UnauthorizedError("spawn requires an instance-level identity")
        res: SpawnResult = self.svc.spawn_sub_agent_authorized(
            v.agent_id, v.instance_id, agent_name=agent_name, agent_type=agent_type,
            description=description, capabilities=capabilities, metadata=metadata,
            issue_credential=False)
        cid, iid = res.agent["agent_id"], res.instance["instance_id"]
        org = res.agent["org_id"]
        deleg = {"delegated_by_agent": v.agent_id, "delegated_by_instance": v.instance_id}
        ab = self._put(org, cid, None, **deleg)
        ib = self._put(org, cid, iid, **deleg)
        return {"agent": res.agent, "instance": res.instance, "spawn": res.spawn,
                "spiffe_ids": {"agent": ab.spiffe_id, "instance": ib.spiffe_id}}
