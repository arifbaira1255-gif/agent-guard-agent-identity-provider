"""Distributed rate limiting (state lives in Redis, never in process memory)."""
import logging
from dataclasses import dataclass
from typing import Optional

from ..spiffe import metrics as _M
from .backend import MemoryBackend, StateBackend
from .errors import StateConfigError, StateCorruptError, StateUnavailableError
from .keys import KeyBuilder

log = logging.getLogger("agentguard.ratelimit")
LIMIT_REJECTED = "agentguard_ratelimit_rejected_total"
LIMIT_ALLOWED = "agentguard_ratelimit_allowed_total"
LIMIT_DEGRADED = "agentguard_ratelimit_degraded_total"


@dataclass(frozen=True)
class BucketPolicy:
    """Token bucket: sustained `rate_per_sec`, short bursts up to `burst`."""
    name: str
    rate_per_sec: float
    burst: int
    on_error: str = "deny"          # deny (default, fail closed) | local (per-process bucket: weaker but bounded)


@dataclass(frozen=True)
class WindowPolicy:
    """Fixed window: at most `limit` events per `window_seconds` (auth failures, issuance quotas)."""
    name: str
    limit: int
    window_seconds: int
    on_error: str = "deny"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    remaining: int = 0
    retry_after_ms: int = 0
    degraded: bool = False          # True when Redis was unreachable and `on_error` decided


class DistributedRateLimiter:
    SUBJECT_TYPES = ("agent", "tenant", "ip", "credential", "global")

    def __init__(self, backend: StateBackend, keys: KeyBuilder, metrics=None):
        self._b, self._k = backend, keys
        self._local = MemoryBackend()
        self.metrics = metrics or _M.Metrics()

    def _key(self, policy, tenant, subject_type, subject):
        if subject_type not in self.SUBJECT_TYPES:
            raise StateConfigError("unknown subject type")
        # subject (agent id / IP / ...) is hashed: no raw identifiers or IPs in Redis keys
        return self._k.hashed(tenant, "ratelimit", policy.name, f"{subject_type}:{subject}")

    @staticmethod
    def _check(policy):
        if policy.on_error not in ("deny", "local"):
            raise StateConfigError("on_error must be 'deny' or 'local'")

    def allow(self, policy: BucketPolicy, tenant: str, subject_type: str, subject: str, cost: int = 1) -> Decision:
        self._check(policy)
        key = self._key(policy, tenant, subject_type, subject)
        try:
            ok, rem, retry = self._b.token_bucket(key, policy.rate_per_sec, policy.burst, cost)
            return self._fin(policy, Decision(ok, rem, retry))
        except (StateUnavailableError, StateCorruptError):
            self.metrics.inc(LIMIT_DEGRADED, policy.name)
            if policy.on_error == "local":
                ok, rem, retry = self._local.token_bucket(key, policy.rate_per_sec, policy.burst, cost)
                return self._fin(policy, Decision(ok, rem, retry, True))
            return self._fin(policy, Decision(False, 0, 1000, True))          # fail closed

    def hit(self, policy: WindowPolicy, tenant: str, subject_type: str, subject: str) -> Decision:
        """Record one event and report whether the subject is still within the limit."""
        self._check(policy)
        key = self._key(policy, tenant, subject_type, subject)
        wms = policy.window_seconds * 1000
        try:
            n = self._b.window_incr(key, wms)
            return self._fin(policy, Decision(n <= policy.limit, max(0, policy.limit - n)))
        except (StateUnavailableError, StateCorruptError):
            self.metrics.inc(LIMIT_DEGRADED, policy.name)
            if policy.on_error == "local":
                n = self._local.window_incr(key, wms)
                return self._fin(policy, Decision(n <= policy.limit, max(0, policy.limit - n), 0, True))
            return self._fin(policy, Decision(False, 0, wms, True))

    def _fin(self, policy, d: Decision) -> Decision:
        self.metrics.inc(LIMIT_ALLOWED if d.allowed else LIMIT_REJECTED, policy.name)
        return d
