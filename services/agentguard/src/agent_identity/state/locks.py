"""Distributed lock (single Redis primary): unique owner token, TTL, owner-checked release/extend, retry+backoff.

CONSISTENCY ASSUMPTIONS (not Redlock): correct while one Redis primary is authoritative. After a failover
that loses the lock key, or if the holder pauses longer than the TTL, two holders can briefly coexist.
Therefore a lock is only an EFFICIENCY/coordination aid (avoid duplicate rotation work); correctness-critical
invariants must still be enforced by PostgreSQL constraints/transactions (they are). Keep critical
sections short and TTL > worst-case duration. Redis errors => the lock is NOT acquired (never assumed)."""
import logging
import random
import secrets
import time
from typing import Optional

from ..spiffe import metrics as _M
from .backend import StateBackend
from .errors import LockNotAcquired, StateUnavailableError
from .keys import KeyBuilder

log = logging.getLogger("agentguard.lock")
LOCK_ACQUIRED = "agentguard_lock_acquired_total"
LOCK_CONTENDED = "agentguard_lock_contended_total"
LOCK_RELEASE_LOST = "agentguard_lock_release_lost_total"


class LockHandle:
    def __init__(self, mgr, key, token, ttl_ms, clock):
        self._m, self.key, self.token, self._ttl, self._clock = mgr, key, token, ttl_ms, clock
        self.expires_at = clock() + ttl_ms / 1000.0
        self.released = False

    def held(self) -> bool:
        return not self.released and self._clock() < self.expires_at

    def extend(self, ttl_seconds: Optional[float] = None) -> bool:
        ttl = int((ttl_seconds or self._ttl / 1000.0) * 1000)
        try:
            ok = self._m._b.compare_and_extend(self.key, self.token, ttl)
        except StateUnavailableError:
            return False
        if ok:
            self.expires_at = self._clock() + ttl / 1000.0
        return ok

    def release(self) -> bool:
        """Deletes the key ONLY if we still own it (compare-and-delete). Never releases another owner's lock."""
        if self.released:
            return False
        self.released = True
        try:
            ok = self._m._b.compare_and_delete(self.key, self.token)
        except StateUnavailableError:
            log.warning("lock release failed (state unavailable); it will expire by TTL")
            return False
        if not ok:
            self._m.metrics.inc(LOCK_RELEASE_LOST)      # we had already lost it (TTL expiry/failover)
        return ok

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.release()


class DistributedLock:
    def __init__(self, backend: StateBackend, keys: KeyBuilder, *, default_ttl_seconds=30, metrics=None,
                 clock=time.monotonic, sleep=time.sleep):
        self._b, self._k, self._ttl = backend, keys, default_ttl_seconds
        self.metrics = metrics or _M.Metrics()
        self._clock, self._sleep = clock, sleep

    def acquire(self, tenant: str, name: str, *, ttl_seconds: Optional[float] = None,
                wait_seconds: float = 0.0, raise_on_fail: bool = False) -> Optional[LockHandle]:
        ttl_ms = int((ttl_seconds or self._ttl) * 1000)
        key = self._k.key(tenant, "lock", "mutex", name)          # `name` is validated (no ':' '{' '}' '*')
        token = secrets.token_hex(16)
        deadline = self._clock() + max(0.0, wait_seconds)
        delay = 0.01
        while True:
            try:
                if self._b.set_if_absent(key, token, ttl_ms):
                    self.metrics.inc(LOCK_ACQUIRED)
                    return LockHandle(self, key, token, ttl_ms, self._clock)
            except StateUnavailableError:
                if raise_on_fail:
                    raise
                return None                                         # cannot prove ownership => not acquired
            self.metrics.inc(LOCK_CONTENDED)
            if self._clock() >= deadline:
                if raise_on_fail:
                    raise LockNotAcquired("lock is held by another owner")
                return None
            self._sleep(min(delay, max(0.0, deadline - self._clock())) * (0.5 + random.random() / 2))
            delay = min(delay * 2, 0.25)
