"""Bounded, tenant/agent-aware rate limiting for the egress gateway.

A token-bucket limiter keyed by ``(org_id, agent_id, scope)``. It is deliberately in-process and
bounded: the bucket map is capped and evicts the least-recently-used entries, so a hostile caller
cannot grow it without limit. For a multi-replica deployment the shared limiter is the existing
Redis-backed state layer (``agent_identity.state``); this in-process limiter is the single-node
implementation and the fallback.

The limiter is fail-closed in the sense that matters: when a bucket is exhausted the request is
denied (``RateLimitedEgressError``), never silently allowed.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class _Bucket:
    tokens: float
    last_refill: float
    last_seen: float


class RateLimiter:
    """A bounded token-bucket rate limiter.

    ``per_second`` is the sustained refill rate; ``burst`` is the bucket capacity. A request costs
    one token. Buckets are keyed by an opaque string the caller builds (tenant+agent+scope).
    """

    def __init__(self, *, max_buckets: int = 100_000, clock=None):
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._max = max(1, int(max_buckets))
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def allow(self, key: str, *, per_second: float, burst: int) -> Tuple[bool, float]:
        """Consume one token. Returns ``(allowed, retry_after_seconds)``.

        ``retry_after_seconds`` is 0.0 when allowed, else the time until the next token is available.
        """
        if per_second <= 0 or burst < 1:
            return False, 1.0
        now = self._now()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(tokens=float(burst), last_refill=now, last_seen=now)
                self._buckets[key] = b
                if len(self._buckets) > self._max:
                    self._evict()
            # refill
            elapsed = max(0.0, now - b.last_refill)
            b.tokens = min(float(burst), b.tokens + elapsed * per_second)
            b.last_refill = now
            b.last_seen = now
            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return True, 0.0
            deficit = 1.0 - b.tokens
            retry_after = deficit / per_second
            return False, retry_after

    def _evict(self) -> None:
        """Evict the least-recently-seen buckets to keep the map bounded."""
        over = len(self._buckets) - self._max
        if over <= 0:
            return
        victims = sorted(self._buckets.items(), key=lambda kv: kv[1].last_seen)[:over]
        for k, _ in victims:
            self._buckets.pop(k, None)

    def reset(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)

    def __len__(self) -> int:  # pragma: no cover - introspection
        with self._lock:
            return len(self._buckets)
