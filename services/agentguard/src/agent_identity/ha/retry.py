"""Bounded retry with exponential backoff and full jitter (Step 7).

One helper used by every Step 7 component that talks to a dependency (PostgreSQL, Redis, KMS,
SPIRE). Rules enforced here:

  * retries are BOUNDED (attempts + max backoff) — a dependency outage can never turn into an
    unbounded retry storm;
  * backoff is exponential with *full jitter* (``random.uniform(0, delay)``) so many instances
    recovering at once do not synchronise into a thundering herd;
  * only the caller decides what is retryable (``retry_on``); non-idempotent operations must pass
    ``retry_on=()`` or a predicate that excludes them — this helper never guesses;
  * the last exception is re-raised unchanged (callers fail closed), never swallowed.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Callable, Optional, Tuple, Type


@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 3
    base_seconds: float = 0.05
    max_seconds: float = 1.0
    jitter: bool = True

    def validate(self) -> "RetryPolicy":
        if self.attempts < 1:
            raise ValueError("attempts must be >= 1")
        if self.base_seconds < 0 or self.max_seconds < 0:
            raise ValueError("backoff must be >= 0")
        if self.max_seconds < self.base_seconds:
            raise ValueError("max_seconds must be >= base_seconds")
        return self

    def delay_for(self, attempt: int, *, rand: Callable[[], float] = random.random) -> float:
        """Delay before retry number ``attempt`` (1-based). Full jitter when enabled."""
        raw = min(self.max_seconds, self.base_seconds * (2 ** (attempt - 1)))
        return raw * rand() if self.jitter else raw


def retry_call(fn: Callable[[], object], *, policy: RetryPolicy,
               retry_on: Tuple[Type[BaseException], ...] = (Exception,),
               sleep: Callable[[float], None] = time.sleep,
               on_retry: Optional[Callable[[int, BaseException], None]] = None,
               rand: Callable[[], float] = random.random):
    """Call ``fn`` up to ``policy.attempts`` times, retrying only ``retry_on`` exceptions.

    ``retry_on=()`` disables retries entirely (use for non-idempotent operations). Any exception
    that is not in ``retry_on`` propagates immediately on the first occurrence.
    """
    policy.validate()
    last: Optional[BaseException] = None
    for attempt in range(1, policy.attempts + 1):
        try:
            return fn()
        except BaseException as e:  # noqa: BLE001 - re-raised below unless retryable
            if not retry_on or not isinstance(e, retry_on):
                raise
            last = e
            if attempt >= policy.attempts:
                break
            if on_retry is not None:
                on_retry(attempt, e)
            sleep(policy.delay_for(attempt, rand=rand))
    assert last is not None
    raise last
