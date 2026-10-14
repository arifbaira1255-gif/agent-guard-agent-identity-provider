"""StateBackend: the ONLY surface the security features use. RedisBackend (production) and MemoryBackend
(tests / single-process development) implement identical semantics; one contract test-suite runs on both.
Every write requires a positive TTL: no transient security state can live forever by accident."""
import math
import threading
import time
from abc import ABC, abstractmethod
from typing import Callable, List, Optional, Tuple

from .errors import StateConfigError

MAX_VALUE_BYTES = 64 * 1024


def _ttl(ttl_ms) -> int:
    if not isinstance(ttl_ms, (int, float)) or isinstance(ttl_ms, bool) or ttl_ms <= 0 or ttl_ms > 31 * 86400_000:
        raise StateConfigError("ttl must be a positive duration (max 31 days)")
    return int(math.ceil(ttl_ms))


def _val(v) -> bytes:
    b = v.encode() if isinstance(v, str) else bytes(v)
    if len(b) > MAX_VALUE_BYTES:
        raise StateConfigError("value too large")
    return b


class StateBackend(ABC):
    @abstractmethod
    def set_if_absent(self, key: str, value, ttl_ms: int) -> bool: ...
    @abstractmethod
    def set(self, key: str, value, ttl_ms: int) -> None: ...
    @abstractmethod
    def get(self, key: str) -> Optional[bytes]: ...
    @abstractmethod
    def delete(self, key: str) -> bool: ...
    @abstractmethod
    def compare_and_delete(self, key: str, expected) -> bool: ...
    @abstractmethod
    def compare_and_extend(self, key: str, expected, ttl_ms: int) -> bool: ...
    @abstractmethod
    def compare_and_set(self, key: str, expected, new) -> bool:
        """Replace value only if it still equals `expected`; the TTL is preserved (never extended)."""
    @abstractmethod
    def token_bucket(self, key: str, rate_per_sec: float, burst: int, cost: int = 1) -> Tuple[bool, int, int]:
        """-> (allowed, remaining_tokens, retry_after_ms). Atomic; bucket state expires on its own."""
    @abstractmethod
    def window_incr(self, key: str, window_ms: int) -> int:
        """Atomic fixed-window counter; the first hit starts the window. Returns the new count."""
    @abstractmethod
    def replay_check(self, key: str, marker_key: str, quarantine_key: str, ttl_ms: int, marker_ttl_ms: int) -> int:
        """Atomic replay check that survives state loss: 1 = new (recorded), 0 = replay,
        2 = QUARANTINED (the marker was missing => Redis lost its data/restarted/failed over; for one replay window
        every check is refused because earlier nonces can no longer be recognised)."""
    @abstractmethod
    def ping(self) -> bool: ...
    def close(self) -> None:
        pass


class MemoryBackend(StateBackend):
    """Thread-safe in-process implementation (same semantics as the Lua scripts). NOT distributed."""

    def __init__(self, now_ms: Callable[[], float] = lambda: time.monotonic() * 1000.0, max_keys=1_000_000):
        self._l = threading.Lock()
        self._d = {}
        self._now = now_ms
        self._max = max_keys

    def _live(self, key):
        e = self._d.get(key)
        if e is None:
            return None
        if e[1] <= self._now():
            del self._d[key]
            return None
        return e

    def _put(self, key, value, ttl_ms):
        if key not in self._d and len(self._d) >= self._max:
            now = self._now()
            self._d = {k: v for k, v in self._d.items() if v[1] > now}
            if len(self._d) >= self._max:
                raise StateConfigError("memory backend full")
        self._d[key] = (value, self._now() + ttl_ms)

    def set_if_absent(self, key, value, ttl_ms):
        t, v = _ttl(ttl_ms), _val(value)
        with self._l:
            if self._live(key) is not None:
                return False
            self._put(key, v, t)
            return True

    def set(self, key, value, ttl_ms):
        t, v = _ttl(ttl_ms), _val(value)
        with self._l:
            self._put(key, v, t)

    def get(self, key):
        with self._l:
            e = self._live(key)
            return None if e is None else e[0]

    def delete(self, key):
        with self._l:
            if self._live(key) is None:
                return False
            del self._d[key]
            return True

    def compare_and_delete(self, key, expected):
        exp = _val(expected)
        with self._l:
            e = self._live(key)
            if e is not None and e[0] == exp:
                del self._d[key]
                return True
            return False

    def compare_and_extend(self, key, expected, ttl_ms):
        t, exp = _ttl(ttl_ms), _val(expected)
        with self._l:
            e = self._live(key)
            if e is not None and e[0] == exp:
                self._d[key] = (e[0], self._now() + t)
                return True
            return False

    def compare_and_set(self, key, expected, new):
        exp, nv = _val(expected), _val(new)
        with self._l:
            e = self._live(key)
            if e is not None and e[0] == exp:
                self._d[key] = (nv, e[1])
                return True
            return False

    def token_bucket(self, key, rate_per_sec, burst, cost=1):
        if rate_per_sec <= 0 or burst < 1 or cost < 1:
            raise StateConfigError("invalid token bucket parameters")
        with self._l:
            now = self._now()
            e = self._live(key)
            tokens, ts = (float(burst), now) if e is None else e[0]
            tokens = min(float(burst), tokens + max(0.0, now - ts) * rate_per_sec / 1000.0)
            allowed, retry = False, 0
            if tokens >= cost:
                tokens -= cost
                allowed = True
            else:
                retry = int(math.ceil((cost - tokens) * 1000.0 / rate_per_sec))
            self._d[key] = ((tokens, now), now + math.ceil(burst / rate_per_sec * 1000) + 1000)
            return allowed, int(tokens), retry

    def window_incr(self, key, window_ms):
        w = _ttl(window_ms)
        with self._l:
            e = self._live(key)
            if e is None:
                self._put(key, 1, w)
                return 1
            self._d[key] = (e[0] + 1, e[1])
            return e[0] + 1

    def replay_check(self, key, marker_key, quarantine_key, ttl_ms, marker_ttl_ms):
        t, mt, v = _ttl(ttl_ms), _ttl(marker_ttl_ms), b"1"
        with self._l:
            if self._live(marker_key) is None:
                self._put(marker_key, v, mt)
                self._put(quarantine_key, v, t)
            if self._live(quarantine_key) is not None:
                return 2
            if self._live(key) is not None:
                return 0
            self._put(key, v, t)
            return 1

    def ping(self):
        return True

    def size(self) -> int:
        with self._l:
            now = self._now()
            return sum(1 for v in self._d.values() if v[1] > now)
