"""Distributed replay protection: ONE atomic script/`SET NX`. First sighting -> True, repeat -> False, two concurrent
identical requests -> exactly one True. Redis errors RAISE (callers deny): there is NO fallback to a local cache
(that would let a replay through via another instance).

STATE-LOSS GUARD: a marker key (long TTL) proves Redis still holds our data. If it is missing at check time, Redis
restarted / failed over / was flushed, so earlier nonces are unrecognisable: the request is refused and a quarantine
of one replay window starts (all checks refused until pre-loss nonces have expired anyway). `ensure_marker()` runs at
startup so a normal first deployment does not quarantine. Limit: JWT-SVID single-use tokens outlive that window."""
import logging
import math

from ..spiffe import metrics as _M
from ..storage.interfaces import ReplayCache
from ..storage.memory import StorageError
from .backend import StateBackend
from .errors import StateUnavailableError
from .keys import SYSTEM_TENANT, KeyBuilder

log = logging.getLogger("agentguard.replay")
REPLAY_ALLOWED = "agentguard_replay_allowed_total"
REPLAY_REJECTED = "agentguard_replay_rejected_total"
REPLAY_QUARANTINED = "agentguard_replay_quarantined_total"
MARKER_TTL_MS = 7 * 86400 * 1000


class RedisReplayCache(ReplayCache):
    def __init__(self, backend: StateBackend, keys: KeyBuilder, *, max_ttl_seconds: int = 86400, metrics=None):
        self._b, self._k, self._max = backend, keys, max_ttl_seconds
        self.metrics = metrics or _M.Metrics()
        self._marker = keys.key(SYSTEM_TENANT, "replay", "marker", "state")
        self._quarantine = keys.key(SYSTEM_TENANT, "replay", "marker", "quarantine")

    def ensure_marker(self) -> None:
        """Initialise the state-loss marker without quarantining (call at startup)."""
        try:
            self._b.set_if_absent(self._marker, b"1", MARKER_TTL_MS)
        except StateUnavailableError:
            log.warning("could not initialise replay marker; first request will quarantine until Redis is healthy")

    def check_and_store(self, key: str, ttl_seconds: float, now: float) -> bool:
        if not isinstance(key, str) or not key:
            raise StorageError("invalid replay key")
        if not (ttl_seconds > 0) or ttl_seconds > self._max:
            raise StorageError("replay ttl outside allowed range")      # never silently shorten the window
        rk = self._k.hashed(SYSTEM_TENANT, "replay", "nonce", key)       # nonces/tokens are never keys in clear
        r = self._b.replay_check(rk, self._marker, self._quarantine, int(math.ceil(ttl_seconds * 1000)), MARKER_TTL_MS)
        if r == 2:
            self.metrics.inc(REPLAY_QUARANTINED)
            raise StateUnavailableError("replay state was lost; requests are refused during quarantine")
        self.metrics.inc(REPLAY_ALLOWED if r == 1 else REPLAY_REJECTED)
        return r == 1
