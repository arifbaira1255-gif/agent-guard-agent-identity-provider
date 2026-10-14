"""Wiring + production guard. Redis supplies: distributed replay cache, revocation/identity caches, rate limiter,
locks, temp security state. PostgreSQL remains the system of record."""
import os
from dataclasses import dataclass
from typing import Optional

from ..spiffe import metrics as _M
from ..spiffe.config import ENV_VAR
from .backend import StateBackend
from .cache import CachedAgentRegistry, CachedRevocationRegistry, VersionedCache
from .config import RedisConfig
from .keys import KeyBuilder
from .locks import DistributedLock
from .ratelimit import DistributedRateLimiter
from .replay import RedisReplayCache
from .tempstate import TempStateStore


@dataclass
class SecurityState:
    backend: StateBackend
    keys: KeyBuilder
    replay: RedisReplayCache
    limiter: DistributedRateLimiter
    locks: DistributedLock
    temp: TempStateStore
    cfg: RedisConfig
    metrics: _M.Metrics

    def wrap_storage(self, agents, revocations):
        """-> (cached_agents, cached_revocations); PostgreSQL registries stay authoritative underneath."""
        ac = VersionedCache(self.backend, self.keys, domain="idcache", ttl_seconds=self.cfg.cache_ttl_agent_seconds,
                            metrics=self.metrics)
        rc = VersionedCache(self.backend, self.keys, domain="revcache",
                            ttl_seconds=self.cfg.cache_ttl_revocation_seconds, metrics=self.metrics)
        return CachedAgentRegistry(agents, ac), CachedRevocationRegistry(revocations, rc)

    def service_kwargs(self, pg_storage) -> dict:
        """IdentityService(config, **state.service_kwargs(pg_storage)): PG durable + Redis accelerators."""
        agents, revs = self.wrap_storage(pg_storage.agents, pg_storage.revocations)
        kw = pg_storage.service_kwargs()
        kw.update(agents=agents, revocations=revs, replay=self.replay)
        return kw

    def health(self) -> dict:
        ok = self.backend.ping()
        return {"live": True, "redis": ok, "ready": ok}

    def close(self):
        self.backend.close()


def build_security_state(cfg: RedisConfig, *, backend: Optional[StateBackend] = None,
                         metrics: Optional[_M.Metrics] = None) -> SecurityState:
    cfg.validate()
    m = metrics or _M.Metrics()
    if backend is None:
        from .redis_backend import RedisBackend
        backend = RedisBackend(cfg, metrics=m)
    kb = KeyBuilder(cfg.environment.value, prefix=cfg.key_prefix)
    replay = RedisReplayCache(backend, kb, max_ttl_seconds=cfg.replay_max_ttl_seconds, metrics=m)
    replay.ensure_marker()
    return SecurityState(backend, kb, replay,
                         DistributedRateLimiter(backend, kb, m),
                         DistributedLock(backend, kb, default_ttl_seconds=cfg.lock_default_ttl_seconds, metrics=m),
                         TempStateStore(backend, kb, max_ttl_seconds=cfg.temp_state_max_ttl_seconds, metrics=m),
                         cfg, m)
