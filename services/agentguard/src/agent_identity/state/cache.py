"""Versioned read-through cache: Redis is an ACCELERATOR; PostgreSQL stays authoritative.

Staleness protection (no stale 'active'/'not revoked' after a change):
  reader : 1) read version token V  2) read cached entry; hit only if entry.V == V  3) on miss read PostgreSQL
           and store the entry tagged with the V read in step 1 (BEFORE the DB read).
  writer : commit to PostgreSQL FIRST, then replace V with a fresh random token (invalidate).
So any entry loaded before a commit carries a token that the writer's bump invalidates. Residual window =
(commit -> bump) latency, plus the entry TTL if the bump itself fails (counted + logged). Random tokens (not
counters) avoid ABA after Redis eviction/restart. Redis failure => BYPASS to PostgreSQL (still correct, just slower).
Corrupted entry => treated as a miss. Negative results ('not found') are cached only under the same version check."""
import dataclasses
import json
import logging
import secrets
from typing import Any, Callable, Optional

from ..core.models import (AgentRecord, InstanceRecord, Organization, RevocationReason, RevocationRecord,
                           Status, TargetType)
from ..spiffe import metrics as _M
from ..storage.interfaces import AgentRegistry, RevocationRegistry
from .backend import StateBackend
from .errors import StateCorruptError, StateUnavailableError
from .keys import SYSTEM_TENANT, KeyBuilder

log = logging.getLogger("agentguard.cache")
HIT = "agentguard_cache_hits_total"
MISS = "agentguard_cache_misses_total"
BYPASS = "agentguard_cache_bypass_total"
CORRUPT = "agentguard_cache_corrupt_total"
INVALIDATED = "agentguard_cache_invalidations_total"
INVALIDATE_FAILED = "agentguard_cache_invalidation_failures_total"
_MISSING = object()


class VersionedCache:
    def __init__(self, backend: StateBackend, keys: KeyBuilder, *, domain: str, ttl_seconds: int,
                 tenant: str = SYSTEM_TENANT, metrics=None, invalidate_retries: int = 3):
        self._b, self._k, self._domain, self._tenant = backend, keys, domain, tenant
        self._ttl_ms = int(ttl_seconds * 1000)
        self._ver_ttl_ms = self._ttl_ms * 2 + 1000                  # version outlives every entry it guards
        self.metrics = metrics or _M.Metrics()
        self._retries = invalidate_retries

    def _keys(self, resource, ident):
        return (self._k.hashed(self._tenant, self._domain, resource + "_v", ident),
                self._k.hashed(self._tenant, self._domain, resource, ident))

    def get(self, resource: str, ident: str, loader: Callable[[], Any], ser: Callable, de: Callable):
        vkey, ekey = self._keys(resource, ident)
        ver = None
        try:
            ver = self._b.get(vkey)
            if ver is None:
                self._b.set_if_absent(vkey, secrets.token_hex(12), self._ver_ttl_ms)
                ver = self._b.get(vkey)
            if ver is not None:
                raw = self._b.get(ekey)
                if raw is not None:
                    hit = self._parse(raw, ver, de)
                    if hit is not _MISSING:
                        self.metrics.inc(HIT, resource)
                        return hit
        except StateUnavailableError:
            self.metrics.inc(BYPASS, resource)
            return loader()                                          # authoritative read, no caching
        except StateCorruptError:
            self.metrics.inc(CORRUPT, resource)
        self.metrics.inc(MISS, resource)
        value = loader()                                             # PostgreSQL; its errors propagate (deny)
        if ver is not None:
            try:
                body = {"v": ver.decode() if isinstance(ver, bytes) else ver,
                        "n": value is None, "d": None if value is None else ser(value)}
                self._b.set(ekey, json.dumps(body, separators=(",", ":")), self._ttl_ms)
            except (StateUnavailableError, StateCorruptError):
                self.metrics.inc(BYPASS, resource)
        return value

    def _parse(self, raw: bytes, ver, de):
        try:
            o = json.loads(raw)
            v = ver.decode() if isinstance(ver, bytes) else ver
            if o["v"] != v:
                return _MISSING                                       # stale: version moved on
            if o["n"]:
                return None
            return de(o["d"])
        except Exception:
            self.metrics.inc(CORRUPT, "entry")
            return _MISSING

    def invalidate(self, resource: str, ident: str) -> bool:
        """Call AFTER the PostgreSQL commit. Returns False (and counts) if the bump could not be made."""
        vkey, ekey = self._keys(resource, ident)
        for _ in range(self._retries):
            try:
                self._b.set(vkey, secrets.token_hex(12), self._ver_ttl_ms)
                self.metrics.inc(INVALIDATED, resource)
                try:
                    self._b.delete(ekey)
                except StateUnavailableError:
                    pass
                return True
            except StateUnavailableError:
                continue
        self.metrics.inc(INVALIDATE_FAILED, resource)
        log.error("cache invalidation failed for %s; stale entries bounded by TTL=%ss", resource, self._ttl_ms // 1000)
        return False


# ---------------------------------------------------------------- (de)serialisation of existing records
def _enum(o):
    return o.value if hasattr(o, "value") else o


def _agent_ser(a: AgentRecord) -> dict:
    d = dataclasses.asdict(a)
    d["status"] = a.status.value
    return d


def _agent_de(d) -> AgentRecord:
    return AgentRecord(d["agent_id"], d["org_id"], d["agent_name"], d["agent_type"], d["owner"], d["description"],
                       tuple(d["capabilities"]), d["environment"], dict(d["metadata"]), d["parent_agent_id"],
                       tuple(d["lineage"]), d["created_at"], Status(d["status"]), d["key_id"], d["public_key"],
                       d["fingerprint"], tuple((k, float(n)) for k, n in d["retired_keys"]), d["created_by"])


def _inst_ser(i: InstanceRecord) -> dict:
    d = dataclasses.asdict(i)
    d["status"] = i.status.value
    return d


def _inst_de(d) -> InstanceRecord:
    return InstanceRecord(d["instance_id"], d["agent_id"], d["org_id"], d["session_id"], d["created_at"],
                          Status(d["status"]), d["agent_key_id"], d["agent_public_key"], d["binding_signature"])


def _org_ser(o: Organization) -> dict:
    d = dataclasses.asdict(o)
    d["status"] = o.status.value
    return d


def _org_de(d) -> Organization:
    caps = None if d["allowed_capabilities"] is None else tuple(d["allowed_capabilities"])
    return Organization(d["org_id"], d["name"], d["created_at"], Status(d["status"]), d["active_issuer_key_id"], caps)


def _rev_ser(r: RevocationRecord) -> dict:
    return {"tt": r.target_type.value, "id": r.target_id, "rs": r.reason.value, "ra": r.revoked_at,
            "rb": r.revoked_by, "ea": r.effective_at, "dt": r.detail}


def _rev_de(d) -> RevocationRecord:
    return RevocationRecord(TargetType(d["tt"]), d["id"], RevocationReason(d["rs"]), d["ra"], d["rb"], d["ea"], d["dt"])


class CachedRevocationRegistry(RevocationRegistry):
    """Wraps the PostgreSQL registry. add(): PostgreSQL commit, THEN invalidate (so every instance sees it).
    get(): version-checked cache; Redis down => straight to PostgreSQL. Never answers 'not revoked' from Redis
    without a matching version token."""

    def __init__(self, inner: RevocationRegistry, cache: VersionedCache):
        self.inner, self.cache = inner, cache

    def add(self, rec):
        out = self.inner.add(rec)
        self.cache.invalidate("rev", f"{rec.target_type.value}:{rec.target_id}")
        return out

    def get(self, target_type, target_id):
        return self.cache.get("rev", f"{target_type.value}:{target_id}",
                              lambda: self.inner.get(target_type, target_id), _rev_ser, _rev_de)


class CachedAgentRegistry(AgentRegistry):
    """Cache-aside for hot identity lookups (agent, instance, org). Writes go to PostgreSQL first, then invalidate.
    Lists/spawn lookups are not cached. Records contain public metadata only (never private keys)."""

    def __init__(self, inner: AgentRegistry, cache: VersionedCache):
        self.inner, self.cache = inner, cache

    def put_org(self, org):
        self.inner.put_org(org)
        self.cache.invalidate("org", org.org_id)

    def get_org(self, org_id):
        return self.cache.get("org", org_id, lambda: self.inner.get_org(org_id), _org_ser, _org_de)

    def put_agent(self, a):
        self.inner.put_agent(a)
        self.cache.invalidate("agent", a.agent_id)

    def get_agent(self, agent_id):
        return self.cache.get("agent", agent_id, lambda: self.inner.get_agent(agent_id), _agent_ser, _agent_de)

    def put_instance(self, i):
        self.inner.put_instance(i)
        self.cache.invalidate("instance", i.instance_id)

    def get_instance(self, instance_id):
        return self.cache.get("instance", instance_id, lambda: self.inner.get_instance(instance_id),
                              _inst_ser, _inst_de)

    def list_instances(self, agent_id):
        return self.inner.list_instances(agent_id)

    def put_spawn(self, s):
        return self.inner.put_spawn(s)

    def get_spawn(self, child_agent_id):
        return self.inner.get_spawn(child_agent_id)

    def list_children(self, parent_agent_id):
        return self.inner.list_children(parent_agent_id)
