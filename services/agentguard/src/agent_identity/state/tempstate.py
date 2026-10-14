"""Short-lived, tenant-scoped security records (foundation for future JIT approvals / challenges / temporary grants).
Every record: explicit bounded TTL, unique id (create-only), tenant + owner, created_at/expires_at, ctx_version, status.
Status transitions and single-use consumption are atomic (compare-and-set / compare-and-delete)."""
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .backend import StateBackend
from .errors import StateConfigError, StateConflictError, StateCorruptError
from .keys import KeyBuilder, TenantKeys

KINDS = ("authz_decision", "approval", "grant", "challenge", "risk")


@dataclass(frozen=True)
class TempRecord:
    kind: str
    ident: str
    tenant: str
    owner: str
    status: str
    ctx_version: int
    created_at: float
    expires_at: float
    data: Dict[str, Any]


class TenantTempState:
    """Handle FIXED to one tenant (obtained via TempStateStore.for_tenant); it cannot address other tenants."""

    def __init__(self, backend, keys: TenantKeys, max_ttl, clock, metrics):
        self._b, self._k, self._max, self._clock, self.metrics = backend, keys, max_ttl, clock, metrics

    @property
    def tenant(self):
        return self._k.tenant

    def _key(self, kind, ident):
        if kind not in KINDS:
            raise StateConfigError("unknown record kind")
        return self._k.key("tmp", kind, ident)

    def put(self, kind, ident, *, owner, ttl_seconds, data=None, status="pending", ctx_version=1) -> TempRecord:
        if not (0 < ttl_seconds <= self._max):
            raise StateConfigError("ttl outside allowed range")
        now = self._clock()
        rec = TempRecord(kind, ident, self.tenant, owner, status, ctx_version, now, now + ttl_seconds, dict(data or {}))
        if not self._b.set_if_absent(self._key(kind, ident), self._enc(rec), int(ttl_seconds * 1000)):
            raise StateConfigError("a record with this id already exists")           # ids are unique, create-only
        return rec

    def get(self, kind, ident) -> Optional[TempRecord]:
        raw = self._b.get(self._key(kind, ident))
        return None if raw is None else self._dec(raw, kind, ident)

    def transition(self, kind, ident, *, expected_status, new_status, data_update=None) -> TempRecord:
        """Atomic: succeeds only if the stored record is byte-identical to what we read (no lost update)."""
        key = self._key(kind, ident)
        for _ in range(5):
            raw = self._b.get(key)
            if raw is None:
                raise StateConflictError("record not found or expired")
            rec = self._dec(raw, kind, ident)
            if rec.status != expected_status:
                raise StateConflictError("record is not in the expected state")
            new = TempRecord(rec.kind, rec.ident, rec.tenant, rec.owner, new_status, rec.ctx_version,
                             rec.created_at, rec.expires_at, {**rec.data, **(data_update or {})})
            if self._b.compare_and_set(key, raw, self._enc(new)):                      # TTL preserved by backend
                return new
        raise StateConflictError("record changed concurrently")

    def consume(self, kind, ident) -> Optional[TempRecord]:
        """Single-use: exactly one concurrent caller receives the record; the rest get None."""
        key = self._key(kind, ident)
        raw = self._b.get(key)
        if raw is None:
            return None
        rec = self._dec(raw, kind, ident)
        return rec if self._b.compare_and_delete(key, raw) else None

    def revoke(self, kind, ident) -> bool:
        return self._b.delete(self._key(kind, ident))

    # -- serialization (bounded, validated; anything malformed is rejected, never trusted)
    def _enc(self, r: TempRecord) -> bytes:
        return json.dumps({"k": r.kind, "i": r.ident, "t": r.tenant, "o": r.owner, "s": r.status,
                           "v": r.ctx_version, "c": r.created_at, "e": r.expires_at, "d": r.data},
                          separators=(",", ":"), sort_keys=True).encode()

    def _dec(self, raw: bytes, kind, ident) -> TempRecord:
        try:
            o = json.loads(raw)
            rec = TempRecord(o["k"], o["i"], o["t"], o["o"], o["s"], int(o["v"]), float(o["c"]),
                             float(o["e"]), dict(o["d"]))
        except Exception:
            self.metrics.inc("agentguard_state_corrupt_total", "tempstate")
            raise StateCorruptError("malformed security-state record") from None
        if rec.tenant != self.tenant or rec.kind != kind or rec.ident != ident:
            self.metrics.inc("agentguard_state_corrupt_total", "tempstate_scope")   # key/tenant mismatch => reject
            raise StateCorruptError("security-state record scope mismatch")
        if rec.expires_at <= self._clock():
            raise StateConflictError("record expired")                              # defence if a TTL were ever lost
        return rec


class TempStateStore:
    def __init__(self, backend: StateBackend, keys: KeyBuilder, *, max_ttl_seconds=86400, clock=time.time,
                 metrics=None):
        from ..spiffe import metrics as _M
        self._b, self._kb, self._max, self._clock = backend, keys, max_ttl_seconds, clock
        self.metrics = metrics or _M.Metrics()

    def for_tenant(self, tenant: str) -> TenantTempState:
        return TenantTempState(self._b, self._kb.scoped(tenant), self._max, self._clock, self.metrics)
