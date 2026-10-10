"""Non-secret key metadata persistence + a durable audit trail for key operations.

Two stores, one contract:
  * `MemoryKeyMetadataStore` — development / tests.
  * `PgKeyMetadataStore`     — the durable system of record (table `kms_keys`, migration 0002).

The concurrency-safe primitive is `transition()`: a compare-and-swap on the lifecycle
state. Rotation is built on it, so two concurrent rotations of the same key cannot both
succeed (one observes `active`, the loser observes `rotating` and is refused).

Nothing here ever stores private key material — only ids, public keys, states and links.
"""
import threading
from abc import ABC, abstractmethod
from dataclasses import replace
from typing import Iterable, List, Optional, Sequence

from ..core.errors import ConflictError
from ..core.models import iso
from .errors import KeyNotFoundError, KeyStateError
from .models import KeyAlgorithm, KeyMetadata, KeyStatus


class KeyMetadataStore(ABC):
    @abstractmethod
    def put(self, meta: KeyMetadata) -> KeyMetadata: ...

    @abstractmethod
    def get(self, key_id: str) -> Optional[KeyMetadata]: ...

    @abstractmethod
    def list(self, status: Optional[KeyStatus] = None) -> List[KeyMetadata]: ...

    @abstractmethod
    def update(self, key_id: str, **changes) -> KeyMetadata:
        """Best-effort metadata enrichment (links, not_after). Does not change custody."""

    @abstractmethod
    def transition(self, key_id: str, from_statuses: Sequence[KeyStatus], to_status: KeyStatus,
                   **changes) -> KeyMetadata:
        """Atomic compare-and-swap on lifecycle state. Raises KeyStateError if the key was
        not in one of `from_statuses` (i.e. somebody else moved it first)."""

    @abstractmethod
    def delete(self, key_id: str) -> None: ...


class MemoryKeyMetadataStore(KeyMetadataStore):
    def __init__(self):
        self._lock = threading.RLock()
        self._m = {}

    def put(self, meta):
        with self._lock:
            self._m[meta.key_id] = meta
            return meta

    def get(self, key_id):
        with self._lock:
            return self._m.get(key_id)

    def list(self, status=None):
        with self._lock:
            items = list(self._m.values())
        if status is not None:
            items = [m for m in items if m.status is status]
        return sorted(items, key=lambda m: (m.created_at, m.key_id))

    def update(self, key_id, **changes):
        with self._lock:
            cur = self._m.get(key_id)
            if cur is None:
                raise KeyNotFoundError("unknown key id")
            if "status" in changes:
                raise KeyStateError("status changes must go through transition()")
            new = replace(cur, **changes)
            self._m[key_id] = new
            return new

    def transition(self, key_id, from_statuses, to_status, **changes):
        with self._lock:
            cur = self._m.get(key_id)
            if cur is None:
                raise KeyNotFoundError("unknown key id")
            if cur.status not in set(from_statuses):
                raise KeyStateError(f"key is {cur.status.value}; expected one of "
                                    f"{sorted(s.value for s in from_statuses)}")
            new = replace(cur, status=to_status, version=cur.version + 1, **changes)
            self._m[key_id] = new
            return new

    def delete(self, key_id):
        with self._lock:
            self._m.pop(key_id, None)


class PgKeyMetadataStore(KeyMetadataStore):
    """Durable metadata store. `transition()` is a single guarded UPDATE (atomic in PG)."""

    def __init__(self, db):
        self.db = db

    # --------------------------------------------------------------- row mapping
    @staticmethod
    def _meta(r) -> KeyMetadata:
        return KeyMetadata(
            key_id=r["key_id"], provider=r["provider"],
            algorithm=KeyAlgorithm(r["algorithm"]), status=KeyStatus(r["status"]),
            created_at=float(r["created_at"]), public_key_b64=r["public_key"],
            fingerprint=r["fingerprint"], version=int(r["version"]),
            external_ref=r["external_ref"], not_after=(float(r["not_after"])
                                                        if r["not_after"] is not None else None),
            rotates_to=r["rotates_to"], rotated_from=r["rotated_from"],
            revoked_reason=r["revoked_reason"],
            revoke_effective_at=(float(r["revoke_effective_at"])
                                 if r["revoke_effective_at"] is not None else None),
            exportable=bool(r["exportable"]), created_by=r["created_by"],
            tenant_id=r["tenant_id"], labels=tuple(r["labels"] or ()))

    def put(self, meta):
        # NOTE: never raise a domain error inside the transaction callback — the pool's
        # error mapper would wrap it into a generic StorageError. Signal the outcome and
        # raise outside, where the caller can act on it.
        def go(c):
            cur = c.execute(
                "INSERT INTO kms_keys (key_id, provider, algorithm, status, created_at,"
                " public_key, fingerprint, version, external_ref, not_after, rotates_to,"
                " rotated_from, revoked_reason, revoke_effective_at, exportable, created_by,"
                " tenant_id, labels) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (key_id) DO NOTHING",
                (meta.key_id, meta.provider, meta.algorithm.value, meta.status.value,
                 meta.created_at, meta.public_key_b64, meta.fingerprint, meta.version,
                 meta.external_ref, meta.not_after, meta.rotates_to, meta.rotated_from,
                 meta.revoked_reason, meta.revoke_effective_at, meta.exportable,
                 meta.created_by, meta.tenant_id, list(meta.labels)))
            if cur.rowcount == 1:
                return "ok"
            row = c.execute("SELECT * FROM kms_keys WHERE key_id=%s",
                            (meta.key_id,)).fetchone()
            # re-registering an IDENTICAL row is a no-op (idempotent); anything else collides
            return "ok" if (row is not None and self._meta(row) == meta) else "conflict"
        if self.db.run("kms_put_key", go) == "conflict":
            raise ConflictError("key id already exists with different metadata")
        return meta

    def get(self, key_id):
        r = self.db.run("kms_get_key", lambda c: c.execute(
            "SELECT * FROM kms_keys WHERE key_id=%s", (key_id,)).fetchone())
        return self._meta(r) if r else None

    def list(self, status=None):
        if status is None:
            rows = self.db.run("kms_list_keys", lambda c: c.execute(
                "SELECT * FROM kms_keys ORDER BY created_at, key_id").fetchall())
        else:
            rows = self.db.run("kms_list_keys", lambda c: c.execute(
                "SELECT * FROM kms_keys WHERE status=%s ORDER BY created_at, key_id",
                (status.value,)).fetchall())
        return [self._meta(r) for r in rows]

    def update(self, key_id, **changes):
        if "status" in changes:
            raise KeyStateError("status changes must go through transition()")
        return self._apply(key_id, changes, guarded=False)

    def transition(self, key_id, from_statuses, to_status, **changes):
        return self._apply(key_id, dict(changes, status=to_status),
                           guarded=True, from_statuses=tuple(from_statuses))

    def _apply(self, key_id, changes, *, guarded, from_statuses=()):
        allowed = {"not_after", "rotates_to", "rotated_from", "revoked_reason",
                   "revoke_effective_at", "external_ref", "tenant_id", "labels", "status",
                   "exportable"}
        unknown = set(changes) - allowed
        if unknown:
            raise KeyStateError(f"unsupported metadata change: {sorted(unknown)}")
        cols, vals = [], []
        for k, v in changes.items():
            cols.append(f"{k}=%s")
            vals.append(v.value if isinstance(v, KeyStatus) else
                        (list(v) if k == "labels" else v))
        sql = ("UPDATE kms_keys SET " + ", ".join(cols) +
               ", version=version+1, row_updated_at=now() WHERE key_id=%s")
        params = list(vals) + [key_id]
        if guarded:
            sql += " AND status = ANY(%s)"
            params.append([s.value for s in from_statuses])

        def go(c):
            cur = c.execute(sql, tuple(params))
            if cur.rowcount == 1:
                row = c.execute("SELECT * FROM kms_keys WHERE key_id=%s", (key_id,)).fetchone()
                return "ok", dict(row)
            row = c.execute("SELECT status FROM kms_keys WHERE key_id=%s", (key_id,)).fetchone()
            return ("missing", None) if row is None else ("conflict", row["status"])

        kind, payload = self.db.run("kms_update_key", go)
        if kind == "ok":
            return self._meta(payload)
        if kind == "missing":
            raise KeyNotFoundError("unknown key id")
        raise KeyStateError(f"key is {payload}; concurrent transition rejected")

    def delete(self, key_id):
        self.db.run("kms_delete_key", lambda c: c.execute(
            "DELETE FROM kms_keys WHERE key_id=%s", (key_id,)))


class KeyAuditSink:
    """Durable audit sink for key operations. Field values are never secrets."""

    def record(self, event: str, **fields) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


class NullKeyAuditSink(KeyAuditSink):
    def record(self, event, **fields):
        return None


class PgKeyAuditSink(KeyAuditSink):
    """Append-only security audit for key administration. No key/token material is stored."""

    _FIELDS = ("key_id", "provider", "algorithm", "result", "reason", "actor",
               "correlation_id", "detail")

    def __init__(self, db):
        self.db = db

    def record(self, event, **fields):
        clean = {k: (str(fields[k])[:256] if fields.get(k) is not None else None)
                 for k in self._FIELDS}
        self.db.run("kms_audit", lambda c: c.execute(
            "INSERT INTO kms_key_audit (event, key_id, provider, algorithm, result, reason,"
            " actor, correlation_id, detail) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (event, clean["key_id"], clean["provider"], clean["algorithm"],
             clean["result"] or "ok", clean["reason"], clean["actor"],
             clean["correlation_id"], clean["detail"])))
        return None
