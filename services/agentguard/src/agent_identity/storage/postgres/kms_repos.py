"""PostgreSQL ``KeyMetadataStore``: the durable, NON-SECRET ledger of KMS key versions.

Stores no key material - private keys belong to the provider. Implements the same contract as
``kms.stores.InMemoryKeyMetadataStore``; the compare-and-swap ``transition`` maps onto a conditional
UPDATE that only fires while the current state is one of the expected ones, which is what makes
rotation concurrency-safe across replicas.
"""
from typing import Iterable, Optional, Tuple

from ...core.errors import ConflictError
from ...kms.errors import KmsProviderError
from ...kms.interfaces import KeyMetadataStore
from ...kms.models import (KeyMetadata, KeyVersion, KmsAlgorithm, KmsKeyState, KmsKeyType,
                           coerce_state, coerce_usages)
from .errors import sqlstate_of

_TERMINAL = ("retired", "revoked", "destroyed")


def _v(r) -> KeyVersion:
    return KeyVersion(key_id=r["key_id"], version=r["version"], provider=r["provider"],
                      provider_key_id=r["provider_key_id"],
                      algorithm=KmsAlgorithm(r["algorithm"]), key_type=KmsKeyType(r["key_type"]),
                      usages=coerce_usages(r["version_usages"]),
                      state=coerce_state(r["state"]), public_key_b64=r["public_key_b64"],
                      fingerprint=r["fingerprint"] or "", created_at=r["created_at"],
                      enabled_at=r["enabled_at"], retire_at=r["retire_at"],
                      retired_at=r["retired_at"], revoked_at=r["revoked_at"],
                      revoke_reason=r["revoke_reason"], exportable=bool(r["exportable"]),
                      org_id=r["org_id"], purpose=r["purpose"] or "")


class PgKeyMetadataStore(KeyMetadataStore):
    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------ write
    def put_key(self, meta: KeyMetadata) -> None:
        def go(c):
            c.execute(
                "INSERT INTO kms_keys (key_id, provider, algorithm, key_type, usages, org_id,"
                " purpose, created_at, created_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (key_id) DO NOTHING",
                (meta.key_id, meta.provider, meta.algorithm.value, meta.key_type.value,
                 [u.value for u in meta.usages], meta.org_id, meta.purpose, meta.created_at,
                 meta.created_by))
            for v in meta.versions:
                self._upsert_version(c, meta, v)
        self.db.run("kms_put_key", go)

    def _upsert_version(self, c, meta, v: KeyVersion) -> None:
        c.execute(
            "INSERT INTO kms_key_versions (key_id, version, provider_key_id, state, public_key_b64,"
            " fingerprint, usages, exportable, created_at, enabled_at, retire_at, retired_at,"
            " revoked_at, revoke_reason) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (key_id, version) DO UPDATE SET state=EXCLUDED.state,"
            " retire_at=EXCLUDED.retire_at, retired_at=EXCLUDED.retired_at,"
            " revoked_at=EXCLUDED.revoked_at, revoke_reason=EXCLUDED.revoke_reason,"
            " enabled_at=COALESCE(EXCLUDED.enabled_at, kms_key_versions.enabled_at)",
            (v.key_id, v.version, v.provider_key_id, v.state.value, v.public_key_b64,
             v.fingerprint, [u.value for u in v.usages], v.exportable, v.created_at, v.enabled_at,
             v.retire_at, v.retired_at, v.revoked_at, v.revoke_reason))

    def put_version(self, ver: KeyVersion) -> None:
        def go(c):
            c.execute(
                "INSERT INTO kms_keys (key_id, provider, algorithm, key_type, usages, org_id,"
                " purpose, created_at, created_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (key_id) DO NOTHING",
                (ver.key_id, ver.provider, ver.algorithm.value, ver.key_type.value,
                 [u.value for u in ver.usages], ver.org_id, ver.purpose, ver.created_at, "kms"))
            self._upsert_version(c, None, ver)
        self.db.run("kms_put_version", go)

    def transition(self, key_id: str, version: int, *, expected_states: Iterable[KmsKeyState],
                   new_state: KmsKeyState, **fields) -> Optional[KeyVersion]:
        expected = [coerce_state(s).value for s in expected_states]
        if not expected:
            return None
        sets = ["state=%s"]
        vals = [coerce_state(new_state).value]
        for name in ("retire_at", "retired_at", "revoked_at", "revoke_reason", "enabled_at"):
            if name in fields and fields[name] is not None:
                sets.append(f"{name}=%s")
                vals.append(fields[name])
        sql = (f"UPDATE kms_key_versions SET {', '.join(sets)} WHERE key_id=%s AND version=%s "
               f"AND state = ANY(%s) RETURNING *")
        params = tuple(vals) + (key_id, version, expected)

        def go(c):
            row = c.execute(sql, params).fetchone()
            if row is None:
                return None
            full = c.execute(self._SELECT_ONE, (key_id, version)).fetchone()
            return full
        row = self.db.run("kms_transition", go)
        return _v(row) if row else None

    _SELECT_ONE = ("SELECT v.*, k.provider, k.algorithm, k.key_type, k.org_id, k.purpose,"
                   " v.usages AS version_usages FROM kms_key_versions v"
                   " JOIN kms_keys k ON k.key_id = v.key_id WHERE v.key_id=%s AND v.version=%s")

    # ------------------------------------------------------------------ read
    def get_key(self, key_id: str) -> Optional[KeyMetadata]:
        rows = self.db.run("kms_get_key", lambda c: c.execute(
            "SELECT v.*, k.provider, k.algorithm, k.key_type, k.org_id, k.purpose,"
            " v.usages AS version_usages FROM kms_key_versions v"
            " JOIN kms_keys k ON k.key_id = v.key_id WHERE v.key_id=%s ORDER BY v.version",
            (key_id,)).fetchall())
        if not rows:
            return None
        return self._meta(rows)

    def list_keys(self, *, provider: Optional[str] = None,
                  org_id: Optional[str] = None) -> Tuple[KeyMetadata, ...]:
        clauses, params = [], []
        if provider:
            clauses.append("k.provider = %s")
            params.append(provider)
        if org_id:
            clauses.append("k.org_id = %s")
            params.append(org_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.db.run("kms_list_keys", lambda c: c.execute(
            "SELECT v.*, k.provider, k.algorithm, k.key_type, k.org_id, k.purpose,"
            " v.usages AS version_usages FROM kms_key_versions v"
            " JOIN kms_keys k ON k.key_id = v.key_id" + where + " ORDER BY v.key_id, v.version",
            tuple(params)).fetchall())
        out, by_id = [], {}
        for r in rows:
            by_id.setdefault(r["key_id"], []).append(r)
        for key_id, rs in by_id.items():
            out.append(self._meta(rs))
        return tuple(out)

    @staticmethod
    def _meta(rows) -> KeyMetadata:
        first = rows[0]
        meta = KeyMetadata(first["key_id"], first["provider"], KmsAlgorithm(first["algorithm"]),
                           KmsKeyType(first["key_type"]), coerce_usages(first["version_usages"]),
                           first["org_id"], first["purpose"] or "", first["created_at"], "kms")
        for r in rows:
            meta = meta.with_version(_v(r))
        return meta

    # ------------------------------------------------------------------ delete
    def delete(self, key_id: str, version: Optional[int] = None) -> None:
        if version is None:
            self.db.run("kms_delete_key",
                        lambda c: c.execute("DELETE FROM kms_keys WHERE key_id=%s", (key_id,)))
        else:
            self.db.run("kms_delete_version", lambda c: c.execute(
                "DELETE FROM kms_key_versions WHERE key_id=%s AND version=%s", (key_id, version)))
