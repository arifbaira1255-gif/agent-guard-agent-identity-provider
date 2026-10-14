"""Development / test-only key provider.

Private keys are generated in-process and Fernet-encrypted at rest, exactly like the pre-existing
``EncryptedMemoryKeyStore``, but behind the full ``KeyManagementProvider`` lifecycle. It is NOT a
production provider and refuses (twice) to run when ``AGENTGUARD_ENV`` is staging/production:
once at construction and once on every signing operation, so a running process that is started in
development and somehow re-enters production mode still fails closed instead of silently signing
with a development key.

Key material is stored as an ``Ed25519PrivateKey`` object in a JSON entity (mirroring the existing
``EntityStore`` usage where the in-memory state store persists objects directly). This provider is
explicitly marked ``exportable`` because tests and local tooling need raw material; real providers
are not.
"""
from __future__ import annotations

import os
import threading
from typing import Dict, Iterable, Optional, Tuple

from ..crypto import keys
from ..crypto.encoding import b64u_encode
from ..spiffe.config import ENV_VAR, Environment
from .errors import (KmsKeyNotFoundError, KmsKeyStateError, KmsKeyUsageError,
                     KmsProductionProviderError, KmsProviderError)
from .interfaces import KeyManagementProvider
from .models import (KeyMetadata, KeyVersion, KmsAlgorithm, KmsKeyState, KmsKeyType,
                     KmsKeyUsage, check_transition, coerce_algorithm, coerce_state,
                     coerce_usages)

DEFAULT_MAX_KEYS = 100_000


def _process_environment() -> Optional[Environment]:
    raw = os.environ.get(ENV_VAR, "").strip().lower()
    if not raw:
        return None
    try:
        return Environment(raw)
    except ValueError:
        return None


class LocalDevProvider(KeyManagementProvider):
    name = "local-dev"
    is_development = True
    supports_export = True

    def __init__(self, entity_store=None, master_key: Optional[bytes] = None,
                 *, max_keys: int = DEFAULT_MAX_KEYS, allow_export: bool = True):
        # --- guard #1: refuse to even exist in a durable environment -------------------------
        if _process_environment() in (Environment.STAGING, Environment.PRODUCTION):
            raise KmsProductionProviderError(
                "local-dev key provider is disabled outside development")
        self._store = entity_store
        self._lock = threading.RLock()
        self._max_keys = max_keys
        self._allow_export = allow_export
        if self._store is None:                       # standalone / tests
            self._mem: Dict[str, dict] = {}
        from cryptography.fernet import Fernet
        self._fernet = Fernet(master_key or Fernet.generate_key())

    # ------------------------------------------------------------------ storage helpers
    def _all(self) -> Dict[str, dict]:
        with self._lock:
            if self._store is None:
                return {k: dict(self._mem[k]) for k in self._mem}
            return {k: dict(e.content) for k, e in self._store.list("kms_key")}

    def _load(self, key_id: str) -> dict:
        with self._lock:
            if self._store is None:
                e = self._mem.get(key_id)
            else:
                ent = self._store.get("kms_key", key_id)
                e = dict(ent.content) if ent is not None else None
        if e is None:
            raise KmsKeyNotFoundError("unknown key")
        return e

    def _save(self, key_id: str, rec: dict) -> None:
        with self._lock:
            if self._store is None:
                if key_id not in self._mem and len(self._mem) >= self._max_keys:
                    raise KmsProviderError("local-dev provider key capacity exhausted")
                self._mem[key_id] = rec
            else:
                self._store.put("kms_key", key_id, dict(rec),
                                ttl_seconds=0, org_id=rec.get("org_id"))

    def _remove(self, key_id: str) -> None:
        with self._lock:
            if self._store is None:
                self._mem.pop(key_id, None)
            else:
                self._store.delete("kms_key", key_id)

    # ------------------------------------------------------------------ entity <-> model
    def _version_from(self, rec: dict, vrec: dict) -> KeyVersion:
        return KeyVersion(key_id=rec["key_id"], version=int(vrec["version"]),
                          provider=self.name, provider_key_id=f"{rec['key_id']}#{vrec['version']}",
                          algorithm=coerce_algorithm(rec["algorithm"]),
                          key_type=KmsKeyType.ASYMMETRIC_SIGNATURE,
                          usages=coerce_usages(vrec.get("usages", rec.get("usages", ()))),
                          state=coerce_state(vrec["state"]),
                          public_key_b64=vrec.get("public_key_b64"),
                          fingerprint=vrec.get("fingerprint", ""),
                          created_at=float(vrec["created_at"]),
                          enabled_at=vrec.get("enabled_at"), retire_at=vrec.get("retire_at"),
                          retired_at=vrec.get("retired_at"), revoked_at=vrec.get("revoked_at"),
                          revoke_reason=vrec.get("revoke_reason"), exportable=self._allow_export,
                          org_id=rec.get("org_id"), purpose=rec.get("purpose", ""))

    def _to_metadata(self, rec: dict) -> KeyMetadata:
        vs = tuple(self._version_from(rec, v) for v in rec["versions"].values())
        meta = KeyMetadata(rec["key_id"], self.name, coerce_algorithm(rec["algorithm"]),
                           KmsKeyType.ASYMMETRIC_SIGNATURE, coerce_usages(rec.get("usages", ())),
                           rec.get("org_id"), rec.get("purpose", ""), float(rec["created_at"]),
                           rec.get("created_by", "system"))
        for v in vs:
            meta = meta.with_version(v)
        return meta

    def _write_meta(self, rec: dict, ver: KeyVersion) -> KeyVersion:
        v = rec["versions"][str(ver.version)]
        v["state"] = ver.state.value
        for f in ("retire_at", "retired_at", "revoked_at", "revoke_reason", "enabled_at"):
            if getattr(ver, f) is not None:
                v[f] = getattr(ver, f)
        self._save(rec["key_id"], rec)
        return self._version_from(rec, v)

    # ------------------------------------------------------------------ capability / health
    def capabilities(self) -> Tuple[KmsAlgorithm, ...]:
        return (KmsAlgorithm.ED25519,)

    def health_check(self) -> bool:
        try:
            return self._fernet is not None and _process_environment() not in (
                Environment.STAGING, Environment.PRODUCTION)
        except Exception:
            return False

    # ------------------------------------------------------------------ creation / discovery
    def create_key(self, key_id, *, algorithm=KmsAlgorithm.ED25519, usages=(), exportable=False,
                   org_id=None, purpose="", created_by="system") -> KeyVersion:
        alg = coerce_algorithm(algorithm)
        if alg not in self.capabilities():
            raise KmsProviderError("unsupported algorithm")
        us = coerce_usages(usages)
        with self._lock:
            try:
                self._load(key_id)
            except KmsKeyNotFoundError:
                pass
            else:
                raise KmsProviderError("key id collision")
            priv = keys.generate_private_key()
            pub = keys.public_bytes(priv)
            now = _now()
            rec = {"key_id": key_id, "algorithm": alg.value, "usages": [u.value for u in us],
                   "org_id": org_id, "purpose": purpose, "created_at": now,
                   "created_by": created_by, "versions": {
                       "1": {"version": 1, "state": KmsKeyState.ENABLED.value,
                             "public_key_b64": b64u_encode(pub),
                             "fingerprint": keys.fingerprint(pub), "created_at": now,
                             "enabled_at": now, "usages": [u.value for u in us],
                             "encrypted_private": self._fernet.encrypt(keys.private_raw(priv))}}}
            self._save(key_id, rec)
            return self._version_from(rec, rec["versions"]["1"])

    def describe(self, key_id) -> KeyMetadata:
        return self._to_metadata(self._load(key_id))

    def get_version(self, key_id, version) -> KeyVersion:
        rec = self._load(key_id)
        v = rec["versions"].get(str(version))
        if v is None:
            raise KmsKeyNotFoundError("unknown key version")
        return self._version_from(rec, v)

    def public_key(self, key_id, version=None):
        rec = self._load(key_id)
        v = self._pick(rec, version)
        if coerce_state(v["state"]) not in (KmsKeyState.ENABLED, KmsKeyState.RETIRING):
            raise KmsKeyStateError("key is not available for public-key retrieval")
        pub = keys.b64u_decode(v["public_key_b64"])
        return pub, v["public_key_b64"], int(v["version"])

    def _pick(self, rec: dict, version: Optional[int]) -> dict:
        if version is not None:
            v = rec["versions"].get(str(version))
            if v is None:
                raise KmsKeyNotFoundError("unknown key version")
            return v
        enabled = [v for v in rec["versions"].values() if v["state"] == KmsKeyState.ENABLED.value]
        if not enabled:
            raise KmsKeyStateError("no enabled version for key")
        return max(enabled, key=lambda v: int(v["version"]))

    # ------------------------------------------------------------------ crypto operations
    def sign(self, key_id, domain, data, *, usage=None, version=None) -> bytes:
        # --- guard #2: never sign with a development key while running in production --------
        if _process_environment() in (Environment.STAGING, Environment.PRODUCTION):
            raise KmsProductionProviderError(
                "local-dev key provider refuses to sign outside development")
        rec = self._load(key_id)
        v = self._pick(rec, version)
        state = coerce_state(v["state"])
        if state != KmsKeyState.ENABLED:
            raise KmsKeyStateError("key is not enabled for signing")
        if usage is not None and KmsKeyUsage(usage) not in coerce_usages(v.get("usages", ())):
            raise KmsKeyUsageError("key not permitted for this operation")
        from cryptography.fernet import InvalidToken
        try:
            raw = self._fernet.decrypt(bytes(v["encrypted_private"]))
        except InvalidToken:
            raise KmsProviderError("key cannot be decrypted (wrong master key?)")
        return keys.sign(keys.private_from_raw(raw), domain, data)

    def verify(self, public_key_b64, domain, data, signature) -> bool:
        return keys.verify(public_key_b64, domain, data, signature)

    # ------------------------------------------------------------------ lifecycle
    def rotate(self, key_id, *, purpose="") -> KeyVersion:
        rec = self._load(key_id)
        if purpose:
            rec["purpose"] = purpose
        n = max(int(k) for k in rec["versions"]) + 1
        priv = keys.generate_private_key()
        pub = keys.public_bytes(priv)
        now = _now()
        with self._lock:
            for v in rec["versions"].values():
                if v["state"] == KmsKeyState.ENABLED.value:
                    v["state"] = KmsKeyState.RETIRING.value
            rec["versions"][str(n)] = {
                "version": n, "state": KmsKeyState.ENABLED.value, "public_key_b64": b64u_encode(pub),
                "fingerprint": keys.fingerprint(pub), "created_at": now, "enabled_at": now,
                "usages": list(rec.get("usages", [])),
                "encrypted_private": self._fernet.encrypt(keys.private_raw(priv))}
            self._save(key_id, rec)
            return self._version_from(rec, rec["versions"][str(n)])

    def set_state(self, key_id, version, state, **fields) -> KeyVersion:
        rec = self._load(key_id)
        v = rec["versions"].get(str(version))
        if v is None:
            raise KmsKeyNotFoundError("unknown key version")
        check_transition(coerce_state(v["state"]), coerce_state(state))
        v["state"] = coerce_state(state).value
        for f in ("retire_at", "retired_at", "revoked_at", "revoke_reason", "enabled_at"):
            if f in fields and fields[f] is not None:
                v[f] = fields[f]
        self._save(key_id, rec)
        return self._version_from(rec, v)

    def revoke(self, key_id, version, reason) -> KeyVersion:
        return self.set_state(key_id, version, KmsKeyState.REVOKED, revoked_at=_now(),
                              revoke_reason=str(reason)[:128])

    def delete_key(self, key_id, version=None) -> None:
        if version is None:
            self._remove(key_id)
            return
        rec = self._load(key_id)
        with self._lock:
            rec["versions"].pop(str(version), None)
            if not rec["versions"]:
                self._remove(key_id)
            else:
                self._save(key_id, rec)

    def export_private_key(self, key_id, version=None) -> bytes:
        if not self._allow_export:
            raise NotImplementedError("export disabled for this provider instance")
        rec = self._load(key_id)
        v = self._pick(rec, version)
        return self._fernet.decrypt(bytes(v["encrypted_private"]))

    def __repr__(self) -> str:
        n = len(self._mem) if self._store is None else -1
        return f"LocalDevProvider(keys={n}, store={'memory' if self._store is None else 'entity'})"


def _now() -> float:
    import time
    return time.time()
