"""Key metadata ledger + key-management *manager* (rotation, retirement, recovery).

The ledger stores NO key material - only key ids, versions, lifecycle states and deadlines. The
in-memory implementation is for development/tests; ``storage/postgres`` provides the production one.
"""
from __future__ import annotations

import threading
from dataclasses import replace
from typing import Dict, Iterable, Optional, Tuple

from .errors import KmsIntegrityError, KmsProviderError
from .interfaces import KeyMetadataStore
from .models import (KeyMetadata, KeyVersion, KmsKeyState, TERMINAL_STATES, check_transition,
                     coerce_state)


class InMemoryKeyMetadataStore(KeyMetadataStore):
    def __init__(self):
        self._lock = threading.RLock()
        self._keys: Dict[str, KeyMetadata] = {}

    def put_key(self, meta: KeyMetadata) -> None:
        with self._lock:
            self._keys[meta.key_id] = meta

    def get_key(self, key_id: str) -> Optional[KeyMetadata]:
        with self._lock:
            return self._keys.get(key_id)

    def list_keys(self, *, provider: Optional[str] = None,
                  org_id: Optional[str] = None) -> Tuple[KeyMetadata, ...]:
        with self._lock:
            return tuple(m for m in self._keys.values()
                         if (provider is None or m.provider == provider)
                         and (org_id is None or m.org_id == org_id))

    def put_version(self, ver: KeyVersion) -> None:
        with self._lock:
            meta = self._keys.get(ver.key_id)
            if meta is None:
                meta = KeyMetadata(ver.key_id, ver.provider, ver.algorithm, ver.key_type,
                                   ver.usages, ver.org_id, ver.purpose, ver.created_at, "kms")
            self._keys[ver.key_id] = meta.with_version(ver)

    def transition(self, key_id: str, version: int, *, expected_states: Iterable[KmsKeyState],
                   new_state: KmsKeyState, **fields) -> Optional[KeyVersion]:
        with self._lock:
            meta = self._keys.get(key_id)
            if meta is None:
                return None
            cur = meta.version(version)
            if cur is None or cur.state not in set(expected_states):
                return None                              # precondition failed: another writer won
            check_transition(cur.state, new_state)
            updated = replace(cur, state=coerce_state(new_state),
                              **{k: fields[k] for k in
                                 ("retire_at", "retired_at", "revoked_at", "revoke_reason",
                                  "enabled_at") if k in fields and fields[k] is not None})
            self._keys[key_id] = meta.with_version(updated)
            return updated

    def delete(self, key_id: str, version: Optional[int] = None) -> None:
        with self._lock:
            if version is None:
                self._keys.pop(key_id, None)
                return
            meta = self._keys.get(key_id)
            if meta is None:
                return
            left = tuple(v for v in meta.versions if v.version != version)
            if not left:
                self._keys.pop(key_id, None)
            else:
                self._keys[key_id] = replace(meta, versions=left)


class KeyManagementManager:
    """Lifecycle orchestration on top of a provider + metadata ledger.

    A *logical key* has one or more ordered *versions*. Exactly one version is ENABLED (the signer);
    previously-enabled versions are RETIRING and remain verifiable until their overlap deadline, then
    become RETIRED (terminal). The manager owns deadlines and concurrency; the provider owns the raw
    crypto and the true state of the material.
    """

    def __init__(self, provider, store: KeyMetadataStore, config, logger=None, clock=None,
                 metrics=None):
        self.provider = provider
        self.store = store
        self.cfg = config
        self.log = logger
        self.clock = clock
        self.metrics = metrics
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ helpers
    def _now(self) -> float:
        return self.clock.now() if self.clock is not None else __import__("time").time()

    def _emit(self, event: str, **fields):
        if self.log is not None:
            try:
                return self.log.emit(event, **fields)
            except Exception:
                return None
        return None

    def _register(self, ver: KeyVersion) -> None:
        self.store.put_version(ver)

    # ------------------------------------------------------------------ create / get / rotate
    def create_key(self, key_id: str, *, usages=(), org_id: Optional[str] = None, purpose: str = "",
                   actor: str = "system") -> KeyVersion:
        with self._lock:
            if self.store.get_key(key_id) is not None:
                raise KmsProviderError("key id already registered")
            ver = self.provider.create_key(key_id, usages=usages, org_id=org_id, purpose=purpose,
                                           created_by=actor)
            self._register(ver)
            self._emit("kms.key_create", key_id=key_id, key_id_version=ver.version,
                       provider=self.provider.name, actor=actor, result="ok")
            return ver

    def get_metadata(self, key_id: str) -> KeyMetadata:
        meta = self.store.get_key(key_id)
        if meta is None:
            raise KmsProviderError("unknown key")
        return meta

    def rotate(self, key_id: str, *, actor: str = "system", overlap_seconds: Optional[int] = None,
               force: bool = False) -> KeyVersion:
        """Create a new enabled version and retire the current one after an overlap window.

        Concurrency-safe: the retirement of each old version is a compare-and-swap that only fires
        while the version is still ENABLED, so two concurrent rotations cannot both 'retire' the same
        version or leave two signers enabled."""
        overlap = self.cfg.retire_overlap_seconds if overlap_seconds is None else int(overlap_seconds)
        if overlap < 0:
            raise KmsProviderError("invalid overlap")
        with self._lock:
            meta = self.get_metadata(key_id)
            if not force and meta.active() is None and meta.latest() is not None:
                raise KmsProviderError("key has no active version; refusing to rotate")
            new = self.provider.rotate(key_id, purpose=meta.purpose)
            self._register(new)
            deadline = self._now() + overlap
            for v in meta.versions:
                if v.state == KmsKeyState.ENABLED:
                    self.store.transition(key_id, v.version, expected_states=(KmsKeyState.ENABLED,),
                                          new_state=KmsKeyState.RETIRING, retire_at=deadline)
            self._emit("kms.key_rotate", key_id=key_id, key_id_version=new.version,
                       provider=self.provider.name, actor=actor, result="ok")
            return new

    # ------------------------------------------------------------------ retire / revoke / destroy
    def retire(self, key_id: str, version: int, *, actor: str = "system") -> Optional[KeyVersion]:
        """Move a RETIRING version to RETIRED once its overlap has elapsed. Refuses early retirement
        (credentials may still validly depend on it)."""
        with self._lock:
            meta = self.get_metadata(key_id)
            v = meta.version(version)
            if v is None:
                raise KmsProviderError("unknown key version")
            if v.state == KmsKeyState.RETIRED:
                return v
            if v.state in (KmsKeyState.REVOKED, KmsKeyState.DESTROYED):
                return v
            if v.state == KmsKeyState.ENABLED:
                raise KmsProviderError("cannot retire an enabled key; rotate first")
            if v.state == KmsKeyState.RETIRING and v.retire_at is not None \
                    and self._now() < v.retire_at:
                raise KmsProviderError("retirement overlap has not elapsed")
            self.provider.set_state(key_id, version, KmsKeyState.RETIRED, retired_at=self._now())
            out = self.store.transition(key_id, version, expected_states=(KmsKeyState.RETIRING,),
                                        new_state=KmsKeyState.RETIRED, retired_at=self._now())
            if out is not None:
                self._emit("kms.key_retire", key_id=key_id, key_id_version=version, actor=actor,
                           result="ok")
            return out or v

    def revoke(self, key_id: str, version: int, reason: str, *, actor: str = "system"):
        with self._lock:
            meta = self.get_metadata(key_id)
            v = meta.version(version)
            if v is None:
                raise KmsProviderError("unknown key version")
            if v.state in (KmsKeyState.REVOKED, KmsKeyState.DESTROYED):
                return v
            self.provider.revoke(key_id, version, reason)
            out = self.store.transition(key_id, version, expected_states=tuple(
                s for s in KmsKeyState if s not in (KmsKeyState.RETIRED, KmsKeyState.REVOKED,
                                                    KmsKeyState.DESTROYED)),
                new_state=KmsKeyState.REVOKED, revoked_at=self._now(),
                revoke_reason=str(reason)[:128])
            self._emit("kms.key_revoke", key_id=key_id, key_id_version=version, actor=actor,
                       revocation_reason=str(reason)[:64], result="ok")
            return out or v

    def destroy(self, key_id: str, version: Optional[int] = None, *, actor: str = "system") -> None:
        """Destroy key material. Only terminal versions may be destroyed: a live credential must
        never lose its verification key."""
        with self._lock:
            meta = self.get_metadata(key_id)
            targets = meta.versions if version is None else (meta.version(version),)
            for v in targets:
                if v is None:
                    continue
                if v.state not in TERMINAL_STATES:
                    raise KmsProviderError("refusing to destroy a non-terminal key version")
            self.provider.delete_key(key_id, version)
            self.store.delete(key_id, version)
            self._emit("kms.key_destroy", key_id=key_id, key_id_version=version, actor=actor,
                       result="ok")

    # ------------------------------------------------------------------ recovery / housekeeping
    def reap(self, *, actor: str = "system") -> int:
        """Advance every RETIRING version whose overlap has elapsed to RETIRED. Idempotent and safe
        to run from any replica; used to recover from an interrupted rotation (the state ledger,
        not a process, decides what happens)."""
        n = 0
        now = self._now()
        for meta in self.store.list_keys(provider=self.provider.name):
            for v in meta.versions:
                if v.state == KmsKeyState.RETIRING and v.retire_at is not None and now >= v.retire_at:
                    try:
                        self.provider.set_state(meta.key_id, v.version, KmsKeyState.RETIRED,
                                                retired_at=now)
                        if self.store.transition(meta.key_id, v.version,
                                                 expected_states=(KmsKeyState.RETIRING,),
                                                 new_state=KmsKeyState.RETIRED,
                                                 retired_at=now) is not None:
                            n += 1
                            self._emit("kms.key_retire", key_id=meta.key_id,
                                       key_id_version=v.version, actor=actor, result="ok")
                    except Exception:
                        # never let one stuck key block the rest of the sweep
                        continue
        return n

    def health(self) -> dict:
        ok = False
        try:
            ok = bool(self.provider.health_check())
        except Exception:
            ok = False
        out = {"provider": self.provider.name, "development": self.provider.is_development,
               "provider_healthy": ok, "keys": len(self.store.list_keys(provider=self.provider.name))}
        out["ready"] = ok if self.cfg.require_health_check else True
        return out
