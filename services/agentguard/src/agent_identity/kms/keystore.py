"""Drop-in adapter: presents the EXISTING ``storage.interfaces.KeyStore`` contract while delegating
all key custody to the KMS/HSM provider.

This is what makes Step 5 backward compatible: ``IdentityService`` calls ``generate_key``/``sign``/
``public_key``/``has_key``/``delete_key`` exactly as before, but private material now lives in a
real provider. No engine change is required.

Usage is inferred from the AgentGuard key-id convention so the unchanged service automatically tags
each key with the right purpose (and providers can then enforce least privilege):

    root_*  -> ISSUER_CERT_SIGNING   (root key: signs issuer certificates)
    iss_*   -> PASSPORT_SIGNING      (org issuer key: signs agent passports)
    key_*   -> IDENTITY_SIGNING      (agent identity key / service-held credential key)
    other   -> PROOF_SIGNING         (conservative default for ephemeral proof keys)
"""
from __future__ import annotations

import threading
from typing import Optional, Tuple

from ..core.errors import StorageError
from ..storage.interfaces import KeyStore
from .errors import (KmsError, KmsKeyNotFoundError, KmsKeyStateError, KmsProviderError,
                     KmsRetiredKeyInUseError)
from .models import (KeyVersion, KmsKeyState, KmsKeyUsage, TERMINAL_STATES,
                     SIGNING_USAGES)

_USAGE_BY_PREFIX = (("root_", KmsKeyUsage.ISSUER_CERT_SIGNING),
                    ("iss_", KmsKeyUsage.PASSPORT_SIGNING),
                    ("key_", KmsKeyUsage.IDENTITY_SIGNING))


def infer_usages(key_id: str) -> Tuple[KmsKeyUsage, ...]:
    for prefix, usage in _USAGE_BY_PREFIX:
        if key_id.startswith(prefix):
            return (usage,)
    return (KmsKeyUsage.PROOF_SIGNING,)


class KmsKeyStore(KeyStore):
    """``KeyStore`` implemented on top of a ``KeyManagementProvider`` + ``KeyManagementManager``."""

    def __init__(self, provider, manager, store, *, logger=None):
        self.provider = provider
        self.manager = manager
        self.store = store
        self.log = logger
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ KeyStore ABC
    def generate_key(self, key_id: str, *, usages=None, org_id: Optional[str] = None) -> bytes:
        us = tuple(usages) if usages is not None else infer_usages(key_id)
        try:
            ver = self.manager.create_key(key_id, usages=us, org_id=org_id,
                                          purpose=us[0].value if us else "")
        except KmsError as e:
            raise StorageError(f"kms key creation failed: {getattr(e, 'code', 'kms_error')}") from None
        return self._raw(ver)

    def public_key(self, key_id: str) -> bytes:
        try:
            raw, _, _ = self.provider.public_key(key_id)
            return raw
        except KmsKeyNotFoundError:
            raise StorageError("unknown key") from None
        except KmsError as e:
            raise StorageError(f"kms public key lookup failed: {getattr(e, 'code', 'kms_error')}") \
                from None

    def sign(self, key_id: str, domain: bytes, data: bytes) -> bytes:
        meta = self.store.get_key(key_id)
        if meta is not None and meta.active() is None:
            # every version is non-signing (retiring/retired/revoked): refuse loudly
            raise KmsRetiredKeyInUseError("no enabled version for key")
        try:
            return self.provider.sign(key_id, domain, data)
        except KmsKeyNotFoundError:
            raise StorageError("unknown key") from None
        except KmsError:
            raise
        except Exception as e:                                       # noqa: BLE001
            raise StorageError("kms signing failed") from None

    def has_key(self, key_id: str) -> bool:
        try:
            return self.store.get_key(key_id) is not None
        except Exception:                                            # noqa: BLE001
            return False

    def delete_key(self, key_id: str) -> None:
        """Force-remove key material. Non-terminal versions are revoked first so the metadata ledger
        stays consistent (a key is never silently deleted while still enabled)."""
        meta = self.store.get_key(key_id)
        if meta is None:
            return
        for v in meta.versions:
            if v.state not in TERMINAL_STATES:
                try:
                    self.provider.revoke(key_id, v.version, "key_destroyed")
                except Exception:                                    # noqa: BLE001
                    pass
                try:
                    self.store.transition(
                        key_id, v.version,
                        expected_states=tuple(s for s in KmsKeyState
                                              if s not in TERMINAL_STATES),
                        new_state=KmsKeyState.REVOKED,
                        revoke_reason="key_destroyed")
                except Exception:                                    # noqa: BLE001
                    pass
        try:
            self.provider.delete_key(key_id)
        except KmsError:
            pass
        self.store.delete(key_id)

    # ------------------------------------------------------------------ richer API
    def create_key(self, key_id: str, *, usages=(), org_id: Optional[str] = None,
                   purpose: str = "", actor: str = "system") -> KeyVersion:
        return self.manager.create_key(key_id, usages=usages, org_id=org_id, purpose=purpose,
                                       actor=actor)

    def rotate(self, key_id: str, *, actor: str = "system", overlap_seconds: Optional[int] = None):
        return self.manager.rotate(key_id, actor=actor, overlap_seconds=overlap_seconds)

    def key_metadata(self, key_id: str) -> dict:
        return self.manager.get_metadata(key_id).public_dict()

    def health(self) -> dict:
        return self.manager.health()

    def _raw(self, ver: KeyVersion) -> bytes:
        from ..crypto.encoding import b64u_decode
        if ver.public_key_b64:
            return b64u_decode(ver.public_key_b64)
        raw, _, _ = self.provider.public_key(ver.key_id, ver.version)
        return raw

    def __repr__(self) -> str:
        return f"KmsKeyStore(provider={self.provider.name!r})"
