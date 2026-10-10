"""DEVELOPMENT / TEST-ONLY software key provider.

NOT FOR PRODUCTION. The private key is generated in-process and held Fernet-encrypted
at rest (in memory, or in the existing `keystore_keys` table when a blob store is
supplied). The master key comes from the caller and is never persisted here.

Real deployments must use the Vault Transit provider or a PKCS#11 HSM: `KmsConfig.validate()`
refuses this provider outside development unless an explicit, audited override is set
(`allow_local_in_production`). See docs/KMS_HSM.md.
"""
import threading
from typing import Optional, Protocol, Tuple

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from ...crypto import keys as _keys
from ..errors import (KeyCollisionError, KeyNotFoundError, KmsConfigError,
                      ProviderResponseError)
from ..interfaces import CryptoBackend
from ..models import KeyAlgorithm, ProviderHealth

_ED25519_PUB_LEN = 32


class KeyBlobStore(Protocol):
    """Minimal encrypted-blob store (never sees plaintext private key bytes)."""

    def get(self, key_id: str) -> Optional[bytes]: ...
    def put_if_absent(self, key_id: str, blob: bytes) -> bool: ...
    def delete(self, key_id: str) -> None: ...


class MemoryBlobStore:
    """Thread-safe in-memory encrypted-blob store (development / tests)."""

    def __init__(self):
        self._lock = threading.RLock()
        self._blobs = {}

    def get(self, key_id: str) -> Optional[bytes]:
        with self._lock:
            return self._blobs.get(key_id)

    def put_if_absent(self, key_id: str, blob: bytes) -> bool:
        with self._lock:
            if key_id in self._blobs:
                return False
            self._blobs[key_id] = blob
            return True

    def delete(self, key_id: str) -> None:
        with self._lock:
            self._blobs.pop(key_id, None)


class LocalKeyBackend(CryptoBackend):
    """Software Ed25519. Encrypted at rest; sign-only; no method returns private bytes."""

    name = "local"
    exportable = True          # software keys are exportable by nature — recorded honestly

    def __init__(self, master_key, *, store: Optional[KeyBlobStore] = None):
        if isinstance(master_key, str):
            master_key = master_key.encode()
        if isinstance(master_key, (bytes,)):
            master_key = [master_key]
        if not master_key:
            raise KmsConfigError("local software provider requires a master key")
        try:
            self._f = MultiFernet([Fernet(k) for k in master_key])
        except Exception:
            raise KmsConfigError("invalid local provider master key") from None
        self._store = store if store is not None else MemoryBlobStore()

    # ------------------------------------------------------------------ backend
    def generate(self, key_id: str, algorithm: KeyAlgorithm) -> Tuple[bytes, dict]:
        self._require(algorithm)
        priv = _keys.generate_private_key()
        pub = _keys.public_bytes(priv)
        blob = self._f.encrypt(_keys.private_raw(priv))
        if not self._store.put_if_absent(key_id, blob):
            raise KeyCollisionError("key id already exists in the local provider")
        return pub, {"ref": None}

    def public(self, key_id, external_ref, algorithm) -> bytes:
        self._require(algorithm)
        raw = self._load(key_id)
        return _keys.public_bytes(_keys.private_from_raw(raw))

    def sign(self, key_id, external_ref, algorithm, data: bytes) -> bytes:
        self._require(algorithm)
        raw = self._load(key_id)
        # `data` already carries its domain-separation prefix (see crypto/keys.sign)
        return _keys.sign(_keys.private_from_raw(raw), b"", data)

    def destroy(self, key_id, external_ref) -> None:
        self._store.delete(key_id)

    def health(self) -> ProviderHealth:
        return ProviderHealth(healthy=True, provider=self.name,

                              detail="software provider (development only)")

    # ----------------------------------------------------------------- internals
    def _load(self, key_id: str) -> bytes:
        blob = self._store.get(key_id)
        if blob is None:
            raise KeyNotFoundError("unknown key in the local provider")
        try:
            return self._f.decrypt(blob)
        except InvalidToken:
            raise ProviderResponseError("local key cannot be decrypted (wrong master key)") from None

    @staticmethod
    def _require(algorithm: KeyAlgorithm) -> None:
        if algorithm is not KeyAlgorithm.ED25519:
            from ..errors import UnsupportedAlgorithmError
            raise UnsupportedAlgorithmError(f"local provider does not support {algorithm}")

    def __repr__(self) -> str:
        return "LocalKeyBackend(<redacted>)"
