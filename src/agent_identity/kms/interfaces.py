"""Key-management interfaces.

`KeyManager` EXTENDS the pre-existing `KeyStore` ABC (storage/interfaces.py) rather than
duplicating it. Consequence: any KeyManager is a drop-in replacement for the legacy
KeyStore that `IdentityService`/`Verifier` already accept — no redesign of the identity
system is required, and both stay backwards compatible.

The pre-existing KeyStore contract is preserved verbatim:
    * sign-only — no method ever returns private key bytes
    * the five legacy methods keep their exact signatures and semantics

`CryptoBackend` is the provider-specific half: it isolates *crypto + key custody* (a
software Ed25519 key, Vault Transit, a PKCS#11 HSM) behind one narrow interface, so
provider code never leaks into the identity/lifecycle logic.
"""
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

from ..storage.interfaces import KeyStore
from .models import KeyAlgorithm, KeyMetadata, KeyStatus, ProviderHealth


class KeyManager(KeyStore, ABC):
    """Provider-independent key management on top of a `CryptoBackend`.

    Creation / identification / versioning / signing / verification-support /
    rotation / status / revocation metadata / health / controlled retirement.
    """

    # ---------------------------------------------------------------- creation
    @abstractmethod
    def create_key(self, key_id: str, algorithm: KeyAlgorithm = KeyAlgorithm.ED25519, *,
                   status: KeyStatus = KeyStatus.ACTIVE, labels: Tuple[str, ...] = (),
                   tenant_id: Optional[str] = None, external_ref: Optional[str] = None,
                   actor: str = "system") -> KeyMetadata:
        """Generate a NEW key in the provider and record its metadata.

        The private key is created inside the provider and (unless the provider is
        explicitly configured exportable) never leaves it.
        """

    # -------------------------------------------------------------------- read
    @abstractmethod
    def get_key_status(self, key_id: str) -> KeyMetadata:
        """Full non-secret metadata for a key (status, version, rotation links...)."""

    @abstractmethod
    def get_public_key(self, key_id: str) -> str:
        """Base64url raw Ed25519 public key — what a verifier needs."""

    @abstractmethod
    def list_keys(self, *, status: Optional[KeyStatus] = None) -> List[KeyMetadata]:
        """Keys known to this manager, optionally filtered by lifecycle state."""

    # --------------------------------------------------------------- lifecycle
    @abstractmethod
    def rotate_key(self, key_id: str, new_key_id: str, *, grace_seconds: float,
                   actor: str = "system") -> Tuple[KeyMetadata, KeyMetadata]:
        """Create `new_key_id` ACTIVE and move `key_id` to ROTATING -> RETIRING with an
        overlap deadline. During the overlap BOTH keys verify; afterwards only the new one
        does. Returns (rotated_old_metadata, new_metadata).
        """

    @abstractmethod
    def retire_key(self, key_id: str, *, not_after: float, actor: str = "system") -> KeyMetadata:
        """Move a key out of the signing path. It stays available for verification until
        `not_after`, then only until every credential that depends on it has expired.
        """

    @abstractmethod
    def revoke_key(self, key_id: str, *, reason: str, actor: str = "system") -> KeyMetadata:
        """Irreversibly mark a key compromised. Terminal."""

    @abstractmethod
    def destroy_key(self, key_id: str, *, actor: str = "system") -> None:
        """Delete the provider-side key material. Refused unless the key is RETIRED/REVOKED
        (i.e. no live credential may still depend on it) — see `may_destroy`.
        """

    # -------------------------------------------------------------------- ops
    @abstractmethod
    def health_check(self) -> ProviderHealth:
        """Cheap liveness check against the provider (used by /readyz and by callers who
        want to fail closed *before* attempting a signing operation)."""


class CryptoBackend(ABC):
    """Provider-specific crypto + custody. No lifecycle logic lives here.

    Implementations MUST:
      * generate keys inside the provider (non-exportable where supported);
      * never return private key bytes;
      * raise the kms.errors.* provider failures (unavailable/timeout/permission/...)
        rather than leaking provider exceptions to callers.
    """

    name: str = "abstract"

    @abstractmethod
    def generate(self, key_id: str, algorithm: KeyAlgorithm) -> Tuple[bytes, dict]:
        """Create a keypair; return (raw public key bytes, provider refs dict).

        `provider refs` is whatever the backend needs to address the key later
        (e.g. {"vault_key": "..."} or {"cka_id": b"..."}), stored as `external_ref`.
        """

    @abstractmethod
    def public(self, key_id: str, external_ref: Optional[str], algorithm: KeyAlgorithm) -> bytes:
        """Return the raw public key bytes for an existing key."""

    @abstractmethod
    def sign(self, key_id: str, external_ref: Optional[str], algorithm: KeyAlgorithm,
             data: bytes) -> bytes:
        """Sign `data` (already domain-separated by the caller) with the provider key."""

    @abstractmethod
    def destroy(self, key_id: str, external_ref: Optional[str]) -> None:
        """Delete the key material in the provider. Idempotent for an absent key."""

    @abstractmethod
    def health(self) -> ProviderHealth:
        """Provider liveness/readiness."""

    def supports(self, algorithm: KeyAlgorithm) -> bool:
        return algorithm is KeyAlgorithm.ED25519
