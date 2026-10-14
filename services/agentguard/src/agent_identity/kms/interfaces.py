"""Key-management abstraction: provider-independent contracts.

``KeyManagementProvider`` is the HSM/KMS boundary. Key material lives behind it; it can sign but
(except in explicitly development-only providers) never export. Implementations MUST fail closed:
a method that cannot establish trust raises rather than returning a permissive default.

``KeyMetadataStore`` is AgentGuard's own NON-SECRET ledger of key ids, versions, states and retire
deadlines. It stores no key material and exists so the system can version, rotate, recover and
audit keys across restarts and replicas.
"""
from abc import ABC, abstractmethod
from typing import Iterable, Optional, Tuple

from .models import (KeyMetadata, KeyVersion, KmsAlgorithm, KmsKeyState, KmsKeyType,
                     KmsKeyUsage)


class KeyManagementProvider(ABC):
    name: str = "abstract"
    is_development: bool = False
    supports_export: bool = False

    # ------------------------------------------------------------------ capability / health
    @abstractmethod
    def capabilities(self) -> Tuple[KmsAlgorithm, ...]:
        """Algorithms this provider can host for signing."""

    @abstractmethod
    def health_check(self) -> bool:
        """Best-effort liveness AND authorisation probe. Must never raise, never leak details."""

    # ------------------------------------------------------------------ key creation
    @abstractmethod
    def create_key(self, key_id: str, *, algorithm: KmsAlgorithm = KmsAlgorithm.ED25519,
                   usages: Iterable[KmsKeyUsage] = (), exportable: bool = False,
                   org_id: Optional[str] = None, purpose: str = "",
                   created_by: str = "system") -> KeyVersion:
        """Create version 1 of a logical key. Raises on collision; never overwrites."""

    # ------------------------------------------------------------------ discovery
    @abstractmethod
    def describe(self, key_id: str) -> KeyMetadata:
        """All versions of a logical key known to the provider. Raises KmsKeyNotFoundError."""

    @abstractmethod
    def get_version(self, key_id: str, version: int) -> KeyVersion: ...

    @abstractmethod
    def public_key(self, key_id: str, version: Optional[int] = None) -> Tuple[bytes, str, int]:
        """Return ``(raw_public_bytes, base64url, version)`` for an ENABLED/RETIRING version."""

    # ------------------------------------------------------------------ crypto operations
    @abstractmethod
    def sign(self, key_id: str, domain: bytes, data: bytes, *,
             usage: Optional[KmsKeyUsage] = None, version: Optional[int] = None) -> bytes:
        """Sign ``domain + data``. State- and usage-restricted; fails closed if not permitted."""

    @abstractmethod
    def verify(self, public_key_b64: str, domain: bytes, data: bytes, signature: bytes) -> bool:
        """Verify a signature against a public key. Returns False for a bad signature; raises only
        for malformed public keys."""

    # ------------------------------------------------------------------ lifecycle
    @abstractmethod
    def rotate(self, key_id: str, *, purpose: str = "") -> KeyVersion:
        """Create the next version ENABLED and move every previously-enabled version to RETIRING,
        so exactly one version can sign at a time. The manager owns the retire deadline."""

    @abstractmethod
    def set_state(self, key_id: str, version: int, state: KmsKeyState, **fields) -> KeyVersion:
        """Advance a version's lifecycle state (validated against the legal transition table).
        ``fields`` may carry ``retire_at`` / ``retired_at`` / ``revoked_at`` / ``revoke_reason``."""

    @abstractmethod
    def revoke(self, key_id: str, version: int, reason: str) -> KeyVersion:
        """Terminal revocation. The key can never sign or verify again."""

    @abstractmethod
    def delete_key(self, key_id: str, version: Optional[int] = None) -> None:
        """Destroy key material. Callers must ensure no valid credential depends on it."""

    # ------------------------------------------------------------------ dev-only escape hatch
    def export_private_key(self, key_id: str, version: Optional[int] = None) -> bytes:
        raise NotImplementedError("this provider does not export private keys")


class KeyMetadataStore(ABC):
    """Durable, non-secret ledger of key versions (backed by PostgreSQL in production)."""

    @abstractmethod
    def put_key(self, meta: KeyMetadata) -> None: ...

    @abstractmethod
    def get_key(self, key_id: str) -> Optional[KeyMetadata]: ...

    @abstractmethod
    def list_keys(self, *, provider: Optional[str] = None,
                  org_id: Optional[str] = None) -> Tuple[KeyMetadata, ...]: ...

    @abstractmethod
    def put_version(self, ver: KeyVersion) -> None:
        """Insert/replace one version on its (already-registered) key."""

    @abstractmethod
    def transition(self, key_id: str, version: int, *, expected_states: Iterable[KmsKeyState],
                   new_state: KmsKeyState, **fields) -> Optional[KeyVersion]:
        """Atomically compare-and-swap one version's state, but ONLY if its current state is in
        ``expected_states``. Returns the updated version, or ``None`` when the precondition failed
        (another writer got there first). ``fields`` updates retire_at/retired_at/revoked_at/..."""

    @abstractmethod
    def delete(self, key_id: str, version: Optional[int] = None) -> None: ...
