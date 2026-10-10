"""Enterprise KMS/HSM key management (Step 5).

Provider-independent cryptographic key management for AgentGuard:
creation, identification/versioning, signing, verification material, rotation,
lifecycle/status, revocation metadata, provider health and controlled retirement.

`DefaultKeyManager` implements the pre-existing `KeyStore` ABC, so it drops straight into
`IdentityService`/`Verifier`/`SpiffeIdentityProvider` with no redesign.

Providers: `local` (development/test only), `vault` (HashiCorp Vault Transit, Ed25519,
non-exportable) and `pkcs11` (PKCS#11 HSM, CKM_EDDSA). See docs/KMS_HSM.md for the
validated-against matrix and known limitations.
"""
from .config import PROVIDERS, KmsConfig
from .errors import (KeyCollisionError, KeyNotFoundError, KeyStateError, KmsConfigError,
                     KmsError, ProviderError, ProviderPermissionError,
                     ProviderRateLimitedError, ProviderResponseError,
                     ProviderTimeoutError, ProviderUnavailableError,
                     UnsupportedAlgorithmError)
from .factory import backend_from_config, build_key_manager
from .interfaces import CryptoBackend, KeyManager
from .manager import DefaultKeyManager
from .metadata import (KeyAuditSink, KeyMetadataStore, MemoryKeyMetadataStore,
                       NullKeyAuditSink, PgKeyAuditSink, PgKeyMetadataStore)
from .models import (KeyAlgorithm, KeyMetadata, KeyStatus, ProviderHealth, is_terminal,
                     may_destroy, may_sign, may_verify)
from .trust_bridge import TrustStoreComposition, managed_storage_kwargs

__all__ = [
    "KmsConfig", "PROVIDERS", "KeyAlgorithm", "KeyStatus", "KeyMetadata", "ProviderHealth",
    "KeyManager", "CryptoBackend", "DefaultKeyManager", "KeyMetadataStore",
    "MemoryKeyMetadataStore", "PgKeyMetadataStore", "KeyAuditSink", "NullKeyAuditSink",
    "PgKeyAuditSink", "KmsError", "KmsConfigError", "KeyNotFoundError", "KeyStateError",
    "KeyCollisionError", "UnsupportedAlgorithmError", "ProviderError",
    "ProviderUnavailableError", "ProviderTimeoutError", "ProviderPermissionError",
    "ProviderRateLimitedError", "ProviderResponseError", "may_sign", "may_verify",
    "may_destroy", "is_terminal", "build_key_manager", "backend_from_config",
    "TrustStoreComposition", "managed_storage_kwargs",
]
