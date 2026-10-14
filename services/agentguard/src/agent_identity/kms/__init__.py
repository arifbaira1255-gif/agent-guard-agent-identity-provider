"""AgentGuard Step 5 - Enterprise KMS/HSM Key Management.

Provider-independent, sign-only key custody behind existing AgentGuard interfaces:

    KeyManagementProvider   (kms/interfaces.py)  <- LocalDevProvider / AwsKmsProvider / Pkcs11Provider
    KeyMetadataStore        (kms/interfaces.py)  <- InMemoryKeyMetadataStore / PgKeyMetadataStore
    KeyManagementManager    (kms/stores.py)      -> versions, rotation, retirement, recovery
    KmsKeyStore             (kms/keystore.py)    -> drop-in storage.interfaces.KeyStore adapter

Quick start (development):
    from agent_identity.kms import KmsConfig, build_kms
    rt = build_kms(KmsConfig(environment="development", provider="local-dev"))
    svc = IdentityService(cfg, **rt.service_kwargs())     # signing now goes through the KMS layer

Production: select ``aws-kms`` or ``pkcs11``; see docs/KMS.md.
"""
from .config import DEV_ONLY_PROVIDERS, PROVIDERS, KmsConfig
from .errors import (KmsAccessDeniedError, KmsConfigError, KmsError, KmsIntegrityError,
                     KmsKeyNotFoundError, KmsKeyStateError, KmsKeyUsageError,
                     KmsProductionProviderError, KmsProviderError, KmsRetiredKeyInUseError,
                     KmsUnavailableError)
from .factory import KmsRuntime, build_key_metadata_store, build_kms
from .interfaces import KeyManagementProvider, KeyMetadataStore
from .keystore import KmsKeyStore
from .models import (KeyMetadata, KeyVersion, KmsAlgorithm, KmsKeyState, KmsKeyType, KmsKeyUsage,
                     SIGNING_STATES, SIGNING_USAGES, TERMINAL_STATES, VERIFYING_STATES,
                     can_transition, check_transition)
from .stores import InMemoryKeyMetadataStore, KeyManagementManager

__all__ = [
    "KmsConfig", "PROVIDERS", "DEV_ONLY_PROVIDERS",
    "KmsError", "KmsConfigError", "KmsUnavailableError", "KmsAccessDeniedError",
    "KmsKeyNotFoundError", "KmsKeyStateError", "KmsRetiredKeyInUseError", "KmsKeyUsageError",
    "KmsProviderError", "KmsIntegrityError", "KmsProductionProviderError",
    "KeyManagementProvider", "KeyMetadataStore",
    "KmsAlgorithm", "KmsKeyType", "KmsKeyUsage", "KmsKeyState", "SIGNING_USAGES",
    "SIGNING_STATES", "VERIFYING_STATES", "TERMINAL_STATES", "can_transition", "check_transition",
    "KeyVersion", "KeyMetadata",
    "InMemoryKeyMetadataStore", "KeyManagementManager", "KmsKeyStore",
    "KmsRuntime", "build_kms", "build_key_metadata_store",
]
