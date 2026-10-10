"""KMS/HSM error hierarchy. Messages NEVER contain key material or provider secrets.

Every error derives from the existing IdentityError so callers that already handle
agent_identity errors keep working. Provider/transport failures are separated from
key-state failures because the two demand different handling: a provider failure is
transient (bounded retry), a key-state failure is a policy denial (never retried).
"""
from ..core.errors import IdentityError


class KmsError(IdentityError):
    code = "kms_error"


class KmsConfigError(KmsError):
    code = "kms_config_error"


class KeyNotFoundError(KmsError):
    """The key id is unknown to this provider/metadata store."""
    code = "key_not_found"


class KeyStateError(KmsError):
    """Operation not permitted for the key's current lifecycle state (e.g. signing
    with a RETIRING/RETIRED/REVOKED key). A policy denial, never retried."""
    code = "key_state_error"


class KeyCollisionError(KmsError):
    """A key id already exists in the provider with different content."""
    code = "key_collision"


class UnsupportedAlgorithmError(KmsError):
    code = "unsupported_algorithm"


class ProviderError(KmsError):
    """Base for provider-side failures (network, 5xx, invalid response...)."""
    code = "provider_error"


class ProviderUnavailableError(ProviderError):
    code = "provider_unavailable"


class ProviderTimeoutError(ProviderError):
    code = "provider_timeout"


class ProviderPermissionError(ProviderError):
    """Provider denied the operation (IAM/Vault policy/HSM PIN). Never retried."""
    code = "provider_permission_denied"


class ProviderRateLimitedError(ProviderError):
    code = "provider_rate_limited"


class ProviderResponseError(ProviderError):
    """Provider returned something we cannot trust (missing/invalid fields)."""
    code = "provider_invalid_response"
