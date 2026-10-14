"""KMS/HSM layer errors. Messages NEVER contain key material, credentials or provider text
(driver/API messages can echo key ids, ARNs or request payloads)."""
from ..core.errors import IdentityError


class KmsError(IdentityError):
    code = "kms_error"


class KmsConfigError(KmsError, ValueError):
    code = "kms_config_error"


class KmsUnavailableError(KmsError):
    """Provider unreachable / throttled / timed out after bounded retries.

    Callers MUST fail closed (deny the signing/verification operation); there is no local
    fallback and never a development key substituted for a production key."""
    code = "kms_unavailable"


class KmsAccessDeniedError(KmsError):
    """Provider denied the operation (IAM/permission/HSM login). Never retried: it is not
    transient, and retrying a denied privileged call is itself an anti-pattern."""
    code = "kms_access_denied"


class KmsKeyNotFoundError(KmsError):
    code = "kms_key_not_found"


class KmsKeyStateError(KmsError):
    """Operation not permitted for the key's lifecycle state (disabled/retiring/retired/revoked)."""
    code = "kms_key_state"


class KmsRetiredKeyInUseError(KmsKeyStateError):
    """A key that must no longer sign was asked to sign. Distinguished so callers can alert."""
    code = "kms_retired_key_in_use"


class KmsKeyUsageError(KmsError):
    """Key exists but is not permitted for the requested cryptographic operation/algorithm."""
    code = "kms_key_usage"


class KmsProviderError(KmsError):
    """Malformed or inconsistent provider response: the provider cannot be trusted for this
    operation, so it is treated as a failure (fail closed), never as a partial success."""
    code = "kms_provider_error"


class KmsIntegrityError(KmsError):
    """Key metadata failed integrity validation, or provider and ledger disagree (tamper/drift)."""
    code = "kms_integrity"


class KmsProductionProviderError(KmsConfigError):
    """A development-only provider was selected while the process runs in staging/production."""
    code = "kms_dev_provider_forbidden"
