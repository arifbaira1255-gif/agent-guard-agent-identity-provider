"""SPIFFE-layer errors and machine-readable (secret-free) failure reasons."""


class R:
    MALFORMED = "malformed_svid"
    BAD_SPIFFE_ID = "invalid_spiffe_id"
    UNKNOWN_TRUST_DOMAIN = "unknown_trust_domain"
    BUNDLE_STALE = "trust_bundle_stale"
    BAD_CHAIN = "invalid_certificate_chain"
    EXPIRED = "svid_expired"
    NOT_YET_VALID = "svid_not_yet_valid"
    BAD_SIGNATURE = "invalid_signature"
    UNKNOWN_KEY = "unknown_signing_key"
    BAD_ALG = "disallowed_algorithm"
    BAD_ISSUER = "invalid_issuer"
    BAD_AUDIENCE = "invalid_audience"
    TTL_TOO_LONG = "svid_ttl_exceeds_policy"
    REPLAY = "replay_detected"
    UNBOUND = "unbound_spiffe_id"
    BINDING_MISMATCH = "binding_mismatch"
    INSTANCE_REQUIRED = "instance_identity_required"
    BAD_DELEGATION = "invalid_delegation"
    NOT_ACTIVE = "identity_not_active"
    UNAVAILABLE = "workload_api_unavailable"
    INTERNAL = "internal_error"


class SpiffeError(Exception):
    reason = R.INTERNAL

    def __init__(self, message: str = "", reason: str = None):
        super().__init__(message or (reason or self.reason))
        if reason:
            self.reason = reason


class SvidError(SpiffeError):
    """An SVID / bundle failed validation. Always means DENY."""


class SpiffeIdError(SvidError):
    reason = R.BAD_SPIFFE_ID


class UnknownTrustDomainError(SvidError):
    reason = R.UNKNOWN_TRUST_DOMAIN


class BundleStaleError(SvidError):
    reason = R.BUNDLE_STALE


class WorkloadApiUnavailable(SpiffeError):
    reason = R.UNAVAILABLE


class ConfigError(SpiffeError):
    reason = "invalid_configuration"


class DevModeError(ConfigError):
    reason = "dev_mode_forbidden"
