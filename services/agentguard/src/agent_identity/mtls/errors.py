"""mTLS-layer errors. Reasons are stable, secret-free strings (safe for logs/metrics labels)."""


class M:
    CONFIG = "invalid_configuration"
    PLAINTEXT_FORBIDDEN = "plaintext_forbidden"
    IDENTITY_UNAVAILABLE = "identity_unavailable"       # no valid own SVID (expired / SPIRE down)
    TRUST_UNAVAILABLE = "trust_bundle_unavailable"      # missing / stale / unknown-domain bundle
    HANDSHAKE = "tls_handshake_failed"
    HANDSHAKE_TIMEOUT = "tls_handshake_timeout"
    NO_PEER_CERT = "no_peer_certificate"
    PEER_CHAIN = "peer_chain_invalid"                   # untrusted / malformed / expired chain
    PEER_DOMAIN = "peer_trust_domain_not_accepted"
    PEER_NOT_ALLOWED = "peer_identity_not_allowed"      # authenticated, but not in trust policy
    PEER_MISMATCH = "peer_identity_mismatch"            # expected a specific service, got another
    PEER_PURPOSE = "peer_certificate_purpose"           # EKU does not permit this role
    PEER_REVOKED = "peer_revoked"
    PEER_INACTIVE = "peer_identity_not_active"          # agent identity suspended/revoked/unbound
    POLICY = "trust_policy_invalid"
    POLICY_SIGNATURE = "trust_policy_signature_invalid"
    POLICY_ROLLBACK = "trust_policy_rollback"
    POLICY_EXPIRED = "trust_policy_expired"
    KMS_UNAVAILABLE = "kms_unavailable"
    OVERLOAD = "connection_limit_reached"
    INTERNAL = "internal_error"


class MtlsError(Exception):
    reason = M.INTERNAL

    def __init__(self, message: str = "", reason: str = None):
        super().__init__(message or (reason or self.reason))
        if reason:
            self.reason = reason


class MtlsConfigError(MtlsError):
    reason = M.CONFIG


class PlaintextForbidden(MtlsConfigError):
    reason = M.PLAINTEXT_FORBIDDEN


class PeerRejected(MtlsError):
    """Peer authenticated cryptographically at most partially; connection MUST be closed."""
    reason = M.PEER_CHAIN
