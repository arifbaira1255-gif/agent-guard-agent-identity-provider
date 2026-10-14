"""Phase 4 egress/DLP configuration.

Fail-closed defaults. Nothing here is a secret; credentials for outbound calls are supplied by the
caller/connector, never stored in egress config.

The knobs that shape how the gateway treats a destination it cannot classify are constrained: there
is deliberately no "allow everything" option, so misconfiguration cannot open a hole.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, replace

from ..core.errors import ValidationError

ENV_VAR = "AGENTGUARD_ENV"


@dataclass(frozen=True)
class EgressConfig:
    environment: str = "development"

    # ---- default posture --------------------------------------------------------------------
    #: What to do when NO egress policy matches a destination. Constrained to deny|require_approval
    #: (there is deliberately no "allow" option).
    default_action: str = "deny"
    #: Whether the SSRF address floor is enforced. MUST stay True; retained for documentation.
    block_private_addresses: bool = True
    #: Whether a hostname that resolves to a blocked address class is denied (DNS validation).
    validate_dns: bool = True
    #: Whether a redirect to a different host/address is re-validated (and denied by default).
    revalidate_redirects: bool = True
    #: Whether redirects are followed at all by default (a policy may opt in per rule).
    allow_redirects_default: bool = False
    #: Maximum number of redirects to follow when a policy permits them.
    max_redirects: int = 3

    # ---- bounded limits (never unbounded) ---------------------------------------------------
    max_request_bytes: int = 1 * 1024 * 1024        # 1 MiB outbound body ceiling
    max_response_bytes: int = 4 * 1024 * 1024       # 4 MiB inbound body ceiling
    connect_timeout_ms: int = 2_000
    read_timeout_ms: int = 10_000
    max_concurrent_requests: int = 64               # bounded worker gate; excess fails closed

    # ---- default rate limits (per tenant and per agent) -------------------------------------
    default_rate_per_second: float = 20.0
    default_rate_burst: int = 40

    # ---- DLP --------------------------------------------------------------------------------
    dlp_enabled: bool = True
    #: What to do when DLP inspection cannot complete (oversized/undecodable). Constrained to
    #: block|require_approval (fail closed; never "allow").
    dlp_failure_action: str = "block"
    #: Maximum bytes of a payload that DLP will inspect. Larger payloads are handled per
    #: ``dlp_failure_action`` (never silently passed).
    dlp_max_inspect_bytes: int = 512 * 1024
    #: Maximum nesting depth DLP will walk in a structured payload.
    dlp_max_depth: int = 12
    #: Whether DLP also inspects base64/percent/hex-encoded substrings (decoded once).
    dlp_inspect_encoded: bool = True

    # ---- decision seal (anti-forgery, mirrors Step 11) --------------------------------------
    seal_ttl_s: int = 30
    seal_max_entries: int = 65536

    # ---- audit ------------------------------------------------------------------------------
    audit_enabled: bool = True

    def __post_init__(self):
        if self.environment not in ("development", "staging", "production"):
            raise ValidationError("environment must be development|staging|production")
        if self.default_action not in ("deny", "require_approval"):
            raise ValidationError("default_action must be 'deny' or 'require_approval' "
                                  "(there is no 'allow' option)")
        if self.dlp_failure_action not in ("block", "require_approval"):
            raise ValidationError("dlp_failure_action must be 'block' or 'require_approval'")
        if not self.block_private_addresses:
            raise ValidationError("block_private_addresses may not be disabled")
        if not (1 <= self.max_redirects <= 10):
            raise ValidationError("max_redirects must be 1..10")
        if not (1 <= self.max_concurrent_requests <= 4096):
            raise ValidationError("max_concurrent_requests must be 1..4096")
        if not (1 <= self.seal_ttl_s <= 3600):
            raise ValidationError("seal_ttl_s must be 1..3600")
        if self.max_request_bytes <= 0 or self.max_response_bytes <= 0:
            raise ValidationError("size limits must be positive")
        if self.dlp_max_inspect_bytes <= 0:
            raise ValidationError("dlp_max_inspect_bytes must be positive")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def with_overrides(self, **kwargs) -> "EgressConfig":
        return replace(self, **kwargs)

    @classmethod
    def from_env(cls, **overrides) -> "EgressConfig":
        e = os.environ

        def boolean(key, default):
            raw = e.get(key)
            if raw is None:
                return default
            return raw.strip().lower() in ("1", "true", "yes", "on")

        def num(key, default, cast=int):
            raw = e.get(key)
            if raw in (None, ""):
                return default
            try:
                return cast(raw)
            except ValueError:
                raise ValidationError(f"{key} must be a number")

        base = cls(
            environment=(e.get(ENV_VAR, "development").strip().lower() or "development"),
            default_action=(e.get("AGENTGUARD_EGRESS_DEFAULT_ACTION", "deny").strip().lower()
                            or "deny"),
            validate_dns=boolean("AGENTGUARD_EGRESS_VALIDATE_DNS", True),
            revalidate_redirects=boolean("AGENTGUARD_EGRESS_REVALIDATE_REDIRECTS", True),
            allow_redirects_default=boolean("AGENTGUARD_EGRESS_ALLOW_REDIRECTS", False),
            max_redirects=num("AGENTGUARD_EGRESS_MAX_REDIRECTS", 3),
            max_request_bytes=num("AGENTGUARD_EGRESS_MAX_REQUEST_BYTES", 1 * 1024 * 1024),
            max_response_bytes=num("AGENTGUARD_EGRESS_MAX_RESPONSE_BYTES", 4 * 1024 * 1024),
            connect_timeout_ms=num("AGENTGUARD_EGRESS_CONNECT_TIMEOUT_MS", 2_000),
            read_timeout_ms=num("AGENTGUARD_EGRESS_READ_TIMEOUT_MS", 10_000),
            max_concurrent_requests=num("AGENTGUARD_EGRESS_MAX_CONCURRENCY", 64),
            default_rate_per_second=num("AGENTGUARD_EGRESS_RATE_PER_SECOND", 20.0, float),
            default_rate_burst=num("AGENTGUARD_EGRESS_RATE_BURST", 40),
            dlp_enabled=boolean("AGENTGUARD_DLP_ENABLED", True),
            dlp_failure_action=(e.get("AGENTGUARD_DLP_FAILURE_ACTION", "block").strip().lower()
                                or "block"),
            dlp_max_inspect_bytes=num("AGENTGUARD_DLP_MAX_INSPECT_BYTES", 512 * 1024),
            dlp_max_depth=num("AGENTGUARD_DLP_MAX_DEPTH", 12),
            dlp_inspect_encoded=boolean("AGENTGUARD_DLP_INSPECT_ENCODED", True),
            seal_ttl_s=num("AGENTGUARD_EGRESS_SEAL_TTL_S", 30),
            audit_enabled=boolean("AGENTGUARD_EGRESS_AUDIT_ENABLED", True),
        )
        return base.with_overrides(**overrides) if overrides else base
