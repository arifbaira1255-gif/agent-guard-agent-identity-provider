"""Phase 7 assurance-plane configuration.

Fail-closed, environment-driven, and deliberately constrained where a knob could weaken a control:

* ``audit_require_signature`` defaults to **True** -- an audit record that cannot be signed is
  refused rather than written unsigned (the caller may explicitly opt out for development).
* ``audit_fail_closed`` defaults to **True** -- when the audit store cannot be read/written, the
  protected operation is refused rather than admitted.
* ``proposal_require_approval`` defaults to **True** -- a recommendation never becomes active on the
  strength of the model's opinion alone.
* ``proposal_allow_auto_activate`` defaults to **False** -- even a low-impact change needs an
  explicit, authorized activation step.
* ``siem_require_tls`` defaults to **True** -- a plaintext transport is refused unless an operator
  explicitly acknowledges the risk in a non-production environment.
* ``siem_fail_closed`` defaults to **False** for *delivery* (a SIEM outage must not stop the
  security plane) but the delivery failure is always recorded and surfaced; the audit store itself
  is fail-closed.

Nothing here is a secret. Configuration is non-secret metadata only.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, replace

from ..core.errors import ValidationError

ENV_VAR = "AGENTGUARD_ENV"

#: Impact classes for a proposed policy change, weakest -> strongest.
IMPACT_LEVELS = ("low", "medium", "high", "critical")
#: Lifecycle states a proposal moves through.
PROPOSAL_STATES = ("draft", "validated", "simulated", "pending_approval", "approved", "canary",
                   "active", "rejected", "rolled_back", "expired")
#: Compliance frameworks the mapping framework knows about (mappings are configurable data).
KNOWN_FRAMEWORKS = ("soc2", "iso27001", "gdpr", "eu_ai_act")
#: SIEM transport kinds.
SIEM_TRANSPORTS = ("syslog_tls", "syslog_tcp", "http", "splunk_hec", "elastic_bulk", "webhook")


@dataclass(frozen=True)
class AssuranceConfig:
    environment: str = "development"

    # ---- self-healing policy intelligence ----------------------------------------------------
    #: Minimum number of corroborating signals before a recommendation is emitted at all.
    recommendation_min_signals: int = 2
    #: Observation window (seconds) over which signals are aggregated.
    recommendation_window_s: int = 604_800          # 7 days
    #: A single signal kind repeated at least this many times is treated as a pattern.
    recommendation_repeat_threshold: int = 3
    #: Hard cap on recommendations returned for one analysis run.
    recommendation_max: int = 100
    #: Hard cap on evidence references attached to one recommendation.
    recommendation_max_evidence: int = 50
    #: Confidence below which a recommendation is labelled ``insufficient_evidence`` and not emitted
    #: as an actionable proposal.
    recommendation_min_confidence: float = 0.35

    # ---- safe policy lifecycle ---------------------------------------------------------------
    #: A proposal must be approved before activation.
    proposal_require_approval: bool = True
    #: Even a low-impact change needs an explicit activation call (never auto-activated).
    proposal_allow_auto_activate: bool = False
    #: Impact at or above which a proposal requires a second, distinct approver (separation of duties).
    proposal_high_impact_requires_two_approvers: bool = True
    #: Impact at or above which a proposal is classified high-impact.
    proposal_high_impact_level: str = "high"
    #: Bounded number of pending proposals per tenant.
    proposal_max_pending: int = 200
    #: Proposal TTL (seconds) after which an unapproved proposal expires.
    proposal_ttl_s: int = 604_800
    #: Canary evaluation: fraction of traffic (0..1) a canary version serves before full activation.
    proposal_canary_fraction: float = 0.1
    #: Canary must observe at least this many evaluations before promotion is allowed.
    proposal_canary_min_samples: int = 20
    #: Canary is auto-rejected when the observed deny-rate delta exceeds this fraction.
    proposal_canary_max_deny_delta: float = 0.25

    # ---- tamper-evident audit ----------------------------------------------------------------
    #: Sign each audit record with the KMS/HSM key (in addition to hash chaining).
    audit_require_signature: bool = True
    #: Refuse a protected operation when the audit store cannot be written (fail closed).
    audit_fail_closed: bool = True
    #: Emit a signed checkpoint every N records (0 disables periodic checkpoints).
    audit_checkpoint_interval: int = 1_000
    #: Key id used for audit signing (resolved through the KMS layer; never a raw key).
    audit_signing_key_id: str = "audit_signing"
    #: Domain-separation label for audit signatures.
    audit_signature_domain: str = "agentguard:audit:v1"
    #: Bounded number of records verified in one verification pass.
    audit_verify_limit: int = 100_000
    #: Retention (days) for audit records; 0 = keep forever (append-only).
    audit_retention_days: int = 0

    # ---- compliance evidence -----------------------------------------------------------------
    #: Frameworks enabled for this deployment (subset of KNOWN_FRAMEWORKS).
    compliance_frameworks: tuple = ("soc2", "iso27001", "gdpr", "eu_ai_act")
    #: Evidence older than this (days) is flagged stale in a report.
    compliance_evidence_stale_days: int = 90
    #: Bounded number of evidence items per report.
    compliance_max_evidence: int = 5_000

    # ---- SIEM / security operations ----------------------------------------------------------
    #: Require TLS for every transport that supports it.
    siem_require_tls: bool = True
    #: Verify the server certificate (never disable in production).
    siem_verify_tls: bool = True
    #: Bounded delivery queue size (backpressure boundary).
    siem_queue_max: int = 10_000
    #: When the queue is full: ``reject`` (fail closed, surface backpressure) or ``drop_oldest``.
    siem_backpressure_policy: str = "reject"
    #: Bounded retry attempts per event.
    siem_max_retries: int = 5
    #: Initial retry backoff (seconds); exponential with jitter.
    siem_retry_backoff_s: float = 0.5
    #: Maximum retry backoff (seconds).
    siem_retry_backoff_max_s: float = 30.0
    #: Per-request timeout (seconds).
    siem_timeout_s: int = 10
    #: Max events per batch.
    siem_batch_max: int = 500
    #: Max events per second per destination (rate limit; 0 = unlimited).
    siem_rate_limit_per_s: int = 200
    #: A SIEM outage must not stop the security plane; delivery failures are recorded, not raised.
    siem_fail_closed: bool = False
    #: Data classifications that may be exported. Anything else is dropped before export.
    siem_allowed_classifications: tuple = ("public", "internal", "confidential")
    #: Field names that are ALWAYS redacted before export (defence in depth).
    siem_redact_fields: tuple = ("password", "secret", "token", "authorization", "api_key",
                                 "apikey", "private_key", "credential", "cookie", "session",
                                 "refresh_token", "access_token", "client_secret", "pin")

    # ---- correlation -------------------------------------------------------------------------
    #: Deduplication window (seconds) for identical events.
    correlation_dedup_window_s: int = 300
    #: Bounded number of correlated events retained per tenant.
    correlation_max_events: int = 200_000

    def __post_init__(self):
        if self.environment not in ("development", "staging", "production"):
            raise ValidationError("environment must be development|staging|production")
        for name in ("recommendation_min_signals", "recommendation_window_s",
                     "recommendation_repeat_threshold", "recommendation_max",
                     "recommendation_max_evidence", "proposal_max_pending", "proposal_ttl_s",
                     "proposal_canary_min_samples", "audit_checkpoint_interval",
                     "audit_verify_limit", "compliance_evidence_stale_days",
                     "compliance_max_evidence", "siem_queue_max", "siem_timeout_s",
                     "siem_batch_max", "correlation_dedup_window_s", "correlation_max_events"):
            if getattr(self, name) < 1:
                raise ValidationError(f"{name} must be >= 1")
        if self.siem_max_retries < 0:
            raise ValidationError("siem_max_retries must be >= 0")
        if self.audit_retention_days < 0:
            raise ValidationError("audit_retention_days must be >= 0")
        if not (0.0 <= self.recommendation_min_confidence <= 1.0):
            raise ValidationError("recommendation_min_confidence must be 0..1")
        if not (0.0 < self.proposal_canary_fraction < 1.0):
            raise ValidationError("proposal_canary_fraction must be in (0,1)")
        if not (0.0 <= self.proposal_canary_max_deny_delta <= 1.0):
            raise ValidationError("proposal_canary_max_deny_delta must be 0..1")
        if self.proposal_high_impact_level not in IMPACT_LEVELS:
            raise ValidationError("proposal_high_impact_level must be low|medium|high|critical")
        if self.siem_backpressure_policy not in ("reject", "drop_oldest"):
            raise ValidationError("siem_backpressure_policy must be reject|drop_oldest")
        for fw in self.compliance_frameworks:
            if fw not in KNOWN_FRAMEWORKS:
                raise ValidationError(f"unknown compliance framework: {fw}")
        if self.is_production:
            # A production deployment may not silently weaken these controls.
            if not self.audit_require_signature:
                raise ValidationError("audit_require_signature must be True in production")
            if not self.audit_fail_closed:
                raise ValidationError("audit_fail_closed must be True in production")
            if not self.siem_require_tls:
                raise ValidationError("siem_require_tls must be True in production")
            if not self.siem_verify_tls:
                raise ValidationError("siem_verify_tls must be True in production")
            if not self.proposal_require_approval:
                raise ValidationError("proposal_require_approval must be True in production")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def with_overrides(self, **kwargs) -> "AssuranceConfig":
        return replace(self, **kwargs)

    @classmethod
    def from_env(cls, **overrides) -> "AssuranceConfig":
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

        def csv(key, default):
            raw = e.get(key)
            if raw in (None, ""):
                return default
            return tuple(x.strip().lower() for x in raw.split(",") if x.strip())

        base = cls(
            environment=(e.get(ENV_VAR, "development").strip().lower() or "development"),
            recommendation_min_signals=num("AGENTGUARD_ASSURANCE_REC_MIN_SIGNALS", 2),
            recommendation_window_s=num("AGENTGUARD_ASSURANCE_REC_WINDOW_S", 604_800),
            recommendation_repeat_threshold=num("AGENTGUARD_ASSURANCE_REC_REPEAT_THRESHOLD", 3),
            recommendation_max=num("AGENTGUARD_ASSURANCE_REC_MAX", 100),
            recommendation_max_evidence=num("AGENTGUARD_ASSURANCE_REC_MAX_EVIDENCE", 50),
            recommendation_min_confidence=num("AGENTGUARD_ASSURANCE_REC_MIN_CONFIDENCE", 0.35, float),
            proposal_require_approval=boolean("AGENTGUARD_ASSURANCE_PROPOSAL_REQUIRE_APPROVAL", True),
            proposal_allow_auto_activate=boolean("AGENTGUARD_ASSURANCE_PROPOSAL_ALLOW_AUTO_ACTIVATE",
                                                 False),
            proposal_high_impact_requires_two_approvers=boolean(
                "AGENTGUARD_ASSURANCE_PROPOSAL_HIGH_IMPACT_TWO_APPROVERS", True),
            proposal_high_impact_level=(e.get("AGENTGUARD_ASSURANCE_PROPOSAL_HIGH_IMPACT_LEVEL",
                                              "high").strip().lower() or "high"),
            proposal_max_pending=num("AGENTGUARD_ASSURANCE_PROPOSAL_MAX_PENDING", 200),
            proposal_ttl_s=num("AGENTGUARD_ASSURANCE_PROPOSAL_TTL_S", 604_800),
            proposal_canary_fraction=num("AGENTGUARD_ASSURANCE_PROPOSAL_CANARY_FRACTION", 0.1, float),
            proposal_canary_min_samples=num("AGENTGUARD_ASSURANCE_PROPOSAL_CANARY_MIN_SAMPLES", 20),
            proposal_canary_max_deny_delta=num("AGENTGUARD_ASSURANCE_PROPOSAL_CANARY_MAX_DENY_DELTA",
                                               0.25, float),
            audit_require_signature=boolean("AGENTGUARD_ASSURANCE_AUDIT_REQUIRE_SIGNATURE", True),
            audit_fail_closed=boolean("AGENTGUARD_ASSURANCE_AUDIT_FAIL_CLOSED", True),
            audit_checkpoint_interval=num("AGENTGUARD_ASSURANCE_AUDIT_CHECKPOINT_INTERVAL", 1_000),
            audit_signing_key_id=(e.get("AGENTGUARD_ASSURANCE_AUDIT_SIGNING_KEY_ID",
                                        "audit_signing").strip() or "audit_signing"),
            audit_signature_domain=(e.get("AGENTGUARD_ASSURANCE_AUDIT_SIGNATURE_DOMAIN",
                                          "agentguard:audit:v1").strip() or "agentguard:audit:v1"),
            audit_verify_limit=num("AGENTGUARD_ASSURANCE_AUDIT_VERIFY_LIMIT", 100_000),
            audit_retention_days=num("AGENTGUARD_ASSURANCE_AUDIT_RETENTION_DAYS", 0),
            compliance_frameworks=csv("AGENTGUARD_ASSURANCE_COMPLIANCE_FRAMEWORKS",
                                      ("soc2", "iso27001", "gdpr", "eu_ai_act")),
            compliance_evidence_stale_days=num("AGENTGUARD_ASSURANCE_COMPLIANCE_STALE_DAYS", 90),
            compliance_max_evidence=num("AGENTGUARD_ASSURANCE_COMPLIANCE_MAX_EVIDENCE", 5_000),
            siem_require_tls=boolean("AGENTGUARD_ASSURANCE_SIEM_REQUIRE_TLS", True),
            siem_verify_tls=boolean("AGENTGUARD_ASSURANCE_SIEM_VERIFY_TLS", True),
            siem_queue_max=num("AGENTGUARD_ASSURANCE_SIEM_QUEUE_MAX", 10_000),
            siem_backpressure_policy=(e.get("AGENTGUARD_ASSURANCE_SIEM_BACKPRESSURE",
                                            "reject").strip().lower() or "reject"),
            siem_max_retries=num("AGENTGUARD_ASSURANCE_SIEM_MAX_RETRIES", 5),
            siem_retry_backoff_s=num("AGENTGUARD_ASSURANCE_SIEM_RETRY_BACKOFF_S", 0.5, float),
            siem_retry_backoff_max_s=num("AGENTGUARD_ASSURANCE_SIEM_RETRY_BACKOFF_MAX_S", 30.0, float),
            siem_timeout_s=num("AGENTGUARD_ASSURANCE_SIEM_TIMEOUT_S", 10),
            siem_batch_max=num("AGENTGUARD_ASSURANCE_SIEM_BATCH_MAX", 500),
            siem_rate_limit_per_s=num("AGENTGUARD_ASSURANCE_SIEM_RATE_LIMIT_PER_S", 200),
            siem_fail_closed=boolean("AGENTGUARD_ASSURANCE_SIEM_FAIL_CLOSED", False),
            siem_allowed_classifications=csv("AGENTGUARD_ASSURANCE_SIEM_ALLOWED_CLASSIFICATIONS",
                                             ("public", "internal", "confidential")),
            correlation_dedup_window_s=num("AGENTGUARD_ASSURANCE_CORRELATION_DEDUP_WINDOW_S", 300),
            correlation_max_events=num("AGENTGUARD_ASSURANCE_CORRELATION_MAX_EVENTS", 200_000),
        )
        return base.with_overrides(**overrides) if overrides else base
