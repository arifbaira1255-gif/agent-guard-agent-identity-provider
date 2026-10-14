"""Phase 6 response-plane configuration.

Fail-closed defaults, environment-driven, and deliberately constrained where a knob could weaken a
security control:

* ``containment_allow_auto`` defaults to **False** -- automated containment is opt-in per deployment.
* ``containment_high_impact_requires_approval`` defaults to **True** -- a disruptive action needs a
  human decision unless an operator explicitly turns that off.
* ``approval_require_separation_of_duties`` defaults to **True** -- the requester cannot approve.
* ``budget_fail_closed`` defaults to **True** -- when the budget store cannot be read, protected
  operations are refused rather than admitted.

Nothing here is a secret. Configuration is non-secret metadata only.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, replace

from ..core.errors import ValidationError

ENV_VAR = "AGENTGUARD_ENV"

#: Response levels, weakest -> strongest. Ordered so a policy can pick a floor.
RESPONSE_LEVELS = ("observe", "require_approval", "restrict", "suspend", "incident")


@dataclass(frozen=True)
class ResponseConfig:
    environment: str = "development"

    # ---- loop / runaway detection ------------------------------------------------------------
    #: Observation window (seconds) over which repetition is measured.
    loop_window_s: int = 300
    #: Minimum repeats of the same (action, resource) inside the window to be "repeated".
    loop_min_repeats: int = 5
    #: Minimum cycle length for a circular-invocation pattern (A->B->A is length 2).
    loop_circular_min_cycle: int = 2
    #: Retries of the same action inside the window that count as excessive.
    loop_retry_threshold: int = 5
    #: Authorization denials inside the window that count as repeated denial.
    loop_denial_threshold: int = 5
    #: Outbound requests to the SAME destination inside the window.
    loop_egress_threshold: int = 10
    #: Distinct failing tools inside the window that indicate a cascade.
    loop_cascade_threshold: int = 3
    #: Hard cap on observations retained per (org, agent) so a runaway agent cannot exhaust memory.
    loop_max_observations: int = 5_000
    #: Hard cap on the number of findings returned for one evaluation.
    loop_max_findings: int = 50

    # ---- execution budgets -------------------------------------------------------------------
    budget_default_max_actions: int = 1_000
    budget_default_max_retries: int = 50
    budget_default_deadline_s: int = 3_600
    budget_default_max_requests: int = 500
    budget_default_max_concurrency: int = 8
    budget_default_max_tokens: int = 2_000_000
    budget_default_max_cost: float = 100.0
    #: When the budget store cannot be read, refuse protected operations (fail closed).
    budget_fail_closed: bool = True

    # ---- human approval ----------------------------------------------------------------------
    approval_ttl_s: int = 900
    #: The requester may not approve their own request.
    approval_require_separation_of_duties: bool = True
    #: Bounded number of PENDING approvals per agent (resource-exhaustion guard).
    approval_max_pending_per_agent: int = 50
    #: Risk band at or above which an operation requires human approval.
    approval_risk_band: str = "high"

    # ---- incidents ---------------------------------------------------------------------------
    #: Alerts/findings within this window may be correlated into one incident.
    incident_correlation_window_s: int = 900
    #: Bounded number of concurrently open incidents per tenant.
    incident_max_open: int = 500
    #: Bounded timeline length per incident.
    incident_max_timeline: int = 500

    # ---- containment -------------------------------------------------------------------------
    #: Whether automated containment may run at all. Default False: opt-in per deployment.
    containment_allow_auto: bool = False
    #: High-impact actions require an approved human decision even when auto containment is on.
    containment_high_impact_requires_approval: bool = True
    #: Per-action timeout (seconds) for a delegated enforcement call.
    containment_action_timeout_s: int = 30
    #: Bounded retries for a delegated enforcement call.
    containment_max_retries: int = 2
    #: Bounded number of steps in one response plan.
    response_max_actions_per_plan: int = 12

    # ---- evidence / audit --------------------------------------------------------------------
    evidence_retention_days: int = 365
    audit_enabled: bool = True

    # ---- response levels (risk -> level) -----------------------------------------------------
    #: Risk band at or above which the agent's operations are restricted.
    restrict_risk_band: str = "high"
    #: Risk band at or above which the agent is suspended.
    suspend_risk_band: str = "critical"

    def __post_init__(self):
        if self.environment not in ("development", "staging", "production"):
            raise ValidationError("environment must be development|staging|production")
        for name in ("loop_window_s", "loop_min_repeats", "loop_circular_min_cycle",
                     "loop_retry_threshold", "loop_denial_threshold", "loop_egress_threshold",
                     "loop_cascade_threshold", "loop_max_observations", "loop_max_findings",
                     "budget_default_max_actions", "budget_default_max_retries",
                     "budget_default_deadline_s", "budget_default_max_requests",
                     "budget_default_max_concurrency", "budget_default_max_tokens",
                     "approval_ttl_s", "approval_max_pending_per_agent",
                     "incident_correlation_window_s", "incident_max_open", "incident_max_timeline",
                     "containment_action_timeout_s", "response_max_actions_per_plan",
                     "evidence_retention_days"):
            if getattr(self, name) < 1:
                raise ValidationError(f"{name} must be >= 1")
        if self.containment_max_retries < 0:
            raise ValidationError("containment_max_retries must be >= 0")
        if self.budget_default_max_cost <= 0:
            raise ValidationError("budget_default_max_cost must be > 0")
        for name in ("approval_risk_band", "restrict_risk_band", "suspend_risk_band"):
            if getattr(self, name) not in ("low", "medium", "high", "critical"):
                raise ValidationError(f"{name} must be low|medium|high|critical")
        if not (1 <= self.evidence_retention_days <= 3650):
            raise ValidationError("evidence_retention_days must be 1..3650")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def with_overrides(self, **kwargs) -> "ResponseConfig":
        return replace(self, **kwargs)

    @classmethod
    def from_env(cls, **overrides) -> "ResponseConfig":
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
            loop_window_s=num("AGENTGUARD_RESPONSE_LOOP_WINDOW_S", 300),
            loop_min_repeats=num("AGENTGUARD_RESPONSE_LOOP_MIN_REPEATS", 5),
            loop_circular_min_cycle=num("AGENTGUARD_RESPONSE_LOOP_CIRCULAR_MIN_CYCLE", 2),
            loop_retry_threshold=num("AGENTGUARD_RESPONSE_LOOP_RETRY_THRESHOLD", 5),
            loop_denial_threshold=num("AGENTGUARD_RESPONSE_LOOP_DENIAL_THRESHOLD", 5),
            loop_egress_threshold=num("AGENTGUARD_RESPONSE_LOOP_EGRESS_THRESHOLD", 10),
            loop_cascade_threshold=num("AGENTGUARD_RESPONSE_LOOP_CASCADE_THRESHOLD", 3),
            loop_max_observations=num("AGENTGUARD_RESPONSE_LOOP_MAX_OBSERVATIONS", 5_000),
            loop_max_findings=num("AGENTGUARD_RESPONSE_LOOP_MAX_FINDINGS", 50),
            budget_default_max_actions=num("AGENTGUARD_RESPONSE_BUDGET_MAX_ACTIONS", 1_000),
            budget_default_max_retries=num("AGENTGUARD_RESPONSE_BUDGET_MAX_RETRIES", 50),
            budget_default_deadline_s=num("AGENTGUARD_RESPONSE_BUDGET_DEADLINE_S", 3_600),
            budget_default_max_requests=num("AGENTGUARD_RESPONSE_BUDGET_MAX_REQUESTS", 500),
            budget_default_max_concurrency=num("AGENTGUARD_RESPONSE_BUDGET_MAX_CONCURRENCY", 8),
            budget_default_max_tokens=num("AGENTGUARD_RESPONSE_BUDGET_MAX_TOKENS", 2_000_000),
            budget_default_max_cost=num("AGENTGUARD_RESPONSE_BUDGET_MAX_COST", 100.0, float),
            budget_fail_closed=boolean("AGENTGUARD_RESPONSE_BUDGET_FAIL_CLOSED", True),
            approval_ttl_s=num("AGENTGUARD_RESPONSE_APPROVAL_TTL_S", 900),
            approval_require_separation_of_duties=boolean(
                "AGENTGUARD_RESPONSE_APPROVAL_SOD", True),
            approval_max_pending_per_agent=num("AGENTGUARD_RESPONSE_APPROVAL_MAX_PENDING", 50),
            approval_risk_band=(e.get("AGENTGUARD_RESPONSE_APPROVAL_RISK_BAND", "high").strip()
                                .lower() or "high"),
            incident_correlation_window_s=num("AGENTGUARD_RESPONSE_INCIDENT_WINDOW_S", 900),
            incident_max_open=num("AGENTGUARD_RESPONSE_INCIDENT_MAX_OPEN", 500),
            incident_max_timeline=num("AGENTGUARD_RESPONSE_INCIDENT_MAX_TIMELINE", 500),
            containment_allow_auto=boolean("AGENTGUARD_RESPONSE_CONTAINMENT_ALLOW_AUTO", False),
            containment_high_impact_requires_approval=boolean(
                "AGENTGUARD_RESPONSE_CONTAINMENT_HIGH_IMPACT_APPROVAL", True),
            containment_action_timeout_s=num("AGENTGUARD_RESPONSE_CONTAINMENT_TIMEOUT_S", 30),
            containment_max_retries=num("AGENTGUARD_RESPONSE_CONTAINMENT_MAX_RETRIES", 2),
            response_max_actions_per_plan=num("AGENTGUARD_RESPONSE_MAX_ACTIONS_PER_PLAN", 12),
            evidence_retention_days=num("AGENTGUARD_RESPONSE_EVIDENCE_RETENTION_DAYS", 365),
            audit_enabled=boolean("AGENTGUARD_RESPONSE_AUDIT_ENABLED", True),
            restrict_risk_band=(e.get("AGENTGUARD_RESPONSE_RESTRICT_RISK_BAND", "high").strip()
                                .lower() or "high"),
            suspend_risk_band=(e.get("AGENTGUARD_RESPONSE_SUSPEND_RISK_BAND", "critical").strip()
                               .lower() or "critical"),
        )
        return base.with_overrides(**overrides) if overrides else base
