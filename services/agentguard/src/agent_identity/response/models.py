"""Phase 6 response-plane domain models.

ADDITIVE, immutable (or explicitly-mutable aggregate) records for the autonomous-response plane.
Nothing here holds secrets or payloads by construction:

* :class:`LoopFinding` is an observation about *observable repetition*, with an explicit
  ``classification`` that separates a normal retry from a suspicious repetition from a confirmed
  policy violation. It never claims to know why an agent repeated itself.
* :class:`ExecutionBudget` is a counter aggregate enforced at a server-side boundary.
* :class:`ApprovalRequest` carries a **fingerprint** of the exact operation it authorizes, so a
  modified request cannot reuse an approval granted for a different action.
* :class:`Incident` is a lifecycle record with a bounded timeline and evidence references.
* :class:`ResponseExecution` is the idempotent, auditable record of a containment plan.

Key vocabularies are closed enums so an unknown value is detectable and rejected rather than
silently defaulted -- the same discipline used by ``runtime_monitoring/models.py``.
"""
from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..core.models import iso  # reuse the existing ISO-8601 formatter
from ..runtime_monitoring.models import Severity  # reuse the Phase 5 severity vocabulary

# --------------------------------------------------------------------------- bounded field sizes
ID_MAX = 200
FIELD_MAX = 512          # max length of a free-text metadata field
DETAIL_MAX = 2000
EVIDENCE_MAX = 64        # bounded evidence reference list
TIMELINE_MAX = 500


# --------------------------------------------------------------------------- loop detection
class LoopPattern(str, enum.Enum):
    """The closed set of repetitive-activity patterns the detector understands."""

    REPEATED_ACTION = "repeated_action"            # same (action, resource) over and over
    CIRCULAR_INVOCATION = "circular_invocation"    # A -> B -> A cycle in the tool sequence
    EXCESSIVE_RETRY = "excessive_retry"            # the same action retried past the threshold
    REPEATED_DENIAL = "repeated_denial"            # authorization denied repeatedly
    EGRESS_REPETITION = "egress_repetition"        # repeated outbound requests to one destination
    CASCADE_FAILURE = "cascade_failure"            # failures spreading across dependent tools
    RESOURCE_BURN = "resource_burn"                # abnormal token/time/resource consumption

    @classmethod
    def coerce(cls, value) -> Optional["LoopPattern"]:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None


class LoopClassification(str, enum.Enum):
    """How strongly the available telemetry supports a runaway/loop claim.

    Ordered strongest -> weakest. Only ``CONFIRMED_VIOLATION`` means the observed repetition
    contradicts an authoritative source (a configured budget or an explicit policy limit).
    """

    CONFIRMED_VIOLATION = "confirmed_violation"     # contradicts a configured budget/policy limit
    SUSPICIOUS_REPETITION = "suspicious_repetition"  # repeated beyond a heuristic threshold
    NORMAL_RETRY = "normal_retry"                   # repetition consistent with ordinary retrying
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"  # not enough telemetry to say anything

    @classmethod
    def coerce(cls, value) -> "LoopClassification":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())


@dataclass(frozen=True)
class LoopFinding:
    """One detected repetitive-activity pattern, with the evidence that produced it."""

    finding_id: str
    org_id: str
    agent_id: Optional[str]
    ts: float
    pattern: str
    classification: str
    subject: str                       # the action/resource/destination that repeated
    observed_count: int
    threshold: int
    window_s: int
    severity: str = Severity.MEDIUM.value
    evidence: Tuple[str, ...] = ()
    detail: str = ""
    task_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id, "org_id": self.org_id, "agent_id": self.agent_id,
            "ts": iso(self.ts), "pattern": self.pattern, "classification": self.classification,
            "subject": self.subject, "observed_count": self.observed_count,
            "threshold": self.threshold, "window_s": self.window_s, "severity": self.severity,
            "evidence": list(self.evidence), "detail": self.detail, "task_id": self.task_id,
        }


# --------------------------------------------------------------------------- execution budgets
class BudgetScope(str, enum.Enum):
    AGENT = "agent"
    TASK = "task"

    @classmethod
    def coerce(cls, value) -> "BudgetScope":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())


@dataclass
class ExecutionBudget:
    """A server-side execution budget. Counters are consumed at the enforcement boundary.

    ``None`` on a limit means "not configured" (unlimited for that dimension) -- it is never
    silently treated as zero, which would deny all traffic.
    """

    budget_id: str
    org_id: str
    scope: str = BudgetScope.AGENT.value
    agent_id: Optional[str] = None
    task_id: Optional[str] = None
    max_actions: Optional[int] = None
    max_retries: Optional[int] = None
    max_requests: Optional[int] = None
    max_concurrency: Optional[int] = None
    max_tokens: Optional[int] = None
    max_cost: Optional[float] = None
    deadline_s: Optional[int] = None
    started_at: float = 0.0
    updated_at: float = 0.0
    actions_used: int = 0
    retries_used: int = 0
    requests_used: int = 0
    concurrency_used: int = 0
    tokens_used: int = 0
    cost_used: float = 0.0
    enabled: bool = True

    def public_dict(self) -> dict:
        return {
            "budget_id": self.budget_id, "org_id": self.org_id, "scope": self.scope,
            "agent_id": self.agent_id, "task_id": self.task_id,
            "limits": {"max_actions": self.max_actions, "max_retries": self.max_retries,
                       "max_requests": self.max_requests, "max_concurrency": self.max_concurrency,
                       "max_tokens": self.max_tokens, "max_cost": self.max_cost,
                       "deadline_s": self.deadline_s},
            "used": {"actions": self.actions_used, "retries": self.retries_used,
                     "requests": self.requests_used, "concurrency": self.concurrency_used,
                     "tokens": self.tokens_used, "cost": round(self.cost_used, 4)},
            "started_at": iso(self.started_at), "updated_at": iso(self.updated_at),
            "enabled": self.enabled,
        }


@dataclass(frozen=True)
class BudgetDecision:
    """The outcome of a budget check. ``allowed=False`` is an ENFORCEMENT result."""

    allowed: bool
    reason: str
    dimension: Optional[str] = None
    limit: Optional[float] = None
    used: Optional[float] = None
    budget_id: Optional[str] = None
    fail_closed: bool = False

    def to_dict(self) -> dict:
        return {"allowed": self.allowed, "reason": self.reason, "dimension": self.dimension,
                "limit": self.limit, "used": self.used, "budget_id": self.budget_id,
                "fail_closed": self.fail_closed}


@dataclass(frozen=True)
class EmergencyStop:
    """An emergency stop. Scoped to an agent or a task; always carries who requested it."""

    stop_id: str
    org_id: str
    agent_id: Optional[str]
    task_id: Optional[str]
    requested_by: str
    reason: str
    ts: float
    active: bool = True
    released_by: Optional[str] = None
    released_at: Optional[float] = None
    release_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {"stop_id": self.stop_id, "org_id": self.org_id, "agent_id": self.agent_id,
                "task_id": self.task_id, "requested_by": self.requested_by,
                "reason": self.reason, "ts": iso(self.ts), "active": self.active,
                "released_by": self.released_by,
                "released_at": iso(self.released_at) if self.released_at else None,
                "release_reason": self.release_reason}


# --------------------------------------------------------------------------- human approval
class ApprovalStatus(str, enum.Enum):
    """A CLOSED approval vocabulary: an unknown value raises rather than silently defaulting."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"

    @classmethod
    def coerce(cls, value) -> "ApprovalStatus":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())


#: Statuses an approval may still transition out of.
APPROVAL_TERMINAL_STATES = frozenset({ApprovalStatus.DENIED, ApprovalStatus.EXPIRED,
                                      ApprovalStatus.CANCELLED})


def operation_fingerprint(*, org_id: str, agent_id: Optional[str], action: str, resource: str,
                          params: Optional[dict] = None) -> str:
    """A stable digest binding an approval to the EXACT operation it authorizes.

    Canonical JSON (sorted keys, no whitespace) over the tenant, agent, action, resource and the
    operation parameters. Any change to any of those -- including a reordered or altered parameter
    set -- produces a different fingerprint, so a modified request cannot reuse an approval.
    """
    payload = {"org_id": org_id, "agent_id": agent_id, "action": action, "resource": resource,
               "params": _canonical(params or {})}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _canonical(value):
    """Recursively normalize a parameter bag so the fingerprint is order-independent."""
    if isinstance(value, dict):
        return {str(k): _canonical(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


@dataclass
class ApprovalRequest:
    """A human-approval request bound to one exact operation via ``fingerprint``."""

    approval_id: str
    org_id: str
    agent_id: Optional[str]
    action: str
    resource: str
    fingerprint: str
    status: str = ApprovalStatus.PENDING.value
    requested_at: float = 0.0
    expires_at: float = 0.0
    requested_by: str = ""
    reason: str = ""
    risk_score: Optional[float] = None
    risk_band: Optional[str] = None
    risk_evidence: Tuple[str, ...] = ()
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    incident_id: Optional[str] = None
    decided_at: Optional[float] = None
    decided_by: Optional[str] = None
    decision_reason: str = ""
    delegated_to: Optional[str] = None
    params: Dict[str, object] = field(default_factory=dict)

    def is_expired_at(self, now: float) -> bool:
        """Whether this PENDING approval has passed its expiry at ``now``.

        Takes an explicit clock rather than reading the wall clock, so expiry is deterministic in
        tests and consistent with the service's injected clock.
        """
        return (self.status == ApprovalStatus.PENDING.value and self.expires_at > 0
                and now >= self.expires_at)

    def public_dict(self) -> dict:
        return {
            "approval_id": self.approval_id, "org_id": self.org_id, "agent_id": self.agent_id,
            "action": self.action, "resource": self.resource, "fingerprint": self.fingerprint,
            "status": self.status, "requested_at": iso(self.requested_at),
            "expires_at": iso(self.expires_at), "requested_by": self.requested_by,
            "reason": self.reason, "risk_score": self.risk_score, "risk_band": self.risk_band,
            "risk_evidence": list(self.risk_evidence), "policy_id": self.policy_id,
            "policy_version": self.policy_version, "incident_id": self.incident_id,
            "decided_at": iso(self.decided_at) if self.decided_at else None,
            "decided_by": self.decided_by, "decision_reason": self.decision_reason,
            "delegated_to": self.delegated_to, "params": dict(self.params),
        }


# --------------------------------------------------------------------------- incidents
class IncidentStatus(str, enum.Enum):
    """The incident lifecycle. A CLOSED vocabulary with validated transitions."""

    DETECTED = "detected"
    TRIAGE = "triage"
    INVESTIGATING = "investigating"
    CONTAINMENT = "containment"
    RECOVERY = "recovery"
    CLOSED = "closed"
    POST_REVIEW = "post_review"

    @classmethod
    def coerce(cls, value) -> "IncidentStatus":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())


INCIDENT_TERMINAL_STATES = frozenset({IncidentStatus.CLOSED, IncidentStatus.POST_REVIEW})

INCIDENT_STATE_TRANSITIONS: Dict[IncidentStatus, frozenset] = {
    IncidentStatus.DETECTED: frozenset({IncidentStatus.TRIAGE, IncidentStatus.INVESTIGATING,
                                        IncidentStatus.CLOSED}),
    IncidentStatus.TRIAGE: frozenset({IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINMENT,
                                      IncidentStatus.CLOSED}),
    IncidentStatus.INVESTIGATING: frozenset({IncidentStatus.CONTAINMENT, IncidentStatus.RECOVERY,
                                             IncidentStatus.CLOSED}),
    IncidentStatus.CONTAINMENT: frozenset({IncidentStatus.RECOVERY, IncidentStatus.INVESTIGATING,
                                           IncidentStatus.CLOSED}),
    IncidentStatus.RECOVERY: frozenset({IncidentStatus.CLOSED, IncidentStatus.CONTAINMENT}),
    IncidentStatus.CLOSED: frozenset({IncidentStatus.POST_REVIEW}),
    IncidentStatus.POST_REVIEW: frozenset(),
}


@dataclass(frozen=True)
class IncidentTimelineEntry:
    ts: float
    kind: str
    detail: str
    actor: Optional[str] = None
    ref: Optional[str] = None

    def to_dict(self) -> dict:
        # ``ts`` is stored as the raw epoch float (not ISO) so the PostgreSQL JSONB round-trip is
        # lossless: the reader parses it straight back into a float. Formatting it as ISO here made
        # the reader raise on reload -- a real round-trip bug caught by the PG integration test.
        return {"ts": self.ts, "kind": self.kind, "detail": self.detail,
                "actor": self.actor, "ref": self.ref}


@dataclass
class Incident:
    """A structured security incident with a bounded timeline and evidence references."""

    incident_id: str
    org_id: str
    title: str
    severity: str = Severity.MEDIUM.value
    status: str = IncidentStatus.DETECTED.value
    opened_at: float = 0.0
    updated_at: float = 0.0
    closed_at: Optional[float] = None
    owner: Optional[str] = None
    agent_ids: Tuple[str, ...] = ()
    resources: Tuple[str, ...] = ()
    alert_ids: Tuple[str, ...] = ()
    finding_ids: Tuple[str, ...] = ()
    evidence_ids: Tuple[str, ...] = ()
    response_ids: Tuple[str, ...] = ()
    timeline: List[IncidentTimelineEntry] = field(default_factory=list)
    detection_source: str = ""
    risk_score: Optional[float] = None
    risk_band: Optional[str] = None
    resolution: str = ""
    post_review: str = ""
    correlation_key: str = ""

    def public_dict(self) -> dict:
        return {
            "incident_id": self.incident_id, "org_id": self.org_id, "title": self.title,
            "severity": self.severity, "status": self.status, "opened_at": iso(self.opened_at),
            "updated_at": iso(self.updated_at),
            "closed_at": iso(self.closed_at) if self.closed_at else None, "owner": self.owner,
            "agent_ids": list(self.agent_ids), "resources": list(self.resources),
            "alert_ids": list(self.alert_ids), "finding_ids": list(self.finding_ids),
            "evidence_ids": list(self.evidence_ids), "response_ids": list(self.response_ids),
            "timeline": [t.to_dict() for t in self.timeline],
            "detection_source": self.detection_source, "risk_score": self.risk_score,
            "risk_band": self.risk_band, "resolution": self.resolution,
            "post_review": self.post_review, "correlation_key": self.correlation_key,
        }


# --------------------------------------------------------------------------- containment
class ContainmentAction(str, enum.Enum):
    """Defensive actions the containment engine can execute.

    Every one of these DELEGATES to an existing enforcement mechanism (policy engine, JIT grant
    service, identity/credential plane, egress gateway, governance registry, budget boundary). The
    response plane never creates a competing authorization path.
    """

    DENY_PROTECTED_OPERATIONS = "deny_protected_operations"   # policy: deny new protected ops
    SUSPEND_AGENT = "suspend_agent"                           # identity: suspend the agent
    REVOKE_JIT_GRANTS = "revoke_jit_grants"                   # policy/JIT: revoke live grants
    REVOKE_CREDENTIALS = "revoke_credentials"                 # identity: revoke credentials
    ROTATE_CREDENTIALS = "rotate_credentials"                 # identity: rotate credentials
    BLOCK_DESTINATION = "block_destination"                   # egress: block an outbound destination
    DISABLE_TOOL = "disable_tool"                             # governance: disable a tool integration
    LIMIT_BUDGET = "limit_budget"                             # budget: tighten execution budgets
    REQUIRE_APPROVAL = "require_approval"                     # policy: require human approval
    ISOLATE_WORKLOAD = "isolate_workload"                     # deployment: isolate a workload

    @classmethod
    def coerce(cls, value) -> Optional["ContainmentAction"]:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None


#: Actions whose blast radius is disruptive enough to require explicit configuration and, by default,
#: a human decision. ``reversible`` records whether an audited rollback exists for the action.
CONTAINMENT_ACTION_SPECS: Dict[ContainmentAction, dict] = {
    ContainmentAction.DENY_PROTECTED_OPERATIONS: {"impact": "medium", "reversible": True},
    ContainmentAction.SUSPEND_AGENT: {"impact": "high", "reversible": True},
    ContainmentAction.REVOKE_JIT_GRANTS: {"impact": "medium", "reversible": False},
    ContainmentAction.REVOKE_CREDENTIALS: {"impact": "high", "reversible": False},
    ContainmentAction.ROTATE_CREDENTIALS: {"impact": "high", "reversible": False},
    ContainmentAction.BLOCK_DESTINATION: {"impact": "medium", "reversible": True},
    ContainmentAction.DISABLE_TOOL: {"impact": "high", "reversible": True},
    ContainmentAction.LIMIT_BUDGET: {"impact": "low", "reversible": True},
    ContainmentAction.REQUIRE_APPROVAL: {"impact": "low", "reversible": True},
    ContainmentAction.ISOLATE_WORKLOAD: {"impact": "high", "reversible": True},
}


class ResponseState(str, enum.Enum):
    """The response-execution state machine. A CLOSED vocabulary with validated transitions."""

    PLANNED = "planned"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"          # some steps failed: recorded honestly, never reported as success
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"

    @classmethod
    def coerce(cls, value) -> "ResponseState":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())


RESPONSE_TERMINAL_STATES = frozenset({ResponseState.SUCCEEDED, ResponseState.PARTIAL,
                                      ResponseState.FAILED, ResponseState.ROLLED_BACK,
                                      ResponseState.ROLLBACK_FAILED})

RESPONSE_STATE_TRANSITIONS: Dict[ResponseState, frozenset] = {
    # PLANNED -> SUCCEEDED covers the observe-only path (no containment action is a valid terminal
    # outcome); a non-observe plan must still pass through RUNNING.
    ResponseState.PLANNED: frozenset({ResponseState.RUNNING, ResponseState.SUCCEEDED,
                                      ResponseState.FAILED}),
    ResponseState.RUNNING: frozenset({ResponseState.SUCCEEDED, ResponseState.PARTIAL,
                                      ResponseState.FAILED}),
    ResponseState.SUCCEEDED: frozenset({ResponseState.ROLLED_BACK, ResponseState.ROLLBACK_FAILED}),
    ResponseState.PARTIAL: frozenset({ResponseState.ROLLED_BACK, ResponseState.ROLLBACK_FAILED}),
    ResponseState.FAILED: frozenset({ResponseState.ROLLED_BACK, ResponseState.ROLLBACK_FAILED}),
    ResponseState.ROLLED_BACK: frozenset(),
    ResponseState.ROLLBACK_FAILED: frozenset(),
}


@dataclass(frozen=True)
class ResponseStep:
    """One executed containment step, with its honest outcome."""

    action: str
    status: str                       # ok | unavailable | failed | skipped | rolled_back
    mechanism: str = ""
    detail: str = ""
    attempts: int = 1
    reversible: bool = False
    result: Optional[dict] = None

    def to_dict(self) -> dict:
        return {"action": self.action, "status": self.status, "mechanism": self.mechanism,
                "detail": self.detail, "attempts": self.attempts, "reversible": self.reversible,
                "result": self.result}


@dataclass
class ResponseExecution:
    """An idempotent, auditable containment execution.

    ``idempotency_key`` is derived from the incident + plan so a duplicate delivery of the same
    trigger cannot execute containment twice.
    """

    response_id: str
    org_id: str
    idempotency_key: str
    incident_id: Optional[str] = None
    agent_id: Optional[str] = None
    task_id: Optional[str] = None
    state: str = ResponseState.PLANNED.value
    trigger: str = ""
    requested_by: str = ""
    approved_by: Optional[str] = None
    approval_id: Optional[str] = None
    created_at: float = 0.0
    updated_at: float = 0.0
    steps: List[ResponseStep] = field(default_factory=list)
    rollback_steps: List[ResponseStep] = field(default_factory=list)
    partial_failures: Tuple[str, ...] = ()
    evidence_ids: Tuple[str, ...] = ()
    note: str = ""

    def public_dict(self) -> dict:
        return {
            "response_id": self.response_id, "org_id": self.org_id,
            "idempotency_key": self.idempotency_key, "incident_id": self.incident_id,
            "agent_id": self.agent_id, "task_id": self.task_id, "state": self.state,
            "trigger": self.trigger, "requested_by": self.requested_by,
            "approved_by": self.approved_by, "approval_id": self.approval_id,
            "created_at": iso(self.created_at), "updated_at": iso(self.updated_at),
            "steps": [s.to_dict() for s in self.steps],
            "rollback_steps": [s.to_dict() for s in self.rollback_steps],
            "partial_failures": list(self.partial_failures),
            "evidence_ids": list(self.evidence_ids), "note": self.note,
        }


# --------------------------------------------------------------------------- evidence
@dataclass(frozen=True)
class EvidenceRecord:
    """A preserved evidence item. Holds REFERENCES and digests, never raw sensitive payloads."""

    evidence_id: str
    org_id: str
    kind: str
    ts: float
    summary: str
    ref: Optional[str] = None
    digest: Optional[str] = None
    incident_id: Optional[str] = None
    agent_id: Optional[str] = None
    source: str = ""
    retention_until: Optional[float] = None
    sealed: bool = False

    def to_dict(self) -> dict:
        return {"evidence_id": self.evidence_id, "org_id": self.org_id, "kind": self.kind,
                "ts": iso(self.ts), "summary": self.summary, "ref": self.ref,
                "digest": self.digest, "incident_id": self.incident_id,
                "agent_id": self.agent_id, "source": self.source,
                "retention_until": iso(self.retention_until) if self.retention_until else None,
                "sealed": self.sealed}


# --------------------------------------------------------------------------- response levels
class ResponseLevel(str, enum.Enum):
    """Configurable response levels, weakest -> strongest.

    A statistical anomaly must NOT automatically trigger the most disruptive level; the level is a
    policy decision derived from the evidence class and the configured thresholds.
    """

    OBSERVE = "observe"
    REQUIRE_APPROVAL = "require_approval"
    RESTRICT = "restrict"
    SUSPEND = "suspend"
    INCIDENT = "incident"

    @classmethod
    def coerce(cls, value) -> "ResponseLevel":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())

    @property
    def rank(self) -> int:
        return _LEVEL_RANK[self]


_LEVEL_RANK = {ResponseLevel.OBSERVE: 0, ResponseLevel.REQUIRE_APPROVAL: 1,
               ResponseLevel.RESTRICT: 2, ResponseLevel.SUSPEND: 3, ResponseLevel.INCIDENT: 4}

#: The containment actions each response level authorizes, weakest first.
RESPONSE_LEVEL_ACTIONS: Dict[ResponseLevel, Tuple[ContainmentAction, ...]] = {
    ResponseLevel.OBSERVE: (),
    ResponseLevel.REQUIRE_APPROVAL: (ContainmentAction.REQUIRE_APPROVAL,),
    ResponseLevel.RESTRICT: (ContainmentAction.REQUIRE_APPROVAL,
                             ContainmentAction.DENY_PROTECTED_OPERATIONS,
                             ContainmentAction.LIMIT_BUDGET),
    ResponseLevel.SUSPEND: (ContainmentAction.REQUIRE_APPROVAL,
                            ContainmentAction.DENY_PROTECTED_OPERATIONS,
                            ContainmentAction.LIMIT_BUDGET,
                            ContainmentAction.REVOKE_JIT_GRANTS,
                            ContainmentAction.SUSPEND_AGENT),
    ResponseLevel.INCIDENT: tuple(ContainmentAction),
}
