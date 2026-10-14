"""Phase 5 runtime-monitoring domain models.

ADDITIVE, immutable (or explicitly-mutable aggregate) records for the runtime-observability plane.
Nothing here holds secrets or payloads by construction:

* :class:`RuntimeEvent` is a **normalized metadata record** -- ids, an event type, a decision, reason
  codes, resource/destination identifiers, a severity, a correlation/trace context and a bounded
  primitive-only ``extra`` bag. It never carries a prompt, a request body, a credential or a DLP
  match's content (see ``redaction.py``, which enforces this at the pipeline boundary).
* :class:`BehaviorProfile` is an aggregate of counts -- it summarizes observable activity and holds
  no raw event content.
* :class:`DriftFinding` distinguishes what the telemetry can actually establish
  (``corroboration``), and never claims to know an agent's internal intent.
* :class:`RiskAssessment` is an explainable heuristic score with its contributing signals; it is
  explicitly NOT an enforcement decision (the Step 10 policy engine stays authoritative).

Key vocabularies are closed enums so an unknown value is detectable and rejected rather than
silently defaulted -- the same discipline used by ``egress/models.py``.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from ..core.models import iso  # reuse the existing ISO-8601 formatter

# --------------------------------------------------------------------------- bounded field sizes
ID_MAX = 200
FIELD_MAX = 512          # max length of a free-text metadata field
EXTRA_MAX_KEYS = 24      # bounded primitive bag
EXTRA_MAX_DEPTH = 4


# --------------------------------------------------------------------------- vocabularies
class EventType(str, enum.Enum):
    """The closed set of normalized runtime event types Phase 5 understands.

    Anything outside this set is REJECTED at the pipeline boundary (``EventValidationError``) so a
    new producer cannot create un-normalized telemetry by accident.
    """

    # -- identity / lifecycle
    AGENT_INITIALIZED = "agent.initialized"
    AGENT_IDENTITY_CHANGED = "agent.identity.changed"
    AGENT_TERMINATED = "agent.terminated"
    # -- invocation
    TOOL_INVOCATION = "tool.invocation"
    API_INVOCATION = "api.invocation"
    # -- authorization
    AUTHORIZATION_DECISION = "authorization.decision"
    AUTHORIZATION_FAILURE = "authorization.failure"
    # -- just-in-time privilege
    JIT_GRANT_CREATED = "jit.grant.created"
    JIT_GRANT_EXPIRED = "jit.grant.expired"
    JIT_GRANT_REVOKED = "jit.grant.revoked"
    # -- data / file access
    DATA_ACCESS = "data.access"
    FILE_ACCESS = "file.access"
    # -- network egress
    NETWORK_REQUEST = "network.request"
    # -- DLP
    DLP_DETECTION = "dlp.detection"
    DLP_BLOCKED = "dlp.blocked"
    # -- human approval
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_DECIDED = "approval.decided"
    # -- policy
    POLICY_CHANGED = "policy.changed"
    POLICY_ENFORCEMENT_FAILURE = "policy.enforcement.failure"
    # -- agent health
    AGENT_ERROR = "agent.error"
    AGENT_RETRY = "agent.retry"
    # -- derived (produced by the pipeline, never ingested raw)
    ACTION_SEQUENCE = "action.sequence"

    @classmethod
    def coerce(cls, value) -> Optional["EventType"]:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None


#: Event types the pipeline derives itself; a producer may not inject them.
DERIVED_EVENT_TYPES = frozenset({EventType.ACTION_SEQUENCE})


class Decision(str, enum.Enum):
    """A closed decision vocabulary spanning authorization, DLP, approval and liveness."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    INDETERMINATE = "INDETERMINATE"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    APPROVED = "APPROVED"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def coerce(cls, value) -> "Decision":
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return cls.UNKNOWN
        try:
            return cls(value.strip().upper())
        except ValueError:
            return cls.UNKNOWN


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def coerce(cls, value) -> "Severity":
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return cls.INFO
        try:
            return cls(value.strip().lower())
        except ValueError:
            return cls.INFO

    @property
    def rank(self) -> int:
        return _SEV_RANK[self]


_SEV_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3,
             Severity.CRITICAL: 4}


class DriftClass(str, enum.Enum):
    """How strongly the available telemetry supports a drift claim.

    Ordered strongest -> weakest. The distinction is the whole point: only
    ``CONFIRMED_VIOLATION`` means the observed activity contradicts an authoritative source.
    """

    CONFIRMED_VIOLATION = "confirmed_violation"     # contradicts authoritative config (capabilities, policy)
    STATISTICAL_ANOMALY = "statistical_anomaly"     # deviates from a MATURE baseline beyond threshold
    HEURISTIC_SUSPICION = "heuristic_suspicion"     # matches a heuristic; no authoritative contradiction
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"  # not enough telemetry to say anything

    @classmethod
    def coerce(cls, value) -> "DriftClass":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())


class Corroboration(str, enum.Enum):
    """What established the expected value in a drift comparison."""

    AUTHORITATIVE = "authoritative"   # a capability set / policy the agent must obey
    BASELINE = "baseline"             # the agent's own learned profile (mature)
    HEURISTIC = "heuristic"           # a pattern rule, no authoritative source
    NONE = "none"                     # nothing to compare against

    @classmethod
    def coerce(cls, value) -> "Corroboration":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())


class AlertState(str, enum.Enum):
    """Alert lifecycle states. A CLOSED vocabulary: an unknown value raises rather than silently
    defaulting, because a silently-coerced state would hide data corruption from an investigator."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"

    @classmethod
    def coerce(cls, value) -> "AlertState":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())


#: Lifecycle states an alert may still transition out of.
ALERT_TERMINAL_STATES = frozenset({AlertState.RESOLVED, AlertState.SUPPRESSED})
ALERT_STATE_TRANSITIONS: Dict[AlertState, frozenset] = {
    AlertState.OPEN: frozenset({AlertState.ACKNOWLEDGED, AlertState.INVESTIGATING,
                                AlertState.RESOLVED, AlertState.SUPPRESSED}),
    AlertState.ACKNOWLEDGED: frozenset({AlertState.INVESTIGATING, AlertState.RESOLVED,
                                        AlertState.SUPPRESSED}),
    AlertState.INVESTIGATING: frozenset({AlertState.RESOLVED, AlertState.SUPPRESSED}),
    AlertState.RESOLVED: frozenset(),
    AlertState.SUPPRESSED: frozenset(),
}


class EdgeKind(str, enum.Enum):
    """Intent-graph relationship kinds. Deliberately factual (observed/declared), never 'intent'."""

    AGENT_TOOL = "agent_tool"                 # agent invoked a tool
    AGENT_RESOURCE = "agent_resource"         # agent accessed a resource
    AGENT_DESTINATION = "agent_destination"   # agent sent traffic to a destination
    AGENT_POLICY = "agent_policy"             # agent was governed by a policy (decision made)
    AGENT_TASK = "agent_task"                 # agent worked on a task (declared by a trusted app)
    TASK_RESOURCE = "task_resource"           # a task's declared scope includes a resource
    EVENT_SUBJECT = "event_subject"           # an event touched a subject node
    RESOURCE_DESTINATION = "resource_destination"  # a resource was reached via a destination

    @classmethod
    def coerce(cls, value) -> Optional["EdgeKind"]:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None


class NodeKind(str, enum.Enum):
    AGENT = "agent"
    IDENTITY = "identity"
    TASK = "task"
    TOOL = "tool"
    RESOURCE = "resource"
    POLICY = "policy"
    PERMISSION = "permission"
    EVENT = "event"
    DATA_CLASS = "data_class"
    DESTINATION = "destination"

    @classmethod
    def coerce(cls, value) -> Optional["NodeKind"]:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None


class SignalKind(str, enum.Enum):
    """Closed vocabulary of risk signals (each is versioned in the scoring rule set)."""

    POLICY_VIOLATION = "policy_violation"
    DLP_FINDING = "dlp_finding"
    DESTINATION_RISK = "destination_risk"
    BEHAVIORAL_DEVIATION = "behavioral_deviation"
    REPEATED_AUTH_FAILURE = "repeated_auth_failure"
    ABNORMAL_FREQUENCY = "abnormal_frequency"
    SENSITIVE_RESOURCE_ACCESS = "sensitive_resource_access"
    CORRELATED_SUSPICION = "correlated_suspicion"


class RiskBand(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResponseAction(str, enum.Enum):
    """Automated actions an alert rule may request. Every one of these DELEGATES to an existing
    enforcement mechanism -- the monitoring plane never enforces anything itself.
    """

    REEVALUATE_POLICY = "reevaluate_policy"     # ask the Step 10 policy engine to re-decide
    REVOKE_JIT_GRANT = "revoke_jit"             # ask the Step 10 JIT service to revoke grants
    REQUIRE_APPROVAL = "require_approval"       # raise an approval request via the policy plane
    NOTIFY_INCIDENT = "notify_incident"         # emit an incident-response notification record

    @classmethod
    def coerce(cls, value) -> Optional["ResponseAction"]:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None


# --------------------------------------------------------------------------- runtime event
@dataclass(frozen=True)
class RuntimeEvent:
    """A normalized runtime telemetry record.

    ``ts`` is the PRODUCER event time; ``ingested_at`` is when this pipeline saw it. Keeping both
    lets the plane represent late/out-of-order delivery honestly instead of pretending arrival order
    is event order. ``redacted``/``sampled`` record what the pipeline did to the record so an
    investigator can reason about coverage.
    """

    event_id: str
    event_type: str
    ts: float
    org_id: str
    agent_id: Optional[str] = None
    instance_id: Optional[str] = None
    session_id: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    resource_type: Optional[str] = None
    decision: Optional[str] = None
    reason: Optional[str] = None
    outcome: str = "ok"
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    destination: Optional[str] = None
    address_class: Optional[str] = None
    data_classes: Tuple[str, ...] = ()
    dlp_rule_ids: Tuple[str, ...] = ()
    severity: Optional[str] = None
    latency_ms: Optional[int] = None
    correlation_id: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    actor_user_id: Optional[str] = None
    task_id: Optional[str] = None
    ingested_at: float = 0.0
    late: bool = False
    redacted: bool = False
    sampled: bool = False
    dedup_key: Optional[str] = None
    extra: Dict[str, object] = field(default_factory=dict)

    # -- convenience predicates used by the detectors -----------------------------------------
    @property
    def is_denial(self) -> bool:
        return self.decision in (Decision.DENY.value, Decision.BLOCKED.value,
                                 Decision.REQUIRE_APPROVAL.value, Decision.INDETERMINATE.value)

    @property
    def is_failure(self) -> bool:
        return self.outcome == "error" or self.decision == Decision.ERROR.value

    def public_dict(self) -> dict:
        return {
            "event_id": self.event_id, "event_type": self.event_type, "ts": iso(self.ts),
            "ts_epoch": self.ts, "ingested_at": iso(self.ingested_at), "org_id": self.org_id,
            "agent_id": self.agent_id, "instance_id": self.instance_id, "session_id": self.session_id,
            "action": self.action, "resource": self.resource, "resource_type": self.resource_type,
            "decision": self.decision, "reason": self.reason, "outcome": self.outcome,
            "policy_id": self.policy_id, "policy_version": self.policy_version,
            "destination": self.destination, "address_class": self.address_class,
            "data_classes": list(self.data_classes), "dlp_rule_ids": list(self.dlp_rule_ids),
            "severity": self.severity, "latency_ms": self.latency_ms,
            "correlation_id": self.correlation_id, "trace_id": self.trace_id,
            "span_id": self.span_id, "parent_span_id": self.parent_span_id,
            "actor_user_id": self.actor_user_id, "task_id": self.task_id,
            "late": self.late, "redacted": self.redacted, "sampled": self.sampled,
            "extra": dict(self.extra),
        }


# --------------------------------------------------------------------------- behaviour profile
@dataclass
class BehaviorProfile:
    """A tenant-isolated behavioural summary built ONLY from observable activity.

    A profile is a *count aggregate*, never a judgement. ``min_samples``/``is_mature`` exist so the
    drift detector can decline to reason from too little data instead of treating sparsity as
    suspiciousness.
    """

    profile_id: str
    org_id: str
    agent_id: str
    version: int = 1
    created_at: float = 0.0
    updated_at: float = 0.0
    window_start: Optional[float] = None
    window_end: Optional[float] = None
    learning_window_s: int = 7 * 24 * 3600
    min_samples: int = 50
    total_events: int = 0
    tools: Dict[str, int] = field(default_factory=dict)
    resources: Dict[str, int] = field(default_factory=dict)
    destinations: Dict[str, int] = field(default_factory=dict)
    actions: Dict[str, int] = field(default_factory=dict)
    decisions: Dict[str, int] = field(default_factory=dict)
    data_classes: Dict[str, int] = field(default_factory=dict)
    hour_histogram: Dict[str, int] = field(default_factory=dict)
    sequences: Dict[str, int] = field(default_factory=dict)
    denials: int = 0
    failures: int = 0
    retries: int = 0
    privileged_actions: int = 0
    sensitive_reads: int = 0
    max_events_per_hour: int = 0

    @property
    def is_mature(self) -> bool:
        """True only once the profile has enough observations to reason from."""
        return self.total_events >= self.min_samples

    def public_dict(self) -> dict:
        return {
            "profile_id": self.profile_id, "org_id": self.org_id, "agent_id": self.agent_id,
            "version": self.version, "created_at": iso(self.created_at),
            "updated_at": iso(self.updated_at),
            "window_start": iso(self.window_start) if self.window_start else None,
            "window_end": iso(self.window_end) if self.window_end else None,
            "learning_window_s": self.learning_window_s, "min_samples": self.min_samples,
            "total_events": self.total_events, "mature": self.is_mature,
            "tools": dict(self.tools), "resources": dict(self.resources),
            "destinations": dict(self.destinations), "actions": dict(self.actions),
            "decisions": dict(self.decisions), "data_classes": dict(self.data_classes),
            "denials": self.denials, "failures": self.failures, "retries": self.retries,
            "privileged_actions": self.privileged_actions, "sensitive_reads": self.sensitive_reads,
            "max_events_per_hour": self.max_events_per_hour,
            "distinct_tools": len(self.tools), "distinct_resources": len(self.resources),
            "distinct_destinations": len(self.destinations),
        }


# --------------------------------------------------------------------------- drift
@dataclass
class DriftFinding:
    finding_id: str
    org_id: str
    agent_id: Optional[str]
    ts: float
    classification: str
    category: str
    observed: str
    expected: Optional[str] = None
    corroboration: str = Corroboration.NONE.value
    evidence: Tuple[str, ...] = ()
    confidence: float = 0.0
    severity: str = Severity.MEDIUM.value
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id, "org_id": self.org_id, "agent_id": self.agent_id,
            "ts": iso(self.ts), "classification": self.classification, "category": self.category,
            "observed": self.observed, "expected": self.expected,
            "corroboration": self.corroboration, "evidence": list(self.evidence),
            "confidence": round(self.confidence, 3), "severity": self.severity,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------- intent graph
@dataclass(frozen=True)
class GraphNode:
    node_id: str
    org_id: str
    kind: str
    label: str
    first_seen: float
    last_seen: float
    attributes: Dict[str, object] = field(default_factory=dict)

    def public_dict(self) -> dict:
        return {"node_id": self.node_id, "org_id": self.org_id, "kind": self.kind,
                "label": self.label, "first_seen": iso(self.first_seen),
                "last_seen": iso(self.last_seen), "attributes": dict(self.attributes)}


@dataclass(frozen=True)
class GraphEdge:
    """An OBSERVED relationship. ``provenance`` records what produced it and ``confidence`` how
    strong that evidence is -- so a time-adjacent guess is never presented as a causal fact.
    """

    edge_id: str
    org_id: str
    kind: str
    src: str
    dst: str
    first_seen: float
    last_seen: float
    count: int = 1
    confidence: float = 1.0
    provenance: str = ""
    last_event_id: Optional[str] = None

    def public_dict(self) -> dict:
        return {"edge_id": self.edge_id, "org_id": self.org_id, "kind": self.kind, "src": self.src,
                "dst": self.dst, "first_seen": iso(self.first_seen), "last_seen": iso(self.last_seen),
                "count": self.count, "confidence": round(self.confidence, 3),
                "provenance": self.provenance, "last_event_id": self.last_event_id}


# --------------------------------------------------------------------------- risk
@dataclass(frozen=True)
class RiskSignal:
    kind: str
    weight: float
    contribution: float
    evidence: Tuple[str, ...] = ()
    detail: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "weight": round(self.weight, 3),
                "contribution": round(self.contribution, 3), "evidence": list(self.evidence),
                "detail": self.detail}


@dataclass(frozen=True)
class RiskAssessment:
    """An EXPLAINABLE heuristic score. Not a validated prediction, not an enforcement decision."""

    assessment_id: str
    org_id: str
    agent_id: Optional[str]
    ts: float
    score: float
    band: str
    rule_version: str
    signals: Tuple[RiskSignal, ...] = ()
    evidence: Tuple[str, ...] = ()
    window_s: int = 3600
    caveat: str = ("heuristic, rule-based score over observed telemetry; not a scientifically "
                   "validated prediction and not an enforcement decision (the policy engine "
                   "remains authoritative)")

    def to_dict(self) -> dict:
        return {
            "assessment_id": self.assessment_id, "org_id": self.org_id, "agent_id": self.agent_id,
            "ts": iso(self.ts), "score": round(self.score, 2), "band": self.band,
            "rule_version": self.rule_version,
            "signals": [s.to_dict() for s in self.signals], "evidence": list(self.evidence),
            "window_s": self.window_s, "caveat": self.caveat,
        }


# --------------------------------------------------------------------------- alerts
@dataclass(frozen=True)
class AlertRule:
    """A tenant-scoped alert condition. ``auto_actions`` must be OPT-IN and only list actions that
    delegate to existing enforcement mechanisms (see :class:`ResponseAction`).
    """

    rule_id: str
    name: str
    org_id: str
    min_severity: str = Severity.MEDIUM.value
    event_types: Tuple[str, ...] = ()
    drift_classes: Tuple[str, ...] = ()
    risk_threshold: Optional[float] = None
    dedup_window_s: int = 300
    rate_window_s: int = 3600
    max_per_window: int = 20
    auto_actions: Tuple[str, ...] = ()
    description: str = ""
    enabled: bool = True
    created_at: float = 0.0

    def public_dict(self) -> dict:
        return {"rule_id": self.rule_id, "name": self.name, "org_id": self.org_id,
                "min_severity": self.min_severity, "event_types": list(self.event_types),
                "drift_classes": list(self.drift_classes), "risk_threshold": self.risk_threshold,
                "dedup_window_s": self.dedup_window_s, "rate_window_s": self.rate_window_s,
                "max_per_window": self.max_per_window, "auto_actions": list(self.auto_actions),
                "description": self.description, "enabled": self.enabled,
                "created_at": iso(self.created_at)}


@dataclass
class Alert:
    alert_id: str
    org_id: str
    rule_id: str
    severity: str
    title: str
    ts: float
    state: str = AlertState.OPEN.value
    dedup_key: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    occurrence_count: int = 1
    suppressed_count: int = 0
    agent_id: Optional[str] = None
    drift_class: Optional[str] = None
    risk_score: Optional[float] = None
    event_ids: Tuple[str, ...] = ()
    actions_taken: Tuple[str, ...] = ()
    acknowledged_by: Optional[str] = None
    resolved_by: Optional[str] = None
    note: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id, "org_id": self.org_id, "rule_id": self.rule_id,
            "severity": self.severity, "title": self.title, "ts": iso(self.ts), "state": self.state,
            "dedup_key": self.dedup_key, "first_seen": iso(self.first_seen),
            "last_seen": iso(self.last_seen), "occurrence_count": self.occurrence_count,
            "suppressed_count": self.suppressed_count, "agent_id": self.agent_id,
            "drift_class": self.drift_class, "risk_score": self.risk_score,
            "event_ids": list(self.event_ids), "actions_taken": list(self.actions_taken),
            "acknowledged_by": self.acknowledged_by, "resolved_by": self.resolved_by,
            "note": self.note, "detail": self.detail,
        }


# --------------------------------------------------------------------------- investigation views
@dataclass(frozen=True)
class CorrelationLink:
    """One link in a correlated action sequence, with an HONEST statement of how it was tied in."""

    event_id: str
    event_type: str
    ts: float
    established_by: str          # "trace" | "correlation_id" | "time_ordered_only"
    causal: bool                 # True only when a trace parent/child link exists
    decision: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None

    def to_dict(self) -> dict:
        return {"event_id": self.event_id, "event_type": self.event_type, "ts": iso(self.ts),
                "established_by": self.established_by, "causal": self.causal,
                "decision": self.decision, "action": self.action, "resource": self.resource}


@dataclass
class ActionSequence:
    """A correlated run of events. ``causal`` is True only when trace context established it."""

    correlation_id: Optional[str]
    org_id: str
    agent_id: Optional[str]
    links: Tuple[CorrelationLink, ...] = ()
    started_at: float = 0.0
    ended_at: float = 0.0
    blocked: bool = False
    approved: bool = False
    completed: bool = False
    departed_from_policy: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "correlation_id": self.correlation_id, "org_id": self.org_id,
            "agent_id": self.agent_id, "links": [l.to_dict() for l in self.links],
            "started_at": iso(self.started_at) if self.started_at else None,
            "ended_at": iso(self.ended_at) if self.ended_at else None,
            "event_count": len(self.links), "blocked": self.blocked, "approved": self.approved,
            "completed": self.completed, "departed_from_policy": self.departed_from_policy,
            "causal_established": bool(self.links) and all(l.established_by == "trace"
                                                          for l in self.links),
            "note": self.note,
        }
