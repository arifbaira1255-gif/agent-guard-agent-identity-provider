"""Phase 7 assurance-plane domain models.

ADDITIVE, immutable records for the security-intelligence / audit-integrity / compliance / SIEM
plane. Nothing here holds secrets: evidence records hold REFERENCES and DIGESTS (never the referenced
payload), SIEM events hold a redacted, classification-gated projection, and audit records hold ids,
an outcome and a bounded primitive-only detail bag.

Provenance is explicit everywhere. A record is one of:

  * ``observed_fact``   -- a directly recorded, authoritative observation,
  * ``heuristic``       -- a rule/pattern conclusion drawn from observations,
  * ``derived``         -- an aggregate/analytics output computed from other records,
  * ``recommendation``  -- a proposed action (never an observation).

The distinction is load-bearing: a recommendation is NEVER presented as a fact, and a heuristic is
NEVER presented as a confirmed violation.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional, Tuple

from ..core.models import iso  # reuse the existing ISO-8601 formatter


# --------------------------------------------------------------------------- closed vocabularies
class Provenance(str, enum.Enum):
    OBSERVED_FACT = "observed_fact"
    HEURISTIC = "heuristic"
    DERIVED = "derived"
    RECOMMENDATION = "recommendation"


class EvidenceKind(str, enum.Enum):
    """The trusted signal sources a recommendation may draw on (requirement 2)."""

    AUTHORIZATION_DENIAL = "authorization_denial"
    POLICY_VIOLATION = "policy_violation"
    DLP_DETECTION = "dlp_detection"
    DRIFT_ALERT = "drift_alert"
    INCIDENT = "incident"
    SUSPICIOUS_TOOL_USE = "suspicious_tool_use"
    ADMIN_FEEDBACK = "admin_feedback"
    FALSE_POSITIVE = "false_positive"


class RecommendationKind(str, enum.Enum):
    TIGHTEN = "tighten"                 # narrow an existing rule
    LOOSEN = "loosen"                   # relax a rule that is producing false positives
    ADD_RULE = "add_rule"               # add a new deny/approval rule
    REMOVE_RULE = "remove_rule"         # remove a rule that is obsolete
    ADD_JIT_SCOPE = "add_jit_scope"     # propose a narrowly scoped JIT grant policy
    REVIEW = "review"                   # insufficient evidence: request human review, no change


class ImpactLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProposalStatus(str, enum.Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    SIMULATED = "simulated"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    CANARY = "canary"
    ACTIVE = "active"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"
    EXPIRED = "expired"


class VerificationStatus(str, enum.Enum):
    """Compliance control verification states (requirement 5)."""

    IMPLEMENTED = "implemented"                 # a technical control exists and is evidenced
    EVIDENCE_COLLECTED = "evidence_collected"   # evidence gathered, control not fully verified
    ORGANIZATIONAL = "organizational"           # requires a human/process control, not code
    UNVERIFIED = "unverified"                   # claimed but not verified
    INCOMPLETE = "incomplete"                   # partially implemented / known gap


class DeliveryStatus(str, enum.Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    RETRYING = "retrying"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"
    SUPPRESSED = "suppressed"                   # dropped by classification/redaction policy


#: Canonical, normalized severities. Every SIEM event is mapped into this closed set.
SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def normalize_severity(value) -> str:
    """Map an arbitrary severity string into the canonical closed set (fail to ``medium``)."""
    if not isinstance(value, str):
        return "medium"
    v = value.strip().lower()
    aliases = {"informational": "info", "notice": "info", "debug": "info", "warning": "medium",
               "warn": "medium", "moderate": "medium", "error": "high", "err": "high",
               "severe": "critical", "fatal": "critical", "emergency": "critical", "alert": "high"}
    v = aliases.get(v, v)
    return v if v in _SEVERITY_RANK else "medium"


def severity_rank(value) -> int:
    return _SEVERITY_RANK.get(normalize_severity(value), 2)


# --------------------------------------------------------------------------- evidence
@dataclass(frozen=True)
class SecurityEvidence:
    """A trusted security signal, referenced (never copied) by a recommendation.

    ``ref`` points at the authoritative record (a policy audit row, a DLP finding, a drift alert, an
    incident, ...) and ``digest`` is a SHA-256 over the referenced content so an investigator can
    later prove the referenced material has not changed. The referenced payload itself is never
    stored here.
    """

    evidence_id: str
    org_id: str
    kind: str
    ts: float
    summary: str
    source: str = ""
    agent_id: Optional[str] = None
    ref: Optional[str] = None
    digest: Optional[str] = None
    severity: str = "medium"
    count: int = 1
    correlation_id: Optional[str] = None
    provenance: str = Provenance.OBSERVED_FACT.value
    detail: Optional[dict] = None

    def public_dict(self) -> dict:
        return {"evidence_id": self.evidence_id, "org_id": self.org_id, "kind": self.kind,
                "ts": iso(self.ts), "summary": self.summary, "source": self.source,
                "agent_id": self.agent_id, "ref": self.ref, "digest": self.digest,
                "severity": normalize_severity(self.severity), "count": self.count,
                "correlation_id": self.correlation_id, "provenance": self.provenance}


# --------------------------------------------------------------------------- recommendations
@dataclass(frozen=True)
class PolicyRecommendation:
    """An explainable, evidence-backed policy recommendation.

    The three epistemic layers are kept SEPARATE and are never conflated:

      * ``observed_facts``        -- what the trusted signals actually recorded,
      * ``heuristic_conclusions`` -- what the rules infer from those facts (labelled as inference),
      * ``proposed_change``       -- the recommendation itself (an action, not a fact).

    ``confidence`` and ``uncertainty`` are both explicit; a low-confidence recommendation is emitted
    as ``REVIEW`` (no change) rather than as an actionable proposal.
    """

    recommendation_id: str
    org_id: str
    created_at: float
    kind: str
    title: str
    target_policy_id: Optional[str]
    target_rule: Optional[str]
    proposed_change: dict
    observed_facts: Tuple[str, ...] = ()
    heuristic_conclusions: Tuple[str, ...] = ()
    evidence_ids: Tuple[str, ...] = ()
    expected_benefit: str = ""
    operational_impact: str = ""
    confidence: float = 0.0
    uncertainty: str = ""
    impact_level: str = ImpactLevel.MEDIUM.value
    requires_approval: bool = True
    test_requirements: Tuple[str, ...] = ()
    rollback_plan: str = ""
    status: str = "open"                 # open | accepted | rejected | superseded
    provenance: str = Provenance.RECOMMENDATION.value

    def public_dict(self) -> dict:
        return {"recommendation_id": self.recommendation_id, "org_id": self.org_id,
                "created_at": iso(self.created_at), "kind": self.kind, "title": self.title,
                "target_policy_id": self.target_policy_id, "target_rule": self.target_rule,
                "proposed_change": dict(self.proposed_change),
                "observed_facts": list(self.observed_facts),
                "heuristic_conclusions": list(self.heuristic_conclusions),
                "evidence_ids": list(self.evidence_ids),
                "expected_benefit": self.expected_benefit,
                "operational_impact": self.operational_impact,
                "confidence": round(float(self.confidence), 4), "uncertainty": self.uncertainty,
                "impact_level": self.impact_level, "requires_approval": self.requires_approval,
                "test_requirements": list(self.test_requirements),
                "rollback_plan": self.rollback_plan, "status": self.status,
                "provenance": self.provenance}


# --------------------------------------------------------------------------- proposals / lifecycle
@dataclass(frozen=True)
class ProposalApproval:
    """One approval decision on a proposal. Bound to the proposal's checksum so a modified proposal
    cannot reuse an earlier approval."""

    approval_id: str
    proposal_id: str
    org_id: str
    approver_user_id: str
    decision: str                        # approved | rejected
    checksum: str                        # the proposal checksum this decision authorizes
    ts: float
    reason: str = ""

    def public_dict(self) -> dict:
        return {"approval_id": self.approval_id, "proposal_id": self.proposal_id,
                "org_id": self.org_id, "approver_user_id": self.approver_user_id,
                "decision": self.decision, "checksum": self.checksum, "ts": iso(self.ts),
                "reason": self.reason}


@dataclass(frozen=True)
class PolicyProposal:
    """A proposed policy change moving through the safe lifecycle.

    A proposal is NEVER activated because a model recommended it: it must be validated, simulated,
    approved by an authorized human (two distinct approvers for high-impact changes), and explicitly
    activated. Every transition is recorded in the tamper-evident audit chain.
    """

    proposal_id: str
    org_id: str
    recommendation_id: Optional[str]
    policy_id: Optional[str]              # None => a brand-new policy
    base_version: Optional[int]
    proposed_rego: str
    checksum: str
    status: str
    impact_level: str
    created_at: float
    created_by: str
    updated_at: float
    title: str = ""
    rationale: str = ""
    validated_at: Optional[float] = None
    validation_summary: Optional[dict] = None
    simulation_summary: Optional[dict] = None
    approvals: Tuple[dict, ...] = ()
    canary: Optional[dict] = None
    activated_at: Optional[float] = None
    activated_by: Optional[str] = None
    activated_version: Optional[int] = None
    rolled_back_at: Optional[float] = None
    rolled_back_to: Optional[int] = None
    expires_at: Optional[float] = None
    emergency: bool = False
    provenance: Tuple[dict, ...] = ()     # ordered lifecycle transitions

    def public_dict(self, *, include_source: bool = False) -> dict:
        out = {"proposal_id": self.proposal_id, "org_id": self.org_id,
               "recommendation_id": self.recommendation_id, "policy_id": self.policy_id,
               "base_version": self.base_version, "checksum": self.checksum, "status": self.status,
               "impact_level": self.impact_level, "created_at": iso(self.created_at),
               "created_by": self.created_by, "updated_at": iso(self.updated_at),
               "title": self.title, "rationale": self.rationale,
               "validated_at": iso(self.validated_at), "validation_summary": self.validation_summary,
               "simulation_summary": self.simulation_summary,
               "approvals": [dict(a) for a in self.approvals], "canary": self.canary,
               "activated_at": iso(self.activated_at), "activated_by": self.activated_by,
               "activated_version": self.activated_version,
               "rolled_back_at": iso(self.rolled_back_at), "rolled_back_to": self.rolled_back_to,
               "expires_at": iso(self.expires_at), "emergency": self.emergency,
               "provenance": [dict(p) for p in self.provenance]}
        if include_source:
            out["proposed_rego"] = self.proposed_rego
        return out


# --------------------------------------------------------------------------- tamper-evident audit
@dataclass(frozen=True)
class AuditChainRecord:
    """One link of the tamper-evident audit chain.

    ``hash`` = SHA-256 over ``prev_hash`` + the canonical serialization of the record's hashed
    fields. ``signature`` is an Ed25519 signature (via the KMS/HSM layer) over the domain-separated
    ``hash``, so a record cannot be forged without the signing key even by an actor who can rewrite
    the whole chain. ``key_id``/``key_version`` make the record verifiable across key rotation.
    """

    seq: int
    record_id: str
    org_id: Optional[str]
    ts: float
    event: str
    actor_user_id: Optional[str]
    outcome: str
    reason: Optional[str]
    payload_digest: Optional[str]
    prev_hash: Optional[str]
    hash: str
    signature: Optional[str] = None
    key_id: Optional[str] = None
    key_version: Optional[int] = None
    correlation_id: Optional[str] = None
    detail: Optional[dict] = None

    def public_dict(self) -> dict:
        return {"seq": self.seq, "record_id": self.record_id, "org_id": self.org_id,
                "ts": iso(self.ts), "event": self.event, "actor_user_id": self.actor_user_id,
                "outcome": self.outcome, "reason": self.reason,
                "payload_digest": self.payload_digest, "prev_hash": self.prev_hash,
                "hash": self.hash, "signature": self.signature, "key_id": self.key_id,
                "key_version": self.key_version, "correlation_id": self.correlation_id}


@dataclass(frozen=True)
class AuditCheckpoint:
    """A signed digest of the chain head at a point in time.

    A checkpoint is the ONLY mechanism that can detect truncation of the tail of the chain: without
    an externally retained checkpoint, an attacker who controls all storage can simply delete the
    last N records and the remaining chain still verifies. Checkpoints are signed with the same
    KMS/HSM key and are intended to be exported/anchored externally (see the limitations doc).
    """

    checkpoint_id: str
    org_id: Optional[str]
    seq: int
    head_hash: str
    record_count: int
    ts: float
    signature: Optional[str] = None
    key_id: Optional[str] = None
    key_version: Optional[int] = None

    def public_dict(self) -> dict:
        return {"checkpoint_id": self.checkpoint_id, "org_id": self.org_id, "seq": self.seq,
                "head_hash": self.head_hash, "record_count": self.record_count, "ts": iso(self.ts),
                "signature": self.signature, "key_id": self.key_id, "key_version": self.key_version}


# --------------------------------------------------------------------------- compliance
@dataclass(frozen=True)
class ComplianceControlMapping:
    """Maps an implemented control + collected evidence to a framework requirement.

    ``verification_status`` distinguishes a technical control that exists and is evidenced from one
    that requires an organizational process or is unverified. Generating a report is NOT a claim of
    certification or legal compliance.
    """

    mapping_id: str
    framework: str
    control_id: str
    control_title: str
    description: str
    scope: str
    evidence_source: str
    owner_component: str
    verification_status: str
    evidence_ts: Optional[float] = None
    provenance: str = Provenance.OBSERVED_FACT.value
    known_gaps: Tuple[str, ...] = ()
    last_review: Optional[float] = None
    next_review: Optional[float] = None
    evidence_refs: Tuple[str, ...] = ()

    def public_dict(self) -> dict:
        return {"mapping_id": self.mapping_id, "framework": self.framework,
                "control_id": self.control_id, "control_title": self.control_title,
                "description": self.description, "scope": self.scope,
                "evidence_source": self.evidence_source, "owner_component": self.owner_component,
                "verification_status": self.verification_status,
                "evidence_ts": iso(self.evidence_ts), "provenance": self.provenance,
                "known_gaps": list(self.known_gaps), "last_review": iso(self.last_review),
                "next_review": iso(self.next_review), "evidence_refs": list(self.evidence_refs)}


# --------------------------------------------------------------------------- SIEM / correlation
@dataclass(frozen=True)
class SiemEvent:
    """A normalized, redacted, classification-gated event ready for export.

    ``provenance`` distinguishes an ORIGINAL evidence event from a DERIVED analytics event, so a
    consumer never mistakes a correlation output for primary evidence.
    """

    event_id: str
    ts: float
    org_id: Optional[str]
    severity: str
    category: str
    action: str
    outcome: str
    source: str
    dedup_key: str
    correlation_id: Optional[str] = None
    agent_id: Optional[str] = None
    classification: str = "internal"
    provenance: str = Provenance.OBSERVED_FACT.value
    incident_id: Optional[str] = None
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    fields: Optional[dict] = None

    def to_export(self) -> dict:
        """The wire projection. ``fields`` is already redacted by the exporter."""
        out = {"event_id": self.event_id, "ts": iso(self.ts), "severity": normalize_severity(self.severity),
               "category": self.category, "action": self.action, "outcome": self.outcome,
               "source": self.source, "dedup_key": self.dedup_key,
               "classification": self.classification, "provenance": self.provenance}
        for k in ("org_id", "correlation_id", "agent_id", "incident_id", "policy_id",
                  "policy_version"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v
        if self.fields:
            out["fields"] = dict(self.fields)
        return out


@dataclass(frozen=True)
class SiemDelivery:
    """Delivery status for one event to one destination (requirement 6/8)."""

    delivery_id: str
    destination_id: str
    event_id: str
    org_id: Optional[str]
    status: str
    attempts: int
    ts: float
    last_error: Optional[str] = None
    next_attempt_at: Optional[float] = None

    def public_dict(self) -> dict:
        return {"delivery_id": self.delivery_id, "destination_id": self.destination_id,
                "event_id": self.event_id, "org_id": self.org_id, "status": self.status,
                "attempts": self.attempts, "ts": iso(self.ts), "last_error": self.last_error,
                "next_attempt_at": iso(self.next_attempt_at)}


@dataclass(frozen=True)
class CorrelationFinding:
    """A cross-system correlation result (requirement 7).

    A finding is DERIVED analytics: it references the original event ids and preserves their
    provenance rather than replacing them.
    """

    finding_id: str
    org_id: str
    correlation_id: str
    ts: float
    severity: str
    summary: str
    event_ids: Tuple[str, ...] = ()
    dedup_key: str = ""
    related_incident_id: Optional[str] = None
    policy_id: Optional[str] = None
    agent_id: Optional[str] = None
    provenance: str = Provenance.DERIVED.value
    detail: Optional[dict] = None

    def public_dict(self) -> dict:
        return {"finding_id": self.finding_id, "org_id": self.org_id,
                "correlation_id": self.correlation_id, "ts": iso(self.ts),
                "severity": normalize_severity(self.severity), "summary": self.summary,
                "event_ids": list(self.event_ids), "dedup_key": self.dedup_key,
                "related_incident_id": self.related_incident_id, "policy_id": self.policy_id,
                "agent_id": self.agent_id, "provenance": self.provenance}
