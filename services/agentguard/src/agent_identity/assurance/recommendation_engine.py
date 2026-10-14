"""Phase 7 self-healing policy intelligence.

Analyzes TRUSTED security signals and produces EXPLAINABLE policy recommendations. It is a
recommendation engine, not an autonomous policy author: it never activates anything, and it never
claims to reliably infer every attack or to discover perfect policies.

Trusted signal sources (requirement 2)
--------------------------------------
``authorization_denial``, ``policy_violation``, ``dlp_detection``, ``drift_alert``, ``incident``,
``suspicious_tool_use``, ``admin_feedback``, ``false_positive``.

Epistemic discipline
--------------------
Every recommendation keeps three layers SEPARATE and never conflates them:

  * ``observed_facts``        -- what the signals actually recorded (counts, ids, sources),
  * ``heuristic_conclusions`` -- what the rules infer (explicitly labelled as inference),
  * ``proposed_change``       -- the recommendation itself (an action, not a fact).

``confidence`` and ``uncertainty`` are both explicit. A recommendation whose confidence is below
``recommendation_min_confidence`` is emitted as ``REVIEW`` (no change) rather than as an actionable
proposal, and every recommendation carries its test and rollback requirements.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

from ..security.ids import new_id
from .config import AssuranceConfig
from .models import (EvidenceKind, ImpactLevel, PolicyRecommendation, Provenance, SecurityEvidence,
                     severity_rank)

#: Signal kinds that indicate a control is too permissive (tighten direction).
_TIGHTEN_SIGNALS = (EvidenceKind.POLICY_VIOLATION.value, EvidenceKind.DLP_DETECTION.value,
                    EvidenceKind.DRIFT_ALERT.value, EvidenceKind.INCIDENT.value,
                    EvidenceKind.SUSPICIOUS_TOOL_USE.value)
#: Signal kinds that indicate a control is too strict (loosen direction).
_LOOSEN_SIGNALS = (EvidenceKind.FALSE_POSITIVE.value,)
#: Signal kinds that indicate a missing capability (add a narrowly scoped grant).
_GAP_SIGNALS = (EvidenceKind.AUTHORIZATION_DENIAL.value,)


class RecommendationEngine:
    """Turns trusted evidence into explainable, evidence-backed recommendations."""

    def __init__(self, *, config: Optional[AssuranceConfig] = None, clock=None):
        self.cfg = config or AssuranceConfig()
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ================================================================== analysis
    def analyze(self, *, org_id: str, evidence: Sequence[SecurityEvidence],
                policies: Optional[Sequence] = None) -> List[PolicyRecommendation]:
        """Analyze a batch of evidence and return recommendations (never more than the cap)."""
        window_start = self._now() - self.cfg.recommendation_window_s
        recent = [e for e in evidence if e.org_id == org_id and e.ts >= window_start]
        by_kind: Dict[str, List[SecurityEvidence]] = defaultdict(list)
        for e in recent:
            by_kind[e.kind].append(e)

        out: List[PolicyRecommendation] = []
        out.extend(self._tighten_recommendations(org_id, by_kind))
        out.extend(self._loosen_recommendations(org_id, by_kind))
        out.extend(self._gap_recommendations(org_id, by_kind))
        # Deterministic ordering: highest confidence first, then id.
        out.sort(key=lambda r: (-r.confidence, r.recommendation_id))
        return out[:self.cfg.recommendation_max]

    # ------------------------------------------------------------------ tighten
    def _tighten_recommendations(self, org_id: str,
                                 by_kind: Dict[str, List[SecurityEvidence]]
                                 ) -> List[PolicyRecommendation]:
        out = []
        for kind in _TIGHTEN_SIGNALS:
            items = by_kind.get(kind, [])
            if not items:
                continue
            total = sum(max(1, e.count) for e in items)
            if total < self.cfg.recommendation_repeat_threshold:
                continue
            # Group by the subject the signal points at (agent or resource), so a recommendation
            # targets a specific rule rather than "everything".
            groups: Dict[str, List[SecurityEvidence]] = defaultdict(list)
            for e in items:
                groups[e.agent_id or e.ref or "global"].append(e)
            for subject, group in groups.items():
                count = sum(max(1, e.count) for e in group)
                if count < self.cfg.recommendation_repeat_threshold:
                    continue
                out.append(self._build_tighten(org_id, kind, subject, group, count))
        return out

    def _build_tighten(self, org_id: str, kind: str, subject: str,
                       group: List[SecurityEvidence], count: int) -> PolicyRecommendation:
        max_sev = max((severity_rank(e.severity) for e in group), default=2)
        severity = ("info", "low", "medium", "high", "critical")[max_sev]
        # Confidence: more corroborating signals and higher severity => more confidence, capped.
        confidence = min(0.95, 0.4 + 0.1 * min(count, 5) + 0.05 * max_sev)
        impact = ImpactLevel.HIGH.value if max_sev >= 3 else ImpactLevel.MEDIUM.value
        facts = tuple(
            f"{kind}: {count} occurrence(s) for subject '{subject}' "
            f"(max severity {severity}, sources: {', '.join(sorted({e.source for e in group if e.source})) or 'n/a'})"
            for _ in [0])
        heuristics = (
            f"Repeated {kind} signals for the same subject are consistent with a control that is "
            f"too permissive for this subject.",
            "This is a heuristic inference from observed counts, not a confirmed root cause.",
        )
        return PolicyRecommendation(
            recommendation_id=new_id("rec"), org_id=org_id, created_at=self._now(),
            kind="tighten", title=f"Tighten policy for {kind} on '{subject}'",
            target_policy_id=None, target_rule=kind,
            proposed_change={"direction": "tighten", "signal": kind, "subject": subject,
                             "suggested": "add or narrow a deny/require_approval rule for this subject",
                             "auto_applied": False},
            observed_facts=facts, heuristic_conclusions=heuristics,
            evidence_ids=tuple(e.evidence_id for e in group[:self.cfg.recommendation_max_evidence]),
            expected_benefit=f"Reduce {kind} occurrences for '{subject}' by denying or gating the "
                             f"repeated action.",
            operational_impact="May block legitimate activity for this subject; validate against "
                               "representative events before activation.",
            confidence=confidence,
            uncertainty="Counts alone cannot distinguish a genuine attack from a misconfigured "
                        "client; human review is required.",
            impact_level=impact, requires_approval=True,
            test_requirements=("simulate against representative events",
                               "regression-test existing allow paths",
                               "canary before full activation"),
            rollback_plan="Roll back to the previously active policy version (retained for rollback).",
            provenance=Provenance.RECOMMENDATION.value)

    # ------------------------------------------------------------------ loosen
    def _loosen_recommendations(self, org_id: str,
                                by_kind: Dict[str, List[SecurityEvidence]]
                                ) -> List[PolicyRecommendation]:
        out = []
        for kind in _LOOSEN_SIGNALS:
            items = by_kind.get(kind, [])
            if not items:
                continue
            total = sum(max(1, e.count) for e in items)
            if total < self.cfg.recommendation_repeat_threshold:
                continue
            groups: Dict[str, List[SecurityEvidence]] = defaultdict(list)
            for e in items:
                groups[e.agent_id or e.ref or "global"].append(e)
            for subject, group in groups.items():
                count = sum(max(1, e.count) for e in group)
                if count < self.cfg.recommendation_repeat_threshold:
                    continue
                confidence = min(0.9, 0.45 + 0.1 * min(count, 5))
                out.append(PolicyRecommendation(
                    recommendation_id=new_id("rec"), org_id=org_id, created_at=self._now(),
                    kind="loosen", title=f"Relax rule producing false positives on '{subject}'",
                    target_policy_id=None, target_rule=kind,
                    proposed_change={"direction": "loosen", "signal": kind, "subject": subject,
                                     "suggested": "narrow the rule scope or add an exception",
                                     "auto_applied": False},
                    observed_facts=(f"{kind}: {count} confirmed false positive(s) for '{subject}'",),
                    heuristic_conclusions=(
                        "Repeated confirmed false positives indicate the rule is over-broad for this "
                        "subject.", "Inference from confirmed investigations, not a guarantee."),
                    evidence_ids=tuple(e.evidence_id for e in
                                       group[:self.cfg.recommendation_max_evidence]),
                    expected_benefit="Reduce analyst toil and avoid blocking legitimate activity.",
                    operational_impact="Relaxing a rule can admit activity the rule previously "
                                       "blocked; scope the exception narrowly.",
                    confidence=confidence,
                    uncertainty="A false-positive label is only as reliable as the investigation "
                                "that produced it.",
                    impact_level=ImpactLevel.MEDIUM.value, requires_approval=True,
                    test_requirements=("simulate the previously-blocked case",
                                       "confirm the exception is narrowly scoped"),
                    rollback_plan="Roll back to the previously active policy version.",
                    provenance=Provenance.RECOMMENDATION.value))
        return out

    # ------------------------------------------------------------------ gap (missing capability)
    def _gap_recommendations(self, org_id: str,
                             by_kind: Dict[str, List[SecurityEvidence]]
                             ) -> List[PolicyRecommendation]:
        out = []
        denials = by_kind.get(EvidenceKind.AUTHORIZATION_DENIAL.value, [])
        if not denials:
            return out
        # Group denials by (agent, action) so a repeated, specific denial can be proposed as a
        # narrowly scoped JIT grant -- never a broad allow.
        groups: Dict[Tuple[str, str], List[SecurityEvidence]] = defaultdict(list)
        for e in denials:
            action = (e.detail or {}).get("action") if e.detail else None
            groups[(e.agent_id or "unknown", action or "unknown")].append(e)
        for (agent, action), group in groups.items():
            count = sum(max(1, e.count) for e in group)
            if count < self.cfg.recommendation_repeat_threshold:
                continue
            # A repeated denial is ambiguous: it may be a missing grant OR an attack probing limits.
            # We therefore emit a REVIEW recommendation unless there is corroborating admin feedback.
            has_feedback = bool(by_kind.get(EvidenceKind.ADMIN_FEEDBACK.value))
            if has_feedback:
                confidence = min(0.85, 0.5 + 0.1 * min(count, 4))
                kind = "add_jit_scope"
                change = {"direction": "grant", "agent_id": agent, "action": action,
                          "suggested": "propose a narrowly scoped, short-lived JIT grant policy",
                          "auto_applied": False}
                benefit = "Unblock a legitimate, repeatedly denied operation without a broad allow."
                impact = ImpactLevel.MEDIUM.value
            else:
                confidence = min(0.5, 0.25 + 0.05 * min(count, 5))
                kind = "review"
                change = {"direction": "review", "agent_id": agent, "action": action,
                          "suggested": "human review: distinguish a missing grant from probing",
                          "auto_applied": False}
                benefit = "Avoid both an unnecessary block and an unjustified grant."
                impact = ImpactLevel.LOW.value
            out.append(PolicyRecommendation(
                recommendation_id=new_id("rec"), org_id=org_id, created_at=self._now(),
                kind=kind, title=f"Repeated authorization denial for '{action}' by '{agent}'",
                target_policy_id=None, target_rule="authorization_denial",
                proposed_change=change,
                observed_facts=(f"authorization_denial: {count} occurrence(s) for agent '{agent}' "
                                f"action '{action}'",),
                heuristic_conclusions=(
                    "Repeated denials for one (agent, action) are consistent with a missing, "
                    "narrowly scoped grant.",
                    "The same pattern is also consistent with an agent probing its limits; the two "
                    "cannot be distinguished from counts alone."),
                evidence_ids=tuple(e.evidence_id for e in
                                   group[:self.cfg.recommendation_max_evidence]),
                expected_benefit=benefit,
                operational_impact="A grant, if wrong, broadens access; keep it narrow and short-lived.",
                confidence=confidence,
                uncertainty="Without corroborating administrative feedback this is a review request, "
                            "not an actionable change.",
                impact_level=impact, requires_approval=True,
                test_requirements=("confirm the operation is legitimate",
                                   "scope the grant to one action/resource and a short TTL"),
                rollback_plan="Revoke the JIT grant; no policy change is required for a review.",
                provenance=Provenance.RECOMMENDATION.value))
        return out

    # ================================================================== confidence gate
    def is_actionable(self, rec: PolicyRecommendation) -> bool:
        """A recommendation is actionable only if it is not a REVIEW and meets the confidence floor."""
        return rec.kind != "review" and rec.confidence >= self.cfg.recommendation_min_confidence
