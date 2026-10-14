"""Phase 5 risk scoring and detection correlation.

Combines the signals Phase 5 (and the earlier phases) already produce into an **explainable**
heuristic score:

    policy violations · DLP findings · destination risk · behavioural deviation ·
    repeated failed authorization · abnormal action frequency · sensitive-resource access ·
    correlated suspicion

Two things this module is careful to state plainly:

1. **It is not an enforcement mechanism.** A score is advisory. The Step 10 policy engine remains
   authoritative for allow/deny. Nothing here can grant or deny a request.
2. **It is not a validated prediction.** It is a weighted rule set -- ``rule_version`` is returned
   with every assessment so a score can be tied to the rule set that produced it, and the
   contributing ``signals`` plus raw ``evidence`` are returned so a human can see exactly why the
   number is what it is. Weights are configurable and versioned; thresholds are calibrated in
   ``config.py`` and exercised by deterministic test fixtures.

A signal fires only from *observed* evidence. Absent telemetry contributes nothing (it is neither
treated as risk nor as safety).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from ..security.ids import new_id
from .config import MonitoringConfig
from .models import (Decision, DriftClass, DriftFinding, EventType, RiskAssessment, RiskBand,
                     RiskSignal, RuntimeEvent, Severity, SignalKind)

#: Default, versioned rule set. Each entry is (signal, weight). Weights are additive points on a
#: 0..risk_max scale and are deliberately inspectable rather than learned.
DEFAULT_RULE_WEIGHTS: Dict[str, float] = {
    SignalKind.POLICY_VIOLATION.value: 30.0,
    SignalKind.DLP_FINDING.value: 25.0,
    SignalKind.DESTINATION_RISK.value: 15.0,
    SignalKind.BEHAVIORAL_DEVIATION.value: 20.0,
    SignalKind.REPEATED_AUTH_FAILURE.value: 18.0,
    SignalKind.ABNORMAL_FREQUENCY.value: 12.0,
    SignalKind.SENSITIVE_RESOURCE_ACCESS.value: 14.0,
    SignalKind.CORRELATED_SUSPICION.value: 10.0,
}

#: Magnitudes that scale a signal's contribution (bounded, documented).
_MAGNITUDE = {"single": 0.5, "repeated": 1.0, "burst": 1.25}

#: Address classes that raise a destination-risk signal on their own.
RISKY_ADDRESS_CLASSES = frozenset({"unknown"})


@dataclass(frozen=True)
class RiskRules:
    """A versioned, immutable rule set so a score is always attributable to the rules that made it."""

    version: str
    weights: Dict[str, float]
    bands: Tuple[float, float, float] = (25.0, 55.0, 80.0)
    max_score: float = 100.0
    repeated_denial_threshold: int = 5
    frequency_multiplier: float = 6.0

    def band_of(self, score: float) -> str:
        m, h, c = self.bands
        if score >= c:
            return RiskBand.CRITICAL.value
        if score >= h:
            return RiskBand.HIGH.value
        if score >= m:
            return RiskBand.MEDIUM.value
        return RiskBand.LOW.value

    @classmethod
    def from_config(cls, cfg: MonitoringConfig) -> "RiskRules":
        return cls(version=cfg.risk_rule_version, weights=dict(DEFAULT_RULE_WEIGHTS),
                   bands=(cfg.risk_band_medium, cfg.risk_band_high, cfg.risk_band_critical),
                   max_score=cfg.risk_max,
                   repeated_denial_threshold=cfg.repeated_denial_threshold,
                   frequency_multiplier=cfg.frequency_anomaly_multiplier)


class RiskScorer:
    """Correlates signals over a window into an explainable :class:`RiskAssessment`."""

    def __init__(self, *, config: Optional[MonitoringConfig] = None,
                 rules: Optional[RiskRules] = None, audit=None, clock=None):
        self.cfg = config or MonitoringConfig()
        self.rules = rules or RiskRules.from_config(self.cfg)
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ scoring
    def assess(self, *, org_id: str, agent_id: Optional[str], events: Sequence[RuntimeEvent],
               findings: Sequence[DriftFinding] = (), baseline_peak_per_hour: Optional[int] = None,
               destination_risk: Optional[Dict[str, str]] = None, now: Optional[float] = None
               ) -> RiskAssessment:
        """Produce an explainable assessment from observed events and drift findings."""
        current = now if now is not None else self._now()
        signals: List[RiskSignal] = []
        evidence: List[str] = []

        # -- policy violations ------------------------------------------------------------------
        denials = [e for e in events
                   if e.decision in (Decision.DENY.value, Decision.BLOCKED.value)
                   or e.event_type in (EventType.POLICY_ENFORCEMENT_FAILURE.value,
                                       EventType.AUTHORIZATION_FAILURE.value)]
        if denials:
            magnitude = _MAGNITUDE["burst"] if len(denials) >= self.rules.repeated_denial_threshold \
                else _MAGNITUDE["single"]
            signals.append(self._sig(SignalKind.POLICY_VIOLATION, magnitude,
                                     tuple(f"event_id={e.event_id}" for e in denials[:10]),
                                     f"{len(denials)} policy denial/blocked decision(s)"))
            evidence.extend(f"denial:{e.event_id}" for e in denials[:5])

        # -- DLP findings -----------------------------------------------------------------------
        dlps = [e for e in events if e.event_type in (EventType.DLP_DETECTION.value,
                                                      EventType.DLP_BLOCKED.value)
                or e.dlp_rule_ids]
        if dlps:
            magnitude = _MAGNITUDE["repeated"] if len(dlps) > 1 else _MAGNITUDE["single"]
            signals.append(self._sig(SignalKind.DLP_FINDING, magnitude,
                                     tuple(f"event_id={e.event_id}" for e in dlps[:10]),
                                     f"{len(dlps)} DLP detection(s)"))
            evidence.extend(f"dlp:{e.event_id}" for e in dlps[:5])

        # -- destination risk -------------------------------------------------------------------
        risky_dest = []
        for e in events:
            if not e.destination:
                continue
            cls = (destination_risk or {}).get(e.destination, e.address_class)
            if cls in RISKY_ADDRESS_CLASSES:
                risky_dest.append(e)
        if risky_dest:
            signals.append(self._sig(SignalKind.DESTINATION_RISK, _MAGNITUDE["single"],
                                     tuple(f"destination={e.destination}" for e in risky_dest[:10]),
                                     "outbound traffic to an unclassified destination"))
            evidence.extend(f"destination:{e.destination}" for e in risky_dest[:5])

        # -- behavioural deviation --------------------------------------------------------------
        dev = [f for f in findings if f.classification in (DriftClass.CONFIRMED_VIOLATION.value,
                                                           DriftClass.STATISTICAL_ANOMALY.value)]
        if dev:
            magnitude = _MAGNITUDE["repeated"] if len(dev) > 1 else _MAGNITUDE["single"]
            signals.append(self._sig(SignalKind.BEHAVIORAL_DEVIATION, magnitude,
                                     tuple(f"finding_id={f.finding_id}" for f in dev[:10]),
                                     f"{len(dev)} behavioural deviation(s)"))
            evidence.extend(f"drift:{f.finding_id}" for f in dev[:5])

        # -- repeated authorization failure -----------------------------------------------------
        authf = [e for e in events if e.event_type in (EventType.AUTHORIZATION_FAILURE.value,
                                                       EventType.POLICY_ENFORCEMENT_FAILURE.value)]
        if len(authf) >= self.rules.repeated_denial_threshold:
            signals.append(self._sig(SignalKind.REPEATED_AUTH_FAILURE, _MAGNITUDE["repeated"],
                                     tuple(f"event_id={e.event_id}" for e in authf[:10]),
                                     f"{len(authf)} authorization failures (>= threshold "
                                     f"{self.rules.repeated_denial_threshold})"))
            evidence.extend(f"authfail:{e.event_id}" for e in authf[:5])

        # -- abnormal frequency -----------------------------------------------------------------
        per_hour: Dict[int, int] = {}
        for e in events:
            h = int(e.ts // 3600)
            per_hour[h] = per_hour.get(h, 0) + 1
        if per_hour and baseline_peak_per_hour:
            peak = max(per_hour.values())
            if peak > baseline_peak_per_hour * self.rules.frequency_multiplier:
                signals.append(self._sig(SignalKind.ABNORMAL_FREQUENCY, _MAGNITUDE["single"],
                                         (f"peak_per_hour={peak}",
                                          f"baseline_peak={baseline_peak_per_hour}"),
                                         "hourly event rate far above baseline"))
                evidence.append(f"frequency:{peak}/h")

        # -- sensitive-resource access ----------------------------------------------------------
        sens = [e for e in events
                if e.event_type in (EventType.DATA_ACCESS.value, EventType.FILE_ACCESS.value)
                and e.data_classes]
        if sens:
            magnitude = _MAGNITUDE["repeated"] if len(sens) > 3 else _MAGNITUDE["single"]
            signals.append(self._sig(SignalKind.SENSITIVE_RESOURCE_ACCESS, magnitude,
                                     tuple(f"event_id={e.event_id}" for e in sens[:10]),
                                     f"{len(sens)} classified-data access(es)"))
            evidence.extend(f"sensitive:{e.event_id}" for e in sens[:5])

        # -- correlated suspicion ----------------------------------------------------------------
        heuristics = [f for f in findings
                      if f.classification == DriftClass.HEURISTIC_SUSPICION.value]
        high_sev = [e for e in events if e.severity in (Severity.HIGH.value,
                                                        Severity.CRITICAL.value)]
        if heuristics and (denials or dlps or sens):
            signals.append(self._sig(SignalKind.CORRELATED_SUSPICION, _MAGNITUDE["single"],
                                     tuple(f"finding_id={f.finding_id}" for f in heuristics[:5]),
                                     "heuristic suspicion co-occurring with other signals"))
            evidence.extend(f"corr:{f.finding_id}" for f in heuristics[:3])
        elif len(high_sev) >= 3:
            signals.append(self._sig(SignalKind.CORRELATED_SUSPICION, _MAGNITUDE["single"],
                                     tuple(f"event_id={e.event_id}" for e in high_sev[:5]),
                                     "multiple high-severity events in one window"))
            evidence.extend(f"highsev:{e.event_id}" for e in high_sev[:3])

        score = min(self.rules.max_score, sum(s.contribution for s in signals))
        assessment = RiskAssessment(
            assessment_id=new_id("rsk"), org_id=org_id, agent_id=agent_id, ts=current,
            score=score, band=self.rules.band_of(score), rule_version=self.rules.version,
            signals=tuple(signals), evidence=tuple(sorted(set(evidence))),
            window_s=self.cfg.risk_window_s)
        if self.audit is not None:
            self.audit.record("runtime.risk.assessment", org_id=org_id, agent_id=agent_id,
                              assessment_id=assessment.assessment_id, outcome="ok",
                              extra={"score": round(score, 2), "band": assessment.band,
                                     "signals": len(signals)})
        return assessment

    def score_of(self, *, org_id: str, agent_id: Optional[str], events: Sequence[RuntimeEvent],
                 **kwargs) -> float:
        return self.assess(org_id=org_id, agent_id=agent_id, events=events, **kwargs).score

    # ------------------------------------------------------------------ helpers
    def _sig(self, kind: SignalKind, magnitude: float, evidence: Tuple[str, ...],
             detail: str) -> RiskSignal:
        weight = self.rules.weights.get(kind.value, 0.0)
        return RiskSignal(kind=kind.value, weight=weight, contribution=weight * magnitude,
                          evidence=evidence, detail=detail)


def band_thresholds(cfg: MonitoringConfig) -> dict:
    """The calibrated band thresholds, for tests/fixtures and operator documentation."""
    return {"rule_version": cfg.risk_rule_version, "medium": cfg.risk_band_medium,
            "high": cfg.risk_band_high, "critical": cfg.risk_band_critical, "max": cfg.risk_max}
