"""Phase 5 agentic drift detection.

Compares OBSERVED activity against what the system actually knows to be expected, and is explicit
about how strong that comparison is. Four classifications, strongest first:

``confirmed_violation``
    The observed activity contradicts an **authoritative** source -- a declared capability set the
    agent must obey, or a policy decision that was DENY. This is a fact about configuration, not an
    inference from statistics.

``statistical_anomaly``
    The observed activity deviates from this agent's own **mature** baseline beyond a configured
    threshold (a novel tool/resource/destination, an access burst, a new action-sequence shape).

``heuristic_suspicion``
    The activity matches a configured heuristic (e.g. a run of permission denials, unusual-hour
    activity) but no authoritative source contradicts it. Pattern-matched, not proven.

``insufficient_evidence``
    Not enough telemetry -- a non-mature baseline, or no baseline at all -- to say anything. This is
    reported rather than silently dropped, so nobody mistakes sparsity for cleanliness.

**What this detector does NOT do.** It cannot know an agent's internal intentions from telemetry.
It reports *observed deviations from expected observable behaviour*, with the comparison source
recorded in ``corroboration``, and nothing more. An agent may deviate for entirely legitimate
reasons (a new approved task, a deploy); every finding carries human-readable evidence so a human can
adjudicate.
"""
from __future__ import annotations

import time
from typing import Dict, Iterable, List, Optional, Sequence, Set

from ..security.ids import new_id
from .config import MonitoringConfig
from .models import (BehaviorProfile, Corroboration, Decision, DriftClass, DriftFinding, EventType,
                     RuntimeEvent, Severity)
from .profiles import _tool_of

#: Tool names that indicate exploratory behaviour ("what tools exist?") rather than task work.
_EXPLORATION_MARKERS = ("list_tools", "discover", "enumerate", "schema", "introspect", "whoami",
                        "describe", "capabilities")


class DriftDetector:
    """Configurable deviation detector over a behaviour baseline and declared scope."""

    def __init__(self, *, config: Optional[MonitoringConfig] = None, audit=None, clock=None):
        self.cfg = config or MonitoringConfig()
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ main entry
    def detect(self, *, org_id: str, agent_id: str, events: Sequence[RuntimeEvent],
               profile: Optional[BehaviorProfile] = None,
               declared_capabilities: Optional[Iterable[str]] = None,
               declared_tools: Optional[Iterable[str]] = None,
               declared_destinations: Optional[Iterable[str]] = None,
               now: Optional[float] = None) -> List[DriftFinding]:
        """Run every configured check and return the findings (possibly empty)."""
        current = now if now is not None else self._now()
        found: List[DriftFinding] = []
        found += self.check_capabilities(org_id=org_id, agent_id=agent_id, events=events,
                                        declared_capabilities=declared_capabilities,
                                        declared_tools=declared_tools, now=current)
        found += self.check_destination_scope(org_id=org_id, agent_id=agent_id, events=events,
                                              declared_destinations=declared_destinations,
                                              now=current)
        found += self.check_repeated_denials(org_id=org_id, agent_id=agent_id, events=events,
                                             now=current)
        found += self.check_access_bursts(org_id=org_id, agent_id=agent_id, events=events,
                                          profile=profile, now=current)
        found += self.check_novelty(org_id=org_id, agent_id=agent_id, events=events,
                                    profile=profile, now=current)
        found += self.check_exploration(org_id=org_id, agent_id=agent_id, events=events,
                                        profile=profile, now=current)
        if not found:
            found.append(self._insufficient(org_id=org_id, agent_id=agent_id, now=current,
                                            detail="no deviation detected in the supplied window"))
        return found

    # ------------------------------------------------------------------ confirmed violations
    def check_capabilities(self, *, org_id: str, agent_id: str, events: Sequence[RuntimeEvent],
                           declared_capabilities: Optional[Iterable[str]] = None,
                           declared_tools: Optional[Iterable[str]] = None,
                           now: Optional[float] = None) -> List[DriftFinding]:
        """Observed action/capability use that CONTRADICTS a declared capability set.

        Only fires when an authoritative declared set is supplied and an event's capability/action is
        provably outside it. A missing declared set is ``insufficient_evidence`` -- never assumed
        permissive or restrictive.
        """
        if not self.cfg.enforce_declared_capabilities:
            return []
        current = now if now is not None else self._now()
        if declared_capabilities is None:
            return [self._insufficient(org_id=org_id, agent_id=agent_id, now=current,
                                       category="capability_scope",
                                       detail="no declared capability set available to compare")]
        allowed: Set[str] = {_normalize(c) for c in declared_capabilities}
        allowed_tools: Optional[Set[str]] = (
            {_normalize(t) for t in declared_tools} if declared_tools is not None else None)
        out: List[DriftFinding] = []
        for ev in events:
            observed = _capability_of(ev)
            if observed and observed not in allowed:
                out.append(self._finding(
                    org_id=org_id, agent_id=agent_id, now=current,
                    classification=DriftClass.CONFIRMED_VIOLATION,
                    category="capability_scope", observed=observed,
                    expected=",".join(sorted(allowed))[:FIELD_SUMMARY],
                    corroboration=Corroboration.AUTHORITATIVE,
                    evidence=(f"event_id={ev.event_id}", f"event_type={ev.event_type}",
                              f"observed_capability={observed}", f"ts={ev.ts:.3f}"),
                    confidence=1.0, severity=Severity.HIGH,
                    detail="observed capability is outside the agent's declared capability set"))
            tool = _tool_of(ev)
            if tool and allowed_tools is not None and _normalize(tool) not in allowed_tools:
                out.append(self._finding(
                    org_id=org_id, agent_id=agent_id, now=current,
                    classification=DriftClass.CONFIRMED_VIOLATION, category="tool_scope",
                    observed=tool, expected=",".join(sorted(allowed_tools))[:FIELD_SUMMARY],
                    corroboration=Corroboration.AUTHORITATIVE,
                    evidence=(f"event_id={ev.event_id}", f"observed_tool={tool}"),
                    confidence=1.0, severity=Severity.HIGH,
                    detail="observed tool is outside the agent's declared tool set"))
        return out

    def check_destination_scope(self, *, org_id: str, agent_id: str, events: Sequence[RuntimeEvent],
                                declared_destinations: Optional[Iterable[str]] = None,
                                now: Optional[float] = None) -> List[DriftFinding]:
        """An outbound destination outside an authoritative declared destination set."""
        current = now if now is not None else self._now()
        if declared_destinations is None:
            return []
        allowed = {_normalize(d) for d in declared_destinations}
        out = []
        for ev in events:
            if not ev.destination:
                continue
            if _normalize(ev.destination) not in allowed:
                out.append(self._finding(
                    org_id=org_id, agent_id=agent_id, now=current,
                    classification=DriftClass.CONFIRMED_VIOLATION, category="destination_scope",
                    observed=ev.destination,
                    expected=",".join(sorted(allowed))[:FIELD_SUMMARY],
                    corroboration=Corroboration.AUTHORITATIVE,
                    evidence=(f"event_id={ev.event_id}", f"destination={ev.destination}",
                              f"address_class={ev.address_class}"),
                    confidence=1.0, severity=Severity.HIGH,
                    detail="outbound destination is outside the agent's declared destination scope"))
        return out

    def policy_violation(self, *, org_id: str, agent_id: str, event: RuntimeEvent,
                         now: Optional[float] = None) -> Optional[DriftFinding]:
        """A DENY/BLOCKED policy outcome is an authoritative violation by construction."""
        if event.decision not in (Decision.DENY.value, Decision.BLOCKED.value):
            return None
        current = now if now is not None else self._now()
        return self._finding(
            org_id=org_id, agent_id=agent_id, now=current,
            classification=DriftClass.CONFIRMED_VIOLATION, category="policy_decision",
            observed=f"{event.event_type}:{event.decision}",
            expected=event.policy_id or "policy engine ALLOW",
            corroboration=Corroboration.AUTHORITATIVE,
            evidence=(f"event_id={event.event_id}", f"reason={event.reason}",
                      f"policy_id={event.policy_id}", f"policy_version={event.policy_version}"),
            confidence=1.0, severity=Severity.HIGH,
            detail="an authoritative enforcement decision refused this operation")

    # ------------------------------------------------------------------ statistical anomalies
    def check_novelty(self, *, org_id: str, agent_id: str, events: Sequence[RuntimeEvent],
                     profile: Optional[BehaviorProfile], now: Optional[float] = None
                     ) -> List[DriftFinding]:
        """A tool/resource/destination never seen in a MATURE baseline."""
        current = now if now is not None else self._now()
        if profile is None or not profile.is_mature:
            return [self._insufficient(org_id=org_id, agent_id=agent_id, now=current,
                                       category="novelty",
                                       detail=("baseline is not mature enough to call a novelty "
                                               "anomaly" if profile is not None else
                                               "no baseline exists for this agent"))]
        out = []
        for ev in events:
            tool = _tool_of(ev)
            if tool and tool not in profile.tools:
                out.append(self._novelty(org_id, agent_id, current, "tool", tool, profile, ev))
            if ev.resource and ev.resource not in profile.resources:
                out.append(self._novelty(org_id, agent_id, current, "resource", ev.resource,
                                         profile, ev))
            if ev.destination and ev.destination not in profile.destinations:
                out.append(self._novelty(org_id, agent_id, current, "destination", ev.destination,
                                         profile, ev))
        return out

    def _novelty(self, org_id, agent_id, now, kind, value, profile, ev) -> DriftFinding:
        return self._finding(
            org_id=org_id, agent_id=agent_id, now=now,
            classification=DriftClass.STATISTICAL_ANOMALY, category=f"novel_{kind}",
            observed=value,
            expected=f"one of {len(getattr(profile, kind + 's'))} baseline {kind}s",
            corroboration=Corroboration.BASELINE,
            evidence=(f"event_id={ev.event_id}", f"baseline_samples={profile.total_events}",
                      f"baseline_version={profile.version}", f"baseline_distinct={len(getattr(profile, kind + 's'))}"),
            confidence=min(0.9, 0.4 + 0.5 * min(1.0, profile.total_events / max(1, profile.min_samples * 4))),
            severity=Severity.MEDIUM,
            detail=f"{kind} was never observed in the agent's mature baseline")

    def check_access_bursts(self, *, org_id: str, agent_id: str, events: Sequence[RuntimeEvent],
                            profile: Optional[BehaviorProfile], now: Optional[float] = None
                            ) -> List[DriftFinding]:
        """An hourly event rate far above the baseline's peak hourly rate."""
        current = now if now is not None else self._now()
        if profile is None or not profile.is_mature or profile.max_events_per_hour <= 0:
            return [self._insufficient(org_id=org_id, agent_id=agent_id, now=current,
                                       category="access_burst",
                                       detail="no mature baseline rate to compare against")]
        per_hour: Dict[int, int] = {}
        for ev in events:
            h = int(ev.ts // 3600)
            per_hour[h] = per_hour.get(h, 0) + 1
        out = []
        threshold = profile.max_events_per_hour * self.cfg.frequency_anomaly_multiplier
        for h, count in sorted(per_hour.items()):
            if count > threshold:
                out.append(self._finding(
                    org_id=org_id, agent_id=agent_id, now=current,
                    classification=DriftClass.STATISTICAL_ANOMALY, category="access_burst",
                    observed=f"{count} events in hour {h}",
                    expected=f"<= {threshold:.0f} (baseline peak {profile.max_events_per_hour} "
                             f"x {self.cfg.frequency_anomaly_multiplier})",
                    corroboration=Corroboration.BASELINE,
                    evidence=(f"hour_bucket={h}", f"observed_count={count}",
                              f"baseline_peak={profile.max_events_per_hour}"),
                    confidence=0.7, severity=Severity.MEDIUM,
                    detail="event frequency far exceeds the agent's baseline rate"))
        return out

    # ------------------------------------------------------------------ heuristics
    def check_repeated_denials(self, *, org_id: str, agent_id: str, events: Sequence[RuntimeEvent],
                               now: Optional[float] = None) -> List[DriftFinding]:
        """A run of authorization/permission denials -- a heuristic signal, not a proven violation."""
        current = now if now is not None else self._now()
        denials = [e for e in events
                   if e.event_type in (EventType.AUTHORIZATION_FAILURE.value,
                                       EventType.POLICY_ENFORCEMENT_FAILURE.value)
                   or e.decision in (Decision.DENY.value, Decision.BLOCKED.value)]
        if len(denials) < self.cfg.repeated_denial_threshold:
            return []
        evidence = tuple(f"event_id={e.event_id}" for e in denials[:10])
        return [self._finding(
            org_id=org_id, agent_id=agent_id, now=current,
            classification=DriftClass.HEURISTIC_SUSPICION, category="repeated_denials",
            observed=f"{len(denials)} denials",
            expected=f"< {self.cfg.repeated_denial_threshold} denials in window",
            corroboration=Corroboration.HEURISTIC, evidence=evidence, confidence=0.5,
            severity=Severity.MEDIUM,
            detail=("repeated permission denials can indicate probing or a misconfigured agent; "
                    "this is a heuristic signal and requires human adjudication"))]

    def check_exploration(self, *, org_id: str, agent_id: str, events: Sequence[RuntimeEvent],
                          profile: Optional[BehaviorProfile], now: Optional[float] = None
                          ) -> List[DriftFinding]:
        """Tool discovery / enumeration patterns outside a baseline."""
        current = now if now is not None else self._now()
        hits = []
        for ev in events:
            name = (_tool_of(ev) or ev.action or "").lower()
            if any(marker in name for marker in _EXPLORATION_MARKERS):
                if profile is None or not profile.is_mature or name not in profile.actions:
                    hits.append(ev)
        if not hits:
            return []
        baseline_known = profile is not None and profile.is_mature
        return [self._finding(
            org_id=org_id, agent_id=agent_id, now=current,
            classification=(DriftClass.STATISTICAL_ANOMALY if baseline_known
                            else DriftClass.HEURISTIC_SUSPICION),
            category="tool_exploration",
            observed=",".join(sorted({(_tool_of(e) or e.action or "?") for e in hits}))[:FIELD_SUMMARY],
            expected="tools observed in the baseline" if baseline_known else "no baseline",
            corroboration=(Corroboration.BASELINE if baseline_known
                           else Corroboration.HEURISTIC),
            evidence=tuple(f"event_id={e.event_id}" for e in hits[:10]),
            confidence=0.6 if baseline_known else 0.4, severity=Severity.MEDIUM,
            detail=("tool exploration/enumeration observed; this may be benign discovery "
                    "bootstrap behaviour"))]

    # ------------------------------------------------------------------ helpers
    def _finding(self, *, org_id, agent_id, now, classification, category, observed, expected=None,
                 corroboration=Corroboration.NONE, evidence=(), confidence=0.0,
                 severity=Severity.MEDIUM, detail="") -> DriftFinding:
        return DriftFinding(
            finding_id=new_id("drf"), org_id=org_id, agent_id=agent_id, ts=now,
            classification=DriftClass.coerce(classification).value, category=category,
            observed=observed, expected=expected, corroboration=Corroboration.coerce(corroboration).value,
            evidence=tuple(evidence), confidence=float(confidence),
            severity=Severity.coerce(severity).value, detail=detail)

    def _insufficient(self, *, org_id, agent_id, now, category="coverage",
                      detail="insufficient telemetry") -> DriftFinding:
        return self._finding(
            org_id=org_id, agent_id=agent_id, now=now,
            classification=DriftClass.INSUFFICIENT_EVIDENCE, category=category,
            observed="insufficient telemetry", expected=None,
            corroboration=Corroboration.NONE, evidence=(), confidence=0.0,
            severity=Severity.INFO, detail=detail)


FIELD_SUMMARY = 256


def _normalize(value: str) -> str:
    return str(value).strip().lower()


def _capability_of(ev: RuntimeEvent) -> Optional[str]:
    """The capability an event exercised, when the event makes that explicit."""
    if isinstance(ev.extra, dict):
        cap = ev.extra.get("capability")
        if isinstance(cap, str) and cap:
            return _normalize(cap)
    if ev.event_type in (EventType.TOOL_INVOCATION.value, EventType.API_INVOCATION.value,
                         EventType.DATA_ACCESS.value, EventType.FILE_ACCESS.value,
                         EventType.NETWORK_REQUEST.value):
        if ev.resource and ev.action:
            return _normalize(f"{ev.resource}:{ev.action}")
    return None
