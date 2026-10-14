"""Phase 5 real-time alerts, deduplication, rate limiting, lifecycle and response integration.

An :class:`~.models.Alert` is raised when a configured condition matches, then:

* **deduplicated** -- an open alert with the same ``dedup_key`` inside its window is *updated*
  (``occurrence_count``/``last_seen``) instead of producing a new alert;
* **rate limited** -- a per-rule ceiling within a rolling window bounds alert volume, and the
  suppressed count is recorded rather than the alert being silently dropped;
* **given a lifecycle** -- ``open → acknowledged → investigating → resolved/suppressed`` with an
  explicit transition table (an illegal transition is rejected, not coerced);
* **optionally acted upon** -- a rule's ``auto_actions`` run ONLY when automated actions are enabled
  in config, and every action delegates to an existing enforcement mechanism via
  :class:`~.runtime_monitoring.policy_integration.PolicyIntegration`. The monitoring plane never
  enforces anything itself.

Every containment action is scoped, audited and (where the underlying mechanism supports it)
reversible -- e.g. revoking a JIT grant is reversible by the policy plane issuing a new one through
its normal approval flow.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Sequence, Tuple

from ..security.ids import new_id
from . import audit as A
from .audit import RuntimeMonitoringAudit
from .config import MonitoringConfig
from .errors import AlertError, ResponseActionError, TenantBoundaryError
from .models import (ALERT_STATE_TRANSITIONS, ALERT_TERMINAL_STATES, Alert, AlertRule, AlertState,
                     DriftFinding, ResponseAction, RiskAssessment, RuntimeEvent, Severity)
from .policy_integration import PolicyIntegration
from .store import RuntimeMonitoringStore


class AlertService:
    """Rule registry, alert lifecycle, dedup/rate-limiting and delegated response actions."""

    def __init__(self, store: RuntimeMonitoringStore, *, config: Optional[MonitoringConfig] = None,
                 audit: Optional[RuntimeMonitoringAudit] = None, integration: Optional[PolicyIntegration] = None,
                 clock=None):
        self.store = store
        self.cfg = config or MonitoringConfig()
        self.audit = audit or RuntimeMonitoringAudit(store, enabled=self.cfg.audit_enabled,
                                                     clock=clock)
        self.integration = integration or PolicyIntegration()
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ rule CRUD
    def register_rule(self, *, org_id: str, name: str, min_severity: str = Severity.MEDIUM.value,
                      event_types: Sequence[str] = (), drift_classes: Sequence[str] = (),
                      risk_threshold: Optional[float] = None,
                      dedup_window_s: Optional[int] = None, rate_window_s: Optional[int] = None,
                      max_per_window: Optional[int] = None, auto_actions: Sequence[str] = (),
                      description: str = "", rule_id: Optional[str] = None,
                      actor_user_id: Optional[str] = None) -> AlertRule:
        if not org_id or not isinstance(org_id, str):
            raise AlertError("org_id is required")
        if not name or not isinstance(name, str):
            raise AlertError("name is required")
        actions: Tuple[str, ...] = ()
        for a in auto_actions or ():
            coerced = ResponseAction.coerce(a)
            if coerced is None:
                raise AlertError(f"unknown response action: {a!r}")
            actions += (coerced.value,)
        if actions and not self.cfg.allow_auto_actions:
            raise AlertError("automated response actions are disabled in configuration "
                             "(AGENTGUARD_MONITOR_ALLOW_AUTO_ACTIONS)")
        rule = AlertRule(
            rule_id=rule_id or new_id("arul"), name=name, org_id=org_id,
            min_severity=Severity.coerce(min_severity).value, event_types=tuple(event_types or ()),
            drift_classes=tuple(drift_classes or ()), risk_threshold=risk_threshold,
            dedup_window_s=int(dedup_window_s if dedup_window_s is not None
                               else self.cfg.default_dedup_window_s),
            rate_window_s=int(rate_window_s if rate_window_s is not None
                              else self.cfg.default_rate_window_s),
            max_per_window=int(max_per_window if max_per_window is not None
                               else self.cfg.default_max_alerts_per_window),
            auto_actions=actions, description=description, created_at=self._now())
        self.store.put_rule(rule)
        self.audit.record(A.E_RULE_REGISTERED, org_id=org_id, rule_id=rule.rule_id,
                          actor_user_id=actor_user_id, outcome="ok", action="register_rule")
        return rule

    def list_rules(self, *, org_id: str) -> List[AlertRule]:
        return self.store.list_rules(org_id=org_id)

    def get_rule(self, *, org_id: str, rule_id: str) -> Optional[AlertRule]:
        return self.store.get_rule(rule_id, org_id=org_id)

    def delete_rule(self, *, org_id: str, rule_id: str, actor_user_id: Optional[str] = None) -> None:
        self.store.delete_rule(rule_id, org_id=org_id)
        self.audit.record(A.E_RULE_DELETED, org_id=org_id, rule_id=rule_id,
                          actor_user_id=actor_user_id, outcome="ok", action="delete_rule")

    # ------------------------------------------------------------------ raising
    def evaluate_events(self, *, org_id: str, events: Sequence[RuntimeEvent],
                        agent_id: Optional[str] = None) -> List[Alert]:
        """Raise alerts for event-type rules that match the supplied events."""
        raised: List[Alert] = []
        for rule in self.store.list_rules(org_id=org_id):
            if not rule.enabled or not rule.event_types:
                continue
            matched = [e for e in events if e.event_type in rule.event_types]
            if not matched:
                continue
            severity = _max_severity(rule.min_severity, _severity_of_events(matched))
            raised.append(self.raise_alert(
                org_id=org_id, rule=rule, severity=severity,
                title=f"{rule.name}: {len(matched)} matching event(s)",
                agent_id=agent_id or (matched[0].agent_id if matched else None),
                event_ids=tuple(e.event_id for e in matched[:20]),
                detail="event-type rule matched", ts=matched[-1].ts))
        return raised

    def evaluate_findings(self, *, org_id: str, findings: Sequence[DriftFinding]) -> List[Alert]:
        """Raise alerts for drift findings matching a rule's ``drift_classes``."""
        raised: List[Alert] = []
        for rule in self.store.list_rules(org_id=org_id):
            if not rule.enabled or not rule.drift_classes:
                continue
            for f in findings:
                if f.classification not in rule.drift_classes:
                    continue
                severity = _max_severity(rule.min_severity, Severity.coerce(f.severity))
                raised.append(self.raise_alert(
                    org_id=org_id, rule=rule, severity=severity,
                    title=f"{rule.name}: {f.category} ({f.classification})",
                    agent_id=f.agent_id, drift_class=f.classification,
                    event_ids=tuple(e.split("=", 1)[1] for e in f.evidence if e.startswith("event_id=")),
                    detail=f.detail, ts=f.ts))
        return raised

    def evaluate_assessment(self, *, org_id: str, assessment: RiskAssessment) -> List[Alert]:
        """Raise alerts for a risk assessment that crosses a rule's configured threshold."""
        raised: List[Alert] = []
        for rule in self.store.list_rules(org_id=org_id):
            if not rule.enabled or rule.risk_threshold is None:
                continue
            if assessment.score < rule.risk_threshold:
                continue
            severity = _band_to_severity(assessment.band)
            severity = _max_severity(rule.min_severity, severity)
            raised.append(self.raise_alert(
                org_id=org_id, rule=rule, severity=severity,
                title=f"{rule.name}: risk {assessment.score:.1f} ({assessment.band})",
                agent_id=assessment.agent_id, risk_score=assessment.score,
                event_ids=tuple(assessment.evidence[:20]), detail=assessment.caveat,
                ts=assessment.ts))
        return raised

    # ------------------------------------------------------------------ alert core
    def raise_alert(self, *, org_id: str, rule: AlertRule, severity: str, title: str,
                    agent_id: Optional[str] = None, drift_class: Optional[str] = None,
                    risk_score: Optional[float] = None, event_ids: Sequence[str] = (),
                    detail: str = "", ts: Optional[float] = None,
                    performed_by: str = "system") -> Alert:
        if not org_id:
            raise TenantBoundaryError("org_id is required to raise an alert")
        now = ts if ts is not None else self._now()
        severity = Severity.coerce(severity).value
        dedup_key = f"{rule.rule_id}|{agent_id or '-'}|{drift_class or title}"

        existing = self.store.find_open_alert(org_id=org_id, dedup_key=dedup_key)
        if existing is not None and (now - existing.last_seen) <= rule.dedup_window_s:
            updated = Alert(**{**existing.__dict__,
                               "occurrence_count": existing.occurrence_count + 1,
                               "last_seen": now,
                               "event_ids": tuple(dict.fromkeys(
                                   list(existing.event_ids) + list(event_ids)))[:50],
                               "severity": _max_severity(existing.severity,
                                                         Severity.coerce(severity)).value})
            self.store.put_alert(updated)
            self.audit.record(A.E_ALERT_DEDUPED, org_id=org_id, rule_id=rule.rule_id,
                              alert_id=updated.alert_id, agent_id=agent_id, outcome="ok",
                              reason="deduplicated", extra={"occurrences": updated.occurrence_count})
            return updated

        since = now - rule.rate_window_s
        if self.store.count_alerts(org_id=org_id, rule_id=rule.rule_id, since=since) >= rule.max_per_window:
            # Rate-limited. The alert is still RECORDED (state ``suppressed``) so it stays visible to
            # an investigator and is never silently dropped, and the caller's analysis chain is not
            # broken by a noisy rule. Nothing is enforced.
            base = existing if existing is not None else Alert(
                alert_id=new_id("alt"), org_id=org_id, rule_id=rule.rule_id, severity=severity,
                title=title, ts=now, dedup_key=dedup_key, first_seen=now, last_seen=now,
                agent_id=agent_id, drift_class=drift_class, risk_score=risk_score,
                event_ids=tuple(dict.fromkeys(event_ids))[:50], detail=detail)
            suppressed = Alert(**{**base.__dict__, "state": AlertState.SUPPRESSED.value,
                                  "suppressed_count": base.suppressed_count + 1, "last_seen": now})
            self.store.put_alert(suppressed)
            self.audit.record(A.E_ALERT_RATE_LIMITED, org_id=org_id, rule_id=rule.rule_id,
                              alert_id=suppressed.alert_id, agent_id=agent_id, outcome="denied",
                              reason="rate_limited",
                              extra={"suppressed": suppressed.suppressed_count})
            return suppressed

        alert = Alert(alert_id=new_id("alt"), org_id=org_id, rule_id=rule.rule_id, severity=severity,
                      title=title, ts=now, state=AlertState.OPEN.value, dedup_key=dedup_key,
                      first_seen=now, last_seen=now, occurrence_count=1, agent_id=agent_id,
                      drift_class=drift_class, risk_score=risk_score,
                      event_ids=tuple(dict.fromkeys(event_ids))[:50], detail=detail)
        actions = self._run_auto_actions(alert=alert, rule=rule, performed_by=performed_by)
        if actions:
            alert = Alert(**{**alert.__dict__, "actions_taken": tuple(actions)})
        self.store.put_alert(alert)
        self.audit.record(A.E_ALERT_RAISED, org_id=org_id, rule_id=rule.rule_id,
                          alert_id=alert.alert_id, agent_id=agent_id, outcome="ok",
                          extra={"severity": severity, "actions": ",".join(actions)})
        return alert

    # ------------------------------------------------------------------ lifecycle
    def transition(self, *, org_id: str, alert_id: str, new_state: str,
                   actor_user_id: Optional[str] = None, note: str = "") -> Alert:
        alert = self.store.get_alert(alert_id, org_id=org_id)
        if alert is None:
            raise AlertError("alert not found")
        target = AlertState.coerce(new_state)
        current = AlertState.coerce(alert.state)
        allowed = ALERT_STATE_TRANSITIONS.get(current, frozenset())
        if target not in allowed:
            raise AlertError(f"illegal alert transition: {current.value} -> {target.value}")
        updated = Alert(**{**alert.__dict__, "state": target.value, "last_seen": self._now(),
                           "note": note or alert.note})
        if target == AlertState.ACKNOWLEDGED:
            updated = Alert(**{**updated.__dict__, "acknowledged_by": actor_user_id})
        if target in ALERT_TERMINAL_STATES:
            updated = Alert(**{**updated.__dict__, "resolved_by": actor_user_id})
        self.store.put_alert(updated)
        self.audit.record(A.E_ALERT_STATE, org_id=org_id, alert_id=alert_id,
                          actor_user_id=actor_user_id, outcome="ok",
                          reason=f"{current.value}->{target.value}", extra={"note": note[:200]})
        return updated

    def list_alerts(self, *, org_id: str, state: Optional[str] = None,
                    agent_id: Optional[str] = None, limit: int = 100) -> List[Alert]:
        return self.store.list_alerts(org_id=org_id, state=state, agent_id=agent_id, limit=limit)

    def get_alert(self, *, org_id: str, alert_id: str) -> Optional[Alert]:
        return self.store.get_alert(alert_id, org_id=org_id)

    def investigation_view(self, *, org_id: str, alert_id: str) -> dict:
        """An alert plus the events/findings it references, for an investigator."""
        alert = self.store.get_alert(alert_id, org_id=org_id)
        if alert is None:
            raise AlertError("alert not found")
        events = []
        for eid in alert.event_ids:
            ev = self.store.get_event(eid, org_id=org_id)
            if ev is not None:
                events.append(ev.public_dict())
        return {"alert": alert.to_dict(), "events": events,
                "event_count": len(events),
                "note": ("only events recorded by instrumented integrations are shown; the "
                         "absence of an event is not evidence that nothing occurred")}

    # ------------------------------------------------------------------ response actions
    def _run_auto_actions(self, *, alert: Alert, rule: AlertRule, performed_by: str) -> List[str]:
        """Run a rule's automated response actions, delegated to existing mechanisms."""
        if not rule.auto_actions:
            return []
        if not self.cfg.allow_auto_actions:
            self.audit.record(A.E_RESPONSE_DENIED, org_id=alert.org_id, rule_id=rule.rule_id,
                              alert_id=alert.alert_id, agent_id=alert.agent_id, outcome="denied",
                              reason="auto_actions_disabled")
            return []
        taken: List[str] = []
        for raw in rule.auto_actions:
            action = ResponseAction.coerce(raw)
            if action is None:
                continue
            try:
                res = self._perform_action(action, alert=alert, performed_by=performed_by)
            except ResponseActionError as e:
                self.audit.record(A.E_RESPONSE_DENIED, org_id=alert.org_id, rule_id=rule.rule_id,
                                  alert_id=alert.alert_id, agent_id=alert.agent_id,
                                  outcome="error", reason=str(e)[:200], action=action.value)
                continue
            status = "ok" if res.performed else "unavailable"
            self.audit.record(A.E_RESPONSE_ACTION, org_id=alert.org_id, rule_id=rule.rule_id,
                              alert_id=alert.alert_id, agent_id=alert.agent_id, outcome=status,
                              action=action.value, extra={"mechanism": res.mechanism,
                                                          "detail": res.detail[:200]})
            taken.append(action.value if res.performed else f"{action.value}:{status}")
        return taken

    def _perform_action(self, action: ResponseAction, *, alert: Alert, performed_by: str):
        agent_id = alert.agent_id
        if agent_id is None:
            raise ResponseActionError("alert has no agent to act upon")
        if action == ResponseAction.REEVALUATE_POLICY:
            return self.integration.reevaluate(agent_id=agent_id, tenant=alert.org_id,
                                              action="runtime.reevaluate",
                                              resource=alert.rule_id,
                                              context={"alert_id": alert.alert_id})
        if action == ResponseAction.REVOKE_JIT_GRANT:
            return self.integration.revoke_grants_for_agent(
                org_id=alert.org_id, agent_id=agent_id,
                reason=f"runtime_alert:{alert.alert_id}", revoked_by=performed_by)
        if action == ResponseAction.REQUIRE_APPROVAL:
            return self.integration.request_approval(org_id=alert.org_id, agent_id=agent_id,
                                                     action="runtime.restrict",
                                                     resource=alert.rule_id,
                                                     reason=f"runtime alert {alert.alert_id}")
        if action == ResponseAction.NOTIFY_INCIDENT:
            # Pure notification: recorded in the audit stream (the incident-response seam).
            return type("R", (), {"available": True, "performed": True,
                                  "mechanism": "incident_notification",
                                  "detail": "incident notification recorded",
                                  "to_dict": lambda self: {}})()
        raise ResponseActionError(f"unsupported response action: {action}")


# --------------------------------------------------------------------------- helpers
def _severity_of_events(events: Sequence[RuntimeEvent]) -> Severity:
    best = Severity.INFO
    for e in events:
        s = Severity.coerce(e.severity)
        if s.rank > best.rank:
            best = s
    return best


def _max_severity(a, b) -> Severity:
    sa, sb = Severity.coerce(a), Severity.coerce(b)
    return sa if sa.rank >= sb.rank else sb


def _band_to_severity(band: str) -> Severity:
    return {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH,
            "critical": Severity.CRITICAL}.get(str(band).lower(), Severity.MEDIUM)
