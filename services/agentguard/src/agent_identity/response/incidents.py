"""Phase 6 security incident management.

A structured incident lifecycle: detection -> triage -> investigation -> containment -> recovery ->
closure -> post-incident review, with validated transitions, a bounded timeline, evidence references,
ownership and resolution notes.

Correlation rule (deliberately conservative)
--------------------------------------------
Alerts/findings are correlated into an incident only when they share a **correlation key** -- the
same tenant, the same agent and the same primary subject (resource or destination). Time proximity
alone is NEVER sufficient: two unrelated events that merely happened close together stay separate
incidents. The window is applied as a secondary constraint on top of the key, not as the key itself.

Honest limitation: correlation is key-based, so a genuinely multi-agent campaign that shares no
subject will appear as several incidents. That is a documented coverage limit, not a silent failure.
"""
from __future__ import annotations

import dataclasses
import time
from typing import Iterable, List, Optional, Sequence

from ..runtime_monitoring.models import Severity
from ..security.ids import new_id
from .config import ResponseConfig
from .errors import IncidentError, ResponsePlaneError
from .models import (INCIDENT_STATE_TRANSITIONS, INCIDENT_TERMINAL_STATES, Incident,
                     IncidentStatus, IncidentTimelineEntry)


class IncidentService:
    """Incident lifecycle + correlation over the shared response store."""

    def __init__(self, store, *, config: Optional[ResponseConfig] = None, audit=None, clock=None):
        self.store = store
        self.cfg = config or ResponseConfig()
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ correlation key
    @staticmethod
    def correlation_key(*, agent_id: Optional[str], subject: Optional[str]) -> str:
        """The key that decides whether two detections belong to the same incident.

        Requires BOTH an agent and a subject. Without a subject there is nothing to correlate on, so
        the key is unique per detection (``""``) and the detection opens its own incident rather than
        being merged on time proximity.
        """
        if not agent_id or not subject:
            return ""
        return f"{agent_id}|{subject}"[:512]

    # ------------------------------------------------------------------ open / correlate
    def open_or_correlate(self, *, org_id: str, title: str, agent_id: Optional[str] = None,
                          subject: Optional[str] = None, severity: str = Severity.MEDIUM.value,
                          detection_source: str = "", alert_ids: Sequence[str] = (),
                          finding_ids: Sequence[str] = (), resources: Sequence[str] = (),
                          risk_score: Optional[float] = None, risk_band: Optional[str] = None,
                          owner: Optional[str] = None, now: Optional[float] = None) -> Incident:
        """Open a new incident, or attach to the existing open one for the same correlation key."""
        current = now if now is not None else self._now()
        key = self.correlation_key(agent_id=agent_id, subject=subject)
        if key:
            existing = self.store.find_open_incident(org_id=org_id, correlation_key=key)
            if existing is not None and \
                    current - existing.updated_at <= self.cfg.incident_correlation_window_s:
                return self.attach(org_id=org_id, incident_id=existing.incident_id,
                                   alert_ids=alert_ids, finding_ids=finding_ids,
                                   resources=resources, severity=severity,
                                   risk_score=risk_score, risk_band=risk_band,
                                   detail=f"correlated detection from {detection_source or 'unknown'}",
                                   now=current)
        if self.store.count_open_incidents(org_id=org_id) >= self.cfg.incident_max_open:
            raise IncidentError("too many open incidents for this tenant")
        inc = Incident(
            incident_id=new_id("inc"), org_id=org_id, title=title[:512],
            severity=Severity.coerce(severity).value, status=IncidentStatus.DETECTED.value,
            opened_at=current, updated_at=current, owner=owner,
            agent_ids=tuple(a for a in {agent_id} if a),
            resources=tuple(dict.fromkeys(resources))[:64],
            alert_ids=tuple(dict.fromkeys(alert_ids))[:64],
            finding_ids=tuple(dict.fromkeys(finding_ids))[:64],
            detection_source=detection_source[:512], risk_score=risk_score, risk_band=risk_band,
            correlation_key=key)
        self._append(inc, kind="detected", detail=f"incident opened by {detection_source or 'system'}",
                     ref=inc.incident_id, now=current)
        self.store.put_incident(inc)
        self._audit("response.incident.opened", org_id=org_id, agent_id=agent_id,
                    extra={"incident_id": inc.incident_id, "severity": inc.severity,
                           "correlation_key": key})
        return inc

    def attach(self, *, org_id: str, incident_id: str, alert_ids: Sequence[str] = (),
               finding_ids: Sequence[str] = (), resources: Sequence[str] = (),
               severity: Optional[str] = None, risk_score: Optional[float] = None,
               risk_band: Optional[str] = None, detail: str = "",
               now: Optional[float] = None) -> Incident:
        """Attach further detections to an existing incident (idempotent per reference)."""
        inc = self._require(org_id=org_id, incident_id=incident_id)
        if inc.status in {s.value for s in INCIDENT_TERMINAL_STATES}:
            raise IncidentError("cannot attach to a closed incident")
        current = now if now is not None else self._now()
        inc.alert_ids = tuple(dict.fromkeys(inc.alert_ids + tuple(alert_ids)))[:64]
        inc.finding_ids = tuple(dict.fromkeys(inc.finding_ids + tuple(finding_ids)))[:64]
        inc.resources = tuple(dict.fromkeys(inc.resources + tuple(resources)))[:64]
        if severity is not None:
            inc.severity = _max_severity(inc.severity, severity)
        if risk_score is not None:
            inc.risk_score = max(inc.risk_score or 0.0, risk_score)
        if risk_band is not None:
            inc.risk_band = risk_band
        self._append(inc, kind="correlated", detail=detail or "additional detection correlated",
                     now=current)
        inc.updated_at = current
        self.store.put_incident(inc)
        return inc

    # ------------------------------------------------------------------ lifecycle
    def transition(self, *, org_id: str, incident_id: str, new_status: str,
                   actor_user_id: Optional[str] = None, note: str = "",
                   now: Optional[float] = None) -> Incident:
        """Move an incident through the lifecycle, validating the transition."""
        inc = self._require(org_id=org_id, incident_id=incident_id)
        target = IncidentStatus.coerce(new_status)
        current_status = IncidentStatus.coerce(inc.status)
        if target == current_status:
            return inc
        allowed = INCIDENT_STATE_TRANSITIONS.get(current_status, frozenset())
        if target not in allowed:
            raise IncidentError(
                f"invalid incident transition {current_status.value} -> {target.value}")
        current = now if now is not None else self._now()
        inc.status = target.value
        inc.updated_at = current
        if target in INCIDENT_TERMINAL_STATES:
            inc.closed_at = current
        if actor_user_id and inc.owner is None:
            inc.owner = actor_user_id
        self._append(inc, kind=f"status:{target.value}", detail=note or "status changed",
                     actor=actor_user_id, now=current)
        self.store.put_incident(inc)
        self._audit("response.incident.transition", org_id=org_id, actor_user_id=actor_user_id,
                    extra={"incident_id": incident_id, "status": target.value})
        return inc

    def assign(self, *, org_id: str, incident_id: str, owner: str,
               actor_user_id: Optional[str] = None) -> Incident:
        inc = self._require(org_id=org_id, incident_id=incident_id)
        inc.owner = owner
        inc.updated_at = self._now()
        self._append(inc, kind="assigned", detail=f"owner set to {owner}", actor=actor_user_id)
        self.store.put_incident(inc)
        return inc

    def resolve(self, *, org_id: str, incident_id: str, resolution: str,
                actor_user_id: Optional[str] = None) -> Incident:
        """Close an incident with a resolution note (the closure step of the lifecycle)."""
        inc = self._require(org_id=org_id, incident_id=incident_id)
        inc.resolution = resolution[:2000]
        return self.transition(org_id=org_id, incident_id=incident_id,
                               new_status=IncidentStatus.CLOSED.value,
                               actor_user_id=actor_user_id, note="incident closed")

    def post_review(self, *, org_id: str, incident_id: str, review: str,
                    actor_user_id: Optional[str] = None) -> Incident:
        inc = self._require(org_id=org_id, incident_id=incident_id)
        inc.post_review = review[:2000]
        return self.transition(org_id=org_id, incident_id=incident_id,
                               new_status=IncidentStatus.POST_REVIEW.value,
                               actor_user_id=actor_user_id, note="post-incident review recorded")

    # ------------------------------------------------------------------ references
    def link_evidence(self, *, org_id: str, incident_id: str, evidence_ids: Sequence[str],
                      actor_user_id: Optional[str] = None) -> Incident:
        inc = self._require(org_id=org_id, incident_id=incident_id)
        inc.evidence_ids = tuple(dict.fromkeys(inc.evidence_ids + tuple(evidence_ids)))[:64]
        inc.updated_at = self._now()
        self._append(inc, kind="evidence", detail=f"{len(evidence_ids)} evidence item(s) linked",
                     actor=actor_user_id)
        self.store.put_incident(inc)
        return inc

    def link_response(self, *, org_id: str, incident_id: str, response_id: str,
                      actor_user_id: Optional[str] = None) -> Incident:
        inc = self._require(org_id=org_id, incident_id=incident_id)
        inc.response_ids = tuple(dict.fromkeys(inc.response_ids + (response_id,)))[:64]
        inc.updated_at = self._now()
        self._append(inc, kind="response", detail=f"containment execution {response_id} linked",
                     actor=actor_user_id, ref=response_id)
        self.store.put_incident(inc)
        return inc

    # ------------------------------------------------------------------ reads
    def get(self, *, org_id: str, incident_id: str) -> Optional[Incident]:
        return self.store.get_incident(incident_id, org_id=org_id)

    def list(self, *, org_id: str, status: Optional[str] = None, agent_id: Optional[str] = None,
             since: Optional[float] = None, limit: int = 100) -> List[Incident]:
        return self.store.list_incidents(org_id=org_id, status=status, agent_id=agent_id,
                                         since=since, limit=limit)

    def investigation_view(self, *, org_id: str, incident_id: str) -> dict:
        """An incident plus its linked evidence and containment executions."""
        inc = self._require(org_id=org_id, incident_id=incident_id)
        evidence = [self.store.get_evidence(eid, org_id=org_id) for eid in inc.evidence_ids]
        responses = [self.store.get_response(rid, org_id=org_id) for rid in inc.response_ids]
        return {"incident": inc.public_dict(),
                "evidence": [e.to_dict() for e in evidence if e is not None],
                "responses": [r.public_dict() for r in responses if r is not None],
                "note": ("only detections recorded by instrumented integrations are represented; "
                         "the absence of a detection is not evidence that nothing occurred")}

    # ------------------------------------------------------------------ helpers
    def _require(self, *, org_id: str, incident_id: str) -> Incident:
        inc = self.store.get_incident(incident_id, org_id=org_id)
        if inc is None:
            raise IncidentError("incident not found")
        return inc

    def _append(self, inc: Incident, *, kind: str, detail: str, actor: Optional[str] = None,
                ref: Optional[str] = None, now: Optional[float] = None) -> None:
        inc.timeline.append(IncidentTimelineEntry(
            ts=now if now is not None else self._now(), kind=kind[:64], detail=detail[:512],
            actor=actor, ref=ref))
        if len(inc.timeline) > self.cfg.incident_max_timeline:
            del inc.timeline[:len(inc.timeline) - self.cfg.incident_max_timeline]

    def _audit(self, event: str, *, org_id: Optional[str] = None, agent_id: Optional[str] = None,
               outcome: str = "ok", reason: Optional[str] = None,
               actor_user_id: Optional[str] = None, extra: Optional[dict] = None) -> None:
        if self.audit is not None:
            self.audit.record(event, org_id=org_id, agent_id=agent_id, outcome=outcome,
                              reason=reason, actor_user_id=actor_user_id, extra=extra)


def _max_severity(a, b) -> str:
    sa, sb = Severity.coerce(a), Severity.coerce(b)
    return (sa if sa.rank >= sb.rank else sb).value
