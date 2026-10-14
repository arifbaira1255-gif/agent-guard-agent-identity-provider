"""Phase 7 cross-system security event correlation.

Integrates SIEM exports with the existing runtime event pipeline and incident-management system.
Supports (requirement 7):

  * consistent event identifiers and correlation ids,
  * severity normalization into a closed set,
  * event deduplication (a bounded window keyed by a stable dedup key),
  * related incident references,
  * policy and agent context,
  * delivery-failure visibility (delegated to the SIEM service),
  * provenance preservation: an ORIGINAL evidence event is never replaced by a DERIVED analytics
    event -- a correlation finding REFERENCES the original event ids.

It avoids exporting duplicate or excessively sensitive data: a duplicate event is suppressed (and
recorded), and the SIEM exporter applies the classification/redaction gate before anything leaves.
"""
from __future__ import annotations

import hashlib
import time
from collections import deque
from typing import Dict, List, Optional, Sequence, Tuple

from ..security.ids import new_id
from .config import AssuranceConfig
from .models import (CorrelationFinding, Provenance, SiemEvent, normalize_severity, severity_rank)
from .store import AssuranceStore


def dedup_key(*, org_id: Optional[str], category: str, action: str, outcome: str,
              agent_id: Optional[str] = None, subject: Optional[str] = None) -> str:
    """A stable dedup key over the fields that make two events 'the same event'."""
    blob = "|".join([org_id or "", category, action, outcome, agent_id or "", subject or ""])
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


class CorrelationService:
    """Normalizes, deduplicates and correlates security events across systems."""

    def __init__(self, store: AssuranceStore, *, config: Optional[AssuranceConfig] = None,
                 clock=None):
        self.store = store
        self.cfg = config or AssuranceConfig()
        self._clock = clock
        self._seen: Dict[Tuple[Optional[str], str], float] = {}
        self._recent: deque = deque(maxlen=self.cfg.correlation_max_events)

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ normalize
    def normalize(self, *, org_id: Optional[str], category: str, action: str, outcome: str,
                  source: str, severity: str = "medium", agent_id: Optional[str] = None,
                  correlation_id: Optional[str] = None, classification: str = "internal",
                  provenance: str = Provenance.OBSERVED_FACT.value,
                  incident_id: Optional[str] = None, policy_id: Optional[str] = None,
                  policy_version: Optional[str] = None, fields: Optional[dict] = None,
                  subject: Optional[str] = None, ts: Optional[float] = None) -> SiemEvent:
        """Build a normalized event with a consistent id, correlation id and dedup key."""
        return SiemEvent(
            event_id=new_id("sev"), ts=ts if ts is not None else self._now(), org_id=org_id,
            severity=normalize_severity(severity), category=category, action=action, outcome=outcome,
            source=source, dedup_key=dedup_key(org_id=org_id, category=category, action=action,
                                               outcome=outcome, agent_id=agent_id, subject=subject),
            correlation_id=correlation_id or new_id("cor"), agent_id=agent_id,
            classification=classification, provenance=provenance, incident_id=incident_id,
            policy_id=policy_id, policy_version=policy_version, fields=fields)

    # ------------------------------------------------------------------ dedup
    def is_duplicate(self, event: SiemEvent) -> bool:
        """True when an identical event (same tenant + dedup key) was seen inside the window."""
        now = self._now()
        key = (event.org_id, event.dedup_key)
        last = self._seen.get(key)
        if last is not None and now - last <= self.cfg.correlation_dedup_window_s:
            return True
        self._seen[key] = now
        # bound the dedup map
        if len(self._seen) > self.cfg.correlation_max_events:
            cutoff = now - self.cfg.correlation_dedup_window_s
            for k in [k for k, v in self._seen.items() if v < cutoff]:
                self._seen.pop(k, None)
        return False

    # ------------------------------------------------------------------ ingest
    def ingest(self, event: SiemEvent) -> dict:
        """Record an event, suppressing duplicates. Returns ``{"accepted", "duplicate"}``."""
        if self.is_duplicate(event):
            return {"accepted": False, "duplicate": True, "event_id": event.event_id}
        self.store.put_siem_event(event)
        self._recent.append(event)
        return {"accepted": True, "duplicate": False, "event_id": event.event_id}

    # ------------------------------------------------------------------ correlate
    def correlate(self, *, org_id: str, window_s: Optional[int] = None,
                  min_events: int = 3) -> List[CorrelationFinding]:
        """Correlate recent events for a tenant into findings.

        A finding is DERIVED analytics: it references the original event ids and preserves their
        provenance. Correlation is key-based (agent + category), never time-based alone.
        """
        window = window_s if window_s is not None else self.cfg.correlation_dedup_window_s
        cutoff = self._now() - window
        events = [e for e in self._recent if e.org_id == org_id and e.ts >= cutoff]
        groups: Dict[Tuple[str, str], List[SiemEvent]] = {}
        for e in events:
            groups.setdefault((e.agent_id or "unknown", e.category), []).append(e)
        findings: List[CorrelationFinding] = []
        for (agent, category), group in groups.items():
            if len(group) < min_events:
                continue
            max_sev = max((severity_rank(e.severity) for e in group), default=2)
            severity = ("info", "low", "medium", "high", "critical")[max_sev]
            # a correlation id shared by the group, else a fresh one
            cid = next((e.correlation_id for e in group if e.correlation_id), None) or new_id("cor")
            incident_id = next((e.incident_id for e in group if e.incident_id), None)
            policy_id = next((e.policy_id for e in group if e.policy_id), None)
            f = CorrelationFinding(
                finding_id=new_id("crf"), org_id=org_id, correlation_id=cid, ts=self._now(),
                severity=severity,
                summary=f"{len(group)} correlated '{category}' events for agent '{agent}'",
                event_ids=tuple(e.event_id for e in group[:200]),
                dedup_key=dedup_key(org_id=org_id, category=category, action="correlated",
                                    outcome="derived", agent_id=agent),
                related_incident_id=incident_id, policy_id=policy_id, agent_id=agent,
                provenance=Provenance.DERIVED.value,
                detail={"event_count": len(group), "category": category})
            self.store.put_correlation(f)
            findings.append(f)
        return findings

    def list_findings(self, *, org_id: str, limit: int = 200) -> List[dict]:
        return [f.public_dict() for f in self.store.list_correlations(org_id=org_id, limit=limit)]
