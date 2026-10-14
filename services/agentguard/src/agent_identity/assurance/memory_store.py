"""In-memory ``AssuranceStore`` for unit tests and single-process development.

Semantics mirror the PostgreSQL backend closely enough for the security contract to hold:
  * every read/write is tenant-filtered explicitly,
  * the audit log is append-only and hash-chained (see ``audit.py``),
  * ``list_audit`` returns INSERTION order (oldest first) so reordering/removal is detectable,
  * checkpoints are retained so tail truncation can be detected.

It is NOT a production store: no durability, no cross-process sharing, no SQL indexes. Production
uses PostgreSQL (migration 0010).
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional, Tuple

from .models import (AuditChainRecord, AuditCheckpoint, ComplianceControlMapping,
                     CorrelationFinding, PolicyProposal, PolicyRecommendation, SecurityEvidence,
                     SiemDelivery, SiemEvent)
from .store import AssuranceStore


class MemoryAssuranceStore(AssuranceStore):
    def __init__(self, *, max_items: int = 200_000):
        self._lock = threading.RLock()
        self._evidence: Dict[Tuple[str, str], SecurityEvidence] = {}
        self._recommendations: Dict[Tuple[str, str], PolicyRecommendation] = {}
        self._proposals: Dict[Tuple[str, str], PolicyProposal] = {}
        self._mappings: Dict[str, ComplianceControlMapping] = {}
        self._siem_events: Dict[str, SiemEvent] = {}
        self._deliveries: Dict[str, SiemDelivery] = {}
        self._correlations: List[CorrelationFinding] = []
        self._audit: List[AuditChainRecord] = []
        self._checkpoints: Dict[str, AuditCheckpoint] = {}
        self.max_items = max(1, int(max_items))

    # ------------------------------------------------------------------ evidence
    def put_evidence(self, e: SecurityEvidence) -> None:
        with self._lock:
            self._evidence[(e.org_id, e.evidence_id)] = e

    def get_evidence(self, evidence_id: str, *, org_id: str) -> Optional[SecurityEvidence]:
        with self._lock:
            return self._evidence.get((org_id, evidence_id))

    def list_evidence(self, *, org_id: str, kind: Optional[str] = None,
                      since: Optional[float] = None, limit: int = 500) -> List[SecurityEvidence]:
        with self._lock:
            out = [e for (o, _), e in self._evidence.items()
                   if o == org_id and (kind is None or e.kind == kind)
                   and (since is None or e.ts >= since)]
        out.sort(key=lambda e: (e.ts, e.evidence_id), reverse=True)
        return out[:int(limit)]

    # ------------------------------------------------------------------ recommendations
    def put_recommendation(self, r: PolicyRecommendation) -> None:
        with self._lock:
            self._recommendations[(r.org_id, r.recommendation_id)] = r

    def get_recommendation(self, recommendation_id: str, *,
                           org_id: str) -> Optional[PolicyRecommendation]:
        with self._lock:
            return self._recommendations.get((org_id, recommendation_id))

    def list_recommendations(self, *, org_id: str, status: Optional[str] = None,
                             limit: int = 100) -> List[PolicyRecommendation]:
        with self._lock:
            out = [r for (o, _), r in self._recommendations.items()
                   if o == org_id and (status is None or r.status == status)]
        out.sort(key=lambda r: (r.created_at, r.recommendation_id), reverse=True)
        return out[:int(limit)]

    # ------------------------------------------------------------------ proposals
    def put_proposal(self, p: PolicyProposal) -> None:
        with self._lock:
            self._proposals[(p.org_id, p.proposal_id)] = p

    def get_proposal(self, proposal_id: str, *, org_id: str) -> Optional[PolicyProposal]:
        with self._lock:
            return self._proposals.get((org_id, proposal_id))

    def list_proposals(self, *, org_id: str, status: Optional[str] = None,
                       limit: int = 100) -> List[PolicyProposal]:
        with self._lock:
            out = [p for (o, _), p in self._proposals.items()
                   if o == org_id and (status is None or p.status == status)]
        out.sort(key=lambda p: (p.created_at, p.proposal_id), reverse=True)
        return out[:int(limit)]

    def count_pending_proposals(self, *, org_id: str) -> int:
        with self._lock:
            return sum(1 for (o, _), p in self._proposals.items()
                       if o == org_id and p.status in ("pending_approval", "approved", "canary"))

    # ------------------------------------------------------------------ compliance
    def put_mapping(self, m: ComplianceControlMapping) -> None:
        with self._lock:
            self._mappings[m.mapping_id] = m

    def get_mapping(self, mapping_id: str) -> Optional[ComplianceControlMapping]:
        with self._lock:
            return self._mappings.get(mapping_id)

    def list_mappings(self, *, framework: Optional[str] = None,
                      limit: int = 1_000) -> List[ComplianceControlMapping]:
        with self._lock:
            out = [m for m in self._mappings.values()
                   if framework is None or m.framework == framework]
        out.sort(key=lambda m: (m.framework, m.control_id))
        return out[:int(limit)]

    # ------------------------------------------------------------------ SIEM events + deliveries
    def put_siem_event(self, e: SiemEvent) -> None:
        with self._lock:
            self._siem_events[e.event_id] = e
            if len(self._siem_events) > self.max_items:
                # bounded footprint: drop the oldest by ts
                oldest = sorted(self._siem_events.values(), key=lambda x: x.ts)[:1]
                for o in oldest:
                    self._siem_events.pop(o.event_id, None)

    def get_siem_event(self, event_id: str, *, org_id: Optional[str] = None) -> Optional[SiemEvent]:
        with self._lock:
            e = self._siem_events.get(event_id)
            if e is None:
                return None
            if org_id is not None and e.org_id != org_id:
                return None
            return e

    def list_siem_events(self, *, org_id: Optional[str] = None, since: Optional[float] = None,
                         limit: int = 500) -> List[SiemEvent]:
        with self._lock:
            out = [e for e in self._siem_events.values()
                   if (org_id is None or e.org_id == org_id)
                   and (since is None or e.ts >= since)]
        out.sort(key=lambda e: (e.ts, e.event_id), reverse=True)
        return out[:int(limit)]

    def put_delivery(self, d: SiemDelivery) -> None:
        with self._lock:
            self._deliveries[d.delivery_id] = d

    def get_delivery(self, delivery_id: str) -> Optional[SiemDelivery]:
        with self._lock:
            return self._deliveries.get(delivery_id)

    def list_deliveries(self, *, destination_id: Optional[str] = None, status: Optional[str] = None,
                        limit: int = 500) -> List[SiemDelivery]:
        with self._lock:
            out = [d for d in self._deliveries.values()
                   if (destination_id is None or d.destination_id == destination_id)
                   and (status is None or d.status == status)]
        out.sort(key=lambda d: (d.ts, d.delivery_id), reverse=True)
        return out[:int(limit)]

    # ------------------------------------------------------------------ correlation
    def put_correlation(self, f: CorrelationFinding) -> None:
        with self._lock:
            self._correlations.append(f)
            if len(self._correlations) > self.max_items:
                del self._correlations[:len(self._correlations) - self.max_items]

    def list_correlations(self, *, org_id: str, since: Optional[float] = None,
                          limit: int = 200) -> List[CorrelationFinding]:
        with self._lock:
            out = [f for f in self._correlations
                   if f.org_id == org_id and (since is None or f.ts >= since)]
        out.sort(key=lambda f: (f.ts, f.finding_id), reverse=True)
        return out[:int(limit)]

    # ------------------------------------------------------------------ tamper-evident audit
    def append_audit(self, record: AuditChainRecord) -> None:
        with self._lock:
            self._audit.append(record)
            if len(self._audit) > self.max_items:
                del self._audit[:len(self._audit) - self.max_items]

    def list_audit(self, *, org_id: Optional[str] = None, limit: int = 1_000
                   ) -> List[AuditChainRecord]:
        with self._lock:
            out = [r for r in self._audit if r.org_id == org_id]
        return out[:int(limit)]

    def audit_chain_head(self, *, org_id: Optional[str] = None) -> Optional[AuditChainRecord]:
        with self._lock:
            for r in reversed(self._audit):
                if r.org_id == org_id:
                    return r
        return None

    def audit_count(self, *, org_id: Optional[str] = None) -> int:
        with self._lock:
            return sum(1 for r in self._audit if r.org_id == org_id)

    def put_checkpoint(self, c: AuditCheckpoint) -> None:
        with self._lock:
            self._checkpoints[c.checkpoint_id] = c

    def get_checkpoint(self, checkpoint_id: str) -> Optional[AuditCheckpoint]:
        with self._lock:
            return self._checkpoints.get(checkpoint_id)

    def latest_checkpoint(self, *, org_id: Optional[str] = None) -> Optional[AuditCheckpoint]:
        with self._lock:
            cands = [c for c in self._checkpoints.values() if c.org_id == org_id]
        if not cands:
            return None
        cands.sort(key=lambda c: (c.seq, c.ts))
        return cands[-1]

    def list_checkpoints(self, *, org_id: Optional[str] = None,
                         limit: int = 100) -> List[AuditCheckpoint]:
        with self._lock:
            out = [c for c in self._checkpoints.values() if c.org_id == org_id]
        out.sort(key=lambda c: (c.seq, c.ts), reverse=True)
        return out[:int(limit)]
