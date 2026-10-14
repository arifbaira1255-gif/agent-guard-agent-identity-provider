"""In-memory ``ResponseStore`` for unit tests and single-process development.

Semantics mirror the PostgreSQL backend closely enough for the security contract to hold:
  * every read/write is tenant-filtered explicitly,
  * containment executions are idempotent by ``(org_id, idempotency_key)``,
  * the audit log is append-only and hash-chained (see ``audit.py``),
  * ``purge_evidence_before`` is the only deletion path and is org-scoped when an org is given.

It is NOT a production store: no durability, no cross-process sharing, no SQL indexes. Production
uses PostgreSQL (migration 0009).
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional, Tuple

from .models import (ApprovalRequest, EmergencyStop, EvidenceRecord, ExecutionBudget, Incident,
                     LoopFinding, ResponseExecution)
from .store import ResponseStore

#: Maps a budget dimension to the usage-counter attribute it increments.
_USED_ATTR = {"actions": "actions_used", "retries": "retries_used", "requests": "requests_used",
              "concurrency": "concurrency_used", "tokens": "tokens_used", "cost": "cost_used"}


class MemoryResponseStore(ResponseStore):
    def __init__(self, *, max_items: int = 200_000):
        self._lock = threading.RLock()
        self._loop_findings: List[LoopFinding] = []
        self._budgets: Dict[Tuple[str, str], ExecutionBudget] = {}
        self._stops: Dict[Tuple[str, str], EmergencyStop] = {}
        self._approvals: Dict[Tuple[str, str], ApprovalRequest] = {}
        self._incidents: Dict[Tuple[str, str], Incident] = {}
        self._responses: Dict[Tuple[str, str], ResponseExecution] = {}
        self._evidence: Dict[Tuple[str, str], EvidenceRecord] = {}
        self._audit: List[dict] = []
        self.max_items = max(1, int(max_items))

    # ------------------------------------------------------------------ loop findings
    def put_loop_finding(self, f: LoopFinding) -> None:
        with self._lock:
            self._loop_findings.append(f)
            if len(self._loop_findings) > self.max_items:
                del self._loop_findings[:len(self._loop_findings) - self.max_items]

    def list_loop_findings(self, *, org_id: str, agent_id: Optional[str] = None,
                           pattern: Optional[str] = None, since: Optional[float] = None,
                           limit: int = 100) -> List[LoopFinding]:
        with self._lock:
            out = [f for f in self._loop_findings
                   if f.org_id == org_id
                   and (agent_id is None or f.agent_id == agent_id)
                   and (pattern is None or f.pattern == pattern)
                   and (since is None or f.ts >= since)]
        out.sort(key=lambda f: (f.ts, f.finding_id), reverse=True)
        return out[:int(limit)]

    # ------------------------------------------------------------------ budgets
    def put_budget(self, b: ExecutionBudget) -> None:
        with self._lock:
            self._budgets[(b.org_id, b.budget_id)] = b

    def get_budget(self, budget_id: str, *, org_id: str) -> Optional[ExecutionBudget]:
        with self._lock:
            return self._budgets.get((org_id, budget_id))

    def find_budget(self, *, org_id: str, agent_id: Optional[str] = None,
                    task_id: Optional[str] = None) -> Optional[ExecutionBudget]:
        with self._lock:
            cands = [b for (o, _), b in self._budgets.items()
                     if o == org_id and b.enabled
                     and ((task_id is not None and b.task_id == task_id)
                          or (task_id is None and agent_id is not None and b.task_id is None
                              and b.agent_id == agent_id))]
        if not cands:
            return None
        # A task-scoped budget is more specific than an agent-scoped one.
        cands.sort(key=lambda b: (b.task_id is None, b.updated_at), reverse=False)
        return cands[0]

    def list_budgets(self, *, org_id: str, limit: int = 200) -> List[ExecutionBudget]:
        with self._lock:
            out = [b for (o, _), b in self._budgets.items() if o == org_id]
        out.sort(key=lambda b: b.updated_at, reverse=True)
        return out[:int(limit)]

    def delete_budget(self, budget_id: str, *, org_id: str) -> None:
        with self._lock:
            self._budgets.pop((org_id, budget_id), None)

    def consume_budget(self, budget_id: str, *, org_id: str, dimension: str, amount: float,
                       now: float, limit: Optional[float] = None) -> Optional[ExecutionBudget]:
        """Lock-guarded read-modify-write. When ``limit`` is set the increment is conditional and
        ``None`` is returned when it would exceed (so a refused op never advances the counter)."""
        attr = _USED_ATTR.get(dimension)
        if attr is None:
            raise ValueError(f"unknown budget dimension: {dimension}")
        with self._lock:
            b = self._budgets.get((org_id, budget_id))
            if b is None:
                return None
            current = getattr(b, attr)
            if limit is not None and amount > 0 and current + amount > limit:
                return None
            new = current + amount
            if new < 0:
                new = 0
            if attr == "cost_used":
                new = round(float(new), 6)
            else:
                new = int(new)
            setattr(b, attr, new)
            b.updated_at = now
            return b

    # ------------------------------------------------------------------ emergency stops
    def put_stop(self, s: EmergencyStop) -> None:
        with self._lock:
            self._stops[(s.org_id, s.stop_id)] = s

    def get_stop(self, stop_id: str, *, org_id: str) -> Optional[EmergencyStop]:
        with self._lock:
            return self._stops.get((org_id, stop_id))

    def find_active_stop(self, *, org_id: str, agent_id: Optional[str] = None,
                         task_id: Optional[str] = None) -> Optional[EmergencyStop]:
        with self._lock:
            cands = [s for (o, _), s in self._stops.items()
                     if o == org_id and s.active
                     and ((task_id is not None and s.task_id == task_id)
                          or (agent_id is not None and s.agent_id == agent_id))]
        if not cands:
            return None
        cands.sort(key=lambda s: s.ts, reverse=True)
        return cands[0]

    def list_stops(self, *, org_id: str, active_only: bool = False,
                   limit: int = 200) -> List[EmergencyStop]:
        with self._lock:
            out = [s for (o, _), s in self._stops.items()
                   if o == org_id and (not active_only or s.active)]
        out.sort(key=lambda s: s.ts, reverse=True)
        return out[:int(limit)]

    # ------------------------------------------------------------------ approvals
    def put_approval(self, a: ApprovalRequest) -> None:
        with self._lock:
            self._approvals[(a.org_id, a.approval_id)] = a

    def get_approval(self, approval_id: str, *, org_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            return self._approvals.get((org_id, approval_id))

    def find_approval_by_fingerprint(self, *, org_id: str, fingerprint: str
                                     ) -> Optional[ApprovalRequest]:
        with self._lock:
            cands = [a for (o, _), a in self._approvals.items()
                     if o == org_id and a.fingerprint == fingerprint]
        if not cands:
            return None
        cands.sort(key=lambda a: a.requested_at, reverse=True)
        return cands[0]

    def list_approvals(self, *, org_id: str, status: Optional[str] = None,
                       agent_id: Optional[str] = None, limit: int = 100) -> List[ApprovalRequest]:
        with self._lock:
            out = [a for (o, _), a in self._approvals.items()
                   if o == org_id and (status is None or a.status == status)
                   and (agent_id is None or a.agent_id == agent_id)]
        out.sort(key=lambda a: a.requested_at, reverse=True)
        return out[:int(limit)]

    def count_pending_approvals(self, *, org_id: str, agent_id: str) -> int:
        with self._lock:
            return sum(1 for (o, _), a in self._approvals.items()
                       if o == org_id and a.agent_id == agent_id and a.status == "pending")

    # ------------------------------------------------------------------ incidents
    def put_incident(self, i: Incident) -> None:
        with self._lock:
            self._incidents[(i.org_id, i.incident_id)] = i

    def get_incident(self, incident_id: str, *, org_id: str) -> Optional[Incident]:
        with self._lock:
            return self._incidents.get((org_id, incident_id))

    def list_incidents(self, *, org_id: str, status: Optional[str] = None,
                       agent_id: Optional[str] = None, since: Optional[float] = None,
                       limit: int = 100) -> List[Incident]:
        with self._lock:
            out = [i for (o, _), i in self._incidents.items()
                   if o == org_id and (status is None or i.status == status)
                   and (agent_id is None or agent_id in i.agent_ids)
                   and (since is None or i.opened_at >= since)]
        out.sort(key=lambda i: i.opened_at, reverse=True)
        return out[:int(limit)]

    def find_open_incident(self, *, org_id: str, correlation_key: str) -> Optional[Incident]:
        with self._lock:
            cands = [i for (o, _), i in self._incidents.items()
                     if o == org_id and i.correlation_key == correlation_key
                     and i.status not in ("closed", "post_review")]
        if not cands:
            return None
        cands.sort(key=lambda i: i.opened_at, reverse=True)
        return cands[0]

    def count_open_incidents(self, *, org_id: str) -> int:
        with self._lock:
            return sum(1 for (o, _), i in self._incidents.items()
                       if o == org_id and i.status not in ("closed", "post_review"))

    # ------------------------------------------------------------------ responses
    def put_response(self, r: ResponseExecution) -> None:
        with self._lock:
            self._responses[(r.org_id, r.response_id)] = r

    def get_response(self, response_id: str, *, org_id: str) -> Optional[ResponseExecution]:
        with self._lock:
            return self._responses.get((org_id, response_id))

    def get_response_by_key(self, *, org_id: str, idempotency_key: str
                            ) -> Optional[ResponseExecution]:
        with self._lock:
            for (o, _), r in self._responses.items():
                if o == org_id and r.idempotency_key == idempotency_key:
                    return r
        return None

    def list_responses(self, *, org_id: str, incident_id: Optional[str] = None,
                       agent_id: Optional[str] = None, limit: int = 100
                       ) -> List[ResponseExecution]:
        with self._lock:
            out = [r for (o, _), r in self._responses.items()
                   if o == org_id and (incident_id is None or r.incident_id == incident_id)
                   and (agent_id is None or r.agent_id == agent_id)]
        out.sort(key=lambda r: r.created_at, reverse=True)
        return out[:int(limit)]

    # ------------------------------------------------------------------ evidence
    def put_evidence(self, e: EvidenceRecord) -> None:
        with self._lock:
            self._evidence[(e.org_id, e.evidence_id)] = e

    def get_evidence(self, evidence_id: str, *, org_id: str) -> Optional[EvidenceRecord]:
        with self._lock:
            return self._evidence.get((org_id, evidence_id))

    def list_evidence(self, *, org_id: str, incident_id: Optional[str] = None,
                      limit: int = 200) -> List[EvidenceRecord]:
        with self._lock:
            out = [e for (o, _), e in self._evidence.items()
                   if o == org_id and (incident_id is None or e.incident_id == incident_id)]
        out.sort(key=lambda e: e.ts, reverse=True)
        return out[:int(limit)]

    def purge_evidence_before(self, cutoff_ts: float, *, org_id: Optional[str] = None) -> int:
        with self._lock:
            doomed = [k for k, e in self._evidence.items()
                      if e.ts < cutoff_ts and (org_id is None or e.org_id == org_id)
                      and not e.sealed]
            for k in doomed:
                del self._evidence[k]
            return len(doomed)

    # ------------------------------------------------------------------ audit
    def append_audit(self, event: dict) -> None:
        with self._lock:
            self._audit.append(dict(event))
            if len(self._audit) > self.max_items:
                del self._audit[:len(self._audit) - self.max_items]

    def list_audit(self, *, org_id: Optional[str] = None, limit: int = 100) -> List[dict]:
        """Insertion-ordered (oldest first) copies for the tenant -- the order the hash chain was
        built in, so ``verify_chain`` can detect reordering and removal."""
        with self._lock:
            out = [dict(e) for e in self._audit if e.get("org_id") == org_id]
        return out[:int(limit)]

    def audit_chain_head(self, *, org_id: Optional[str] = None) -> Optional[dict]:
        """The LAST record (insertion order) for the tenant -- the previous link of the chain."""
        with self._lock:
            for e in reversed(self._audit):
                if e.get("org_id") == org_id:
                    return dict(e)
        return None
