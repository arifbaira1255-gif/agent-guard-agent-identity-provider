"""Phase 6 storage boundary for the autonomous-response plane.

One interface (mirroring ``runtime_monitoring/store.py``, ``egress/store.py`` and
``governance/store.py``), two backends:

  * ``storage.postgres.response`` -- authoritative in production (migration 0009, same RLS GUC
    contract ``app.current_org`` / ``app.platform_admin``).
  * ``response.memory_store.MemoryResponseStore`` -- unit tests + single-process dev only.

Tenant contract
---------------
Every tenant-scoped method takes an explicit ``org_id`` and the query MUST be filtered by it. The
PostgreSQL backend additionally runs under Row-Level Security, so a forgotten filter still cannot
leak across tenants -- the same defence-in-depth the earlier phases use.

Idempotency contract
--------------------
``put_response`` is keyed by ``(org_id, idempotency_key)`` and ``get_response_by_key`` is the lookup
used to make containment execution idempotent under duplicate event delivery.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

from .models import (ApprovalRequest, EmergencyStop, EvidenceRecord, ExecutionBudget, Incident,
                     LoopFinding, ResponseExecution)


class ResponseStore(ABC):
    # ------------------------------------------------------------------ loop findings
    @abstractmethod
    def put_loop_finding(self, f: LoopFinding) -> None: ...

    @abstractmethod
    def list_loop_findings(self, *, org_id: str, agent_id: Optional[str] = None,
                           pattern: Optional[str] = None, since: Optional[float] = None,
                           limit: int = 100) -> List[LoopFinding]: ...

    # ------------------------------------------------------------------ budgets
    @abstractmethod
    def put_budget(self, b: ExecutionBudget) -> None: ...

    @abstractmethod
    def get_budget(self, budget_id: str, *, org_id: str) -> Optional[ExecutionBudget]: ...

    @abstractmethod
    def find_budget(self, *, org_id: str, agent_id: Optional[str] = None,
                    task_id: Optional[str] = None) -> Optional[ExecutionBudget]: ...

    @abstractmethod
    def list_budgets(self, *, org_id: str, limit: int = 200) -> List[ExecutionBudget]: ...

    @abstractmethod
    def delete_budget(self, budget_id: str, *, org_id: str) -> None: ...

    @abstractmethod
    def consume_budget(self, budget_id: str, *, org_id: str, dimension: str, amount: float,
                       now: float, limit: Optional[float] = None) -> Optional[ExecutionBudget]:
        """Atomically add ``amount`` to one usage counter and return the updated budget.

        When ``limit`` is given, the increment is CONDITIONAL: it is applied only when it stays
        within the limit, and ``None`` is returned when it would exceed. When ``limit`` is ``None``
        the increment is unconditional (``None`` then means the budget does not exist). Counters are
        clamped at zero so a release can never drive usage negative. MUST be a single atomic
        operation so two concurrent callers cannot both slip past the same limit.
        """

    # ------------------------------------------------------------------ emergency stops
    @abstractmethod
    def put_stop(self, s: EmergencyStop) -> None: ...

    @abstractmethod
    def get_stop(self, stop_id: str, *, org_id: str) -> Optional[EmergencyStop]: ...

    @abstractmethod
    def find_active_stop(self, *, org_id: str, agent_id: Optional[str] = None,
                         task_id: Optional[str] = None) -> Optional[EmergencyStop]: ...

    @abstractmethod
    def list_stops(self, *, org_id: str, active_only: bool = False,
                   limit: int = 200) -> List[EmergencyStop]: ...

    # ------------------------------------------------------------------ approvals
    @abstractmethod
    def put_approval(self, a: ApprovalRequest) -> None: ...

    @abstractmethod
    def get_approval(self, approval_id: str, *, org_id: str) -> Optional[ApprovalRequest]: ...

    @abstractmethod
    def find_approval_by_fingerprint(self, *, org_id: str, fingerprint: str
                                     ) -> Optional[ApprovalRequest]: ...

    @abstractmethod
    def list_approvals(self, *, org_id: str, status: Optional[str] = None,
                       agent_id: Optional[str] = None, limit: int = 100) -> List[ApprovalRequest]: ...

    @abstractmethod
    def count_pending_approvals(self, *, org_id: str, agent_id: str) -> int: ...

    # ------------------------------------------------------------------ incidents
    @abstractmethod
    def put_incident(self, i: Incident) -> None: ...

    @abstractmethod
    def get_incident(self, incident_id: str, *, org_id: str) -> Optional[Incident]: ...

    @abstractmethod
    def list_incidents(self, *, org_id: str, status: Optional[str] = None,
                       agent_id: Optional[str] = None, since: Optional[float] = None,
                       limit: int = 100) -> List[Incident]: ...

    @abstractmethod
    def find_open_incident(self, *, org_id: str, correlation_key: str) -> Optional[Incident]: ...

    @abstractmethod
    def count_open_incidents(self, *, org_id: str) -> int: ...

    # ------------------------------------------------------------------ responses
    @abstractmethod
    def put_response(self, r: ResponseExecution) -> None: ...

    @abstractmethod
    def get_response(self, response_id: str, *, org_id: str) -> Optional[ResponseExecution]: ...

    @abstractmethod
    def get_response_by_key(self, *, org_id: str, idempotency_key: str
                            ) -> Optional[ResponseExecution]: ...

    @abstractmethod
    def list_responses(self, *, org_id: str, incident_id: Optional[str] = None,
                       agent_id: Optional[str] = None, limit: int = 100
                       ) -> List[ResponseExecution]: ...

    # ------------------------------------------------------------------ evidence
    @abstractmethod
    def put_evidence(self, e: EvidenceRecord) -> None: ...

    @abstractmethod
    def get_evidence(self, evidence_id: str, *, org_id: str) -> Optional[EvidenceRecord]: ...

    @abstractmethod
    def list_evidence(self, *, org_id: str, incident_id: Optional[str] = None,
                      limit: int = 200) -> List[EvidenceRecord]: ...

    @abstractmethod
    def purge_evidence_before(self, cutoff_ts: float, *, org_id: Optional[str] = None) -> int: ...

    # ------------------------------------------------------------------ audit
    @abstractmethod
    def append_audit(self, event: dict) -> None: ...

    @abstractmethod
    def list_audit(self, *, org_id: Optional[str] = None, limit: int = 100) -> List[dict]: ...

    @abstractmethod
    def audit_chain_head(self, *, org_id: Optional[str] = None) -> Optional[dict]: ...
