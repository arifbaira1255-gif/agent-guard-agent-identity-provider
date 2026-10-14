"""Phase 7 storage boundary for the assurance plane.

One interface (mirroring ``response/store.py``, ``runtime_monitoring/store.py``), two backends:

  * ``storage.postgres.assurance`` -- authoritative in production (migration 0010, same RLS GUC
    contract ``app.current_org`` / ``app.platform_admin``).
  * ``assurance.memory_store.MemoryAssuranceStore`` -- unit tests + single-process dev only.

Tenant contract
---------------
Every tenant-scoped method takes an explicit ``org_id`` and the query MUST be filtered by it. The
PostgreSQL backend additionally runs under Row-Level Security, so a forgotten filter still cannot
leak across tenants.

Audit contract
--------------
``append_audit`` is append-only and the chain is built in INSERTION order; ``list_audit`` MUST
return records in insertion order (oldest first) so ``verify_chain`` can detect reordering and
removal. ``audit_chain_head`` returns the LAST record for the tenant.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from .models import (AuditChainRecord, AuditCheckpoint, ComplianceControlMapping,
                     CorrelationFinding, PolicyProposal, PolicyRecommendation, SecurityEvidence,
                     SiemDelivery, SiemEvent)


class AssuranceStore(ABC):
    # ------------------------------------------------------------------ evidence
    @abstractmethod
    def put_evidence(self, e: SecurityEvidence) -> None: ...

    @abstractmethod
    def get_evidence(self, evidence_id: str, *, org_id: str) -> Optional[SecurityEvidence]: ...

    @abstractmethod
    def list_evidence(self, *, org_id: str, kind: Optional[str] = None,
                      since: Optional[float] = None, limit: int = 500) -> List[SecurityEvidence]: ...

    # ------------------------------------------------------------------ recommendations
    @abstractmethod
    def put_recommendation(self, r: PolicyRecommendation) -> None: ...

    @abstractmethod
    def get_recommendation(self, recommendation_id: str, *,
                           org_id: str) -> Optional[PolicyRecommendation]: ...

    @abstractmethod
    def list_recommendations(self, *, org_id: str, status: Optional[str] = None,
                             limit: int = 100) -> List[PolicyRecommendation]: ...

    # ------------------------------------------------------------------ proposals
    @abstractmethod
    def put_proposal(self, p: PolicyProposal) -> None: ...

    @abstractmethod
    def get_proposal(self, proposal_id: str, *, org_id: str) -> Optional[PolicyProposal]: ...

    @abstractmethod
    def list_proposals(self, *, org_id: str, status: Optional[str] = None,
                       limit: int = 100) -> List[PolicyProposal]: ...

    @abstractmethod
    def count_pending_proposals(self, *, org_id: str) -> int: ...

    # ------------------------------------------------------------------ compliance
    @abstractmethod
    def put_mapping(self, m: ComplianceControlMapping) -> None: ...

    @abstractmethod
    def get_mapping(self, mapping_id: str) -> Optional[ComplianceControlMapping]: ...

    @abstractmethod
    def list_mappings(self, *, framework: Optional[str] = None,
                      limit: int = 1_000) -> List[ComplianceControlMapping]: ...

    # ------------------------------------------------------------------ SIEM events + deliveries
    @abstractmethod
    def put_siem_event(self, e: SiemEvent) -> None: ...

    @abstractmethod
    def get_siem_event(self, event_id: str, *, org_id: Optional[str] = None) -> Optional[SiemEvent]: ...

    @abstractmethod
    def list_siem_events(self, *, org_id: Optional[str] = None, since: Optional[float] = None,
                         limit: int = 500) -> List[SiemEvent]: ...

    @abstractmethod
    def put_delivery(self, d: SiemDelivery) -> None: ...

    @abstractmethod
    def get_delivery(self, delivery_id: str) -> Optional[SiemDelivery]: ...

    @abstractmethod
    def list_deliveries(self, *, destination_id: Optional[str] = None, status: Optional[str] = None,
                        limit: int = 500) -> List[SiemDelivery]: ...

    # ------------------------------------------------------------------ correlation
    @abstractmethod
    def put_correlation(self, f: CorrelationFinding) -> None: ...

    @abstractmethod
    def list_correlations(self, *, org_id: str, since: Optional[float] = None,
                          limit: int = 200) -> List[CorrelationFinding]: ...

    # ------------------------------------------------------------------ tamper-evident audit
    @abstractmethod
    def append_audit(self, record: AuditChainRecord) -> None: ...

    @abstractmethod
    def list_audit(self, *, org_id: Optional[str] = None, limit: int = 1_000
                   ) -> List[AuditChainRecord]:
        """Insertion-ordered (oldest first) records for the tenant -- the order the chain was built
        in, so ``verify_chain`` can detect reordering and removal."""

    @abstractmethod
    def audit_chain_head(self, *, org_id: Optional[str] = None) -> Optional[AuditChainRecord]: ...

    @abstractmethod
    def audit_count(self, *, org_id: Optional[str] = None) -> int: ...

    @abstractmethod
    def put_checkpoint(self, c: AuditCheckpoint) -> None: ...

    @abstractmethod
    def get_checkpoint(self, checkpoint_id: str) -> Optional[AuditCheckpoint]: ...

    @abstractmethod
    def latest_checkpoint(self, *, org_id: Optional[str] = None) -> Optional[AuditCheckpoint]: ...

    @abstractmethod
    def list_checkpoints(self, *, org_id: Optional[str] = None,
                         limit: int = 100) -> List[AuditCheckpoint]: ...
