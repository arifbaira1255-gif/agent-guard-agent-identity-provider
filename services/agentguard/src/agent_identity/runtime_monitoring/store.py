"""Phase 5 storage boundary for the runtime-monitoring plane.

One interface (mirroring ``egress/store.py``, ``governance/store.py`` and ``policy/store.py``), two
backends:

  * ``storage.postgres.runtime_monitoring.PgRuntimeMonitoringStore`` -- authoritative in production
    (migration 0008, same RLS GUC contract ``app.current_org`` / ``app.platform_admin``).
  * ``runtime_monitoring.memory_store.MemoryRuntimeMonitoringStore`` -- unit tests + single-process
    dev only.

Tenant contract
---------------
Every tenant-scoped method takes an explicit ``org_id`` and the query MUST be filtered by it. The
PostgreSQL backend additionally runs under Row-Level Security, so a forgotten filter still cannot
leak across tenants -- the same defence-in-depth the earlier phases use.

Time semantics
--------------
Retention is expressed in epoch seconds; ``purge_before(org_id, cutoff_ts)`` is the ONLY deletion
path and is org-scoped. Events are append-only (nothing updates an event row).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

from .models import (Alert, AlertRule, BehaviorProfile, DriftFinding, GraphEdge, GraphNode,
                     RiskAssessment, RuntimeEvent)


class RuntimeMonitoringStore(ABC):
    # ------------------------------------------------------------------ events
    @abstractmethod
    def append_event(self, ev: RuntimeEvent) -> None: ...

    @abstractmethod
    def get_event(self, event_id: str, *, org_id: str) -> Optional[RuntimeEvent]: ...

    @abstractmethod
    def list_events(self, *, org_id: str, agent_id: Optional[str] = None,
                    event_type: Optional[str] = None, correlation_id: Optional[str] = None,
                    trace_id: Optional[str] = None, since: Optional[float] = None,
                    until: Optional[float] = None, limit: int = 100,
                    cursor: Optional[str] = None) -> Tuple[List[RuntimeEvent], Optional[str]]:
        """Newest-first page of events. Returns ``(items, next_cursor)``.

        Cursor is an opaque string; it MUST be stable under concurrent appends (it encodes
        ``(ts, event_id)`` so a late-arriving event never duplicates or skips a page boundary).
        """

    @abstractmethod
    def count_events(self, *, org_id: str, agent_id: Optional[str] = None,
                     event_type: Optional[str] = None, since: Optional[float] = None,
                     until: Optional[float] = None) -> int: ...

    @abstractmethod
    def aggregate_by_type(self, *, org_id: str, since: Optional[float] = None,
                          until: Optional[float] = None,
                          agent_id: Optional[str] = None) -> dict: ...

    @abstractmethod
    def latest_event_ts(self, *, org_id: str) -> Optional[float]: ...

    @abstractmethod
    def has_dedup_key(self, *, org_id: str, dedup_key: str) -> bool: ...

    @abstractmethod
    def purge_before(self, cutoff_ts: float, *, org_id: Optional[str] = None) -> int: ...

    # ------------------------------------------------------------------ behavior profiles
    @abstractmethod
    def put_profile(self, p: BehaviorProfile) -> None: ...

    @abstractmethod
    def get_profile(self, *, org_id: str, agent_id: str) -> Optional[BehaviorProfile]: ...

    @abstractmethod
    def list_profiles(self, *, org_id: str, limit: int = 100) -> List[BehaviorProfile]: ...

    @abstractmethod
    def delete_profile(self, *, org_id: str, agent_id: str) -> None: ...

    # ------------------------------------------------------------------ drift findings
    @abstractmethod
    def put_finding(self, f: DriftFinding) -> None: ...

    @abstractmethod
    def list_findings(self, *, org_id: str, agent_id: Optional[str] = None,
                      classification: Optional[str] = None, since: Optional[float] = None,
                      limit: int = 100) -> List[DriftFinding]: ...

    # ------------------------------------------------------------------ intent graph
    @abstractmethod
    def put_node(self, n: GraphNode) -> None: ...

    @abstractmethod
    def get_node(self, node_id: str, *, org_id: str) -> Optional[GraphNode]: ...

    @abstractmethod
    def list_nodes(self, *, org_id: str, kind: Optional[str] = None,
                   limit: int = 500) -> List[GraphNode]: ...

    @abstractmethod
    def put_edge(self, e: GraphEdge) -> None: ...

    @abstractmethod
    def list_edges(self, *, org_id: str, node_id: Optional[str] = None,
                   kind: Optional[str] = None, limit: int = 1000) -> List[GraphEdge]: ...

    @abstractmethod
    def delete_graph(self, *, org_id: str) -> int: ...

    # ------------------------------------------------------------------ risk assessments
    @abstractmethod
    def put_assessment(self, a: RiskAssessment) -> None: ...

    @abstractmethod
    def list_assessments(self, *, org_id: str, agent_id: Optional[str] = None,
                         since: Optional[float] = None, limit: int = 100) -> List[RiskAssessment]: ...

    # ------------------------------------------------------------------ alert rules & alerts
    @abstractmethod
    def put_rule(self, r: AlertRule) -> None: ...

    @abstractmethod
    def get_rule(self, rule_id: str, *, org_id: str) -> Optional[AlertRule]: ...

    @abstractmethod
    def list_rules(self, *, org_id: str) -> List[AlertRule]: ...

    @abstractmethod
    def delete_rule(self, rule_id: str, *, org_id: str) -> None: ...

    @abstractmethod
    def put_alert(self, a: Alert) -> None: ...

    @abstractmethod
    def get_alert(self, alert_id: str, *, org_id: str) -> Optional[Alert]: ...

    @abstractmethod
    def list_alerts(self, *, org_id: str, state: Optional[str] = None,
                    agent_id: Optional[str] = None, rule_id: Optional[str] = None,
                    since: Optional[float] = None, limit: int = 100) -> List[Alert]: ...

    @abstractmethod
    def count_alerts(self, *, org_id: str, rule_id: str, since: float) -> int: ...

    @abstractmethod
    def find_open_alert(self, *, org_id: str, dedup_key: str) -> Optional[Alert]: ...

    # ------------------------------------------------------------------ audit
    @abstractmethod
    def append_audit(self, event: dict) -> None: ...

    @abstractmethod
    def list_audit(self, *, org_id: Optional[str] = None, limit: int = 100) -> List[dict]: ...
