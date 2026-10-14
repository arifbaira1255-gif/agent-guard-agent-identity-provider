"""AgentGuard Phase 5 -- Runtime Monitoring, Agent Behaviour Intelligence, Intent Graph &
Agentic Drift Detection.

A single consolidated observability/intelligence plane layered on top of Steps 1-11 and Phase 4. It
consumes the telemetry those phases already emit (identity events, policy decisions, JIT grants,
governance decisions, egress/DLP detections, audit streams) plus a normalized ingest path for runtime
events, and turns it into investigator-facing intelligence:

  1. Runtime activity monitoring      -- ``pipeline.RuntimeEventPipeline``
  2. Agent behaviour analytics        -- ``profiles.BehaviorProfileService``
  3. Intent graph / relationship analysis -- ``graph.IntentGraph``
  4. Agentic drift detection          -- ``drift.DriftDetector``
  5. Anomaly & abuse detection        -- ``drift`` heuristics + ``risk`` correlation
  6. Risk scoring & correlation       -- ``risk.RiskScorer``
  7. Policy-engine integration        -- ``policy_integration.PolicyIntegration``
  8. Real-time alerts & investigation -- ``alerts.AlertService``

Standing caveats (documented, not hidden):

* Detection coverage is bounded by the telemetry actually emitted by instrumented integrations.
  An uninstrumented path is invisible; absence of an event is not evidence that nothing happened.
* Drift findings are observations about *observable behaviour*, never claims about internal intent.
* Risk scores are explainable heuristics, not validated predictions, and never enforcement decisions
  -- the Step 10 policy engine stays authoritative.
* Automated response actions are opt-in, scoped, audited, and delegate to existing mechanisms.
"""
from __future__ import annotations

from .alerts import AlertService
from .audit import RuntimeMonitoringAudit
from .config import MonitoringConfig
from .drift import DriftDetector
from .errors import (AlertError, DriftError, EventValidationError, GraphError, ProfileError,
                     ResponseActionError, RiskError, RuntimeMonitoringError, TenantBoundaryError)
from .graph import IntentGraph
from .memory_store import MemoryRuntimeMonitoringStore
from .models import (Alert, AlertRule, AlertState, BehaviorProfile, Corroboration, Decision,
                     DriftClass, DriftFinding, EdgeKind, EventType, GraphEdge, GraphNode, NodeKind,
                     ResponseAction, RiskAssessment, RiskBand, RiskSignal, RuntimeEvent, Severity,
                     SignalKind)
from .pipeline import IngestResult, RuntimeEventPipeline
from .policy_integration import PolicyIntegration
from .profiles import BehaviorProfileService
from .redaction import Redactor
from .risk import RiskRules, RiskScorer, band_thresholds
from .service import RuntimeMonitoringService
from .store import RuntimeMonitoringStore

__all__ = [
    # composition root
    "RuntimeMonitoringService", "MonitoringConfig", "RuntimeMonitoringStore",
    "MemoryRuntimeMonitoringStore", "RuntimeMonitoringAudit",
    # capabilities
    "RuntimeEventPipeline", "IngestResult", "BehaviorProfileService", "IntentGraph",
    "DriftDetector", "RiskScorer", "RiskRules", "band_thresholds", "AlertService",
    "PolicyIntegration", "Redactor",
    # models
    "RuntimeEvent", "EventType", "Decision", "Severity", "DriftClass", "Corroboration",
    "BehaviorProfile", "DriftFinding", "GraphNode", "GraphEdge", "NodeKind", "EdgeKind",
    "RiskAssessment", "RiskSignal", "RiskBand", "SignalKind", "Alert", "AlertRule", "AlertState",
    "ResponseAction",
    # errors
    "RuntimeMonitoringError", "EventValidationError", "TenantBoundaryError", "ProfileError",
    "DriftError", "GraphError", "RiskError", "AlertError", "ResponseActionError",
]
