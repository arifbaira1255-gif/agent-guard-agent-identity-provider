"""Phase 6 -- Autonomous Loop Detection, Human Approval, Incident Response & Automated Containment.

A self-contained response plane layered on top of Phases 1-5. It reuses the existing event pipeline,
policy engine, JIT grant service, identity/credential plane, egress gateway, governance registry and
observability stack -- it introduces no second database, no second event pipeline and no competing
authorization path.

Modules
-------
``config``        fail-closed configuration (auto-containment OFF by default)
``models``        net-new domain records + closed vocabularies
``store``         storage interface (PostgreSQL in production, memory for tests)
``loops``         autonomous-loop / runaway-agent detection
``budgets``       execution budgets + emergency stops (server-side enforcement boundary)
``approvals``     risk-based human approval bound to an operation fingerprint
``incidents``     incident lifecycle + conservative correlation
``containment``   containment engine delegating to existing enforcement mechanisms
``orchestrator``  idempotent, auditable response state machine with rollback
``evidence``      evidence preservation (references + digests, sealing, retention)
``audit``         hash-chained response audit log
``service``       composition root
"""
from .approvals import ApprovalService
from .audit import ResponseAudit
from .budgets import BudgetService
from .config import RESPONSE_LEVELS, ResponseConfig
from .containment import ContainmentEngine, ContainmentIntegrations, ContainmentResult
from .errors import (ApprovalError, ApprovalMismatchError, BudgetExceededError, ContainmentError,
                     EmergencyStopError, EvidenceError, IncidentError, LoopDetectionError,
                     ResponseOrchestrationError, ResponsePlaneError, TenantBoundaryError)
from .evidence import EvidenceService
from .incidents import IncidentService
from .loops import LoopDetector
from .memory_store import MemoryResponseStore
from .models import (APPROVAL_TERMINAL_STATES, CONTAINMENT_ACTION_SPECS, INCIDENT_STATE_TRANSITIONS,
                     INCIDENT_TERMINAL_STATES, RESPONSE_LEVEL_ACTIONS, RESPONSE_STATE_TRANSITIONS,
                     RESPONSE_TERMINAL_STATES, ApprovalRequest, ApprovalStatus, BudgetDecision,
                     BudgetScope, ContainmentAction, EmergencyStop, EvidenceRecord, ExecutionBudget,
                     Incident, IncidentStatus, IncidentTimelineEntry, LoopClassification,
                     LoopFinding, LoopPattern, ResponseExecution, ResponseLevel, ResponseState,
                     ResponseStep, operation_fingerprint)
from .orchestrator import ResponseOrchestrator
from .service import ResponseService
from .store import ResponseStore

__all__ = [
    "ResponseConfig", "RESPONSE_LEVELS",
    "ResponsePlaneError", "LoopDetectionError", "BudgetExceededError", "EmergencyStopError",
    "ApprovalError", "ApprovalMismatchError", "IncidentError", "ContainmentError",
    "ResponseOrchestrationError", "EvidenceError", "TenantBoundaryError",
    "LoopPattern", "LoopClassification", "LoopFinding", "BudgetScope", "ExecutionBudget",
    "BudgetDecision", "EmergencyStop", "ApprovalStatus", "APPROVAL_TERMINAL_STATES",
    "ApprovalRequest", "operation_fingerprint", "IncidentStatus", "INCIDENT_TERMINAL_STATES",
    "INCIDENT_STATE_TRANSITIONS", "IncidentTimelineEntry", "Incident", "ContainmentAction",
    "CONTAINMENT_ACTION_SPECS", "ResponseState", "RESPONSE_TERMINAL_STATES",
    "RESPONSE_STATE_TRANSITIONS", "ResponseStep", "ResponseExecution", "EvidenceRecord",
    "ResponseLevel", "RESPONSE_LEVEL_ACTIONS",
    "ResponseStore", "MemoryResponseStore",
    "LoopDetector", "BudgetService", "ApprovalService", "IncidentService", "EvidenceService",
    "ContainmentEngine", "ContainmentIntegrations", "ContainmentResult", "ResponseOrchestrator",
    "ResponseAudit", "ResponseService",
]
