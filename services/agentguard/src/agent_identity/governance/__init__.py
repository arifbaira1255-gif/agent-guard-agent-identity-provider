"""Step 11: Enterprise Tool & Resource Governance.

Public surface (additive to Steps 1-10; nothing here mutates the identity or policy plane):

  * ``GovernanceConfig``        — fail-closed configuration (env-driven; never an ``allow`` default).
  * ``ResourceType`` / ``Sensitivity`` / ``Operation`` / ``RiskClass`` — closed vocabularies so an
    unknown/unclassified value is detectable and denied explicitly.
  * ``ResourceRecord`` / ``ToolRecord`` — the registry models (manifest capabilities are *requested*
    only and can never grant anything).
  * ``ResourceDescriptor``      — the (untrusted) request to operate on a resource.
  * ``GovernanceDecision``      — ALLOW / DENY / REQUIRE_APPROVAL / INDETERMINATE; ``allowed`` is True
    ONLY for a *sealed* ALLOW.
  * ``ResourceRegistry`` / ``ToolRegistry`` — RBAC-guarded, audited, tenant-scoped registries.
  * ``ResourceGuard``           — the single server-side enforcement chokepoint.
  * ``ResourceConnector`` / ``GuardedConnector`` — the standard enforcement interface for adapters.
  * ``GovernanceService``       — composition root + the supported ``execute`` entry point.
  * ``GovernanceStore`` (+ PG / Memory) — authoritative registry persistence.
  * ``install_governance``      — install the governance hook into the HTTP transport.
"""
from .audit import GovernanceAudit
from .classifier import Classification, ResourceClassifier
from .config import GovernanceConfig
from .connectors import (DatabaseConnector, GuardedConnector, HttpApiConnector, ResourceConnector,
                         ShellConnector)
from .errors import (GovernanceError, OperationNotPermittedError, RegistryValidationError,
                     ResourceNotFoundError, ToolNotRegisteredError, UnknownResourceError)
from .guard import ResourceGuard
from .hooks import describe, install_governance, make_governance_hook
from .memory_store import MemoryGovernanceStore
from .models import (DESTRUCTIVE_OPERATIONS, GovernanceAuditEvent, GovernanceDecision,
                     GovernanceOutcome, Operation, ResourceDescriptor, ResourceRecord, ResourceType,
                     RiskClass, Sensitivity, ToolRecord)
from .registry import ResourceRegistry
from .service import GovernanceService
from .store import GovernanceStore
from .tool_registry import ToolRegistry
from .validation import validate_manifest

__all__ = [
    "GovernanceConfig", "GovernanceService", "GovernanceStore", "MemoryGovernanceStore",
    "GovernanceAudit", "GovernanceDecision", "GovernanceOutcome", "GovernanceAuditEvent",
    "ResourceGuard", "ResourceRegistry", "ToolRegistry", "ResourceType", "Sensitivity",
    "Operation", "RiskClass", "ResourceRecord", "ToolRecord", "ResourceDescriptor",
    "DESTRUCTIVE_OPERATIONS", "ResourceConnector", "GuardedConnector", "HttpApiConnector",
    "DatabaseConnector", "ShellConnector", "ResourceClassifier", "Classification",
    "install_governance", "make_governance_hook", "describe", "validate_manifest",
    "GovernanceError", "UnknownResourceError", "ResourceNotFoundError", "RegistryValidationError",
    "ToolNotRegisteredError", "OperationNotPermittedError",
]
