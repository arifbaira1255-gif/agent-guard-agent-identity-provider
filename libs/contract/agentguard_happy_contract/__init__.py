"""agentguard-happy-contract -- the typed, versioned integration contract between Happy LANG and
AgentGuard.

WHY THIS PACKAGE EXISTS
-----------------------
The Step 1 audit found (blockers B1 and B4) that:

* neither project defined a versioned, typed schema for the authorization request/response or the
  security-event payload, and
* Happy LANG is **not** a security boundary, yet nothing at the seam enforced that.

This package fixes both: it is the single, dependency-free definition of the seam, and it contains
the adapter that makes AgentGuard the **authoritative** decision point for a Happy LANG runtime.

THE ONE DESIGN RULE THAT MATTERS
--------------------------------
AgentGuard owns the decision.  A Happy LANG capability declaration, a passing contract, or a clean
compile is **not** authorisation.  A local ALLOW never overrides a remote DENY, and any uncertainty
(unreachable PDP, timeout, malformed answer) is DENIED.

Nothing in AgentGuard or Happy LANG source is modified: the integration plugs into the **existing**
extensibility points on both sides (``use_checker`` in ``happy.std.*``, the policy hook behind
``POST /v1/authorize``).
"""
from __future__ import annotations

from typing import Any

from .config import IntegrationConfig
from .errors import (
    ContractError,
    SerializationError,
    TargetTypeError,
    UnsupportedContractVersion,
    ValidationError,
)
from .events import EventForwarder, http_event_sink
from .models import (
    ArtifactRef,
    AuthorizationDecision,
    AuthorizationRequest,
    Decision,
    EventType,
    ExecutionLimits,
    ExecutionRequest,
    ExecutionResource,
    ExecutionResult,
    ResultKind,
    SecurityEvent,
    SecurityEventOutcome,
    SourceLocation,
    new_id,
)
from .pdp import (
    CallablePdp,
    DenyAllPdp,
    HttpPdp,
    PolicyDecisionPoint,
    SdkPdp,
)
from .schema import SCHEMAS, assert_conforms, schema_names
from .version import (
    CONTRACT_NAME,
    CONTRACT_VERSION,
    EVOLUTION_RULE,
    SCHEMA_ID,
    SUPPORTED_CONTRACT_VERSIONS,
    contract_header,
    is_supported,
    require_supported,
)
from .validation import canonical_json, clean_metadata, redact, sha256_hex

__version__ = CONTRACT_VERSION

__all__ = [
    # versioning
    "CONTRACT_NAME", "CONTRACT_VERSION", "SCHEMA_ID", "SUPPORTED_CONTRACT_VERSIONS",
    "EVOLUTION_RULE", "contract_header", "is_supported", "require_supported",
    # errors
    "ContractError", "ValidationError", "UnsupportedContractVersion", "SerializationError",
    "TargetTypeError",
    # validation helpers
    "canonical_json", "sha256_hex", "redact", "clean_metadata",
    # models
    "Decision", "ResultKind", "SecurityEventOutcome", "EventType",
    "SourceLocation", "ArtifactRef",
    "AuthorizationRequest", "AuthorizationDecision", "SecurityEvent",
    "ExecutionResource", "ExecutionLimits", "ExecutionRequest", "ExecutionResult",
    "new_id",
    # pdp
    "PolicyDecisionPoint", "DenyAllPdp", "CallablePdp", "SdkPdp", "HttpPdp",
    # events
    "EventForwarder", "http_event_sink",
    # config
    "IntegrationConfig",
    # schema
    "SCHEMAS", "assert_conforms", "schema_names",
    # happy-facing adapter (imported lazily so this package works without Happy installed)
    "AgentGuardAuthorizer", "IntegratedExecutor", "GuardedEgress",
    # secure execution runtime (M2)
    "SecureExecutionRuntime", "CallerCredential", "RuntimeEvidence",
    "WorkerPool", "ExecutionJob", "JobOutcome", "WorkerHealth", "QueueFull", "WorkerUnavailable",
    "ExecutionBudget", "BudgetTracker", "CancellationToken", "ResourceLimitExceeded", "LIMIT_KINDS",
    "IsolationReport", "JailSpec", "JailResult", "probe_isolation", "isolation_available",
    "run_in_jail", "make_workdir", "cleanup_workdir", "IsolationUnavailableError",
    "DenyByDefaultChecker", "StaticAllowlistChecker", "install_std_guard", "uninstall_std_guard",
    "std_guard_installed",
]

#: Lazily-resolved names.  These modules import Happy LANG types only inside functions, so they are
#: importable without Happy on ``sys.path`` -- but resolving them lazily keeps package import cheap
#: and keeps an import error localised to the feature that needs it.
_LAZY = {
    "AgentGuardAuthorizer": "authorizer",
    "IntegratedExecutor": "executor",
    "GuardedEgress": "executor",
    "SecureExecutionRuntime": "secure_runtime",
    "CallerCredential": "secure_runtime",
    "RuntimeEvidence": "secure_runtime",
    "WorkerPool": "worker_pool",
    "ExecutionJob": "worker_pool",
    "JobOutcome": "worker_pool",
    "WorkerHealth": "worker_pool",
    "QueueFull": "worker_pool",
    "WorkerUnavailable": "worker_pool",
    "ExecutionBudget": "limits",
    "BudgetTracker": "limits",
    "CancellationToken": "limits",
    "ResourceLimitExceeded": "limits",
    "LIMIT_KINDS": "limits",
    "IsolationReport": "isolation",
    "JailSpec": "isolation",
    "JailResult": "isolation",
    "probe_isolation": "isolation",
    "isolation_available": "isolation",
    "run_in_jail": "isolation",
    "make_workdir": "isolation",
    "cleanup_workdir": "isolation",
    "IsolationUnavailableError": "isolation",
    "DenyByDefaultChecker": "std_guard",
    "StaticAllowlistChecker": "std_guard",
    "install_std_guard": "std_guard",
    "uninstall_std_guard": "std_guard",
    "std_guard_installed": "std_guard",
}


def __getattr__(name: str) -> Any:                      # PEP 562
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    module = import_module(f".{module_name}", __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value


def describe() -> dict:
    """Machine-readable summary of the contract (used by docs, tests and health output)."""
    return {
        "name": CONTRACT_NAME,
        "version": CONTRACT_VERSION,
        "schema_id": SCHEMA_ID,
        "supported_versions": list(SUPPORTED_CONTRACT_VERSIONS),
        "schemas": list(schema_names()),
        "evolution_rule": EVOLUTION_RULE,
    }
