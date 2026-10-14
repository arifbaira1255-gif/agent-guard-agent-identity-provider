"""Step 10: Policy Engine and Just-in-Time Authorization.

Public surface (additive to Steps 1-9; nothing here mutates the identity plane):

  * ``PolicyConfig``            — fail-closed configuration (env-driven).
  * ``PolicyDecisionService``   — the single decision + lifecycle entry point.
  * ``PolicyDecision`` / ``DecisionKind`` — the four explicit outcomes (ALLOW/DENY/REQUIRE_APPROVAL/
    INDETERMINATE); ``INDETERMINATE`` is never an allow.
  * ``PolicyEngine`` (+ OPA HTTP/CLI backends) — Rego evaluation with bounded resources.
  * ``JitGrantService``         — narrowly scoped, short-lived, revocable grants.
  * ``DecisionCache``           — tenant/identity/version-scoped, TTL-bounded, invalidatable.
  * ``StoreApprovalProvider`` / ``RiskSignalProvider`` — minimal integration interfaces.
  * ``PolicyStore`` (+ Pg / Memory) — authoritative policy persistence.
  * ``PolicyAudit``             — durable, allow-listed, secret-free policy audit.
  * ``PolicyEnforcer``          — the anti-bypass enforcement primitive.
"""
from .approval import (ApprovalProvider, NeutralRiskProvider, RiskSignalProvider,
                       StaticRiskProvider, StoreApprovalProvider)
from .audit import PolicyAudit
from .cache import DecisionCache
from .config import PolicyConfig
from .engine import (NullEngine, OpaCliEngine, OpaHttpEngine, PolicyEngine, build_engine,
                     namespaced_package, rewrite_package, validate_rego)
from .enforcer import PolicyEnforcer, install_policy_engine
from .errors import (ApprovalError, JitGrantError, PolicyConflictError, PolicyEngineUnavailableError,
                     PolicyError, PolicyNotFoundError, PolicyValidationError)
from .jit import JitGrantService
from .memory_store import MemoryPolicyStore
from .models import (ApprovalRequest, ApprovalStatus, DecisionKind, GrantStatus, JitGrant,
                     PolicyDecision, PolicyInput, PolicyRecord, PolicyStatus, PolicyVersion,
                     RiskSignal, VersionStatus)
from .service import PolicyDecisionService, make_policy_hook
from .store import PolicyStore

__all__ = [
    "PolicyConfig", "PolicyDecisionService", "make_policy_hook", "PolicyEnforcer",
    "install_policy_engine", "PolicyDecision", "DecisionKind", "PolicyInput", "PolicyRecord",
    "PolicyVersion", "PolicyStatus", "VersionStatus", "JitGrant", "GrantStatus", "ApprovalRequest",
    "ApprovalStatus", "RiskSignal", "PolicyEngine", "OpaHttpEngine", "OpaCliEngine", "NullEngine",
    "build_engine", "validate_rego", "namespaced_package", "rewrite_package", "JitGrantService",
    "DecisionCache", "PolicyStore", "MemoryPolicyStore", "PolicyAudit", "StoreApprovalProvider",
    "RiskSignalProvider", "NeutralRiskProvider", "StaticRiskProvider", "ApprovalProvider",
    "PolicyError", "PolicyNotFoundError", "PolicyValidationError", "PolicyConflictError",
    "PolicyEngineUnavailableError", "JitGrantError", "ApprovalError",
]
