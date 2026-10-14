"""Step 10 policy domain models.

These are ADDITIVE, immutable models for the policy decision plane:

  * :class:`DecisionKind` / :class:`PolicyDecision` — the four explicit outcomes. ``allowed`` is
    True ONLY for ``ALLOW``; ``INDETERMINATE`` is never an allow (fail closed).
  * :class:`PolicyRecord` / :class:`PolicyVersion` — an authoritative policy and its immutable,
    checksummed versions (draft -> active -> retired).
  * :class:`JitGrant` — a narrowly scoped, short-lived, revocable authorization grant.
  * :class:`ApprovalRequest` — the minimal human-approval record (Step 17 owns the full workflow).
  * :class:`RiskSignal` — a risk input produced by an existing component (Step 11+ owns the full
    risk engine; Step 10 only consumes signals through an interface).

Nothing here holds secrets: policy source is Rego (not secret), grants/approvals carry only ids,
scopes, timestamps and reason codes.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional, Tuple

from ..core.models import iso  # reuse the existing ISO-8601 formatter


# --------------------------------------------------------------------------- decisions
class DecisionKind(str, enum.Enum):
    """The four explicit policy outcomes. There is no implicit fifth state."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class PolicyDecision:
    """The result of a policy evaluation.

    ``allowed`` is the ONLY thing that may gate execution, and it is True exclusively for
    :attr:`DecisionKind.ALLOW`. An ``INDETERMINATE`` decision (engine outage, malformed policy,
    unparseable result) is NOT an allow.
    """

    kind: DecisionKind
    reason: str = ""
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    decision_id: Optional[str] = None
    obligations: Tuple[dict, ...] = ()
    grant_id: Optional[str] = None
    approval_id: Optional[str] = None
    correlation_id: Optional[str] = None
    latency_ms: Optional[int] = None
    cached: bool = False

    @property
    def allowed(self) -> bool:
        return self.kind is DecisionKind.ALLOW

    def to_dict(self) -> dict:
        out = {"allowed": self.allowed, "decision": self.kind.value, "reason": self.reason}
        for k in ("policy_id", "policy_version", "decision_id", "grant_id", "approval_id",
                  "correlation_id", "latency_ms"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v
        if self.obligations:
            out["obligations"] = list(self.obligations)
        if self.cached:
            out["cached"] = True
        return out

    @classmethod
    def allow(cls, reason: str = "allow", **kw) -> "PolicyDecision":
        return cls(DecisionKind.ALLOW, reason, **kw)

    @classmethod
    def deny(cls, reason: str = "deny", **kw) -> "PolicyDecision":
        return cls(DecisionKind.DENY, reason, **kw)

    @classmethod
    def require_approval(cls, reason: str = "approval_required", **kw) -> "PolicyDecision":
        return cls(DecisionKind.REQUIRE_APPROVAL, reason, **kw)

    @classmethod
    def indeterminate(cls, reason: str = "indeterminate", **kw) -> "PolicyDecision":
        return cls(DecisionKind.INDETERMINATE, reason, **kw)


# --------------------------------------------------------------------------- policies
class PolicyStatus(str, enum.Enum):
    DRAFT = "draft"            # created, no active version yet
    ACTIVE = "active"          # has an active version and is evaluated
    DISABLED = "disabled"      # administratively turned off (never evaluated)


class VersionStatus(str, enum.Enum):
    DRAFT = "draft"            # authored, not yet activated
    ACTIVE = "active"          # the version currently evaluated
    RETIRED = "retired"        # previously active, superseded (kept for rollback/audit)


@dataclass(frozen=True)
class PolicyRecord:
    """An authoritative policy definition (metadata). The Rego lives in :class:`PolicyVersion`."""

    policy_id: str
    org_id: Optional[str]              # None = platform-wide policy
    name: str
    description: str
    owner_user_id: str
    status: PolicyStatus
    active_version: Optional[int]
    created_at: float
    updated_at: float
    created_by: str

    def public_dict(self) -> dict:
        return {"policy_id": self.policy_id, "org_id": self.org_id, "name": self.name,
                "description": self.description, "owner_user_id": self.owner_user_id,
                "status": self.status.value, "active_version": self.active_version,
                "created_at": iso(self.created_at), "updated_at": iso(self.updated_at)}


@dataclass(frozen=True)
class PolicyVersion:
    """An immutable, checksummed version of a policy's Rego source."""

    policy_id: str
    version: int
    org_id: Optional[str]
    rego_source: str
    checksum: str                      # sha256 of the canonical source
    status: VersionStatus
    created_at: float
    created_by: str
    activated_at: Optional[float] = None
    test_summary: Optional[dict] = None

    def public_dict(self, *, include_source: bool = False) -> dict:
        out = {"policy_id": self.policy_id, "version": self.version, "org_id": self.org_id,
               "checksum": self.checksum, "status": self.status.value,
               "created_at": iso(self.created_at), "activated_at": iso(self.activated_at),
               "test_summary": self.test_summary}
        if include_source:
            out["rego_source"] = self.rego_source
        return out


# --------------------------------------------------------------------------- JIT grants
class GrantStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True)
class JitGrant:
    """A narrowly scoped, short-lived authorization grant.

    Every grant names exactly one (agent, tenant, action, resource) tuple and carries an explicit
    issuance and expiration time plus the policy version / security context under which it was
    issued. There is no wildcard scope and no permanent grant: ``expires_at`` is mandatory and
    bounded by the configured maximum TTL.
    """

    grant_id: str
    org_id: str
    agent_id: str
    instance_id: Optional[str]
    action: str
    resource: str
    issued_at: float
    expires_at: float
    policy_version: Optional[str]
    status: GrantStatus
    issued_by: str
    reason: str = ""
    context: Optional[dict] = None
    revoked_at: Optional[float] = None
    revoked_reason: Optional[str] = None

    def is_live(self, now: float) -> bool:
        return self.status is GrantStatus.ACTIVE and now < self.expires_at

    def matches(self, *, org_id: str, agent_id: str, action: str, resource: str,
                instance_id: Optional[str] = None) -> bool:
        """Exact, least-privilege match. No wildcards, no prefix matching, no cross-tenant match."""
        if self.org_id != org_id or self.agent_id != agent_id:
            return False
        if self.action != action or self.resource != resource:
            return False
        if self.instance_id is not None and instance_id is not None and self.instance_id != instance_id:
            return False
        return True

    def public_dict(self) -> dict:
        return {"grant_id": self.grant_id, "org_id": self.org_id, "agent_id": self.agent_id,
                "instance_id": self.instance_id, "action": self.action, "resource": self.resource,
                "issued_at": iso(self.issued_at), "expires_at": iso(self.expires_at),
                "policy_version": self.policy_version, "status": self.status.value,
                "reason": self.reason, "revoked_at": iso(self.revoked_at)}


# --------------------------------------------------------------------------- approvals
class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass(frozen=True)
class ApprovalRequest:
    """Minimal human-approval record. Step 17 owns the full approval workflow; Step 10 only needs
    enough to gate an action that policy marked ``REQUIRE_APPROVAL``."""

    approval_id: str
    org_id: str
    agent_id: str
    action: str
    resource: str
    status: ApprovalStatus
    requested_at: float
    expires_at: float
    requested_by: str
    decided_at: Optional[float] = None
    decided_by: Optional[str] = None
    reason: str = ""
    context: Optional[dict] = None

    def is_valid(self, now: float) -> bool:
        return self.status is ApprovalStatus.APPROVED and now < self.expires_at

    def public_dict(self) -> dict:
        return {"approval_id": self.approval_id, "org_id": self.org_id, "agent_id": self.agent_id,
                "action": self.action, "resource": self.resource, "status": self.status.value,
                "requested_at": iso(self.requested_at), "expires_at": iso(self.expires_at),
                "decided_at": iso(self.decided_at), "decided_by": self.decided_by, "reason": self.reason}


# --------------------------------------------------------------------------- risk signals
@dataclass(frozen=True)
class RiskSignal:
    """A risk input consumed by policy. Produced by an existing/adjacent component; Step 10 only
    consumes it through :class:`~agent_identity.policy.risk.RiskSignalProvider`."""

    level: str = "low"                 # low | medium | high | critical
    score: float = 0.0                 # 0.0 .. 1.0
    reasons: Tuple[str, ...] = ()
    source: str = ""

    def to_dict(self) -> dict:
        return {"level": self.level, "score": self.score, "reasons": list(self.reasons),
                "source": self.source}


# --------------------------------------------------------------------------- policy input
@dataclass(frozen=True)
class PolicyInput:
    """The complete, server-assembled context handed to the policy engine.

    Every field is derived from VERIFIED server-side state (the credential verifier, the RBAC
    resolver, the JIT grant store, the risk provider). A client can never supply these directly.
    """

    agent_id: str
    instance_id: Optional[str]
    tenant: str
    action: str
    resource: str
    capabilities: Tuple[str, ...] = ()
    credential_status: str = "valid"
    environment: str = "development"
    request_context: dict = field(default_factory=dict)
    risk: RiskSignal = field(default_factory=RiskSignal)
    jit_grants: Tuple[dict, ...] = ()
    approval: dict = field(default_factory=lambda: {"valid": False})
    policy_version: Optional[str] = None
    resource_tenant: str = ""
    denied_actions: Tuple[str, ...] = ()
    approval_required_actions: Tuple[str, ...] = ()
    is_sub_agent: bool = False
    parent_agent_id: Optional[str] = None

    def to_engine_input(self) -> dict:
        """The JSON document sent to OPA as ``input``. Contains no secrets."""
        return {
            "agent_id": self.agent_id,
            "instance_id": self.instance_id,
            "tenant": self.tenant,
            "action": self.action,
            "resource": self.resource,
            "capabilities": list(self.capabilities),
            "credential_status": self.credential_status,
            "environment": self.environment,
            "request_context": dict(self.request_context or {}),
            "risk": self.risk.to_dict(),
            "jit_grants": [dict(g) for g in self.jit_grants],
            "approval": dict(self.approval or {"valid": False}),
            "policy_version": self.policy_version,
            "resource_tenant": self.resource_tenant,
            "denied_actions": list(self.denied_actions),
            "approval_required_actions": list(self.approval_required_actions),
            "is_sub_agent": self.is_sub_agent,
            "parent_agent_id": self.parent_agent_id,
        }
