"""Step 11 governance domain models.

ADDITIVE, immutable models for the resource-governance plane. Nothing here holds secrets: a
descriptor is *what* the agent wants to touch (a logical id + type + operation) — never a credential,
connection string, shell command line, or request body.

Key types
---------
* :class:`ResourceType` / :class:`Sensitivity` / :class:`Operation` / :class:`RiskClass` — closed
  vocabularies so an unknown/unclassified value can be detected and denied explicitly.
* :class:`ResourceRecord` — the registry entry for a governed resource: identity, tenant, type,
  owner, sensitivity, the operations it PERMITS (least privilege), and the policies that apply.
* :class:`ToolRecord` — the registry entry for an approved tool. Manifest-declared capabilities are
  stored as ``requested_capabilities`` and can never grant anything on their own; only
  ``approved_capabilities`` (set by an administrator) carry weight.
* :class:`ResourceDescriptor` — the *request* to operate on something: resource id, type, operation,
  and the capabilities the agent CLAIMS. Claims are advisory and are never trusted.
* :class:`GovernanceDecision` — the guard's outcome: the Step 10 :class:`PolicyDecision`, the resolved
  registry decision, and a **seal** proving the decision was produced by this server process and is
  therefore safe to hand to :meth:`ResourceGuard.enforce`.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import FrozenSet, Optional, Tuple

from ..core.models import iso  # reuse the existing ISO-8601 formatter
from ..policy.models import PolicyDecision


# --------------------------------------------------------------------------- vocabularies
class ResourceType(str, enum.Enum):
    """The classes of protected resource a governed operation can target."""

    TOOL = "tool"                     # a tool function exposed to an agent
    TOOL_SERVER = "tool_server"       # an MCP/other tool server hosting tools
    HTTP_API = "http_api"             # an outbound HTTP API endpoint
    DATABASE = "database"             # a database / schema / table namespace
    FILESYSTEM = "filesystem"         # a file or object-store location
    SHELL = "shell"                   # a command / process execution surface
    CLOUD = "cloud"                   # a cloud provider service resource
    INTERNAL_SERVICE = "internal_service"  # an internal enterprise service
    CUSTOM = "custom"                 # a tenant-defined resource class

    @classmethod
    def coerce(cls, value) -> Optional["ResourceType"]:
        """Return the matching type or ``None`` (None = unclassified -> deny)."""
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None


class Sensitivity(str, enum.Enum):
    """Data/sensitivity classification of a resource. Drives approval escalation."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @classmethod
    def coerce(cls, value) -> Optional["Sensitivity"]:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None

    @property
    def rank(self) -> int:
        return _SENSITIVITY_RANK[self]


_SENSITIVITY_RANK = {Sensitivity.PUBLIC: 0, Sensitivity.INTERNAL: 1,
                     Sensitivity.CONFIDENTIAL: 2, Sensitivity.RESTRICTED: 3}


class Operation(str, enum.Enum):
    """The verbs a governed operation may request. Closed set => unknown op is explicit."""

    READ = "read"
    LIST = "list"
    WRITE = "write"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    INVOKE = "invoke"
    CONNECT = "connect"
    DEPLOY = "deploy"
    SEND = "send"
    ADMIN = "admin"

    @classmethod
    def coerce(cls, value) -> Optional["Operation"]:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None


class RiskClass(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def coerce(cls, value) -> Optional["RiskClass"]:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None

    @property
    def rank(self) -> int:
        return _RISK_RANK[self]


_RISK_RANK = {RiskClass.LOW: 0, RiskClass.MEDIUM: 1, RiskClass.HIGH: 2, RiskClass.CRITICAL: 3}

#: Operations that are destructive / high-impact by nature: these escalate to REQUIRE_APPROVAL when
#: the resource is classified above ``internal`` (see ``ResourceGuard``).
DESTRUCTIVE_OPERATIONS = frozenset({
    Operation.DELETE, Operation.ADMIN, Operation.DEPLOY, Operation.EXECUTE,
})

#: The character set a governed identifier may use. Rejects wildcards, whitespace, path traversal
#: and namespacing characters that could forge another tenant/type.
ID_MAX = 200


# --------------------------------------------------------------------------- registry records
@dataclass(frozen=True)
class ResourceRecord:
    """An authoritative, tenant-scoped registry entry for a governed resource."""

    resource_id: str
    org_id: str
    resource_type: ResourceType
    name: str
    owner: str
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    permitted_operations: FrozenSet[Operation] = frozenset()
    policy_refs: Tuple[str, ...] = ()
    enabled: bool = True
    description: str = ""
    metadata: Optional[dict] = None
    created_at: float = 0.0
    updated_at: float = 0.0
    created_by: str = ""

    def permits(self, operation: Operation) -> bool:
        """Least-privilege check: the operation must be explicitly permitted.

        A disabled resource permits nothing. There is no wildcard operation.
        """
        return self.enabled and operation in self.permitted_operations

    def public_dict(self) -> dict:
        return {"resource_id": self.resource_id, "org_id": self.org_id,
                "resource_type": self.resource_type.value, "name": self.name, "owner": self.owner,
                "sensitivity": self.sensitivity.value,
                "permitted_operations": sorted(o.value for o in self.permitted_operations),
                "policy_refs": list(self.policy_refs), "enabled": self.enabled,
                "description": self.description,
                "created_at": iso(self.created_at), "updated_at": iso(self.updated_at)}


@dataclass(frozen=True)
class ToolRecord:
    """A registry entry for an approved tool and its capabilities.

    ``requested_capabilities`` come from the tool's manifest and are UNTRUSTED: they are recorded for
    review only. ``approved_capabilities`` are what an administrator granted, and are the only
    capabilities that can influence an authorization decision.
    """

    tool_id: str
    org_id: str
    name: str
    version: str
    owner: str
    risk: RiskClass = RiskClass.MEDIUM
    requested_capabilities: Tuple[str, ...] = ()
    approved_capabilities: Tuple[str, ...] = ()
    resource_id: Optional[str] = None
    policy_refs: Tuple[str, ...] = ()
    enabled: bool = True
    approved: bool = False
    description: str = ""
    manifest_checksum: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    created_by: str = ""
    approved_by: Optional[str] = None

    def public_dict(self, *, include_requested: bool = True) -> dict:
        out = {"tool_id": self.tool_id, "org_id": self.org_id, "name": self.name,
               "version": self.version, "owner": self.owner, "risk": self.risk.value,
               "approved_capabilities": list(self.approved_capabilities),
               "resource_id": self.resource_id, "policy_refs": list(self.policy_refs),
               "enabled": self.enabled, "approved": self.approved,
               "description": self.description, "manifest_checksum": self.manifest_checksum,
               "created_at": iso(self.created_at), "updated_at": iso(self.updated_at),
               "approved_by": self.approved_by}
        if include_requested:
            out["requested_capabilities"] = list(self.requested_capabilities)
        return out


# --------------------------------------------------------------------------- request descriptor
@dataclass(frozen=True)
class ResourceDescriptor:
    """A request to operate on a governed resource.

    Everything here is *claimed* by the caller (or derived from the SDK's tool metadata) and is
    therefore UNTRUSTED. The guard resolves the authoritative type/sensitivity/operations from the
    registry; the descriptor only tells the guard *which* resource is meant and *what* is wanted.
    """

    resource_id: str
    operation: str
    resource_type: Optional[str] = None
    tool: Optional[str] = None
    requested_capabilities: Tuple[str, ...] = ()
    resource_tenant: str = ""
    context: Optional[dict] = None

    def to_policy_context(self) -> dict:
        """The (non-secret) fragment merged into the Step 10 policy ``request_context``."""
        out = {"resource_id": self.resource_id, "operation": self.operation}
        if self.resource_type:
            out["resource_type"] = self.resource_type
        if self.tool:
            out["tool"] = self.tool
        if self.requested_capabilities:
            out["requested_capabilities"] = list(self.requested_capabilities)
        if self.context:
            for k, v in self.context.items():
                if k not in out:
                    out[k] = v
        return out


# --------------------------------------------------------------------------- decision
class GovernanceOutcome(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class GovernanceDecision:
    """The guard's decision. ``allowed`` is True ONLY for a sealed ALLOW."""

    outcome: GovernanceOutcome
    reason: str = ""
    policy: Optional[PolicyDecision] = None
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    operation: Optional[str] = None
    sensitivity: Optional[str] = None
    tool_id: Optional[str] = None
    correlation_id: Optional[str] = None
    decision_id: Optional[str] = None
    seal: Optional[str] = None
    latency_ms: Optional[int] = None

    @property
    def allowed(self) -> bool:
        return self.outcome is GovernanceOutcome.ALLOW and self.seal is not None

    def to_dict(self) -> dict:
        out = {"allowed": self.allowed, "decision": self.outcome.value, "reason": self.reason,
               "resource_id": self.resource_id, "operation": self.operation}
        for k in ("resource_type", "sensitivity", "tool_id", "decision_id", "correlation_id",
                  "latency_ms"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v
        if self.policy is not None:
            out["policy"] = self.policy.to_dict()
        return out

    @classmethod
    def allow(cls, reason: str = "allow", **kw) -> "GovernanceDecision":
        return cls(GovernanceOutcome.ALLOW, reason, **kw)

    @classmethod
    def deny(cls, reason: str = "deny", **kw) -> "GovernanceDecision":
        return cls(GovernanceOutcome.DENY, reason, **kw)

    @classmethod
    def require_approval(cls, reason: str = "approval_required", **kw) -> "GovernanceDecision":
        return cls(GovernanceOutcome.REQUIRE_APPROVAL, reason, **kw)

    @classmethod
    def indeterminate(cls, reason: str = "indeterminate", **kw) -> "GovernanceDecision":
        return cls(GovernanceOutcome.INDETERMINATE, reason, **kw)


@dataclass
class GovernanceAuditEvent:
    """One audited governance decision. No secrets, no payloads — ids and reason codes only."""

    event_id: str
    ts: float
    event: str
    org_id: Optional[str] = None
    agent_id: Optional[str] = None
    instance_id: Optional[str] = None
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    operation: Optional[str] = None
    tool_id: Optional[str] = None
    decision: str = ""
    reason: Optional[str] = None
    outcome: str = "ok"
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    actor_user_id: Optional[str] = None
    correlation_id: Optional[str] = None
    extra: dict = field(default_factory=dict)
