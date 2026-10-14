"""Step 8 RBAC engine: the six product roles, a least-privilege permission matrix, and the
server-side authorization decision point.

Design
------
* **Deny by default.** A request is allowed only if the principal's *effective permission set*
  contains the required permission. Anything not explicitly granted is denied.
* **Two authorization scopes.** GLOBAL (platform) roles and TENANT-scoped roles are evaluated
  separately. A tenant membership can NEVER grant a platform-only role/permission (self-escalation
  guard is enforced here *and* in the storage layer).
* **Tenant scoping is mandatory.** A permission check that needs a tenant resource must receive the
  verified `org_id` from the caller's `AuthContext`; the engine refuses to evaluate otherwise.
* **Ownership.** A `developer` may act only on agents they own; a `security_operator`/tenant admin/
  platform admin may act on any agent in their tenant. This is expressed via ``require_agent_manage``.

The matrix is data, not code, so it can be reviewed and unit-tested exhaustively.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from ..core.errors import ForbiddenError, ValidationError
from .models import (ALL_ROLES, PLATFORM_ONLY_ROLES, ROLE_DEVELOPER, ROLE_PLATFORM_ADMIN,
                     ROLE_READONLY_AUDITOR, ROLE_SECURITY_ANALYST, ROLE_SECURITY_OPERATOR,
                     ROLE_TENANT_ADMIN, TENANT_ROLES)

# --------------------------------------------------------------------------- permissions
# resource:action strings. Grouped for readability; the set is closed (allow-list).
P_AGENT_READ = "agent:read"
P_AGENT_WRITE = "agent:write"                 # register agents
P_AGENT_REVOKE = "agent:revoke"               # terminate an agent (cascades)
P_AGENT_SPAWN = "agent:spawn"                 # create sub-agents
P_INSTANCE_READ = "instance:read"
P_INSTANCE_REVOKE = "instance:revoke"
P_CREDENTIAL_READ = "credential:read"
P_CREDENTIAL_ISSUE = "credential:issue"
P_CREDENTIAL_ROTATE = "credential:rotate"
P_CREDENTIAL_REVOKE = "credential:revoke"
P_AUDIT_READ = "audit:read"
P_TENANT_READ = "tenant:read"
P_TENANT_WRITE = "tenant:write"               # rename/suspend own tenant
P_TENANT_CREATE = "tenant:create"             # create organizations (platform only)
P_USER_READ = "user:read"
P_USER_WRITE = "user:write"                   # create/update/suspend users within scope
P_USER_DELETE = "user:delete"                 # hard-deactivate (platform only)
P_MEMBERSHIP_WRITE = "membership:write"       # add/remove users in a tenant
P_ROLE_ASSIGN = "role:assign"                 # assign/remove roles
P_SESSION_READ = "session:read"
P_SESSION_REVOKE = "session:revoke"           # revoke sessions (self or others, by scope)
P_RBAC_READ = "rbac:read"                     # read roles/permissions of others
P_IDP_READ = "idp:read"
P_IDP_WRITE = "idp:write"                     # configure SSO providers
P_PLATFORM_ADMIN = "platform:admin"           # cross-tenant / platform administration
# Step 10 (policy engine): policy administration is a controlled, separate authority.
P_POLICY_READ = "policy:read"                 # read policy definitions/versions
P_POLICY_WRITE = "policy:write"               # create policies/versions, delete
P_POLICY_ACTIVATE = "policy:activate"         # activate/rollback/disable a policy version
# Step 11 (tool & resource governance): the resource/tool registries are governed separately from
# the policy plane. Registering is distinct from approving/admitting (a registrant must not be able
# to approve their own tool), and enabling/disabling/deleting a registry entry is a distinct
# authority from merely editing it.
P_RESOURCE_READ = "resource:read"             # read governed resources
P_RESOURCE_WRITE = "resource:write"           # register/update governed resources
P_RESOURCE_ADMIN = "resource:admin"           # enable/disable/delete governed resources
P_TOOL_READ = "tool:read"                     # read the tool registry
P_TOOL_WRITE = "tool:write"                   # register tools (does NOT approve them)
P_TOOL_APPROVE = "tool:approve"               # approve a tool + grant its capability set
P_TOOL_ADMIN = "tool:admin"                   # enable/disable/delete tools

# Phase 5 (runtime monitoring): reading the runtime telemetry, behaviour profiles, intent graph, risk
# assessments and alerts is an INVESTIGATION authority; managing alert rules and the behaviour
# baselines (create/reset/retrain) is a distinct CONFIGURATION authority. Neither grants any
# enforcement power -- enforcement stays with the policy engine.
P_RUNTIME_READ = "runtime:read"               # read events/profiles/findings/graph/risk/alerts
P_RUNTIME_ADMIN = "runtime:admin"             # manage alert rules, reset baselines, ack/resolve alerts

# Phase 6 (autonomous response): reading the response plane (findings, budgets, approvals, incidents,
# containment executions, evidence, audit) is an INVESTIGATION authority. Managing budgets, emergency
# stops, incidents and containment is a distinct OPERATIONS authority. Approving a high-risk operation
# is a THIRD, separate authority -- deliberately split so that the identity able to approve is not
# automatically the identity able to execute containment (separation of duties).
P_RESPONSE_READ = "response:read"             # read findings/budgets/approvals/incidents/responses
P_RESPONSE_ADMIN = "response:admin"           # budgets, emergency stops, incidents, containment
P_RESPONSE_APPROVE = "response:approve"       # decide a human-approval request

# Phase 7 (assurance plane): reading recommendations, the tamper-evident audit chain, compliance
# mappings and SIEM delivery status is an INVESTIGATION authority. Managing SIEM destinations,
# recording evidence and seeding compliance mappings is a distinct CONFIGURATION authority.
# APPROVING a policy proposal is a THIRD, separate authority -- deliberately split from
# policy:write (which creates proposals) and policy:activate (which activates them), so the identity
# that authors a change is not automatically the identity that authorizes it (separation of duties).
P_ASSURANCE_READ = "assurance:read"           # read recommendations/audit/compliance/SIEM status
P_ASSURANCE_ADMIN = "assurance:admin"         # SIEM destinations, evidence, compliance seeding
P_ASSURANCE_APPROVE = "assurance:approve"     # approve/reject a policy proposal

PERMISSIONS = frozenset({
    P_AGENT_READ, P_AGENT_WRITE, P_AGENT_REVOKE, P_AGENT_SPAWN,
    P_INSTANCE_READ, P_INSTANCE_REVOKE,
    P_CREDENTIAL_READ, P_CREDENTIAL_ISSUE, P_CREDENTIAL_ROTATE, P_CREDENTIAL_REVOKE,
    P_AUDIT_READ, P_TENANT_READ, P_TENANT_WRITE, P_TENANT_CREATE,
    P_USER_READ, P_USER_WRITE, P_USER_DELETE,
    P_MEMBERSHIP_WRITE, P_ROLE_ASSIGN, P_SESSION_READ, P_SESSION_REVOKE,
    P_RBAC_READ, P_IDP_READ, P_IDP_WRITE, P_PLATFORM_ADMIN,
    P_POLICY_READ, P_POLICY_WRITE, P_POLICY_ACTIVATE,
    P_RESOURCE_READ, P_RESOURCE_WRITE, P_RESOURCE_ADMIN,
    P_TOOL_READ, P_TOOL_WRITE, P_TOOL_APPROVE, P_TOOL_ADMIN,
    P_RUNTIME_READ, P_RUNTIME_ADMIN,
    P_RESPONSE_READ, P_RESPONSE_ADMIN, P_RESPONSE_APPROVE,
    P_ASSURANCE_READ, P_ASSURANCE_ADMIN, P_ASSURANCE_APPROVE,
})

_READ_ONLY_OBSERVE = frozenset({
    P_AGENT_READ, P_INSTANCE_READ, P_CREDENTIAL_READ, P_AUDIT_READ, P_TENANT_READ,
    P_USER_READ, P_SESSION_READ, P_RBAC_READ, P_IDP_READ, P_POLICY_READ,
    P_RESOURCE_READ, P_TOOL_READ, P_RUNTIME_READ, P_RESPONSE_READ, P_ASSURANCE_READ,
})

# --------------------------------------------------------------------------- role matrix
ROLE_PERMISSIONS: dict[str, frozenset] = {
    # Platform Administrator: full authority across all tenants + the platform itself.
    ROLE_PLATFORM_ADMIN: PERMISSIONS,

    # Tenant Administrator: runs one tenant end to end, but CANNOT touch the platform plane or
    # other tenants, and CANNOT hold platform:admin / tenant:create.
    ROLE_TENANT_ADMIN: frozenset({
        P_AGENT_READ, P_AGENT_WRITE, P_AGENT_REVOKE, P_AGENT_SPAWN,
        P_INSTANCE_READ, P_INSTANCE_REVOKE,
        P_CREDENTIAL_READ, P_CREDENTIAL_ISSUE, P_CREDENTIAL_ROTATE, P_CREDENTIAL_REVOKE,
        P_AUDIT_READ, P_TENANT_READ, P_TENANT_WRITE,
        P_USER_READ, P_USER_WRITE, P_MEMBERSHIP_WRITE, P_ROLE_ASSIGN,
        P_SESSION_READ, P_SESSION_REVOKE, P_RBAC_READ, P_IDP_READ, P_IDP_WRITE,
        P_POLICY_READ, P_POLICY_WRITE, P_POLICY_ACTIVATE,
        P_RESOURCE_READ, P_RESOURCE_WRITE, P_RESOURCE_ADMIN,
        P_TOOL_READ, P_TOOL_WRITE, P_TOOL_APPROVE, P_TOOL_ADMIN,
        P_RUNTIME_READ, P_RUNTIME_ADMIN,
        P_RESPONSE_READ, P_RESPONSE_ADMIN, P_RESPONSE_APPROVE,
        P_ASSURANCE_READ, P_ASSURANCE_ADMIN, P_ASSURANCE_APPROVE,
    }),

    # Security Analyst: investigates and can cut off compromised material, but does not provision.
    # Phase 5: an analyst gets the full runtime-investigation surface and may manage alert lifecycle
    # (ack/resolve) but the configuration authority over rules/baselines stays with an admin.
    # Phase 6: an analyst reads the response plane and may DECIDE approvals, but does not hold
    # response:admin -- so the identity that approves containment is not the one that executes it.
    ROLE_SECURITY_ANALYST: frozenset({
        P_AGENT_READ, P_INSTANCE_READ, P_CREDENTIAL_READ, P_AUDIT_READ, P_SESSION_READ,
        P_RBAC_READ, P_CREDENTIAL_REVOKE, P_INSTANCE_REVOKE, P_AGENT_REVOKE, P_SESSION_REVOKE,
        P_POLICY_READ, P_RESOURCE_READ, P_TOOL_READ, P_RUNTIME_READ,
        P_RESPONSE_READ, P_RESPONSE_APPROVE,
        P_ASSURANCE_READ, P_ASSURANCE_APPROVE,
    }),

    # Security Operator: day-to-day issuance/rotation/lifecycle operations for agents.
    # Phase 6: an operator may run containment (response:admin) but may NOT approve -- the approval
    # authority is deliberately held by the analyst/admin roles instead.
    ROLE_SECURITY_OPERATOR: frozenset({
        P_AGENT_READ, P_AGENT_WRITE, P_AGENT_REVOKE, P_AGENT_SPAWN,
        P_INSTANCE_READ, P_INSTANCE_REVOKE,
        P_CREDENTIAL_READ, P_CREDENTIAL_ISSUE, P_CREDENTIAL_ROTATE, P_CREDENTIAL_REVOKE,
        P_POLICY_READ, P_RESOURCE_READ, P_TOOL_READ, P_RUNTIME_READ,
        P_RESPONSE_READ, P_RESPONSE_ADMIN,
        P_ASSURANCE_READ, P_ASSURANCE_ADMIN,
    }),

    # Developer: self-service on the agents they own; cannot revoke others' material.
    ROLE_DEVELOPER: frozenset({
        P_AGENT_READ, P_AGENT_WRITE, P_AGENT_SPAWN,
        P_INSTANCE_READ, P_CREDENTIAL_READ, P_CREDENTIAL_ISSUE, P_CREDENTIAL_ROTATE,
        P_POLICY_READ, P_RESOURCE_READ, P_TOOL_READ, P_RESOURCE_WRITE, P_TOOL_WRITE,
        P_RUNTIME_READ, P_RESPONSE_READ, P_ASSURANCE_READ,
    }),

    # Read-Only Auditor: sees everything it is entitled to see, mutates nothing.
    ROLE_READONLY_AUDITOR: _READ_ONLY_OBSERVE,
}


def validate_role(role: str) -> str:
    if role not in ALL_ROLES:
        raise ValidationError("unknown role")
    return role


def _as_roles(roles: Optional[Iterable[str]]) -> tuple:
    if not roles:
        return ()
    out = []
    for r in roles:
        if not isinstance(r, str) or r not in ROLE_PERMISSIONS:
            raise ValidationError("unknown role")
        out.append(r)
    return tuple(sorted(set(out)))


def sanitize_tenant_roles(roles: Iterable[str]) -> tuple:
    """A tenant membership may only carry tenant-scoped roles. Platform roles are rejected here so a
    tenant admin can never smuggle ``platform_administrator`` into a membership (self-escalation)."""
    out = []
    for r in _as_roles(roles):
        if r in PLATFORM_ONLY_ROLES:
            raise ForbiddenError("platform roles cannot be granted via a tenant membership")
        out.append(r)
    return tuple(out)


def sanitize_global_roles(roles: Iterable[str], *, actor_is_platform_admin: bool) -> tuple:
    """Only a platform administrator may grant/keep a platform (global) role."""
    out = []
    for r in _as_roles(roles):
        if r in PLATFORM_ONLY_ROLES and not actor_is_platform_admin:
            raise ForbiddenError("only a platform administrator can grant a platform role")
        out.append(r)
    return tuple(out)


def permission_matrix() -> dict:
    """Read-only view of the role/permission matrix (for docs, the API, and tests)."""
    return {role: sorted(perms) for role, perms in sorted(ROLE_PERMISSIONS.items())}


@dataclass(frozen=True)
class EffectiveAccess:
    """The resolved authority of a principal within a single tenant scope."""

    user_id: str
    org_id: Optional[str]
    is_platform_admin: bool
    roles: tuple
    permissions: frozenset

    def has(self, perm: str) -> bool:
        if perm not in PERMISSIONS:
            return False                      # unknown permission => deny
        return perm in self.permissions

    def has_all(self, perms: Iterable[str]) -> bool:
        return all(self.has(p) for p in perms)

    def has_any(self, perms: Iterable[str]) -> bool:
        return any(self.has(p) for p in perms)


def effective_access(user_id: str, org_id: Optional[str], *, global_roles: Iterable[str] = (),
                     tenant_roles: Iterable[str] = (), deny: Optional[Iterable[str]] = None) -> EffectiveAccess:
    """Compute the effective permission set for a principal in one tenant scope.

    * GLOBAL roles apply everywhere.
    * TENANT roles apply only when ``org_id`` is set (i.e. inside the tenancy they belong to) —
      the caller is responsible for only passing tenant roles that actually belong to ``org_id``.
    * ``deny`` removes permissions explicitly (explicit-deny support). A deny of ``platform:admin``
      can never be overridden by a later grant (denies are applied last).
    """
    roles = list(_as_roles(global_roles)) + list(_as_roles(tenant_roles))
    perms = set()
    for r in roles:
        perms |= set(ROLE_PERMISSIONS.get(r, frozenset()))
    is_padmin = ROLE_PLATFORM_ADMIN in roles
    if deny:
        for p in deny:
            if p in PERMISSIONS:
                perms.discard(p)
                if p == P_PLATFORM_ADMIN:
                    is_padmin = False
    return EffectiveAccess(user_id, org_id, is_padmin, tuple(sorted(set(roles))),
                           frozenset(perms))


class Authorizer:
    """The single server-side decision point. Every protected operation calls through here.

    It is deliberately small and pure: it never trusts a role/permission supplied by the client —
    the caller must have derived ``EffectiveAccess`` from verified server-side state.
    """

    @staticmethod
    def require(access: EffectiveAccess, perm: str, *, org_id: Optional[str] = None) -> None:
        """Raise ``ForbiddenError`` unless ``access`` holds ``perm`` (optionally within ``org_id``).

        Tenant boundary: if ``org_id`` is provided it MUST equal the access's verified scope, unless
        the principal is a platform administrator acting cross-tenant.
        """
        if org_id is not None and not access.is_platform_admin:
            if access.org_id is None or access.org_id != org_id:
                raise ForbiddenError("not permitted in this tenant")
        if not access.has(perm):
            raise ForbiddenError("permission denied")

    @staticmethod
    def require_any(access: EffectiveAccess, perms: Iterable[str], *, org_id: Optional[str] = None) -> None:
        for p in perms:
            try:
                Authorizer.require(access, p, org_id=org_id)
                return
            except ForbiddenError:
                continue
        raise ForbiddenError("permission denied")

    @staticmethod
    def require_agent_manage(access: EffectiveAccess, *, agent_owner: str, agent_org: str,
                             perm: str) -> None:
        """Manage a specific agent. A ``developer`` may only manage agents they own; operators and
        admins may manage any agent inside their scope."""
        Authorizer.require(access, perm, org_id=agent_org)
        if access.is_platform_admin:
            return
        # A principal whose only management path is the developer role must own the agent.
        if ROLE_DEVELOPER in access.roles and not access.has_any(
                (P_AGENT_REVOKE, P_CREDENTIAL_REVOKE, P_INSTANCE_REVOKE)):
            if agent_owner.lower() != access.user_id.lower():
                # Owner is stored by email in the agent registry; compare case-insensitively.
                raise ForbiddenError("developers may only manage agents they own")
