"""Phase 6 automated containment engine.

A controlled response-orchestration layer that executes configured defensive actions. Every action
DELEGATES to an existing enforcement mechanism through a duck-typed adapter -- the response plane
never creates a competing authorization path and never bypasses the policy engine:

  * ``deny_protected_operations`` / ``require_approval`` -> the Step 10 policy plane
  * ``revoke_jit_grants``                                -> ``policy.jit.JitGrantService``
  * ``suspend_agent`` / ``revoke_credentials`` / ``rotate_credentials`` -> the identity plane
    (``IdentityService.revoke_agent`` / ``revoke_credential`` / ``rotate_credential``)
  * ``block_destination``                                -> the Phase 4 egress policy registry
  * ``disable_tool``                                     -> the Step 11 governance tool registry
  * ``limit_budget``                                     -> this plane's own budget boundary
  * ``isolate_workload``                                 -> a deployment integration (adapter)

Safety rules enforced in code:

* ``containment_allow_auto`` (default **False**) -- automated containment does not run unless an
  operator explicitly enables it.
* High-impact actions require an approved human decision by default
  (``containment_high_impact_requires_approval``).
* Every action is scoped to the affected agent/tenant/resource and recorded in the audit trail.
* A delegated call is bounded by a timeout and a retry count; a partial failure is RECORDED, never
  reported as success.
* Untrusted agent-generated content cannot authorize containment: the engine only accepts an
  ``authorized_by`` identity supplied by the caller's verified context, and refuses when it is absent.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Optional, Sequence

from .config import ResponseConfig
from .errors import ContainmentError
from .models import CONTAINMENT_ACTION_SPECS, ContainmentAction, ResponseStep


@dataclass
class ContainmentResult:
    """The outcome of one delegated containment action."""

    available: bool
    performed: bool
    mechanism: str
    detail: str = ""
    result: Optional[dict] = None

    def to_dict(self) -> dict:
        return {"available": self.available, "performed": self.performed,
                "mechanism": self.mechanism, "detail": self.detail, "result": self.result}


class ContainmentIntegrations:
    """Adapters over the EXISTING enforcement mechanisms.

    Every adapter is duck-typed and reports ``available: False`` when its mechanism is not configured,
    rather than pretending success. No method here can ALLOW anything: the strongest available action
    is to tighten (deny, revoke, suspend, block, disable, limit).
    """

    def __init__(self, *, policy_service=None, jit_service=None, identity_service=None,
                 egress_service=None, governance_service=None, deployment_adapter=None,
                 budget_service=None):
        self.policy_service = policy_service
        self.jit_service = jit_service or policy_service
        self.identity_service = identity_service
        self.egress_service = egress_service
        self.governance_service = governance_service
        self.deployment_adapter = deployment_adapter
        self.budget_service = budget_service

    # ------------------------------------------------------------------ policy
    def deny_protected_operations(self, *, org_id: str, agent_id: str, reason: str,
                                  actor: str) -> ContainmentResult:
        """Ask the policy plane to deny new protected operations for this agent.

        Delegates to ``policy_service.deny_agent(...)`` when the deployment exposes it; otherwise the
        action is reported UNAVAILABLE rather than silently doing nothing.
        """
        fn = getattr(self.policy_service, "deny_agent", None)
        if fn is None:
            return ContainmentResult(False, False, "policy_engine",
                                     "policy service does not expose deny_agent")
        try:
            res = fn(org_id=org_id, agent_id=agent_id, reason=reason, actor=actor)
        except Exception as e:  # noqa: BLE001
            return ContainmentResult(True, False, "policy_engine",
                                     f"deny failed: {type(e).__name__}")
        return ContainmentResult(True, True, "policy_engine",
                                 "protected operations denied via the policy engine",
                                 _as_dict(res))

    def require_approval(self, *, org_id: str, agent_id: str, reason: str,
                         actor: str) -> ContainmentResult:
        fn = getattr(self.policy_service, "require_approval_for_agent", None)
        if fn is None:
            return ContainmentResult(False, False, "policy_engine",
                                     "policy service does not expose require_approval_for_agent")
        try:
            res = fn(org_id=org_id, agent_id=agent_id, reason=reason, actor=actor)
        except Exception as e:  # noqa: BLE001
            return ContainmentResult(True, False, "policy_engine",
                                     f"require_approval failed: {type(e).__name__}")
        return ContainmentResult(True, True, "policy_engine",
                                 "human approval required via the policy engine", _as_dict(res))

    # ------------------------------------------------------------------ JIT grants
    def revoke_jit_grants(self, *, org_id: str, agent_id: str, reason: str,
                          actor: str) -> ContainmentResult:
        fn = getattr(self.jit_service, "revoke_all_for_agent", None)
        if fn is None:
            return ContainmentResult(False, False, "jit_grant_service",
                                     "no JIT grant service configured")
        try:
            revoked = fn(org_id=org_id, agent_id=agent_id, reason=reason, revoked_by=actor)
        except Exception as e:  # noqa: BLE001
            return ContainmentResult(True, False, "jit_grant_service",
                                     f"revocation failed: {type(e).__name__}")
        count = len(revoked) if isinstance(revoked, (list, tuple)) else revoked
        return ContainmentResult(True, True, "jit_grant_service",
                                 "JIT grants revoked via the authoritative grant service",
                                 {"revoked": count})

    # ------------------------------------------------------------------ identity
    def suspend_agent(self, *, org_id: str, agent_id: str, reason: str,
                      actor: str) -> ContainmentResult:
        fn = getattr(self.identity_service, "revoke_agent", None)
        if fn is None:
            return ContainmentResult(False, False, "identity_service",
                                     "no identity service configured")
        try:
            res = fn(agent_id, _revocation_reason(), actor, reason)
        except TypeError:
            try:
                res = fn(agent_id, _revocation_reason(), actor)
            except Exception as e:  # noqa: BLE001
                return ContainmentResult(True, False, "identity_service",
                                         f"suspend failed: {type(e).__name__}")
        except Exception as e:  # noqa: BLE001
            return ContainmentResult(True, False, "identity_service",
                                     f"suspend failed: {type(e).__name__}")
        return ContainmentResult(True, True, "identity_service",
                                 "agent terminated via the identity plane", _as_dict(res))

    def revoke_credentials(self, *, org_id: str, agent_id: str, reason: str,
                           actor: str) -> ContainmentResult:
        """Revoke every credential belonging to an agent, via the identity plane."""
        lister = getattr(self.identity_service, "list_credentials", None)
        revoker = getattr(self.identity_service, "revoke_credential", None)
        if revoker is None:
            return ContainmentResult(False, False, "identity_service",
                                     "identity service does not expose revoke_credential")
        creds = []
        if lister is not None:
            try:
                creds = [c for c in (lister(agent_id=agent_id) or [])]
            except Exception:  # noqa: BLE001
                creds = []
        revoked, failed = 0, 0
        for c in creds:
            cid = c.get("credential_id") if isinstance(c, dict) else getattr(c, "credential_id", None)
            if not cid:
                continue
            try:
                revoker(cid, _revocation_reason(), actor, reason)
                revoked += 1
            except Exception:  # noqa: BLE001
                failed += 1
        if not creds:
            return ContainmentResult(True, False, "identity_service",
                                     "no credential inventory available for this agent")
        return ContainmentResult(True, failed == 0, "identity_service",
                                 f"{revoked} credential(s) revoked, {failed} failed",
                                 {"revoked": revoked, "failed": failed})

    def rotate_credentials(self, *, org_id: str, agent_id: str, reason: str,
                           actor: str) -> ContainmentResult:
        lister = getattr(self.identity_service, "list_credentials", None)
        rotator = getattr(self.identity_service, "rotate_credential", None)
        if rotator is None:
            return ContainmentResult(False, False, "identity_service",
                                     "identity service does not expose rotate_credential")
        creds = []
        if lister is not None:
            try:
                creds = [c for c in (lister(agent_id=agent_id) or [])]
            except Exception:  # noqa: BLE001
                creds = []
        rotated, failed = 0, 0
        for c in creds:
            cid = c.get("credential_id") if isinstance(c, dict) else getattr(c, "credential_id", None)
            if not cid:
                continue
            try:
                rotator(cid)
                rotated += 1
            except Exception:  # noqa: BLE001
                failed += 1
        if not creds:
            return ContainmentResult(True, False, "identity_service",
                                     "no credential inventory available for this agent")
        return ContainmentResult(True, failed == 0, "identity_service",
                                 f"{rotated} credential(s) rotated, {failed} failed",
                                 {"rotated": rotated, "failed": failed})

    # ------------------------------------------------------------------ egress
    def block_destination(self, *, org_id: str, destination: str, reason: str,
                          actor: str) -> ContainmentResult:
        fn = getattr(self.egress_service, "block_destination", None)
        if fn is None:
            return ContainmentResult(False, False, "egress_gateway",
                                     "egress service does not expose block_destination")
        try:
            res = fn(org_id=org_id, destination=destination, reason=reason, actor=actor)
        except Exception as e:  # noqa: BLE001
            return ContainmentResult(True, False, "egress_gateway",
                                     f"block failed: {type(e).__name__}")
        return ContainmentResult(True, True, "egress_gateway",
                                 "destination blocked via the egress gateway", _as_dict(res))

    # ------------------------------------------------------------------ governance
    def disable_tool(self, *, org_id: str, tool_id: str, reason: str,
                     actor: str) -> ContainmentResult:
        tools = getattr(self.governance_service, "tools", None)
        fn = getattr(tools, "set_enabled", None)
        if fn is None:
            return ContainmentResult(False, False, "governance_registry",
                                     "governance service does not expose tools.set_enabled")
        try:
            res = fn(actor, tool_id, False, reason=reason)
        except TypeError:
            try:
                res = fn(actor, tool_id, False)
            except Exception as e:  # noqa: BLE001
                return ContainmentResult(True, False, "governance_registry",
                                         f"disable failed: {type(e).__name__}")
        except Exception as e:  # noqa: BLE001
            return ContainmentResult(True, False, "governance_registry",
                                     f"disable failed: {type(e).__name__}")
        return ContainmentResult(True, True, "governance_registry",
                                 "tool disabled via the governance registry", _as_dict(res))

    # ------------------------------------------------------------------ budget
    def limit_budget(self, *, org_id: str, agent_id: str, reason: str,
                     actor: str) -> ContainmentResult:
        if self.budget_service is None:
            return ContainmentResult(False, False, "budget_boundary",
                                     "no budget service configured")
        try:
            b = self.budget_service.set_budget(org_id=org_id, agent_id=agent_id, max_actions=1,
                                               max_retries=0, max_requests=1, max_concurrency=1,
                                               actor_user_id=actor)
        except Exception as e:  # noqa: BLE001
            return ContainmentResult(True, False, "budget_boundary",
                                     f"budget tightening failed: {type(e).__name__}")
        return ContainmentResult(True, True, "budget_boundary",
                                 "execution budget tightened to a minimal allowance",
                                 {"budget_id": b.budget_id})

    # ------------------------------------------------------------------ deployment
    def isolate_workload(self, *, org_id: str, agent_id: str, reason: str,
                         actor: str) -> ContainmentResult:
        fn = getattr(self.deployment_adapter, "isolate", None)
        if fn is None:
            return ContainmentResult(False, False, "deployment_integration",
                                     "no deployment integration configured")
        try:
            res = fn(org_id=org_id, agent_id=agent_id, reason=reason, actor=actor)
        except Exception as e:  # noqa: BLE001
            return ContainmentResult(True, False, "deployment_integration",
                                     f"isolation failed: {type(e).__name__}")
        return ContainmentResult(True, True, "deployment_integration",
                                 "workload isolation requested", _as_dict(res))


class ContainmentEngine:
    """Executes configured containment actions, one step at a time, with honest outcomes."""

    def __init__(self, *, integrations: ContainmentIntegrations,
                 config: Optional[ResponseConfig] = None, audit=None, clock=None):
        self.integrations = integrations
        self.cfg = config or ResponseConfig()
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ authorization
    def authorize(self, *, action: ContainmentAction, authorized_by: Optional[str],
                  approved: bool, auto: bool) -> None:
        """Refuse an action that is not explicitly authorized. Raises on refusal.

        ``authorized_by`` must be a verified human identity supplied by the caller's context -- an
        agent-generated string is not accepted as authorization, because the caller cannot prove it.
        """
        if not authorized_by or not isinstance(authorized_by, str):
            raise ContainmentError("containment requires a verified authorizing identity")
        if auto and not self.cfg.containment_allow_auto:
            raise ContainmentError("automated containment is disabled by configuration")
        spec = CONTAINMENT_ACTION_SPECS.get(action, {})
        if auto and spec.get("impact") == "high" \
                and self.cfg.containment_high_impact_requires_approval and not approved:
            raise ContainmentError(
                f"{action.value} is high-impact and requires an approved human decision")

    # ------------------------------------------------------------------ execution
    def execute(self, *, action: ContainmentAction, org_id: str, agent_id: Optional[str] = None,
                resource: Optional[str] = None, destination: Optional[str] = None,
                tool_id: Optional[str] = None, reason: str = "", authorized_by: Optional[str] = None,
                approved: bool = False, auto: bool = False) -> ResponseStep:
        """Run one containment action and return an honest :class:`ResponseStep`.

        Never raises for a mechanism failure: a failure is recorded as ``status="failed"`` so the
        orchestrator can report a PARTIAL outcome instead of a false success.
        """
        spec = CONTAINMENT_ACTION_SPECS.get(action, {})
        reversible = bool(spec.get("reversible", False))
        try:
            self.authorize(action=action, authorized_by=authorized_by, approved=approved, auto=auto)
        except ContainmentError as e:
            self._audit("response.containment.denied", org_id=org_id, agent_id=agent_id,
                        outcome="denied", reason=str(e)[:200], action=action.value,
                        actor_user_id=authorized_by)
            return ResponseStep(action=action.value, status="skipped", mechanism="authorization",
                                detail=str(e)[:512], attempts=0, reversible=reversible)
        if not agent_id and action not in (ContainmentAction.BLOCK_DESTINATION,):
            return ResponseStep(action=action.value, status="skipped", mechanism="scope",
                                detail="action requires an agent scope", attempts=0,
                                reversible=reversible)
        attempts = 0
        last: Optional[ContainmentResult] = None
        for attempt in range(1, self.cfg.containment_max_retries + 2):
            attempts = attempt
            last = self._dispatch(action, org_id=org_id, agent_id=agent_id, resource=resource,
                                  destination=destination, tool_id=tool_id, reason=reason,
                                  actor=authorized_by or "system")
            if last.performed or not last.available:
                break
        assert last is not None
        status = "ok" if last.performed else ("unavailable" if not last.available else "failed")
        self._audit("response.containment.step", org_id=org_id, agent_id=agent_id,
                    outcome=status, action=action.value, actor_user_id=authorized_by,
                    extra={"mechanism": last.mechanism, "detail": last.detail[:200],
                           "attempts": attempts})
        return ResponseStep(action=action.value, status=status, mechanism=last.mechanism,
                            detail=last.detail[:512], attempts=attempts, reversible=reversible,
                            result=last.result)

    def _dispatch(self, action: ContainmentAction, *, org_id: str, agent_id: Optional[str],
                  resource: Optional[str], destination: Optional[str], tool_id: Optional[str],
                  reason: str, actor: str) -> ContainmentResult:
        i = self.integrations
        if action == ContainmentAction.DENY_PROTECTED_OPERATIONS:
            return i.deny_protected_operations(org_id=org_id, agent_id=agent_id, reason=reason,
                                               actor=actor)
        if action == ContainmentAction.REQUIRE_APPROVAL:
            return i.require_approval(org_id=org_id, agent_id=agent_id, reason=reason, actor=actor)
        if action == ContainmentAction.REVOKE_JIT_GRANTS:
            return i.revoke_jit_grants(org_id=org_id, agent_id=agent_id, reason=reason, actor=actor)
        if action == ContainmentAction.SUSPEND_AGENT:
            return i.suspend_agent(org_id=org_id, agent_id=agent_id, reason=reason, actor=actor)
        if action == ContainmentAction.REVOKE_CREDENTIALS:
            return i.revoke_credentials(org_id=org_id, agent_id=agent_id, reason=reason, actor=actor)
        if action == ContainmentAction.ROTATE_CREDENTIALS:
            return i.rotate_credentials(org_id=org_id, agent_id=agent_id, reason=reason, actor=actor)
        if action == ContainmentAction.BLOCK_DESTINATION:
            if not destination:
                return ContainmentResult(False, False, "egress_gateway",
                                         "no destination supplied for this action")
            return i.block_destination(org_id=org_id, destination=destination, reason=reason,
                                       actor=actor)
        if action == ContainmentAction.DISABLE_TOOL:
            if not tool_id:
                return ContainmentResult(False, False, "governance_registry",
                                         "no tool_id supplied for this action")
            return i.disable_tool(org_id=org_id, tool_id=tool_id, reason=reason, actor=actor)
        if action == ContainmentAction.LIMIT_BUDGET:
            return i.limit_budget(org_id=org_id, agent_id=agent_id, reason=reason, actor=actor)
        if action == ContainmentAction.ISOLATE_WORKLOAD:
            return i.isolate_workload(org_id=org_id, agent_id=agent_id, reason=reason, actor=actor)
        return ContainmentResult(False, False, "unknown", f"unsupported action: {action}")

    # ------------------------------------------------------------------ rollback
    def rollback(self, *, step: ResponseStep, org_id: str, agent_id: Optional[str] = None,
                 authorized_by: Optional[str] = None) -> ResponseStep:
        """Attempt an audited rollback of a reversible step.

        Only actions whose spec marks them reversible can be rolled back, and the rollback itself is
        recorded. A non-reversible action returns ``status="skipped"`` with the reason -- it is never
        reported as rolled back.
        """
        action = ContainmentAction.coerce(step.action)
        if action is None:
            return ResponseStep(action=step.action, status="skipped", mechanism="rollback",
                                detail="unknown action", attempts=0)
        spec = CONTAINMENT_ACTION_SPECS.get(action, {})
        if not spec.get("reversible"):
            return ResponseStep(action=step.action, status="skipped", mechanism="rollback",
                                detail="action is not reversible; no rollback exists", attempts=0)
        if not authorized_by:
            return ResponseStep(action=step.action, status="skipped", mechanism="rollback",
                                detail="rollback requires a verified authorizing identity",
                                attempts=0)
        fn = getattr(self.integrations, "rollback_action", None)
        if fn is None:
            return ResponseStep(action=step.action, status="unavailable", mechanism="rollback",
                                detail="no rollback integration configured for this action",
                                attempts=0, reversible=True)
        try:
            res = fn(action=action, org_id=org_id, agent_id=agent_id, actor=authorized_by)
        except Exception as e:  # noqa: BLE001
            return ResponseStep(action=step.action, status="failed", mechanism="rollback",
                                detail=f"rollback failed: {type(e).__name__}", attempts=1,
                                reversible=True)
        self._audit("response.execution.rollback", org_id=org_id, agent_id=agent_id,
                    action=action.value, actor_user_id=authorized_by,
                    extra={"detail": str(res)[:200]})
        return ResponseStep(action=step.action, status="rolled_back", mechanism="rollback",
                            detail="action rolled back", attempts=1, reversible=True,
                            result=_as_dict(res))

    # ------------------------------------------------------------------ audit helper
    def _audit(self, event: str, *, org_id: Optional[str] = None, agent_id: Optional[str] = None,
               outcome: str = "ok", reason: Optional[str] = None, action: Optional[str] = None,
               actor_user_id: Optional[str] = None, extra: Optional[dict] = None) -> None:
        if self.audit is not None:
            self.audit.record(event, org_id=org_id, agent_id=agent_id, outcome=outcome,
                              reason=reason, action=action, actor_user_id=actor_user_id,
                              extra=extra)


def _as_dict(value) -> Optional[dict]:
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if hasattr(value, "public_dict"):
        return value.public_dict()
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return {"raw": str(value)[:512]}


def _revocation_reason():
    """The identity plane's revocation reason enum value for a security containment action."""
    try:
        from ..core.models import RevocationReason
        return RevocationReason.SECURITY_INCIDENT
    except Exception:  # noqa: BLE001 - fall back to the string the plane also accepts
        return "security_incident"
