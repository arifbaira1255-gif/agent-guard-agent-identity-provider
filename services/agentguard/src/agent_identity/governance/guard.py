"""Step 11 ``ResourceGuard`` — the SINGLE server-side enforcement chokepoint.

Every governed operation passes through :meth:`ResourceGuard.decide` before it may execute, and the
protected callable only ever runs through :meth:`ResourceGuard.enforce` (or
:meth:`authorize_and_run`). There is no other supported execution path — see ``connectors.py`` and
``service.py``, whose only route to a connector is ``authorize_and_run``.

The decision pipeline (fail closed at every step)
-------------------------------------------------
1. **Validate** the descriptor (ids, operation). Malformed input → DENY.
2. **Classify** the target. An unregistered resource or an unrecognised type is handled by an
   explicit, configurable policy that can only be ``deny`` or ``require_approval`` — never ``allow``.
3. **Resolve** the authoritative registry record. Its tenant, type, sensitivity and permitted
   operations win over anything the caller claimed.
4. **Tenant boundary** — a tenant may never act on another tenant's resource.
5. **Operation** least privilege — the operation must be explicitly permitted by the record.
6. **Tool registry** — a tool must be registered, enabled and approved, and the capabilities it
   claims must be within its *approved* set. A manifest declaration never grants anything.
7. **Policy** — the Step 10 policy engine decides, with the registry context merged into
   ``request_context`` so Rego can see type/sensitivity/tool/capabilities.
8. **Escalation** — an otherwise-allowed DESTRUCTIVE operation on a high-sensitivity resource is
   escalated to REQUIRE_APPROVAL. Escalation only ever *tightens* a decision; it can never turn a
   DENY/INDETERMINATE into an allow.
9. **Audit** every outcome (agent, tenant, resource, operation, decision, policy version, cid).
10. **Seal** an ALLOW. :meth:`enforce` accepts only a sealed ALLOW minted by this process; the seal is
    single-use and short-lived, so a client cannot forge or replay a decision.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional, TypeVar

from ..core.errors import ForbiddenError
from ..security.ids import new_id
from ..policy.models import DecisionKind, PolicyDecision
from .audit import E_DECISION, E_DECISION_DENIED, E_ENFORCED, E_REGISTRY_ERROR, GovernanceAudit
from .classifier import ResourceClassifier
from .config import GovernanceConfig
from .errors import RegistryValidationError
from .models import (DESTRUCTIVE_OPERATIONS, GovernanceDecision, GovernanceOutcome, Operation,
                     ResourceDescriptor, Sensitivity)
from .validation import validate_id

T = TypeVar("T")

#: Reasons that represent an EXPLICIT, administrator-issued authorization (as opposed to a policy
#: that simply happens to allow). Used only to decide whether an *unknown* resource may proceed.
_EXPLICIT_GRANT_REASONS = frozenset({"jit_grant", "approval_satisfied"})


class _SealLedger:
    """A bounded, single-use ledger of decision seals.

    A seal proves a decision was produced by THIS server process and has not yet been consumed. It is
    intentionally not a signed token: forging one would require code execution inside the trusted
    process, at which point no in-process control is meaningful. The property that matters is that an
    SDK, tool adapter, or remote caller CANNOT fabricate or replay one.
    """

    def __init__(self, *, max_entries: int, ttl_s: float):
        self._max = max(1, int(max_entries))
        self._ttl = float(ttl_s)
        self._entries: dict[str, float] = {}
        self._lock = threading.Lock()

    def mint(self) -> str:
        token = new_id("gseal")
        now = time.time()
        with self._lock:
            self._entries[token] = now + self._ttl
            if len(self._entries) > self._max:
                self._evict(now)
        return token

    def consume(self, token: Optional[str]) -> bool:
        if not token or not isinstance(token, str):
            return False
        now = time.time()
        with self._lock:
            exp = self._entries.pop(token, None)
            if exp is None or exp < now:
                return False
            return True

    def _evict(self, now: float) -> None:
        for k in [k for k, exp in self._entries.items() if exp < now]:
            self._entries.pop(k, None)
        over = len(self._entries) - self._max
        if over > 0:
            for k in list(self._entries.keys())[:over]:
                self._entries.pop(k, None)

    def __len__(self) -> int:  # pragma: no cover - introspection
        with self._lock:
            return len(self._entries)


class ResourceGuard:
    def __init__(self, policy_service, resources, tools, *, config: Optional[GovernanceConfig] = None,
                 audit: Optional[GovernanceAudit] = None, clock=None, seal_ledger=None,
                 egress=None):
        self.policy = policy_service
        self.resources = resources
        self.tools = tools
        self.cfg = config or GovernanceConfig()
        self.audit = audit or GovernanceAudit(
            resources.store if resources is not None else None, enabled=self.cfg.audit_enabled)
        self._clock = clock
        self.classifier = ResourceClassifier()
        self._seals = seal_ledger or _SealLedger(max_entries=self.cfg.seal_max_entries,
                                                 ttl_s=self.cfg.seal_ttl_s)
        # Phase 4: an OPTIONAL egress gateway. When bound, outbound HTTP/tool calls are additionally
        # governed at the network boundary (destination policy + SSRF + DLP) via
        # ``authorize_egress_and_run``. When None, behaviour is exactly as in Step 11.
        self.egress = egress

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ================================================================== decide
    def decide(self, *, agent_id: str, tenant: str, descriptor: ResourceDescriptor,
               instance_id: Optional[str] = None, claimed_capabilities=(),
               environment: str = "development", credential_status: str = "valid",
               is_sub_agent: bool = False, parent_agent_id: Optional[str] = None,
               correlation_id: Optional[str] = None) -> GovernanceDecision:
        """Resolve, then decide. Never raises for a plain denial; always returns a decision."""
        started = time.perf_counter()
        try:
            decision = self._decide(agent_id=agent_id, tenant=tenant, descriptor=descriptor,
                                    instance_id=instance_id,
                                    claimed_capabilities=claimed_capabilities,
                                    environment=environment,
                                    credential_status=credential_status, is_sub_agent=is_sub_agent,
                                    parent_agent_id=parent_agent_id,
                                    correlation_id=correlation_id)
        except RegistryValidationError as exc:
            decision = GovernanceDecision.deny(f"malformed_request:{exc.code}",
                                               correlation_id=correlation_id)
        except Exception:                      # noqa: BLE001 - ANY unexpected error fails closed
            self._audit(E_REGISTRY_ERROR, org_id=tenant, agent_id=agent_id,
                        outcome="error", reason="governance_internal_error",
                        correlation_id=correlation_id)
            decision = GovernanceDecision.indeterminate("governance_internal_error",
                                                        correlation_id=correlation_id)
        latency = int((time.perf_counter() - started) * 1000)
        return GovernanceDecision(**{**decision.__dict__, "latency_ms": latency})

    def _decide(self, *, agent_id, tenant, descriptor, instance_id, claimed_capabilities,
                environment, credential_status, is_sub_agent, parent_agent_id,
                correlation_id) -> GovernanceDecision:
        # ---- 1. validate ----------------------------------------------------------------
        if not isinstance(tenant, str) or not tenant.strip():
            return GovernanceDecision.deny("missing_tenant", correlation_id=correlation_id)
        if not isinstance(agent_id, str) or not agent_id.strip():
            return GovernanceDecision.deny("missing_agent_id", correlation_id=correlation_id)
        if not isinstance(descriptor, ResourceDescriptor):
            return GovernanceDecision.deny("missing_resource_descriptor",
                                           correlation_id=correlation_id)
        try:
            resource_id = validate_id(descriptor.resource_id, field="resource_id")
        except RegistryValidationError:
            return GovernanceDecision.deny("malformed_resource_id",
                                           correlation_id=correlation_id)
        operation = Operation.coerce(descriptor.operation)
        if operation is None:
            # an unknown verb is never inferred from the resource type
            return GovernanceDecision.deny("unknown_operation", resource_id=resource_id,
                                           operation=str(descriptor.operation),
                                           correlation_id=correlation_id)
        classification = self.classifier.classify_descriptor(
            resource_id=resource_id, declared_type=descriptor.resource_type)

        # ---- 2/3. resolve the authoritative registry record ---------------------------------
        record = self.resources.resolve(resource_id) if self.resources is not None else None
        if record is None:
            outcome = self.cfg.unknown_resource_policy
            reason = ("unclassified_resource" if not classification.known else "unknown_resource")
            # An unknown resource is never auto-allowed: default deny, or require approval.
            if outcome == "require_approval":
                return self._require_unknown_approval(
                    agent_id=agent_id, tenant=tenant, resource_id=resource_id, operation=operation,
                    classification=classification, instance_id=instance_id,
                    environment=environment, credential_status=credential_status,
                    correlation_id=correlation_id, reason=reason)
            return self._finalize(GovernanceDecision.deny(reason, resource_id=resource_id,
                                                          operation=operation.value,
                                                          resource_type=classification.value,
                                                          correlation_id=correlation_id),
                                  org_id=tenant, agent_id=agent_id, instance_id=instance_id,
                                  correlation_id=correlation_id, audit=True)

        resource_type = record.resource_type
        sensitivity = record.sensitivity

        # ---- 4. tenant boundary -------------------------------------------------------------
        if record.org_id != tenant:
            return self._finalize(GovernanceDecision.deny(
                "tenant_boundary_violation", resource_id=resource_id, operation=operation.value,
                resource_type=resource_type.value, sensitivity=sensitivity.value,
                correlation_id=correlation_id), org_id=tenant, agent_id=agent_id,
                instance_id=instance_id, correlation_id=correlation_id, audit=True)
        if descriptor.resource_tenant and descriptor.resource_tenant != tenant:
            return self._finalize(GovernanceDecision.deny(
                "tenant_boundary_violation", resource_id=resource_id, operation=operation.value,
                resource_type=resource_type.value, sensitivity=sensitivity.value,
                correlation_id=correlation_id), org_id=tenant, agent_id=agent_id,
                instance_id=instance_id, correlation_id=correlation_id, audit=True)

        # ---- 5. operation least privilege ---------------------------------------------------
        if not record.enabled:
            return self._finalize(GovernanceDecision.deny(
                "resource_disabled", resource_id=resource_id, operation=operation.value,
                resource_type=resource_type.value, sensitivity=sensitivity.value,
                correlation_id=correlation_id), org_id=tenant, agent_id=agent_id,
                instance_id=instance_id, correlation_id=correlation_id, audit=True)
        if not record.permits(operation):
            return self._finalize(GovernanceDecision.deny(
                "operation_not_permitted", resource_id=resource_id, operation=operation.value,
                resource_type=resource_type.value, sensitivity=sensitivity.value,
                correlation_id=correlation_id), org_id=tenant, agent_id=agent_id,
                instance_id=instance_id, correlation_id=correlation_id, audit=True)

        # ---- 6. tool registry ---------------------------------------------------------------
        tool = None
        if descriptor.tool or str(resource_type) == "ResourceType.TOOL" \
                or resource_type.value == "tool":
            tool_id = descriptor.tool
            if tool_id:
                tool = self.tools.resolve_by_name(tool_id, tenant) if self.tools is not None else None
            elif self.tools is not None:
                tool = self.tools.resolve(resource_id)
            if self.tools is None:
                return self._deny_tool("tool_registry_unavailable", resource_id, operation,
                                       resource_type, sensitivity, tenant, agent_id, instance_id,
                                       correlation_id)
            if tool is None:
                return self._deny_tool("tool_not_registered", resource_id, operation, resource_type,
                                       sensitivity, tenant, agent_id, instance_id, correlation_id)
            if not tool.enabled:
                return self._deny_tool("tool_disabled", resource_id, operation, resource_type,
                                       sensitivity, tenant, agent_id, instance_id, correlation_id,
                                       tool_id=tool.tool_id)
            if self.cfg.require_tool_approval and not tool.approved:
                return self._deny_tool("tool_not_approved", resource_id, operation, resource_type,
                                       sensitivity, tenant, agent_id, instance_id, correlation_id,
                                       tool_id=tool.tool_id)
            if tool.resource_id and tool.resource_id != resource_id:
                return self._deny_tool("tool_resource_mismatch", resource_id, operation,
                                       resource_type, sensitivity, tenant, agent_id, instance_id,
                                       correlation_id, tool_id=tool.tool_id)
            # capabilities the CALLER requested must be within the tool's APPROVED set
            requested = tuple(descriptor.requested_capabilities or ())
            approved = set(tool.approved_capabilities)
            if requested and not set(requested) <= approved:
                return self._deny_tool("capability_not_approved", resource_id, operation,
                                       resource_type, sensitivity, tenant, agent_id, instance_id,
                                       correlation_id, tool_id=tool.tool_id)

        # ---- 7. policy decision -------------------------------------------------------------
        request_context = descriptor.to_policy_context()
        request_context.update({
            "resource_type": resource_type.value,
            "sensitivity": sensitivity.value,
            "registry_status": "registered",
            "permitted_operations": sorted(o.value for o in record.permitted_operations),
        })
        if tool is not None:
            request_context["tool_id"] = tool.tool_id
            request_context["tool_risk"] = tool.risk.value
            request_context["approved_capabilities"] = list(tool.approved_capabilities)
        if claimed_capabilities:
            request_context["claimed_capabilities"] = list(claimed_capabilities)

        action = f"{resource_type.value}:{operation.value}"
        policy_decision = self.policy.authorize(
            agent_id=agent_id, tenant=tenant, action=action, resource=resource_id,
            instance_id=instance_id, capabilities=tuple(claimed_capabilities or ()),
            credential_status=credential_status, environment=environment,
            request_context=request_context, resource_tenant=record.org_id,
            is_sub_agent=is_sub_agent, parent_agent_id=parent_agent_id,
            correlation_id=correlation_id)

        outcome = _map_policy_outcome(policy_decision)

        # ---- 8. escalation (tightening only) ------------------------------------------------
        if outcome is GovernanceOutcome.ALLOW and self._should_escalate(operation, sensitivity) \
                and policy_decision.reason != "approval_satisfied":
            outcome = GovernanceOutcome.REQUIRE_APPROVAL

        decision = GovernanceDecision(
            outcome=outcome, reason=(policy_decision.reason or _default_reason(outcome)),
            policy=policy_decision, resource_id=resource_id, resource_type=resource_type.value,
            operation=operation.value, sensitivity=sensitivity.value,
            tool_id=(tool.tool_id if tool is not None else None), correlation_id=correlation_id,
            decision_id=policy_decision.decision_id)
        if outcome is GovernanceOutcome.ALLOW:
            decision = GovernanceDecision(**{**decision.__dict__, "seal": self._seals.mint()})
        return self._finalize(decision, org_id=tenant, agent_id=agent_id, instance_id=instance_id,
                              correlation_id=correlation_id, audit=True)

    # ================================================================== enforce
    def enforce(self, decision: GovernanceDecision, executor: Callable[[], T]) -> T:
        """Run ``executor`` ONLY for a sealed ALLOW. Otherwise raise and never invoke it.

        This is the anti-bypass guarantee: a DENY / REQUIRE_APPROVAL / INDETERMINATE, a decision
        object the caller constructed by hand, or a seal that has already been used all raise
        ``ForbiddenError`` and the protected callable is never reached.
        """
        if not isinstance(decision, GovernanceDecision) \
                or decision.outcome is not GovernanceOutcome.ALLOW:
            reason = getattr(decision, "reason", "denied") or "denied"
            raise ForbiddenError(f"governed operation denied: {reason}")
        if not self._seals.consume(decision.seal):
            raise ForbiddenError("governed operation denied: invalid_or_consumed_decision_seal")
        return executor()

    def authorize_and_run(self, *, agent_id: str, tenant: str, descriptor: ResourceDescriptor,
                          executor: Callable[[], T], **kwargs) -> T:
        decision = self.decide(agent_id=agent_id, tenant=tenant, descriptor=descriptor, **kwargs)
        return self.enforce(decision, executor)

    # ================================================================== egress (Phase 4)
    def authorize_egress_and_run(self, *, agent_id: str, tenant: str, descriptor: ResourceDescriptor,
                                 egress_request, executor: Callable[[], T], **kwargs) -> T:
        """Authorize a governed operation AND its outbound network destination, then run.

        This is the Phase 4 enforcement boundary for outbound HTTP/tool calls. It composes the two
        chokepoints so that BOTH must allow:

          1. the Step 11 governance decision (``decide``) -- *may this agent touch this resource?*
          2. the Phase 4 egress decision (``egress.decide``) -- *may this payload leave to this
             destination?* (destination policy + SSRF/address protection + DLP).

        The executor runs ONLY when both are sealed ALLOWs. A DENY / REQUIRE_APPROVAL /
        INDETERMINATE from either leg raises ``ForbiddenError`` and the executor is never reached.
        The egress leg is consulted with the governance decision's outcome folded into its context,
        so a governance REQUIRE_APPROVAL cannot be loosened by an egress ALLOW.
        """
        if self.egress is None:
            raise ForbiddenError("egress enforcement is not configured on this guard")
        gov_decision = self.decide(agent_id=agent_id, tenant=tenant, descriptor=descriptor, **kwargs)
        if gov_decision.outcome is not GovernanceOutcome.ALLOW:
            raise ForbiddenError(f"governed operation denied: {gov_decision.reason or 'denied'}")
        egress_decision = self.egress.decide(
            agent_id=agent_id, tenant=tenant, request=egress_request,
            instance_id=kwargs.get("instance_id"),
            claimed_capabilities=tuple(kwargs.get("claimed_capabilities") or ()),
            environment=kwargs.get("environment", "development"),
            correlation_id=kwargs.get("correlation_id"))
        if not egress_decision.allowed:
            raise ForbiddenError(f"egress denied: {egress_decision.reason or 'denied'}")
        # Consume BOTH seals, then run. Consuming the governance seal here (rather than via
        # ``enforce``) keeps the two-leg composition explicit and single-use.
        if not self._seals.consume(gov_decision.seal):
            raise ForbiddenError("governed operation denied: invalid_or_consumed_decision_seal")
        return self.egress.enforce(egress_decision, executor)

    # ================================================================== internals
    def _should_escalate(self, operation: Operation, sensitivity: Sensitivity) -> bool:
        if not self.cfg.approval_for_destructive_ops:
            return False
        if operation not in DESTRUCTIVE_OPERATIONS:
            return False
        threshold = Sensitivity.coerce(self.cfg.escalate_at_or_above)
        if threshold is None:                       # config validated; defensive
            return True
        return sensitivity.rank >= threshold.rank

    def _require_unknown_approval(self, *, agent_id, tenant, resource_id, operation, classification,
                                  instance_id, environment, credential_status, correlation_id,
                                  reason) -> GovernanceDecision:
        """Unknown resource with ``require_approval`` config: allow ONLY on an explicit grant."""
        explicit = None
        if getattr(self.policy, "approvals", None) is not None:
            try:
                a = self.policy.approvals.check(org_id=tenant, agent_id=agent_id,
                                                action=f"{classification.value}:{operation.value}",
                                                resource=resource_id)
            except Exception:                       # noqa: BLE001 - fail closed
                a = None
            if a is not None:
                explicit = f"approval:{a.approval_id}"
        if explicit is not None:
            decision = GovernanceDecision.allow("unknown_resource_approved", resource_id=resource_id,
                                                operation=operation.value,
                                                resource_type=classification.value,
                                                correlation_id=correlation_id)
            decision = GovernanceDecision(**{**decision.__dict__, "seal": self._seals.mint()})
            return self._finalize(decision, org_id=tenant, agent_id=agent_id,
                                  instance_id=instance_id, correlation_id=correlation_id, audit=True)
        return self._finalize(GovernanceDecision.require_approval(
            reason, resource_id=resource_id, operation=operation.value,
            resource_type=classification.value, correlation_id=correlation_id),
            org_id=tenant, agent_id=agent_id, instance_id=instance_id,
            correlation_id=correlation_id, audit=True)

    def _deny_tool(self, reason, resource_id, operation, resource_type, sensitivity, tenant,
                   agent_id, instance_id, correlation_id, tool_id=None) -> GovernanceDecision:
        return self._finalize(GovernanceDecision.deny(
            reason, resource_id=resource_id, operation=operation.value,
            resource_type=resource_type.value, sensitivity=sensitivity.value, tool_id=tool_id,
            correlation_id=correlation_id), org_id=tenant, agent_id=agent_id,
            instance_id=instance_id, correlation_id=correlation_id, audit=True)

    def _finalize(self, decision: GovernanceDecision, *, org_id, agent_id, instance_id,
                  correlation_id, audit: bool) -> GovernanceDecision:
        if audit:
            outcome = "ok" if decision.outcome is GovernanceOutcome.ALLOW else "denied"
            event = E_DECISION if decision.outcome is GovernanceOutcome.ALLOW else E_DECISION_DENIED
            self._audit(event, org_id=org_id, agent_id=agent_id, instance_id=instance_id,
                        resource_id=decision.resource_id, resource_type=decision.resource_type,
                        operation=decision.operation, tool_id=decision.tool_id,
                        decision=decision.outcome.value, reason=decision.reason, outcome=outcome,
                        policy_id=(decision.policy.policy_id if decision.policy else None),
                        policy_version=(decision.policy.policy_version if decision.policy else None),
                        correlation_id=correlation_id)
        return decision

    def _audit(self, event, **kwargs) -> None:
        if self.audit is None:
            return
        self.audit.record(event, **kwargs)

    # ------------------------------------------------------------------ audit of execution
    def audit_enforced(self, *, decision: GovernanceDecision, agent_id: str, tenant: str,
                       instance_id: Optional[str] = None, outcome: str = "ok",
                       reason: Optional[str] = None, correlation_id: Optional[str] = None) -> None:
        """Record that a governed operation actually executed (called by the connector boundary)."""
        self._audit(E_ENFORCED, org_id=tenant, agent_id=agent_id, instance_id=instance_id,
                    resource_id=decision.resource_id, resource_type=decision.resource_type,
                    operation=decision.operation, tool_id=decision.tool_id,
                    decision=decision.outcome.value, reason=reason, outcome=outcome,
                    correlation_id=correlation_id)


def _map_policy_outcome(policy_decision: PolicyDecision) -> GovernanceOutcome:
    if policy_decision.kind is DecisionKind.ALLOW:
        return GovernanceOutcome.ALLOW
    if policy_decision.kind is DecisionKind.DENY:
        return GovernanceOutcome.DENY
    if policy_decision.kind is DecisionKind.REQUIRE_APPROVAL:
        return GovernanceOutcome.REQUIRE_APPROVAL
    return GovernanceOutcome.INDETERMINATE


def _default_reason(outcome: GovernanceOutcome) -> str:
    return {GovernanceOutcome.ALLOW: "allow", GovernanceOutcome.DENY: "deny",
            GovernanceOutcome.REQUIRE_APPROVAL: "approval_required",
            GovernanceOutcome.INDETERMINATE: "indeterminate"}[outcome]
