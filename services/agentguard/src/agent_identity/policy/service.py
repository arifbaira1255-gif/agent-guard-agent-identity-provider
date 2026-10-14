"""Step 10 ``PolicyDecisionService`` — the single policy decision + lifecycle entry point.

Responsibilities
----------------
* **Decision.** :meth:`authorize` assembles a :class:`PolicyInput` from VERIFIED server-side state,
  evaluates the applicable active policies through the OPA engine, applies JIT-grant and
  approval logic, caches only ALLOW decisions, audits every outcome, and returns a
  :class:`PolicyDecision`. It fails closed: an engine outage, a malformed result or an
  ``INDETERMINATE`` outcome is never an allow.
* **Lifecycle.** create / validate / test / activate / rollback / disable / delete policies, with
  ownership, RBAC administration permissions, versioning and change auditing.
* **Default deny.** When a policy engine is configured but no active policy applies to the request,
  the decision is DENY (``no_matching_policy``). Nothing is allowed by omission.

The service never trusts client-supplied authority: the tenant, agent identity, capabilities and
credential status all come from the verified credential (Step 1-9) and the RBAC resolver (Step 8).
"""
from __future__ import annotations

import hashlib
import time
from typing import List, Optional, Tuple

from ..core.errors import ForbiddenError, NotFoundError, ValidationError
from ..security.ids import new_id
from ..security.rbac import (P_POLICY_ACTIVATE, P_POLICY_READ, P_POLICY_WRITE, Authorizer)
from .approval import ApprovalProvider, NeutralRiskProvider, RiskSignalProvider
from .audit import (E_DECISION, E_ENGINE_UNAVAILABLE, E_POLICY_ACTIVATED, E_POLICY_CREATED,
                    E_POLICY_DELETED, E_POLICY_DISABLED, E_POLICY_ROLLED_BACK, E_POLICY_TESTED,
                    E_POLICY_VALIDATED, E_POLICY_VERSION_CREATED, PolicyAudit)
from .cache import DecisionCache
from .config import PolicyConfig
from .engine import PolicyEngine, validate_rego
from .errors import PolicyConflictError, PolicyNotFoundError, PolicyValidationError
from .jit import JitGrantService
from .models import (DecisionKind, PolicyDecision, PolicyInput, PolicyRecord, PolicyStatus,
                     PolicyVersion, VersionStatus)
from .store import PolicyStore


def _checksum(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


class PolicyDecisionService:
    def __init__(self, store: PolicyStore, engine: PolicyEngine, config: PolicyConfig, *,
                 cache: Optional[DecisionCache] = None, jit: Optional[JitGrantService] = None,
                 approvals: Optional[ApprovalProvider] = None,
                 risk: Optional[RiskSignalProvider] = None, audit: Optional[PolicyAudit] = None,
                 clock=None):
        self.store = store
        self.engine = engine
        self.cfg = config
        self.cache = cache
        self.audit = audit or PolicyAudit(store)
        self.jit = jit or JitGrantService(store, config, audit=self.audit, clock=clock)
        self.approvals = approvals
        self.risk = risk or NeutralRiskProvider()
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ================================================================== decision
    def authorize(self, *, agent_id: str, tenant: str, action: str, resource: str,
                  instance_id: Optional[str] = None, capabilities: Tuple[str, ...] = (),
                  credential_status: str = "valid", environment: str = "development",
                  request_context: Optional[dict] = None, resource_tenant: str = "",
                  is_sub_agent: bool = False, parent_agent_id: Optional[str] = None,
                  correlation_id: Optional[str] = None) -> PolicyDecision:
        """Evaluate policy for one (agent, tenant, action, resource) request. Never raises for a
        plain deny; always returns a :class:`PolicyDecision`."""
        if not action or not isinstance(action, str):
            return PolicyDecision.deny("missing_action", correlation_id=correlation_id)
        if not resource or not isinstance(resource, str):
            return PolicyDecision.deny("missing_resource", correlation_id=correlation_id)
        if not tenant or not isinstance(tenant, str):
            return PolicyDecision.deny("missing_tenant", correlation_id=correlation_id)

        # --- tenant boundary: a tenant may never act on another tenant's resource -------------
        if resource_tenant and resource_tenant != tenant:
            return self._finish(PolicyDecision.deny("tenant_boundary_violation",
                                                    correlation_id=correlation_id),
                                agent_id=agent_id, tenant=tenant, action=action, resource=resource,
                                policy_version=None, correlation_id=correlation_id)

        # --- assemble verified input ----------------------------------------------------------
        risk = self.risk.signal_for(org_id=tenant, agent_id=agent_id, action=action,
                                    resource=resource, context=request_context)
        live_grants = self.jit.live_grants_for(org_id=tenant, agent_id=agent_id) if self.cfg.jit_enabled else []
        approval = {"valid": False}
        if self.approvals is not None:
            a = self.approvals.check(org_id=tenant, agent_id=agent_id, action=action, resource=resource)
            if a is not None:
                approval = {"valid": True, "approval_id": a.approval_id, "decided_by": a.decided_by}

        applicable = self._applicable_policies(tenant)
        active_version_str = self._active_version_string(applicable)

        # --- cache (ALLOW only) ---------------------------------------------------------------
        if self.cache is not None:
            cached = self.cache.get(org_id=tenant, agent_id=agent_id, action=action,
                                    resource=resource, policy_version=active_version_str)
            if cached is not None:
                return self._finish(cached, agent_id=agent_id, tenant=tenant, action=action,
                                    resource=resource, policy_version=active_version_str,
                                    correlation_id=correlation_id, audit=False)

        # --- evaluate every applicable active policy ------------------------------------------
        decisions: List[PolicyDecision] = []
        for record, version in applicable:
            input_doc = PolicyInput(
                agent_id=agent_id, instance_id=instance_id, tenant=tenant, action=action,
                resource=resource, capabilities=tuple(capabilities or ()),
                credential_status=credential_status, environment=environment,
                request_context=dict(request_context or {}), risk=risk,
                jit_grants=tuple(g.public_dict() for g in live_grants), approval=approval,
                policy_version=f"{record.policy_id}@v{version.version}",
                resource_tenant=resource_tenant, is_sub_agent=is_sub_agent,
                parent_agent_id=parent_agent_id).to_engine_input()
            decisions.append(self.engine.evaluate(
                policy_source=version.rego_source, policy_id=record.policy_id,
                version=version.version, input_doc=input_doc, correlation_id=correlation_id))

        kind, reason, policy_id, policy_version = self._combine(decisions)
        decision = PolicyDecision(kind, reason, policy_id=policy_id, policy_version=policy_version,
                                  decision_id=new_id("dec"), correlation_id=correlation_id)

        # --- JIT: a live grant can satisfy a default-deny (never an explicit policy DENY) ------
        if decision.kind is DecisionKind.DENY and decision.reason == "no_matching_policy":
            grant = self.jit.find_live_grant(org_id=tenant, agent_id=agent_id, action=action,
                                             resource=resource, instance_id=instance_id)
            if grant is not None:
                decision = PolicyDecision.allow("jit_grant", policy_id=policy_id,
                                                policy_version=policy_version,
                                                decision_id=decision.decision_id,
                                                grant_id=grant.grant_id,
                                                correlation_id=correlation_id)

        # --- approval: REQUIRE_APPROVAL is satisfied only by a valid approval ------------------
        if decision.kind is DecisionKind.REQUIRE_APPROVAL and approval.get("valid"):
            decision = PolicyDecision.allow("approval_satisfied", policy_id=policy_id,
                                            policy_version=policy_version,
                                            decision_id=decision.decision_id,
                                            approval_id=approval.get("approval_id"),
                                            correlation_id=correlation_id)

        # --- cache only ALLOW -----------------------------------------------------------------
        if self.cache is not None and decision.kind is DecisionKind.ALLOW:
            self.cache.put(org_id=tenant, agent_id=agent_id, action=action, resource=resource,
                           policy_version=active_version_str, decision=decision)

        return self._finish(decision, agent_id=agent_id, tenant=tenant, action=action,
                            resource=resource, policy_version=active_version_str,
                            correlation_id=correlation_id)

    # ------------------------------------------------------------------ helpers
    def _applicable_policies(self, tenant: str) -> List[Tuple[PolicyRecord, PolicyVersion]]:
        out = []
        for record in self.store.list_policies(org_id=tenant, include_platform=True):
            if record.status is not PolicyStatus.ACTIVE or record.active_version is None:
                continue
            version = self.store.get_version(record.policy_id, record.active_version)
            if version is not None and version.status is VersionStatus.ACTIVE:
                out.append((record, version))
        return out

    @staticmethod
    def _active_version_string(applicable: List[Tuple[PolicyRecord, PolicyVersion]]) -> Optional[str]:
        if not applicable:
            return None
        return ",".join(f"{r.policy_id}@v{v.version}" for r, v in sorted(
            applicable, key=lambda rv: rv[0].policy_id))

    @staticmethod
    def _combine(decisions: List[PolicyDecision]) -> Tuple[DecisionKind, str, Optional[str], Optional[str]]:
        """Combine per-policy decisions. DENY wins; then INDETERMINATE (fail closed); then
        REQUIRE_APPROVAL; then ALLOW. No applicable policy -> default deny."""
        if not decisions:
            return DecisionKind.DENY, "no_matching_policy", None, None
        for d in decisions:
            if d.kind is DecisionKind.DENY:
                return DecisionKind.DENY, d.reason or "policy_denied", d.policy_id, d.policy_version
        for d in decisions:
            if d.kind is DecisionKind.INDETERMINATE:
                return (DecisionKind.INDETERMINATE, d.reason or "indeterminate", d.policy_id,
                        d.policy_version)
        for d in decisions:
            if d.kind is DecisionKind.REQUIRE_APPROVAL:
                return (DecisionKind.REQUIRE_APPROVAL, d.reason or "approval_required", d.policy_id,
                        d.policy_version)
        for d in decisions:
            if d.kind is DecisionKind.ALLOW:
                return DecisionKind.ALLOW, d.reason or "allow", d.policy_id, d.policy_version
        return DecisionKind.DENY, "no_matching_policy", None, None

    def _finish(self, decision: PolicyDecision, *, agent_id, tenant, action, resource,
                policy_version, correlation_id, audit: bool = True) -> PolicyDecision:
        if audit:
            event = E_ENGINE_UNAVAILABLE if decision.kind is DecisionKind.INDETERMINATE else E_DECISION
            self.audit.record(event, org_id=tenant, policy_id=decision.policy_id,
                              outcome=("ok" if decision.kind is DecisionKind.ALLOW else "denied"),
                              reason=decision.reason, correlation_id=correlation_id,
                              actor_user_id=agent_id)
        return decision

    # ================================================================== lifecycle
    def create_policy(self, actor, *, name: str, description: str = "", org_id: Optional[str] = None,
                      rego_source: Optional[str] = None, correlation_id: Optional[str] = None
                      ) -> PolicyRecord:
        """Create a policy (optionally with an initial draft version). Requires ``policy:write``."""
        self._require(actor, P_POLICY_WRITE, org_id=org_id)
        if org_id is None and self.cfg.require_platform_admin_for_global_policy \
                and not getattr(actor, "is_platform_admin", False):
            raise ForbiddenError("only a platform administrator may create a platform-wide policy")
        if not name or not isinstance(name, str) or len(name) > 200:
            raise ValidationError("a policy name is required")
        now = self._now()
        record = PolicyRecord(policy_id=new_id("pol"), org_id=org_id, name=name,
                              description=description or "", owner_user_id=actor.user_id,
                              status=PolicyStatus.DRAFT, active_version=None, created_at=now,
                              updated_at=now, created_by=actor.user_id)
        self.store.put_policy(record)
        self.audit.record(E_POLICY_CREATED, actor_user_id=actor.user_id, org_id=org_id,
                          policy_id=record.policy_id, outcome="ok", correlation_id=correlation_id)
        if rego_source is not None:
            self.create_version(actor, record.policy_id, rego_source=rego_source,
                                correlation_id=correlation_id)
        return self.store.get_policy(record.policy_id)

    def create_version(self, actor, policy_id: str, *, rego_source: str,
                       correlation_id: Optional[str] = None) -> PolicyVersion:
        """Add a new DRAFT version. The source is validated before it is stored."""
        record = self._get_policy(policy_id)
        self._require(actor, P_POLICY_WRITE, org_id=record.org_id)
        validate_rego(rego_source, max_bytes=self.cfg.max_policy_bytes)
        version_no = self.store.next_version_number(policy_id)
        version = PolicyVersion(policy_id=policy_id, version=version_no, org_id=record.org_id,
                                rego_source=rego_source, checksum=_checksum(rego_source),
                                status=VersionStatus.DRAFT, created_at=self._now(),
                                created_by=actor.user_id)
        self.store.put_version(version)
        self.audit.record(E_POLICY_VERSION_CREATED, actor_user_id=actor.user_id, org_id=record.org_id,
                          policy_id=policy_id, policy_version=version_no, outcome="ok",
                          correlation_id=correlation_id)
        return version

    def validate(self, actor, policy_id: str, version: int, *,
                 correlation_id: Optional[str] = None) -> dict:
        record = self._get_policy(policy_id)
        self._require(actor, P_POLICY_READ, org_id=record.org_id)
        v = self._get_version(policy_id, version)
        try:
            validate_rego(v.rego_source, max_bytes=self.cfg.max_policy_bytes)
            ok, reason = True, "valid"
        except PolicyValidationError as exc:
            ok, reason = False, exc.code
        self.audit.record(E_POLICY_VALIDATED, actor_user_id=actor.user_id, org_id=record.org_id,
                          policy_id=policy_id, policy_version=version,
                          outcome=("ok" if ok else "error"), reason=reason,
                          correlation_id=correlation_id)
        return {"valid": ok, "reason": reason}

    def test(self, actor, policy_id: str, version: int, *, cases: List[dict],
             correlation_id: Optional[str] = None) -> dict:
        """Run a policy version against test cases BEFORE activation. Each case is
        ``{"input": {...}, "expect": "ALLOW"|"DENY"|"REQUIRE_APPROVAL"}`` (``expect`` optional)."""
        record = self._get_policy(policy_id)
        self._require(actor, P_POLICY_READ, org_id=record.org_id)
        v = self._get_version(policy_id, version)
        results, passed, failed = [], 0, 0
        for case in cases or []:
            input_doc = case.get("input") if isinstance(case, dict) else None
            if not isinstance(input_doc, dict):
                results.append({"error": "invalid_case"})
                failed += 1
                continue
            decision = self.engine.evaluate(policy_source=v.rego_source, policy_id=policy_id,
                                            version=version, input_doc=input_doc)
            expect = case.get("expect")
            ok = (expect is None) or (decision.kind.value == str(expect).upper())
            passed += 1 if ok else 0
            failed += 0 if ok else 1
            results.append({"decision": decision.kind.value, "reason": decision.reason,
                            "expect": expect, "ok": ok})
        summary = {"total": len(results), "passed": passed, "failed": failed, "results": results}
        import dataclasses
        self.store.put_version(dataclasses.replace(v, test_summary=summary))
        self.audit.record(E_POLICY_TESTED, actor_user_id=actor.user_id, org_id=record.org_id,
                          policy_id=policy_id, policy_version=version,
                          outcome=("ok" if failed == 0 else "error"),
                          reason=f"passed={passed} failed={failed}", correlation_id=correlation_id)
        return summary

    def activate(self, actor, policy_id: str, version: int, *,
                 correlation_id: Optional[str] = None) -> PolicyRecord:
        """Activate a version: retire the previous active version, mark this one active, and
        invalidate the decision cache for the affected scope."""
        record = self._get_policy(policy_id)
        self._require(actor, P_POLICY_ACTIVATE, org_id=record.org_id)
        if record.org_id is None and self.cfg.require_platform_admin_for_global_policy \
                and not getattr(actor, "is_platform_admin", False):
            raise ForbiddenError("only a platform administrator may activate a platform-wide policy")
        v = self._get_version(policy_id, version)
        validate_rego(v.rego_source, max_bytes=self.cfg.max_policy_bytes)
        import dataclasses
        now = self._now()
        if record.active_version is not None and record.active_version != version:
            prev = self.store.get_version(policy_id, record.active_version)
            if prev is not None:
                self.store.put_version(dataclasses.replace(prev, status=VersionStatus.RETIRED))
        self.store.put_version(dataclasses.replace(v, status=VersionStatus.ACTIVE, activated_at=now))
        updated = dataclasses.replace(record, status=PolicyStatus.ACTIVE, active_version=version,
                                      updated_at=now)
        self.store.put_policy(updated)
        self._invalidate(record.org_id)
        self.audit.record(E_POLICY_ACTIVATED, actor_user_id=actor.user_id, org_id=record.org_id,
                          policy_id=policy_id, policy_version=version, outcome="ok",
                          correlation_id=correlation_id)
        return updated

    def rollback(self, actor, policy_id: str, *, to_version: int,
                 correlation_id: Optional[str] = None) -> PolicyRecord:
        """Roll back to a previously active (retired) version. Equivalent to activating it again."""
        record = self._get_policy(policy_id)
        self._require(actor, P_POLICY_ACTIVATE, org_id=record.org_id)
        target = self._get_version(policy_id, to_version)
        if target.status is VersionStatus.DRAFT:
            raise PolicyConflictError("cannot roll back to a draft version")
        result = self.activate(actor, policy_id, to_version, correlation_id=correlation_id)
        self.audit.record(E_POLICY_ROLLED_BACK, actor_user_id=actor.user_id, org_id=record.org_id,
                          policy_id=policy_id, policy_version=to_version, outcome="ok",
                          correlation_id=correlation_id)
        return result

    def disable(self, actor, policy_id: str, *, correlation_id: Optional[str] = None) -> PolicyRecord:
        record = self._get_policy(policy_id)
        self._require(actor, P_POLICY_ACTIVATE, org_id=record.org_id)
        import dataclasses
        updated = dataclasses.replace(record, status=PolicyStatus.DISABLED, updated_at=self._now())
        self.store.put_policy(updated)
        self._invalidate(record.org_id)
        self.audit.record(E_POLICY_DISABLED, actor_user_id=actor.user_id, org_id=record.org_id,
                          policy_id=policy_id, outcome="ok", correlation_id=correlation_id)
        return updated

    def delete_policy(self, actor, policy_id: str, *, correlation_id: Optional[str] = None) -> None:
        record = self._get_policy(policy_id)
        self._require(actor, P_POLICY_WRITE, org_id=record.org_id)
        self.store.delete_policy(policy_id)
        self._invalidate(record.org_id)
        self.audit.record(E_POLICY_DELETED, actor_user_id=actor.user_id, org_id=record.org_id,
                          policy_id=policy_id, outcome="ok", correlation_id=correlation_id)

    def list_policies(self, actor, *, org_id: Optional[str] = None) -> List[PolicyRecord]:
        self._require(actor, P_POLICY_READ, org_id=org_id)
        return self.store.list_policies(org_id=org_id, include_platform=True)

    def get_policy(self, actor, policy_id: str) -> PolicyRecord:
        record = self._get_policy(policy_id)
        self._require(actor, P_POLICY_READ, org_id=record.org_id)
        return record

    def list_versions(self, actor, policy_id: str) -> List[PolicyVersion]:
        record = self._get_policy(policy_id)
        self._require(actor, P_POLICY_READ, org_id=record.org_id)
        return self.store.list_versions(policy_id)

    # ================================================================== helpers
    def _require(self, actor, perm: str, *, org_id: Optional[str] = None) -> None:
        try:
            Authorizer.require(actor, perm, org_id=org_id)
        except ForbiddenError:
            self.audit.record("policy.authz.denied", actor_user_id=getattr(actor, "user_id", None),
                              org_id=org_id, outcome="denied", reason="permission_denied")
            raise

    def _invalidate(self, org_id: Optional[str]) -> None:
        if self.cache is None:
            return
        if org_id is None:
            self.cache.invalidate_all()
        else:
            self.cache.invalidate_tenant(org_id)

    def _get_policy(self, policy_id: str) -> PolicyRecord:
        record = self.store.get_policy(policy_id)
        if record is None:
            raise PolicyNotFoundError("policy not found")
        return record

    def _get_version(self, policy_id: str, version: int) -> PolicyVersion:
        v = self.store.get_version(policy_id, version)
        if v is None:
            raise PolicyNotFoundError("policy version not found")
        return v


def make_policy_hook(service: PolicyDecisionService):
    """Build the ``set_policy_hook`` callable for the HTTP transport.

    The hook receives the already-verified request (the transport has validated the credential and
    possession proof and injected ``_agent_id`` / ``_instance_id`` / ``_org_id`` / ``_capabilities``).
    It returns a plain dict so the transport stays decoupled from the policy package.
    """
    def hook(svc, request: dict) -> dict:  # noqa: ARG001 - svc unused; signature fixed by transport
        decision = service.authorize(
            agent_id=request.get("_agent_id") or request.get("agent_id") or "",
            tenant=request.get("_org_id") or request.get("org_id") or "",
            action=request.get("action") or "",
            resource=request.get("resource") or "",
            instance_id=request.get("_instance_id") or request.get("instance_id"),
            capabilities=tuple(request.get("_capabilities") or ()),
            credential_status="valid",
            environment=request.get("environment") or "development",
            request_context=request.get("context") if isinstance(request.get("context"), dict) else {},
            correlation_id=request.get("correlation_id"))
        return decision.to_dict()
    return hook
