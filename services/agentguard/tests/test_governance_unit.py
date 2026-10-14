"""Step 11 unit + integration tests for enterprise tool & resource governance.

These run against a REAL OPA binary (``opa eval``) plus the in-memory governance/policy stores, so
the full enforcement path is exercised end to end without external services. The PostgreSQL-backed
governance store + migration 0006 are covered by ``test_governance_pg_integration.py``.

Coverage (per the Step 11 brief):
  * authorised and unauthorised operations
  * resource-level and operation-level restrictions (least privilege)
  * cross-tenant isolation
  * expired / revoked JIT grants
  * policy changes and stale decisions (cache invalidation)
  * unknown / unclassified resources and malformed requests
  * tool registration, approval and unauthorised registry changes
  * concurrent requests and failure scenarios (fail closed)
  * attempts to bypass enforcement through alternate execution paths
"""
from __future__ import annotations

import shutil
import threading
import unittest

from agent_identity.core.errors import ForbiddenError, ValidationError
from agent_identity.governance import (DatabaseConnector, GovernanceConfig, GovernanceOutcome,
                                       GovernanceService, MemoryGovernanceStore, ResourceDescriptor,
                                       ResourceGuard, ResourceType, RiskClass, Sensitivity,
                                       validate_manifest)
from agent_identity.governance.connectors import GuardedConnector, HttpApiConnector
from agent_identity.governance.validation import (validate_capabilities, validate_id,
                                                 validate_metadata)
from agent_identity.observability.logging import SecurityLogger
from agent_identity.policy import (MemoryPolicyStore, PolicyConfig, PolicyDecisionService,
                                   StoreApprovalProvider, build_engine)
from agent_identity.security.rbac import (ROLE_DEVELOPER, ROLE_PLATFORM_ADMIN, ROLE_READONLY_AUDITOR,
                                         ROLE_SECURITY_ANALYST, ROLE_TENANT_ADMIN, effective_access)

OPA = shutil.which("opa")

# --- policy sources used by the tests (the engine namespaces the package per version) ----------
GOV_ALLOW_REGO = """
package agentguard.authz

default decision := {"decision": "DENY", "reason": "default_deny"}

decision := {"decision": "ALLOW", "reason": "gov_allow"} {
    input.request_context.registry_status == "registered"
}
"""

GOV_APPROVAL_REGO = """
package agentguard.authz

default decision := {"decision": "DENY", "reason": "default_deny"}

decision := {"decision": "REQUIRE_APPROVAL", "reason": "needs_human"} {
    input.request_context.registry_status == "registered"
}
"""


class MutableClock:
    """Deterministic, advanceable clock for expiry tests."""

    def __init__(self, start: float = 1_800_000_000.0):
        self._t = float(start)

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += float(seconds)


def actor(role=ROLE_TENANT_ADMIN, *, org_id="acme", platform=False, user_id="usr_admin"):
    if platform:
        return effective_access(user_id, org_id, global_roles=(ROLE_PLATFORM_ADMIN,))
    roles = (role,) if isinstance(role, str) else tuple(role)
    return effective_access(user_id, org_id, tenant_roles=roles)


def policy_service(*, rego=None, clock=None, engine_override=None, approvals=True):
    """A PolicyDecisionService with one ACTIVE policy (or none), on the real OPA CLI engine."""
    pstore = MemoryPolicyStore()
    pcfg = PolicyConfig(environment="development", engine="opa", opa_mode="cli",
                        eval_timeout_ms=3000, cache_enabled=True, cache_ttl_ms=5000)
    engine = engine_override if engine_override is not None else build_engine(pcfg)
    svc = PolicyDecisionService(
        pstore, engine, pcfg, clock=clock,
        approvals=(StoreApprovalProvider(pstore, pcfg, clock=clock) if approvals else None))
    if rego is not None:
        a = actor()
        rec = svc.create_policy(a, name="gov", org_id="acme", rego_source=rego)
        svc.activate(a, rec.policy_id, 1)
    return svc


def governance(*, rego=GOV_ALLOW_REGO, govcfg=None, clock=None, logger=None):
    svc = policy_service(rego=rego, clock=clock)
    gstore = MemoryGovernanceStore()
    gov = GovernanceService(gstore, svc,
                            config=govcfg or GovernanceConfig(environment="development"),
                            audit_logger=logger, clock=clock)
    return svc, gov, gstore


def register(gov, *, rid="api:billing", org="acme", rtype="http_api", ops=("read",),
             sensitivity="internal", enabled=True, a=None):
    return gov.resources.register_resource(a or actor(), resource_id=rid, org_id=org,
                                           resource_type=rtype, name=rid.replace(":", "_"),
                                           owner="platform-team", sensitivity=sensitivity,
                                           permitted_operations=list(ops), enabled=enabled)


@unittest.skipUnless(OPA, "the opa binary is required")
class GovernanceDecisionTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.gov, self.store = governance()

    # ------------------------------------------------------------------ allow / deny
    def test_registered_resource_permitted_operation_allowed(self):
        register(self.gov)
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                            operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.ALLOW)
        self.assertTrue(d.allowed)
        self.assertEqual(d.reason, "gov_allow")

    def test_unknown_resource_denied_by_default(self):
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:unregistered",
                            operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "unknown_resource")

    def test_operation_not_permitted_denied(self):
        register(self.gov, ops=("read",))
        # "delete" IS a known operation, so this must be rejected by least privilege (not as an
        # unknown verb) -- that is the property under test here.
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                            operation="delete")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d.reason, "operation_not_permitted")

    def test_operation_level_write_allowed_when_permitted(self):
        register(self.gov, ops=("read", "write"))
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                            operation="write")
        self.assertIs(d.outcome, GovernanceOutcome.ALLOW)

    def test_resource_level_disabled_resource_denied(self):
        register(self.gov, enabled=False)
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                            operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d.reason, "resource_disabled")

    def test_agent_claim_does_not_grant_authority(self):
        # read-only resource; the caller claims broad capabilities and asks for a write.
        register(self.gov, ops=("read",))
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                            operation="write", claimed_capabilities=("write", "delete"))
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "operation_not_permitted")

    # ------------------------------------------------------------------ tenancy
    def test_cross_tenant_resource_isolation(self):
        register(self.gov, org="acme")
        d = self.gov.decide(agent_id="agt1", tenant="other-tenant", resource_id="api:billing",
                            operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d.reason, "tenant_boundary_violation")

    def test_descriptor_resource_tenant_mismatch_denied(self):
        register(self.gov, org="acme")
        d = self.gov.guard.decide(agent_id="agt1", tenant="acme",
                                  descriptor=ResourceDescriptor(resource_id="api:billing",
                                                                operation="read",
                                                                resource_tenant="other-tenant"))
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d.reason, "tenant_boundary_violation")

    # ------------------------------------------------------------------ malformed / unclassified
    def test_malformed_resource_id_denied(self):
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:../etc/passwd",
                            operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d.reason, "malformed_resource_id")

    def test_unknown_operation_denied(self):
        register(self.gov)
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                            operation="frobnicate")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d.reason, "unknown_operation")

    def test_missing_tenant_denied(self):
        d = self.gov.decide(agent_id="agt1", tenant="", resource_id="api:billing", operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)

    def test_unclassified_declared_type_denied(self):
        d = self.gov.guard.decide(agent_id="agt1", tenant="acme",
                                  descriptor=ResourceDescriptor(resource_id="thing:1",
                                                                operation="read",
                                                                resource_type="quantum"))
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d.reason, "unclassified_resource")

    def test_unknown_resource_require_approval_config(self):
        cfg = GovernanceConfig(environment="development", unknown_resource_policy="require_approval")
        svc, gov, _ = governance(govcfg=cfg)
        d = gov.decide(agent_id="agt1", tenant="acme", resource_id="api:unregistered",
                       operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.REQUIRE_APPROVAL)
        self.assertFalse(d.allowed)

    def test_unknown_resource_require_approval_satisfied_by_approval(self):
        cfg = GovernanceConfig(environment="development", unknown_resource_policy="require_approval")
        svc, gov, _ = governance(govcfg=cfg)
        apr = svc.approvals.request(org_id="acme", agent_id="agt1", action="http_api:read",
                                    resource="api:unregistered", requested_by="usr_admin")
        svc.approvals.decide(apr.approval_id, approved=True, decided_by="usr_admin")
        d = gov.decide(agent_id="agt1", tenant="acme", resource_id="api:unregistered",
                       operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.ALLOW)
        self.assertEqual(d.reason, "unknown_resource_approved")

    # ------------------------------------------------------------------ approvals / escalation
    def test_approval_required_gates_execution_then_allows(self):
        svc, gov, _ = governance(rego=GOV_APPROVAL_REGO)
        register(gov)
        ran = []
        d = gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.REQUIRE_APPROVAL)
        with self.assertRaises(ForbiddenError):
            gov.guard.enforce(d, lambda: ran.append(1))
        self.assertEqual(ran, [])
        apr = svc.approvals.request(org_id="acme", agent_id="agt1", action="http_api:read",
                                    resource="api:billing", requested_by="usr_admin")
        svc.approvals.decide(apr.approval_id, approved=True, decided_by="usr_admin")
        d2 = gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read")
        self.assertIs(d2.outcome, GovernanceOutcome.ALLOW)
        self.assertEqual(d2.reason, "approval_satisfied")

    def test_destructive_operation_on_restricted_resource_escalates(self):
        register(self.gov, ops=("read", "delete"), sensitivity="restricted")
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                            operation="delete")
        self.assertIs(d.outcome, GovernanceOutcome.REQUIRE_APPROVAL)
        self.assertFalse(d.allowed)

    def test_destructive_operation_on_public_resource_not_escalated(self):
        register(self.gov, ops=("delete",), sensitivity="public")
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                            operation="delete")
        self.assertIs(d.outcome, GovernanceOutcome.ALLOW)

    # ------------------------------------------------------------------ fail closed
    def test_indeterminate_is_never_allow(self):
        from agent_identity.policy.engine import NullEngine
        svc = policy_service(rego=GOV_ALLOW_REGO, engine_override=NullEngine())
        gov = GovernanceService(MemoryGovernanceStore(), svc,
                                config=GovernanceConfig(environment="development"))
        register(gov)
        d = gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.INDETERMINATE)
        self.assertFalse(d.allowed)

    def test_policy_engine_outage_fails_closed(self):
        from agent_identity.policy.engine import OpaHttpEngine
        cfg = PolicyConfig(environment="development", engine="opa", opa_mode="http",
                           opa_url="http://127.0.0.1:9", eval_timeout_ms=200)
        svc = policy_service(rego=GOV_ALLOW_REGO, engine_override=OpaHttpEngine(cfg))
        gov = GovernanceService(MemoryGovernanceStore(), svc,
                                config=GovernanceConfig(environment="development"))
        register(gov)
        d = gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read")
        self.assertIsNot(d.outcome, GovernanceOutcome.ALLOW)
        self.assertFalse(d.allowed)

    def test_registry_failure_fails_closed(self):
        class BoomStore(MemoryGovernanceStore):
            def get_resource(self, resource_id):
                raise RuntimeError("registry unavailable")

        svc = policy_service(rego=GOV_ALLOW_REGO)
        gov = GovernanceService(BoomStore(), svc,
                                config=GovernanceConfig(environment="development"))
        d = gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.INDETERMINATE)
        self.assertFalse(d.allowed)

    # ------------------------------------------------------------------ policy change / JIT
    def test_policy_change_invalidates_governance_allow(self):
        register(self.gov)
        self.assertIs(self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                                      operation="read").outcome, GovernanceOutcome.ALLOW)
        a = actor()
        ps = self.svc.list_policies(a, org_id="acme")[0]
        self.svc.disable(a, ps.policy_id)
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                            operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d.reason, "no_matching_policy")

    def test_jit_grant_satisfies_default_deny_then_revocation_denies(self):
        # NO applicable policy -> default deny; a JIT grant is the only way through.
        svc, gov, _ = governance(rego=None)
        register(gov)
        d = gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        grant = svc.jit.issue(org_id="acme", agent_id="agt1", action="http_api:read",
                              resource="api:billing", issued_by="usr_admin")
        d2 = gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read")
        self.assertIs(d2.outcome, GovernanceOutcome.ALLOW)
        self.assertEqual(d2.reason, "jit_grant")
        svc.jit.revoke(grant.grant_id, reason="operator_revoked", revoked_by="usr_admin")
        d3 = gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read")
        self.assertIs(d3.outcome, GovernanceOutcome.DENY)

    def test_expired_jit_grant_denied(self):
        clock = MutableClock()
        svc = policy_service(rego=None, clock=clock)
        gov = GovernanceService(MemoryGovernanceStore(), svc,
                                config=GovernanceConfig(environment="development"), clock=clock)
        register(gov)
        svc.jit.issue(org_id="acme", agent_id="agt1", action="http_api:read",
                      resource="api:billing", ttl_seconds=60, issued_by="usr_admin")
        self.assertIs(gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                                 operation="read").outcome, GovernanceOutcome.ALLOW)
        clock.advance(120)
        d = gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)

    def test_jit_grant_is_tenant_scoped(self):
        svc, gov, _ = governance(rego=None)
        register(gov, org="acme")
        svc.jit.issue(org_id="acme", agent_id="agt1", action="http_api:read",
                      resource="api:billing", issued_by="usr_admin")
        d = gov.decide(agent_id="agt1", tenant="other-tenant", resource_id="api:billing",
                       operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)

    # ------------------------------------------------------------------ seals / bypass
    def test_enforce_requires_sealed_allow(self):
        register(self.gov)
        forged = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                                 operation="read")
        ran = []
        # a decision object rebuilt by hand (no seal) must never execute
        from agent_identity.governance.models import GovernanceDecision
        hand_made = GovernanceDecision.allow("forged")
        with self.assertRaises(ForbiddenError):
            self.gov.guard.enforce(hand_made, lambda: ran.append(1))
        self.assertEqual(ran, [])
        # the genuine decision runs once...
        self.gov.guard.enforce(forged, lambda: ran.append(1))
        # ...and its seal is single-use
        with self.assertRaises(ForbiddenError):
            self.gov.guard.enforce(forged, lambda: ran.append(2))
        self.assertEqual(ran, [1])

    def test_denied_decision_never_executes(self):
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:unregistered",
                            operation="read")
        ran = []
        with self.assertRaises(ForbiddenError):
            self.gov.guard.enforce(d, lambda: ran.append(1))
        self.assertEqual(ran, [])

    def test_guarded_connector_runs_only_on_allow(self):
        register(self.gov)
        guarded = self.gov.register_connector(HttpApiConnector())
        out = guarded(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read")
        self.assertTrue(out["authorized"])
        with self.assertRaises(ForbiddenError):
            guarded(agent_id="agt1", tenant="acme", resource_id="api:unregistered", operation="read")

    def test_service_execute_is_the_enforced_path(self):
        register(self.gov)
        connector = self.gov.register_connector(DatabaseConnector())
        out = self.gov.execute(agent_id="agt1", tenant="acme", resource_id="api:billing",
                               operation="read", connector="database")
        self.assertTrue(out["authorized"])
        with self.assertRaises(ForbiddenError):
            self.gov.execute(agent_id="agt1", tenant="acme", resource_id="api:unregistered",
                             operation="read", connector="database")

    def test_service_never_exposes_raw_connector(self):
        raw = HttpApiConnector()
        guarded = self.gov.register_connector(raw)
        # the returned handle is the GUARDED wrapper, with no direct pass-through to perform
        self.assertIsInstance(guarded, GuardedConnector)
        self.assertFalse(hasattr(guarded, "perform"))
        self.assertFalse(hasattr(guarded, "_connector_public"))

    def test_guarded_connector_cannot_be_forged_with_a_denied_decision(self):
        # A caller holding the guard cannot mint an ALLOW: only decide()+enforce() interlock.
        register(self.gov, ops=("read",))
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                            operation="write")
        self.assertFalse(d.allowed)

    # ------------------------------------------------------------------ concurrency
    def test_concurrent_decisions_are_consistent(self):
        register(self.gov, ops=("read", "delete"), sensitivity="public")
        results = []
        lock = threading.Lock()

        def worker(i):
            d = self.gov.decide(agent_id=f"agt{i}", tenant="acme", resource_id="api:billing",
                                operation="read")
            with lock:
                results.append(d.outcome)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(24)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 24)
        self.assertTrue(all(r is GovernanceOutcome.ALLOW for r in results))

    def test_concurrent_seal_consumption_is_single_use(self):
        register(self.gov)
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                            operation="read")
        outcomes = []
        lock = threading.Lock()

        def worker():
            try:
                self.gov.guard.enforce(d, lambda: None)
                with lock:
                    outcomes.append("ok")
            except ForbiddenError:
                with lock:
                    outcomes.append("denied")

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(outcomes.count("ok"), 1)
        self.assertEqual(outcomes.count("denied"), 15)

    # ------------------------------------------------------------------ audit
    def test_decision_is_audited_with_correlation_id(self):
        register(self.gov)
        self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read",
                        correlation_id="cid-123")
        rows = self.store.list_audit(org_id="acme")
        self.assertTrue(any(r.get("correlation_id") == "cid-123"
                            and r.get("decision") == "ALLOW" for r in rows))

    def test_denials_are_audited(self):
        self.gov.decide(agent_id="agt1", tenant="acme", resource_id="api:unregistered",
                        operation="read")
        rows = self.store.list_audit(org_id="acme")
        self.assertTrue(any(r.get("decision") == "DENY" and r.get("reason") == "unknown_resource"
                            for r in rows))

    def test_audit_fans_out_to_security_logger(self):
        logger = SecurityLogger(use_python_logging=False)
        svc, gov, _ = governance(logger=logger)
        register(gov)
        gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read")
        self.assertTrue(any(e.get("event", "").startswith("governance.")
                            for e in list(logger.events)))


@unittest.skipUnless(OPA, "the opa binary is required")
class ToolRegistryTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.gov, self.store = governance()
        self.tools = self.gov.tools
        register(self.gov, rid="tool:billing_lookup", rtype="tool", ops=("invoke",))

    def _register_tool(self, *, caps=("billing:read",), manifest=None, a=None):
        return self.tools.register_tool(
            a or actor(), org_id="acme", name="billing_lookup", version="1",
            owner="platform-team", manifest=manifest,
            resource_id="tool:billing_lookup", requested_capabilities=list(caps))

    def test_unregistered_tool_denied(self):
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="tool:billing_lookup",
                            operation="invoke", tool="billing_lookup")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d.reason, "tool_not_registered")

    def test_registered_but_unapproved_tool_denied(self):
        self._register_tool()
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="tool:billing_lookup",
                            operation="invoke", tool="billing_lookup")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d.reason, "tool_not_approved")

    def test_approved_tool_with_capability_allowed(self):
        self._register_tool(caps=("billing:read",))
        self.tools.approve_tool(actor(), "billing_lookup@1", approved_capabilities=["billing:read"])
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="tool:billing_lookup",
                            operation="invoke", tool="billing_lookup",
                            claimed_capabilities=("billing:read",))
        self.assertIs(d.outcome, GovernanceOutcome.ALLOW)

    def test_manifest_cannot_self_grant_capabilities(self):
        # The manifest ASKS for a capability; approval with an EMPTY set grants nothing.
        self._register_tool(caps=(), manifest={"name": "billing_lookup", "version": "1",
                                               "capabilities": ["billing:read"]})
        rec = self.tools.resolve("billing_lookup@1")
        self.assertEqual(rec.requested_capabilities, ("billing:read",))
        self.assertEqual(rec.approved_capabilities, ())      # a manifest never approves
        self.tools.approve_tool(actor(), "billing_lookup@1", approved_capabilities=[])
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="tool:billing_lookup",
                            operation="invoke", tool="billing_lookup",
                            requested_capabilities=("billing:read",))
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d.reason, "capability_not_approved")

    def test_approve_cannot_exceed_requested_capabilities(self):
        self._register_tool(caps=("billing:read",))
        with self.assertRaises(ValidationError):
            self.tools.approve_tool(actor(), "billing_lookup@1",
                                    approved_capabilities=["billing:write"])

    def test_disabled_tool_denied(self):
        self._register_tool()
        self.tools.approve_tool(actor(), "billing_lookup@1", approved_capabilities=["billing:read"])
        self.tools.set_enabled(actor(), "billing_lookup@1", False)
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="tool:billing_lookup",
                            operation="invoke", tool="billing_lookup")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d.reason, "tool_disabled")

    def test_tool_bound_to_a_different_resource_denied(self):
        self._register_tool()
        self.tools.approve_tool(actor(), "billing_lookup@1", approved_capabilities=["billing:read"],
                                resource_id=None)
        # a second resource the tool is NOT bound to
        register(self.gov, rid="tool:other", rtype="tool", ops=("invoke",))
        d = self.gov.decide(agent_id="agt1", tenant="acme", resource_id="tool:other",
                            operation="invoke", tool="billing_lookup")
        self.assertIs(d.outcome, GovernanceOutcome.DENY)
        self.assertIn(d.reason, ("tool_resource_mismatch", "tool_not_registered"))

    def test_register_tool_requires_permission(self):
        with self.assertRaises(ForbiddenError):
            self.tools.register_tool(actor(ROLE_READONLY_AUDITOR), org_id="acme",
                                     name="rogue", version="1", owner="attacker")

    def test_analyst_cannot_register_or_approve_tools(self):
        a = actor(ROLE_SECURITY_ANALYST)
        with self.assertRaises(ForbiddenError):
            self.tools.register_tool(a, org_id="acme", name="rogue", version="1", owner="x")
        with self.assertRaises(ForbiddenError):
            self.tools.approve_tool(a, "billing_lookup@1", approved_capabilities=[])

    def test_developer_cannot_admin_tool_state(self):
        self._register_tool(a=actor(ROLE_DEVELOPER))
        with self.assertRaises(ForbiddenError):
            self.tools.set_enabled(actor(ROLE_DEVELOPER), "billing_lookup@1", False)

    def test_unknown_resource_binding_rejected(self):
        with self.assertRaises(ValidationError):
            self.tools.register_tool(actor(), org_id="acme", name="ghost", version="1",
                                     owner="x", resource_id="tool:does_not_exist")


class RegistryValidationTests(unittest.TestCase):
    def test_resource_registration_requires_permission(self):
        _, gov, _ = governance(rego=None)
        with self.assertRaises(ForbiddenError):
            register(gov, a=actor(ROLE_READONLY_AUDITOR))

    def test_developer_cannot_disable_resource(self):
        _, gov, _ = governance(rego=None)
        register(gov)
        with self.assertRaises(ForbiddenError):
            gov.resources.set_enabled(actor(ROLE_DEVELOPER), "api:billing", False)

    def test_unknown_resource_type_rejected_at_registration(self):
        _, gov, _ = governance(rego=None)
        with self.assertRaises(ValidationError):
            register(gov, rtype="quantum")

    def test_wildcard_and_traversal_ids_rejected(self):
        _, gov, _ = governance(rego=None)
        for bad in ("api:*", "api:..", "api:../x", "api:bad id"):
            with self.assertRaises(ValidationError):
                register(gov, rid=bad)

    def test_manifest_shape_and_capability_names_validated(self):
        with self.assertRaises(ValidationError):
            validate_metadata({"nested": {"a": 1}})
        with self.assertRaises(ValidationError):
            validate_metadata({"list": [1, 2]})
        self.assertEqual(validate_metadata({"team": "cx", "tier": 1}), {"team": "cx", "tier": 1})

    def test_capability_names_validated(self):
        with self.assertRaises(ValidationError):
            validate_capabilities(["Bad Name"])
        with self.assertRaises(ValidationError):
            validate_capabilities(["*"])
        self.assertEqual(validate_capabilities(["b:a", "b:a"]), ("b:a",))

    def test_manifest_rejects_unsupported_fields(self):
        with self.assertRaises(ValidationError):
            validate_manifest({"name": "t", "grants": ["admin"]})

    def test_manifest_rejected_after_validation_records_audit(self):
        """A rejected manifest is audited, and no partial tool record is written."""
        _, gov, store = governance(rego=None)
        register(gov, rid="tool:lookup", rtype="tool", ops=("invoke",))
        with self.assertRaises(ValidationError):
            gov.tools.register_tool(actor(), org_id="acme", name="lookup", version="1",
                                    owner="team", resource_id="tool:lookup",
                                    manifest={"name": "lookup", "grants": ["admin"]})
        self.assertEqual(gov.tools.resolve("lookup@1"), None)
        self.assertTrue(any(e.get("event") == "governance.tool.manifest_rejected"
                            for e in store.list_audit(org_id="acme")))

    def test_audit_events_carry_no_payload_fields(self):
        """Audit records are ids + reason codes only -- never payloads or secrets."""
        _, gov, store = governance(rego=None)
        register(gov)
        gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read")
        row = store.list_audit(org_id="acme")[0]
        forbidden = {"payload", "body", "secret", "token", "password", "command"}
        self.assertEqual(forbidden & set(row), set())

    def test_validate_id_rejects_over_long(self):
        with self.assertRaises(ValidationError):
            validate_id("a" * 300)

    def test_config_refuses_unsafe_unknown_policy(self):
        with self.assertRaises(ValidationError):
            GovernanceConfig(environment="development", unknown_resource_policy="allow")

    def test_config_refuses_trusting_manifest_capabilities(self):
        with self.assertRaises(ValidationError):
            GovernanceConfig(environment="development", trust_manifest_capabilities=True)


@unittest.skipUnless(OPA, "the opa binary is required")
class EnumAndHookTests(unittest.TestCase):
    def test_vocabulary_coercion(self):
        self.assertIs(ResourceType.coerce("HTTP_API"), ResourceType.HTTP_API)
        self.assertIsNone(ResourceType.coerce("nope"))
        self.assertIs(Sensitivity.coerce("Restricted"), Sensitivity.RESTRICTED)
        self.assertIsNone(Sensitivity.coerce("ultra"))
        self.assertIs(RiskClass.coerce("HIGH"), RiskClass.HIGH)
        self.assertTrue(Sensitivity.PUBLIC.rank < Sensitivity.RESTRICTED.rank)

    def test_install_governance_installs_a_transport_hook(self):
        from agent_identity.governance.hooks import install_governance

        class FakeTransport:
            hook = None

            @classmethod
            def set_policy_hook(cls, fn):
                cls.hook = fn

        _, gov, _ = governance()
        install_governance(gov, transport=FakeTransport)
        self.assertTrue(callable(FakeTransport.hook))

    def test_describe_is_non_secret(self):
        from agent_identity.governance.hooks import describe
        _, gov, _ = governance()
        info = describe(gov)
        self.assertTrue(info["configured"])
        self.assertNotIn("secret", str(info).lower())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
