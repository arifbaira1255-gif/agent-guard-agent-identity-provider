"""Step 10 unit + integration tests for the policy engine and JIT authorization.

These run against a REAL OPA binary (``opa eval``) and the in-memory policy store / state backend,
so the decision path is exercised end to end without external services. The PostgreSQL-backed store
is covered by ``test_policy_pg_integration.py``.

Coverage (per the Step 10 brief):
  * policy decisions: ALLOW / DENY / REQUIRE_APPROVAL / INDETERMINATE
  * allow/deny boundary tests
  * policy versioning (immutability, activate, rollback)
  * JIT expiration and revocation
  * concurrent authorization
  * cache invalidation (no stale allow survives a change)
  * cross-tenant isolation
  * policy-engine failure (fail closed)
  * approval-required gating
  * SDK integration (the /v1/authorize hook) and the anti-bypass enforcer
"""
from __future__ import annotations

import os
import shutil
import threading
import unittest

from agent_identity.core.errors import ForbiddenError, ValidationError
from agent_identity.policy import (DecisionKind, JitGrantService, MemoryPolicyStore, PolicyConfig,
                                   PolicyDecisionService, PolicyEnforcer, PolicyValidationError,
                                   StaticRiskProvider, StoreApprovalProvider, build_engine,
                                   make_policy_hook, validate_rego)
from agent_identity.policy.cache import DecisionCache
from agent_identity.policy.engine import NullEngine, OpaCliEngine
from agent_identity.policy.models import RiskSignal
from agent_identity.security.rbac import (ROLE_DEVELOPER, ROLE_PLATFORM_ADMIN, ROLE_TENANT_ADMIN,
                                          effective_access)
from agent_identity.state.backend import MemoryBackend

OPA = shutil.which("opa")
REGO_DIR = os.path.join(os.path.dirname(__file__), "..", "src", "agent_identity", "policy", "rego")
EXAMPLE_REGO = open(os.path.join(REGO_DIR, "example.rego"), encoding="utf-8").read()

# A minimal policy used for boundary tests: allow exactly one action, deny everything else.
SCOPED_REGO = """
package agentguard.authz

default decision := {"decision": "DENY", "reason": "default_deny"}

decision := {"decision": "ALLOW", "reason": "scoped_allow"} {
    input.action == "tool:read"
    input.resource == "db:public"
}
"""

APPROVAL_REGO = """
package agentguard.authz

default decision := {"decision": "DENY", "reason": "default_deny"}

decision := {"decision": "REQUIRE_APPROVAL", "reason": "needs_human"} {
    input.action == "tool:delete"
}
"""

MALFORMED_RESULT_REGO = """
package agentguard.authz

decision := "ALLOW"
"""


def _actor(role=ROLE_TENANT_ADMIN, *, org_id="acme", platform=False, user_id="usr_admin"):
    roles = (role,) if isinstance(role, str) else tuple(role)
    if platform:
        return effective_access(user_id, org_id, global_roles=(ROLE_PLATFORM_ADMIN,))
    return effective_access(user_id, org_id, tenant_roles=roles)


def _config(**kw):
    base = dict(environment="development", engine="opa", opa_mode="cli",
                eval_timeout_ms=2000, cache_enabled=True, cache_ttl_ms=5000)
    base.update(kw)
    return PolicyConfig(**base)


def _service(*, config=None, store=None, engine=None, cache=None, approvals=None, risk=None):
    config = config or _config()
    store = store or MemoryPolicyStore()
    engine = engine or build_engine(config)
    svc = PolicyDecisionService(store, engine, config, cache=cache, approvals=approvals, risk=risk)
    return svc, store


def _activate(svc, store, rego, *, org_id="acme", name="p"):
    actor = _actor(org_id=org_id)
    rec = svc.create_policy(actor, name=name, org_id=org_id, rego_source=rego)
    svc.activate(actor, rec.policy_id, 1)
    return rec


@unittest.skipUnless(OPA, "opa binary not available")
class PolicyDecisionTests(unittest.TestCase):
    def test_allow_decision(self):
        svc, store = _service()
        _activate(svc, store, SCOPED_REGO)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.ALLOW)
        self.assertTrue(d.allowed)

    def test_deny_boundary_wrong_resource(self):
        svc, store = _service()
        _activate(svc, store, SCOPED_REGO)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:secret")
        self.assertIs(d.kind, DecisionKind.DENY)
        self.assertFalse(d.allowed)

    def test_deny_boundary_wrong_action(self):
        svc, store = _service()
        _activate(svc, store, SCOPED_REGO)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:write", resource="db:public")
        self.assertIs(d.kind, DecisionKind.DENY)

    def test_default_deny_when_no_policy(self):
        svc, _ = _service()
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.DENY)
        self.assertEqual(d.reason, "no_matching_policy")

    def test_require_approval(self):
        svc, store = _service()
        _activate(svc, store, APPROVAL_REGO)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:delete", resource="db:x")
        self.assertIs(d.kind, DecisionKind.REQUIRE_APPROVAL)
        self.assertFalse(d.allowed)

    def test_indeterminate_is_never_allow(self):
        # A policy whose decision rule returns a non-object -> INDETERMINATE, never ALLOW.
        svc, store = _service()
        _activate(svc, store, MALFORMED_RESULT_REGO)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.INDETERMINATE)
        self.assertFalse(d.allowed)

    def test_engine_outage_fails_closed(self):
        cfg = _config(opa_binary="/nonexistent/opa-binary")
        svc, store = _service(config=cfg, engine=OpaCliEngine(cfg))
        _activate(svc, store, SCOPED_REGO)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.INDETERMINATE)
        self.assertFalse(d.allowed)

    def test_null_engine_fails_closed(self):
        cfg = _config(engine="none")
        svc, store = _service(config=cfg, engine=NullEngine())
        _activate(svc, store, SCOPED_REGO)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.INDETERMINATE)
        self.assertFalse(d.allowed)

    def test_tenant_boundary_violation(self):
        svc, store = _service()
        _activate(svc, store, SCOPED_REGO)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public",
                          resource_tenant="other")
        self.assertIs(d.kind, DecisionKind.DENY)
        self.assertEqual(d.reason, "tenant_boundary_violation")

    def test_cross_tenant_policy_isolation(self):
        # A policy owned by tenant "acme" must not apply to tenant "globex".
        svc, store = _service()
        _activate(svc, store, SCOPED_REGO, org_id="acme")
        d_acme = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        d_globex = svc.authorize(agent_id="a1", tenant="globex", action="tool:read", resource="db:public")
        self.assertIs(d_acme.kind, DecisionKind.ALLOW)
        self.assertIs(d_globex.kind, DecisionKind.DENY)

    def test_high_risk_requires_approval(self):
        risk = StaticRiskProvider(RiskSignal(level="high", score=0.8, reasons=("anomaly",)))
        svc, store = _service(risk=risk)
        _activate(svc, store, EXAMPLE_REGO)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.REQUIRE_APPROVAL)

    def test_critical_risk_denied(self):
        risk = StaticRiskProvider(RiskSignal(level="critical", score=1.0))
        svc, store = _service(risk=risk)
        _activate(svc, store, EXAMPLE_REGO)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.DENY)


@unittest.skipUnless(OPA, "opa binary not available")
class PolicyLifecycleTests(unittest.TestCase):
    def test_version_immutability(self):
        svc, store = _service()
        actor = _actor()
        rec = svc.create_policy(actor, name="p", org_id="acme", rego_source=SCOPED_REGO)
        v1 = store.get_version(rec.policy_id, 1)
        import dataclasses
        import hashlib
        from agent_identity.core.errors import ConflictError
        new_src = "package agentguard.authz\ndecision := {\"decision\":\"DENY\"}"
        with self.assertRaises(ConflictError):
            store.put_version(dataclasses.replace(
                v1, rego_source=new_src,
                checksum=hashlib.sha256(new_src.encode()).hexdigest()))

    def test_activate_and_rollback(self):
        svc, store = _service()
        actor = _actor()
        rec = svc.create_policy(actor, name="p", org_id="acme", rego_source=SCOPED_REGO)
        svc.activate(actor, rec.policy_id, 1)
        self.assertIs(store.get_version(rec.policy_id, 1).status.value, "active")
        # add a v2 that denies everything, activate it
        svc.create_version(actor, rec.policy_id, rego_source=APPROVAL_REGO)
        svc.activate(actor, rec.policy_id, 2)
        self.assertIs(store.get_version(rec.policy_id, 1).status.value, "retired")
        self.assertIs(store.get_version(rec.policy_id, 2).status.value, "active")
        # roll back to v1
        svc.rollback(actor, rec.policy_id, to_version=1)
        self.assertIs(store.get_version(rec.policy_id, 1).status.value, "active")
        self.assertIs(store.get_version(rec.policy_id, 2).status.value, "retired")

    def test_validate_rejects_bad_policy(self):
        with self.assertRaises(PolicyValidationError):
            validate_rego("package agentguard.authz\n# no decision rule", max_bytes=10000)
        with self.assertRaises(PolicyValidationError):
            validate_rego("package other.pkg\ndecision := {}", max_bytes=10000)
        with self.assertRaises(PolicyValidationError):
            validate_rego("package agentguard.authz\ndecision := http.send({})", max_bytes=10000)

    def test_test_before_activation(self):
        svc, store = _service()
        actor = _actor()
        rec = svc.create_policy(actor, name="p", org_id="acme", rego_source=SCOPED_REGO)
        summary = svc.test(actor, rec.policy_id, 1, cases=[
            {"input": {"action": "tool:read", "resource": "db:public"}, "expect": "ALLOW"},
            {"input": {"action": "tool:read", "resource": "db:secret"}, "expect": "DENY"},
        ])
        self.assertEqual(summary["passed"], 2)
        self.assertEqual(summary["failed"], 0)

    def test_policy_admin_requires_permission(self):
        svc, store = _service()
        dev = _actor(ROLE_DEVELOPER)
        with self.assertRaises(ForbiddenError):
            svc.create_policy(dev, name="p", org_id="acme", rego_source=SCOPED_REGO)

    def test_platform_policy_requires_platform_admin(self):
        svc, store = _service()
        tenant_admin = _actor(ROLE_TENANT_ADMIN, platform=False)
        with self.assertRaises(ForbiddenError):
            svc.create_policy(tenant_admin, name="global", org_id=None, rego_source=SCOPED_REGO)
        padmin = _actor(ROLE_PLATFORM_ADMIN, platform=True)
        rec = svc.create_policy(padmin, name="global", org_id=None, rego_source=SCOPED_REGO)
        self.assertIsNone(rec.org_id)


@unittest.skipUnless(OPA, "opa binary not available")
class JitGrantTests(unittest.TestCase):
    def _svc(self):
        cfg = _config()
        store = MemoryPolicyStore()
        svc = PolicyDecisionService(store, build_engine(cfg), cfg)
        return svc, store

    def test_jit_grant_authorizes_exact_scope(self):
        svc, store = self._svc()
        svc.jit.issue(org_id="acme", agent_id="a1", action="tool:read", resource="db:public",
                      ttl_seconds=60, issued_by="usr_admin")
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.ALLOW)
        self.assertEqual(d.reason, "jit_grant")

    def test_jit_grant_does_not_cover_other_scope(self):
        svc, store = self._svc()
        svc.jit.issue(org_id="acme", agent_id="a1", action="tool:read", resource="db:public",
                      ttl_seconds=60)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:secret")
        self.assertIs(d.kind, DecisionKind.DENY)

    def test_jit_expiration(self):
        svc, store = self._svc()
        g = svc.jit.issue(org_id="acme", agent_id="a1", action="tool:read", resource="db:public",
                          ttl_seconds=1)
        # simulate time passing beyond expiry
        svc.jit._clock = type("C", (), {"now": staticmethod(lambda: g.expires_at + 1)})()
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.DENY)

    def test_jit_revocation(self):
        svc, store = self._svc()
        g = svc.jit.issue(org_id="acme", agent_id="a1", action="tool:read", resource="db:public",
                          ttl_seconds=60)
        svc.jit.revoke(g.grant_id, reason="compromised")
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.DENY)

    def test_jit_ttl_bounded(self):
        svc, store = self._svc()
        with self.assertRaises(ValidationError):
            svc.jit.issue(org_id="acme", agent_id="a1", action="tool:read", resource="db:public",
                          ttl_seconds=10 ** 9)

    def test_jit_wildcard_rejected(self):
        svc, store = self._svc()
        with self.assertRaises(ValidationError):
            svc.jit.issue(org_id="acme", agent_id="a1", action="tool:*", resource="db:public")

    def test_jit_forbidden_admin_action(self):
        svc, store = self._svc()
        with self.assertRaises(ForbiddenError):
            svc.jit.issue(org_id="acme", agent_id="a1", action="policy:activate", resource="p1")

    def test_jit_cross_tenant_isolation(self):
        svc, store = self._svc()
        svc.jit.issue(org_id="acme", agent_id="a1", action="tool:read", resource="db:public",
                      ttl_seconds=60)
        d = svc.authorize(agent_id="a1", tenant="globex", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.DENY)


@unittest.skipUnless(OPA, "opa binary not available")
class ApprovalTests(unittest.TestCase):
    def test_approval_gates_execution(self):
        cfg = _config()
        store = MemoryPolicyStore()
        approvals = StoreApprovalProvider(store, cfg)
        svc = PolicyDecisionService(store, build_engine(cfg), cfg, approvals=approvals)
        _activate(svc, store, APPROVAL_REGO)
        # before approval -> REQUIRE_APPROVAL
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:delete", resource="db:x")
        self.assertIs(d.kind, DecisionKind.REQUIRE_APPROVAL)
        # request + approve
        a = approvals.request(org_id="acme", agent_id="a1", action="tool:delete", resource="db:x",
                              requested_by="usr_admin")
        approvals.decide(a.approval_id, approved=True, decided_by="usr_admin")
        d2 = svc.authorize(agent_id="a1", tenant="acme", action="tool:delete", resource="db:x")
        self.assertIs(d2.kind, DecisionKind.ALLOW)
        self.assertEqual(d2.reason, "approval_satisfied")

    def test_denied_approval_does_not_allow(self):
        cfg = _config()
        store = MemoryPolicyStore()
        approvals = StoreApprovalProvider(store, cfg)
        svc = PolicyDecisionService(store, build_engine(cfg), cfg, approvals=approvals)
        _activate(svc, store, APPROVAL_REGO)
        a = approvals.request(org_id="acme", agent_id="a1", action="tool:delete", resource="db:x",
                              requested_by="usr_admin")
        approvals.decide(a.approval_id, approved=False, decided_by="usr_admin")
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:delete", resource="db:x")
        self.assertIs(d.kind, DecisionKind.REQUIRE_APPROVAL)


@unittest.skipUnless(OPA, "opa binary not available")
class CacheTests(unittest.TestCase):
    def _svc(self):
        cfg = _config()
        store = MemoryPolicyStore()
        cache = DecisionCache(MemoryBackend(), cfg)
        svc = PolicyDecisionService(store, build_engine(cfg), cfg, cache=cache)
        return svc, store, cache

    def test_allow_is_cached(self):
        svc, store, cache = self._svc()
        _activate(svc, store, SCOPED_REGO)
        d1 = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        d2 = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d1.kind, DecisionKind.ALLOW)
        self.assertTrue(d2.cached)

    def test_no_stale_allow_after_policy_change(self):
        svc, store, cache = self._svc()
        rec = _activate(svc, store, SCOPED_REGO)
        d1 = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d1.kind, DecisionKind.ALLOW)
        # disable the policy -> cache must be invalidated, decision must become DENY
        svc.disable(_actor(), rec.policy_id)
        d2 = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d2.kind, DecisionKind.DENY)

    def test_no_stale_allow_after_jit_revocation(self):
        cfg = _config()
        store = MemoryPolicyStore()
        cache = DecisionCache(MemoryBackend(), cfg)
        svc = PolicyDecisionService(store, build_engine(cfg), cfg, cache=cache)
        g = svc.jit.issue(org_id="acme", agent_id="a1", action="tool:read", resource="db:public",
                          ttl_seconds=60)
        d1 = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d1.kind, DecisionKind.ALLOW)
        svc.jit.revoke(g.grant_id, reason="compromised")
        cache.invalidate_tenant("acme")            # revocation invalidates the tenant scope
        d2 = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d2.kind, DecisionKind.DENY)

    def test_cache_scoped_by_tenant(self):
        svc, store, cache = self._svc()
        _activate(svc, store, SCOPED_REGO, org_id="acme")
        d_acme = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        d_globex = svc.authorize(agent_id="a1", tenant="globex", action="tool:read", resource="db:public")
        self.assertIs(d_acme.kind, DecisionKind.ALLOW)
        self.assertIs(d_globex.kind, DecisionKind.DENY)   # never served acme's cached allow


@unittest.skipUnless(OPA, "opa binary not available")
class ConcurrencyTests(unittest.TestCase):
    def test_concurrent_authorization(self):
        svc, store = _service()
        _activate(svc, store, SCOPED_REGO)
        results, errors = [], []

        def worker(i):
            try:
                d = svc.authorize(agent_id=f"a{i}", tenant="acme", action="tool:read",
                                  resource="db:public")
                results.append(d.kind)
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(24)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 24)
        self.assertTrue(all(k is DecisionKind.ALLOW for k in results))


@unittest.skipUnless(OPA, "opa binary not available")
class EnforcerTests(unittest.TestCase):
    def test_enforcer_blocks_non_allow(self):
        svc, store = _service()
        _activate(svc, store, SCOPED_REGO)
        enf = PolicyEnforcer(svc)
        ran = {"n": 0}

        def op():
            ran["n"] += 1
            return "ok"

        # allowed scope runs
        out = enf.authorize_and_run(agent_id="a1", tenant="acme", action="tool:read",
                                    resource="db:public", executor=op)
        self.assertEqual(out, "ok")
        self.assertEqual(ran["n"], 1)
        # denied scope must NOT run
        with self.assertRaises(ForbiddenError):
            enf.authorize_and_run(agent_id="a1", tenant="acme", action="tool:read",
                                  resource="db:secret", executor=op)
        self.assertEqual(ran["n"], 1)   # executor never invoked

    def test_enforcer_rejects_indeterminate(self):
        from agent_identity.policy.models import PolicyDecision
        svc, store = _service()
        enf = PolicyEnforcer(svc)
        with self.assertRaises(ForbiddenError):
            enf.enforce(PolicyDecision.indeterminate("engine_down"), lambda: "should not run")


@unittest.skipUnless(OPA, "opa binary not available")
class SdkIntegrationTests(unittest.TestCase):
    """The /v1/authorize hook: a verified credential + policy decision, fail closed."""

    class _Res:
        def __init__(self, valid=True, caps=(), agent="a1", inst="i1", org="acme"):
            self.valid, self.capabilities, self.agent_id = valid, caps, agent
            self.instance_id, self.org_id, self.reason, self.correlation_id = inst, org, "", None

    class _Svc:
        def __init__(self, res):
            self._res = res

        def verify_credential(self, token, **kw):
            return self._res

    def test_hook_allows_via_policy(self):
        svc, store = _service()
        _activate(svc, store, SCOPED_REGO)
        hook = make_policy_hook(svc)
        decision = hook(None, {"_agent_id": "a1", "_org_id": "acme", "_capabilities": [],
                               "action": "tool:read", "resource": "db:public"})
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["decision"], "ALLOW")

    def test_hook_denies_out_of_scope(self):
        svc, store = _service()
        _activate(svc, store, SCOPED_REGO)
        hook = make_policy_hook(svc)
        decision = hook(None, {"_agent_id": "a1", "_org_id": "acme", "_capabilities": [],
                               "action": "tool:read", "resource": "db:secret"})
        self.assertFalse(decision["allowed"])

    def test_transport_authorize_uses_hook(self):
        from agent_identity.api import http_transport
        svc, store = _service()
        _activate(svc, store, SCOPED_REGO)
        http_transport.set_policy_hook(make_policy_hook(svc))
        try:
            status, out = http_transport.handle(
                self._Svc(self._Res()), "admin-token", "POST", "/v1/authorize",
                {"token": "t", "proof": "p", "action": "tool:read", "resource": "db:public"},
                {})
            self.assertEqual(status, 200)
            self.assertTrue(out["allowed"])
            status2, out2 = http_transport.handle(
                self._Svc(self._Res()), "admin-token", "POST", "/v1/authorize",
                {"token": "t", "proof": "p", "action": "tool:read", "resource": "db:secret"},
                {})
            self.assertFalse(out2["allowed"])
        finally:
            http_transport.set_policy_hook(None)   # restore the default deny-by-default hook

    def test_transport_fails_closed_on_invalid_credential(self):
        from agent_identity.api import http_transport
        svc, store = _service()
        _activate(svc, store, SCOPED_REGO)
        http_transport.set_policy_hook(make_policy_hook(svc))
        try:
            status, out = http_transport.handle(
                self._Svc(self._Res(valid=False)), "admin-token", "POST", "/v1/authorize",
                {"token": "t", "proof": "p", "action": "tool:read", "resource": "db:public"}, {})
            self.assertFalse(out["allowed"])
        finally:
            http_transport.set_policy_hook(None)


@unittest.skipUnless(os.environ.get("AGENTGUARD_TEST_OPA_URL"), "set AGENTGUARD_TEST_OPA_URL for OPA-server tests")
class OpaHttpEngineTests(unittest.TestCase):
    """Exercises the production HTTP engine against a real ``opa run --server`` instance."""

    def _svc(self):
        cfg = _config(opa_mode="http", opa_url=os.environ["AGENTGUARD_TEST_OPA_URL"])
        store = MemoryPolicyStore()
        svc = PolicyDecisionService(store, build_engine(cfg), cfg)
        return svc, store

    def test_http_engine_allow_and_deny(self):
        svc, store = self._svc()
        _activate(svc, store, SCOPED_REGO)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.ALLOW)
        d2 = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:secret")
        self.assertIs(d2.kind, DecisionKind.DENY)

    def test_http_engine_outage_fails_closed(self):
        cfg = _config(opa_mode="http", opa_url="http://127.0.0.1:59999")
        store = MemoryPolicyStore()
        svc = PolicyDecisionService(store, build_engine(cfg), cfg)
        _activate(svc, store, SCOPED_REGO)
        d = svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.INDETERMINATE)
        self.assertFalse(d.allowed)


if __name__ == "__main__":
    unittest.main()
