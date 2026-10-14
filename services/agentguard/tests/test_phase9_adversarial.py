"""Phase 9 -- adversarial security validation suite.

A controlled, isolated suite that attacks the INTEGRATED platform the way a hostile actor would,
using synthetic data and in-memory stores (no production system is touched). Each test asserts the
platform REFUSES the attack -- a passing test means the control held, not that the system is
vulnerability-free.

Coverage (per the Phase 9 brief §7):
  * authentication / authorization bypass
  * cross-tenant data access
  * privilege escalation (tenant -> platform, self-approval, self-escalation)
  * credential leakage in API responses
  * replay and concurrency
  * policy-enforcement bypass
  * egress gateway / SSRF bypass (metadata, private, loopback, DNS rebinding, redirect)
  * DLP evasion (obfuscated / encoded secrets)
  * unsafe redirect / destination validation
  * prompt-injection-driven unauthorized tool use
  * resource exhaustion / DoS bounds
  * audit tampering and verification failure
  * unsafe recovery / rollback
  * secret redaction in exported events

Run:  PYTHONPATH=src:. python -m unittest -v tests.test_phase9_adversarial
"""
from __future__ import annotations

import threading
import unittest

from agent_identity.core.errors import ForbiddenError, ValidationError
from agent_identity.security.rbac import (ROLE_DEVELOPER, ROLE_PLATFORM_ADMIN, ROLE_READONLY_AUDITOR,
                                         ROLE_SECURITY_ANALYST, ROLE_TENANT_ADMIN, Authorizer,
                                         effective_access, sanitize_global_roles,
                                         sanitize_tenant_roles)


# =========================================================================== 1. authz bypass
class AuthorizationBypassTests(unittest.TestCase):
    """The single server-side decision point must deny anything not explicitly granted."""

    def test_unknown_permission_denied(self):
        acc = effective_access("u", "acme", tenant_roles=(ROLE_TENANT_ADMIN,))
        self.assertFalse(acc.has("totally:made:up"))
        with self.assertRaises(ForbiddenError):
            Authorizer.require(acc, "totally:made:up")

    def test_deny_by_default_for_readonly(self):
        acc = effective_access("u", "acme", tenant_roles=(ROLE_READONLY_AUDITOR,))
        for perm in ("agent:write", "credential:issue", "policy:activate", "platform:admin"):
            with self.assertRaises(ForbiddenError, msg=perm):
                Authorizer.require(acc, perm)

    def test_developer_cannot_revoke_others(self):
        acc = effective_access("dev@acme.com", "acme", tenant_roles=(ROLE_DEVELOPER,))
        with self.assertRaises(ForbiddenError):
            Authorizer.require_agent_manage(acc, agent_owner="someone-else@acme.com",
                                            agent_org="acme", perm="agent:revoke")

    def test_analyst_cannot_execute_containment(self):
        # Separation of duties: the approver is not the executor.
        acc = effective_access("u", "acme", tenant_roles=(ROLE_SECURITY_ANALYST,))
        self.assertTrue(acc.has("response:approve"))
        self.assertFalse(acc.has("response:admin"))

    def test_operator_cannot_approve(self):
        acc = effective_access("u", "acme", tenant_roles=("security_operator",))
        self.assertTrue(acc.has("response:admin"))
        self.assertFalse(acc.has("response:approve"))


# =========================================================================== 2. cross-tenant
class CrossTenantTests(unittest.TestCase):
    def test_tenant_scope_mismatch_denied(self):
        acc = effective_access("u", "acme", tenant_roles=(ROLE_TENANT_ADMIN,))
        with self.assertRaises(ForbiddenError):
            Authorizer.require(acc, "agent:read", org_id="globex")

    def test_tenant_role_cannot_grant_platform_role(self):
        with self.assertRaises(ForbiddenError):
            sanitize_tenant_roles((ROLE_PLATFORM_ADMIN,))

    def test_non_admin_cannot_grant_platform_role(self):
        with self.assertRaises(ForbiddenError):
            sanitize_global_roles((ROLE_PLATFORM_ADMIN,), actor_is_platform_admin=False)

    def test_platform_admin_may_cross_tenant(self):
        acc = effective_access("root", None, global_roles=(ROLE_PLATFORM_ADMIN,))
        Authorizer.require(acc, "agent:read", org_id="globex")   # must not raise


# =========================================================================== 3. privilege escalation
class PrivilegeEscalationTests(unittest.TestCase):
    def test_explicit_deny_beats_grant(self):
        acc = effective_access("u", "acme", global_roles=(ROLE_PLATFORM_ADMIN,),
                               deny=("platform:admin",))
        self.assertFalse(acc.is_platform_admin)
        self.assertFalse(acc.has("platform:admin"))

    def test_tenant_admin_lacks_platform_admin(self):
        acc = effective_access("u", "acme", tenant_roles=(ROLE_TENANT_ADMIN,))
        self.assertFalse(acc.has("platform:admin"))
        self.assertFalse(acc.has("tenant:create"))

    def test_unknown_role_rejected(self):
        with self.assertRaises(ValidationError):
            effective_access("u", "acme", tenant_roles=("superuser",))


# =========================================================================== 4. credential leakage
class CredentialLeakageTests(unittest.TestCase):
    def test_api_redaction_strips_secrets(self):
        from agent_identity.api.platform import redact_mapping
        payload = {"user": "u", "password": "hunter2", "api_key": "AKIA1234567890ABCDEF",
                   "nested": {"refresh_token": "abc", "ok": "visible"},
                   "token": "agp1.eyJhbGciOiJIUzI1NiJ9.payload.sig"}
        out = redact_mapping(payload)
        self.assertEqual(out["password"], "[REDACTED]")
        self.assertEqual(out["api_key"], "[REDACTED]")
        self.assertEqual(out["nested"]["refresh_token"], "[REDACTED]")
        self.assertEqual(out["nested"]["ok"], "visible")
        self.assertEqual(out["token"], "[REDACTED]")

    def test_private_key_material_redacted(self):
        from agent_identity.api.platform import redact_mapping
        out = redact_mapping({"blob": "-----BEGIN PRIVATE KEY-----\nMIIE..."})
        self.assertEqual(out["blob"], "[REDACTED]")


# =========================================================================== 5. replay / concurrency
class ReplayAndConcurrencyTests(unittest.TestCase):
    def test_replay_cache_rejects_second_use(self):
        from agent_identity.state.backend import MemoryBackend
        from agent_identity.state.keys import KeyBuilder
        from agent_identity.state.replay import RedisReplayCache
        cache = RedisReplayCache(MemoryBackend(), KeyBuilder("development"), max_ttl_seconds=3600)
        cache.ensure_marker()
        self.assertTrue(cache.check_and_store("nonce-1", 300, 1000.0))    # first use OK
        self.assertFalse(cache.check_and_store("nonce-1", 300, 1000.0))   # replay rejected

    def test_concurrent_idempotency_single_winner(self):
        from agent_identity.ha.idempotency import MemoryIdempotencyStore, NEW
        from cryptography.fernet import Fernet
        store = MemoryIdempotencyStore([Fernet.generate_key()])
        results = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            r = store.reserve("acme", "issue", "key-1", digest="d", actor="u",
                              owner_instance="i", ttl_seconds=300, now=1000.0)
            results.append(r.outcome)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(NEW), 1, "exactly one caller may reserve the key")

    def test_idempotency_conflict_on_different_body(self):
        from agent_identity.ha.idempotency import CONFLICT, MemoryIdempotencyStore
        from cryptography.fernet import Fernet
        store = MemoryIdempotencyStore([Fernet.generate_key()])
        store.reserve("acme", "issue", "k", digest="d1", actor="u", owner_instance="i",
                      ttl_seconds=300, now=1000.0)
        r = store.reserve("acme", "issue", "k", digest="d2", actor="u", owner_instance="i",
                          ttl_seconds=300, now=1000.0)
        self.assertEqual(r.outcome, CONFLICT)


# =========================================================================== 6. policy enforcement bypass
class PolicyEnforcementBypassTests(unittest.TestCase):
    def test_unauthorized_actor_cannot_create_policy(self):
        from agent_identity.policy import MemoryPolicyStore, PolicyConfig, PolicyDecisionService, build_engine
        cfg = PolicyConfig(environment="development")
        svc = PolicyDecisionService(MemoryPolicyStore(), build_engine(cfg), cfg)
        readonly = effective_access("u", "acme", tenant_roles=(ROLE_READONLY_AUDITOR,))
        with self.assertRaises(ForbiddenError):
            svc.create_policy(readonly, name="evil", org_id="acme")

    def test_unauthorized_actor_cannot_activate(self):
        from agent_identity.policy import MemoryPolicyStore, PolicyConfig, PolicyDecisionService, build_engine
        cfg = PolicyConfig(environment="development")
        svc = PolicyDecisionService(MemoryPolicyStore(), build_engine(cfg), cfg)
        admin = effective_access("a", "acme", tenant_roles=(ROLE_TENANT_ADMIN,))
        rec = svc.create_policy(admin, name="p", org_id="acme",
                                rego_source='package agentguard.authz\ndefault decision := {"decision":"ALLOW"}\n')
        readonly = effective_access("u", "acme", tenant_roles=(ROLE_READONLY_AUDITOR,))
        with self.assertRaises(ForbiddenError):
            svc.activate(readonly, rec.policy_id, 1)

    def test_invalid_rego_rejected(self):
        from agent_identity.policy import MemoryPolicyStore, PolicyConfig, PolicyDecisionService, build_engine
        cfg = PolicyConfig(environment="development")
        svc = PolicyDecisionService(MemoryPolicyStore(), build_engine(cfg), cfg)
        admin = effective_access("a", "acme", tenant_roles=(ROLE_TENANT_ADMIN,))
        with self.assertRaises((ValidationError, Exception)):
            svc.create_policy(admin, name="bad", org_id="acme",
                              rego_source="this is not rego at all {{{")


# =========================================================================== 7. egress / SSRF
class EgressSsrfTests(unittest.TestCase):
    def _svc(self, mapping):
        from agent_identity.egress import EgressConfig, EgressService, MemoryEgressStore
        from agent_identity.egress.addresses import AddressPolicy, StaticDnsResolver
        return EgressService(MemoryEgressStore(), config=EgressConfig(environment="development"),
                             address_policy=AddressPolicy(resolver=StaticDnsResolver(mapping)))

    def _decide(self, svc, url):
        from agent_identity.egress.gateway import EgressRequest
        return svc.decide(agent_id="agt", tenant="acme", request=EgressRequest(url=url))

    def test_cloud_metadata_blocked(self):
        svc = self._svc({"metadata.google.internal": ["169.254.169.254"]})
        d = self._decide(svc, "http://metadata.google.internal/computeMetadata/v1/")
        self.assertNotEqual(d.outcome.value, "ALLOW")

    def test_literal_metadata_ip_blocked(self):
        svc = self._svc({})
        d = self._decide(svc, "http://169.254.169.254/latest/meta-data/")
        self.assertNotEqual(d.outcome.value, "ALLOW")

    def test_private_and_loopback_blocked(self):
        svc = self._svc({})
        for url in ("http://10.0.0.5/admin", "http://127.0.0.1:8080/", "http://192.168.1.1/"):
            d = self._decide(svc, url)
            self.assertNotEqual(d.outcome.value, "ALLOW", url)

    def test_dns_rebinding_mixed_answer_blocked(self):
        # A hostname resolving to BOTH a public and a private address is hostile.
        svc = self._svc({"rebind.example.com": ["93.184.216.34", "10.0.0.9"]})
        d = self._decide(svc, "https://rebind.example.com/")
        self.assertNotEqual(d.outcome.value, "ALLOW")

    def test_default_deny_for_unregistered_host(self):
        svc = self._svc({"api.example.com": ["93.184.216.34"]})
        d = self._decide(svc, "https://not-registered.example.org/")
        self.assertNotEqual(d.outcome.value, "ALLOW")

    def test_malformed_url_fails_closed(self):
        svc = self._svc({})
        d = self._decide(svc, "not a url at all")
        self.assertNotEqual(d.outcome.value, "ALLOW")


# =========================================================================== 8. DLP evasion
class DlpEvasionTests(unittest.TestCase):
    def test_plaintext_secret_detected(self):
        from agent_identity.egress import DlpEngine
        eng = DlpEngine()
        res = eng.inspect({"body": "my key is AKIAIOSFODNN7EXAMPLE and card 4111111111111111"})
        self.assertTrue(res.findings, "expected DLP findings for a plaintext secret")

    def test_encoded_secret_detected(self):
        import base64
        from agent_identity.egress import DlpEngine
        eng = DlpEngine()
        encoded = base64.b64encode(b"AKIAIOSFODNN7EXAMPLE").decode()
        res = eng.inspect({"body": encoded})
        # The engine decodes candidate encodings; a finding OR a non-allow outcome is acceptable.
        self.assertTrue(res.findings or res.outcome.value != "ALLOW")

    def test_credential_key_context_flagged(self):
        from agent_identity.egress import DlpEngine
        eng = DlpEngine()
        res = eng.inspect({"password": "s3cr3t-value-here", "user": "bob"})
        self.assertTrue(res.findings, "a credential-named key must be flagged")


# =========================================================================== 9. prompt injection -> tool use
class PromptInjectionToolUseTests(unittest.TestCase):
    """A prompt-injected agent must not be able to use a tool it was not granted."""

    def test_ungranted_tool_denied(self):
        from agent_identity.governance import (GovernanceConfig, GovernanceService,
                                               MemoryGovernanceStore)
        svc = GovernanceService(MemoryGovernanceStore(), GovernanceConfig(environment="development"))
        # The agent claims a capability it was never granted; the guard must not allow it.
        d = svc.decide(agent_id="agt", tenant="acme", resource_id="res", operation="delete",
                       tool="shell.exec", claimed_capabilities=("shell:exec",))
        self.assertNotEqual(d.outcome.value, "ALLOW")

    def test_capability_escalation_via_claim_denied(self):
        from agent_identity.governance import (GovernanceConfig, GovernanceService,
                                               MemoryGovernanceStore)
        svc = GovernanceService(MemoryGovernanceStore(), GovernanceConfig(environment="development"))
        d = svc.decide(agent_id="agt", tenant="acme", resource_id="res", operation="read",
                       requested_capabilities=("admin:all",))
        self.assertNotEqual(d.outcome.value, "ALLOW")


# =========================================================================== 10. resource exhaustion
class ResourceExhaustionTests(unittest.TestCase):
    def test_api_rate_limiter_fails_closed(self):
        from agent_identity.api.platform import RateLimiter
        from agent_identity.core.errors import RateLimitedError
        rl = RateLimiter(rate_per_s=1.0, burst=3)
        for _ in range(3):
            rl.check("route", "principal")
        with self.assertRaises(RateLimitedError):
            rl.check("route", "principal")

    def test_pagination_limit_clamped(self):
        from agent_identity.api.platform import MAX_PAGE_SIZE, parse_pagination
        _, limit = parse_pagination({"limit": "1000000"})
        self.assertLessEqual(limit, MAX_PAGE_SIZE)

    def test_negative_and_zero_pagination_rejected(self):
        from agent_identity.api.platform import parse_pagination
        for bad in ({"limit": "0"}, {"limit": "-5"}, {"offset": "-1"}):
            with self.assertRaises(ValidationError):
                parse_pagination(bad)

    def test_time_range_bounded(self):
        from agent_identity.api.platform import parse_time_range
        with self.assertRaises(ValidationError):
            parse_time_range({"since": "0", "until": str(10 ** 12)})

    def test_oversized_filter_rejected(self):
        from agent_identity.api.platform import parse_filters
        with self.assertRaises(ValidationError):
            parse_filters({"agent_id": "x" * 5000}, allowed=("agent_id",))


# =========================================================================== 11. audit tampering
class AuditTamperingTests(unittest.TestCase):
    def _audit(self):
        from agent_identity.assurance import AssuranceConfig, MemoryAssuranceStore
        from agent_identity.assurance.audit import LocalEd25519Signer, TamperEvidentAudit
        store = MemoryAssuranceStore()
        audit = TamperEvidentAudit(store, config=AssuranceConfig(environment="development"),
                                   signer=LocalEd25519Signer(environment="development"))
        return store, audit

    def test_clean_chain_verifies(self):
        store, audit = self._audit()
        for i in range(5):
            audit.record("evt", org_id="acme", actor_user_id="u", outcome="ok")
        res = audit.verify_chain(org_id="acme")
        self.assertTrue(res.get("valid", res.get("ok", False)), res)

    def test_modified_record_detected(self):
        store, audit = self._audit()
        for i in range(5):
            audit.record("evt", org_id="acme", actor_user_id="u", outcome="ok")
        # Tamper: mutate a stored record's payload digest in place.
        recs = store.list_audit(org_id="acme", limit=100)
        target = recs[2]
        object.__setattr__(target, "payload_digest", "deadbeef" * 8)
        res = audit.verify_chain(org_id="acme")
        self.assertFalse(res.get("valid", res.get("ok", True)), "tampering must be detected")

    def test_reordered_records_detected(self):
        store, audit = self._audit()
        for i in range(5):
            audit.record("evt", org_id="acme", actor_user_id="u", outcome="ok")
        # Swap two records in the underlying list to simulate reordering.
        with store._lock:  # noqa: SLF001 - deliberate tamper simulation
            store._audit[1], store._audit[3] = store._audit[3], store._audit[1]
        res = audit.verify_chain(org_id="acme")
        self.assertFalse(res.get("valid", res.get("ok", True)), "reordering must be detected")

    def test_missing_record_detected(self):
        store, audit = self._audit()
        for i in range(5):
            audit.record("evt", org_id="acme", actor_user_id="u", outcome="ok")
        with store._lock:  # noqa: SLF001
            del store._audit[2]
        res = audit.verify_chain(org_id="acme")
        self.assertFalse(res.get("valid", res.get("ok", True)), "a missing record must be detected")


# =========================================================================== 12. unsafe rollback
class UnsafeRollbackTests(unittest.TestCase):
    def test_rollback_requires_authority(self):
        from agent_identity.policy import MemoryPolicyStore, PolicyConfig, PolicyDecisionService, build_engine
        cfg = PolicyConfig(environment="development")
        svc = PolicyDecisionService(MemoryPolicyStore(), build_engine(cfg), cfg)
        admin = effective_access("a", "acme", tenant_roles=(ROLE_TENANT_ADMIN,))
        rec = svc.create_policy(admin, name="p", org_id="acme",
                                rego_source='package agentguard.authz\ndefault decision := {"decision":"ALLOW"}\n')
        readonly = effective_access("u", "acme", tenant_roles=(ROLE_READONLY_AUDITOR,))
        with self.assertRaises(ForbiddenError):
            svc.rollback(readonly, rec.policy_id, to_version=1)


# =========================================================================== 13. secret redaction in exports
class ExportRedactionTests(unittest.TestCase):
    def test_siem_event_redacts_secrets(self):
        from agent_identity.assurance import AssuranceConfig, AssuranceService, MemoryAssuranceStore
        from agent_identity.assurance.models import SiemEvent
        svc = AssuranceService(MemoryAssuranceStore(), config=AssuranceConfig(environment="development"))
        ev = SiemEvent(event_id="evt_1", ts=1000.0, org_id="acme", severity="info",
                       category="auth", action="login", outcome="ok", source="identity",
                       dedup_key="k1", fields={"password": "hunter2", "user": "bob"})
        out = svc.export_event(ev)
        self.assertNotIn("hunter2", str(out), "a secret must never appear in an exported event")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
