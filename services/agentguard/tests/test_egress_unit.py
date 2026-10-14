"""Phase 4 unit tests: egress security, SSRF/address protection, DLP, and the gateway decision path.

These are pure unit tests (no PostgreSQL, no network). They exercise the security-critical behaviour
directly:

  * address classification + SSRF floor (private/loopback/link-local/metadata/CGNAT/reserved)
  * DNS resolution validation and DNS-rebinding protection (a mixed answer is hostile)
  * destination policy matching (exact vs wildcard, deny-wins, default deny)
  * DLP detection, redaction, blocking, contextual credential-key redaction, encoded payloads
  * the gateway's four outcomes (ALLOW/DENY/REQUIRE_APPROVAL/INDETERMINATE) and fail-closed paths
  * adversarial bypass attempts: redirect to an internal address, oversized payload, obfuscated
    secret, forged/consumed decision seal, cross-tenant policy isolation

Run:  PYTHONPATH=src:. python -m unittest -v tests.test_egress_unit
"""
from __future__ import annotations

import unittest

from agent_identity.egress import (DlpAction, DlpEngine, DlpOutcome, DlpRule, DlpSeverity,
                                   EgressConfig, EgressOutcome, EgressRequest, EgressService,
                                   MemoryEgressStore, Protocol, RateLimitSpec)
from agent_identity.egress.addresses import (AddressPolicy, StaticDnsResolver, classify_address,
                                             is_cloud_metadata_address)
from agent_identity.egress.errors import EgressValidationError
from agent_identity.egress.models import AddressClass
from agent_identity.egress.policy import DestinationPolicy, host_matches, validate_host_pattern
from agent_identity.egress.ratelimit import RateLimiter
from agent_identity.core.errors import ForbiddenError


def _service(hosts=None, **cfg):
    resolver = StaticDnsResolver(hosts or {"api.example.com": ["93.184.216.34"],
                                           "evil.example.net": ["8.8.8.8"]})
    return EgressService(MemoryEgressStore(), config=EgressConfig(environment="development", **cfg),
                         address_policy=AddressPolicy(resolver=resolver))


# =========================================================================== address protection
class AddressClassificationTests(unittest.TestCase):
    def test_public(self):
        self.assertIs(classify_address("93.184.216.34"), AddressClass.PUBLIC)
        self.assertIs(classify_address("8.8.8.8"), AddressClass.PUBLIC)

    def test_private(self):
        for ip in ("10.0.0.1", "172.16.5.4", "192.168.1.1", "fd00::1"):
            self.assertIs(classify_address(ip), AddressClass.PRIVATE, ip)

    def test_loopback(self):
        self.assertIs(classify_address("127.0.0.1"), AddressClass.LOOPBACK)
        self.assertIs(classify_address("::1"), AddressClass.LOOPBACK)

    def test_link_local_and_metadata(self):
        self.assertIs(classify_address("169.254.1.1"), AddressClass.LINK_LOCAL)
        self.assertTrue(is_cloud_metadata_address("169.254.169.254"))
        self.assertTrue(is_cloud_metadata_address("fd00:ec2::254"))

    def test_cgnat(self):
        self.assertIs(classify_address("100.64.0.1"), AddressClass.CGNAT)

    def test_multicast_reserved_unspecified(self):
        self.assertIs(classify_address("224.0.0.1"), AddressClass.MULTICAST)
        self.assertIs(classify_address("240.0.0.1"), AddressClass.RESERVED)
        self.assertIs(classify_address("0.0.0.0"), AddressClass.UNSPECIFIED)

    def test_unknown(self):
        self.assertIs(classify_address("not-an-ip"), AddressClass.UNKNOWN)


class AddressPolicyTests(unittest.TestCase):
    def test_metadata_host_denied(self):
        ap = AddressPolicy(resolver=StaticDnsResolver({}))
        _, _, reason = ap.resolve_and_validate("metadata.google.internal")
        self.assertEqual(reason, "cloud_metadata_host")

    def test_literal_private_denied(self):
        ap = AddressPolicy(resolver=StaticDnsResolver({}))
        _, verdicts, reason = ap.resolve_and_validate("10.1.2.3")
        self.assertTrue(reason.startswith("blocked_address_"))
        self.assertTrue(verdicts[0].blocked)

    def test_dns_rebinding_mixed_answer_is_hostile(self):
        # a name that resolves to BOTH a public and a private address must be denied
        ap = AddressPolicy(resolver=StaticDnsResolver({"rebind.example.com": ["93.184.216.34",
                                                                             "10.0.0.5"]}))
        _, verdicts, reason = ap.resolve_and_validate("rebind.example.com")
        self.assertTrue(reason.startswith("blocked_address_"))
        self.assertTrue(any(v.blocked for v in verdicts))

    def test_public_resolution_allowed(self):
        ap = AddressPolicy(resolver=StaticDnsResolver({"ok.example.com": ["93.184.216.34"]}))
        addrs, verdicts, reason = ap.resolve_and_validate("ok.example.com")
        self.assertEqual(reason, "")
        self.assertEqual(addrs, ["93.184.216.34"])
        self.assertFalse(verdicts[0].blocked)

    def test_resolution_failure_fails_closed(self):
        class Boom:
            def resolve(self, host):
                raise OSError("dns down")
        ap = AddressPolicy(resolver=Boom())
        _, _, reason = ap.resolve_and_validate("whatever.example.com")
        self.assertTrue(reason.startswith("dns_resolution_failed"))


# =========================================================================== destination policy
class HostPatternTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(host_matches("api.example.com", "api.example.com"))
        self.assertFalse(host_matches("api.example.com", "evil.example.com"))

    def test_wildcard_matches_subdomain_not_apex(self):
        self.assertTrue(host_matches("*.example.com", "api.example.com"))
        self.assertTrue(host_matches("*.example.com", "a.b.example.com"))
        self.assertFalse(host_matches("*.example.com", "example.com"))

    def test_bare_wildcard_rejected(self):
        for bad in ("*", "*.", "api.*.com", ".example.com", "a b.com"):
            with self.assertRaises(EgressValidationError, msg=bad):
                validate_host_pattern(bad)

    def test_valid_patterns_normalised(self):
        self.assertEqual(validate_host_pattern("API.Example.COM"), "api.example.com")
        self.assertEqual(validate_host_pattern("*.Example.com"), "*.example.com")


class DestinationPolicyTests(unittest.TestCase):
    def _rec(self, **kw):
        from agent_identity.egress.models import EgressPolicyRecord
        base = dict(policy_id="p1", org_id="o1", name="n", host_patterns=("api.example.com",),
                    protocols=frozenset({Protocol.HTTPS}), ports=frozenset({443}),
                    action=EgressOutcome.ALLOW)
        base.update(kw)
        return EgressPolicyRecord(**base)

    def test_no_match_default_deny(self):
        dp = DestinationPolicy(default_action="deny")
        v = dp.evaluate(host="x.example.com", protocol=Protocol.HTTPS, port=443, policies=[])
        self.assertIs(v.action, EgressOutcome.DENY)
        self.assertFalse(v.matched)

    def test_no_match_require_approval(self):
        dp = DestinationPolicy(default_action="require_approval")
        v = dp.evaluate(host="x.example.com", protocol=Protocol.HTTPS, port=443, policies=[])
        self.assertIs(v.action, EgressOutcome.REQUIRE_APPROVAL)

    def test_exact_beats_wildcard(self):
        dp = DestinationPolicy()
        wild = self._rec(policy_id="wild", host_patterns=("*.example.com",),
                         action=EgressOutcome.ALLOW)
        exact = self._rec(policy_id="exact", host_patterns=("api.example.com",),
                          action=EgressOutcome.DENY)
        v = dp.evaluate(host="api.example.com", protocol=Protocol.HTTPS, port=443,
                        policies=[wild, exact])
        self.assertIs(v.action, EgressOutcome.DENY)
        self.assertEqual(v.policy.policy_id, "exact")

    def test_deny_wins_at_same_specificity(self):
        dp = DestinationPolicy()
        allow = self._rec(policy_id="a", action=EgressOutcome.ALLOW, priority=100)
        deny = self._rec(policy_id="d", action=EgressOutcome.DENY, priority=100)
        v = dp.evaluate(host="api.example.com", protocol=Protocol.HTTPS, port=443,
                        policies=[allow, deny])
        self.assertIs(v.action, EgressOutcome.DENY)

    def test_protocol_port_must_match(self):
        dp = DestinationPolicy()
        rec = self._rec(protocols=frozenset({Protocol.HTTPS}), ports=frozenset({443}))
        v = dp.evaluate(host="api.example.com", protocol=Protocol.HTTP, port=80, policies=[rec])
        self.assertIs(v.action, EgressOutcome.DENY)   # no match -> default deny

    def test_disabled_rule_ignored(self):
        dp = DestinationPolicy()
        rec = self._rec(enabled=False)
        v = dp.evaluate(host="api.example.com", protocol=Protocol.HTTPS, port=443, policies=[rec])
        self.assertFalse(v.matched)


# =========================================================================== rate limiter
class RateLimiterTests(unittest.TestCase):
    def test_burst_then_deny(self):
        rl = RateLimiter()
        allowed = sum(1 for _ in range(5) if rl.allow("k", per_second=1.0, burst=3)[0])
        self.assertEqual(allowed, 3)
        ok, retry = rl.allow("k", per_second=1.0, burst=3)
        self.assertFalse(ok)
        self.assertGreater(retry, 0)

    def test_bounded_map(self):
        rl = RateLimiter(max_buckets=10)
        for i in range(100):
            rl.allow(f"k{i}", per_second=1.0, burst=1)
        self.assertLessEqual(len(rl), 10)


# =========================================================================== DLP
class DlpTests(unittest.TestCase):
    def setUp(self):
        self.dlp = DlpEngine()

    def test_clean(self):
        r = self.dlp.inspect({"note": "hello world"})
        self.assertIs(r.outcome, DlpOutcome.CLEAN)

    def test_aws_secret_blocks(self):
        r = self.dlp.inspect({"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
        self.assertIs(r.outcome, DlpOutcome.BLOCK)

    def test_private_key_blocks(self):
        r = self.dlp.inspect("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        self.assertIs(r.outcome, DlpOutcome.BLOCK)

    def test_connection_string_blocks(self):
        r = self.dlp.inspect("postgres://user:s3cr3t@db.internal:5432/app")
        self.assertIs(r.outcome, DlpOutcome.BLOCK)

    def test_credit_card_luhn(self):
        # 4111 1111 1111 1111 is Luhn-valid; 4111 1111 1111 1112 is not
        self.assertIs(self.dlp.inspect("card 4111 1111 1111 1111").outcome, DlpOutcome.BLOCK)
        self.assertIsNot(self.dlp.inspect("num 4111 1111 1111 1112").outcome, DlpOutcome.BLOCK)

    def test_email_redacted(self):
        r = self.dlp.inspect({"to": "alice@example.com"})
        self.assertIs(r.outcome, DlpOutcome.REDACTED)
        self.assertIn("[REDACTED]", r.redacted_payload["to"])

    def test_contextual_credential_key_redacted(self):
        r = self.dlp.inspect({"password": "x"})     # value too short for the regex
        self.assertIs(r.outcome, DlpOutcome.REDACTED)
        self.assertEqual(r.redacted_payload["password"], "[REDACTED]")
        self.assertIn("dlp.credential_key", r.rule_ids)

    def test_nested_redaction(self):
        r = self.dlp.inspect({"outer": {"token": "abcdefghijklmnopqrstuvwxyz012345"}})
        self.assertIs(r.outcome, DlpOutcome.REDACTED)
        self.assertEqual(r.redacted_payload["outer"]["token"], "[REDACTED]")

    def test_encoded_secret_detected(self):
        import base64
        secret = "AKIAIOSFODNN7EXAMPLE"
        encoded = base64.b64encode(secret.encode()).decode()
        r = self.dlp.inspect({"blob": encoded})
        self.assertIn("dlp.aws_access_key_id", r.rule_ids)

    def test_oversized_payload_indeterminate(self):
        dlp = DlpEngine(max_inspect_bytes=64)
        r = dlp.inspect("x" * 1000)
        self.assertIs(r.outcome, DlpOutcome.INDETERMINATE)
        self.assertEqual(r.reason, "payload_too_large")

    def test_no_sensitive_content_in_findings(self):
        r = self.dlp.inspect({"password": "supersecretvalue123"})
        for f in r.findings:
            self.assertNotIn("supersecretvalue123", f.preview)
            self.assertEqual(f.preview, "[REDACTED]")

    def test_custom_rule(self):
        rule = DlpRule(rule_id="org.internal_id", name="Internal ID", pattern=r"INT-\d{6}",
                       severity=DlpSeverity.HIGH, action=DlpAction.BLOCK, category="enterprise")
        dlp = DlpEngine(rules=(rule,))
        self.assertIs(dlp.inspect("ref INT-123456").outcome, DlpOutcome.BLOCK)

    def test_entropy_gate_rejects_placeholder(self):
        # a low-entropy "secret" (all same char) must not trip the generic api-key rule
        r = self.dlp.inspect({"api_key": "aaaaaaaaaaaaaaaaaaaa"})
        self.assertNotIn("dlp.generic_api_key", r.rule_ids)


# =========================================================================== gateway
class GatewayDecisionTests(unittest.TestCase):
    def test_allow_with_seal(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])
        d = svc.decide(agent_id="a1", tenant="o1",
                       request=EgressRequest(url="https://api.example.com/x"))
        self.assertIs(d.outcome, EgressOutcome.ALLOW)
        self.assertTrue(d.allowed)
        self.assertIsNotNone(d.seal)

    def test_ssrf_metadata_denied(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])
        d = svc.decide(agent_id="a1", tenant="o1",
                       request=EgressRequest(url="http://169.254.169.254/latest/meta-data"))
        self.assertIs(d.outcome, EgressOutcome.DENY)
        self.assertEqual(d.reason, "cloud_metadata_host")

    def test_private_ip_denied(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])
        d = svc.decide(agent_id="a1", tenant="o1", request=EgressRequest(url="http://10.0.0.5/x"))
        self.assertIs(d.outcome, EgressOutcome.DENY)
        self.assertTrue(d.reason.startswith("blocked_address_"))

    def test_no_policy_denied(self):
        svc = _service()
        d = svc.decide(agent_id="a1", tenant="o1",
                       request=EgressRequest(url="https://evil.example.net/x"))
        self.assertIs(d.outcome, EgressOutcome.DENY)
        self.assertEqual(d.reason, "no_matching_policy")

    def test_dlp_block_denied(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])
        d = svc.decide(agent_id="a1", tenant="o1", request=EgressRequest(
            url="https://api.example.com/x", method="POST",
            body={"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}))
        self.assertIs(d.outcome, EgressOutcome.DENY)
        self.assertEqual(d.reason, "dlp_blocked")

    def test_dlp_redact_allows_with_redacted_body(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])
        d = svc.decide(agent_id="a1", tenant="o1", request=EgressRequest(
            url="https://api.example.com/x", method="POST", body={"password": "hunter2secret"}))
        self.assertIs(d.outcome, EgressOutcome.ALLOW)
        self.assertEqual(d.redacted_body["password"], "[REDACTED]")

    def test_require_approval_policy(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="approve", host_patterns=["api.example.com"],
                            action="REQUIRE_APPROVAL")
        d = svc.decide(agent_id="a1", tenant="o1",
                       request=EgressRequest(url="https://api.example.com/x"))
        self.assertIs(d.outcome, EgressOutcome.REQUIRE_APPROVAL)
        self.assertFalse(d.allowed)

    def test_unsupported_scheme_denied(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])
        d = svc.decide(agent_id="a1", tenant="o1",
                       request=EgressRequest(url="ftp://api.example.com/x"))
        self.assertIs(d.outcome, EgressOutcome.DENY)
        self.assertTrue(d.reason.startswith("malformed_url"))

    def test_oversized_request_denied(self):
        svc = _service(max_request_bytes=32)
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])
        d = svc.decide(agent_id="a1", tenant="o1", request=EgressRequest(
            url="https://api.example.com/x", method="POST", body="y" * 100))
        self.assertIs(d.outcome, EgressOutcome.DENY)
        self.assertEqual(d.reason, "request_too_large")

    def test_rate_limited(self):
        svc = _service(default_rate_per_second=0.001, default_rate_burst=1)
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])
        first = svc.decide(agent_id="a1", tenant="o1",
                           request=EgressRequest(url="https://api.example.com/x"))
        second = svc.decide(agent_id="a1", tenant="o1",
                            request=EgressRequest(url="https://api.example.com/x"))
        self.assertIs(first.outcome, EgressOutcome.ALLOW)
        self.assertIs(second.outcome, EgressOutcome.DENY)
        self.assertEqual(second.reason, "rate_limited")

    def test_cross_tenant_policy_isolation(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])
        # o2 has no policy -> denied even though o1 allows the same host
        d = svc.decide(agent_id="a1", tenant="o2",
                       request=EgressRequest(url="https://api.example.com/x"))
        self.assertIs(d.outcome, EgressOutcome.DENY)
        self.assertEqual(d.reason, "no_matching_policy")

    def test_missing_tenant_denied(self):
        svc = _service()
        d = svc.decide(agent_id="a1", tenant="",
                       request=EgressRequest(url="https://api.example.com/x"))
        self.assertIs(d.outcome, EgressOutcome.DENY)
        self.assertEqual(d.reason, "missing_tenant")


class GatewayEnforceTests(unittest.TestCase):
    def test_enforce_runs_on_sealed_allow(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])
        d = svc.decide(agent_id="a1", tenant="o1",
                       request=EgressRequest(url="https://api.example.com/x"))
        ran = {"v": False}

        def ex():
            ran["v"] = True
            return "ok"
        self.assertEqual(svc.gateway.enforce(d, ex), "ok")
        self.assertTrue(ran["v"])

    def test_enforce_rejects_consumed_seal(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])
        d = svc.decide(agent_id="a1", tenant="o1",
                       request=EgressRequest(url="https://api.example.com/x"))
        svc.gateway.enforce(d, lambda: "ok")
        with self.assertRaises(ForbiddenError):
            svc.gateway.enforce(d, lambda: "should not run")

    def test_enforce_rejects_forged_decision(self):
        from agent_identity.egress.gateway import EgressDecision
        svc = _service()
        forged = EgressDecision.allow("forged", seal="eseal_forged")
        with self.assertRaises(ForbiddenError):
            svc.gateway.enforce(forged, lambda: "should not run")

    def test_enforce_rejects_deny(self):
        svc = _service()
        d = svc.decide(agent_id="a1", tenant="o1",
                       request=EgressRequest(url="https://evil.example.net/x"))
        with self.assertRaises(ForbiddenError):
            svc.gateway.enforce(d, lambda: "should not run")


class RedirectBypassTests(unittest.TestCase):
    """A redirect to an internal address must be blocked even when the first hop is allowed."""

    def test_redirect_to_private_blocked(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"],
                            allow_redirects=True)

        class RedirectingTransport:
            def send(self, **kw):
                return {"status": 302, "headers": {"Location": "http://169.254.169.254/secret"},
                        "body": b""}
        out = svc.request(agent_id="a1", tenant="o1",
                          request=EgressRequest(url="https://api.example.com/x"),
                          transport=RedirectingTransport())
        self.assertFalse(out["response"]["executed"])
        self.assertIn("redirect", out["response"]["reason"])

    def test_redirect_not_permitted_by_default(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])

        class RedirectingTransport:
            def send(self, **kw):
                return {"status": 302, "headers": {"Location": "https://api.example.com/other"},
                        "body": b""}
        out = svc.request(agent_id="a1", tenant="o1",
                          request=EgressRequest(url="https://api.example.com/x"),
                          transport=RedirectingTransport())
        self.assertFalse(out["response"]["executed"])
        self.assertEqual(out["response"]["reason"], "redirect_not_permitted")


class MetricsTests(unittest.TestCase):
    def test_metrics_counted(self):
        svc = _service()
        svc.register_policy(org_id="o1", name="allow", host_patterns=["api.example.com"])
        svc.decide(agent_id="a1", tenant="o1", request=EgressRequest(url="https://api.example.com/x"))
        svc.decide(agent_id="a1", tenant="o1", request=EgressRequest(url="http://10.0.0.1/x"))
        m = svc.metrics()
        self.assertEqual(m["requests"], 2)
        self.assertEqual(m["allowed"], 1)
        self.assertEqual(m["denied"], 1)
        self.assertGreaterEqual(m["ssrf_blocked"], 1)


class EgressHttpRouteTests(unittest.TestCase):
    """The egress admin + governed-request routes are RBAC-checked and return structured decisions."""

    def _router(self):
        from agent_identity.api.enterprise_http import EnterpriseRouter
        from agent_identity.security.admin_ops import AdminOps
        from tests.test_security_unit import _service as _sec_service, _user, GOOD_PW
        from agent_identity.security.rbac import ROLE_PLATFORM_ADMIN
        svc, store, clock = _sec_service()
        ops = AdminOps(store, svc.audit, svc.config, permission_cache=svc.permission_cache,
                       sessions=svc.sessions, clock=clock)
        eg = _service()
        router = EnterpriseRouter(svc, ops, svc.config, egress_service=eg)
        _user(store, global_roles=(ROLE_PLATFORM_ADMIN,))
        status, body, _ = router.handle("POST", "/v1/auth/login",
                                        {"email": "admin@acme.test", "password": GOOD_PW}, {}, {})
        headers = {"Authorization": f"Bearer {body['access_token']}",
                   "X-CSRF-Token": body["csrf_token"]}
        return router, headers, eg

    def test_register_and_list_policy(self):
        router, headers, eg = self._router()
        s, b, _ = router.handle("POST", "/v1/admin/egress/policies",
                                {"org_id": "acme", "name": "allow api",
                                 "host_patterns": ["api.example.com"], "action": "ALLOW"},
                                headers, {})
        self.assertEqual(s, 201)
        self.assertEqual(b["host_patterns"], ["api.example.com"])
        s2, b2, _ = router.handle("GET", "/v1/admin/egress/policies", {"org_id": "acme"},
                                  headers, {})
        self.assertEqual(s2, 200)
        self.assertEqual(len(b2["policies"]), 1)

    def test_governed_request_returns_decision(self):
        router, headers, eg = self._router()
        eg.register_policy(org_id="acme", name="allow api", host_patterns=["api.example.com"])
        s, b, _ = router.handle("POST", "/v1/egress/request",
                                {"org_id": "acme", "url": "https://api.example.com/x",
                                 "method": "GET"}, headers, {})
        self.assertEqual(s, 200)
        self.assertIn("decision", b)
        self.assertIn(b["decision"]["decision"], ("ALLOW", "DENY", "REQUIRE_APPROVAL",
                                                  "INDETERMINATE"))

    def test_governed_request_ssrf_denied(self):
        router, headers, eg = self._router()
        eg.register_policy(org_id="acme", name="allow api", host_patterns=["api.example.com"])
        s, b, _ = router.handle("POST", "/v1/egress/request",
                                {"org_id": "acme", "url": "http://169.254.169.254/latest/meta-data"},
                                headers, {})
        self.assertEqual(s, 200)
        self.assertFalse(b["decision"]["allowed"])
        self.assertEqual(b["decision"]["reason"], "cloud_metadata_host")

    def test_metrics_route(self):
        router, headers, eg = self._router()
        s, b, _ = router.handle("GET", "/v1/admin/egress/metrics", {"org_id": "acme"}, headers, {})
        self.assertEqual(s, 200)
        self.assertIn("requests", b)

    def test_egress_routes_404_when_not_configured(self):
        from agent_identity.api.enterprise_http import EnterpriseRouter
        from agent_identity.security.admin_ops import AdminOps
        from tests.test_security_unit import _service as _sec_service, _user, GOOD_PW
        from agent_identity.security.rbac import ROLE_PLATFORM_ADMIN
        svc, store, clock = _sec_service()
        ops = AdminOps(store, svc.audit, svc.config, permission_cache=svc.permission_cache,
                       sessions=svc.sessions, clock=clock)
        router = EnterpriseRouter(svc, ops, svc.config)     # no egress service
        _user(store, global_roles=(ROLE_PLATFORM_ADMIN,))
        _, body, _ = router.handle("POST", "/v1/auth/login",
                                   {"email": "admin@acme.test", "password": GOOD_PW}, {}, {})
        headers = {"Authorization": f"Bearer {body['access_token']}",
                   "X-CSRF-Token": body["csrf_token"]}
        s, _, _ = router.handle("GET", "/v1/admin/egress/policies", {}, headers, {})
        self.assertEqual(s, 404)


if __name__ == "__main__":
    unittest.main()
