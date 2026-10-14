"""Step 9 Python SDK unit tests.

Covers: configuration fail-closed rules, transport (TLS verification, timeouts, bounded retries,
cancellation, non-idempotent POST never replayed, network failure), credential acquisition/renewal,
expiry/revocation handling, proof-of-possession format compatibility with the core library,
authorization fail-closed behaviour, the anti-bypass enforcement guarantee, the tool guard, security
event reporting/redaction, and negative security assertions (no secrets in errors or reprs).

No external services required: a fake HTTP opener stands in for the AgentGuard control plane.
"""
import json
import socket
import ssl
import unittest
import urllib.error

from agent_identity.crypto import keys
from agent_identity.crypto.client import AgentSideKey
from agent_identity.crypto.encoding import b64u_decode

from agentguard_sdk import (AgentGuardClient, AuthorizationError, CancelledError, Decision,
                            DenyAllPdp, PolicyUnavailableError, SdkConfig, ServerError, StaticPdp,
                            TimeoutError, Transport, TransportError, ValidationError)
from agentguard_sdk.adapters import ToolGuard, ToolGuardError
from agentguard_sdk.config import ConfigurationError
from agentguard_sdk.models import Credential, ToolCall


# --------------------------------------------------------------------------- fake HTTP harness
class FakeResponse:
    def __init__(self, status, body, headers=None):
        if isinstance(body, (bytes, bytearray)):
            self._raw = bytes(body)
        elif isinstance(body, str):
            self._raw = body.encode()
        else:
            self._raw = json.dumps(body).encode()
        self.status = status
        self.headers = headers or {}

    def read(self, n=-1):
        return self._raw if n is None or n < 0 else self._raw[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOpener:
    """Records every request and delegates to a handler(req) -> FakeResponse (or raises)."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def open(self, req, timeout=None):
        self.calls.append({"method": req.method, "url": req.full_url, "data": req.data,
                           "headers": dict(req.headers), "timeout": timeout})
        return self.handler(req)


def make_client(handler, **cfg):
    base = dict(base_url="https://agentguard.test", environment="development", max_retries=3,
                retry_base_seconds=0.001, retry_max_seconds=0.002)
    base.update(cfg)
    config = SdkConfig(**base)
    opener = FakeOpener(handler)
    transport = Transport(config, opener=opener, sleep=lambda s: None)
    client = AgentGuardClient(config, agent_id="agt_test", instance_id="inst_test",
                              transport=transport)
    return client, opener


def ok(body, status=200):
    return lambda req: FakeResponse(status, body)


# --------------------------------------------------------------------------- configuration
class ConfigTests(unittest.TestCase):
    def test_requires_absolute_url(self):
        with self.assertRaises(ConfigurationError):
            SdkConfig(base_url="agentguard.test")

    def test_rejects_plaintext_in_production(self):
        with self.assertRaises(ConfigurationError):
            SdkConfig(base_url="http://agentguard.test", environment="production")

    def test_rejects_disabled_tls_outside_development(self):
        with self.assertRaises(ConfigurationError):
            SdkConfig(base_url="https://x.test", environment="staging", verify_tls=False)

    def test_allows_disabled_tls_in_development(self):
        c = SdkConfig(base_url="https://x.test", environment="development", verify_tls=False)
        self.assertFalse(c.verify_tls)

    def test_bounds(self):
        with self.assertRaises(ConfigurationError):
            SdkConfig(base_url="https://x.test", timeout_seconds=0)
        with self.assertRaises(ConfigurationError):
            SdkConfig(base_url="https://x.test", max_retries=99)
        with self.assertRaises(ConfigurationError):
            SdkConfig(base_url="https://x.test", client_cert="a.pem")   # key missing

    def test_from_env_defaults(self):
        c = SdkConfig.from_env()
        self.assertTrue(c.verify_tls)
        self.assertEqual(c.environment, "development")


# --------------------------------------------------------------------------- transport
class TransportTests(unittest.TestCase):
    def test_ssl_context_verifies_by_default(self):
        t = Transport(SdkConfig(base_url="https://agentguard.test"))
        ctx = t._ssl_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_get_retries_then_succeeds(self):
        state = {"n": 0}

        def handler(req):
            state["n"] += 1
            if state["n"] < 3:
                return FakeResponse(503, {"error": "unavailable"})
            return FakeResponse(200, {"ok": True})

        client, opener = make_client(handler)
        resp = client._request("GET", "/v1/agents/agt_test")
        self.assertEqual(resp.status, 200)
        self.assertEqual(len(opener.calls), 3)

    def test_non_idempotent_post_is_not_replayed(self):
        def handler(req):
            return FakeResponse(503, {"error": "unavailable"})

        client, opener = make_client(handler)
        with self.assertRaises(ServerError):
            client._request("POST", "/v1/agents", body={"x": 1})
        self.assertEqual(len(opener.calls), 1)          # never silently replayed

    def test_idempotent_post_is_retried(self):
        state = {"n": 0}

        def handler(req):
            state["n"] += 1
            if state["n"] < 2:
                return FakeResponse(503, {"error": "unavailable"})
            return FakeResponse(201, {"agent_id": "agt_1"})

        client, opener = make_client(handler)
        resp = client._request("POST", "/v1/agents", body={"x": 1}, idempotency_key="k1")
        self.assertEqual(resp.status, 201)
        self.assertEqual(len(opener.calls), 2)
        self.assertEqual(opener.calls[0]["headers"].get("Idempotency-key"), "k1")

    def test_timeout_maps_to_typed_error(self):
        def handler(req):
            raise urllib.error.URLError(socket.timeout())

        client, _ = make_client(handler)
        with self.assertRaises(TimeoutError):
            client._request("GET", "/v1/agents/agt_test")

    def test_network_failure_maps_to_transport_error(self):
        def handler(req):
            raise urllib.error.URLError(ConnectionRefusedError())

        client, _ = make_client(handler)
        with self.assertRaises(TransportError):
            client._request("GET", "/v1/agents/agt_test")

    def test_cancellation_before_request(self):
        from agentguard_sdk import CancellationToken
        client, opener = make_client(ok({"ok": True}))
        tok = CancellationToken()
        tok.cancel()
        with self.assertRaises(CancelledError):
            client._request("GET", "/v1/agents/agt_test", cancel=tok)
        self.assertEqual(len(opener.calls), 0)

    def test_response_size_cap(self):
        def handler(req):
            return FakeResponse(200, b"x" * 5000)

        client, _ = make_client(handler, max_response_bytes=100)
        with self.assertRaises(TransportError):
            client._request("GET", "/v1/agents/agt_test")

    def test_error_carries_correlation_id_not_secrets(self):
        def handler(req):
            return FakeResponse(403, {"error": "forbidden", "message": "nope",
                                      "correlation_id": "cor_abc"})

        client, _ = make_client(handler)
        try:
            client._request("GET", "/v1/agents/agt_test")
            self.fail("expected AuthorizationError")
        except AuthorizationError as e:
            self.assertEqual(e.correlation_id, "cor_abc")
            self.assertNotIn("Bearer", str(e))


# --------------------------------------------------------------------------- credentials / auth
class CredentialTests(unittest.TestCase):
    def _issue_handler(self, *, expires_in=900, credential_id="crd_1"):
        def handler(req):
            if req.full_url.endswith("/v1/credentials/issue"):
                return FakeResponse(201, {"credential_id": credential_id, "agent_id": "agt_test",
                                          "instance_id": "inst_test", "org_id": "acme",
                                          "issued_at": "2026-01-01T00:00:00Z",
                                          "expires_at": "2026-01-01T00:15:00Z",
                                          "capabilities": ["tool:read"],
                                          "token": "agp1.payload.sig"})
            if req.full_url.endswith("/v1/credentials/rotate"):
                return FakeResponse(200, {"credential_id": "crd_2", "agent_id": "agt_test",
                                          "instance_id": "inst_test", "org_id": "acme",
                                          "issued_at": "2026-01-01T00:10:00Z",
                                          "expires_at": "2026-01-01T00:25:00Z",
                                          "capabilities": ["tool:read"],
                                          "token": "agp1.payload2.sig2"})
            if "/status" in req.full_url:
                return FakeResponse(200, {"credential_id": credential_id, "status": "active"})
            return FakeResponse(404, {"error": "not_found"})
        return handler

    def test_acquire_sends_public_key_and_pop_not_private_key(self):
        client, opener = make_client(self._issue_handler())
        cred = client.issue_credential()
        self.assertEqual(cred.credential_id, "crd_1")
        body = json.loads(opener.calls[0]["data"])
        self.assertIn("public_key", body)
        self.assertIn("pop_signature", body)
        self.assertNotIn("private", json.dumps(body).lower())
        # the private key never appears anywhere in the request
        self.assertNotIn("private_key", json.dumps(body))

    def test_proof_format_matches_core_library(self):
        client, _ = make_client(self._issue_handler())
        client.issue_credential()
        proof = client.authenticator.make_proof()
        pub = client.authenticator.key.public_key
        ok_ = keys.verify(pub, keys.DOMAIN_PROOF, keys.proof_bytes(proof),
                          b64u_decode(proof["signature"]))
        self.assertTrue(ok_)                            # verifies with the CORE verifier

    def test_csr_format_matches_core_library(self):
        client, _ = make_client(self._issue_handler())
        csr = client.authenticator.key.csr("agt_test", "inst_test")
        ok_ = keys.verify(csr["public_key"], keys.DOMAIN_CSR,
                          keys.csr_bytes("agt_test", "inst_test", csr["public_key"]),
                          b64u_decode(csr["pop_signature"]))
        self.assertTrue(ok_)

    def test_ensure_valid_renews_near_expiry(self):
        # credential already expired -> ensure_valid must renew (rotate)
        def handler(req):
            if req.full_url.endswith("/v1/credentials/issue"):
                return FakeResponse(201, {"credential_id": "crd_old", "agent_id": "agt_test",
                                          "instance_id": "inst_test", "org_id": "acme",
                                          "expires_at": "2000-01-01T00:00:00Z",
                                          "token": "agp1.a.b"})
            if req.full_url.endswith("/v1/credentials/rotate"):
                return FakeResponse(200, {"credential_id": "crd_new", "agent_id": "agt_test",
                                          "instance_id": "inst_test", "org_id": "acme",
                                          "expires_at": "2999-01-01T00:00:00Z",
                                          "token": "agp1.c.d"})
            return FakeResponse(404, {"error": "not_found"})

        client, opener = make_client(handler)
        client.issue_credential()
        cred = client.ensure_credential()
        self.assertEqual(cred.credential_id, "crd_new")
        self.assertTrue(any(c["url"].endswith("/rotate") for c in opener.calls))

    def test_revoked_credential_raises_typed_error(self):
        def handler(req):
            if req.full_url.endswith("/v1/credentials/issue"):
                return FakeResponse(201, {"credential_id": "crd_1", "agent_id": "agt_test",
                                          "instance_id": "inst_test", "org_id": "acme",
                                          "expires_at": "2999-01-01T00:00:00Z", "token": "agp1.a.b"})
            if "/status" in req.full_url:
                return FakeResponse(200, {"credential_id": "crd_1", "status": "revoked"})
            return FakeResponse(404, {"error": "not_found"})

        from agentguard_sdk import CredentialRevokedError
        client, _ = make_client(handler)
        client.issue_credential()
        with self.assertRaises(CredentialRevokedError):
            client.authenticator.credentials.assert_usable()

    def test_auth_headers_never_contain_private_key(self):
        client, _ = make_client(self._issue_handler())
        client.issue_credential()
        headers = client.authenticator.auth_headers()
        self.assertTrue(headers["Authorization"].startswith("AgentPassport "))
        self.assertIn("X-Agent-Proof", headers)
        self.assertNotIn("private", json.dumps(headers).lower())

    def test_credential_repr_redacts_token(self):
        c = Credential("crd_1", "agt_1", "inst_1", "acme", token="agp1.secret.sig")
        self.assertNotIn("agp1.secret", repr(c))
        self.assertIn("redacted", repr(c))


# --------------------------------------------------------------------------- authorization
class AuthorizationTests(unittest.TestCase):
    def _client_with_cred(self, pdp):
        def handler(req):
            if req.full_url.endswith("/v1/credentials/issue"):
                return FakeResponse(201, {"credential_id": "crd_1", "agent_id": "agt_test",
                                          "instance_id": "inst_test", "org_id": "acme",
                                          "expires_at": "2999-01-01T00:00:00Z", "token": "agp1.a.b"})
            return FakeResponse(404, {"error": "not_found"})

        client, opener = make_client(handler)
        client.authorization.pdp = pdp
        client.issue_credential()
        return client, opener

    def test_static_pdp_allow_and_deny(self):
        client, _ = self._client_with_cred(StaticPdp(["tool:read"]))
        self.assertTrue(client.authorize(action="tool:read", resource="db").allowed)
        self.assertFalse(client.authorize(action="tool:write", resource="db").allowed)

    def test_require_raises_on_deny(self):
        client, _ = self._client_with_cred(StaticPdp([]))
        with self.assertRaises(AuthorizationError):
            client.require(action="tool:read", resource="db")

    def test_deny_all_pdp_is_safe_default(self):
        client, _ = self._client_with_cred(DenyAllPdp())
        self.assertFalse(client.authorize(action="tool:read", resource="db").allowed)

    def test_policy_unavailable_fails_closed(self):
        # RemotePdp against a server that has no /v1/authorize endpoint -> DENY, never allow
        def handler(req):
            if req.full_url.endswith("/v1/credentials/issue"):
                return FakeResponse(201, {"credential_id": "crd_1", "agent_id": "agt_test",
                                          "instance_id": "inst_test", "org_id": "acme",
                                          "expires_at": "2999-01-01T00:00:00Z", "token": "agp1.a.b"})
            return FakeResponse(404, {"error": "not_found"})

        client, _ = make_client(handler)
        client.issue_credential()
        decision = client.authorize(action="tool:read", resource="db")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "policy_unavailable")

    def test_pdp_exception_fails_closed(self):
        class Boom:
            def decide(self, request):
                raise RuntimeError("pdp exploded")

        client, _ = self._client_with_cred(Boom())
        decision = client.authorize(action="tool:read", resource="db")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "policy_error")

    def test_enforce_does_not_run_executor_on_deny(self):
        client, _ = self._client_with_cred(StaticPdp([]))
        ran = {"v": False}

        def executor():
            ran["v"] = True
            return "done"

        with self.assertRaises(AuthorizationError):
            client.authorization.enforce(Decision.deny("nope"), executor)
        self.assertFalse(ran["v"])

    def test_enforce_runs_executor_on_allow(self):
        client, _ = self._client_with_cred(StaticPdp(["tool:read"]))
        decision = client.authorize(action="tool:read", resource="db")
        self.assertEqual(client.authorization.enforce(decision, lambda: "ok"), "ok")

    def test_authorize_validates_inputs(self):
        client, _ = self._client_with_cred(StaticPdp(["tool:read"]))
        with self.assertRaises(ValidationError):
            client.authorize(action="", resource="db")
        with self.assertRaises(ValidationError):
            client.authorize(action="tool:read", resource="")


# --------------------------------------------------------------------------- tool guard
class ToolGuardTests(unittest.TestCase):
    def _client(self, allowed):
        def handler(req):
            if req.full_url.endswith("/v1/credentials/issue"):
                return FakeResponse(201, {"credential_id": "crd_1", "agent_id": "agt_test",
                                          "instance_id": "inst_test", "org_id": "acme",
                                          "expires_at": "2999-01-01T00:00:00Z", "token": "agp1.a.b"})
            if req.full_url.endswith("/v1/security/events"):
                return FakeResponse(202, {"accepted": 1})
            return FakeResponse(404, {"error": "not_found"})

        client, opener = make_client(handler)
        client.authorization.pdp = StaticPdp(allowed)
        client.issue_credential()
        return client, opener

    def test_denied_tool_is_never_executed(self):
        client, _ = self._client([])
        guard = ToolGuard(client)
        ran = {"v": False}

        def dangerous():
            ran["v"] = True
            return "secret"

        with self.assertRaises(ToolGuardError):
            guard.execute("delete_db", dangerous)
        self.assertFalse(ran["v"])

    def test_allowed_tool_executes(self):
        client, _ = self._client(["tool:read"])
        guard = ToolGuard(client)
        self.assertEqual(guard.execute("read", lambda: "data"), "data")

    def test_guarded_tool_wrapper(self):
        client, _ = self._client(["tool:read"])
        guard = ToolGuard(client)
        wrapped = guard.guard("read", lambda x: x * 2)
        self.assertEqual(wrapped(21), 42)

    def test_tool_error_is_reported_and_reraised(self):
        client, opener = self._client(["tool:read"])
        guard = ToolGuard(client)

        def boom():
            raise ValueError("kaboom")

        with self.assertRaises(ValueError):
            guard.execute("read", boom)
        client.flush_events()
        self.assertTrue(any(c["url"].endswith("/v1/security/events") for c in opener.calls))

    def test_tool_call_normalization(self):
        call = ToolCall(tool="send_email", arguments={"to": "x"})
        self.assertEqual(call.action(), "tool:send_email")
        body = call.to_authorization_body()
        self.assertEqual(body["action"], "tool:send_email")
        self.assertEqual(body["context"]["tool"], "send_email")


# --------------------------------------------------------------------------- events
class EventTests(unittest.TestCase):
    def test_metadata_is_allow_listed_and_redacted(self):
        def handler(req):
            if req.full_url.endswith("/v1/credentials/issue"):
                return FakeResponse(201, {"credential_id": "crd_1", "agent_id": "agt_test",
                                          "instance_id": "inst_test", "org_id": "acme",
                                          "expires_at": "2999-01-01T00:00:00Z", "token": "agp1.a.b"})
            if req.full_url.endswith("/v1/security/events"):
                return FakeResponse(202, {"accepted": 1})
            return FakeResponse(404, {"error": "not_found"})

        client, opener = make_client(handler)
        client.issue_credential()
        client.report_event("tool.allowed", outcome="ok", action="tool:read",
                            metadata={"tool": "read", "secret_token": "agp1.leak.sig",
                                      "latency_ms": 5})
        client.flush_events()
        sent = json.loads([c for c in opener.calls
                           if c["url"].endswith("/v1/security/events")][0]["data"])
        meta = sent["events"][0]["metadata"]
        self.assertIn("tool", meta)
        self.assertNotIn("secret_token", meta)          # unknown key dropped
        self.assertNotIn("agp1.leak", json.dumps(sent))

    def test_flush_failure_keeps_events_buffered(self):
        def handler(req):
            if req.full_url.endswith("/v1/credentials/issue"):
                return FakeResponse(201, {"credential_id": "crd_1", "agent_id": "agt_test",
                                          "instance_id": "inst_test", "org_id": "acme",
                                          "expires_at": "2999-01-01T00:00:00Z", "token": "agp1.a.b"})
            return FakeResponse(500, {"error": "server_error"})

        client, _ = make_client(handler)
        client.issue_credential()
        client.report_event("x")
        self.assertEqual(client.flush_events(), 0)
        self.assertEqual(client.events.pending(), 1)     # not lost


# --------------------------------------------------------------------------- models
class ModelTests(unittest.TestCase):
    def test_credential_expiry_parsing(self):
        c = Credential("c", "a", "i", "o", expires_at="2026-01-01T00:15:00Z")
        self.assertIsNotNone(c.expires_at_epoch)
        self.assertFalse(c.is_expired(now=c.expires_at_epoch - 10))
        self.assertTrue(c.is_expired(now=c.expires_at_epoch + 1))

    def test_decision_from_dict(self):
        d = Decision.from_dict({"allowed": True, "reason": "ok", "policy": "p1"})
        self.assertTrue(d.allowed)
        self.assertEqual(d.policy, "p1")

    def test_decision_deny_helper(self):
        d = Decision.deny("nope")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "nope")


if __name__ == "__main__":
    unittest.main()
