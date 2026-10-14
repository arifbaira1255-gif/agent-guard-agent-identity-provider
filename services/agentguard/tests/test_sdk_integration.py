"""Step 9 Python SDK INTEGRATION tests against a REAL AgentGuard control plane.

Skipped unless AGENTGUARD_TEST_PG_HOST and AGENTGUARD_TEST_REDIS_HOST are set. A throwaway
PostgreSQL database and a unique Redis key prefix are used, so a shared dev instance is safe.

The test starts the real HTTP transport (``agent_identity.api.http_transport``) backed by real
PostgreSQL persistence + real Redis distributed state, then drives it with the Python SDK over
loopback HTTP. It exercises the full agent lifecycle end to end: register -> instance -> credential
-> verify -> authorize (allow/deny) -> tool guard -> security events, plus negative security cases
(tampered credential, missing proof, revoked credential, expired credential).

  AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=... AGENTGUARD_TEST_PG_PASSWORD=... \
  AGENTGUARD_TEST_REDIS_HOST=127.0.0.1 PYTHONPATH=src:. python -m unittest -v tests.test_sdk_integration
"""
import os
import secrets
import socket
import threading
import unittest

from cryptography.fernet import Fernet

from agent_identity import IdentityConfig, IdentityService
from agent_identity.api import http_transport
from agent_identity.core.clock import FixedClock
from agent_identity.observability.logging import SecurityLogger
from agent_identity.state import RedisConfig
from agent_identity.state.factory import build_security_state
from agent_identity.storage.postgres import PgConfig, build_postgres_storage
from agent_identity.storage.postgres import migrate
from agent_identity.storage.postgres.db import Database

from agentguard_sdk import AgentGuardClient, SdkConfig, StaticPdp
from agentguard_sdk.adapters import ToolGuard, ToolGuardError

PG_HOST = os.environ.get("AGENTGUARD_TEST_PG_HOST", "")
PG_PORT = int(os.environ.get("AGENTGUARD_TEST_PG_PORT", "5432"))
PG_USER = os.environ.get("AGENTGUARD_TEST_PG_USER", "")
PG_PW = os.environ.get("AGENTGUARD_TEST_PG_PASSWORD", "")
R_HOST = os.environ.get("AGENTGUARD_TEST_REDIS_HOST", "")
R_PORT = int(os.environ.get("AGENTGUARD_TEST_REDIS_PORT", "6379"))
R_PW = os.environ.get("AGENTGUARD_TEST_REDIS_PASSWORD", "")

ADMIN_TOKEN = "test-admin-token-" + secrets.token_hex(8)


def _admin():
    import psycopg
    return psycopg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PW, dbname="postgres",
                           autocommit=True)


def _pgcfg(dbname):
    return PgConfig(environment="development", host=PG_HOST, port=PG_PORT, dbname=dbname, user=PG_USER,
                    password=PG_PW, sslmode=os.environ.get("AGENTGUARD_TEST_PG_SSLMODE", "disable"),
                    retry_initial_backoff_seconds=0.01, pool_min_size=1, pool_max_size=8).validate()


def _rcfg(prefix):
    return RedisConfig(environment="development", host=R_HOST, port=R_PORT, password=R_PW,
                       tls=False, key_prefix=prefix, retry_base_backoff_seconds=0.01,
                       command_timeout_seconds=1.0, connect_timeout_seconds=2.0).validate()


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@unittest.skipUnless(PG_HOST and PG_USER and R_HOST,
                     "set AGENTGUARD_TEST_PG_HOST/USER/PASSWORD and AGENTGUARD_TEST_REDIS_HOST")
class SdkIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dbname = "ag_sdk_" + secrets.token_hex(6)
        with _admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')
        cls.master = Fernet.generate_key()
        cls.cfg = _pgcfg(cls.dbname)
        db = Database(cls.cfg)
        migrate.migrate(db)
        db.close()
        cls.st = build_postgres_storage(cls.cfg, cls.master)
        cls.state = build_security_state(_rcfg("agsdk" + secrets.token_hex(4)))
        cls.svc = IdentityService(IdentityConfig(log_to_python_logging=False),
                                  clock=FixedClock(), logger=SecurityLogger(use_python_logging=False),
                                  **cls.state.service_kwargs(cls.st))
        cls.svc.register_organization("acme", "Acme Corp")
        cls.port = _free_port()
        cls.server = http_transport.make_server(cls.svc, ADMIN_TOKEN, host="127.0.0.1", port=cls.port)
        cls.thread = threading.Thread(
            target=http_transport.serve_forever, args=(cls.server,),
            kwargs={"install_signal_handlers": False}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.server.shutdown()
            cls.server.server_close()
        except Exception:
            pass
        try:
            cls.state.close()
        except Exception:
            pass
        try:
            cls.st.close()
        except Exception:
            pass
        with _admin() as a:
            a.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}" WITH (FORCE)')

    # ------------------------------------------------------------------ helpers
    def _client(self, *, pdp=None, capabilities=("tool:read",)):
        cfg = SdkConfig(base_url=f"http://127.0.0.1:{self.port}", environment="development",
                        control_plane_token=ADMIN_TOKEN, max_retries=2, retry_base_seconds=0.01)
        # align the SDK clock with the server's injected clock so possession proofs are fresh
        client = AgentGuardClient(cfg, clock=lambda: self.svc.clock.now())
        ident = client.register_agent(org_id="acme", agent_name="sdk-bot-" + secrets.token_hex(3),
                                      agent_type="support", owner="ops@acme.com",
                                      capabilities=list(capabilities), environment="production")
        inst = client.create_instance()
        client.bind(agent_id=ident.agent_id, instance_id=inst["instance_id"])
        if pdp is not None:
            client.authorization.pdp = pdp
        return client

    # ------------------------------------------------------------------ lifecycle
    def test_full_agent_lifecycle_over_real_server(self):
        client = self._client()
        cred = client.issue_credential()
        self.assertTrue(cred.credential_id)
        self.assertTrue(cred.token)
        # the credential verifies against the real server
        res = client.verify_credential(cred.token, client.authenticator.make_proof(cred))
        self.assertTrue(res.valid, res.reason)
        self.assertEqual(res.org_id, "acme")
        # status is authoritative
        self.assertEqual(client.credential_status(cred.credential_id)["status"], "active")

    def test_authorize_allow_and_deny_against_real_server(self):
        client = self._client(capabilities=("tool:read",))
        client.issue_credential()
        allow = client.authorize(action="tool:read", resource="db:customers")
        self.assertTrue(allow.allowed, allow.reason)
        deny = client.authorize(action="tool:delete", resource="db:customers")
        self.assertFalse(deny.allowed)
        self.assertEqual(deny.reason, "no_matching_capability")

    def test_wildcard_capability(self):
        # capabilities are exact-match (the core capability charset forbids '*'); a different
        # capability must NOT authorize the action.
        client = self._client(capabilities=("tool:read",))
        client.issue_credential()
        self.assertTrue(client.authorize(action="tool:read", resource="x").allowed)
        self.assertFalse(client.authorize(action="tool:write", resource="x").allowed)

    def test_tool_guard_blocks_unauthorized_tool(self):
        client = self._client(capabilities=("tool:read",))
        client.issue_credential()
        guard = ToolGuard(client)
        ran = {"v": False}

        def dangerous():
            ran["v"] = True
            return "leaked"

        with self.assertRaises(ToolGuardError):
            guard.execute("delete_everything", dangerous)
        self.assertFalse(ran["v"])
        # the allowed tool runs
        self.assertEqual(guard.execute("read", lambda: "ok"), "ok")

    def test_security_events_are_accepted(self):
        client = self._client()
        client.issue_credential()
        client.report_event("tool.allowed", outcome="ok", action="tool:read",
                            metadata={"tool": "read", "latency_ms": 3})
        self.assertEqual(client.flush_events(), 1)

    # ------------------------------------------------------------------ negative security
    def test_tampered_credential_is_denied(self):
        client = self._client()
        cred = client.issue_credential()
        head, body, sig = cred.token.split(".")
        tampered = f"{head}.{body}.{'A' * len(sig)}"
        decision = client.authorize(action="tool:read", resource="db")
        # sanity: the real credential is allowed
        self.assertTrue(decision.allowed)
        # a tampered token must be denied by the server
        res = client.verify_credential(tampered, client.authenticator.make_proof(cred))
        self.assertFalse(res.valid)

    def test_missing_proof_is_denied(self):
        client = self._client()
        cred = client.issue_credential()
        res = client.verify_credential(cred.token, None)     # no possession proof
        self.assertFalse(res.valid)

    def test_revoked_credential_is_denied(self):
        client = self._client()
        cred = client.issue_credential()
        client.revoke_credential(cred.credential_id, reason="administrative_action")
        res = client.verify_credential(cred.token, client.authenticator.make_proof(cred))
        self.assertFalse(res.valid)
        self.assertEqual(client.credential_status(cred.credential_id)["status"], "revoked")

    def test_expired_credential_is_denied(self):
        # issue a very short-lived credential, then advance the server clock past its expiry
        client = self._client()
        cred = client.issue_credential(ttl_seconds=60)
        self.assertTrue(client.verify_credential(cred.token,
                                                 client.authenticator.make_proof(cred)).valid)
        self.svc.clock.advance(120)                          # server-side clock moves forward
        try:
            res = client.verify_credential(cred.token, client.authenticator.make_proof(cred))
            self.assertFalse(res.valid)
        finally:
            self.svc.clock.advance(-120)

    def test_authorize_without_credential_is_denied(self):
        # a client that never obtained a credential cannot get an ALLOW
        cfg = SdkConfig(base_url=f"http://127.0.0.1:{self.port}", environment="development",
                        control_plane_token=ADMIN_TOKEN)
        client = AgentGuardClient(cfg, agent_id="agt_missing", instance_id="inst_missing")
        client.authorization.pdp = StaticPdp(["tool:read"])   # even a permissive PDP...
        # ...cannot help: the SDK must still authenticate first, and issuance fails for a bogus agent
        from agentguard_sdk import NotFoundError
        with self.assertRaises(NotFoundError):
            client.issue_credential()

    def test_unknown_route_is_not_exposed(self):
        from agentguard_sdk import AuthenticationError, NotFoundError
        client = self._client()
        # an internal/unknown path is never served: it falls through to the admin-token gate and is
        # refused (401) rather than exposing an internal administration endpoint.
        with self.assertRaises((NotFoundError, AuthenticationError)):
            client._request("GET", "/v1/internal/secret-admin")


if __name__ == "__main__":
    unittest.main()
