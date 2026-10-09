"""REAL SPIRE integration test (real server + agent + gRPC Workload API). Not mocked.
Skipped unless AGENTGUARD_SPIRE_INTEGRATION=1; run via integration/spire/run.sh on a Docker host.
The test process is attested by uid (unix:uid selector), so entries are registered for os.getuid()."""
import os
import subprocess
import unittest

from agent_identity import IdentityConfig, IdentityService
from agent_identity.observability.logging import SecurityLogger
from agent_identity.spiffe.config import Environment, SpireConfig
from agent_identity.spiffe.errors import SpiffeError, WorkloadApiUnavailable
from agent_identity.spiffe.factory import build_identity_provider
from agent_identity.spiffe.ids import agent_spiffe_id

TD = "agentguard-it.internal"
ON = os.environ.get("AGENTGUARD_SPIRE_INTEGRATION") == "1"
SOCK = os.environ.get("AGENTGUARD_SPIRE_SOCKET", "")
COMPOSE = os.environ.get("AGENTGUARD_SPIRE_COMPOSE_DIR", "")


def _spire_server(*args):
    cmd = ["docker", "compose", "exec", "-T", "spire-server", "/opt/spire/bin/spire-server", *args]
    return subprocess.run(cmd, cwd=COMPOSE, check=True, capture_output=True, text=True, timeout=60).stdout


def _register(spiffe_id, uid):
    _spire_server("entry", "create", "-parentID", f"spiffe://{TD}/test-agent", "-spiffeID", spiffe_id,
                  "-selector", f"unix:uid:{uid}", "-x509SVIDTTL", "90", "-jwtSVIDTTL", "90")


@unittest.skipUnless(ON and SOCK, "set AGENTGUARD_SPIRE_INTEGRATION=1 (see integration/spire/run.sh)")
class RealSpire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.svc = IdentityService(IdentityConfig(trust_domain=TD, log_to_python_logging=False),
                                  logger=SecurityLogger(use_python_logging=False))
        cls.svc.register_organization("acme", "Acme")
        a = cls.svc.register_agent("acme", "it-bot", "t", "o@x.com", "", ["agent:spawn"], "production", {})
        cls.a_id = a["agent_id"]
        cls.i_id = cls.svc.create_agent_instance(cls.a_id)["instance_id"]
        cls.sid_agent = agent_spiffe_id(TD, "acme", cls.a_id)
        cls.sid_inst = agent_spiffe_id(TD, "acme", cls.a_id, cls.i_id)
        uid = os.getuid()
        _register(cls.sid_agent, uid)
        _register(cls.sid_inst, uid)
        cls.cfg = SpireConfig(environment=Environment.STAGING, provider="spire", trust_domain=TD,
                              socket_path=SOCK, retry_initial_backoff_seconds=0.5, retry_max_attempts=10,
                              rotation_min_remaining_seconds=30).validate()
        cls.p = build_identity_provider(cls.svc, cls.cfg)
        cls.p.bind_agent(cls.a_id)
        cls.p.bind_instance(cls.a_id, cls.i_id)

    @classmethod
    def tearDownClass(cls):
        cls.p.client.close()

    def test_01_fetch_x509_svid_and_verify_against_real_bundle(self):
        svid = self.p.client.fetch_x509_svid(self.sid_inst)
        self.assertEqual(str(svid.spiffe_id), self.sid_inst)
        r = self.p.verify_x509(svid.chain_der())
        self.assertTrue(r.valid, r.reason)
        self.assertEqual((r.agent_id, r.instance_id), (self.a_id, self.i_id))

    def test_02_issue_with_jwt_svid_roundtrip(self):
        ident = self.p.issue(self.a_id, self.i_id, audience="gateway")
        r = self.p.verify(ident.jwt_svid.token, audience="gateway")
        self.assertTrue(r.valid, r.reason)

    def test_03_wrong_audience_denied(self):
        ident = self.p.issue(self.a_id, self.i_id, audience="gateway")
        self.assertFalse(self.p.verify(ident.jwt_svid.token, audience="other-service").valid)

    def test_04_unregistered_identity_cannot_be_obtained(self):
        other = agent_spiffe_id(TD, "acme", self.a_id, "i-not-registered")
        with self.assertRaises(SpiffeError):
            self.p.client.fetch_x509_svid(other)

    def test_05_trust_bundle_loaded_for_own_domain_only(self):
        self.p.refresh_bundles()
        self.assertTrue(self.p.bundles.has_fresh(TD))
        self.assertFalse(self.p.bundles.is_allowed("evil.example.net"))

    def test_06_real_rotation_before_expiry(self):
        """SVID TTL is 90s; the source must hand out a NEW certificate before the old one expires."""
        src = self.p.x509_source(self.sid_inst)
        first = src.current()
        import time
        deadline = time.time() + 100
        while time.time() < deadline:
            cur = src.current()
            if cur.leaf.serial_number != first.leaf.serial_number:
                self.assertLess(time.time(), first.not_after)      # rotated before expiry
                return
            time.sleep(3)
        self.fail("no rotation observed within 100s")

    def test_99_unavailable_workload_api_fails_closed(self):
        cfg = SpireConfig(environment=Environment.STAGING, provider="spire", trust_domain=TD,
                          socket_path="unix:///nonexistent/agent.sock", retry_max_attempts=2,
                          retry_initial_backoff_seconds=0.0, rpc_timeout_seconds=2).validate()
        p = build_identity_provider(self.svc, cfg)
        with self.assertRaises(WorkloadApiUnavailable):
            p.client.fetch_x509_svid(self.sid_inst)


if __name__ == "__main__":
    unittest.main()
