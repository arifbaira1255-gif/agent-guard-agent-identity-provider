"""REAL SPIRE mTLS integration test (real SPIRE server + agent + gRPC Workload API; NOT mocked).

Skipped unless AGENTGUARD_SPIRE_INTEGRATION=1 and AGENTGUARD_SPIRE_SOCKET are set (run via
integration/spire/run.sh on a Docker host). It was NOT executed in the environment that produced
this change (no Docker, no SPIRE binaries, no grpcio there): treat it as unverified until run.
Both services run in this one process and are attested by uid; two registration entries give the
workload two SPIFFE IDs, and each MtlsEndpoint selects its own via MtlsConfig.workload_spiffe_id.
"""
import os
import socket
import threading
import time
import unittest

from agent_identity import IdentityConfig, IdentityService
from agent_identity.mtls import (MtlsConfig, MtlsEndpoint, MtlsError, MtlsServer, PolicyHolder,
                                 TrustPolicy)
from agent_identity.mtls.policy import PeerRules
from agent_identity.observability.logging import SecurityLogger
from agent_identity.spiffe.config import Environment, SpireConfig
from agent_identity.spiffe.errors import SpiffeError
from agent_identity.spiffe.factory import build_identity_provider
from tests.test_spire_integration import COMPOSE, ON, SOCK, TD, _register

SRV = f"spiffe://{TD}/service/mtls-server"
CLI = f"spiffe://{TD}/service/mtls-client"


def _node(svc, sid, pol):
    cfg = SpireConfig(environment=Environment.STAGING, provider="spire", trust_domain=TD, socket_path=SOCK,
                      retry_initial_backoff_seconds=0.5, retry_max_attempts=10,
                      rotation_min_remaining_seconds=30).validate()
    prov = build_identity_provider(svc, cfg)
    holder = PolicyHolder(prov.clock)
    holder.set(pol)
    mc = MtlsConfig(environment="staging", workload_spiffe_id=sid, listen_port=8443).validate()
    return MtlsEndpoint(mc, prov, holder, logger=svc.log)


@unittest.skipUnless(ON and SOCK, "set AGENTGUARD_SPIRE_INTEGRATION=1 (see integration/spire/run.sh)")
class RealSpireMtls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.svc = IdentityService(IdentityConfig(trust_domain=TD, log_to_python_logging=False),
                                  logger=SecurityLogger(use_python_logging=False))
        uid = os.getuid()
        _register(SRV, uid)
        _register(CLI, uid)
        cls.srv_ep = _node(cls.svc, SRV, TrustPolicy(1, (TD,), PeerRules((CLI,)), PeerRules()))
        cls.cli_ep = _node(cls.svc, CLI, TrustPolicy(1, (TD,), PeerRules(), PeerRules((SRV,))))
        deadline = time.time() + 60                       # SPIRE agent syncs new entries after a delay
        while True:
            try:
                cls.srv_ep.contexts.snapshot()
                cls.cli_ep.contexts.snapshot()
                break
            except MtlsError:
                if time.time() > deadline:
                    raise
                time.sleep(2)

    def _server(self):
        seen = []

        def handler(tls, peer):
            seen.append(peer)
            tls.sendall(b"pong:" + tls.recv(16))
        s = MtlsServer(self.srv_ep, handler, port=0).start()
        s.seen = seen
        return s

    def test_01_real_mutual_authentication(self):
        s = self._server()
        try:
            tls, peer = self.cli_ep.connect(*s.address, expected_spiffe_id=SRV)
            tls.sendall(b"x")
            self.assertEqual(tls.recv(16), b"pong:x")
            tls.close()
            self.assertEqual(peer.spiffe_id, SRV)
            self.assertEqual([p.spiffe_id for p in s.seen], [CLI])
        finally:
            s.shutdown()

    def test_02_wrong_expected_identity_rejected(self):
        s = self._server()
        try:
            with self.assertRaises(MtlsError):
                self.cli_ep.connect(*s.address, expected_spiffe_id=CLI)     # server is SRV
        finally:
            s.shutdown()

    def test_03_unregistered_service_cannot_obtain_identity(self):
        ep = _node(self.svc, f"spiffe://{TD}/service/not-registered",
                   TrustPolicy(1, (TD,), PeerRules(), PeerRules((SRV,))))
        with self.assertRaises(MtlsError):
            ep.contexts.snapshot()

    def test_04_plaintext_client_gets_nothing(self):
        s = self._server()
        try:
            raw = socket.create_connection(s.address, timeout=3)
            raw.sendall(b"hello")
            try:
                self.assertNotEqual(raw.recv(16)[:5], b"pong:")
            except OSError:
                pass
            raw.close()
            self.assertEqual(s.seen, [])
        finally:
            s.shutdown()

    def test_05_real_certificate_rotation_keeps_new_connections_working(self):
        """SVID TTL is 90s (see _register): rotation must occur and connections keep working."""
        first = self.cli_ep.contexts.snapshot().serial
        s = self._server()
        try:
            deadline = time.time() + 110
            while time.time() < deadline:
                self.cli_ep.refresh_once()
                self.srv_ep.refresh_once()
                if self.cli_ep.contexts.snapshot().serial != first:
                    tls, peer = self.cli_ep.connect(*s.address, expected_spiffe_id=SRV)
                    tls.close()
                    self.assertEqual(peer.spiffe_id, SRV)
                    return
                time.sleep(3)
            self.fail("no SVID rotation observed within 110s")
        finally:
            s.shutdown()


if __name__ == "__main__":
    unittest.main()
