"""Step 6 tests. Everything here uses the MOCKED SPIRE (DevSpireCA / DevWorkloadTransport) with real
X.509 certificates, real OpenSSL TLS and real TCP sockets. It is NOT a real SPIRE deployment."""
import json
import os
import socket
import ssl
import threading
import time
import unittest
from unittest import mock

from cryptography.x509.oid import ExtendedKeyUsageOID

from agent_identity import RevocationReason
from agent_identity.api import http_transport
from agent_identity.core.clock import FixedClock
from agent_identity.kms import KmsConfig, build_kms
from agent_identity.kms.errors import KmsUnavailableError
from agent_identity.kms.models import KmsKeyUsage
from agent_identity.mtls import (CertDenylist, HealthServer, M, MtlsConfig, MtlsConfigError, MtlsError,
                                 MtlsServer, PeerRejected, PlaintextForbidden, PolicyHolder,
                                 SAFE_TLS12_CIPHERS, TrustPolicy, load_signed_policy, sign_policy)
from agent_identity.mtls import metrics as MM
from agent_identity.mtls.policy import PeerRules
from agent_identity.spiffe import tlsutil
from agent_identity.spiffe.dev import DevSpireCA
from agent_identity.spiffe.ids import SpiffeId, agent_spiffe_id, parse_spiffe_id
from agent_identity.spiffe.x509svid import parse_x509_svid
from tests.mtls_env import (CLI, OTHER, SRV, Node, echo_server, fast_env, issue_leaf, mtls_cfg, now_clock,
                            policy)
from tests.spiffe_env import TD, Env as SpiffeEnv


def pair(inbound=(CLI,), outbound=(SRV,), srv_kw=None, cli_kw=None, env=None):
    env = env or SpiffeEnv(clock_start=time.time())
    server = Node(env, SRV, policy(inbound=inbound), **(srv_kw or {}))
    client = Node(env, CLI, policy(outbound=outbound), **(cli_kw or {}))
    return env, server, client


def talk(client, srv, expect=SRV, payload=b"hi"):
    """Connect + one round trip. In TLS 1.3 the client's handshake completes BEFORE the server has
    authenticated the client, so a server-side rejection shows up as EOF/alert on the first read.
    Either way the caller sees MtlsError and the server handler never runs."""
    tls, peer = client.ep.connect(*srv.address, expected_spiffe_id=expect)
    try:
        tls.sendall(payload)
        reply = tls.recv(64)
    except (ssl.SSLError, OSError):
        reply = b""
    finally:
        tls.close()
    if not reply:
        raise MtlsError("closed by peer", "connection_closed")
    return peer, reply


class ValidMutualAuth(unittest.TestCase):
    def test_both_peers_authenticate_each_other(self):
        env, s, c = pair()
        srv = echo_server(s)
        try:
            peer, reply = talk(c, srv)
        finally:
            srv.shutdown()
        self.assertEqual(reply, b"echo:hi")
        self.assertEqual(peer.spiffe_id, SRV)                       # client authenticated the server
        self.assertEqual([p.spiffe_id for p in srv.seen], [CLI])     # server authenticated the client
        self.assertFalse(peer.is_agent)
        self.assertEqual(c.ep.metrics.get(MM.HANDSHAKES, "outbound"), 1)
        self.assertEqual(s.ep.metrics.get(MM.HANDSHAKES, "inbound"), 1)

    def test_negotiates_tls13_by_default(self):
        env, s, c = pair()
        srv = echo_server(s)
        try:
            tls, _ = c.ep.connect(*srv.address, expected_spiffe_id=SRV)
            self.assertEqual(tls.version(), "TLSv1.3")
            tls.close()
        finally:
            srv.shutdown()

    def test_agent_identity_peer_is_registry_checked(self):
        env = SpiffeEnv(clock_start=time.time())
        s = Node(env, SRV, policy(inbound=(), allow_agents=True))
        c = Node(env, env.sid_inst, policy(outbound=(SRV,)))
        srv = echo_server(s)
        try:
            talk(c, srv)
        finally:
            srv.shutdown()
        p = srv.seen[0]
        self.assertTrue(p.is_agent)
        self.assertEqual((p.agent_id, p.instance_id, p.org_id), (env.a_id, env.i_id, "acme"))

    def test_revoked_agent_instance_is_rejected_at_connect_time(self):
        env = SpiffeEnv(clock_start=time.time())
        s = Node(env, SRV, policy(allow_agents=True))
        c = Node(env, env.sid_inst, policy(outbound=(SRV,)))
        srv = echo_server(s)
        try:
            env.svc.revoke_instance(env.i_id, RevocationReason.COMPROMISE, "sec")
            with self.assertRaises(MtlsError):
                talk(c, srv)                                        # server closes: client revoked
            self.assertEqual(s.ep.metrics.get(MM.PEER_REJECTED, M.PEER_INACTIVE), 1)
            self.assertEqual(srv.seen, [])
        finally:
            srv.shutdown()

    def test_agent_not_in_policy_is_rejected_even_though_registered(self):
        env = SpiffeEnv(clock_start=time.time())
        s = Node(env, SRV, policy(inbound=(CLI,), allow_agents=False))
        c = Node(env, env.sid_inst, policy(outbound=(SRV,)))
        srv = echo_server(s)
        try:
            with self.assertRaises(MtlsError):
                talk(c, srv)
            self.assertEqual(s.ep.metrics.get(MM.PEER_REJECTED, M.PEER_NOT_ALLOWED), 1)
        finally:
            srv.shutdown()


class IdentityRejection(unittest.TestCase):
    def _expect_reject(self, c, s, reason, expect=SRV, side="client"):
        srv = echo_server(s)
        try:
            with self.assertRaises(MtlsError) as cm:
                talk(c, srv, expect=expect)
        finally:
            srv.shutdown()
        return cm.exception

    def test_wrong_service_identity_pinned_by_client(self):
        env, s, c = pair(outbound=(SRV, OTHER))
        e = self._expect_reject(c, s, M.PEER_MISMATCH, expect=OTHER)     # server is SRV, we wanted OTHER
        self.assertEqual(e.reason, M.PEER_MISMATCH)
        self.assertEqual(c.ep.metrics.get(MM.PEER_REJECTED, M.PEER_MISMATCH), 1)

    def test_client_must_pin_an_identity(self):
        env, s, c = pair()
        with self.assertRaises(MtlsError) as cm:
            c.ep.connect("127.0.0.1", 1, expected_spiffe_id="")
        self.assertEqual(cm.exception.reason, M.PEER_MISMATCH)

    def test_pin_outside_outbound_policy_is_denied(self):
        env, s, c = pair(outbound=(OTHER,))                  # policy forbids talking to SRV
        e = self._expect_reject(c, s, M.PEER_NOT_ALLOWED)
        self.assertEqual(e.reason, M.PEER_NOT_ALLOWED)

    def test_server_denies_client_not_in_inbound_policy(self):
        env, s, c = pair(inbound=(OTHER,))
        srv = echo_server(s)
        try:
            with self.assertRaises(MtlsError):
                talk(c, srv)
            self.assertEqual(s.ep.metrics.get(MM.PEER_REJECTED, M.PEER_NOT_ALLOWED), 1)
        finally:
            srv.shutdown()

    def test_empty_policy_trusts_nobody(self):
        env, s, c = pair(inbound=())
        srv = echo_server(s)
        try:
            with self.assertRaises(MtlsError):
                talk(c, srv)
        finally:
            srv.shutdown()

    def test_explicit_deny_beats_allow(self):
        env = SpiffeEnv(clock_start=time.time())
        s = Node(env, SRV, policy(inbound=(CLI,), denied=(CLI,)))
        c = Node(env, CLI, policy(outbound=(SRV,)))
        srv = echo_server(s)
        try:
            with self.assertRaises(MtlsError):
                talk(c, srv)
        finally:
            srv.shutdown()

    def test_untrusted_ca_client_rejected_by_server(self):
        env = SpiffeEnv(clock_start=time.time())
        s = Node(env, SRV, policy(inbound=(CLI,)))
        evil = DevSpireCA(TD, env.clock, name="evil")
        c = Node(env, CLI, policy(outbound=(SRV,)), ca=evil)
        # evil node trusts the real roots for verifying the server, but presents an evil-CA cert
        c.provider.bundles.update(TD, x509_der=env.ca.bundle_der())
        srv = echo_server(s)
        try:
            with self.assertRaises(MtlsError):
                talk(c, srv)
            time.sleep(0.1)
            self.assertGreaterEqual(s.ep.metrics.total(MM.HANDSHAKE_FAIL) + s.ep.metrics.total(MM.PEER_REJECTED), 1)
        finally:
            srv.shutdown()

    def test_untrusted_ca_server_rejected_by_client(self):
        env = SpiffeEnv(clock_start=time.time())
        evil = DevSpireCA(TD, env.clock, name="evil")
        s = Node(env, SRV, policy(inbound=(CLI,)), ca=evil)
        c = Node(env, CLI, policy(outbound=(SRV,)))
        srv = echo_server(s)
        try:
            with self.assertRaises(MtlsError) as cm:
                talk(c, srv)
            self.assertIn(cm.exception.reason, (M.PEER_CHAIN, M.HANDSHAKE))
        finally:
            srv.shutdown()

    def test_foreign_trust_domain_not_accepted_by_policy(self):
        env = SpiffeEnv(clock_start=time.time())
        s = Node(env, SRV, policy(inbound=(CLI,)))
        # same CA mints an ID in ANOTHER trust domain; bundles/policy only know TD
        foreign = "spiffe://other.example.net/service/gateway"
        c = Node(env, CLI, policy(outbound=(SRV,)))
        chain, kd = env.ca.issue_x509(foreign)
        from agent_identity.mtls.authenticator import PeerAuthenticator
        with self.assertRaises(PeerRejected) as cm:
            s.ep.auth.authenticate([chain[:len(chain)]] if False else
                                   __import__("agent_identity.spiffe.bundle", fromlist=["split_der"]).split_der(chain),
                                   direction="inbound")
        self.assertEqual(cm.exception.reason, M.PEER_DOMAIN)

    def test_policy_accepted_domains_exclude_peer_domain(self):
        env, s, c = pair()
        s.policies.set(policy(version=2, inbound=(CLI,), domains=("another.example.net",)))
        srv = echo_server(s)
        try:
            with self.assertRaises(MtlsError):
                talk(c, srv)
            self.assertEqual(s.ep.metrics.get(MM.PEER_REJECTED, M.PEER_DOMAIN), 1)
        finally:
            srv.shutdown()

    def test_revoked_certificate_denylist(self):
        env, s, c = pair()
        srv = echo_server(s)
        try:
            talk(c, srv)
            svid = c.provider.x509_source(CLI).current()
            s.ep.auth.denylist.deny(svid.chain_der()[0], until=env.clock.now() + 600)
            with self.assertRaises(MtlsError):
                talk(c, srv)
            self.assertEqual(s.ep.metrics.get(MM.PEER_REJECTED, M.PEER_REVOKED), 1)
        finally:
            srv.shutdown()


class Authenticator(unittest.TestCase):
    def setUp(self):
        self.env, self.s, self.c = pair()
        self.auth = self.s.ep.auth

    def chain(self, **kw):
        from agent_identity.spiffe.bundle import split_der
        return split_der(issue_leaf(self.env.ca, kw.pop("sid", CLI), **kw)[0])

    def test_valid(self):
        p = self.auth.authenticate(self.chain(), direction="inbound")
        self.assertEqual(p.spiffe_id, CLI)

    def test_malformed_and_empty_chain(self):
        with self.assertRaises(PeerRejected) as cm:
            self.auth.authenticate([], direction="inbound")
        self.assertEqual(cm.exception.reason, M.NO_PEER_CERT)
        for bad in ([b"garbage"], [b"\x30\x03abc"], [self.chain()[0][:-9]], [b""]):
            with self.assertRaises(PeerRejected) as cm:
                self.auth.authenticate(bad, direction="inbound")
            self.assertEqual(cm.exception.reason, M.PEER_CHAIN)

    def test_expired_certificate_rejected(self):
        ch = self.chain(ttl=300)
        self.env.clock.advance(400)
        with self.assertRaises(PeerRejected) as cm:
            self.auth.authenticate(ch, direction="inbound")
        self.assertEqual(cm.exception.reason, M.PEER_CHAIN)

    def test_certificate_not_yet_valid_rejected(self):
        ch = self.chain(not_before=self.env.clock.now() + 7200)
        with self.assertRaises(PeerRejected):
            self.auth.authenticate(ch, direction="inbound")

    def test_purpose_enforced(self):
        server_only = self.chain(eku=(ExtendedKeyUsageOID.SERVER_AUTH,))
        with self.assertRaises(PeerRejected) as cm:                 # a server-only cert cannot be a client
            self.auth.authenticate(server_only, direction="inbound")
        # (the underlying RFC 5280 client-path validator also rejects it as a chain; either way DENY)
        self.assertIn(cm.exception.reason, (M.PEER_PURPOSE, M.PEER_CHAIN))
        client_only = self.chain(sid=SRV, eku=(ExtendedKeyUsageOID.CLIENT_AUTH,))
        with self.assertRaises(PeerRejected) as cm:
            self.c.ep.auth.authenticate(client_only, direction="outbound", expected_spiffe_id=SRV)
        self.assertEqual(cm.exception.reason, M.PEER_PURPOSE)
        for eku in (None, (ExtendedKeyUsageOID.CODE_SIGNING,)):
            with self.assertRaises(PeerRejected) as cm:
                self.auth.authenticate(self.chain(eku=eku), direction="inbound")
            self.assertIn(cm.exception.reason, (M.PEER_PURPOSE, M.PEER_CHAIN))

    def test_any_eku_is_not_a_substitute_when_required(self):
        ch = self.chain(eku=(ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,))
        with self.assertRaises(PeerRejected) as cm:
            self.auth.authenticate(ch, direction="inbound")
        self.assertIn(cm.exception.reason, (M.PEER_PURPOSE, M.PEER_CHAIN))

    def test_missing_eku_allowed_only_when_not_required_in_development(self):
        env, s, c = pair(srv_kw={"require_eku": False})
        from agent_identity.spiffe.bundle import split_der
        ch = split_der(issue_leaf(env.ca, CLI, eku=None)[0])
        self.assertEqual(s.ep.auth.authenticate(ch, direction="inbound").spiffe_id, CLI)

    def test_no_policy_denies(self):
        node = Node(self.env, SRV, policy(inbound=(CLI,)))
        node.policies = PolicyHolder(self.env.clock)
        node.ep.auth.policies = node.policies
        with self.assertRaises(PeerRejected) as cm:
            node.ep.auth.authenticate(self.chain(), direction="inbound")
        self.assertEqual(cm.exception.reason, M.POLICY)

    def test_unexpected_internal_error_denies(self):
        self.s.ep.auth.provider = mock.Mock(side_effect=RuntimeError)
        with self.assertRaises(PeerRejected):
            self.auth.authenticate(self.chain(), direction="inbound")

    def test_stale_bundle_denies(self):
        ch = self.chain()
        self.env.clock.advance(self.s.sp_cfg.bundle_max_age_seconds + 10)
        with self.assertRaises(PeerRejected) as cm:
            self.auth.authenticate(ch, direction="inbound")
        self.assertEqual(cm.exception.reason, M.TRUST_UNAVAILABLE)


class PolicyMatching(unittest.TestCase):
    def test_segment_bounded_prefix(self):
        r = PeerRules(prefixes=(f"spiffe://{TD}/service/",))
        ok = parse_spiffe_id(f"spiffe://{TD}/service/api")
        self.assertTrue(r.matches(ok))
        for bad in (f"spiffe://{TD}/service-evil/api", f"spiffe://{TD}/servicefoo", f"spiffe://{TD}/service",
                    f"spiffe://{TD}.evil/service/api", f"spiffe://{TD}/other/service/api"):
            self.assertFalse(r.matches(parse_spiffe_id(bad)), bad)

    def test_invalid_rules_rejected(self):
        for kw in ({"prefixes": (f"spiffe://{TD}/service",)}, {"prefixes": ("spiffe://x/",)},
                   {"exact": ("http://x/y",)}, {"exact": (f"spiffe://{TD}",)},
                   {"exact": (f"spiffe://{TD}/a/../b",)}):
            with self.assertRaises(MtlsConfigError):
                PeerRules(**kw)

    def test_policy_validation_and_roundtrip(self):
        p = policy(inbound=(CLI,), outbound=(SRV,), allow_agents=True, denied=(OTHER,))
        self.assertEqual(TrustPolicy.from_dict(p.to_dict()), p)
        for bad in ({}, {"version": 0, "accepted_trust_domains": [TD]}, {"version": 1, "accepted_trust_domains": []},
                    {"version": 1, "accepted_trust_domains": [TD], "extra": 1},
                    {"version": True, "accepted_trust_domains": [TD]},
                    {"version": 1, "accepted_trust_domains": [TD], "inbound": {"allow_agents": "yes"}},
                    {"version": 1, "accepted_trust_domains": [f"{TD}/x"]}):
            with self.assertRaises(MtlsConfigError):
                TrustPolicy.from_dict(bad)

    def test_agent_rule_matches_only_canonical_agent_ids(self):
        r = PeerRules(allow_agents=True)
        a = agent_spiffe_id(TD, "acme", "agt_" + "A" * 22, "bot-instance-0123456789abcdef")
        self.assertTrue(r.matches(parse_spiffe_id(a)))
        self.assertFalse(r.matches(parse_spiffe_id(f"spiffe://{TD}/org/acme/agent/x/extra/y")))
        self.assertFalse(r.matches(parse_spiffe_id(f"spiffe://{TD}/service/api")))

    def test_holder_monotonic_expiry_and_empty(self):
        clk = FixedClock()
        h = PolicyHolder(clk)
        with self.assertRaises(MtlsError):
            h.current()
        h.set(policy(version=2))
        for v in (1, 2):
            with self.assertRaises(MtlsError) as cm:
                h.set(policy(version=v))
            self.assertEqual(cm.exception.reason, M.POLICY_ROLLBACK)
        h.set(policy(version=3, not_after=int(clk.now()) + 10))
        clk.advance(11)
        with self.assertRaises(MtlsError) as cm:
            h.current()
        self.assertEqual(cm.exception.reason, M.POLICY_EXPIRED)
        with self.assertRaises(MtlsError):
            h.set(policy(version=9, not_after=int(clk.now()) - 1))


class SignedPolicyWithKms(unittest.TestCase):
    def setUp(self):
        self.rt = build_kms(KmsConfig(environment="development", provider="local-dev"))
        self.rt.provider.create_key("mtls-policy", usages=(KmsKeyUsage.ISSUER_CERT_SIGNING,))
        self.pol = policy(version=5, inbound=(CLI,))

    def test_sign_and_load(self):
        b = sign_policy(self.rt.provider, "mtls-policy", self.pol, issued_at=1)
        got = load_signed_policy(b, [b["signer"]])
        self.assertEqual(got, self.pol)

    def test_tamper_wrong_signer_and_garbage_rejected(self):
        import base64
        b = sign_policy(self.rt.provider, "mtls-policy", self.pol, issued_at=1)
        body = json.loads(base64.urlsafe_b64decode(b["body"]))
        body["policy"]["inbound"]["exact"].append(OTHER)
        forged = dict(b, body=base64.urlsafe_b64encode(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).decode())
        with self.assertRaises(MtlsError) as cm:
            load_signed_policy(forged, [b["signer"]])
        self.assertEqual(cm.exception.reason, M.POLICY_SIGNATURE)
        with self.assertRaises(MtlsError) as cm:
            load_signed_policy(b, ["AAAA"])                       # signer not trusted
        self.assertEqual(cm.exception.reason, M.POLICY_SIGNATURE)
        for junk in ({}, {"body": "x", "signature": "y", "signer": "z"}, {"body": 1}):
            with self.assertRaises(MtlsError):
                load_signed_policy(junk, [b["signer"]])

    def test_rollback_blocked_by_holder(self):
        h = PolicyHolder(FixedClock())
        new = sign_policy(self.rt.provider, "mtls-policy", self.pol, issued_at=1)
        old = sign_policy(self.rt.provider, "mtls-policy", policy(version=4, inbound=(CLI, OTHER)), issued_at=1)
        h.set(load_signed_policy(new, [new["signer"]]))
        with self.assertRaises(MtlsError) as cm:
            h.set(load_signed_policy(old, [new["signer"]]))
        self.assertEqual(cm.exception.reason, M.POLICY_ROLLBACK)

    def test_kms_outage_fails_closed_without_exposing_key(self):
        prov = mock.Mock()
        prov.sign.side_effect = KmsUnavailableError("down")
        with self.assertRaises(MtlsError) as cm:
            sign_policy(prov, "mtls-policy", self.pol, issued_at=1)
        self.assertEqual(cm.exception.reason, M.KMS_UNAVAILABLE)

    def test_provider_never_exports_key_material_through_this_path(self):
        calls = []
        real = self.rt.provider

        class Spy:
            def __getattr__(self, n):
                calls.append(n)
                return getattr(real, n)
        b = sign_policy(Spy(), "mtls-policy", self.pol, issued_at=1)
        self.assertEqual(set(calls), {"sign", "public_key"})        # sign-only: no export_private_key
        self.assertEqual(set(b), {"body", "signature", "signer"})


class Rotation(unittest.TestCase):
    """REAL wall clock + 6s SVIDs (rotation at 50% = 3s): OpenSSL validates against real time, so a
    fake clock cannot be used to age certificates that OpenSSL itself checks."""

    def test_certificate_renewal_without_dropping_existing_connection(self):
        env = fast_env(6)
        s = Node(env, SRV, policy(inbound=(CLI,)))
        c = Node(env, CLI, policy(outbound=(SRV,)))

        def handler(tls, peer):
            for _ in range(2):
                tls.sendall(b"r:" + tls.recv(16))
        srv = MtlsServer(s.ep, handler, port=0).start()
        try:
            tls1, _ = c.ep.connect(*srv.address, expected_spiffe_id=SRV)
            tls1.sendall(b"one")
            self.assertEqual(tls1.recv(16), b"r:one")
            serial_old = c.ep.contexts.snapshot().serial
            time.sleep(3.3)                               # past the 50% rotation point
            c.ep.refresh_once()
            s.ep.refresh_once()
            self.assertNotEqual(serial_old, c.ep.contexts.snapshot().serial)
            self.assertGreaterEqual(c.ep.metrics.get(MM.CERT_ROTATIONS), 1)
            self.assertGreaterEqual(s.ep.metrics.get(MM.CERT_ROTATIONS), 1)
            tls1.sendall(b"two")                          # pre-rotation connection is unaffected
            self.assertEqual(tls1.recv(16), b"r:two")
            tls1.close()
            tls2, peer2 = c.ep.connect(*srv.address, expected_spiffe_id=SRV)
            self.assertEqual(peer2.spiffe_id, SRV)        # a NEW connection uses the NEW certificate
            tls2.close()
        finally:
            srv.shutdown()

    def test_context_cached_until_rotation(self):
        env = fast_env(6)
        s = Node(env, SRV, policy(inbound=(CLI,)))
        a = s.ep.contexts.server_context()
        self.assertIs(a, s.ep.contexts.server_context())
        time.sleep(3.3)
        self.assertIsNot(a, s.ep.contexts.server_context())

    def test_bundle_rotation_with_overlap_then_retirement(self):
        env, s, c = pair()
        srv = echo_server(s)
        try:
            talk(c, srv)
            env.ca.rotate_root(keep_old=True)          # new root added, old kept (overlap)
            s.ep.refresh_once()
            c.ep.refresh_once()
            self.assertEqual(talk(c, srv)[0].spiffe_id, SRV)
            self.assertGreaterEqual(c.ep.metrics.get(MM.BUNDLE_ROTATIONS), 1)
            old_only = Node(env, CLI, policy(outbound=(SRV,)))          # trusts only the ORIGINAL root
            old_only.ep.contexts.snapshot()                             # SVID obtained before retirement
            from cryptography.hazmat.primitives import serialization as ser
            old_only.provider.bundles.update(TD, x509_der=env.ca.roots[0].public_bytes(ser.Encoding.DER))
            env.ca.rotate_root(keep_old=False)         # retire every previous root
            s.ep.refresh_once()
            c.ep.refresh_once()
            with self.assertRaises(MtlsError):         # SVIDs still chain to the retired root: fail closed
                talk(c, srv)
            for n in (s, c):                           # SPIRE re-issues SVIDs under the new root
                n.provider.x509_source(n.sid).refresh()
                n.ep.refresh_once()
            self.assertEqual(talk(c, srv)[0].spiffe_id, SRV)
            # a node that never picked up the new root cannot authenticate the server any more
            with self.assertRaises(MtlsError):
                talk(old_only, srv)
        finally:
            srv.shutdown()

    def test_rotation_failure_keeps_serving_while_svid_valid(self):
        env = fast_env(6)
        s = Node(env, SRV, policy(inbound=(CLI,)))
        c = Node(env, CLI, policy(outbound=(SRV,)))
        srv = echo_server(s)
        try:
            talk(c, srv)
            serial = s.ep.contexts.snapshot().serial
            s.transport.available = False                  # SPIRE outage exactly when rotation is due
            time.sleep(3.3)
            self.assertFalse(s.ep.refresh_once())          # refresh fails, counted, nothing relaxed
            self.assertGreaterEqual(s.ep.metrics.total(MM.WORKLOAD_API_FAIL), 1)
            self.assertEqual(s.ep.contexts.snapshot().serial, serial)       # old cert, still valid
            self.assertEqual(talk(c, srv)[0].spiffe_id, SRV)
            time.sleep(3.0)                                # now the old SVID has really expired
            c.ep.refresh_once()
            with self.assertRaises(MtlsError):
                talk(c, srv)
        finally:
            srv.shutdown()


class Outages(unittest.TestCase):
    def test_workload_api_outage_after_expiry_refuses_handshakes(self):
        env, s, c = pair()
        srv = echo_server(s)
        try:
            talk(c, srv)
            s.transport.available = False
            env.clock.advance(3600 + 5)                            # own SVID expired, SPIRE down
            with self.assertRaises(MtlsError):
                talk(c, srv)
            self.assertEqual(s.ep.readiness()["status"], "not_ready")
            self.assertEqual(s.ep.readiness()["checks"]["identity"], "fail")
        finally:
            srv.shutdown()

    def test_client_without_identity_cannot_connect_and_never_downgrades(self):
        env, s, c = pair()
        srv = echo_server(s)
        try:
            c.transport.available = False
            env.clock.advance(3600 + 5)
            with self.assertRaises(MtlsError) as cm:
                c.ep.connect(*srv.address, expected_spiffe_id=SRV)
            self.assertEqual(cm.exception.reason, M.IDENTITY_UNAVAILABLE)
            self.assertEqual(srv.seen, [])
        finally:
            srv.shutdown()

    def test_missing_bundle_fails_closed(self):
        env = SpiffeEnv(clock_start=time.time())
        n = Node(env, SRV, policy(inbound=(CLI,)))
        n.provider.bundles._b.clear()                              # no bundle loaded
        n.transport.available = False                              # and none can be fetched
        n.provider._sources.clear()
        with self.assertRaises(MtlsError) as cm:
            n.ep.contexts.server_context()
        self.assertIn(cm.exception.reason, (M.TRUST_UNAVAILABLE, M.IDENTITY_UNAVAILABLE))
        self.assertEqual(n.ep.readiness()["status"], "not_ready")

    def test_stale_bundle_blocks_new_handshakes_even_with_valid_svid(self):
        env = SpiffeEnv(clock_start=time.time())
        env.ca = DevSpireCA(TD, env.clock, x509_ttl=7200)          # SVID outlives the bundle max-age
        s = Node(env, SRV, policy(inbound=(CLI,)))
        c = Node(env, CLI, policy(outbound=(SRV,)))
        srv = echo_server(s)
        try:
            s.ep.contexts.snapshot()                               # SVID already obtained
            s.transport.available = False                          # cannot refresh the bundle
            env.clock.advance(s.sp_cfg.bundle_max_age_seconds + 5)
            with self.assertRaises(MtlsError) as cm:
                s.ep.contexts.snapshot()
            self.assertEqual(cm.exception.reason, M.TRUST_UNAVAILABLE)
            r = s.ep.readiness()
            self.assertEqual((r["checks"]["trust_bundle"], r["status"]), ("fail", "not_ready"))
        finally:
            srv.shutdown()

    def test_recovery_after_outage(self):
        env = fast_env(3)
        s = Node(env, SRV, policy(inbound=(CLI,)), min_ready_remaining_seconds=1)
        c = Node(env, CLI, policy(outbound=(SRV,)))
        srv = echo_server(s)
        try:
            talk(c, srv)
            s.transport.available = False
            c.transport.available = False
            time.sleep(3.3)                                        # both SVIDs expire during the outage
            with self.assertRaises(MtlsError):
                talk(c, srv)
            self.assertEqual(s.ep.readiness()["status"], "not_ready")
            s.transport.available = True
            c.transport.available = True
            self.assertTrue(s.ep.refresh_once())
            self.assertTrue(c.ep.refresh_once())
            self.assertEqual(talk(c, srv)[0].spiffe_id, SRV)
            self.assertEqual(s.ep.readiness()["status"], "ready")
        finally:
            srv.shutdown()

    def test_workload_not_entitled_to_configured_identity(self):
        env = SpiffeEnv(clock_start=time.time())
        n = Node(env, SRV, policy(inbound=(CLI,)))
        n.transport.entitled = []                                   # SPIRE would not issue this ID
        n.provider._sources.clear()
        with self.assertRaises(MtlsError) as cm:
            n.ep.contexts.snapshot()
        self.assertEqual(cm.exception.reason, M.IDENTITY_UNAVAILABLE)

    def test_connection_refused_is_counted(self):
        env, s, c = pair()
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        with self.assertRaises(MtlsError):
            c.ep.connect("127.0.0.1", port, expected_spiffe_id=SRV)
        self.assertEqual(c.ep.metrics.total(MM.CONN_FAIL), 1)


class TlsHandshakeAndConfig(unittest.TestCase):
    def _raw_client(self, node, server_addr, *, maxv=None, ciphers=None, with_cert=True):
        svid = node.provider.x509_source(node.sid).current()
        roots = node.provider.bundles.get(TD).x509_roots
        ctx = tlsutil.client_context(svid, roots, "TLSv1.2")
        if not with_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if maxv:
            ctx.maximum_version = maxv
        if ciphers:
            ctx.set_ciphers(ciphers)
        return ctx.wrap_socket(socket.create_connection(server_addr, timeout=3))

    def test_tls12_client_rejected_when_min_is_13(self):
        env, s, c = pair()
        srv = echo_server(s)
        try:
            with self.assertRaises((ssl.SSLError, OSError)):
                self._raw_client(c, srv.address, maxv=ssl.TLSVersion.TLSv1_2)
            time.sleep(0.1)
            self.assertGreaterEqual(s.ep.metrics.total(MM.HANDSHAKE_FAIL), 1)
        finally:
            srv.shutdown()

    def test_weak_tls12_cipher_rejected_even_when_tls12_allowed(self):
        env, s, c = pair(srv_kw={"min_tls_version": "TLSv1.2"})
        srv = echo_server(s)
        try:
            with self.assertRaises((ssl.SSLError, OSError)):
                self._raw_client(c, srv.address, maxv=ssl.TLSVersion.TLSv1_2, ciphers="AES128-SHA:AES256-SHA")
            tls = self._raw_client(c, srv.address, maxv=ssl.TLSVersion.TLSv1_2,
                                   ciphers="ECDHE-ECDSA-AES128-GCM-SHA256")
            self.assertEqual(tls.version(), "TLSv1.2")
            self.assertIn("GCM", tls.cipher()[0])
            tls.close()
        finally:
            srv.shutdown()

    def test_client_without_certificate_rejected(self):
        env, s, c = pair()
        srv = echo_server(s)
        try:
            try:
                t = self._raw_client(c, srv.address, with_cert=False)
                t.sendall(b"x")
                data = t.recv(8)                                    # TLS1.3: failure may surface on read
                self.assertEqual(data, b"")
            except (ssl.SSLError, OSError):
                pass
            time.sleep(0.15)
            self.assertEqual(srv.seen, [])
            self.assertGreaterEqual(s.ep.metrics.total(MM.HANDSHAKE_FAIL), 1)
        finally:
            srv.shutdown()

    def test_plaintext_client_and_garbage_rejected(self):
        env, s, c = pair()
        srv = echo_server(s)
        try:
            for payload in (b"GET / HTTP/1.1\r\n\r\n", b"\x16\x03\x01\x00\x05garbage", b"\x00" * 100):
                raw = socket.create_connection(srv.address, timeout=3)
                raw.sendall(payload)
                try:
                    self.assertEqual(raw.recv(100)[:5] != b"HTTP/", True)
                except OSError:
                    pass
                raw.close()
            time.sleep(0.2)
            self.assertEqual(srv.seen, [])
            self.assertGreaterEqual(s.ep.metrics.total(MM.HANDSHAKE_FAIL), 3)
        finally:
            srv.shutdown()

    def test_slow_client_times_out_without_blocking_others(self):
        env, s, c = pair(srv_kw={"handshake_timeout_seconds": 0.5})
        srv = echo_server(s)
        try:
            stall = socket.create_connection(srv.address, timeout=3)     # never sends a ClientHello
            peer, reply = talk(c, srv)                                   # another client is unaffected
            self.assertEqual(reply, b"echo:hi")
            time.sleep(0.8)
            self.assertGreaterEqual(s.ep.metrics.get(MM.HANDSHAKE_FAIL, M.HANDSHAKE_TIMEOUT), 1)
            stall.close()
        finally:
            srv.shutdown()

    def test_context_hardening_flags(self):
        env, s, c = pair()
        ctx = s.ep.contexts.server_context()
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.options & ssl.OP_NO_COMPRESSION)
        self.assertTrue(ctx.options & ssl.OP_NO_RENEGOTIATION)


class ConfigValidation(unittest.TestCase):
    BASE = dict(workload_spiffe_id=SRV)

    def test_production_is_default_and_secure(self):
        c = MtlsConfig(**self.BASE).validate()
        self.assertEqual(c.environment.value, "production")
        self.assertEqual(c.min_tls_version, "TLSv1.3")
        self.assertFalse(c.allow_plaintext)
        self.assertTrue(c.require_eku)

    def test_unsafe_settings_rejected(self):
        bad = [dict(min_tls_version="TLSv1.1"), dict(min_tls_version="SSLv3"),
               dict(tls12_ciphers=("AES128-SHA",)), dict(tls12_ciphers=()), dict(tls12_ciphers=("ECDHE-RSA-AES128-SHA",)),
               dict(workload_spiffe_id=""), dict(workload_spiffe_id="http://x/y"), dict(workload_spiffe_id=f"spiffe://{TD}"),
               dict(listen_port=0), dict(handshake_timeout_seconds=0), dict(handshake_timeout_seconds=999),
               dict(max_concurrent_connections=0), dict(bundle_refresh_interval_seconds=0),
               dict(environment="prod")]
        for kw in bad:
            with self.assertRaises(MtlsConfigError, msg=str(kw)):
                MtlsConfig(**{**self.BASE, **kw}).validate()

    def test_development_escapes_refused_in_staging_and_production(self):
        for env in ("staging", "production"):
            with self.assertRaises(MtlsConfigError):
                MtlsConfig(**self.BASE, environment=env, allow_plaintext=True).validate()
            with self.assertRaises(MtlsConfigError):
                MtlsConfig(**self.BASE, environment=env, require_eku=False).validate()
        MtlsConfig(**self.BASE, environment="development", allow_plaintext=True, require_eku=False).validate()

    def test_process_environment_can_only_tighten(self):
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production"}):
            with self.assertRaises(MtlsConfigError):
                MtlsConfig(**self.BASE, environment="development").validate()
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "bogus"}):
            with self.assertRaises(MtlsConfigError):
                MtlsConfig(**self.BASE).validate()

    def test_unknown_keys_and_env_loader(self):
        with self.assertRaises(MtlsConfigError):
            MtlsConfig.from_dict({**self.BASE, "tls_verify": False})
        with mock.patch.dict(os.environ, {"AGENTGUARD_MTLS_SPIFFE_ID": SRV}, clear=False):
            os.environ.pop("AGENTGUARD_ENV", None)
            self.assertEqual(MtlsConfig.from_env().environment.value, "production")

    def test_endpoint_rejects_identity_outside_provider_trust_domain(self):
        env = SpiffeEnv(clock_start=time.time())
        n = Node(env, SRV, policy(inbound=(CLI,)))
        from agent_identity.mtls import MtlsEndpoint
        with self.assertRaises(MtlsError):
            MtlsEndpoint(mtls_cfg("spiffe://elsewhere.example.net/service/x"), n.provider, n.policies)


class PlaintextDowngradePrevention(unittest.TestCase):
    def setUp(self):
        self._svc_obj = SpiffeEnv(clock_start=time.time()).svc      # built before any env patching

    def _svc(self):
        return self._svc_obj

    def test_plaintext_refused_in_staging_and_production(self):
        for e in ("staging", "production"):
            with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": e}):
                for host in ("127.0.0.1", "0.0.0.0", "10.0.0.5"):
                    with self.assertRaises(PlaintextForbidden):
                        http_transport.make_server(self._svc(), "tok", host, 0)

    def test_unset_environment_allows_loopback_only(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENTGUARD_ENV", None)
            srv = http_transport.make_server(self._svc(), "tok", "127.0.0.1", 0)
            srv.server_close()
            for host in ("0.0.0.0", "10.1.2.3", "example.internal", "::"):
                with self.assertRaises(PlaintextForbidden):
                    http_transport.make_server(self._svc(), "tok", host, 0)

    def test_development_allows_plaintext(self):
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "development"}):
            http_transport.make_server(self._svc(), "tok", "127.0.0.1", 0).server_close()

    def test_health_listener_refuses_non_loopback(self):
        env, s, c = pair()
        for host in ("0.0.0.0", "10.0.0.1", "::"):
            with self.assertRaises(MtlsConfigError):
                HealthServer(s.ep, host=host)

    def test_endpoint_has_no_plaintext_path(self):
        env, s, c = pair()
        srv = echo_server(s)
        try:
            c.transport.available = False
            env.clock.advance(3601)
            for _ in range(2):
                with self.assertRaises(MtlsError):
                    c.ep.connect(*srv.address, expected_spiffe_id=SRV)
            self.assertEqual(srv.seen, [])
        finally:
            srv.shutdown()


class HttpIntegration(unittest.TestCase):
    def setUp(self):
        self.env = SpiffeEnv(clock_start=time.time())
        self.server = Node(self.env, SRV, policy(inbound=(CLI,)))
        self.client = Node(self.env, CLI, policy(outbound=(SRV,)))
        self.httpd = http_transport.make_server(self.env.svc, "admin-token", "127.0.0.1", 0, mtls=self.server.ep)
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()
        self.addr = self.httpd.server_address

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _req(self, path, token="admin-token", extra=""):
        tls, peer = self.client.ep.connect(*self.addr, expected_spiffe_id=SRV)
        try:
            auth = f"Authorization: Bearer {token}\r\n" if token else ""
            tls.sendall(f"GET {path} HTTP/1.0\r\nHost: x\r\n{auth}{extra}\r\n".encode())
            buf = b""
            while True:
                d = tls.recv(4096)
                if not d:
                    break
                buf += d
            head, _, body = buf.partition(b"\r\n\r\n")
            return int(head.split()[1]), body
        finally:
            tls.close()

    def test_mtls_http_roundtrip_keeps_bearer_requirement(self):
        code, body = self._req(f"/v1/agents/{self.env.a_id}")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["agent_id"], self.env.a_id)
        self.assertEqual(self._req(f"/v1/agents/{self.env.a_id}", token="")[0], 401)   # mTLS != authorisation
        self.assertEqual(self._req(f"/v1/agents/{self.env.a_id}", token="wrong")[0], 401)

    def test_peer_header_is_server_set_and_client_forgery_dropped(self):
        seen = {}
        real = http_transport.handle

        def spy(svc, tok, method, path, body, headers):
            seen.update(headers)
            return real(svc, tok, method, path, body, headers)
        with mock.patch.object(http_transport, "handle", spy):
            self._req(f"/v1/agents/{self.env.a_id}", extra="X-Peer-Spiffe-Id: spiffe://evil/x\r\nx-peer-spiffe-id: spiffe://evil/y\r\n")
        peers = [v for k, v in seen.items() if k.lower() == "x-peer-spiffe-id"]
        self.assertEqual(peers, [CLI])

    def test_unauthorized_peer_gets_no_http_response(self):
        evilenv = self.env
        other = Node(evilenv, OTHER, policy(outbound=(SRV,)))
        with self.assertRaises(MtlsError):
            tls, _ = other.ep.connect(*self.addr, expected_spiffe_id=SRV)
            tls.sendall(b"GET / HTTP/1.0\r\n\r\n")
            if tls.recv(10) == b"":
                raise MtlsError("closed")

    def test_plaintext_http_to_mtls_listener_gets_nothing(self):
        raw = socket.create_connection(self.addr, timeout=3)
        raw.sendall(b"GET /v1/agents/x HTTP/1.0\r\nAuthorization: Bearer admin-token\r\n\r\n")
        try:
            data = raw.recv(100)
        except OSError:
            data = b""
        raw.close()
        self.assertFalse(data.startswith(b"HTTP/"))


class Concurrency(unittest.TestCase):
    def test_many_concurrent_authenticated_connections(self):
        env, s, c = pair()
        srv = echo_server(s)
        errors, ok = [], []

        def work(n):
            try:
                for k in range(5):
                    peer, reply = talk(c, srv, payload=f"{n}-{k}".encode())
                    ok.append(reply == f"echo:{n}-{k}".encode() and peer.spiffe_id == SRV)
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))
        try:
            ts = [threading.Thread(target=work, args=(i,)) for i in range(16)]
            [t.start() for t in ts]
            [t.join(30) for t in ts]
        finally:
            srv.shutdown()
        self.assertEqual(errors, [])
        self.assertEqual(len(ok), 80)
        self.assertTrue(all(ok))
        self.assertEqual(len(srv.seen), 80)

    def test_connections_during_rotation(self):
        env = fast_env(4)                                         # rotates every ~2s
        s = Node(env, SRV, policy(inbound=(CLI,)))
        c = Node(env, CLI, policy(outbound=(SRV,)))
        srv = echo_server(s)
        errors, n_ok, stop = [], [], threading.Event()

        def work():
            while not stop.is_set():
                try:
                    talk(c, srv)
                    n_ok.append(1)
                except Exception as e:  # noqa: BLE001
                    errors.append(repr(e))
        ts = [threading.Thread(target=work) for _ in range(6)]
        [t.start() for t in ts]
        try:
            time.sleep(5.5)
        finally:
            stop.set()
            [t.join(10) for t in ts]
            srv.shutdown()
        self.assertEqual(errors, [])
        self.assertGreater(len(n_ok), 20)
        self.assertGreaterEqual(c.ep.metrics.get(MM.CERT_ROTATIONS), 1)
        self.assertGreaterEqual(s.ep.metrics.get(MM.CERT_ROTATIONS), 1)

    def test_connection_limit_sheds_load_without_skipping_auth(self):
        env, s, c = pair(srv_kw={"max_concurrent_connections": 1})
        gate = threading.Event()

        def handler(tls, peer):
            gate.wait(5)
        srv = MtlsServer(s.ep, handler, port=0).start()
        try:
            held = []
            tls, _ = c.ep.connect(*srv.address, expected_spiffe_id=SRV)
            held.append(tls)
            time.sleep(0.2)
            try:
                tls2, _ = c.ep.connect(*srv.address, expected_spiffe_id=SRV)
                tls2.sendall(b"x")
                self.assertEqual(tls2.recv(4), b"")
            except (MtlsError, OSError):
                pass
            self.assertGreaterEqual(s.ep.metrics.get(MM.CONN_REFUSED, M.OVERLOAD), 1)
        finally:
            gate.set()
            srv.shutdown()

    def test_graceful_shutdown_waits_for_inflight(self):
        env, s, c = pair(srv_kw={"shutdown_grace_seconds": 5})
        done = []

        def handler(tls, peer):
            time.sleep(0.4)
            tls.sendall(b"finished")
            done.append(1)
        srv = MtlsServer(s.ep, handler, port=0).start()
        addr = srv.address
        tls, _ = c.ep.connect(*addr, expected_spiffe_id=SRV)
        time.sleep(0.1)
        t0 = time.time()
        self.assertTrue(srv.shutdown())
        self.assertGreaterEqual(time.time() - t0, 0.2)
        self.assertEqual(tls.recv(16), b"finished")
        tls.close()
        with self.assertRaises(MtlsError):
            c.ep.connect(*addr, expected_spiffe_id=SRV)         # listener is closed after shutdown


class HealthAndObservability(unittest.TestCase):
    def test_readiness_is_coarse_and_leaks_nothing(self):
        env, s, c = pair()
        r = s.ep.readiness()
        self.assertEqual(r["status"], "ready")
        blob = json.dumps(r) + json.dumps(s.ep.liveness())
        for secret in (SRV, CLI, TD, "spiffe", "PRIVATE", "agp1", ".sock"):
            self.assertNotIn(secret, blob)
        self.assertEqual(set(r["checks"]), {"identity", "trust_bundle", "policy"})

    def test_readiness_degrades_independently(self):
        env, s, c = pair()
        s.policies._p = None
        r = s.ep.readiness()
        self.assertEqual((r["status"], r["checks"]["policy"], r["checks"]["identity"]), ("not_ready", "fail", "ok"))

    def test_readiness_when_svid_close_to_expiry(self):
        env, s, c = pair(srv_kw={"min_ready_remaining_seconds": 600})
        s.transport.available = False
        env.clock.advance(3600 - 100)
        self.assertEqual(s.ep.readiness()["checks"]["identity"], "fail")

    def test_kms_dependency_in_readiness_only_when_required(self):
        env, s, c = pair()
        s.ep._kms_health, s.ep._kms_required = (lambda: False), False
        self.assertEqual(s.ep.readiness()["status"], "ready")
        s.ep._kms_required = True
        self.assertEqual(s.ep.readiness()["checks"]["kms"], "fail")
        s.ep._kms_health = mock.Mock(side_effect=RuntimeError)
        self.assertEqual(s.ep.readiness()["status"], "not_ready")

    def test_health_server_endpoints(self):
        import urllib.request
        import urllib.error
        env, s, c = pair()
        hs = HealthServer(s.ep, port=0).start()
        try:
            base = f"http://127.0.0.1:{hs.address[1]}"
            self.assertEqual(urllib.request.urlopen(base + "/livez").status, 200)
            self.assertEqual(urllib.request.urlopen(base + "/readyz").status, 200)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(base + "/metrics")
            self.assertEqual(cm.exception.code, 404)
            s.policies._p = None
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(base + "/readyz")
            self.assertEqual(cm.exception.code, 503)
        finally:
            hs.shutdown()

    def test_metrics_and_logs_contain_no_secrets(self):
        env, s, c = pair()
        srv = echo_server(s)
        try:
            talk(c, srv)
            with self.assertRaises(MtlsError):
                talk(c, srv, expect=OTHER)
        finally:
            srv.shutdown()
        svid = c.provider.x509_source(CLI).current()
        key_hex = svid.private_key_pkcs8_der().hex()
        blob = (c.ep.metrics.render_prometheus() + s.ep.metrics.render_prometheus()
                + json.dumps(list(env.svc.log.events)) + json.dumps(s.ep.diagnostics()))
        for secret in (key_hex, "PRIVATE KEY", "-----BEGIN"):
            self.assertNotIn(secret, blob)
        for name in (MM.HANDSHAKES, MM.PEER_REJECTED, MM.G_CERT_EXPIRY, MM.HANDSHAKE_LATENCY):
            self.assertIn(name, c.ep.metrics.render_prometheus())
        events = {e["event"] for e in env.svc.log.events}
        self.assertTrue({"mtls.peer.rejected"} <= events)

    def test_expiry_warning_logged_once_per_certificate(self):
        env, s, c = pair(srv_kw={"expiry_warning_seconds": 4000})
        s.ep.contexts.snapshot()
        s.ep.contexts.snapshot()
        warnings = [e for e in env.svc.log.events if e["event"] == "mtls.cert.expiring"]
        self.assertEqual(len(warnings), 1)

    def test_cert_expiry_gauge(self):
        env, s, c = pair()
        s.ep.contexts.snapshot()
        g = s.ep.metrics.gauge(MM.G_CERT_EXPIRY)
        self.assertTrue(3000 < g <= 3600)


class DevSeparation(unittest.TestCase):
    def test_dev_mock_spire_refused_in_production_environment(self):
        from agent_identity.spiffe.errors import ConfigError
        env = SpiffeEnv(clock_start=time.time())
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production"}):
            with self.assertRaises(ConfigError):               # dev transport/config refused in prod
                Node(env, SRV, policy(inbound=(CLI,)))


if __name__ == "__main__":
    unittest.main()
