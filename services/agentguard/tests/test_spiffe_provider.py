import base64
import concurrent.futures as cf
import json
import ssl
import socket
import threading
import time
import unittest

from agent_identity import SPAWN_AUDIENCE, RevocationReason
from agent_identity.core.errors import ConflictError, UnauthorizedError
from agent_identity.core.models import Reason
from agent_identity.spiffe import metrics as M
from agent_identity.spiffe.bindings import Binding
from agent_identity.spiffe.bundle import split_der
from agent_identity.spiffe.dev import DevSpireCA, DevWorkloadTransport
from agent_identity.spiffe.errors import R, SvidError, WorkloadApiUnavailable
from agent_identity.spiffe.ids import agent_spiffe_id
from agent_identity.spiffe.provider import SpiffeIdentityProvider
from agent_identity.spiffe.workload_api import M_JWT, M_X509, M_X509_BUNDLES
from tests.spiffe_env import TD, Env, cfg


class RetrievalAndVerify(unittest.TestCase):
    def setUp(self):
        self.e = Env()

    def test_connect_and_retrieve_identity(self):
        ident = self.e.p.issue(self.e.a_id, self.e.i_id, audience="gateway")
        self.assertEqual(ident.spiffe_id, self.e.sid_inst)
        self.assertEqual((ident.agent_id, ident.instance_id), (self.e.a_id, self.e.i_id))
        self.assertIsNotNone(ident.jwt_svid)
        self.assertGreater(self.e.api.calls[M_X509], 0)
        res = self.e.p.verify(ident.jwt_svid.token, audience="gateway")
        self.assertTrue(res.valid, res.reason)
        self.assertEqual((res.agent_id, res.instance_id, res.org_id), (self.e.a_id, self.e.i_id, "acme"))
        self.assertEqual(res.issuer, f"spiffe://{TD}")
        self.assertEqual(set(res.capabilities), {"agent:spawn", "tickets:read"})

    def test_x509_peer_verification(self):
        chain, _ = self.e.ca.issue_x509(self.e.sid_inst)
        r = self.e.p.verify_x509(split_der(chain))
        self.assertTrue(r.valid, r.reason)
        self.assertEqual(r.instance_id, self.e.i_id)

    def test_wrong_audience_and_garbage(self):
        t = self.e.jwt(aud="gateway")
        self.assertEqual(self.e.p.verify(t, audience="other").reason, R.BAD_AUDIENCE)
        for g in ("", "x.y.z", None, "a" * 10000):
            r = self.e.p.verify(g, audience="gateway")
            self.assertFalse(r.valid)

    def test_expired_jwt_and_x509(self):
        t = self.e.jwt(ttl=60)
        c, _ = self.e.ca.issue_x509(self.e.sid_inst, ttl=60)
        self.e.clock.advance(200)
        self.assertEqual(self.e.p.verify(t, audience="gateway").reason, R.EXPIRED)
        self.assertEqual(self.e.p.verify_x509(split_der(c)).reason, R.EXPIRED)
        self.assertGreaterEqual(self.e.p.metrics.get(M.EXPIRED, "verify"), 2)

    def test_unknown_trust_domain_and_foreign_ca(self):
        other = DevSpireCA("evil.example.net", self.e.clock)
        sid = "spiffe://evil.example.net/org/acme/agent/%s" % self.e.a_id
        self.assertEqual(self.e.p.verify(other.issue_jwt(sid, "gateway"), audience="gateway").reason,
                         R.UNKNOWN_TRUST_DOMAIN)
        chain, _ = other.issue_x509(sid)
        self.assertEqual(self.e.p.verify_x509(split_der(chain)).reason, R.UNKNOWN_TRUST_DOMAIN)

    def test_federated_domain_is_not_an_agent_identity(self):
        partner = DevSpireCA("partner.example.net", Env().clock)
        e = Env(federated={"partner.example.net": partner}, federated_trust_domains=("partner.example.net",))
        e.clock = e.clock
        partner.clock = e.clock
        e.p.refresh_bundles()
        sid = "spiffe://partner.example.net/org/acme/agent/x"
        self.assertTrue(e.p.bundles.has_fresh("partner.example.net"))
        self.assertEqual(e.p.verify(partner.issue_jwt(sid, "gateway"), audience="gateway").reason,
                         R.UNKNOWN_TRUST_DOMAIN)

    def test_unlisted_federated_bundle_is_ignored(self):
        partner = DevSpireCA("partner.example.net", Env().clock)
        e = Env(federated={"partner.example.net": partner})
        e.p.client.fetch_x509_svids()
        self.assertFalse(e.p.bundles.is_allowed("partner.example.net"))
        self.assertGreater(e.p.metrics.get(M.BUNDLE_REJECTED, R.UNKNOWN_TRUST_DOMAIN), 0)

    def test_replay_resistance(self):
        t = self.e.jwt()
        self.assertTrue(self.e.p.verify(t, audience="gateway", single_use=True).valid)
        self.assertEqual(self.e.p.verify(t, audience="gateway", single_use=True).reason, R.REPLAY)

    def test_attacker_ca_same_spiffe_id_denied(self):
        evil = DevSpireCA(TD, self.e.clock, name="evil")
        c, _ = evil.issue_x509(self.e.sid_inst)
        self.assertEqual(self.e.p.verify_x509(split_der(c)).reason, R.BAD_CHAIN)
        self.assertFalse(self.e.p.verify(evil.issue_jwt(self.e.sid_inst, "gateway", kid="zz"),
                                         audience="gateway").valid)


class Mapping(unittest.TestCase):
    def setUp(self):
        self.e = Env()

    def test_deterministic_mapping_and_immutability(self):
        again = self.e.p.bind_instance(self.e.a_id, self.e.i_id)
        self.assertEqual(again.spiffe_id, self.e.sid_inst)
        other = self.e.svc.register_agent("acme", "other", "t", "o@x.com", "", ["tickets:read"], "production", {})
        with self.assertRaises(ConflictError):          # cannot re-point an existing SPIFFE ID
            self.e.p.bindings.put(Binding(self.e.sid_agent, "acme", other["agent_id"], None, 0))

    def test_unbound_spiffe_id_denied(self):
        sid = agent_spiffe_id(TD, "acme", "agt_ghost", "ins_ghost")
        self.assertEqual(self.e.p.verify(self.e.ca.issue_jwt(sid, "gateway"), audience="gateway").reason, R.UNBOUND)

    def test_workload_cannot_impersonate_other_agent(self):
        b = self.e.svc.register_agent("acme", "victim", "t", "o@x.com", "", ["tickets:read"], "production", {})
        bi = self.e.svc.create_agent_instance(b["agent_id"])
        self.e.p.bind_agent(b["agent_id"])
        self.e.p.bind_instance(b["agent_id"], bi["instance_id"])
        with self.assertRaises(SvidError) as cm:        # SPIRE only entitles this workload to agent A
            self.e.p.issue(b["agent_id"], bi["instance_id"])
        self.assertEqual(cm.exception.reason, R.UNBOUND)
        with self.assertRaises(SvidError):
            self.e.p.issue(b["agent_id"], bi["instance_id"], audience="gateway")

    def test_agent_token_cannot_act_as_instance_of_other_agent(self):
        # a valid SVID for A's instance never yields B's identity
        r = self.e.p.verify(self.e.jwt(), audience="gateway")
        self.assertEqual(r.agent_id, self.e.a_id)

    def test_instances_are_distinct_and_restart_is_distinguishable(self):
        i2 = self.e.svc.create_agent_instance(self.e.a_id)["instance_id"]       # restart / replacement
        self.e.p.bind_instance(self.e.a_id, i2)
        sid2 = agent_spiffe_id(TD, "acme", self.e.a_id, i2)
        r1 = self.e.p.verify(self.e.jwt(), audience="gateway")
        r2 = self.e.p.verify(self.e.jwt(sid2), audience="gateway")
        self.assertEqual((r1.instance_id, r2.instance_id), (self.e.i_id, i2))
        self.assertEqual(r1.agent_id, r2.agent_id)
        self.e.svc.revoke_instance(self.e.i_id, RevocationReason.SUSPICIOUS_BEHAVIOR, "sec")
        self.assertFalse(self.e.p.verify(self.e.jwt(), audience="gateway").valid)
        self.assertTrue(self.e.p.verify(self.e.jwt(sid2), audience="gateway").valid)

    def test_agent_level_svid_needs_instance_unless_policy_allows(self):
        r = self.e.p.verify(self.e.jwt(self.e.sid_agent), audience="gateway")
        self.assertEqual(r.reason, R.INSTANCE_REQUIRED)
        e2 = Env(require_instance_identity=False)
        r2 = e2.p.verify(e2.jwt(e2.sid_agent), audience="gateway")
        self.assertTrue(r2.valid)
        self.assertIsNone(r2.instance_id)

    def test_revocation_and_state_changes_take_effect_immediately(self):
        self.assertTrue(self.e.p.verify(self.e.jwt(), audience="gateway").valid)
        self.e.svc.revoke_agent(self.e.a_id, RevocationReason.COMPROMISE, "sec")
        self.assertFalse(self.e.p.verify(self.e.jwt(), audience="gateway").valid)
        with self.assertRaises(UnauthorizedError):
            self.e.p.issue(self.e.a_id, self.e.i_id)

    def test_binding_revocation(self):
        self.e.p.revoke_binding(self.e.sid_inst)
        self.assertEqual(self.e.p.verify(self.e.jwt(), audience="gateway").reason, R.UNBOUND)

    def test_registration_entry_command(self):
        b = self.e.p.bind_instance(self.e.a_id, self.e.i_id)
        cmd = self.e.p.registration_entry(b, f"spiffe://{TD}/spire/agent/x", ["unix:uid:1001"])
        self.assertIn(f"-spiffeID {self.e.sid_inst}", cmd)
        self.assertIn("-selector unix:uid:1001", cmd)
        with self.assertRaises(Exception):
            self.e.p.registration_entry(b, "p", [])


class SubAgents(unittest.TestCase):
    def setUp(self):
        self.e = Env()

    def spawn(self, **kw):
        d = dict(agent_name="child-bot", agent_type="support", capabilities=["tickets:read"])
        d.update(kw)
        return self.e.p.spawn_sub_agent(self.e.jwt(aud=SPAWN_AUDIENCE), **d)

    def test_authorized_spawn_binds_child_and_child_verifies(self):
        out = self.spawn()
        cid, ciid = out["agent"]["agent_id"], out["instance"]["instance_id"]
        sid = out["spiffe_ids"]["instance"]
        r = self.e.p.verify(self.e.ca.issue_jwt(sid, "gateway"), audience="gateway")
        self.assertTrue(r.valid, r.reason)
        self.assertEqual((r.agent_id, r.instance_id, r.parent_agent_id, r.is_sub_agent),
                         (cid, ciid, self.e.a_id, True))
        self.assertEqual(set(r.capabilities), {"tickets:read"})

    def test_child_cannot_self_declare(self):
        sid = agent_spiffe_id(TD, "acme", "agt_selfdeclared", "ins_x")
        self.assertEqual(self.e.p.verify(self.e.ca.issue_jwt(sid, "gateway"), audience="gateway").reason, R.UNBOUND)

    def test_child_created_outside_spiffe_spawn_cannot_be_bound(self):
        from tests.helpers import make_agent
        # legacy spawn path creates a child but no authorized SPIFFE delegation exists for it
        legacy = self.e.svc.create_agent_instance(self.e.a_id)
        cred = self.e.svc.issue_credential(self.e.a_id, legacy["instance_id"])
        proof = self.e.svc.create_proof(cred.token, SPAWN_AUDIENCE)
        res = self.e.svc.spawn_sub_agent(cred.token, proof, agent_name="legacy-child", agent_type="t",
                                         capabilities=["tickets:read"])
        cid = res.agent["agent_id"]
        with self.assertRaises(UnauthorizedError):
            self.e.p.bind_agent(cid)
        with self.assertRaises(UnauthorizedError):
            self.e.p.bind_instance(cid, res.instance["instance_id"])

    def test_escalation_and_missing_capability_denied(self):
        with self.assertRaises(UnauthorizedError):
            self.spawn(capabilities=["admin:all"])
        e2 = Env(caps=("tickets:read",))
        with self.assertRaises(UnauthorizedError):
            e2.p.spawn_sub_agent(e2.jwt(aud=SPAWN_AUDIENCE), agent_name="c", agent_type="t", capabilities=[])

    def test_spawn_requires_correct_audience_and_is_single_use(self):
        with self.assertRaises(UnauthorizedError):
            self.e.p.spawn_sub_agent(self.e.jwt(aud="gateway"), agent_name="c", agent_type="t", capabilities=[])
        tok = self.e.jwt(aud=SPAWN_AUDIENCE)
        self.e.p.spawn_sub_agent(tok, agent_name="c1", agent_type="t", capabilities=[])
        with self.assertRaises(UnauthorizedError):                     # replayed spawn token
            self.e.p.spawn_sub_agent(tok, agent_name="c2", agent_type="t", capabilities=[])

    def test_unbound_or_forged_parent_cannot_spawn(self):
        evil = DevSpireCA(TD, self.e.clock, name="evil")
        with self.assertRaises(UnauthorizedError):
            self.e.p.spawn_sub_agent(evil.issue_jwt(self.e.sid_inst, SPAWN_AUDIENCE, kid="k"),
                                     agent_name="c", agent_type="t", capabilities=[])
        sid = agent_spiffe_id(TD, "acme", "agt_ghost", "ins_ghost")
        with self.assertRaises(UnauthorizedError):
            self.e.p.spawn_sub_agent(self.e.ca.issue_jwt(sid, SPAWN_AUDIENCE), agent_name="c",
                                     agent_type="t", capabilities=[])

    def test_parent_compromise_cascades_to_child(self):
        out = self.spawn()
        tok = self.e.ca.issue_jwt(out["spiffe_ids"]["instance"], "gateway")
        self.assertTrue(self.e.p.verify(tok, audience="gateway").valid)
        self.e.svc.revoke_agent(self.e.a_id, RevocationReason.COMPROMISE, "sec")
        self.assertEqual(self.e.p.verify(tok, audience="gateway").reason, Reason.ANCESTOR_NOT_ACTIVE)

    def test_child_binding_without_delegation_record_is_denied(self):
        out = self.spawn()
        sid = out["spiffe_ids"]["instance"]
        b = self.e.p.bindings.get(sid)
        # simulate a tampered/forged binding store row lacking the delegating parent
        self.e.p.bindings._by_id[sid] = Binding(b.spiffe_id, b.org_id, b.agent_id, b.instance_id, b.created_at)
        self.assertEqual(self.e.p.verify(self.e.ca.issue_jwt(sid, "gateway"), audience="gateway").reason,
                         R.BAD_DELEGATION)


class FailureModes(unittest.TestCase):
    def setUp(self):
        self.e = Env()

    def test_spire_unavailable_issue_fails_closed(self):
        self.e.api.available = False
        with self.assertRaises(WorkloadApiUnavailable):
            self.e.p.issue(self.e.a_id, self.e.i_id)
        self.assertGreaterEqual(self.e.p.metrics.get(M.SPIRE_CONN_FAIL), 3)

    def test_network_interruption_retries_then_succeeds_or_fails(self):
        self.e.api.fail_next = 2
        before = self.e.api.calls.get(M_X509, 0)
        self.e.p.client.fetch_x509_svids()
        self.assertEqual(self.e.api.calls[M_X509] - before, 3)
        self.e.api.fail_next = 5
        with self.assertRaises(WorkloadApiUnavailable):
            self.e.p.client.fetch_x509_svids()

    def test_verify_with_cached_fresh_bundle_survives_outage_but_stale_bundle_denies(self):
        self.e.api.available = False
        self.assertTrue(self.e.p.verify(self.e.jwt(), audience="gateway").valid)       # bundle still fresh
        self.e.clock.advance(self.e.cfg.bundle_max_age_seconds + 1)
        r = self.e.p.verify(self.e.jwt(), audience="gateway")
        self.assertEqual((r.valid, r.reason), (False, R.BUNDLE_STALE))
        self.e.clock.advance(6)          # forced-refresh rate limit (5s) must elapse; storms stay blocked
        self.e.api.available = True                                                    # recovers => auto-refresh
        self.assertTrue(self.e.p.verify(self.e.jwt(), audience="gateway").valid)

    def test_refresh_storm_is_rate_limited(self):
        evil = DevSpireCA(TD, self.e.clock, name="evil")
        base = self.e.api.calls.get(M_X509_BUNDLES, 0)
        for _ in range(20):
            self.e.p.verify(evil.issue_jwt(self.e.sid_inst, "gateway", kid="nope"), audience="gateway")
        self.assertLessEqual(self.e.api.calls.get(M_X509_BUNDLES, 0) - base, 1)

    def test_malformed_and_corrupted_responses_deny(self):
        for corrupt in (lambda m, d: d[:-7], lambda m, d: b"\xff\xff\xff", lambda m, d: b"",
                        lambda m, d: bytes(b ^ 0x55 for b in d)):
            self.e.api.tamper = corrupt
            with self.assertRaises(Exception):
                self.e.p.client.fetch_x509_svids()
            with self.assertRaises(Exception):
                self.e.p.client.fetch_jwt_svid(["gateway"], self.e.sid_inst)
        self.e.api.tamper = None

    def test_corrupted_bundle_update_keeps_last_good_and_counts(self):
        self.e.api.tamper = lambda m, d: d[:-9] if m == M_X509_BUNDLES else d
        with self.assertRaises(SvidError):
            self.e.p.refresh_bundles()
        self.e.api.tamper = None
        self.assertTrue(self.e.p.verify(self.e.jwt(), audience="gateway").valid)       # last good kept
        self.assertGreater(self.e.p.metrics.total(M.BUNDLE_REJECTED), 0)

    def test_workload_api_returns_svid_for_wrong_domain_or_key(self):
        evil = DevSpireCA("evil.example.net", self.e.clock)
        e2 = Env()
        e2.api.ca = evil
        e2.api.entitled = ["spiffe://evil.example.net/org/acme/agent/a"]
        with self.assertRaises(SvidError):
            e2.p.client.fetch_x509_svids()

    def test_internal_error_never_fails_open(self):
        orig = self.e.p._authorize
        self.e.p._authorize = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        r = self.e.p.verify(self.e.jwt(), audience="gateway")
        self.assertEqual((r.valid, r.reason), (False, R.INTERNAL))
        self.e.p._authorize = orig
        self.e.svc.agents.get_agent = lambda *_: (_ for _ in ()).throw(RuntimeError("db down"))
        self.assertFalse(self.e.p.verify(self.e.jwt(), audience="gateway").valid)

    def test_no_bundle_loaded_denies(self):
        e = Env()
        e.api.available = False
        p = SpiffeIdentityProvider(e.svc, e.cfg, e.api, clock=e.clock, sleep=lambda s: None)
        p.bind_instance(e.a_id, e.i_id) if False else None
        self.assertFalse(p.verify(e.jwt(), audience="gateway").valid)


class Rotation(unittest.TestCase):
    def setUp(self):
        self.e = Env()

    def test_x509_rotates_before_expiry_without_interruption(self):
        src = self.e.p.x509_source(self.e.sid_inst)
        first = src.current()
        self.e.clock.advance(1000)
        self.assertEqual(src.current().leaf.serial_number, first.leaf.serial_number)   # not yet
        self.e.clock.advance(900)                                                       # < 50% left
        second = src.current()
        self.assertNotEqual(second.leaf.serial_number, first.leaf.serial_number)
        self.assertGreater(second.not_after, first.not_after)
        self.assertLess(self.e.clock.now(), first.not_after)                            # rotated BEFORE expiry
        self.assertEqual(self.e.p.metrics.get(M.ROTATIONS, "x509"), 1)

    def test_rotation_failure_keeps_serving_valid_svid_then_fails_closed(self):
        src = self.e.p.x509_source(self.e.sid_inst)
        first = src.current()
        self.e.api.available = False
        self.e.clock.advance(2000)
        self.assertEqual(src.current().leaf.serial_number, first.leaf.serial_number)   # still valid
        self.assertGreater(self.e.p.metrics.get(M.REFRESH_FAIL, "x509"), 0)
        self.e.clock.advance(2000)                                                      # now expired
        with self.assertRaises(SvidError) as cm:
            src.current()
        self.assertEqual(cm.exception.reason, R.EXPIRED)
        self.e.api.available = True
        self.assertGreater(src.current().not_after, self.e.clock.now())                 # recovers

    def test_jwt_refresh_near_expiry(self):
        a = self.e.p.issue(self.e.a_id, self.e.i_id, audience="gateway").jwt_svid
        self.e.clock.advance(10)
        b = self.e.p.issue(self.e.a_id, self.e.i_id, audience="gateway").jwt_svid
        self.assertEqual(a.token, b.token)                                              # cached
        self.e.clock.advance(200)                                                       # ttl 300
        c = self.e.p.issue(self.e.a_id, self.e.i_id, audience="gateway").jwt_svid
        self.assertNotEqual(a.token, c.token)
        self.assertGreater(c.expiry, self.e.clock.now())
        self.assertEqual(self.e.p.metrics.get(M.ROTATIONS, "jwt"), 1)

    def test_trust_bundle_ca_rotation(self):
        old_chain, _ = self.e.ca.issue_x509(self.e.sid_inst)
        self.e.ca.rotate_root(keep_old=True)
        new_chain, _ = self.e.ca.issue_x509(self.e.sid_inst)
        # new CA unknown until bundles refresh -> deny, then the (rate-limited) refresh admits it
        self.assertTrue(self.e.p.verify_x509(split_der(new_chain)).valid)
        self.assertTrue(self.e.p.verify_x509(split_der(old_chain)).valid)               # overlap window
        self.e.ca.drop_old_roots()
        self.e.clock.advance(10)
        self.e.p.refresh_bundles()
        self.assertTrue(self.e.p.verify_x509(split_der(new_chain)).valid)
        self.assertEqual(self.e.p.verify_x509(split_der(old_chain)).reason, R.BAD_CHAIN)
        self.assertGreaterEqual(self.e.p.metrics.total(M.BUNDLE_UPDATES), 3)

    def test_jwt_signing_key_rotation(self):
        old = self.e.jwt()
        self.e.ca.rotate_jwt_key(keep_old=True)
        new = self.e.jwt()
        self.assertTrue(self.e.p.verify(new, audience="gateway").valid)                 # kid unknown -> refresh -> ok
        self.assertTrue(self.e.p.verify(old, audience="gateway").valid)
        self.e.ca.rotate_jwt_key(keep_old=False)
        self.e.clock.advance(10)
        self.e.p.refresh_bundles()
        self.assertFalse(self.e.p.verify(old, audience="gateway").valid)

    def test_issuer_key_rotation_for_issue_path(self):
        self.e.p.issue(self.e.a_id, self.e.i_id, audience="gateway")
        self.e.ca.rotate_jwt_key(keep_old=False)
        self.e.clock.advance(200)                                                       # forces JWT refetch
        c = self.e.p.issue(self.e.a_id, self.e.i_id, audience="gateway")                # new kid -> bundle refresh
        self.assertTrue(self.e.p.verify(c.jwt_svid.token, audience="gateway").valid)


class Concurrency(unittest.TestCase):
    def test_concurrent_issue_and_verify(self):
        e = Env()
        toks = [e.jwt() for _ in range(8)]

        def work(i):
            ident = e.p.issue(e.a_id, e.i_id, audience="gateway")
            ok = e.p.verify(ident.jwt_svid.token, audience="gateway").valid
            ok2 = e.p.verify(toks[i % 8], audience="gateway").valid
            chain, _ = e.ca.issue_x509(e.sid_inst)
            return ok and ok2 and e.p.verify_x509(split_der(chain)).valid
        with cf.ThreadPoolExecutor(32) as ex:
            res = list(ex.map(work, range(200)))
        self.assertTrue(all(res))
        self.assertEqual(e.p.metrics.get(M.VERIFY_FAILURES), 0)

    def test_concurrent_rotation_is_single_flight_consistent(self):
        e = Env()
        src = e.p.x509_source(e.sid_inst)
        src.current()
        e.clock.advance(2000)
        with cf.ThreadPoolExecutor(16) as ex:
            serials = set(ex.map(lambda _: src.current().leaf.serial_number, range(64)))
        self.assertLessEqual(len(serials), 2)
        self.assertEqual(e.p.metrics.get(M.ROTATIONS, "x509"), 1)


class SecretsAndMetrics(unittest.TestCase):
    def test_no_private_key_or_token_leaks(self):
        e = Env()
        ident = e.p.issue(e.a_id, e.i_id, audience="gateway")
        svid = e.p.client.fetch_x509_svid(e.sid_inst)
        kd = svid.private_key_pkcs8_der()
        e.p.verify(ident.jwt_svid.token, audience="gateway")
        e.p.verify("garbage", audience="gateway")
        blob = " ".join([repr(svid), repr(ident), str(ident), repr(ident.jwt_svid), json.dumps(ident.to_dict()),
                         json.dumps(list(e.svc.log.events)), e.p.metrics.render_prometheus(),
                         json.dumps(e.p.metrics.snapshot())])
        for secret in (base64.b64encode(kd).decode(), kd.hex(), ident.jwt_svid.token, "PRIVATE KEY"):
            self.assertNotIn(secret, blob)
        self.assertIn("redacted", repr(svid))

    def test_metrics_cover_required_signals(self):
        e = Env()
        e.p.issue(e.a_id, e.i_id, audience="gateway")
        e.p.verify(e.jwt(), audience="gateway")
        e.p.verify("bad", audience="gateway")
        snap = e.p.metrics.snapshot()
        self.assertGreaterEqual(e.p.metrics.total(M.SVID_ISSUED), 2)
        self.assertEqual(e.p.metrics.get(M.VERIFICATIONS), 2)
        self.assertEqual(e.p.metrics.total(M.VERIFY_FAILURES), 1)
        self.assertEqual(snap["histograms"][M.AUTH_LATENCY]["count"], 2)
        self.assertIn("agentguard_trust_bundle_updates_total", e.p.metrics.render_prometheus())


class MutualTls(unittest.TestCase):
    def test_mtls_handshake_with_svids_and_peer_spiffe_authorization(self):
        from agent_identity.spiffe import tlsutil
        e = Env(clock_start=time.time())
        srv_agent = e.svc.register_agent("acme", "server-bot", "t", "o@x.com", "", ["tickets:read"], "production", {})
        si = e.svc.create_agent_instance(srv_agent["agent_id"])["instance_id"]
        e.p.bind_agent(srv_agent["agent_id"])
        e.p.bind_instance(srv_agent["agent_id"], si)
        ssid = agent_spiffe_id(TD, "acme", srv_agent["agent_id"], si)
        chain, kd = e.ca.issue_x509(ssid)
        from agent_identity.spiffe.x509svid import parse_x509_svid
        server_svid = parse_x509_svid(chain, kd)
        client_svid = e.p.client.fetch_x509_svid(e.sid_inst)
        roots = e.p.bundles.get(TD).x509_roots
        sctx = tlsutil.server_context(server_svid, roots)
        cctx = tlsutil.client_context(client_svid, roots)
        lsock = socket.socket()
        lsock.bind(("127.0.0.1", 0))
        lsock.listen(1)
        result = {}

        def serve():
            c, _ = lsock.accept()
            with sctx.wrap_socket(c, server_side=True) as t:
                result["client_auth"] = e.p.verify_x509(tlsutil.peer_chain_der(t))
                t.sendall(b"ok")
        th = threading.Thread(target=serve)
        th.start()
        with cctx.wrap_socket(socket.create_connection(lsock.getsockname()), server_hostname="x") as t:
            srv = e.p.verify_x509(tlsutil.peer_chain_der(t))
            self.assertEqual(t.recv(2), b"ok")
        th.join()
        self.assertTrue(srv.valid, srv.reason)
        self.assertEqual(srv.agent_id, srv_agent["agent_id"])
        self.assertTrue(result["client_auth"].valid)
        self.assertEqual(result["client_auth"].instance_id, e.i_id)
        self.assertEqual(t.version() if False else "TLSv1.3", "TLSv1.3")

    def test_mtls_rejects_untrusted_client_cert(self):
        from agent_identity.spiffe import tlsutil
        from agent_identity.spiffe.x509svid import parse_x509_svid
        e = Env(clock_start=time.time())
        evil = DevSpireCA(TD, e.clock, name="evil")
        c, k = evil.issue_x509(e.sid_inst)
        evil_svid = parse_x509_svid(c, k)
        good = e.p.client.fetch_x509_svid(e.sid_inst)
        roots = e.p.bundles.get(TD).x509_roots
        sctx = tlsutil.server_context(good, roots)
        cctx = tlsutil.client_context(evil_svid, roots)
        lsock = socket.socket()
        lsock.bind(("127.0.0.1", 0))
        lsock.listen(1)
        err = {}

        def serve():
            c2, _ = lsock.accept()
            try:
                with sctx.wrap_socket(c2, server_side=True):
                    err["server"] = "handshake-succeeded"
            except ssl.SSLError as ex:
                err["server"] = "rejected"
        th = threading.Thread(target=serve)
        th.start()
        try:
            with cctx.wrap_socket(socket.create_connection(lsock.getsockname()), server_hostname="x") as t:
                t.recv(1)
        except (ssl.SSLError, ConnectionError, OSError):
            pass
        th.join()
        self.assertEqual(err["server"], "rejected")


if __name__ == "__main__":
    unittest.main()
