"""REAL Redis integration tests. Skipped unless AGENTGUARD_TEST_REDIS_HOST is set.
  AGENTGUARD_TEST_REDIS_HOST=127.0.0.1 [AGENTGUARD_TEST_REDIS_PORT=6379] [AGENTGUARD_TEST_REDIS_PASSWORD=...]
  PYTHONPATH=src:. python -m unittest -v tests.test_state_integration
Every test class uses a unique key prefix, so a shared dev Redis is safe (nothing is flushed)."""
import concurrent.futures as cf
import os
import secrets
import time
import unittest

from agent_identity import IdentityConfig, IdentityService
from agent_identity.core.models import RevocationReason
from agent_identity.state import (BucketPolicy, KeyBuilder, RedisConfig, StateUnavailableError, WindowPolicy,
                                  build_security_state)
from agent_identity.state import cache as C
from agent_identity.state.redis_backend import RedisBackend
from tests.helpers import make_agent, make_service
from tests.state_contract import BackendContract

HOST = os.environ.get("AGENTGUARD_TEST_REDIS_HOST", "")
PORT = int(os.environ.get("AGENTGUARD_TEST_REDIS_PORT", "6379"))
PW = os.environ.get("AGENTGUARD_TEST_REDIS_PASSWORD", "")
TLS = os.environ.get("AGENTGUARD_TEST_REDIS_TLS", "0") == "1"
ON = bool(HOST)


def rcfg(prefix, **kw):
    d = dict(environment="development", host=HOST, port=PORT, password=PW, tls=TLS, key_prefix=prefix,
             retry_base_backoff_seconds=0.01, command_timeout_seconds=1.0, connect_timeout_seconds=2.0)
    d.update(kw)
    return RedisConfig(**d).validate()


def new_prefix():
    return "agt" + secrets.token_hex(5)


@unittest.skipUnless(ON, "set AGENTGUARD_TEST_REDIS_HOST for real Redis tests")
class RedisContract(BackendContract, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prefix = new_prefix()
        cls.b = RedisBackend(rcfg(cls.prefix))
        cls.k = "{" + cls.prefix + "}"                 # one hash slot, so cluster mode also works

    @classmethod
    def tearDownClass(cls):
        cls.b.close()

    def sleep_ms(self, ms):
        time.sleep(ms / 1000.0)

    def test_ping_and_pool_stats(self):
        self.assertTrue(self.b.ping())
        self.assertIsInstance(self.b.pool_stats(), dict)


@unittest.skipUnless(ON, "set AGENTGUARD_TEST_REDIS_HOST for real Redis tests")
class Distributed(unittest.TestCase):
    """Two RedisBackend clients = two independent AgentGuard instances sharing one Redis."""

    def setUp(self):
        self.prefix = new_prefix()
        self.s1 = build_security_state(rcfg(self.prefix))
        self.s2 = build_security_state(rcfg(self.prefix))

    def tearDown(self):
        self.s1.close()
        self.s2.close()

    def test_replay_cannot_pass_on_two_instances(self):
        def go(i):
            return (self.s1 if i % 2 else self.s2).replay.check_and_store("cred1:nonceX", 30, 0)
        with cf.ThreadPoolExecutor(24) as ex:
            res = list(ex.map(go, range(120)))
        self.assertEqual(res.count(True), 1)

    def test_rate_limit_shared_budget_across_instances(self):
        p = BucketPolicy("issue", rate_per_sec=0.001, burst=10)

        def go(i):
            return (self.s1 if i % 2 else self.s2).limiter.allow(p, "acme", "tenant", "acme").allowed
        with cf.ThreadPoolExecutor(24) as ex:
            res = list(ex.map(go, range(100)))
        self.assertEqual(res.count(True), 10)
        w = WindowPolicy("authfail", 5, 60)
        out = [(self.s1 if i % 2 else self.s2).limiter.hit(w, "acme", "ip", "198.51.100.7").allowed for i in range(9)]
        self.assertEqual(out.count(True), 5)

    def test_lock_single_owner_across_instances_and_owner_checked_release(self):
        def go(i):
            return (self.s1 if i % 2 else self.s2).locks.acquire("acme", "rotate-1", ttl_seconds=20)
        with cf.ThreadPoolExecutor(16) as ex:
            handles = [h for h in ex.map(go, range(32)) if h]
        self.assertEqual(len(handles), 1)
        h = handles[0]
        self.assertIsNone(self.s2.locks.acquire("acme", "rotate-1"))
        self.assertTrue(h.release())
        self.assertIsNotNone(self.s2.locks.acquire("acme", "rotate-1", ttl_seconds=5))

    def test_lock_expires_by_ttl(self):
        h = self.s1.locks.acquire("acme", "short", ttl_seconds=1)
        self.assertIsNotNone(h)
        time.sleep(1.3)
        self.assertIsNotNone(self.s2.locks.acquire("acme", "short", ttl_seconds=5))
        self.assertFalse(h.release())                         # old owner cannot free the new owner's lock

    def test_tenant_isolation_in_real_redis(self):
        a, b = self.s1.temp.for_tenant("acme"), self.s2.temp.for_tenant("globex")
        a.put("grant", "g1", owner="o", ttl_seconds=60, data={"x": 1})
        self.assertIsNone(b.get("grant", "g1"))
        self.assertIsNone(b.consume("grant", "g1"))
        self.assertIsNotNone(a.get("grant", "g1"))

    def test_temp_state_transition_and_consume_race(self):
        t = self.s1.temp.for_tenant("acme")
        t.put("approval", "ap", owner="o", ttl_seconds=60)
        t2 = self.s2.temp.for_tenant("acme")

        def go(i):
            try:
                (t if i % 2 else t2).transition("approval", "ap", expected_status="pending", new_status=f"d{i}")
                return True
            except Exception:
                return False
        with cf.ThreadPoolExecutor(16) as ex:
            self.assertEqual(list(ex.map(go, range(32))).count(True), 1)
        t.put("challenge", "c", owner="o", ttl_seconds=60)
        with cf.ThreadPoolExecutor(16) as ex:
            got = [r for r in ex.map(lambda i: (t if i % 2 else t2).consume("challenge", "c"), range(32)) if r]
        self.assertEqual(len(got), 1)

    def test_every_key_has_a_ttl(self):
        self.s1.replay.check_and_store("n", 30, 0)
        self.s1.limiter.allow(BucketPolicy("p", 1, 2), "acme", "agent", "a")
        self.s1.limiter.hit(WindowPolicy("w", 3, 60), "acme", "ip", "1.2.3.4")
        self.s1.locks.acquire("acme", "l", ttl_seconds=10)
        self.s1.temp.for_tenant("acme").put("risk", "r", owner="o", ttl_seconds=30)
        r = self.s1.backend._r
        keys = list(r.scan_iter(match=f"{self.prefix}:*", count=500))
        self.assertGreaterEqual(len(keys), 6)
        for k in keys:
            self.assertGreater(r.pttl(k), 0, k)               # no key without an expiry (-1) and none already gone
            self.assertNotIn(b"1.2.3.4", k)

    def test_reconnect_after_connections_are_killed(self):
        self.assertTrue(self.s1.replay.check_and_store("pre", 30, 0))
        self.s1.backend._r.execute_command("CLIENT", "KILL", "TYPE", "normal", "SKIPME", "yes")
        self.assertTrue(self.s1.replay.check_and_store("post", 30, 0))       # retry + fresh connection
        self.assertFalse(self.s1.replay.check_and_store("pre", 30, 0))       # state intact

    def test_state_loss_triggers_quarantine_on_real_redis(self):
        self.assertTrue(self.s1.replay.check_and_store("old", 3, 0))
        r = self.s1.backend._r
        for k in list(r.scan_iter(match=f"{self.prefix}:*")):
            r.delete(k)                                                       # simulate restart without persistence
        with self.assertRaises(StateUnavailableError):
            self.s2.replay.check_and_store("old", 3, 0)
        time.sleep(3.3)
        self.assertTrue(self.s2.replay.check_and_store("fresh", 30, 0))

    def test_revocation_cache_and_identity_cache_across_instances_with_real_service(self):
        base, clock = make_service()
        a, i, c = make_agent(base)

        def instance(st):
            agents, revs = st.wrap_storage(base.agents, base.revocations)
            return IdentityService(IdentityConfig(log_to_python_logging=False), clock=clock, keystore=base.keystore,
                                   agents=agents, credentials=base.credentials, revocations=revs, trust=base.trust,
                                   replay=st.replay, root_key_id=base.root_key_id)
        x, y = instance(self.s1), instance(self.s2)
        self.assertTrue(x.verify_credential(c.token, require_proof=False).valid)
        self.assertTrue(y.verify_credential(c.token, require_proof=False).valid)
        hits = self.s1.metrics.total(C.HIT)
        self.assertTrue(x.verify_credential(c.token, require_proof=False).valid)
        self.assertGreater(self.s1.metrics.total(C.HIT), hits)               # Redis really served it
        x.revoke_credential(c.credential_id, RevocationReason.COMPROMISE, "t")
        self.assertFalse(y.verify_credential(c.token, require_proof=False).valid)


@unittest.skipUnless(ON, "set AGENTGUARD_TEST_REDIS_HOST for real Redis tests")
class Failure(unittest.TestCase):
    def test_unreachable_redis_fails_closed(self):
        st = build_security_state(rcfg(new_prefix(), host="127.0.0.1", port=1, retry_attempts=2,
                                       connect_timeout_seconds=0.5))
        with self.assertRaises(StateUnavailableError):
            st.replay.check_and_store("k", 10, 0)
        self.assertFalse(st.limiter.allow(BucketPolicy("p", 1, 1), "acme", "agent", "a").allowed)
        self.assertIsNone(st.locks.acquire("acme", "x"))
        self.assertFalse(st.health()["ready"])
        st.close()

    @unittest.skipUnless(PW, "needs a password-protected test Redis")
    def test_wrong_password_is_safe(self):
        bad = "WRONG-" + secrets.token_hex(4)
        st = build_security_state(rcfg(new_prefix(), password=bad, retry_attempts=1))
        with self.assertRaises(StateUnavailableError) as cm:
            st.replay.check_and_store("k", 10, 0)
        self.assertNotIn(bad, str(cm.exception))
        self.assertNotIn(PW, str(cm.exception))
        st.close()


if __name__ == "__main__":
    unittest.main()
