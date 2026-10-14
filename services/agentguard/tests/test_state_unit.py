"""Redis security-state tests that need NO Redis (MemoryBackend implements identical semantics; the same
contract suite runs on real Redis in tests/test_state_integration.py)."""
import concurrent.futures as cf
import json
import os
import threading
import unittest
from unittest import mock

from agent_identity import IdentityConfig, IdentityService
from agent_identity.core.errors import StorageError
from agent_identity.core.models import RevocationReason, RevocationRecord, TargetType
from agent_identity.spiffe import metrics as M
from agent_identity.spiffe.config import Environment
from agent_identity.state import (BucketPolicy, KeyBuilder, LockNotAcquired, MemoryBackend, RedisConfig,
                                  StateConfigError, StateConflictError, StateCorruptError,
                                  StateUnavailableError, WindowPolicy, build_security_state)
from agent_identity.state import cache as C
from agent_identity.state import redis_backend as RB
from agent_identity.state.backend import StateBackend
from agent_identity.state.locks import DistributedLock, LockHandle
from agent_identity.state.ratelimit import DistributedRateLimiter
from agent_identity.state.redis_backend import RedisBackend
from agent_identity.state.replay import RedisReplayCache
from agent_identity.state.tempstate import TempStateStore
from agent_identity.storage.memory import MemoryAgentRegistry, MemoryReplayCache, MemoryRevocationRegistry
from agent_identity.storage.postgres import require_durable_or_raise
from tests.helpers import make_agent, make_service
from tests.state_contract import BackendContract

SECRET = "R3dis-Passw0rd-XYZ"


class Clock:
    def __init__(self):
        self.ms = 1_000_000.0

    def __call__(self):
        return self.ms


class MemoryContract(BackendContract, unittest.TestCase):
    def setUp(self):
        self.clk = Clock()
        self.b = MemoryBackend(now_ms=self.clk)
        self.k = "t"

    def sleep_ms(self, ms):
        self.clk.ms += ms


class Down(StateBackend):
    """Backend whose every call fails like an outage (all abstract methods raise)."""
    def _f(self, *a, **k):
        raise StateUnavailableError("down")
    set_if_absent = set = get = delete = compare_and_delete = compare_and_extend = compare_and_set = _f
    token_bucket = window_incr = replay_check = ping = _f


def cfg(**kw):
    d = dict(environment="development", host="r", tls=False)
    d.update(kw)
    return RedisConfig(**d).validate()


class Keys(unittest.TestCase):
    def setUp(self):
        self.kb = KeyBuilder("production")

    def test_format_and_cluster_hash_tag(self):
        k = self.kb.key("acme", "replay", "nonce", "abc")
        self.assertEqual(k, "agentguard:v1:{production.acme}:replay:nonce:abc")

    def test_injection_and_ambiguity_rejected(self):
        for bad in ("a:b", "a{b", "a}b", "a*b", "a b", "a\nb", "", "x" * 129, "a/../b", "é", "a\x00b"):
            with self.assertRaises(StateConfigError):
                self.kb.key("acme", "d", "r", bad)
            with self.assertRaises(StateConfigError):
                self.kb.key(bad, "d", "r", "x")
        for bad in ("A", "1x", "a:b", "", "x" * 40):
            with self.assertRaises(StateConfigError):
                self.kb.key("acme", bad, "r", "x")
        with self.assertRaises(StateConfigError):
            KeyBuilder("prod")

    def test_tenants_and_environments_never_collide(self):
        a = KeyBuilder("production").key("acme", "d", "r", "1")
        self.assertNotEqual(a, KeyBuilder("production").key("globex", "d", "r", "1"))
        self.assertNotEqual(a, KeyBuilder("staging").key("acme", "d", "r", "1"))
        # a tenant id cannot smuggle another namespace
        with self.assertRaises(StateConfigError):
            self.kb.key("acme}:replay:nonce:x{globex", "d", "r", "1")

    def test_hashed_never_contains_raw_value(self):
        k = self.kb.hashed("acme", "replay", "nonce", "cred_1:SECRET-NONCE")
        self.assertNotIn("SECRET", k)
        self.assertEqual(k, self.kb.hashed("acme", "replay", "nonce", "cred_1:SECRET-NONCE"))

    def test_scoped_keys_fixed_to_tenant(self):
        s = self.kb.scoped("acme")
        self.assertIn("{production.acme}", s.key("d", "r", "1"))
        self.assertFalse(hasattr(s, "for_tenant"))
        with self.assertRaises(StateConfigError):
            self.kb.scoped("bad:tenant")


class Config(unittest.TestCase):
    def test_production_requires_tls_hostname_check_and_auth(self):
        base = dict(environment="production", host="r", tls=True, password=SECRET)
        RedisConfig(**base).validate()
        for kw in (dict(tls=False), dict(tls_check_hostname=False), dict(password=""),
                   dict(tls_client_cert="/c.pem")):
            with self.assertRaises(StateConfigError):
                RedisConfig(**{**base, **kw}).validate()

    def test_process_env_can_only_tighten(self):
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production"}):
            with self.assertRaises(StateConfigError):
                cfg()

    def test_url_with_credentials_rejected_and_parsing(self):
        env = {"AGENTGUARD_ENV": "development"}
        with self.assertRaises(StateConfigError):
            RedisConfig.from_env({**env, "AGENTGUARD_REDIS_URL": f"rediss://user:{SECRET}@h:6380/0"})
        c = RedisConfig.from_env({**env, "AGENTGUARD_REDIS_URL": "redis://cache.local:6380/2"})
        self.assertEqual((c.host, c.port, c.db, c.tls), ("cache.local", 6380, 2, False))
        with self.assertRaises(StateConfigError):
            RedisConfig.from_env({**env, "AGENTGUARD_REDIS_URL": "http://x"})

    def test_password_never_in_repr_or_safe_dict_and_bounds(self):
        c = cfg(password=SECRET)
        self.assertNotIn(SECRET, repr(c) + str(c.safe_dict()))
        for kw in (dict(host=""), dict(mode="x"), dict(command_timeout_seconds=0), dict(replay_max_ttl_seconds=0),
                   dict(cache_ttl_agent_seconds=10 ** 9), dict(pool_max_connections=0), dict(port=0)):
            with self.assertRaises(StateConfigError):
                cfg(**kw)


class Replay(unittest.TestCase):
    def setUp(self):
        self.clk, self.m = Clock(), M.Metrics()
        self.b = MemoryBackend(now_ms=self.clk)
        self.r = RedisReplayCache(self.b, KeyBuilder("development"), metrics=self.m)
        self.r.ensure_marker()

    def test_first_ok_repeat_denied_and_expires(self):
        self.assertTrue(self.r.check_and_store("cred:n1", 10, 0))
        self.assertFalse(self.r.check_and_store("cred:n1", 10, 0))
        self.assertEqual(self.m.get("agentguard_replay_rejected_total"), 1)
        self.clk.ms += 11_000
        self.assertTrue(self.r.check_and_store("cred:n1", 10, 0))

    def test_concurrent_identical_requests_single_winner(self):
        with cf.ThreadPoolExecutor(32) as ex:
            res = list(ex.map(lambda _: self.r.check_and_store("cred:race", 30, 0), range(100)))
        self.assertEqual(res.count(True), 1)

    def test_invalid_ttl_and_key_rejected_not_shortened(self):
        for ttl in (0, -1, 86401):
            with self.assertRaises(StorageError):
                self.r.check_and_store("k", ttl, 0)
        with self.assertRaises(StorageError):
            self.r.check_and_store("", 5, 0)

    def test_raw_nonce_never_stored_in_key(self):
        self.r.check_and_store("cred_77:TOP-SECRET-NONCE", 10, 0)
        for key in self.b._d:
            self.assertNotIn("TOP-SECRET", key)

    def test_state_loss_quarantines_instead_of_allowing_replays(self):
        self.assertTrue(self.r.check_and_store("cred:old", 60, 0))
        self.b._d.clear()                                           # simulate Redis restart without persistence
        with self.assertRaises(StateUnavailableError):
            self.r.check_and_store("cred:old", 60, 0)               # replay of a pre-loss nonce is NOT accepted
        with self.assertRaises(StateUnavailableError):
            self.r.check_and_store("cred:other", 60, 0)             # all checks refused during the window
        self.assertEqual(self.m.get("agentguard_replay_quarantined_total"), 2)
        self.clk.ms += 61_000
        self.assertTrue(self.r.check_and_store("cred:new", 60, 0))

    def test_outage_raises_never_allows(self):
        r = RedisReplayCache(Down(), KeyBuilder("development"))
        with self.assertRaises(StateUnavailableError):
            r.check_and_store("k", 5, 0)
        r.ensure_marker()                                           # startup with Redis down must not crash

    def test_service_verification_denies_replay_and_denies_on_redis_outage(self):
        svc, _ = make_service()
        svc.verifier.replay = self.r
        _, _, c = make_agent(svc)
        proof = svc.create_proof(c.token, "gw")
        self.assertTrue(svc.verify_credential(c.token, proof=proof, audience="gw").valid)
        again = svc.verify_credential(c.token, proof=proof, audience="gw")
        self.assertFalse(again.valid)
        svc.verifier.replay = RedisReplayCache(Down(), KeyBuilder("development"))
        out = svc.verify_credential(c.token, proof=svc.create_proof(c.token, "gw"), audience="gw")
        self.assertFalse(out.valid)                                 # fail closed, no local fallback


class RateLimits(unittest.TestCase):
    def setUp(self):
        self.clk, self.m = Clock(), M.Metrics()
        self.b = MemoryBackend(now_ms=self.clk)
        self.rl = DistributedRateLimiter(self.b, KeyBuilder("development"), self.m)

    def test_bucket_burst_sustained_and_isolation(self):
        p = BucketPolicy("api", rate_per_sec=2, burst=3)
        d = [self.rl.allow(p, "acme", "agent", "a1") for _ in range(4)]
        self.assertEqual([x.allowed for x in d], [True, True, True, False])
        self.assertGreater(d[-1].retry_after_ms, 0)
        self.assertTrue(self.rl.allow(p, "acme", "agent", "a2").allowed)        # other agent unaffected
        self.assertTrue(self.rl.allow(p, "globex", "agent", "a1").allowed)      # other tenant unaffected
        self.clk.ms += 1000
        self.assertTrue(self.rl.allow(p, "acme", "agent", "a1").allowed)        # refilled
        self.assertEqual(self.m.get("agentguard_ratelimit_rejected_total", "api"), 1)

    def test_window_auth_failure_limit(self):
        p = WindowPolicy("authfail", limit=3, window_seconds=60)
        self.assertEqual([self.rl.hit(p, "acme", "ip", "203.0.113.9").allowed for _ in range(5)],
                         [True, True, True, False, False])
        self.clk.ms += 61_000
        self.assertTrue(self.rl.hit(p, "acme", "ip", "203.0.113.9").allowed)

    def test_two_limiter_instances_share_one_budget(self):
        other = DistributedRateLimiter(self.b, KeyBuilder("development"))     # "second AgentGuard instance"
        p = BucketPolicy("issue", rate_per_sec=0.001, burst=10)
        def go(i):
            return (self.rl if i % 2 else other).allow(p, "acme", "tenant", "acme").allowed
        with cf.ThreadPoolExecutor(16) as ex:
            res = list(ex.map(go, range(100)))
        self.assertEqual(res.count(True), 10)

    def test_ips_are_hashed_in_keys_and_bad_inputs_rejected(self):
        self.rl.hit(WindowPolicy("authfail", 3, 60), "acme", "ip", "203.0.113.9")
        for key in self.b._d:
            self.assertNotIn("203.0.113.9", key)
        with self.assertRaises(StateConfigError):
            self.rl.allow(BucketPolicy("x", 1, 1), "acme", "weird", "s")
        with self.assertRaises(StateConfigError):
            self.rl.allow(BucketPolicy("x", 1, 1, on_error="allow"), "acme", "ip", "s")
        with self.assertRaises(StateConfigError):
            self.rl.allow(BucketPolicy("bad:name", 1, 1), "acme", "ip", "s")

    def test_outage_policy_deny_vs_local(self):
        rl = DistributedRateLimiter(Down(), KeyBuilder("development"), self.m)
        d = rl.allow(BucketPolicy("api", 1, 1), "acme", "agent", "a")
        self.assertFalse(d.allowed)
        self.assertTrue(d.degraded)                                          # default: fail closed
        loc = BucketPolicy("api2", 0.001, 2, on_error="local")
        res = [rl.allow(loc, "acme", "agent", "a").allowed for _ in range(3)]
        self.assertEqual(res, [True, True, False])                           # bounded per-process fallback
        self.assertFalse(rl.hit(WindowPolicy("w", 5, 60), "acme", "ip", "x").allowed)
        self.assertGreaterEqual(self.m.total("agentguard_ratelimit_degraded_total"), 3)


class Locks(unittest.TestCase):
    def setUp(self):
        self.clk = Clock()
        self.b = MemoryBackend(now_ms=self.clk)
        self.kb = KeyBuilder("development")
        self.sec = lambda: self.clk.ms / 1000.0
        self.lk = DistributedLock(self.b, self.kb, clock=self.sec, sleep=lambda s: None)

    def test_single_owner_under_concurrency(self):
        with cf.ThreadPoolExecutor(16) as ex:
            res = list(ex.map(lambda _: self.lk.acquire("acme", "rotate-agent-1", ttl_seconds=30), range(40)))
        self.assertEqual(len([h for h in res if h]), 1)

    def test_release_only_by_owner_and_never_frees_foreign_lock(self):
        h1 = self.lk.acquire("acme", "job", ttl_seconds=5)
        impostor = LockHandle(self.lk, h1.key, "forged-token", 5000, self.sec)
        self.assertFalse(impostor.release())
        self.assertIsNone(self.lk.acquire("acme", "job", ttl_seconds=5))      # still held
        self.assertTrue(h1.release())
        self.assertFalse(h1.release())                                        # double release is a no-op
        self.assertIsNotNone(self.lk.acquire("acme", "job", ttl_seconds=5))

    def test_expired_lock_is_not_released_by_old_owner(self):
        h1 = self.lk.acquire("acme", "job", ttl_seconds=5)
        self.clk.ms += 6000
        self.assertFalse(h1.held())
        h2 = self.lk.acquire("acme", "job", ttl_seconds=5)
        self.assertIsNotNone(h2)
        self.assertFalse(h1.release())                                        # stale owner cannot delete h2's lock
        self.assertIsNone(self.lk.acquire("acme", "job", ttl_seconds=5))
        self.assertEqual(self.lk.metrics.get("agentguard_lock_release_lost_total"), 1)

    def test_extend_only_by_owner(self):
        h = self.lk.acquire("acme", "job", ttl_seconds=5)
        self.assertTrue(h.extend(20))
        self.clk.ms += 10_000
        self.assertIsNone(self.lk.acquire("acme", "job", ttl_seconds=5))      # extension held
        self.assertFalse(LockHandle(self.lk, h.key, "x", 1000, self.sec).extend(5))

    def test_wait_with_backoff_and_failure_modes(self):
        h = self.lk.acquire("acme", "job", ttl_seconds=5)
        calls = []
        def sleeper(s):
            calls.append(s)
            self.clk.ms += 3000
        lk = DistributedLock(self.b, self.kb, clock=self.sec, sleep=sleeper)
        got = lk.acquire("acme", "job", ttl_seconds=5, wait_seconds=10)       # lock expires while we wait
        self.assertIsNotNone(got)
        self.assertTrue(calls)
        with self.assertRaises(LockNotAcquired):
            lk.acquire("acme", "job", wait_seconds=0, raise_on_fail=True)
        down = DistributedLock(Down(), self.kb)
        self.assertIsNone(down.acquire("acme", "job"))                        # outage => NOT acquired
        with self.assertRaises(StateUnavailableError):
            down.acquire("acme", "job", raise_on_fail=True)

    def test_tenant_isolation_and_name_validation(self):
        self.assertIsNotNone(self.lk.acquire("acme", "job", ttl_seconds=5))
        self.assertIsNotNone(self.lk.acquire("globex", "job", ttl_seconds=5))  # same name, other tenant: independent
        with self.assertRaises(StateConfigError):
            self.lk.acquire("acme", "job}:x{", ttl_seconds=5)

    def test_context_manager_releases(self):
        with self.lk.acquire("acme", "ctx", ttl_seconds=5):
            self.assertIsNone(self.lk.acquire("acme", "ctx"))
        self.assertIsNotNone(self.lk.acquire("acme", "ctx"))


class TempState(unittest.TestCase):
    def setUp(self):
        self.t = [1_800_000_000.0]
        self.clk = Clock()
        self.b = MemoryBackend(now_ms=self.clk)
        self.store = TempStateStore(self.b, KeyBuilder("development"), clock=lambda: self.t[0], max_ttl_seconds=600)
        self.A, self.B = self.store.for_tenant("acme"), self.store.for_tenant("globex")

    def adv(self, s):
        self.t[0] += s
        self.clk.ms += s * 1000

    def test_lifecycle_ttl_and_metadata(self):
        r = self.A.put("approval", "ap1", owner="agent-1", ttl_seconds=60, data={"scope": "read"}, ctx_version=3)
        self.assertEqual((r.tenant, r.owner, r.status, r.ctx_version), ("acme", "agent-1", "pending", 3))
        self.assertEqual(self.A.get("approval", "ap1").data, {"scope": "read"})
        self.adv(61)
        self.assertIsNone(self.A.get("approval", "ap1"))

    def test_ttl_required_and_bounded_ids_unique(self):
        for ttl in (0, -1, 601):
            with self.assertRaises(StateConfigError):
                self.A.put("grant", "g", owner="o", ttl_seconds=ttl)
        self.A.put("grant", "g1", owner="o", ttl_seconds=10)
        with self.assertRaises(StateConfigError):
            self.A.put("grant", "g1", owner="o", ttl_seconds=10)               # create-only
        with self.assertRaises(StateConfigError):
            self.A.put("nonsense", "x", owner="o", ttl_seconds=10)

    def test_transition_is_atomic_single_winner(self):
        self.A.put("approval", "ap2", owner="o", ttl_seconds=60)
        def go(i):
            try:
                self.A.transition("approval", "ap2", expected_status="pending", new_status=f"decided{i}")
                return True
            except StateConflictError:
                return False
        with cf.ThreadPoolExecutor(16) as ex:
            res = list(ex.map(go, range(32)))
        self.assertEqual(res.count(True), 1)

    def test_consume_is_single_use(self):
        self.A.put("challenge", "ch1", owner="o", ttl_seconds=60)
        with cf.ThreadPoolExecutor(16) as ex:
            res = list(ex.map(lambda _: self.A.consume("challenge", "ch1"), range(32)))
        self.assertEqual(len([r for r in res if r]), 1)
        self.assertIsNone(self.A.get("challenge", "ch1"))

    def test_cross_tenant_cannot_read_overwrite_consume_or_revoke(self):
        self.A.put("grant", "g9", owner="o", ttl_seconds=60, data={"x": 1})
        self.assertIsNone(self.B.get("grant", "g9"))
        self.assertIsNone(self.B.consume("grant", "g9"))
        self.assertFalse(self.B.revoke("grant", "g9"))
        with self.assertRaises(StateConflictError):
            self.B.transition("grant", "g9", expected_status="pending", new_status="x")
        self.B.put("grant", "g9", owner="evil", ttl_seconds=60)                 # same id in B: separate record
        self.assertEqual(self.A.get("grant", "g9").owner, "o")

    def test_planted_or_copied_records_are_rejected(self):
        self.A.put("grant", "g5", owner="o", ttl_seconds=60)
        ka = self.A._key("grant", "g5")
        raw = self.b_get(ka)
        kb_ = self.B._key("grant", "g5")
        self.B._b.set(kb_, raw, 60_000)
        with self.assertRaises(StateCorruptError):                              # tenant field != key's tenant
            self.B.get("grant", "g5")
        self.B._b.set(self.B._key("grant", "bad"), b"{not json", 60_000)
        with self.assertRaises(StateCorruptError):
            self.B.get("grant", "bad")
        self.B._b.set(self.B._key("grant", "bad2"), json.dumps({"k": "grant"}), 60_000)
        with self.assertRaises(StateCorruptError):
            self.B.get("grant", "bad2")

    def b_get(self, k):
        return self.A._b.get(k)

    def test_tampered_expiry_is_defence_in_depth(self):
        self.A.put("grant", "g6", owner="o", ttl_seconds=60)
        k = self.A._key("grant", "g6")
        o = json.loads(self.A._b.get(k))
        o["e"] = self.t[0] - 1                                                  # expiry in the past, TTL still alive
        self.A._b.set(k, json.dumps(o), 60_000)
        with self.assertRaises(StateConflictError):
            self.A.get("grant", "g6")


class Cache(unittest.TestCase):
    def setUp(self):
        self.b = MemoryBackend(now_ms=Clock())
        self.kb = KeyBuilder("development")
        self.m = M.Metrics()
        self.vc = lambda **kw: C.VersionedCache(self.b, self.kb, domain="revcache", ttl_seconds=10,
                                                metrics=self.m, **kw)

    def _rev(self, i, eff=1.0):
        return RevocationRecord(TargetType.CREDENTIAL, i, RevocationReason.COMPROMISE, 1.0, "t", eff, None)

    def test_hit_miss_negative_and_invalidation_across_instances(self):
        inner = MemoryRevocationRegistry()
        a = C.CachedRevocationRegistry(inner, self.vc())
        b = C.CachedRevocationRegistry(inner, self.vc())                         # second AgentGuard instance
        self.assertIsNone(a.get(TargetType.CREDENTIAL, "c1"))                    # miss + negative cached
        self.assertIsNone(b.get(TargetType.CREDENTIAL, "c1"))
        self.assertGreaterEqual(self.m.get(C.HIT, "rev"), 1)
        a.add(self._rev("c1"))                                                   # PG first, then invalidate
        got = b.get(TargetType.CREDENTIAL, "c1")                                 # other instance sees it NOW
        self.assertIsNotNone(got)
        self.assertEqual(got.reason, RevocationReason.COMPROMISE)

    def test_stale_negative_entry_cannot_survive_a_concurrent_commit(self):
        """Reader reads version, then the writer commits+invalidates DURING the reader's DB read:
        the reader's entry carries the old version and must never be served afterwards."""
        inner = MemoryRevocationRegistry()
        cache = self.vc()
        reg = C.CachedRevocationRegistry(inner, cache)
        real_get = inner.get
        def racing_get(tt, tid):
            old = real_get(tt, tid)                      # reader sees "not revoked"
            inner.add(self._rev(tid))                    # writer commits ...
            cache.invalidate("rev", f"{tt.value}:{tid}")  # ... and invalidates
            return old
        inner.get = racing_get
        self.assertIsNone(reg.get(TargetType.CREDENTIAL, "c2"))                  # reader returns its (old) read once
        inner.get = real_get
        self.assertIsNotNone(reg.get(TargetType.CREDENTIAL, "c2"))               # but the stale entry is NOT served

    def test_redis_outage_bypasses_to_authoritative_store(self):
        inner = MemoryRevocationRegistry()
        inner.add(self._rev("c3"))
        reg = C.CachedRevocationRegistry(inner, C.VersionedCache(Down(), self.kb, domain="revcache",
                                                                 ttl_seconds=10, metrics=self.m))
        self.assertIsNotNone(reg.get(TargetType.CREDENTIAL, "c3"))               # still correct, just uncached
        self.assertIsNone(reg.get(TargetType.CREDENTIAL, "nope"))
        self.assertGreaterEqual(self.m.get(C.BYPASS, "rev"), 2)
        reg.add(self._rev("c4"))                                                 # write path survives; failure counted
        self.assertEqual(self.m.get(C.INVALIDATE_FAILED, "rev"), 1)

    def test_authoritative_errors_propagate_not_swallowed(self):
        class Boom(MemoryRevocationRegistry):
            def get(self, *a):
                raise StorageError("pg down")
        reg = C.CachedRevocationRegistry(Boom(), self.vc())
        with self.assertRaises(StorageError):
            reg.get(TargetType.CREDENTIAL, "c")

    def test_corrupted_entries_are_misses_and_are_replaced(self):
        inner = MemoryRevocationRegistry()
        inner.add(self._rev("c5"))
        cache = self.vc()
        reg = C.CachedRevocationRegistry(inner, cache)
        reg.get(TargetType.CREDENTIAL, "c5")
        _, ekey = cache._keys("rev", "credential:c5")
        for junk in (b"\x00\xff", b"{}", b'{"v":"x","n":false,"d":{"tt":"bogus"}}'):
            self.b.set(ekey, junk, 10_000)
            self.assertIsNotNone(reg.get(TargetType.CREDENTIAL, "c5"))
        self.assertGreaterEqual(self.m.total(C.CORRUPT), 1)

    def test_entry_ttl_bounds_staleness_when_invalidation_is_lost(self):
        clk = Clock()
        b = MemoryBackend(now_ms=clk)
        inner = MemoryRevocationRegistry()
        cache = C.VersionedCache(b, self.kb, domain="revcache", ttl_seconds=10, metrics=self.m)
        reg = C.CachedRevocationRegistry(inner, cache)
        self.assertIsNone(reg.get(TargetType.CREDENTIAL, "c6"))
        inner.add(self._rev("c6"))                                               # commit, invalidation LOST
        self.assertIsNone(reg.get(TargetType.CREDENTIAL, "c6"))                  # stale within TTL (documented bound)
        clk.ms += 11_000
        self.assertIsNotNone(reg.get(TargetType.CREDENTIAL, "c6"))               # never beyond TTL

    def test_agent_registry_cache_roundtrip_and_status_change_visible_everywhere(self):
        from dataclasses import replace
        from agent_identity.core.models import Status
        svc, _ = make_service()
        a, i, _c = make_agent(svc)
        rec = svc.agents.get_agent(a["agent_id"])
        inner = MemoryAgentRegistry()
        inner.put_org(svc.agents.get_org("acme"))
        inner.put_agent(rec)
        c1 = C.CachedAgentRegistry(inner, C.VersionedCache(self.b, self.kb, domain="idcache", ttl_seconds=30))
        c2 = C.CachedAgentRegistry(inner, C.VersionedCache(self.b, self.kb, domain="idcache", ttl_seconds=30))
        self.assertEqual(c1.get_agent(rec.agent_id), rec)                        # exact round trip incl. tuples/enums
        self.assertEqual(c2.get_agent(rec.agent_id), rec)
        self.assertEqual(c2.get_org("acme"), inner.get_org("acme"))
        c1.put_agent(replace(rec, status=Status.TERMINATED))
        self.assertEqual(c2.get_agent(rec.agent_id).status, Status.TERMINATED)   # no stale ACTIVE
        self.assertIsNone(c2.get_agent("agt_missing"))

    def test_no_private_key_material_in_cached_values(self):
        svc, _ = make_service()
        a, _i, _c = make_agent(svc)
        inner = MemoryAgentRegistry()
        inner.put_org(svc.agents.get_org("acme"))
        inner.put_agent(svc.agents.get_agent(a["agent_id"]))
        reg = C.CachedAgentRegistry(inner, C.VersionedCache(self.b, self.kb, domain="idcache", ttl_seconds=30))
        reg.get_agent(a["agent_id"])
        blob = b" ".join(v[0] if isinstance(v[0], bytes) else b"" for v in self.b._d.values()).lower()
        self.assertNotIn(b"private", blob)

    def test_full_service_with_shared_redis_state_across_two_instances(self):
        """Two IdentityService instances share one PG-like store (memory here) + one Redis-like backend."""
        base, clock = make_service()
        a, i, c = make_agent(base)
        state = build_security_state(cfg(), backend=self.b)

        def instance():                                   # an independent "AgentGuard instance"
            agents, revs = state.wrap_storage(base.agents, base.revocations)
            return IdentityService(IdentityConfig(log_to_python_logging=False), clock=clock, keystore=base.keystore,
                                   agents=agents, credentials=base.credentials, revocations=revs, trust=base.trust,
                                   replay=state.replay, root_key_id=base.root_key_id)
        s2, s3 = instance(), instance()
        self.assertTrue(s2.verify_credential(c.token, require_proof=False).valid)
        self.assertTrue(s3.verify_credential(c.token, require_proof=False).valid)     # both now hold cache entries
        s2.revoke_credential(c.credential_id, RevocationReason.COMPROMISE, "t")      # revoke via instance 2
        r = s3.verify_credential(c.token, require_proof=False)                       # instance 3 must deny at once
        self.assertFalse(r.valid)
        self.assertFalse(s2.verify_credential(c.token, require_proof=False).valid)

    def test_agent_termination_via_one_instance_denies_on_another(self):
        base, clock = make_service()
        a, i, c = make_agent(base)
        state = build_security_state(cfg(), backend=self.b)

        def instance():
            agents, revs = state.wrap_storage(base.agents, base.revocations)
            return IdentityService(IdentityConfig(log_to_python_logging=False), clock=clock, keystore=base.keystore,
                                   agents=agents, credentials=base.credentials, revocations=revs, trust=base.trust,
                                   replay=state.replay, root_key_id=base.root_key_id)
        s2, s3 = instance(), instance()
        self.assertTrue(s3.verify_credential(c.token, require_proof=False).valid)
        s2.revoke_agent(a["agent_id"], RevocationReason.AGENT_TERMINATED, "t")
        self.assertFalse(s3.verify_credential(c.token, require_proof=False).valid)


class Guards(unittest.TestCase):
    def test_local_replay_rejected_in_production_unless_explicitly_allowed(self):
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production"}):
            with self.assertRaises(StorageError):
                require_durable_or_raise(replay=MemoryReplayCache())
            require_durable_or_raise(replay=RedisReplayCache(MemoryBackend(), KeyBuilder("production")))
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production", "AGENTGUARD_ALLOW_LOCAL_REPLAY": "1"}):
            require_durable_or_raise(replay=MemoryReplayCache())

    def test_service_service_kwargs_wires_everything(self):
        class PG:
            agents, revocations = MemoryAgentRegistry(), MemoryRevocationRegistry()
            def service_kwargs(self):
                return {"agents": self.agents, "revocations": self.revocations, "credentials": object()}
        st = build_security_state(cfg(), backend=MemoryBackend())
        kw = st.service_kwargs(PG())
        self.assertIsInstance(kw["agents"], C.CachedAgentRegistry)
        self.assertIsInstance(kw["revocations"], C.CachedRevocationRegistry)
        self.assertIs(kw["replay"], st.replay)
        self.assertTrue(st.health()["ready"])


class FakeRedisErr(Exception):
    pass


class ConnectionError(FakeRedisErr):            # same class NAMES as redis-py => classified like the real ones
    pass


class TimeoutError(FakeRedisErr):
    pass


class AuthenticationError(FakeRedisErr):
    pass


class ResponseError(FakeRedisErr):
    pass


class ReadOnlyError(FakeRedisErr):
    pass


class FakeClient:
    def __init__(self, errors=()):
        self.errors, self.calls, self.closed = list(errors), 0, False
        self.store = {}

    def register_script(self, lua):
        def run(keys, args):
            return self._maybe(lambda: 1)
        return run

    def _maybe(self, ok):
        self.calls += 1
        if self.errors:
            e = self.errors.pop(0)
            if e:
                raise e
        return ok()

    def set(self, k, v, nx=False, px=None):
        return self._maybe(lambda: True)

    def get(self, k):
        return self._maybe(lambda: b"v")

    def delete(self, k):
        return self._maybe(lambda: 1)

    def ping(self):
        return self._maybe(lambda: True)

    def close(self):
        self.closed = True


class RedisBackendBehaviour(unittest.TestCase):
    def mk(self, errors=(), **kw):
        self.c = FakeClient(errors)
        return RedisBackend(cfg(retry_attempts=3, **kw), client=self.c, sleep=lambda s: None)

    def test_retry_on_connection_and_timeout_then_success(self):
        b = self.mk([ConnectionError(f"x {SECRET}"), TimeoutError("t"), None])
        self.assertEqual(b.get("k"), b"v")
        self.assertEqual(self.c.calls, 3)
        self.assertEqual(b.metrics.get(RB.RETRIES, "get"), 2)
        self.assertEqual(b.metrics.get(RB.RECONNECTS), 1)

    def test_exhausted_retries_fail_with_safe_message(self):
        b = self.mk([ConnectionError(f"redis://u:{SECRET}@h") for _ in range(3)])
        with self.assertRaises(StateUnavailableError) as cm:
            b.get("k")
        self.assertNotIn(SECRET, str(cm.exception))
        self.assertEqual(self.c.calls, 3)

    def test_auth_and_readonly_and_other_are_not_retried(self):
        for err in (AuthenticationError(SECRET), ReadOnlyError("replica"), RuntimeError(SECRET)):
            b = self.mk([err, None])
            with self.assertRaises(StateUnavailableError) as cm:
                b.set("k", "v", 1000)
            self.assertNotIn(SECRET, str(cm.exception))
            self.assertEqual(self.c.calls, 1)

    def test_response_error_is_corrupt_not_unavailable(self):
        b = self.mk([ResponseError(f"WRONGTYPE {SECRET}")])
        with self.assertRaises(StateCorruptError) as cm:
            b.get("k")
        self.assertNotIn(SECRET, str(cm.exception))

    def test_logs_never_contain_driver_text(self):
        b = self.mk([AuthenticationError(f"bad password {SECRET}")])
        with self.assertLogs("agentguard.redis", level="WARNING") as lg:
            with self.assertRaises(StateUnavailableError):
                b.get("k")
        self.assertNotIn(SECRET, "\n".join(lg.output))

    def test_ping_false_on_outage_and_closed_backend_denies(self):
        b = self.mk([ConnectionError("x")] * 3)
        self.assertFalse(b.ping())
        b.close()
        self.assertTrue(self.c.closed)
        with self.assertRaises(StateUnavailableError):
            b.get("k")

    def test_ttl_validated_before_any_network_call(self):
        b = self.mk()
        with self.assertRaises(StateConfigError):
            b.set("k", "v", 0)
        with self.assertRaises(StateConfigError):
            b.set_if_absent("k", "v", -1)
        self.assertEqual(self.c.calls, 0)

    def test_scripts_registered_and_pool_stats_safe(self):
        b = self.mk()
        self.assertEqual(set(b._scripts), {"cad", "cae", "cas", "bucket", "window", "replay"})
        self.assertEqual(b.pool_stats(), {})

    def test_lua_scripts_are_single_key_slot_safe_and_atomic_by_construction(self):
        for name in ("_CAD", "_CAE", "_CAS", "_BUCKET", "_WINDOW", "_REPLAY"):
            lua = getattr(RB, name)
            self.assertNotIn("redis.call('KEYS'", lua)           # no key scans
            self.assertNotIn("FLUSH", lua.upper())
        self.assertIn("KEEPTTL", RB._CAS)


if __name__ == "__main__":
    unittest.main()
