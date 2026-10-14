"""Backend contract: the SAME behavioural tests run on MemoryBackend (unit) and RedisBackend (integration)."""
import concurrent.futures as cf
import secrets

from agent_identity.state.errors import StateConfigError


class BackendContract:
    b = None            # StateBackend under test
    k = ""              # unique key prefix per test run

    def key(self, n):
        return f"{self.k}:{n}"

    def sleep_ms(self, ms):               # provided by the concrete test class
        raise NotImplementedError

    def test_set_if_absent_is_atomic_under_concurrency(self):
        key = self.key("nx" + secrets.token_hex(3))
        with cf.ThreadPoolExecutor(32) as ex:
            res = list(ex.map(lambda i: self.b.set_if_absent(key, f"v{i}", 5000), range(64)))
        self.assertEqual(res.count(True), 1)

    def test_ttl_is_mandatory_and_enforced(self):
        key = self.key("ttl" + secrets.token_hex(3))
        for bad in (0, -5, None, True, 40 * 86400_000):
            with self.assertRaises(StateConfigError):
                self.b.set(key, "x", bad)
            with self.assertRaises(StateConfigError):
                self.b.set_if_absent(key, "x", bad)
        self.b.set(key, "x", 150)
        self.assertEqual(self.b.get(key), b"x")
        self.sleep_ms(300)
        self.assertIsNone(self.b.get(key))
        self.assertTrue(self.b.set_if_absent(key, "y", 5000))          # expired key is free again

    def test_value_size_bounded(self):
        with self.assertRaises(StateConfigError):
            self.b.set(self.key("big"), b"x" * (64 * 1024 + 1), 1000)

    def test_compare_and_delete_only_for_owner(self):
        key = self.key("cad" + secrets.token_hex(3))
        self.b.set(key, "tokA", 5000)
        self.assertFalse(self.b.compare_and_delete(key, "tokB"))
        self.assertEqual(self.b.get(key), b"tokA")
        self.assertTrue(self.b.compare_and_delete(key, "tokA"))
        self.assertFalse(self.b.compare_and_delete(key, "tokA"))

    def test_compare_and_extend(self):
        key = self.key("cae" + secrets.token_hex(3))
        self.b.set(key, "t", 200)
        self.assertFalse(self.b.compare_and_extend(key, "other", 5000))
        self.assertTrue(self.b.compare_and_extend(key, "t", 5000))
        self.sleep_ms(350)
        self.assertEqual(self.b.get(key), b"t")

    def test_compare_and_set_keeps_ttl_and_is_exclusive(self):
        key = self.key("cas" + secrets.token_hex(3))
        self.b.set(key, "a", 250)
        self.assertFalse(self.b.compare_and_set(key, "zzz", "b"))
        self.assertTrue(self.b.compare_and_set(key, "a", "b"))
        self.assertEqual(self.b.get(key), b"b")
        self.sleep_ms(400)
        self.assertIsNone(self.b.get(key))                              # TTL was NOT extended by the CAS
        self.assertFalse(self.b.compare_and_set(key, "b", "c"))         # missing key never created

    def test_concurrent_compare_and_set_single_winner(self):
        key = self.key("casrace" + secrets.token_hex(3))
        self.b.set(key, "start", 5000)
        with cf.ThreadPoolExecutor(16) as ex:
            res = list(ex.map(lambda i: self.b.compare_and_set(key, "start", f"w{i}"), range(32)))
        self.assertEqual(res.count(True), 1)

    def test_token_bucket_burst_then_deny_then_refill(self):
        key = self.key("tb" + secrets.token_hex(3))
        out = [self.b.token_bucket(key, 10.0, 5) for _ in range(6)]
        self.assertEqual([o[0] for o in out], [True] * 5 + [False])
        self.assertGreater(out[-1][2], 0)                               # retry_after_ms
        self.sleep_ms(350)                                              # ~3 tokens at 10/s
        self.assertTrue(self.b.token_bucket(key, 10.0, 5)[0])
        with self.assertRaises(StateConfigError):
            self.b.token_bucket(key, 0, 5)

    def test_token_bucket_is_exact_under_concurrency(self):
        key = self.key("tbrace" + secrets.token_hex(3))
        with cf.ThreadPoolExecutor(16) as ex:
            res = list(ex.map(lambda _: self.b.token_bucket(key, 0.001, 10)[0], range(100)))
        self.assertEqual(res.count(True), 10)                           # never more than burst

    def test_window_counter(self):
        key = self.key("win" + secrets.token_hex(3))
        self.assertEqual([self.b.window_incr(key, 200) for _ in range(3)], [1, 2, 3])
        self.sleep_ms(350)
        self.assertEqual(self.b.window_incr(key, 200), 1)

    def test_window_counter_concurrent_counts_are_unique(self):
        key = self.key("winrace" + secrets.token_hex(3))
        with cf.ThreadPoolExecutor(16) as ex:
            res = list(ex.map(lambda _: self.b.window_incr(key, 5000), range(100)))
        self.assertEqual(sorted(res), list(range(1, 101)))

    def test_replay_check_new_replay_and_race(self):
        m, q = self.key("mk" + secrets.token_hex(3)), self.key("qu" + secrets.token_hex(3))
        self.b.set_if_absent(m, "1", 60000)                             # marker present (normal operation)
        n = self.key("n" + secrets.token_hex(3))
        self.assertEqual(self.b.replay_check(n, m, q, 5000, 60000), 1)
        self.assertEqual(self.b.replay_check(n, m, q, 5000, 60000), 0)
        race = self.key("r" + secrets.token_hex(3))
        with cf.ThreadPoolExecutor(32) as ex:
            res = list(ex.map(lambda _: self.b.replay_check(race, m, q, 5000, 60000), range(64)))
        self.assertEqual(res.count(1), 1)
        self.assertEqual(res.count(0), 63)

    def test_replay_check_quarantines_after_state_loss(self):
        m, q = self.key("mk2" + secrets.token_hex(3)), self.key("qu2" + secrets.token_hex(3))
        n = self.key("n2" + secrets.token_hex(3))
        self.assertEqual(self.b.replay_check(n, m, q, 300, 60000), 2)   # marker missing => data was lost
        self.assertEqual(self.b.replay_check(n, m, q, 300, 60000), 2)   # still refused during the window
        self.sleep_ms(450)
        self.assertEqual(self.b.replay_check(n, m, q, 5000, 60000), 1)  # window over, marker restored
