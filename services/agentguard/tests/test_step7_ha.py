"""Step 7 — distributed high-availability identity service tests.

Three tiers, clearly separated:

  * **Unit** (no external services): retry/backoff, in-memory idempotency, health aggregation,
    coordination scheduling, graceful shutdown, outage/retry simulation.
  * **Real PostgreSQL** (skipped unless AGENTGUARD_TEST_PG_HOST): PgIdempotencyStore concurrency,
    concurrent idempotent registration/issuance, duplicate-job prevention, multi-instance service.
  * **Real PostgreSQL + Redis** (skipped unless both hosts set): two independent service instances
    sharing durable + distributed state — the actual multi-instance test.

Run:
  PYTHONPATH=src:. python3 -m unittest -v tests.test_step7_ha
  AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=... AGENTGUARD_TEST_PG_PASSWORD=... \
  AGENTGUARD_TEST_REDIS_HOST=127.0.0.1 AGENTGUARD_TEST_REDIS_PASSWORD=... \
  PYTHONPATH=src:. python3 -m unittest -v tests.test_step7_ha
"""
import concurrent.futures as cf
import os
import secrets
import threading
import time
import unittest

from cryptography.fernet import Fernet

from agent_identity import IdentityConfig, IdentityService
from agent_identity.core.clock import FixedClock
from agent_identity.core.errors import ConflictError, StorageError
from agent_identity.core.models import RevocationReason
from agent_identity.ha import (CoordinationRunner, HealthAggregator, MemoryIdempotencyStore,
                               PeriodicScheduler, RetryPolicy, retry_call)
from agent_identity.ha import idempotency as IDEM
from agent_identity.ha.idempotency import (CONFLICT, IN_PROGRESS, NEW, REPLAY, PgIdempotencyStore,
                                           request_digest)
from agent_identity.observability.logging import SecurityLogger

PG_HOST = os.environ.get("AGENTGUARD_TEST_PG_HOST", "")
PG_PORT = int(os.environ.get("AGENTGUARD_TEST_PG_PORT", "5432"))
PG_USER = os.environ.get("AGENTGUARD_TEST_PG_USER", "")
PG_PW = os.environ.get("AGENTGUARD_TEST_PG_PASSWORD", "")
REDIS_HOST = os.environ.get("AGENTGUARD_TEST_REDIS_HOST", "")
REDIS_PORT = int(os.environ.get("AGENTGUARD_TEST_REDIS_PORT", "6379"))
REDIS_PW = os.environ.get("AGENTGUARD_TEST_REDIS_PASSWORD", "")
TD = "step7.agentguard.example.net"


def _mk():
    return Fernet.generate_key()


# ============================================================================ UNIT
class RetryUnit(unittest.TestCase):
    def test_retries_then_succeeds(self):
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise StorageError("transient")
            return "ok"
        out = retry_call(flaky, policy=RetryPolicy(attempts=5, base_seconds=0, max_seconds=0),
                         retry_on=(StorageError,), sleep=lambda s: None)
        self.assertEqual(out, "ok")
        self.assertEqual(calls["n"], 3)

    def test_gives_up_after_bound(self):
        calls = {"n": 0}

        def always():
            calls["n"] += 1
            raise StorageError("down")
        with self.assertRaises(StorageError):
            retry_call(always, policy=RetryPolicy(attempts=3, base_seconds=0, max_seconds=0),
                       retry_on=(StorageError,), sleep=lambda s: None)
        self.assertEqual(calls["n"], 3)                       # bounded, never unbounded

    def test_non_retryable_propagates_immediately(self):
        calls = {"n": 0}

        def bad():
            calls["n"] += 1
            raise ValueError("not retryable")
        with self.assertRaises(ValueError):
            retry_call(bad, policy=RetryPolicy(attempts=5, base_seconds=0, max_seconds=0),
                       retry_on=(StorageError,), sleep=lambda s: None)
        self.assertEqual(calls["n"], 1)

    def test_no_retry_when_retry_on_empty(self):
        calls = {"n": 0}

        def bad():
            calls["n"] += 1
            raise StorageError("x")
        with self.assertRaises(StorageError):
            retry_call(bad, policy=RetryPolicy(attempts=5), retry_on=(), sleep=lambda s: None)
        self.assertEqual(calls["n"], 1)                       # non-idempotent: never retried

    def test_backoff_is_bounded_and_jittered(self):
        p = RetryPolicy(attempts=6, base_seconds=0.1, max_seconds=1.0)
        delays = [p.delay_for(i, rand=lambda: 1.0) for i in range(1, 6)]
        self.assertEqual(delays, [0.1, 0.2, 0.4, 0.8, 1.0])   # exponential, capped
        self.assertTrue(all(0 <= p.delay_for(i, rand=lambda: 0.0) <= 1.0 for i in range(1, 6)))


class IdempotencyMemoryUnit(unittest.TestCase):
    def setUp(self):
        self.s = MemoryIdempotencyStore([_mk()])
        self.now = 1_000_000.0

    def _reserve(self, key="k", digest="d", actor="a", ttl=3600):
        return self.s.reserve("acme", "issue_credential", key, digest=digest, actor=actor,
                              owner_instance="i1", ttl_seconds=ttl, now=self.now)

    def test_first_is_new_then_in_progress(self):
        self.assertEqual(self._reserve().outcome, NEW)
        self.assertEqual(self._reserve().outcome, IN_PROGRESS)

    def test_completed_replay_returns_stored_response(self):
        self._reserve()
        self.s.complete("acme", "issue_credential", "k", result_ref="crd_1",
                        response=b"secret-token", now=self.now)
        r = self._reserve()
        self.assertEqual(r.outcome, REPLAY)
        self.assertEqual(r.result_ref, "crd_1")
        self.assertEqual(r.response, b"secret-token")

    def test_different_body_is_conflict(self):
        self._reserve(digest="d1")
        self.assertEqual(self._reserve(digest="d2").outcome, CONFLICT)

    def test_different_actor_is_conflict_never_leaks(self):
        self._reserve(actor="alice")
        self.s.complete("acme", "issue_credential", "k", result_ref="crd_1",
                        response=b"secret", now=self.now)
        r = self._reserve(actor="mallory")                    # same key, different principal
        self.assertEqual(r.outcome, CONFLICT)
        self.assertIsNone(r.response)                         # credential NEVER returned

    def test_tenant_scope_isolation(self):
        self.s.reserve("acme", "issue_credential", "k", digest="d", actor="a",
                       owner_instance="i1", ttl_seconds=3600, now=self.now)
        r = self.s.reserve("globex", "issue_credential", "k", digest="d", actor="a",
                           owner_instance="i1", ttl_seconds=3600, now=self.now)
        self.assertEqual(r.outcome, NEW)                      # different tenant => different record

    def test_fail_frees_key_for_safe_retry(self):
        self._reserve()
        self.s.fail("acme", "issue_credential", "k", now=self.now)
        self.assertEqual(self._reserve().outcome, NEW)

    def test_stale_takeover_single_winner(self):
        # reserve in the PAST so the in_progress reservation is genuinely stale
        self.s.reserve("acme", "issue_credential", "k", digest="d", actor="a", owner_instance="i0",
                       ttl_seconds=3600, now=self.now - 200)
        stale_before = self.now - 120
        winners = [self.s.takeover_stale("acme", "issue_credential", "k", digest="d", actor="a",
                                         owner_instance=f"i{n}", stale_before=stale_before,
                                         now=self.now) for n in range(5)]
        self.assertEqual(winners.count(True), 1)              # exactly one instance takes over

    def test_takeover_refused_when_fresh(self):
        self._reserve()
        self.assertFalse(self.s.takeover_stale("acme", "issue_credential", "k", digest="d", actor="a",
                                               owner_instance="i2", stale_before=self.now - 120,
                                               now=self.now))

    def test_bounded_retention_purge(self):
        self._reserve(ttl=10)
        self.assertEqual(self.s.purge_expired(self.now + 5), 0)
        self.assertEqual(self.s.purge_expired(self.now + 11), 1)

    def test_concurrent_reserve_single_winner(self):
        def go(i):
            return self.s.reserve("acme", "register_agent", "race", digest="d", actor="a",
                                  owner_instance=f"i{i}", ttl_seconds=3600, now=self.now).outcome
        with cf.ThreadPoolExecutor(32) as ex:
            out = list(ex.map(go, range(64)))
        self.assertEqual(out.count(NEW), 1)
        self.assertEqual(out.count(IN_PROGRESS), 63)


class HealthUnit(unittest.TestCase):
    def test_liveness_never_touches_dependencies(self):
        class Boom:
            def readiness(self):
                raise RuntimeError("db down")
        h = HealthAggregator(instance_id="i1", db=Boom())
        self.assertEqual(h.liveness(), {"status": "alive"})   # liveness is process-only

    def test_readiness_reflects_dependency_failure(self):
        class Down:
            def readiness(self):
                return {"ready": False}
        h = HealthAggregator(instance_id="i1", db=Down())
        r = h.readiness()
        self.assertEqual(r["status"], "not_ready")
        self.assertEqual(r["checks"]["database"], "fail")

    def test_readiness_ok_when_all_healthy(self):
        class Up:
            def readiness(self):
                return {"ready": True}
        h = HealthAggregator(instance_id="i1", db=Up(), spiffe=lambda: True, kms=lambda: True)
        self.assertEqual(h.readiness()["status"], "ready")

    def test_readiness_optional_dependency_failure(self):
        h = HealthAggregator(instance_id="i1", kms=lambda: False)
        self.assertEqual(h.readiness()["checks"]["kms"], "fail")
        self.assertEqual(h.readiness()["status"], "not_ready")

    def test_public_payload_has_no_internal_details(self):
        h = HealthAggregator(instance_id="i1")
        blob = str(h.readiness())
        for leak in ("password", "host", "version", "dsn", "secret"):
            self.assertNotIn(leak, blob.lower())


class CoordinationUnit(unittest.TestCase):
    def test_scheduler_runs_each_job_once_per_tick(self):
        class FakeRunner:
            def __init__(self):
                self.calls = []
            def run(self, name, fn):
                self.calls.append(name)
                return fn()
        r = FakeRunner()
        s = PeriodicScheduler(r, {"a": lambda: 1, "b": lambda: 2}, interval_seconds=1)
        out = s.run_once()
        self.assertEqual(set(out), {"a", "b"})
        self.assertEqual(sorted(r.calls), ["a", "b"])

    def test_scheduler_stop_is_clean(self):
        class FakeRunner:
            def run(self, name, fn):
                return fn()
        s = PeriodicScheduler(FakeRunner(), {"a": lambda: 1}, interval_seconds=0.05,
                              initial_delay_seconds=0.01)
        s.start()
        time.sleep(0.1)
        s.stop()                                              # must not hang or raise


class GracefulShutdownUnit(unittest.TestCase):
    def test_serve_forever_runs_on_shutdown(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from agent_identity.api.http_transport import serve_forever

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        called = threading.Event()
        t = threading.Thread(target=serve_forever, args=(srv,),
                             kwargs={"on_shutdown": called.set, "install_signal_handlers": False},
                             daemon=True)
        t.start()
        time.sleep(0.1)
        srv.shutdown()
        t.join(timeout=3)
        self.assertTrue(called.is_set())                      # graceful shutdown hook ran
        self.assertFalse(t.is_alive())


class OutageUnit(unittest.TestCase):
    def test_idempotent_operation_recovers_after_transient_outage(self):
        s = MemoryIdempotencyStore([_mk()])
        now = 1_000_000.0
        s.reserve("acme", "issue_credential", "k", digest="d", actor="a", owner_instance="i1",
                  ttl_seconds=3600, now=now)
        attempts = {"n": 0}

        def complete():
            attempts["n"] += 1
            if attempts["n"] < 2:
                raise StorageError("db blip")
            s.complete("acme", "issue_credential", "k", result_ref="crd_1", response=b"t", now=now)
        retry_call(complete, policy=RetryPolicy(attempts=3, base_seconds=0, max_seconds=0),
                   retry_on=(StorageError,), sleep=lambda x: None)
        self.assertEqual(s.reserve("acme", "issue_credential", "k", digest="d", actor="a",
                                   owner_instance="i2", ttl_seconds=3600, now=now).outcome, REPLAY)

    def test_service_denies_when_idempotency_store_unavailable(self):
        class DeadStore:
            def reserve(self, *a, **k):
                raise StorageError("idempotency store down")
        svc = IdentityService(IdentityConfig(log_to_python_logging=False),
                              idempotency=DeadStore())
        svc.register_organization("acme", "Acme")
        with self.assertRaises(StorageError):                 # fail closed, never silently proceed
            svc.register_agent("acme", "bot", "t", "o@x.com", "d", ["x:read"], "production", {},
                               idempotency_key="k1")


# ============================================================================ REAL POSTGRES
def _admin():
    import psycopg
    return psycopg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PW,
                           dbname="postgres", autocommit=True)


def _pgcfg(dbname, **kw):
    from agent_identity.storage.postgres import PgConfig
    d = dict(environment="development", host=PG_HOST, port=PG_PORT, dbname=dbname, user=PG_USER,
             password=PG_PW, sslmode=os.environ.get("AGENTGUARD_TEST_PG_SSLMODE", "disable"),
             retry_initial_backoff_seconds=0.01, pool_min_size=2, pool_max_size=16)
    d.update(kw)
    return PgConfig(**d).validate()


@unittest.skipUnless(PG_HOST and PG_USER, "set AGENTGUARD_TEST_PG_HOST/USER/PASSWORD")
class PgCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from agent_identity.storage.postgres import build_postgres_storage
        from agent_identity.storage.postgres import migrate
        from agent_identity.storage.postgres.db import Database
        cls.dbname = "ag_s7_" + secrets.token_hex(6)
        with _admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')
        cls.master = Fernet.generate_key()
        cls.cfg = _pgcfg(cls.dbname)
        db = Database(cls.cfg)
        migrate.migrate(db)
        db.close()
        cls.st = build_postgres_storage(cls.cfg, cls.master)

    @classmethod
    def tearDownClass(cls):
        st = getattr(cls, "st", None)
        if st:
            st.close()
        with _admin() as a:
            a.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}" WITH (FORCE)')


class PgIdempotencyIntegration(PgCase):
    def setUp(self):
        self.s = PgIdempotencyStore(self.st.db, [self.master])
        self.now = 1_000_000.0

    def test_reserve_replay_conflict(self):
        k = "k-" + secrets.token_hex(4)
        self.assertEqual(self.s.reserve("acme", "issue_credential", k, digest="d", actor="a",
                                        owner_instance="i1", ttl_seconds=3600, now=self.now).outcome, NEW)
        self.assertEqual(self.s.reserve("acme", "issue_credential", k, digest="d", actor="a",
                                        owner_instance="i2", ttl_seconds=3600, now=self.now).outcome,
                         IN_PROGRESS)
        self.s.complete("acme", "issue_credential", k, result_ref="crd_1", response=b"tok",
                        now=self.now)
        r = self.s.reserve("acme", "issue_credential", k, digest="d", actor="a",
                           owner_instance="i3", ttl_seconds=3600, now=self.now)
        self.assertEqual(r.outcome, REPLAY)
        self.assertEqual(r.response, b"tok")
        self.assertEqual(self.s.reserve("acme", "issue_credential", k, digest="OTHER", actor="a",
                                        owner_instance="i4", ttl_seconds=3600, now=self.now).outcome,
                         CONFLICT)

    def test_concurrent_reserve_single_winner(self):
        k = "race-" + secrets.token_hex(4)
        def go(i):
            return self.s.reserve("acme", "register_agent", k, digest="d", actor="a",
                                  owner_instance=f"i{i}", ttl_seconds=3600, now=self.now).outcome
        with cf.ThreadPoolExecutor(16) as ex:
            out = list(ex.map(go, range(32)))
        self.assertEqual(out.count(NEW), 1)
        self.assertEqual(out.count(IN_PROGRESS), 31)

    def test_completed_record_is_terminal(self):
        k = "term-" + secrets.token_hex(4)
        self.s.reserve("acme", "issue_credential", k, digest="d", actor="a", owner_instance="i1",
                       ttl_seconds=3600, now=self.now)
        self.s.complete("acme", "issue_credential", k, result_ref="crd_1", response=b"t",
                        now=self.now)
        with self.assertRaises(StorageError):                 # cannot re-complete / reset
            self.s.complete("acme", "issue_credential", k, result_ref="crd_2", response=b"t2",
                            now=self.now)

    def test_purge_bounded_retention(self):
        k = "old-" + secrets.token_hex(4)
        self.s.reserve("acme", "issue_credential", k, digest="d", actor="a", owner_instance="i1",
                       ttl_seconds=10, now=self.now)
        self.assertEqual(self.s.purge_expired(self.now + 5), 0)
        self.assertEqual(self.s.purge_expired(self.now + 11), 1)


class PgServiceIdempotencyIntegration(PgCase):
    def setUp(self):
        self.svc = IdentityService(IdentityConfig(trust_domain=TD, log_to_python_logging=False),
                                   idempotency=PgIdempotencyStore(self.st.db, [self.master]),
                                   **self.st.service_kwargs())
        if self.svc.agents.get_org("acme") is None:
            self.svc.register_organization("acme", "Acme")

    def test_concurrent_idempotent_registration_creates_one_agent(self):
        key = "reg-" + secrets.token_hex(4)
        def go(_):
            return self.svc.register_agent("acme", "bot", "t", "o@x.com", "d", ["x:read"],
                                           "production", {}, idempotency_key=key)["agent_id"]
        with cf.ThreadPoolExecutor(12) as ex:
            ids = list(ex.map(go, range(24)))
        self.assertEqual(len(set(ids)), 1)                    # exactly one agent created

    def test_concurrent_idempotent_issuance_returns_one_credential(self):
        a = self.svc.register_agent("acme", "bot2", "t", "o@x.com", "d", ["x:read"], "production", {})
        i = self.svc.create_agent_instance(a["agent_id"])
        key = "iss-" + secrets.token_hex(4)

        def go(_):
            return self.svc.issue_credential(a["agent_id"], i["instance_id"],
                                             idempotency_key=key).credential_id
        with cf.ThreadPoolExecutor(12) as ex:
            ids = list(ex.map(go, range(24)))
        self.assertEqual(len(set(ids)), 1)                    # one credential, replayed to all

    def test_idempotent_issuance_replay_returns_same_token(self):
        a = self.svc.register_agent("acme", "bot3", "t", "o@x.com", "d", ["x:read"], "production", {})
        i = self.svc.create_agent_instance(a["agent_id"])
        key = "iss-" + secrets.token_hex(4)
        c1 = self.svc.issue_credential(a["agent_id"], i["instance_id"], idempotency_key=key)
        c2 = self.svc.issue_credential(a["agent_id"], i["instance_id"], idempotency_key=key)
        self.assertEqual(c1.credential_id, c2.credential_id)
        self.assertEqual(c1.token, c2.token)                  # byte-identical: safe retry

    def test_conflicting_idempotency_key_rejected(self):
        a = self.svc.register_agent("acme", "bot4", "t", "o@x.com", "d", ["x:read"], "production", {})
        i = self.svc.create_agent_instance(a["agent_id"])
        key = "iss-" + secrets.token_hex(4)
        self.svc.issue_credential(a["agent_id"], i["instance_id"], idempotency_key=key)
        with self.assertRaises(ConflictError):
            self.svc.issue_credential(a["agent_id"], i["instance_id"], ttl_seconds=1234,
                                      idempotency_key=key)


class CoordinationIntegration(PgCase):
    def test_duplicate_job_prevented_across_instances(self):
        counter = {"n": 0}
        lock = threading.Lock()

        def job():
            with lock:
                counter["n"] += 1
            time.sleep(0.2)                                   # hold the advisory lock
            return 1
        r1 = CoordinationRunner(self.st.db, instance_id="i1")
        r2 = CoordinationRunner(self.st.db, instance_id="i2")
        with cf.ThreadPoolExecutor(2) as ex:
            f1 = ex.submit(r1.run, "purge_expired_material", job)
            time.sleep(0.05)                                  # let i1 grab the lock first
            f2 = ex.submit(r2.run, "purge_expired_material", job)
            out = [f1.result(), f2.result()]
        self.assertEqual(counter["n"], 1)                     # job body ran exactly once
        self.assertEqual(sorted(r.status for r in out), ["ok", "skipped"])

    def test_job_ledger_records_runner(self):
        r = CoordinationRunner(self.st.db, instance_id="i1")
        r.run("purge_idempotency", lambda: 0)
        st = r.status()
        self.assertIn("purge_idempotency", st)
        self.assertEqual(st["purge_idempotency"]["last_instance"], "i1")


# ============================================================================ MULTI-INSTANCE (PG + Redis)
@unittest.skipUnless(PG_HOST and PG_USER and REDIS_HOST,
                     "set AGENTGUARD_TEST_PG_* and AGENTGUARD_TEST_REDIS_HOST for multi-instance tests")
class MultiInstanceIntegration(unittest.TestCase):
    """Two independent service instances sharing PostgreSQL + Redis — the real multi-instance test."""

    @classmethod
    def setUpClass(cls):
        from agent_identity.storage.postgres import build_postgres_storage, migrate
        from agent_identity.storage.postgres.db import Database
        from agent_identity.state import RedisConfig, build_security_state
        from agent_identity.ha.factory import build_ha
        cls.dbname = "ag_s7m_" + secrets.token_hex(6)
        with _admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')
        cls.master = Fernet.generate_key()
        os.environ["AGENT_IDENTITY_MASTER_KEY"] = cls.master.decode()
        cls.cfg = _pgcfg(cls.dbname)
        db = Database(cls.cfg)
        migrate.migrate(db)
        db.close()
        cls.pg = build_postgres_storage(cls.cfg, cls.master)
        cls.prefix = "s7m" + secrets.token_hex(5)
        rcfg = RedisConfig(environment="development", host=REDIS_HOST, port=REDIS_PORT,
                           password=REDIS_PW, tls=False, key_prefix=cls.prefix,
                           retry_base_backoff_seconds=0.01).validate()
        cls.state = build_security_state(rcfg)
        # two instances, same PG + same Redis, distinct instance ids
        cls.ha1 = build_ha(cls.pg, cls.state, IdentityConfig(trust_domain=TD, log_to_python_logging=False),
                           instance_id="inst-1", enable_scheduler=False)
        cls.ha2 = build_ha(cls.pg, cls.state, IdentityConfig(trust_domain=TD, log_to_python_logging=False),
                           instance_id="inst-2", enable_scheduler=False)
        cls.svc1, cls.svc2 = cls.ha1.service, cls.ha2.service
        cls.svc1.register_organization("acme", "Acme")

    @classmethod
    def tearDownClass(cls):
        cls.state.close()
        cls.pg.close()
        with _admin() as a:
            a.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}" WITH (FORCE)')

    def test_credential_issued_on_one_instance_verifies_on_other(self):
        a = self.svc1.register_agent("acme", "m1", "t", "o@x.com", "d", ["x:read"], "production", {})
        i = self.svc1.create_agent_instance(a["agent_id"])
        c = self.svc1.issue_credential(a["agent_id"], i["instance_id"])
        self.assertTrue(self.svc2.verify_credential(c.token, require_proof=False).valid)

    def test_revocation_on_one_instance_visible_on_other(self):
        a = self.svc1.register_agent("acme", "m2", "t", "o@x.com", "d", ["x:read"], "production", {})
        i = self.svc1.create_agent_instance(a["agent_id"])
        c = self.svc1.issue_credential(a["agent_id"], i["instance_id"])
        self.assertTrue(self.svc2.verify_credential(c.token, require_proof=False).valid)
        self.svc1.revoke_credential(c.credential_id, RevocationReason.COMPROMISE, "t")
        self.assertFalse(self.svc2.verify_credential(c.token, require_proof=False).valid)

    def test_idempotent_issuance_across_instances_returns_same_credential(self):
        a = self.svc1.register_agent("acme", "m3", "t", "o@x.com", "d", ["x:read"], "production", {})
        i = self.svc1.create_agent_instance(a["agent_id"])
        key = "x-" + secrets.token_hex(4)
        c1 = self.svc1.issue_credential(a["agent_id"], i["instance_id"], idempotency_key=key)
        c2 = self.svc2.issue_credential(a["agent_id"], i["instance_id"], idempotency_key=key)
        self.assertEqual(c1.credential_id, c2.credential_id)  # retry on another replica is safe
        self.assertEqual(c1.token, c2.token)

    def test_concurrent_registration_across_instances_all_distinct(self):
        def go(n):
            svc = self.svc1 if n % 2 else self.svc2
            return svc.register_agent("acme", f"c{n}", "t", "o@x.com", "d", ["x:read"],
                                      "production", {})["agent_id"]
        with cf.ThreadPoolExecutor(12) as ex:
            ids = list(ex.map(go, range(40)))
        self.assertEqual(len(set(ids)), 40)

    def test_health_reports_ready_on_both_instances(self):
        self.assertEqual(self.ha1.health.readiness()["status"], "ready")
        self.assertEqual(self.ha2.health.readiness()["status"], "ready")

    def test_restart_survival_new_instance_same_state(self):
        a = self.svc1.register_agent("acme", "m4", "t", "o@x.com", "d", ["x:read"], "production", {})
        i = self.svc1.create_agent_instance(a["agent_id"])
        c = self.svc1.issue_credential(a["agent_id"], i["instance_id"])
        # "restart": a brand-new service instance over the same PG + Redis
        from agent_identity.ha.factory import build_ha
        ha3 = build_ha(self.pg, self.state, IdentityConfig(trust_domain=TD, log_to_python_logging=False),
                       instance_id="inst-3", enable_scheduler=False)
        self.assertTrue(ha3.service.verify_credential(c.token, require_proof=False).valid)


if __name__ == "__main__":
    unittest.main()
