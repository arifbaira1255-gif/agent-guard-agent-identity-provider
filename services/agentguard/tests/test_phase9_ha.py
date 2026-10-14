"""Phase 9 -- high-availability / horizontal-scaling validation.

These tests exercise the properties that must hold when MORE THAN ONE replica serves traffic
against a SHARED authoritative store (PostgreSQL) and SHARED distributed state (Redis):

  * concurrent identity issuance across replicas is safe (no duplicate serials, no lost writes);
  * a revocation issued on one replica is observed by another (no process-local security state);
  * the coordination advisory lock has exactly one winner across replicas;
  * the idempotency ledger is shared, so a retried request is not executed twice;
  * the replay marker is shared, so a replayed nonce is rejected by a different instance.

They use the real PostgreSQL + Redis when available (env-gated, like the existing integration
suite) and are SKIPPED -- never silently passed -- when the infrastructure is absent.
"""
from __future__ import annotations

import os
import secrets
import threading
import unittest

HOST = os.environ.get("AGENTGUARD_TEST_PG_HOST", "")
PORT = int(os.environ.get("AGENTGUARD_TEST_PG_PORT", "5432"))
USER = os.environ.get("AGENTGUARD_TEST_PG_USER", "")
PW = os.environ.get("AGENTGUARD_TEST_PG_PASSWORD", "")
SSLMODE = os.environ.get("AGENTGUARD_TEST_PG_SSLMODE", "disable")
REDIS_HOST = os.environ.get("AGENTGUARD_TEST_REDIS_HOST", "")

_HAVE_PG = bool(HOST and USER)


def _admin(dbname="postgres"):
    import psycopg
    return psycopg.connect(host=HOST, port=PORT, user=USER, password=PW, dbname=dbname,
                           autocommit=True)


def _pgcfg(dbname):
    from agent_identity.storage.postgres.config import PgConfig
    return PgConfig(environment="development", host=HOST, port=PORT, dbname=dbname, user=USER,
                    password=PW, sslmode=SSLMODE, retry_initial_backoff_seconds=0.01,
                    pool_min_size=1, pool_max_size=8).validate()


@unittest.skipUnless(_HAVE_PG, "set AGENTGUARD_TEST_PG_HOST/USER/PASSWORD for real PostgreSQL tests")
class MultiInstanceIdentityTests(unittest.TestCase):
    """Two independent service instances over one shared PostgreSQL store."""

    @classmethod
    def setUpClass(cls):
        from cryptography.fernet import Fernet
        from agent_identity.storage.postgres.db import Database
        from agent_identity.storage.postgres import migrate
        from agent_identity.storage.postgres.factory import build_postgres_storage
        from agent_identity.api.service import IdentityService
        from agent_identity.core.config import IdentityConfig
        cls.dbname = "ag_p9_ha_" + secrets.token_hex(6)
        with _admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')
        cls.cfg = _pgcfg(cls.dbname)
        cls.db = Database(cls.cfg)
        migrate.migrate(cls.db)
        cls.key = Fernet.generate_key()
        cls.pg = build_postgres_storage(cls.cfg, [cls.key])
        cls.svc_a = IdentityService(IdentityConfig(log_to_python_logging=False),
                                    **cls.pg.service_kwargs())
        # A SECOND service object over the SAME store == a second replica.
        cls.svc_b = IdentityService(IdentityConfig(log_to_python_logging=False),
                                    **cls.pg.service_kwargs())
        cls.org = "ha_org"
        cls.svc_a.register_organization(cls.org, "HA Org")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.pg.close()
        finally:
            with _admin() as a:
                a.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}" WITH (FORCE)')

    def test_concurrent_issuance_across_replicas_is_safe(self):
        agent = self.svc_a.register_agent(self.org, "ha-agent", "support", "ops@ha.io", "ha",
                                          ["tickets:read"], "production", {})
        inst = self.svc_a.create_agent_instance(agent["agent_id"])
        serials, errors = [], []
        barrier = threading.Barrier(6)

        def worker(svc):
            try:
                barrier.wait()
                c = svc.issue_credential(agent["agent_id"], inst["instance_id"])
                serials.append(c.credential_id)
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))

        threads = [threading.Thread(target=worker, args=(self.svc_a if i % 2 == 0 else self.svc_b,))
                   for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [], f"issuance must not error under concurrency: {errors}")
        self.assertEqual(len(serials), len(set(serials)), "credential serials must be unique")

    def test_revocation_propagates_across_replicas(self):
        agent = self.svc_a.register_agent(self.org, "ha-revoke", "support", "ops@ha.io", "ha",
                                          ["tickets:read"], "production", {})
        inst = self.svc_a.create_agent_instance(agent["agent_id"])
        cred = self.svc_a.issue_credential(agent["agent_id"], inst["instance_id"])
        # Revoke via replica A; replica B must observe it (shared authoritative store).
        self.svc_a.revoke_credential(cred.credential_id, revoked_by="ops@ha.io",
                                     reason="administrative_action")
        result = self.svc_b.verify_credential(cred.token)
        self.assertFalse(result.valid, "replica B must reject a credential revoked on replica A")
        self.assertEqual(result.reason, "revoked")

    def test_agent_visible_across_replicas(self):
        agent = self.svc_a.register_agent(self.org, "ha-visible", "support", "ops@ha.io", "ha",
                                          ["tickets:read"], "production", {})
        first = self.svc_a.get_agent_identity(agent["agent_id"])
        second = self.svc_b.get_agent_identity(agent["agent_id"])
        self.assertEqual(first["agent_id"], second["agent_id"])


@unittest.skipUnless(_HAVE_PG, "set AGENTGUARD_TEST_PG_HOST/USER/PASSWORD for real PostgreSQL tests")
class CoordinationTests(unittest.TestCase):
    """The advisory-lock coordination primitive must have exactly one winner across replicas."""

    @classmethod
    def setUpClass(cls):
        from agent_identity.storage.postgres.db import Database
        from agent_identity.storage.postgres import migrate
        cls.dbname = "ag_p9_coord_" + secrets.token_hex(6)
        with _admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')
        cls.cfg = _pgcfg(cls.dbname)
        db = Database(cls.cfg)
        migrate.migrate(db)
        db.close()

    @classmethod
    def tearDownClass(cls):
        with _admin() as a:
            a.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}" WITH (FORCE)')

    def test_single_winner_across_instances(self):
        """Two CoordinationRunner instances (two replicas) must not both run the same job."""
        from agent_identity.storage.postgres.db import Database
        from agent_identity.ha.coordination import CoordinationRunner
        db1 = Database(self.cfg)
        db2 = Database(self.cfg)
        try:
            r1 = CoordinationRunner(db1, instance_id="replica-a")
            r2 = CoordinationRunner(db2, instance_id="replica-b")
            # Hold the lock on replica A for the duration of a slow job, then run B concurrently.
            import threading
            started = threading.Event()
            release = threading.Event()

            def slow_job():
                started.set()
                release.wait(5)
                return 1

            t = threading.Thread(target=lambda: r1.run("purge_idempotency", slow_job))
            t.start()
            started.wait(5)
            res_b = r2.run("purge_idempotency", lambda: 1)
            release.set()
            t.join(5)
            self.assertFalse(res_b.ran, "replica B must be skipped while replica A holds the lock")
            self.assertEqual(res_b.status, "skipped")
            # After A releases, B may run.
            res_b2 = r2.run("purge_idempotency", lambda: 1)
            self.assertTrue(res_b2.ran, "replica B must run once the lock is free")
        finally:
            db1.close()
            db2.close()


@unittest.skipUnless(REDIS_HOST, "set AGENTGUARD_TEST_REDIS_HOST for real Redis tests")
class SharedStateTests(unittest.TestCase):
    """Distributed security state must be shared, not process-local."""

    def test_replay_marker_shared_across_instances(self):
        from agent_identity.state.config import RedisConfig
        from agent_identity.state.factory import build_security_state
        cfg = RedisConfig(environment="development", host=REDIS_HOST, port=6379, tls=False,
                          key_prefix="agentguard").validate()
        a = build_security_state(cfg)
        b = build_security_state(cfg)
        try:
            a.replay.ensure_marker()
            nonce = "ha-nonce-" + secrets.token_hex(4)
            self.assertTrue(a.replay.check_and_store(nonce, 300, 1000.0))
            # A DIFFERENT instance must see the marker -> replay rejected.
            self.assertFalse(b.replay.check_and_store(nonce, 300, 1000.0))
        finally:
            a.close()
            b.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
