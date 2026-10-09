"""REAL PostgreSQL integration tests. Skipped unless AGENTGUARD_TEST_PG_HOST is set.
Needs a role allowed to CREATE DATABASE. Each class gets a fresh throwaway database.
  AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=... AGENTGUARD_TEST_PG_PASSWORD=...
  PYTHONPATH=src:. python -m unittest -v tests.test_pg_integration"""
import concurrent.futures as cf
import logging
import os
import random
import secrets
import unittest

from cryptography.fernet import Fernet

from agent_identity import IdentityConfig, IdentityService
from agent_identity.core.errors import ConflictError, StorageError
from agent_identity.core.models import (AgentRecord, CredentialRecord, InstanceRecord,
                                         RevocationReason, RevocationRecord, Status, TargetType)
from agent_identity.spiffe.bindings import Binding
from agent_identity.storage.postgres import (PgConfig, SchemaMismatchError, StorageUnavailableError,
                                              build_postgres_storage)
from agent_identity.storage.postgres import migrate
from agent_identity.storage.postgres.db import Database
from agent_identity.storage.postgres.errors import MigrationError

HOST = os.environ.get("AGENTGUARD_TEST_PG_HOST", "")
PORT = int(os.environ.get("AGENTGUARD_TEST_PG_PORT", "5432"))
USER = os.environ.get("AGENTGUARD_TEST_PG_USER", "")
PW = os.environ.get("AGENTGUARD_TEST_PG_PASSWORD", "")
TD = "pg.agentguard.example.net"


def admin():
    import psycopg
    return psycopg.connect(host=HOST, port=PORT, user=USER, password=PW, dbname="postgres", autocommit=True)


def pgcfg(dbname, **kw):
    d = dict(environment="development", host=HOST, port=PORT, dbname=dbname, user=USER, password=PW,
             sslmode=os.environ.get("AGENTGUARD_TEST_PG_SSLMODE", "disable"),
             retry_initial_backoff_seconds=0.01, pool_min_size=1, pool_max_size=12)
    d.update(kw)
    return PgConfig(**d).validate()


@unittest.skipUnless(HOST and USER, "set AGENTGUARD_TEST_PG_HOST/USER/PASSWORD for real PostgreSQL tests")
class PgCase(unittest.TestCase):
    migrate_on_setup = True

    @classmethod
    def setUpClass(cls):
        cls.dbname = "ag_test_" + secrets.token_hex(6)
        with admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')       # name is generated here, not user input
        cls.master = Fernet.generate_key()
        cls.cfg = pgcfg(cls.dbname)
        if cls.migrate_on_setup:
            db = Database(cls.cfg)
            migrate.migrate(db)
            db.close()
            cls.st = build_postgres_storage(cls.cfg, cls.master)
            cls.svc = IdentityService(IdentityConfig(trust_domain=TD, log_to_python_logging=False),
                                      **cls.st.service_kwargs())
            cls.svc.register_organization("acme", "Acme")
            cls.svc.register_organization("globex", "Globex")

    @classmethod
    def tearDownClass(cls):
        st = getattr(cls, "st", None)
        if st:
            st.close()
        with admin() as a:
            a.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}" WITH (FORCE)')

    def mkagent(self, org="acme", name=None, caps=("agent:spawn", "x:read")):
        a = self.svc.register_agent(org, name or "bot-" + secrets.token_hex(3), "t", "o@x.com", "d",
                                    list(caps), "production", {"k": "v"})
        i = self.svc.create_agent_instance(a["agent_id"])
        return a, i


class Migrations(PgCase):
    migrate_on_setup = False

    def test_fresh_apply_idempotent_and_tamper_detection(self):
        db = Database(self.cfg)
        try:
            self.assertEqual(migrate.migrate(db), [1])
            self.assertEqual(migrate.migrate(db), [])                       # repeatable
            self.assertEqual(migrate.verify_schema(db), 1)
            tables = {r["table_name"] for r in db.run("t", lambda c: c.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='public'").fetchall())}
            for t in ("agents", "agent_instances", "credentials", "revocations", "spiffe_bindings",
                      "keystore_keys", "organizations", "agent_spawns", "trust_roots", "issuer_certificates"):
                self.assertIn(t, tables)
            db.run("tamper", lambda c: c.execute("UPDATE schema_migrations SET checksum='x' WHERE version=1"))
            with self.assertRaises(MigrationError):
                migrate.migrate(db)
            with self.assertRaises(SchemaMismatchError):
                migrate.verify_schema(db)
            self.assertFalse(db.readiness()["ready"])
        finally:
            db.close()

    def test_concurrent_migrators_apply_once(self):
        name = "ag_test_" + secrets.token_hex(6)
        with admin() as a:
            a.execute(f'CREATE DATABASE "{name}"')
        try:
            def one(_):
                d = Database(pgcfg(name))
                try:
                    return migrate.migrate(d)
                finally:
                    d.close()
            with cf.ThreadPoolExecutor(4) as ex:
                results = list(ex.map(one, range(4)))
            self.assertEqual(sorted(len(r) for r in results), [0, 0, 0, 1])
        finally:
            with admin() as a:
                a.execute(f'DROP DATABASE "{name}" WITH (FORCE)')

    def test_service_refuses_unmigrated_database(self):
        with self.assertRaises(SchemaMismatchError):
            build_postgres_storage(self.cfg, self.master)


class IdentityPersistence(PgCase):
    def test_full_lifecycle_and_restart_survival(self):
        a, i = self.mkagent()
        c = self.svc.issue_credential(a["agent_id"], i["instance_id"])
        self.assertTrue(self.svc.verify_credential(c.token, require_proof=False).valid)
        # "restart": brand-new pool + service on the same DB, same root key id and master key
        st2 = build_postgres_storage(self.cfg, self.master)
        try:
            svc2 = IdentityService(IdentityConfig(trust_domain=TD, log_to_python_logging=False),
                                   root_key_id=self.svc.root_key_id, **st2.service_kwargs())
            self.assertTrue(svc2.verify_credential(c.token, require_proof=False).valid)
            self.assertEqual(svc2.get_agent_identity(a["agent_id"])["agent_name"], a["agent_name"])
            svc2.revoke_credential(c.credential_id, RevocationReason.COMPROMISE, "t")
        finally:
            st2.close()
        r = self.svc.verify_credential(c.token, require_proof=False)          # original instance sees it
        self.assertFalse(r.valid)

    def test_terminate_agent_denies_and_cannot_be_reactivated(self):
        a, i = self.mkagent()
        c = self.svc.issue_credential(a["agent_id"], i["instance_id"])
        self.svc.revoke_agent(a["agent_id"], RevocationReason.AGENT_TERMINATED, "t")
        self.assertFalse(self.svc.verify_credential(c.token, require_proof=False).valid)
        rec = self.st.agents.get_agent(a["agent_id"])
        self.assertEqual(rec.status, Status.TERMINATED)
        from dataclasses import replace
        with self.assertRaises(ConflictError):
            self.st.agents.put_agent(replace(rec, status=Status.ACTIVE))      # DB trigger: terminal state

    def test_sub_agent_relationship_persisted(self):
        a, i = self.mkagent()
        res = self.svc.spawn_sub_agent_authorized(a["agent_id"], i["instance_id"], agent_name="child",
                                                  agent_type="t", capabilities=["x:read"])
        kids = self.st.agents.list_children(a["agent_id"])
        self.assertEqual([k.child_agent_id for k in kids], [res.agent["agent_id"]])
        child = self.st.agents.get_agent(res.agent["agent_id"])
        self.assertEqual(child.parent_agent_id, a["agent_id"])
        self.assertEqual(child.lineage, (a["agent_id"],))

    def test_agent_key_rotation_persisted(self):
        a, _ = self.mkagent()
        self.svc.rotate_agent_key(a["agent_id"])
        rec = self.st.agents.get_agent(a["agent_id"])
        self.assertEqual(len(rec.retired_keys), 1)
        self.assertIsInstance(rec.retired_keys[0][1], float)

    def test_no_plaintext_private_key_in_database(self):
        a, _ = self.mkagent()
        rows = self.st.db.run("k", lambda c: c.execute(
            "SELECT key_id, public_key, encrypted_private FROM keystore_keys").fetchall())
        self.assertTrue(rows)
        for r in rows:
            self.assertTrue(bytes(r["encrypted_private"]).startswith(b"gAAAA"))     # Fernet token
            self.assertNotEqual(bytes(r["encrypted_private"])[:32], bytes(r["public_key"]))
        # wrong master key can't use the keys
        from agent_identity.storage.postgres.repos import PgKeyStore
        bad = PgKeyStore(self.st.db, Fernet.generate_key())
        with self.assertRaises(StorageError):
            bad.sign(rows[0]["key_id"], b"d", b"x")


class Constraints(PgCase):
    def test_cross_tenant_instance_and_credential_rejected(self):
        a, i = self.mkagent("acme")
        bad = InstanceRecord("inst_x" + secrets.token_hex(4), a["agent_id"], "globex", "s", 1.0,
                             Status.ACTIVE, "k", "p", "sig")
        with self.assertRaises(ConflictError):
            self.st.agents.put_instance(bad)                                       # composite FK
        with self.assertRaises(ConflictError):
            self.st.credentials.put(CredentialRecord("cred_x" + secrets.token_hex(4), a["agent_id"],
                                                     i["instance_id"], "globex", "ik", 1.0, 2.0, None, "f", "d"))

    def test_agent_cannot_move_org_or_parent(self):
        a, _ = self.mkagent("acme")
        rec = self.st.agents.get_agent(a["agent_id"])
        from dataclasses import replace
        with self.assertRaises(ConflictError):
            self.st.agents.put_agent(replace(rec, org_id="globex"))
        other, _ = self.mkagent("acme")
        with self.assertRaises(ConflictError):
            self.st.agents.put_agent(replace(rec, parent_agent_id=other["agent_id"], lineage=(other["agent_id"],)))

    def test_unknown_org_agent_rejected(self):
        a, _ = self.mkagent()
        from dataclasses import replace
        rec = replace(self.st.agents.get_agent(a["agent_id"]), agent_id="agt_" + secrets.token_hex(4),
                      org_id="no-such-org")
        with self.assertRaises(ConflictError):
            self.st.agents.put_agent(rec)

    def test_binding_rules(self):
        a, i = self.mkagent()
        sid = f"spiffe://{TD}/org/acme/agent/{a['agent_id']}/instance/{i['instance_id']}"
        b = Binding(sid, "acme", a["agent_id"], i["instance_id"], 1.0)
        self.assertEqual(self.st.bindings.put(b).spiffe_id, sid)
        self.assertEqual(self.st.bindings.put(b).spiffe_id, sid)                    # idempotent
        a2, i2 = self.mkagent()
        with self.assertRaises(ConflictError):                                      # re-pointing denied
            self.st.bindings.put(Binding(sid, "acme", a2["agent_id"], i2["instance_id"], 2.0))
        with self.assertRaises(ConflictError):                                      # 2nd SPIFFE ID, same identity
            self.st.bindings.put(Binding(sid + "x", "acme", a["agent_id"], i["instance_id"], 2.0))
        self.st.bindings.revoke(sid)
        self.assertEqual(self.st.bindings.get(sid).status, "revoked")
        with self.assertRaises(ConflictError):                                      # revoked is terminal (trigger)
            self.st.db.run("u", lambda c: c.execute(
                "UPDATE spiffe_bindings SET status='active' WHERE spiffe_id=%s", (sid,)))

    def test_rollback_leaves_no_partial_state(self):
        def fn(c):
            c.execute("INSERT INTO trust_roots (root_key_id, public_key) VALUES (%s,%s)", ("rb_root", "pk"))
            raise RuntimeError("boom")
        with self.assertRaises(StorageError):
            self.st.db.run("rb", fn)
        self.assertIsNone(self.st.trust.get_root("rb_root"))


class Concurrency(PgCase):
    def test_concurrent_registrations_are_all_distinct(self):
        with cf.ThreadPoolExecutor(12) as ex:
            ids = list(ex.map(lambda n: self.mkagent()[0]["agent_id"], range(40)))
        self.assertEqual(len(set(ids)), 40)

    def test_same_spiffe_id_binds_to_exactly_one_identity(self):
        pairs = [self.mkagent() for _ in range(10)]
        sid = f"spiffe://{TD}/org/acme/agent/contested"

        def bind(p):
            a, i = p
            try:
                self.st.bindings.put(Binding(sid, "acme", a["agent_id"], i["instance_id"], 1.0))
                return "ok"
            except ConflictError:
                return "conflict"
        with cf.ThreadPoolExecutor(10) as ex:
            res = list(ex.map(bind, pairs))
        self.assertEqual(res.count("conflict"), 9)                                  # idempotent winner returns same
        self.assertIn(res.count("ok"), (1,))

    def test_revocation_earliest_effective_wins_under_races(self):
        tid = "cred_race_" + secrets.token_hex(3)
        times = [1000.0 + random.randint(0, 10_000) for _ in range(30)]

        def add(t):
            self.st.revocations.add(RevocationRecord(TargetType.CREDENTIAL, tid, RevocationReason.COMPROMISE,
                                                     t, "t", t, None))
        with cf.ThreadPoolExecutor(12) as ex:
            list(ex.map(add, times))
        self.assertEqual(self.st.revocations.get(TargetType.CREDENTIAL, tid).effective_at, min(times))

    def test_concurrent_issue_and_verify(self):
        a, i = self.mkagent()
        with cf.ThreadPoolExecutor(8) as ex:
            creds = list(ex.map(lambda _: self.svc.issue_credential(a["agent_id"], i["instance_id"]), range(24)))
        self.assertEqual(len({c.credential_id for c in creds}), 24)
        with cf.ThreadPoolExecutor(8) as ex:
            ok = list(ex.map(lambda c: self.svc.verify_credential(c.token, require_proof=False).valid, creds))
        self.assertTrue(all(ok))


class Security(PgCase):
    INJ = ["x'; DROP TABLE agents; --", "' OR '1'='1", "\\'; DELETE FROM revocations; --", "a\x00b"]

    def test_sql_injection_strings_are_inert(self):
        for s in self.INJ:
            try:
                self.assertIsNone(self.st.agents.get_agent(s))
                self.assertIsNone(self.st.agents.get_instance(s))
                self.assertIsNone(self.st.credentials.get(s))
                self.assertIsNone(self.st.bindings.get(s))
                self.assertIsNone(self.st.revocations.get(TargetType.AGENT, s))
            except StorageError:
                pass                                                                # NUL byte etc.: rejected, not executed
        self.assertTrue(self.st.db.health())
        n = self.st.db.run("c", lambda c: c.execute("SELECT count(*) AS n FROM agents").fetchone()["n"])
        self.assertGreaterEqual(n, 0)                                               # table still exists

    def test_injection_in_agent_fields_is_stored_literally_or_rejected(self):
        for s in self.INJ[:3]:
            try:
                a = self.svc.register_agent("acme", s, "t", "o@x.com", s, ["x:read"], "production", {})
            except Exception:
                continue                                                            # input validation rejected it
            self.assertEqual(self.st.agents.get_agent(a["agent_id"]).agent_name, s)

    def test_bad_credentials_fail_closed_without_leaking_secret(self):
        with self.assertLogs("agentguard.postgres", level="WARNING") as lg:
            logging.getLogger("agentguard.postgres").warning("probe")
            with self.assertRaises(StorageUnavailableError) as cm:
                Database(pgcfg(self.dbname, password="WRONG-PW-" + secrets.token_hex(4), retry_max_attempts=1))
        self.assertNotIn(PW or "\x00never", str(cm.exception))
        self.assertNotIn("WRONG-PW", str(cm.exception) + "\n".join(lg.output))

    def test_unreachable_database_fails_closed(self):
        with self.assertRaises(StorageUnavailableError):
            Database(pgcfg(self.dbname, host="127.0.0.1", port=1, pool_acquire_timeout_seconds=1,
                           connect_timeout_seconds=1))

    def test_db_down_after_start_denies_verification(self):
        a, i = self.mkagent()
        c = self.svc.issue_credential(a["agent_id"], i["instance_id"])
        st = build_postgres_storage(self.cfg, self.master)
        svc = IdentityService(IdentityConfig(trust_domain=TD, log_to_python_logging=False),
                              root_key_id=self.svc.root_key_id, **st.service_kwargs())
        self.assertTrue(svc.verify_credential(c.token, require_proof=False).valid)
        st.close()                                                                  # simulate lost DB
        self.assertFalse(svc.verify_credential(c.token, require_proof=False).valid)  # no fallback, deny


class Reconnect(PgCase):
    def test_pool_recovers_after_backends_are_killed(self):
        a, _ = self.mkagent()
        self.assertIsNotNone(self.st.agents.get_agent(a["agent_id"]))
        with admin() as ad:
            ad.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                       "WHERE datname=%s AND pid <> pg_backend_pid()", (self.dbname,))
        self.assertIsNotNone(self.st.agents.get_agent(a["agent_id"]))              # retry + pool health check
        self.assertTrue(self.st.db.readiness()["ready"])


if __name__ == "__main__":
    unittest.main()
