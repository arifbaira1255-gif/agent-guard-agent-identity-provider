"""REAL PostgreSQL integration tests for the Step 10 policy store (migration 0005).

Skipped unless AGENTGUARD_TEST_PG_HOST is set. Each class gets a fresh throwaway database, runs the
full migration chain (0001..0005), and exercises the authoritative ``PgPolicyStore``: policy
lifecycle persistence, version immutability, JIT grant expiry/revocation, approval lookup, the
append-only audit log, and cross-tenant isolation.

  AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres AGENTGUARD_TEST_PG_PASSWORD=postgres \
  PYTHONPATH=src:. python -m unittest -v tests.test_policy_pg_integration
"""
import os
import secrets
import time
import unittest

from agent_identity.policy import (DecisionKind, MemoryPolicyStore, PolicyConfig,
                                   PolicyDecisionService, build_engine)
from agent_identity.policy.models import (ApprovalRequest, ApprovalStatus, GrantStatus, JitGrant,
                                          PolicyRecord, PolicyStatus, PolicyVersion, VersionStatus)
from agent_identity.security.ids import new_id
from agent_identity.storage.postgres import PgConfig, build_postgres_storage, migrate
from agent_identity.storage.postgres.db import Database
from agent_identity.storage.postgres.policy import create_policy_store

HOST = os.environ.get("AGENTGUARD_TEST_PG_HOST", "")
PORT = int(os.environ.get("AGENTGUARD_TEST_PG_PORT", "5432"))
USER = os.environ.get("AGENTGUARD_TEST_PG_USER", "")
PW = os.environ.get("AGENTGUARD_TEST_PG_PASSWORD", "")

REGO = """
package agentguard.authz

default decision := {"decision": "DENY", "reason": "default_deny"}

decision := {"decision": "ALLOW", "reason": "scoped_allow"} {
    input.action == "tool:read"
    input.resource == "db:public"
}
"""


def admin():
    import psycopg
    return psycopg.connect(host=HOST, port=PORT, user=USER, password=PW, dbname="postgres",
                           autocommit=True)


def pgcfg(dbname):
    return PgConfig(environment="development", host=HOST, port=PORT, dbname=dbname, user=USER,
                    password=PW, sslmode=os.environ.get("AGENTGUARD_TEST_PG_SSLMODE", "disable"),
                    retry_initial_backoff_seconds=0.01, pool_min_size=1, pool_max_size=8).validate()


@unittest.skipUnless(HOST and USER, "set AGENTGUARD_TEST_PG_HOST/USER/PASSWORD for real PostgreSQL tests")
class PgPolicyStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dbname = "ag_pol_" + secrets.token_hex(6)
        with admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')
        cls.cfg = pgcfg(cls.dbname)
        db = Database(cls.cfg)
        migrate.migrate(db)                       # applies 0001..0005
        cls.db = db
        cls.store = create_policy_store(db)
        # organizations are required by the jit_grants/approvals FKs
        cls.db.run("mk_orgs", lambda c: c.execute(
            "INSERT INTO organizations (org_id, name, status, created_at, active_issuer_key_id)"
            " VALUES ('acme','Acme','active',0,'k1'), ('globex','Globex','active',0,'k1')"
            " ON CONFLICT (org_id) DO NOTHING"))

    @classmethod
    def tearDownClass(cls):
        try:
            cls.db.close()
        except Exception:  # noqa: BLE001
            pass
        with admin() as a:
            a.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}" WITH (FORCE)')

    def _policy(self, org_id="acme"):
        now = time.time()
        return PolicyRecord(new_id("pol"), org_id, "p", "", "usr_admin", PolicyStatus.DRAFT, None,
                            now, now, "usr_admin")

    def test_policy_and_version_roundtrip(self):
        p = self._policy()
        self.store.put_policy(p)
        got = self.store.get_policy(p.policy_id)
        self.assertEqual(got.name, "p")
        v = PolicyVersion(p.policy_id, 1, "acme", REGO, "sum1", VersionStatus.DRAFT, time.time(),
                          "usr_admin")
        self.store.put_version(v)
        self.assertEqual(self.store.get_version(p.policy_id, 1).checksum, "sum1")
        self.assertEqual(self.store.next_version_number(p.policy_id), 2)

    def test_version_immutability_pg(self):
        p = self._policy()
        self.store.put_policy(p)
        v = PolicyVersion(p.policy_id, 1, "acme", REGO, "sum1", VersionStatus.DRAFT, time.time(),
                          "usr_admin")
        self.store.put_version(v)
        from agent_identity.core.errors import ConflictError
        bad = PolicyVersion(p.policy_id, 1, "acme", "different", "sum2", VersionStatus.DRAFT,
                            time.time(), "usr_admin")
        with self.assertRaises(ConflictError):
            self.store.put_version(bad)

    def test_jit_grant_expiry_and_revocation(self):
        now = time.time()
        g = JitGrant(new_id("jit"), "acme", "a1", None, "tool:read", "db:public", now, now + 60,
                     None, GrantStatus.ACTIVE, "usr_admin")
        self.store.put_grant(g)
        live = self.store.list_grants(org_id="acme", agent_id="a1", active_only=True, now=now)
        self.assertEqual(len(live), 1)
        # after expiry it is no longer "active"
        self.assertEqual(self.store.list_grants(org_id="acme", agent_id="a1", active_only=True,
                                                now=now + 120), [])
        # revoke
        self.assertIsNotNone(self.store.revoke_grant(g.grant_id, "compromised", now))
        self.assertIsNone(self.store.revoke_grant(g.grant_id, "again", now))   # idempotent
        self.assertEqual(self.store.get_grant(g.grant_id).status, GrantStatus.REVOKED)

    def test_approval_lookup(self):
        now = time.time()
        a = ApprovalRequest(new_id("apr"), "acme", "a1", "tool:delete", "db:x",
                            ApprovalStatus.APPROVED, now, now + 300, "usr_admin", now, "usr_admin")
        self.store.put_approval(a)
        found = self.store.find_approval(org_id="acme", agent_id="a1", action="tool:delete",
                                         resource="db:x", now=now)
        self.assertIsNotNone(found)
        # expired approval is not found
        self.assertIsNone(self.store.find_approval(org_id="acme", agent_id="a1", action="tool:delete",
                                                   resource="db:x", now=now + 400))

    def test_audit_append_only(self):
        ev = {"event_id": new_id("pau"), "ts": time.time(), "event": "policy.created",
              "org_id": "acme", "outcome": "ok"}
        self.store.append_audit(ev)
        rows = self.store.list_audit(org_id="acme")
        self.assertTrue(any(r["event_id"] == ev["event_id"] for r in rows))
        # the append-only trigger must reject an UPDATE (mapped to ConflictError by the db layer)
        from agent_identity.core.errors import ConflictError
        with self.assertRaises(ConflictError):
            self.db.run("try_update_audit", lambda c: c.execute(
                "UPDATE policy_audit SET outcome='denied' WHERE event_id=%s", (ev["event_id"],)))

    def test_cross_tenant_isolation(self):
        p_acme = self._policy("acme")
        p_globex = self._policy("globex")
        self.store.put_policy(p_acme)
        self.store.put_policy(p_globex)
        acme_ids = {p.policy_id for p in self.store.list_policies(org_id="acme", include_platform=False)}
        self.assertIn(p_acme.policy_id, acme_ids)
        self.assertNotIn(p_globex.policy_id, acme_ids)


@unittest.skipUnless(HOST and USER, "set AGENTGUARD_TEST_PG_HOST/USER/PASSWORD for real PostgreSQL tests")
class PgPolicyDecisionTests(unittest.TestCase):
    """End-to-end: PgPolicyStore + real OPA engine + JIT, exercising the full decision path."""

    @classmethod
    def setUpClass(cls):
        import shutil
        if not shutil.which("opa"):
            raise unittest.SkipTest("opa binary not available")
        cls.dbname = "ag_pold_" + secrets.token_hex(6)
        with admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')
        cls.cfg = pgcfg(cls.dbname)
        db = Database(cls.cfg)
        migrate.migrate(db)
        cls.db = db
        cls.store = create_policy_store(db)
        cls.db.run("mk_orgs", lambda c: c.execute(
            "INSERT INTO organizations (org_id, name, status, created_at, active_issuer_key_id)"
            " VALUES ('acme','Acme','active',0,'k1') ON CONFLICT (org_id) DO NOTHING"))
        cls.pcfg = PolicyConfig(environment="development", engine="opa", opa_mode="cli",
                                eval_timeout_ms=2000)
        cls.svc = PolicyDecisionService(cls.store, build_engine(cls.pcfg), cls.pcfg)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.db.close()
        except Exception:  # noqa: BLE001
            pass
        with admin() as a:
            a.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}" WITH (FORCE)')

    def test_full_decision_path_pg(self):
        from agent_identity.security.rbac import ROLE_TENANT_ADMIN, effective_access
        actor = effective_access("usr_admin", "acme", tenant_roles=(ROLE_TENANT_ADMIN,))
        rec = self.svc.create_policy(actor, name="p", org_id="acme", rego_source=REGO)
        self.svc.activate(actor, rec.policy_id, 1)
        d = self.svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:public")
        self.assertIs(d.kind, DecisionKind.ALLOW)
        d2 = self.svc.authorize(agent_id="a1", tenant="acme", action="tool:read", resource="db:secret")
        self.assertIs(d2.kind, DecisionKind.DENY)


if __name__ == "__main__":
    unittest.main()
