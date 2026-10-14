"""Step 11 REAL PostgreSQL integration tests: migration 0006 + the PG governance store.

Skipped unless ``AGENTGUARD_TEST_PG_HOST`` is set. Mirrors ``test_policy_pg_integration.py``: a fresh
throwaway database, the real migration chain (0001..0006), real RLS, and the real PgGovernanceStore.

  AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres \\
    AGENTGUARD_TEST_PG_PASSWORD=postgres PYTHONPATH=src:. \\
    python -m unittest -v tests.test_governance_pg_integration

Coverage:
  * migration 0006 applies on top of 0005 (schema version >= 6, new tables present)
  * resource + tool round-trips through PostgreSQL
  * a resource can never change tenant (the ON CONFLICT ... WHERE org_id guard)
  * governance_audit is append-only (UPDATE/DELETE rejected by the trigger)
  * cross-tenant isolation holds even for an unfiltered SELECT (RLS)
  * a full guard decision (real OPA + PG registry) ALLOWs, then DENYs after a registry change
"""
from __future__ import annotations

import os
import secrets
import shutil
import unittest
from dataclasses import replace

from agent_identity.governance import (GovernanceConfig, GovernanceOutcome, GovernanceService)
from agent_identity.governance.models import ResourceType, Sensitivity
from agent_identity.policy import (PolicyConfig, PolicyDecisionService, StoreApprovalProvider,
                                   build_engine)
from agent_identity.security.rbac import (ROLE_PLATFORM_ADMIN, ROLE_TENANT_ADMIN, effective_access)
from agent_identity.storage.postgres import PgConfig, migrate
from agent_identity.storage.postgres.db import Database
from agent_identity.storage.postgres.governance import create_governance_store
from agent_identity.storage.postgres.policy import create_policy_store

HOST = os.environ.get("AGENTGUARD_TEST_PG_HOST", "")
PORT = int(os.environ.get("AGENTGUARD_TEST_PG_PORT", "5432"))
USER = os.environ.get("AGENTGUARD_TEST_PG_USER", "")
PW = os.environ.get("AGENTGUARD_TEST_PG_PASSWORD", "")
OPA = shutil.which("opa")

GOV_ALLOW_REGO = """
package agentguard.authz

default decision := {"decision": "DENY", "reason": "default_deny"}

decision := {"decision": "ALLOW", "reason": "gov_allow"} {
    input.request_context.registry_status == "registered"
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


@unittest.skipUnless(HOST and USER, "set AGENTGUARD_TEST_PG_HOST/USER/PASSWORD for real PG tests")
@unittest.skipUnless(OPA, "the opa binary is required")
class GovernancePgTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dbname = "ag_gov_" + secrets.token_hex(6)
        with admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')
        cls.cfg = pgcfg(cls.dbname)
        cls.db = Database(cls.cfg)
        migrate.migrate(cls.db)                     # applies 0001..0006
        cls.store = create_governance_store(cls.db)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.db.close()
        except Exception:                           # noqa: BLE001
            pass
        try:
            with admin() as a:
                a.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}" WITH (FORCE)')
        except Exception:                           # noqa: BLE001
            pass

    def setUp(self):
        self.org = "org_" + secrets.token_hex(6)
        self.db.run("s11_mk_org", lambda c: c.execute(
            "INSERT INTO organizations (org_id, name, status, created_at, active_issuer_key_id)"
            " VALUES (%s, %s, 'active', 0, 'k1')", (self.org, self.org)))
        self.actor = effective_access("usr_admin", self.org, tenant_roles=(ROLE_TENANT_ADMIN,))

    def _service(self):
        pstore = create_policy_store(self.db)
        pcfg = PolicyConfig(environment="development", engine="opa", opa_mode="cli",
                            eval_timeout_ms=3000, cache_enabled=True)
        psvc = PolicyDecisionService(pstore, build_engine(pcfg), pcfg,
                                     approvals=StoreApprovalProvider(pstore, pcfg))
        return GovernanceService(self.store, psvc,
                                 config=GovernanceConfig(environment="development"))

    # ------------------------------------------------------------------ migration
    def test_migration_0006_applied(self):
        self.assertGreaterEqual(migrate.expected_version(), 6)
        self.assertEqual(migrate.current_version(self.db), migrate.expected_version())

    def test_governance_tables_exist(self):
        rows = self.db.run("s11_tables", lambda c: c.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' "
            "AND tablename IN ('resources','tools','governance_audit')").fetchall())
        self.assertEqual({r["tablename"] for r in rows},
                         {"resources", "tools", "governance_audit"})

    # ------------------------------------------------------------------ round-trips
    def test_resource_round_trip(self):
        gov = self._service()
        rid = f"api:{self.org}"
        gov.resources.register_resource(
            self.actor, resource_id=rid, org_id=self.org, resource_type="http_api",
            name="billing_api", owner="platform-team", sensitivity="confidential",
            permitted_operations=["read", "write"])
        rec = gov.resources.get_resource(self.actor, rid)
        self.assertIs(rec.resource_type, ResourceType.HTTP_API)
        self.assertIs(rec.sensitivity, Sensitivity.CONFIDENTIAL)
        self.assertEqual({o.value for o in rec.permitted_operations}, {"read", "write"})

    def test_tool_round_trip(self):
        gov = self._service()
        rid = f"tool:{self.org}"
        gov.resources.register_resource(
            self.actor, resource_id=rid, org_id=self.org, resource_type="tool", name="lookup",
            owner="platform-team", permitted_operations=["invoke"])
        gov.tools.register_tool(self.actor, org_id=self.org, name="lookup", version="1",
                                owner="platform-team", resource_id=rid,
                                requested_capabilities=["data:read"])
        gov.tools.approve_tool(self.actor, "lookup@1", approved_capabilities=["data:read"])
        rec = gov.tools.resolve("lookup@1")
        self.assertTrue(rec.approved)
        self.assertEqual(rec.approved_capabilities, ("data:read",))
        self.assertEqual(rec.requested_capabilities, ("data:read",))

    def test_resource_cannot_change_tenant(self):
        gov = self._service()
        rid = f"api:{self.org}"
        gov.resources.register_resource(
            self.actor, resource_id=rid, org_id=self.org, resource_type="http_api",
            name="billing_api", owner="team", permitted_operations=["read"])
        rec = self.store.get_resource(rid)
        self.store.put_resource(replace(rec, org_id="other_tenant_xyz"))   # guarded: rejected
        self.assertEqual(self.store.get_resource(rid).org_id, self.org)

    # ------------------------------------------------------------------ append-only audit
    def test_governance_audit_is_append_only(self):
        eid = "ev_" + secrets.token_hex(6)
        self.store.append_audit({"event_id": eid, "ts": 1.0, "event": "governance.decision",
                                 "org_id": self.org, "decision": "ALLOW", "outcome": "ok"})
        with self.assertRaises(Exception):
            self.db.run("s11_audit_update", lambda c: c.execute(
                "UPDATE governance_audit SET decision='DENY' WHERE event_id=%s", (eid,)))
        with self.assertRaises(Exception):
            self.db.run("s11_audit_delete", lambda c: c.execute(
                "DELETE FROM governance_audit WHERE event_id=%s", (eid,)))

    # ------------------------------------------------------------------ RLS
    def test_rls_enabled_and_scoped_on_governance_tables(self):
        """RLS must be ENABLED with a policy on every tenant-scoped governance table."""
        rows = self.db.run("s11_rls_catalog", lambda c: c.execute(
            "SELECT relname, relrowsecurity FROM pg_class WHERE relname IN "
            "('resources','tools','governance_audit')").fetchall())
        self.assertEqual({r["relname"] for r in rows},
                         {"resources", "tools", "governance_audit"})
        for r in rows:
            self.assertTrue(r["relrowsecurity"], f"RLS not enabled on {r['relname']}")
        pol = self.db.run("s11_rls_policies", lambda c: c.execute(
            "SELECT count(*) AS n FROM pg_policies WHERE tablename IN "
            "('resources','tools','governance_audit')").fetchone())
        self.assertGreaterEqual(pol["n"], 3)

    def test_rls_blocks_cross_tenant_reads_for_non_superuser(self):
        """A non-owner, NON-superuser role must see only the tenant in ``app.current_org``.

        RLS does not apply to superusers or to the table owner, so the isolation guarantee for the
        application is only real when the app connects as a least-privilege role — which is exactly
        what this test provisions and proves.
        """
        other = "org_" + secrets.token_hex(6)
        self.db.run("s11_mk_other_org", lambda c: c.execute(
            "INSERT INTO organizations (org_id, name, status, created_at, active_issuer_key_id)"
            " VALUES (%s, %s, 'active', 0, 'k1')", (other, other)))
        gov = self._service()
        plat = effective_access("usr_platform", self.org, global_roles=(ROLE_PLATFORM_ADMIN,))
        gov.resources.register_resource(
            plat, resource_id=f"api:{other}", org_id=other, resource_type="http_api",
            name="secret_api", owner="team", permitted_operations=["read"])
        gov.resources.register_resource(
            self.actor, resource_id=f"api:{self.org}", org_id=self.org, resource_type="http_api",
            name="own_api", owner="team", permitted_operations=["read"])

        probe_role = "ag_rls_" + secrets.token_hex(4)
        probe_pw = secrets.token_urlsafe(12)
        try:
            # CREATE ROLE is DDL: PostgreSQL does not accept a bind placeholder for the password, so
            # the value is inlined. probe_pw is a locally generated token_urlsafe value (charset
            # [A-Za-z0-9_-]), so it carries no quote/escape hazard.
            self.db.run("s11_mk_probe", lambda c: c.execute(
                f"CREATE ROLE {probe_role} LOGIN PASSWORD '{probe_pw}' "
                "NOSUPERUSER NOBYPASSRLS"))
            self.db.run("s11_grant_probe", lambda c: (
                c.execute(f"GRANT USAGE ON SCHEMA public TO {probe_role}"),
                c.execute(f"GRANT SELECT ON resources TO {probe_role}")))
            import psycopg
            conn = psycopg.connect(host=HOST, port=PORT, user=probe_role, password=probe_pw,
                                   dbname=self.dbname)
            try:
                # SET is not parameterizable; set_config() accepts a bound value.
                conn.execute("SELECT set_config('app.current_org', %s, false)", (self.org,))
                got = {r[0] for r in conn.execute(
                    "SELECT resource_id FROM resources").fetchall()}
            finally:
                conn.close()
        finally:
            try:
                self.db.run("s11_cleanup_probe", lambda c: (
                    c.execute(f"REVOKE ALL ON resources FROM {probe_role}"),
                    c.execute(f"DROP OWNED BY {probe_role}"),
                    c.execute(f"DROP ROLE IF EXISTS {probe_role}")))
            except Exception:                       # noqa: BLE001
                pass

        # the unfiltered SELECT under the probe role saw ONLY the scoped tenant's row
        self.assertIn(f"api:{self.org}", got)
        self.assertNotIn(f"api:{other}", got)

    # ------------------------------------------------------------------ end-to-end
    def test_full_decision_path_with_pg_registry(self):
        gov = self._service()
        pol = gov.policy.create_policy(self.actor, name="gov", org_id=self.org,
                                       rego_source=GOV_ALLOW_REGO)
        gov.policy.activate(self.actor, pol.policy_id, 1)
        rid = f"api:{self.org}"
        gov.resources.register_resource(
            self.actor, resource_id=rid, org_id=self.org, resource_type="http_api",
            name="billing_api", owner="team", permitted_operations=["read"])
        d = gov.decide(agent_id="agt1", tenant=self.org, resource_id=rid, operation="read")
        self.assertIs(d.outcome, GovernanceOutcome.ALLOW)
        self.assertTrue(d.allowed)
        gov.resources.set_enabled(self.actor, rid, False)
        d2 = gov.decide(agent_id="agt1", tenant=self.org, resource_id=rid, operation="read")
        self.assertIs(d2.outcome, GovernanceOutcome.DENY)
        self.assertEqual(d2.reason, "resource_disabled")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
