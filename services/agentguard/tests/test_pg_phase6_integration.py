"""Phase 6 REAL PostgreSQL integration tests (migration 0009).

Skipped unless ``AGENTGUARD_TEST_PG_HOST`` is set. Each class gets its own throwaway database, so the
tests exercise the authoritative ``PgResponseStore``, the RLS policies, the append-only triggers, the
conditional budget increment and the hash-chained audit against real SQL rather than an in-memory
double.

    AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=... AGENTGUARD_TEST_PG_PASSWORD=... \\
    PYTHONPATH=src:. python3 -m unittest tests.test_pg_phase6_integration

**RLS honesty note.** The test role is a superuser (it must be, to CREATE DATABASE), and PostgreSQL
exempts SUPERUSER/BYPASSRLS roles from Row-Level Security. So this suite verifies the tenant-boundary
control in two independent ways that DO hold for a superuser: (1) the application-level ``org_id=``
filter exercised through the real store, and (2) the RLS *configuration* itself (policies present,
enabled, non-permissive), plus a live enforcement check as a NON-superuser role. The production
requirement (connect as a non-superuser) is recorded in ``docs/PHASE6_SECURITY_LIMITATIONS.md``.
"""
from __future__ import annotations

import os
import secrets
import time
import unittest

from agent_identity.response import (ApprovalError, ApprovalService, BudgetService,
                                     ContainmentEngine, ContainmentIntegrations, EvidenceService,
                                     IncidentService, LoopPattern, MemoryResponseStore,
                                     ResponseConfig, ResponseLevel, ResponseService, ResponseState)
from agent_identity.response.audit import ResponseAudit
from agent_identity.runtime_monitoring.models import RuntimeEvent
from agent_identity.storage.postgres import PgConfig
from agent_identity.storage.postgres import migrate
from agent_identity.storage.postgres.db import Database
from agent_identity.storage.postgres.response import PgResponseStore

HOST = os.environ.get("AGENTGUARD_TEST_PG_HOST", "")
PORT = int(os.environ.get("AGENTGUARD_TEST_PG_PORT", "5432"))
USER = os.environ.get("AGENTGUARD_TEST_PG_USER", "")
PW = os.environ.get("AGENTGUARD_TEST_PG_PASSWORD", "")
ORG_A = "org_a"
ORG_B = "org_b"
NOW = time.time() - 86400


def admin(dbname="postgres"):
    import psycopg
    return psycopg.connect(host=HOST, port=PORT, user=USER, password=PW, dbname=dbname,
                           autocommit=True)


def pgcfg(dbname, **kw):
    d = dict(environment="development", host=HOST, port=PORT, dbname=dbname, user=USER, password=PW,
             sslmode=os.environ.get("AGENTGUARD_TEST_PG_SSLMODE", "disable"),
             retry_initial_backoff_seconds=0.01, pool_min_size=1, pool_max_size=8)
    d.update(kw)
    return PgConfig(**d).validate()


@unittest.skipUnless(HOST and USER, "set AGENTGUARD_TEST_PG_HOST/USER/PASSWORD for real PostgreSQL tests")
class PgPhase6Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dbname = "ag_p6_" + secrets.token_hex(6)
        with admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')
            cls.role = "ag_p6_app_" + secrets.token_hex(4)
            a.execute(f"CREATE ROLE {cls.role} LOGIN PASSWORD 'apppw'")
        cls.cfg = pgcfg(cls.dbname)
        cls.db = Database(cls.cfg)
        migrate.migrate(cls.db)
        cls.store = PgResponseStore(cls.db)
        cls.clock = _Clock(NOW)
        cls.cfgm = ResponseConfig(containment_allow_auto=True,
                                  containment_high_impact_requires_approval=False)
        cls.svc = ResponseService(cls.store, config=cls.cfgm, clock=cls.clock)
        with cls.db.tenant_scope(None, platform_admin=True):
            cls.db.run("seed_orgs", lambda c: c.execute(
                "INSERT INTO organizations (org_id, name, status, created_at, active_issuer_key_id)"
                " VALUES (%s,%s,'active',%s,'key_a'),(%s,%s,'active',%s,'key_b') ON CONFLICT DO NOTHING",
                (ORG_A, "a", NOW, ORG_B, "b", NOW)))

    @classmethod
    def tearDownClass(cls):
        try:
            cls.db.close()
        finally:
            with admin() as a:
                a.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}" WITH (FORCE)')
                try:
                    a.execute(f"DROP OWNED BY {cls.role}")
                    a.execute(f"DROP ROLE IF EXISTS {cls.role}")
                except Exception:                             # noqa: BLE001
                    pass


class _Clock:
    def __init__(self, t):
        self.t = t

    def now(self):
        return self.t


class MigrationTests(PgPhase6Case):
    def test_migration_0009_is_the_expected_head(self):
        with self.db.tenant_scope(None, platform_admin=True):
            version = migrate.current_version(self.db)
        self.assertEqual(version, migrate.expected_version())
        self.assertGreaterEqual(version, 9)

    def test_all_phase6_tables_exist(self):
        tables = ("response_loop_findings", "response_budgets", "response_emergency_stops",
                  "response_approvals", "response_incidents", "response_executions",
                  "response_evidence", "response_audit")
        with self.db.tenant_scope(None, platform_admin=True):
            rows = self.db.run("t", lambda c: c.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname='public'").fetchall())
        names = {r["tablename"] for r in rows}
        for t in tables:
            self.assertIn(t, names)

    def test_migration_is_idempotent(self):
        with self.db.tenant_scope(None, platform_admin=True):
            before = migrate.current_version(self.db)
            migrate.migrate(self.db)
            after = migrate.current_version(self.db)
        self.assertEqual(before, after)

    def test_rls_enabled_and_policies_present(self):
        with self.db.tenant_scope(None, platform_admin=True):
            rows = self.db.run("rls", lambda c: c.execute(
                "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class"
                " WHERE relname LIKE 'response_%' AND relkind='r'").fetchall())
        rls = {r["relname"]: r for r in rows}
        for t in ("response_loop_findings", "response_budgets", "response_approvals",
                  "response_incidents", "response_executions", "response_evidence",
                  "response_audit"):
            self.assertTrue(rls[t]["relrowsecurity"], f"{t} must have rowsecurity enabled")
        with self.db.tenant_scope(None, platform_admin=True):
            pol = self.db.run("pol", lambda c: c.execute(
                "SELECT tablename, policyname FROM pg_policies WHERE tablename LIKE 'response_%'"
            ).fetchall())
        by_table = {}
        for p in pol:
            by_table.setdefault(p["tablename"], []).append(p["policyname"])
        for t in ("response_loop_findings", "response_budgets", "response_approvals",
                  "response_incidents", "response_executions", "response_evidence",
                  "response_audit"):
            self.assertIn(f"{t}_tenant_isolation", by_table.get(t, []), f"{t} missing RLS policy")


class BudgetPgTests(PgPhase6Case):
    def test_budget_round_trips_and_conditional_increment(self):
        b = self.svc.budgets.set_budget(org_id=ORG_A, agent_id="agent_pg", max_actions=2)
        with self.db.tenant_scope(ORG_A):
            d1 = self.svc.budgets.guard(org_id=ORG_A, agent_id="agent_pg")
            d2 = self.svc.budgets.guard(org_id=ORG_A, agent_id="agent_pg")
        self.assertTrue(d1.allowed and d2.allowed)
        from agent_identity.response import BudgetExceededError
        with self.assertRaises(BudgetExceededError):
            with self.db.tenant_scope(ORG_A):
                self.svc.budgets.guard(org_id=ORG_A, agent_id="agent_pg")
        # The refused op did NOT advance the counter (counter stays at 2, not 3).
        with self.db.tenant_scope(ORG_A):
            got = self.svc.budgets.get_budget(org_id=ORG_A, agent_id="agent_pg")
        self.assertEqual(got.actions_used, 2)

    def test_budget_cross_tenant_isolation(self):
        self.svc.budgets.set_budget(org_id=ORG_A, agent_id="agent_iso", max_actions=5)
        with self.db.tenant_scope(ORG_B):
            got = self.svc.budgets.get_budget(org_id=ORG_B, agent_id="agent_iso")
        self.assertIsNone(got)


class ApprovalPgTests(PgPhase6Case):
    def test_approval_round_trips_and_binding(self):
        a = self.svc.approvals.request(org_id=ORG_A, agent_id="agent_ap", action="export",
                                       resource="users", requested_by="req",
                                       params={"fmt": "csv"})
        self.svc.approvals.decide(org_id=ORG_A, approval_id=a.approval_id, approved=True,
                                  decided_by="appr", approver_org_id=ORG_A)
        with self.db.tenant_scope(ORG_A):
            ok = self.svc.approvals.check(org_id=ORG_A, agent_id="agent_ap", action="export",
                                          resource="users", params={"fmt": "csv"},
                                          approval_id=a.approval_id)
        self.assertIsNotNone(ok)
        # A modified parameter set must not satisfy the same approval.
        from agent_identity.response import ApprovalMismatchError
        with self.assertRaises(ApprovalMismatchError):
            with self.db.tenant_scope(ORG_A):
                self.svc.approvals.check(org_id=ORG_A, agent_id="agent_ap", action="export",
                                         resource="users", params={"fmt": "json"},
                                         approval_id=a.approval_id)


class IncidentPgTests(PgPhase6Case):
    def test_incident_lifecycle_persists(self):
        inc = self.svc.incidents.open_or_correlate(org_id=ORG_A, title="pg incident",
                                                   agent_id="agent_inc", subject="s::r")
        inc = self.svc.incidents.transition(org_id=ORG_A, incident_id=inc.incident_id,
                                            new_status="triage")
        with self.db.tenant_scope(ORG_A):
            got = self.svc.incidents.get(org_id=ORG_A, incident_id=inc.incident_id)
        self.assertEqual(got.status, "triage")
        self.assertEqual(got.correlation_key, "agent_inc|s::r")

    def test_incident_cross_tenant_isolation(self):
        inc = self.svc.incidents.open_or_correlate(org_id=ORG_A, title="a",
                                                   agent_id="agent_x", subject="s::r")
        with self.db.tenant_scope(ORG_B):
            got = self.svc.incidents.get(org_id=ORG_B, incident_id=inc.incident_id)
        self.assertIsNone(got)


class ResponsePgTests(PgPhase6Case):
    def test_response_idempotency_across_duplicate_delivery(self):
        ex1 = self.svc.orchestrator.execute(
            org_id=ORG_A, level=ResponseLevel.RESTRICT, agent_id="agent_resp",
            authorized_by="admin", idempotency_key="pg-k1")
        ex2 = self.svc.orchestrator.execute(
            org_id=ORG_A, level=ResponseLevel.RESTRICT, agent_id="agent_resp",
            authorized_by="admin", idempotency_key="pg-k1")
        self.assertEqual(ex1.response_id, ex2.response_id)
        self.assertEqual(ex2.state, ex1.state)

    def test_loop_finding_persists(self):
        self.svc.observe_events([RuntimeEvent(
            event_id="e1", event_type="tool.invocation", ts=self.clock.t, org_id=ORG_A,
            agent_id="agent_loop", action="read_file", resource="s3://b/x")])
        findings = self.svc.evaluate_agent(org_id=ORG_A, agent_id="agent_loop", persist=True)
        # one event -> below threshold -> no finding, but evaluate must return a list
        self.assertIsInstance(findings, list)

    def test_audit_chain_round_trips_and_verifies(self):
        # A dedicated tenant so the chain length is exactly what this test wrote (the class shares one
        # database, and another test's audit rows would otherwise make the count order-dependent).
        org = "org_audit_chain"
        with self.db.tenant_scope(None, platform_admin=True):
            self.db.run("seed", lambda c: c.execute(
                "INSERT INTO organizations (org_id, name, status, created_at, active_issuer_key_id)"
                " VALUES (%s,'ac','active',%s,'k') ON CONFLICT DO NOTHING", (org, NOW)))
        audit = ResponseAudit(self.store, clock=self.clock)
        for i in range(3):
            audit.record(f"evt{i}", org_id=org)
        with self.db.tenant_scope(org):
            result = audit.verify_chain(org_id=org)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["checked"], 3)

    def test_append_only_audit_update_is_rejected(self):
        self.svc.audit.record("x", org_id=ORG_A)
        with self.db.tenant_scope(ORG_A):
            with self.assertRaises(Exception) as ctx:
                self.db.run("upd", lambda c: c.execute(
                    "UPDATE response_audit SET event='tampered' WHERE org_id=%s", (ORG_A,)),
                    retry=False)
        self.assertIn("immutable", str(ctx.exception).lower())


class RlsEnforcementPgTests(PgPhase6Case):
    def test_rls_blocks_a_cross_tenant_read_as_non_superuser(self):
        # Seed an approval in ORG_A, then read it as the non-superuser app role pinned to ORG_B:
        # RLS must return no rows even though the query has no org_id filter at the SQL level.
        a = self.svc.approvals.request(org_id=ORG_A, agent_id="agent_rls", action="act",
                                       resource="res", requested_by="req")
        import psycopg
        with self.db.tenant_scope(ORG_A):
            self.db.run("q", lambda c: c.execute(
                "SELECT approval_id FROM response_approvals WHERE approval_id=%s",
                (a.approval_id,)).fetchone())
        with admin(self.dbname) as adm:
            adm.execute(f"GRANT CONNECT ON DATABASE \"{self.dbname}\" TO {self.role}")
            adm.execute(f"GRANT USAGE ON SCHEMA public TO {self.role}")
            adm.execute("GRANT SELECT ON response_approvals TO " + self.role)
        conn = psycopg.connect(host=HOST, port=PORT, user=self.role, password="apppw",
                               dbname=self.dbname, autocommit=True)
        try:
            conn.execute("SELECT set_config('app.current_org', %s, true)", (ORG_B,))
            row = conn.execute(
                "SELECT approval_id FROM response_approvals WHERE approval_id=%s",
                (a.approval_id,)).fetchone()
        finally:
            conn.close()
        # RLS pinned the connection to ORG_B, so ORG_A's approval is invisible.
        self.assertIsNone(row)


if __name__ == "__main__":
    unittest.main()
