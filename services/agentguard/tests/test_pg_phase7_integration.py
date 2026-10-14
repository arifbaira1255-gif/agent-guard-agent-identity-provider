"""Phase 7 REAL PostgreSQL integration tests (migration 0010).

Skipped unless ``AGENTGUARD_TEST_PG_HOST`` is set. Each class gets its own throwaway database, so the
tests exercise the authoritative ``PostgresAssuranceStore``, the RLS policies, the append-only audit
trigger and the hash-chained audit against real SQL rather than an in-memory double.

    AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=... AGENTGUARD_TEST_PG_PASSWORD=... \\
    PYTHONPATH=src:. python3 -m unittest tests.test_pg_phase7_integration

**RLS honesty note.** The test role is a superuser (it must be, to CREATE DATABASE), and PostgreSQL
exempts SUPERUSER/BYPASSRLS roles from Row-Level Security. So this suite verifies the tenant-boundary
control in two independent ways that DO hold for a superuser: (1) the application-level ``org_id=``
filter exercised through the real store, and (2) the RLS *configuration* itself (policies present,
enabled, non-permissive), plus a live enforcement check as a NON-superuser role. The production
requirement (connect as a non-superuser) is recorded in ``docs/PHASE7_SECURITY_LIMITATIONS.md``.
"""
from __future__ import annotations

import os
import secrets
import time
import unittest

from agent_identity.assurance import (AssuranceConfig, AssuranceService, LocalEd25519Signer,
                                      MemoryAssuranceStore, SiemEvent, TamperEvidentAudit)
from agent_identity.assurance.models import EvidenceKind, SiemDelivery
from agent_identity.storage.postgres import PgConfig
from agent_identity.storage.postgres import migrate
from agent_identity.storage.postgres.assurance import PostgresAssuranceStore
from agent_identity.storage.postgres.db import Database

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


class _Clock:
    def __init__(self, t):
        self.t = t

    def now(self):
        return self.t


@unittest.skipUnless(HOST and USER, "set AGENTGUARD_TEST_PG_HOST/USER/PASSWORD for real PostgreSQL tests")
class PgPhase7Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dbname = "ag_p7_" + secrets.token_hex(6)
        with admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')
            cls.role = "ag_p7_app_" + secrets.token_hex(4)
            a.execute(f"CREATE ROLE {cls.role} LOGIN PASSWORD 'apppw'")
        cls.cfg = pgcfg(cls.dbname)
        cls.db = Database(cls.cfg)
        migrate.migrate(cls.db)
        cls.store = PostgresAssuranceStore(cls.db)
        cls.clock = _Clock(NOW)
        cls.svc = AssuranceService(cls.store, config=AssuranceConfig(environment="development"),
                                   clock=cls.clock)
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


class MigrationTests(PgPhase7Case):
    def test_migration_0010_is_the_expected_head(self):
        with self.db.tenant_scope(None, platform_admin=True):
            version = migrate.current_version(self.db)
        self.assertEqual(version, migrate.expected_version())
        self.assertGreaterEqual(version, 10)

    def test_all_phase7_tables_exist(self):
        tables = ("assurance_evidence", "assurance_recommendations", "assurance_proposals",
                  "assurance_compliance_mappings", "assurance_siem_events",
                  "assurance_siem_deliveries", "assurance_correlations", "assurance_audit",
                  "assurance_checkpoints")
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
                "SELECT relname, relrowsecurity FROM pg_class WHERE relname LIKE 'assurance_%'"
                " AND relkind='r'").fetchall())
            pols = self.db.run("pols", lambda c: c.execute(
                "SELECT tablename, policyname FROM pg_policies WHERE tablename LIKE 'assurance_%'"
                " AND policyname LIKE '%tenant_isolation'").fetchall())
        enabled = {r["relname"] for r in rows if r["relrowsecurity"]}
        for t in ("assurance_evidence", "assurance_recommendations", "assurance_proposals",
                  "assurance_siem_events", "assurance_correlations", "assurance_audit"):
            self.assertIn(t, enabled)
        self.assertGreaterEqual(len(pols), 6)

    def test_audit_update_is_rejected_by_trigger(self):
        with self.db.tenant_scope(ORG_A):
            self.svc.audit.record("evt", org_id=ORG_A, actor_user_id="u1")
        with self.assertRaises(Exception):
            with self.db.tenant_scope(ORG_A):
                self.db.run("tamper", lambda c: c.execute(
                    "UPDATE assurance_audit SET outcome='forged' WHERE org_id=%s", (ORG_A,)))


class StoreRoundTripTests(PgPhase7Case):
    def test_evidence_round_trip(self):
        with self.db.tenant_scope(ORG_A):
            e = self.svc.record_evidence(org_id=ORG_A, kind=EvidenceKind.DLP_DETECTION.value,
                                         summary="hit", source="egress", agent_id="a1")
            got = self.store.get_evidence(e.evidence_id, org_id=ORG_A)
        self.assertIsNotNone(got)
        self.assertEqual(got.kind, EvidenceKind.DLP_DETECTION.value)

    def test_tenant_isolation_of_evidence(self):
        with self.db.tenant_scope(ORG_A):
            self.svc.record_evidence(org_id=ORG_A, kind=EvidenceKind.INCIDENT.value, summary="a",
                                     source="s")
        with self.db.tenant_scope(ORG_B):
            rows = self.store.list_evidence(org_id=ORG_B, limit=100)
        self.assertEqual(rows, [])

    def test_audit_chain_round_trip_and_verify(self):
        with self.db.tenant_scope(ORG_A):
            for i in range(5):
                self.svc.audit.record("evt", org_id=ORG_A, actor_user_id="u1", detail={"i": i})
            result = self.svc.verify_audit(org_id=ORG_A)
        self.assertTrue(result["ok"], result)

    def test_audit_chain_detects_tampering(self):
        # Use a dedicated org so tampering cannot pollute the chain other tests verify.
        org = "org_tamper"
        with self.db.tenant_scope(None, platform_admin=True):
            self.db.run("seed_tamper_org", lambda c: c.execute(
                "INSERT INTO organizations (org_id, name, status, created_at, active_issuer_key_id)"
                " VALUES (%s,'t','active',%s,'key_a') ON CONFLICT DO NOTHING", (org, NOW)))
        with self.db.tenant_scope(org):
            for i in range(3):
                self.svc.audit.record("evt", org_id=org, actor_user_id="u1")
        # bypass the trigger by disabling it, then tamper (simulating an attacker with DDL rights)
        with self.db.tenant_scope(org):
            self.db.run("disable", lambda c: c.execute(
                "ALTER TABLE assurance_audit DISABLE TRIGGER assurance_audit_no_update"))
            self.db.run("tamper", lambda c: c.execute(
                "UPDATE assurance_audit SET outcome='forged' WHERE org_id=%s AND seq="
                "(SELECT min(seq) FROM assurance_audit WHERE org_id=%s)", (org, org)))
            self.db.run("enable", lambda c: c.execute(
                "ALTER TABLE assurance_audit ENABLE TRIGGER assurance_audit_no_update"))
            result = self.svc.verify_audit(org_id=org)
        self.assertFalse(result["ok"])

    def test_checkpoint_round_trip(self):
        with self.db.tenant_scope(ORG_A):
            for i in range(3):
                self.svc.audit.record("evt", org_id=ORG_A, actor_user_id="u1")
            cp = self.svc.checkpoint(org_id=ORG_A)
            self.assertIsNotNone(cp)
            result = self.svc.verify_audit(org_id=ORG_A)
        self.assertTrue(result["ok"], result)

    def test_siem_event_and_delivery_round_trip(self):
        ev = SiemEvent(event_id="sev_pg_1", ts=NOW, org_id=ORG_A, severity="high",
                       category="policy", action="deny", outcome="denied", source="policy",
                       dedup_key="k", classification="internal", fields={"note": "ok"})
        with self.db.tenant_scope(ORG_A):
            self.store.put_siem_event(ev)
            got = self.store.get_siem_event("sev_pg_1", org_id=ORG_A)
            self.store.put_delivery(SiemDelivery(delivery_id="dlv_pg_1", destination_id="d1",
                                                 event_id="sev_pg_1", org_id=ORG_A,
                                                 status="delivered", attempts=1, ts=NOW))
            dlv = self.store.get_delivery("dlv_pg_1")
        self.assertIsNotNone(got)
        self.assertEqual(got.severity, "high")
        self.assertEqual(dlv.status, "delivered")

    def test_compliance_mapping_round_trip(self):
        with self.db.tenant_scope(None, platform_admin=True):
            n = self.svc.seed_compliance()
            controls = self.store.list_mappings(framework="soc2", limit=100)
        self.assertGreater(n, 0)
        self.assertGreater(len(controls), 0)

    def test_proposal_round_trip(self):
        from agent_identity.security.rbac import ROLE_TENANT_ADMIN, effective_access
        actor = effective_access("usr_admin", ORG_A, tenant_roles=(ROLE_TENANT_ADMIN,))
        rego = ("package agentguard.authz\n\ndefault decision := {\"decision\": \"DENY\","
                " \"reason\": \"d\"}\n")
        with self.db.tenant_scope(ORG_A):
            p = self.svc.create_proposal(actor, org_id=ORG_A, proposed_rego=rego, title="t")
            got = self.store.get_proposal(p.proposal_id, org_id=ORG_A)
        self.assertIsNotNone(got)
        self.assertEqual(got.status, "draft")


class RlsEnforcementTests(PgPhase7Case):
    """Live RLS enforcement as a NON-superuser role (the production requirement)."""

    def test_non_superuser_cannot_read_other_tenant(self):
        with self.db.tenant_scope(ORG_A):
            self.svc.record_evidence(org_id=ORG_A, kind=EvidenceKind.INCIDENT.value, summary="a",
                                     source="s")
        # grant table access as the SUPERUSER (the app role cannot grant to itself)
        with admin(self.dbname) as a:
            a.execute(f"GRANT USAGE ON SCHEMA public TO {self.role}")
            a.execute(f"GRANT SELECT ON assurance_evidence TO {self.role}")
        # connect as the non-superuser app role and try to read ORG_A's row while scoped to ORG_B
        import psycopg
        with psycopg.connect(host=HOST, port=PORT, user=self.role, password="apppw",
                             dbname=self.dbname, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.current_org', %s, false)", (ORG_B,))
            rows = conn.execute("SELECT count(*) FROM assurance_evidence").fetchone()
        self.assertEqual(rows[0], 0)


if __name__ == "__main__":
    unittest.main()
