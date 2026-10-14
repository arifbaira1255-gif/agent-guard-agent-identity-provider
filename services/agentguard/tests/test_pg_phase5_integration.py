"""Phase 5 REAL PostgreSQL integration tests (migration 0008).

Skipped unless ``AGENTGUARD_TEST_PG_HOST`` is set. Each class gets its own throwaway database, so the
tests exercise the authoritative store, the RLS policies, the append-only triggers and the cursor
pagination against real SQL rather than an in-memory double.

    AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=... AGENTGUARD_TEST_PG_PASSWORD=... \
    PYTHONPATH=src:. python3 -m unittest tests.test_pg_phase5_integration

**RLS honesty note.** PostgreSQL exempts SUPERUSER and BYPASSRLS roles from Row-Level Security, and
the test role here is a superuser (it must be, to CREATE DATABASE). So this suite verifies the
tenant-boundary control in two independent ways that DO hold for a superuser:

  1. the application-level ``org_id=`` filter, exercised through the real store against real SQL
     (``test_cross_tenant_read_is_blocked_by_the_query_filter``), and
  2. the RLS *configuration itself* -- policies present, enabled and non-permissive
     (``test_rls_policies_are_configured``) -- plus a live enforcement check executed as a
     **non-superuser** role when one can be created (``test_rls_blocks_a_cross_tenant_read``).

The production requirement (the application connects as a NON-superuser, non-BYPASSRLS role) is
recorded in ``docs/PHASE5_SECURITY_LIMITATIONS.md``.
"""
from __future__ import annotations

import os
import secrets
import time
import unittest

from agent_identity.runtime_monitoring import (AlertService, BehaviorProfileService, IntentGraph,
                                               MonitoringConfig, RuntimeEventPipeline)
from agent_identity.storage.postgres import PgConfig
from agent_identity.storage.postgres import migrate
from agent_identity.storage.postgres.db import Database
from agent_identity.storage.postgres.runtime_monitoring import PgRuntimeMonitoringStore

HOST = os.environ.get("AGENTGUARD_TEST_PG_HOST", "")
PORT = int(os.environ.get("AGENTGUARD_TEST_PG_PORT", "5432"))
USER = os.environ.get("AGENTGUARD_TEST_PG_USER", "")
PW = os.environ.get("AGENTGUARD_TEST_PG_PASSWORD", "")
ORG_A = "org_a"
ORG_B = "org_b"
ORG_C = "org_c"                    # dedicated tenant for the pagination walk, so no other test's
                                     # rows can interleave with the keyset ordering
N_PAGE_EVENTS = 6
#: Fixed reference instant for the suite -- recomputed per run from the wall clock, because the
#: ingestion pipeline rejects events that predate the retention horizon (fail-closed).
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


def raw(**kw):
    base = {"org_id": ORG_A, "event_type": "tool.invocation", "ts": NOW, "agent_id": "agent_1",
            "action": "read_file", "resource": "s3://bucket/x", "decision": "ALLOW"}
    base.update(kw)
    return base


@unittest.skipUnless(HOST and USER, "set AGENTGUARD_TEST_PG_HOST/USER/PASSWORD for real PostgreSQL tests")
class PgPhase5Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dbname = "ag_p5_" + secrets.token_hex(6)
        with admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')      # generated name, never user input
            # A least-privilege login role used by the RLS enforcement test. CREATE ROLE is a
            # utility statement and takes no bound parameters, so the literals below are hardcoded
            # in-file constants -- never user input. The name is run-scoped so parallel or repeated
            # runs never collide on a cluster-level object.
            cls.role = "ag_p5_app_" + secrets.token_hex(4)
            a.execute(f"CREATE ROLE {cls.role} LOGIN PASSWORD 'apppw'")
        cls.cfg = pgcfg(cls.dbname)
        cls.db = Database(cls.cfg)
        migrate.migrate(cls.db)
        cls.store = PgRuntimeMonitoringStore(cls.db)
        cls.cfgm = MonitoringConfig(default_min_samples=1)
        cls.pipe = RuntimeEventPipeline(cls.store, config=cls.cfgm)
        with cls.db.tenant_scope(None, platform_admin=True):
            cls.db.run("seed_orgs", lambda c: c.execute(
                "INSERT INTO organizations (org_id, name, status, created_at, active_issuer_key_id)"
                " VALUES (%s,%s,'active',%s,'key_a'),(%s,%s,'active',%s,'key_b'),"
                "(%s,%s,'active',%s,'key_c') ON CONFLICT DO NOTHING",
                (ORG_A, "a", NOW, ORG_B, "b", NOW, ORG_C, "c", NOW)))

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
                except Exception:                             # noqa: BLE001 - role never created
                    pass

    # ------------------------------------------------------------------ helpers
    def ingest(self, org, **kw):
        with self.db.tenant_scope(org):
            return self.pipe.ingest(raw(org_id=org, **kw))


class MigrationTests(PgPhase5Case):
    def test_migration_0008_applied_and_is_the_expected_head(self):
        with self.db.tenant_scope(None, platform_admin=True):
            version = migrate.current_version(self.db)
        self.assertEqual(version, migrate.expected_version())
        self.assertGreaterEqual(version, 8)

    def test_all_phase5_tables_and_indexes_exist(self):
        tables = ("runtime_events", "runtime_behavior_profiles", "runtime_drift_findings",
                  "runtime_graph_nodes", "runtime_graph_edges", "runtime_risk_assessments",
                  "runtime_alert_rules", "runtime_alerts", "runtime_monitoring_audit")
        with self.db.tenant_scope(None, platform_admin=True):
            rows = self.db.run("t", lambda c: c.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname='public'").fetchall())
            idx = self.db.run("i", lambda c: c.execute(
                "SELECT indexname FROM pg_indexes WHERE schemaname='public'").fetchall())
        names = {r["tablename"] for r in rows}
        for t in tables:
            self.assertIn(t, names)
        idxnames = {r["indexname"] for r in idx}
        for expected in ("runtime_events_org_ts_idx", "runtime_events_org_agent_ts_idx",
                         "runtime_events_corr_idx", "runtime_events_dedup_idx",
                         "runtime_alerts_rate_idx", "runtime_findings_class_idx"):
            self.assertIn(expected, idxnames)


class EventStoreTests(PgPhase5Case):
    def test_event_round_trips_through_postgres(self):
        res = self.ingest(ORG_A, correlation_id="c1", trace_id="t1", policy_id="p1",
                          latency_ms=12, data_classes=["pii"], extra={"tool_id": "t"})
        with self.db.tenant_scope(ORG_A):
            got = self.store.get_event(res.event.event_id, org_id=ORG_A)
        self.assertIsNotNone(got)
        self.assertEqual(got.correlation_id, "c1")
        self.assertEqual(got.latency_ms, 12)
        self.assertEqual(got.data_classes, ("pii",))
        self.assertEqual(got.extra.get("tool_id"), "t")

    def test_events_are_append_only_update_is_rejected(self):
        self.ingest(ORG_A, dedup_key="imm-1")
        with self.db.tenant_scope(ORG_A):
            with self.assertRaises(Exception) as ctx:
                self.db.run("try_update", lambda c: c.execute(
                    "UPDATE runtime_events SET action='tampered' WHERE org_id=%s", (ORG_A,)),
                    retry=False)
        # the append-only guard fires on UPDATE (SQLSTATE 23514 -> ConflictError)
        self.assertIn("immutable", str(ctx.exception).lower())

    def test_duplicate_dedup_key_is_detected_across_connections(self):
        self.ingest(ORG_A, dedup_key="dupe-1")
        with self.db.tenant_scope(ORG_A):
            self.assertTrue(self.store.has_dedup_key(org_id=ORG_A, dedup_key="dupe-1"))
            self.assertFalse(self.store.has_dedup_key(org_id=ORG_A, dedup_key="dupe-2"))

    def test_cursor_pagination_is_exact_and_does_not_repeat_boundaries(self):
        # ORG_C is used by no other test, so the corpus is exactly N_PAGE_EVENTS rows and the walk
        # can be asserted exhaustively. (This test previously shared ORG_A, where another test's
        # rows interleaved with the keyset ordering and made the page sum non-deterministic.)
        for i in range(N_PAGE_EVENTS):
            self.ingest(ORG_C, ts=NOW + i, resource=f"r{i}", dedup_key=f"pg{i}")
        with self.db.tenant_scope(ORG_C):
            total = self.store.count_events(org_id=ORG_C)
            self.assertEqual(total, N_PAGE_EVENTS)
            # Walk with the cursor until the store says there is no continuation. (Passing a None
            # cursor back in legitimately means "start again", so the walk must stop at the first
            # None rather than asking for a third page unconditionally.)
            seen: list = []
            cursor = None
            pages = 0
            first_two_lengths = []
            while True:
                page, cursor = self.store.list_events(org_id=ORG_C, limit=3, cursor=cursor)
                if not page:
                    break
                seen.extend(page)
                pages += 1
                if pages <= 2:
                    first_two_lengths.append(len(page))
                if cursor is None:
                    break
                self.assertLessEqual(pages, 10, "cursor walk failed to terminate")
            self.assertEqual(first_two_lengths, [3, 3])
            self.assertEqual(pages, 2)
        row_ids = [e.event_id for e in seen]
        self.assertEqual(len(row_ids), total, "the walk must not skip a row")
        self.assertEqual(len(row_ids), len(set(row_ids)), "the walk must not repeat a row")
        tss = [e.ts for e in seen]
        self.assertEqual(tss, sorted(tss, reverse=True), "order must hold across page boundaries")

    def test_aggregate_and_counts_are_tenant_scoped(self):
        self.ingest(ORG_A, event_type="tool.invocation", dedup_key="a1")
        self.ingest(ORG_A, event_type="dlp.blocked", dedup_key="a2")
        self.ingest(ORG_B, event_type="tool.invocation", dedup_key="b1")
        with self.db.tenant_scope(ORG_A):
            self.assertEqual(self.store.count_events(org_id=ORG_A), 2)
            agg = self.store.aggregate_by_type(org_id=ORG_A)
        self.assertEqual(agg.get("dlp.blocked"), 1)
        self.assertEqual(agg.get("tool.invocation"), 1)     # NOT 2 -- B's row is invisible

    def test_late_flag_is_persisted(self):
        self.ingest(ORG_A, ts=NOW, dedup_key="l0")
        res = self.ingest(ORG_A, ts=NOW - 3600, resource="late", dedup_key="l1")
        with self.db.tenant_scope(ORG_A):
            got = self.store.get_event(res.event.event_id, org_id=ORG_A)
        self.assertTrue(got.late)


class TenantBoundaryTests(PgPhase5Case):
    def test_cross_tenant_read_is_blocked_by_the_query_filter(self):
        self.ingest(ORG_B, dedup_key="bt1")
        with self.db.tenant_scope(ORG_A):
            self.assertEqual(self.store.count_events(org_id=ORG_A), 0)
            self.assertEqual(self.store.list_events(org_id=ORG_A)[0], [])
            self.assertEqual(self.store.list_findings(org_id=ORG_A), [])
            self.assertEqual(self.store.list_alerts(org_id=ORG_A), [])
            self.assertEqual(self.store.list_nodes(org_id=ORG_A), [])
            self.assertEqual(self.store.list_edges(org_id=ORG_A), [])

    def test_rls_policies_are_configured_enabled_and_non_permissive(self):
        with self.db.tenant_scope(None, platform_admin=True):
            rows = self.db.run("rls", lambda c: c.execute(
                "SELECT tablename, rowsecurity FROM pg_tables"
                " WHERE schemaname='public' AND tablename LIKE 'runtime_%'").fetchall())
            policies = self.db.run("pol", lambda c: c.execute(
                "SELECT tablename, qual FROM pg_policies WHERE schemaname='public'"
                " AND tablename LIKE 'runtime_%'").fetchall())
        enabled = {r["tablename"] for r in rows if r["rowsecurity"]}
        for t in ("runtime_events", "runtime_behavior_profiles", "runtime_drift_findings",
                  "runtime_graph_nodes", "runtime_graph_edges", "runtime_risk_assessments",
                  "runtime_alert_rules", "runtime_alerts", "runtime_monitoring_audit"):
            self.assertIn(t, enabled, f"{t} must have RLS enabled")
        self.assertTrue(policies)
        for p in policies:
            qual = (p["qual"] or "").lower()
            self.assertIn("app.current_org", qual, "every policy must scope to the request tenant")
            # must not be EVERYTHING-permissive: ``USING (true)`` with no tenant predicate.
            self.assertNotEqual(qual.replace(" ", ""), "true")
            self.assertIn("org_id", qual)

    def test_rls_blocks_a_cross_tenant_read_as_a_non_superuser(self):
        """Live RLS enforcement: connect as a NON-superuser, non-BYPASSRLS role and try to read
        another tenant's row. Skipped (with reason) if this environment forbids creating the role."""
        self.ingest(ORG_A, dedup_key="rls-a")
        self.ingest(ORG_B, dedup_key="rls-b")
        try:
            # the object grants must run AGAINST THE TEST DATABASE, where the tables live
            with admin(self.dbname) as a:
                a.execute(f'GRANT CONNECT ON DATABASE "{self.dbname}" TO {self.role}')
                a.execute(f"GRANT USAGE ON SCHEMA public TO {self.role}")
                a.execute(f"GRANT SELECT ON runtime_events TO {self.role}")
        except Exception as e:                                        # noqa: BLE001
            self.skipTest(f"cannot provision the least-privilege test role: {type(e).__name__}: {e}")
        import psycopg
        from psycopg.rows import dict_row
        with psycopg.connect(host=HOST, port=PORT, user=self.role, password="apppw",
                             dbname=self.dbname, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('app.current_org', %s, true)", (ORG_A,))
                n = conn.execute("SELECT count(*) AS n FROM runtime_events").fetchone()["n"]
                ours = conn.execute(
                    "SELECT count(*) AS n FROM runtime_events WHERE org_id=%s", (ORG_A,)
                ).fetchone()["n"]
                theirs = conn.execute(
                    "SELECT count(*) AS n FROM runtime_events WHERE org_id=%s", (ORG_B,)
                ).fetchone()["n"]
        # RLS hides B's row even when the query explicitly asks for it
        self.assertEqual(theirs, 0, "RLS must hide another tenant's rows")
        self.assertEqual(n, ours)


class RetentionTests(PgPhase5Case):
    def test_purge_is_org_scoped_and_removes_only_old_rows(self):
        self.ingest(ORG_A, ts=NOW - 100000, dedup_key="old-a")
        self.ingest(ORG_A, ts=NOW, dedup_key="new-a")
        self.ingest(ORG_B, ts=NOW - 100000, dedup_key="old-b")
        with self.db.tenant_scope(None, platform_admin=True):
            removed = self.store.purge_before(NOW - 1000, org_id=ORG_A)
        self.assertEqual(removed, 1)
        with self.db.tenant_scope(None, platform_admin=True):
            self.assertEqual(self.store.count_events(org_id=ORG_A), 1)
            self.assertEqual(self.store.count_events(org_id=ORG_B), 1)   # untouched


class ProfileGraphAlertTests(PgPhase5Case):
    def test_profile_upsert_merges_and_versions(self):
        svc = BehaviorProfileService(self.store, config=self.cfgm)
        with self.db.tenant_scope(ORG_A):
            svc.build(org_id=ORG_A, agent_id="agent_1", events=[], now=NOW)
            v2 = svc.build(org_id=ORG_A, agent_id="agent_1", events=[], now=NOW + 10)
            got = svc.get(org_id=ORG_A, agent_id="agent_1")
        self.assertEqual(v2.version, 2)
        self.assertEqual(got.version, 2)

    def test_graph_edge_upsert_accumulates_count_in_sql(self):
        g = IntentGraph(self.store)
        with self.db.tenant_scope(ORG_A):
            for i in range(3):
                g.record_event(self.pipe.normalize(raw(org_id=ORG_A, resource="db://users",
                                                       ts=NOW + i, dedup_key=f"ge{i}")))
            edges = self.store.list_edges(org_id=ORG_A, kind="agent_resource")
        self.assertEqual(edges[0].count, 3)
        self.assertEqual(edges[0].provenance, "direct_observation")

    def test_alert_lifecycle_and_rate_count_persist(self):
        svc = AlertService(self.store, config=self.cfgm)
        with self.db.tenant_scope(ORG_A):
            rule = svc.register_rule(org_id=ORG_A, name="r", event_types=["dlp.blocked"])
            a = svc.raise_alert(org_id=ORG_A, rule=rule, severity="high", title="t",
                                agent_id="agent_1", ts=NOW)
            svc.transition(org_id=ORG_A, alert_id=a.alert_id, new_state="acknowledged",
                           actor_user_id="u1")
            got = svc.get_alert(org_id=ORG_A, alert_id=a.alert_id)
            count = self.store.count_alerts(org_id=ORG_A, rule_id=rule.rule_id, since=NOW - 1)
        self.assertEqual(got.state, "acknowledged")
        self.assertEqual(count, 1)

    def test_rule_cannot_be_moved_to_another_tenant(self):
        svc = AlertService(self.store, config=self.cfgm)
        with self.db.tenant_scope(ORG_A):
            rule = svc.register_rule(org_id=ORG_A, name="mine", rule_id="rule_fixed")
        with self.db.tenant_scope(ORG_B):
            # a same-id upsert claiming another tenant must not overwrite the original
            svc.register_rule(org_id=ORG_B, name="stolen", rule_id="rule_fixed")
        with self.db.tenant_scope(ORG_A):
            still = self.store.get_rule("rule_fixed", org_id=ORG_A)
        self.assertEqual(still.name, "mine")

    def test_monitoring_audit_is_append_only(self):
        svc = AlertService(self.store, config=self.cfgm)
        with self.db.tenant_scope(ORG_A):
            svc.register_rule(org_id=ORG_A, name="auditted")
        with self.db.tenant_scope(None, platform_admin=True):
            rows = self.store.list_audit(org_id=ORG_A)
            with self.assertRaises(Exception):
                self.db.run("try_update_audit", lambda c: c.execute(
                    "UPDATE runtime_monitoring_audit SET outcome='ok' WHERE org_id=%s", (ORG_A,)),
                    retry=False)
        self.assertTrue(rows)
        self.assertEqual(rows[0]["event"], "runtime.alert_rule.registered")


class SchemaConstraintTests(PgPhase5Case):
    def test_invalid_drift_classification_is_rejected_by_the_database(self):
        with self.db.tenant_scope(ORG_A):
            with self.assertRaises(Exception):
                self.db.run("bad_class", lambda c: c.execute(
                    "INSERT INTO runtime_drift_findings (finding_id, org_id, agent_id, ts,"
                    " classification, category, observed) VALUES"
                    " ('f_bad',%s,'a',%s,'made_up_category','x','y')", (ORG_A, NOW)), retry=False)

    def test_invalid_node_kind_is_rejected_by_the_database(self):
        with self.db.tenant_scope(ORG_A):
            with self.assertRaises(Exception):
                self.db.run("bad_node", lambda c: c.execute(
                    "INSERT INTO runtime_graph_nodes (org_id, node_id, kind, label, first_seen,"
                    " last_seen) VALUES (%s,'n1','not_a_kind','l',%s,%s)", (ORG_A, NOW, NOW)),
                    retry=False)

    def test_negative_confidence_is_rejected(self):
        with self.db.tenant_scope(ORG_A):
            with self.assertRaises(Exception):
                self.db.run("bad_conf", lambda c: c.execute(
                    "INSERT INTO runtime_drift_findings (finding_id, org_id, ts, classification,"
                    " category, observed, confidence) VALUES ('f_c',%s,%s,'heuristic_suspicion',"
                    "'x','y',-1)", (ORG_A, NOW)), retry=False)


if __name__ == "__main__":                                            # pragma: no cover
    unittest.main()
