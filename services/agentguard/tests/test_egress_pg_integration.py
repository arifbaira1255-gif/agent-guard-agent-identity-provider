"""Phase 4 REAL PostgreSQL integration tests: migration 0007 + the PG egress store.

Skipped unless ``AGENTGUARD_TEST_PG_HOST`` is set. Mirrors ``test_governance_pg_integration.py``: a
fresh throwaway database, the real migration chain (0001..0007), real RLS, and the real PgEgressStore.

  AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres \\
    AGENTGUARD_TEST_PG_PASSWORD=postgres PYTHONPATH=src:. \\
    python -m unittest -v tests.test_egress_pg_integration

Coverage:
  * migration 0007 applies on top of 0006 (schema version >= 7, new tables present)
  * egress policy round-trips through PostgreSQL
  * a policy can never change tenant (the ON CONFLICT ... WHERE org_id guard)
  * egress_audit is append-only (UPDATE/DELETE rejected by the trigger)
  * cross-tenant isolation holds even for an unfiltered SELECT (RLS)
  * a full gateway decision (real PG policy store) ALLOWs, then DENYs after a policy change
"""
from __future__ import annotations

import os
import secrets
import unittest

from agent_identity.egress import (EgressConfig, EgressOutcome, EgressRequest, EgressService,
                                   Protocol)
from agent_identity.egress.addresses import AddressPolicy, StaticDnsResolver
from agent_identity.storage.postgres import PgConfig, migrate
from agent_identity.storage.postgres.db import Database
from agent_identity.storage.postgres.egress import create_egress_store

HOST = os.environ.get("AGENTGUARD_TEST_PG_HOST", "")
PORT = int(os.environ.get("AGENTGUARD_TEST_PG_PORT", "5432"))
USER = os.environ.get("AGENTGUARD_TEST_PG_USER", "")
PW = os.environ.get("AGENTGUARD_TEST_PG_PASSWORD", "")


def admin():
    import psycopg
    return psycopg.connect(host=HOST, port=PORT, user=USER, password=PW, dbname="postgres",
                           autocommit=True)


def pgcfg(dbname):
    return PgConfig(environment="development", host=HOST, port=PORT, dbname=dbname, user=USER,
                    password=PW, sslmode=os.environ.get("AGENTGUARD_TEST_PG_SSLMODE", "disable"),
                    retry_initial_backoff_seconds=0.01, pool_min_size=1, pool_max_size=8).validate()


@unittest.skipUnless(HOST and USER, "set AGENTGUARD_TEST_PG_HOST/USER/PASSWORD for real PG tests")
class EgressPgTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dbname = "ag_egr_" + secrets.token_hex(6)
        with admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')
        cls.cfg = pgcfg(cls.dbname)
        cls.db = Database(cls.cfg)
        migrate.migrate(cls.db)                     # applies 0001..0007
        cls.store = create_egress_store(cls.db)

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
        self.db.run("p4_mk_org", lambda c: c.execute(
            "INSERT INTO organizations (org_id, name, status, created_at, active_issuer_key_id)"
            " VALUES (%s, %s, 'active', 0, 'k1')", (self.org, self.org)))

    def _service(self):
        resolver = StaticDnsResolver({"api.example.com": ["93.184.216.34"]})
        return EgressService(self.store, config=EgressConfig(environment="development"),
                             address_policy=AddressPolicy(resolver=resolver))

    # ------------------------------------------------------------------ migration
    def test_migration_0007_applied(self):
        self.assertGreaterEqual(migrate.expected_version(), 7)
        self.assertEqual(migrate.current_version(self.db), migrate.expected_version())

    def test_egress_tables_exist(self):
        rows = self.db.run("p4_tables", lambda c: c.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' "
            "AND tablename IN ('egress_policies','egress_audit')").fetchall())
        self.assertEqual({r["tablename"] for r in rows}, {"egress_policies", "egress_audit"})

    # ------------------------------------------------------------------ round-trips
    def test_policy_round_trip(self):
        svc = self._service()
        rec = svc.register_policy(org_id=self.org, name="allow api",
                                  host_patterns=["api.example.com", "*.trusted.net"],
                                  protocols=["https"], ports=[443], action="ALLOW",
                                  rate_limit={"per_second": 5.0, "burst": 10})
        got = self.store.get_policy(rec.policy_id)
        self.assertEqual(got.org_id, self.org)
        self.assertEqual(set(got.host_patterns), {"api.example.com", "*.trusted.net"})
        self.assertIs(got.action, EgressOutcome.ALLOW)
        self.assertIn(Protocol.HTTPS, got.protocols)
        self.assertEqual(got.rate_limit.per_second, 5.0)

    def test_policy_cannot_change_tenant(self):
        svc = self._service()
        rec = svc.register_policy(org_id=self.org, name="allow api",
                                  host_patterns=["api.example.com"])
        other = "org_" + secrets.token_hex(6)
        self.db.run("p4_mk_org2", lambda c: c.execute(
            "INSERT INTO organizations (org_id, name, status, created_at, active_issuer_key_id)"
            " VALUES (%s, %s, 'active', 0, 'k1')", (other, other)))
        from agent_identity.egress.models import EgressPolicyRecord
        hijack = EgressPolicyRecord(**{**rec.__dict__, "org_id": other})
        self.store.put_policy(hijack)               # ON CONFLICT ... WHERE org_id blocks the move
        self.assertEqual(self.store.get_policy(rec.policy_id).org_id, self.org)

    # ------------------------------------------------------------------ audit
    def test_audit_append_only(self):
        svc = self._service()
        svc.register_policy(org_id=self.org, name="allow api", host_patterns=["api.example.com"])
        svc.decide(agent_id="a1", tenant=self.org,
                   request=EgressRequest(url="https://api.example.com/x"))
        rows = self.store.list_audit(org_id=self.org, limit=10)
        self.assertTrue(rows)
        eid = rows[0]["event_id"]
        with self.assertRaises(Exception):
            self.db.run("p4_tamper", lambda c: c.execute(
                "UPDATE egress_audit SET reason='tampered' WHERE event_id=%s", (eid,)))

    def test_rls_blocks_cross_tenant_reads_for_non_superuser(self):
        """A non-owner, NON-superuser role must see only the tenant in ``app.current_org``.

        RLS does not apply to superusers or the table owner, so the isolation guarantee is only real
        when the app connects as a least-privilege role -- which this test provisions and proves.
        """
        svc = self._service()
        svc.register_policy(org_id=self.org, name="allow api", host_patterns=["api.example.com"])
        other = "org_" + secrets.token_hex(6)
        self.db.run("p4_mk_other_org", lambda c: c.execute(
            "INSERT INTO organizations (org_id, name, status, created_at, active_issuer_key_id)"
            " VALUES (%s, %s, 'active', 0, 'k1')", (other, other)))
        svc.register_policy(org_id=other, name="other api", host_patterns=["other.example.com"])

        probe_role = "ag_egr_" + secrets.token_hex(4)
        probe_pw = secrets.token_urlsafe(12)
        try:
            self.db.run("p4_mk_probe", lambda c: c.execute(
                f"CREATE ROLE {probe_role} LOGIN PASSWORD '{probe_pw}' NOSUPERUSER NOBYPASSRLS"))
            self.db.run("p4_grant_probe", lambda c: (
                c.execute(f"GRANT USAGE ON SCHEMA public TO {probe_role}"),
                c.execute(f"GRANT SELECT ON egress_policies TO {probe_role}")))
            import psycopg
            conn = psycopg.connect(host=HOST, port=PORT, user=probe_role, password=probe_pw,
                                   dbname=self.dbname)
            try:
                conn.execute("SELECT set_config('app.current_org', %s, false)", (self.org,))
                got = {r[0] for r in conn.execute(
                    "SELECT org_id FROM egress_policies").fetchall()}
            finally:
                conn.close()
        finally:
            try:
                self.db.run("p4_cleanup_probe", lambda c: (
                    c.execute(f"REVOKE ALL ON egress_policies FROM {probe_role}"),
                    c.execute(f"DROP OWNED BY {probe_role}"),
                    c.execute(f"DROP ROLE IF EXISTS {probe_role}")))
            except Exception:                       # noqa: BLE001
                pass
        self.assertEqual(got, {self.org})

    # ------------------------------------------------------------------ end-to-end
    def test_gateway_allow_then_deny_after_policy_change(self):
        svc = self._service()
        rec = svc.register_policy(org_id=self.org, name="allow api",
                                  host_patterns=["api.example.com"])
        d1 = svc.decide(agent_id="a1", tenant=self.org,
                        request=EgressRequest(url="https://api.example.com/x"))
        self.assertIs(d1.outcome, EgressOutcome.ALLOW)
        # disable the policy -> the very next decision must deny (no stale allow)
        svc.registry.set_enabled(rec.policy_id, org_id=self.org, enabled=False)
        d2 = svc.decide(agent_id="a1", tenant=self.org,
                        request=EgressRequest(url="https://api.example.com/x"))
        self.assertIs(d2.outcome, EgressOutcome.DENY)
        self.assertEqual(d2.reason, "no_matching_policy")


if __name__ == "__main__":
    unittest.main()
