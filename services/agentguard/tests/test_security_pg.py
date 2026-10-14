"""REAL PostgreSQL + Redis integration and NEGATIVE security tests for Step 8.

Skipped unless AGENTGUARD_TEST_PG_HOST and AGENTGUARD_TEST_REDIS_HOST are set. Each class gets a
fresh throwaway database; Redis uses a unique key prefix (shared dev Redis is safe).

  AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=... AGENTGUARD_TEST_PG_PASSWORD=...
  AGENTGUARD_TEST_REDIS_HOST=127.0.0.1 PYTHONPATH=src:. python -m unittest -v tests.test_security_pg
"""
import dataclasses
import os
import secrets
import unittest

from agent_identity.core.clock import FixedClock
from agent_identity.core.errors import (AuthenticationError, ConflictError, ForbiddenError,
                                        NotFoundError, RateLimitedError, ValidationError)
from agent_identity.observability.logging import SecurityLogger
from agent_identity.security import (AdminOps, EnterpriseAuthConfig, EnterpriseAuthService,
                                     MemoryEnterpriseStore, TokenSigner)
from agent_identity.security import passwords as pw
from agent_identity.security import rbac
from agent_identity.security.admin_ops import bootstrap_platform_admin
from agent_identity.security.ids import new_id
from agent_identity.security.models import (EnterpriseUser, MembershipStatus, TenantMembership,
                                            UserStatus, ROLE_PLATFORM_ADMIN, ROLE_TENANT_ADMIN,
                                            ROLE_SECURITY_ANALYST, ROLE_SECURITY_OPERATOR,
                                            ROLE_DEVELOPER, ROLE_READONLY_AUDITOR)
from agent_identity.security.redis_keys import SecurityKeys
from agent_identity.state.redis_backend import RedisBackend
from agent_identity.state import RedisConfig
from agent_identity.storage.postgres import PgConfig, build_postgres_storage
from agent_identity.storage.postgres import migrate
from agent_identity.storage.postgres.db import Database
from agent_identity.storage.postgres.enterprise import PgEnterpriseStore

PG_HOST = os.environ.get("AGENTGUARD_TEST_PG_HOST", "")
PG_PORT = int(os.environ.get("AGENTGUARD_TEST_PG_PORT", "5432"))
PG_USER = os.environ.get("AGENTGUARD_TEST_PG_USER", "")
PG_PW = os.environ.get("AGENTGUARD_TEST_PG_PASSWORD", "")
R_HOST = os.environ.get("AGENTGUARD_TEST_REDIS_HOST", "")
R_PORT = int(os.environ.get("AGENTGUARD_TEST_REDIS_PORT", "6379"))
R_PW = os.environ.get("AGENTGUARD_TEST_REDIS_PASSWORD", "")

GOOD_PW = "Corr3ct-Horse-Battery!"


def _admin():
    import psycopg
    return psycopg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PW, dbname="postgres",
                           autocommit=True)


def _conn(dbname, user, password, autocommit=True):
    import psycopg
    return psycopg.connect(host=PG_HOST, port=PG_PORT, user=user, password=password, dbname=dbname,
                           autocommit=autocommit)


def pgcfg(dbname):
    return PgConfig(environment="development", host=PG_HOST, port=PG_PORT, dbname=dbname, user=PG_USER,
                    password=PG_PW, sslmode=os.environ.get("AGENTGUARD_TEST_PG_SSLMODE", "disable"),
                    retry_initial_backoff_seconds=0.01, pool_min_size=1, pool_max_size=8).validate()


def rcfg(prefix):
    return RedisConfig(environment="development", host=R_HOST, port=R_PORT, password=R_PW,
                       tls=False, key_prefix=prefix, retry_base_backoff_seconds=0.01,
                       command_timeout_seconds=1.0, connect_timeout_seconds=2.0).validate()


BOTH = bool(PG_HOST and PG_USER and R_HOST)


@unittest.skipUnless(BOTH, "set AGENTGUARD_TEST_PG_HOST+USER+PASSWORD and AGENTGUARD_TEST_REDIS_HOST")
class PgRedisCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dbname = "ag_test_" + secrets.token_hex(6)
        with _admin() as a:
            a.execute(f'CREATE DATABASE "{cls.dbname}"')
        cls.cfg = pgcfg(cls.dbname)
        db = Database(cls.cfg)
        migrate.migrate(db)
        db.close()
        cls.db = Database(cls.cfg)
        cls.store = PgEnterpriseStore(cls.db)
        cls.redis = RedisBackend(rcfg("s8" + secrets.token_hex(5)))
        cls.clock = FixedClock()
        cls.logger = SecurityLogger(use_python_logging=False)
        cls.config = EnterpriseAuthConfig(environment="development", session_secret=b"k" * 32,
                                          cookie_secure=False, login_burst=100000,
                                          login_rate_per_min=1_000_000)
        cls.svc = EnterpriseAuthService(cls.store, cls.config, backend=cls.redis,
                                        logger=cls.logger, clock=cls.clock)
        cls.ops = AdminOps(cls.store, cls.svc.audit, cls.config,
                           permission_cache=cls.svc.permission_cache, sessions=cls.svc.sessions,
                           clock=cls.clock)
        cls._seed()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.db.close()
        finally:
            try:
                cls.redis.close()
            except Exception:
                pass
            with _admin() as a:
                a.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}" WITH (FORCE)')

    @classmethod
    def _seed(cls):
        """Two tenants + a platform admin + one user per role, all through the Store."""
        now = cls.clock.now()
        for org in ("acme", "globex"):
            cls.db.run("seed_org", lambda c, o=org: c.execute(
                "INSERT INTO organizations (org_id,name,created_at,status,active_issuer_key_id)"
                " VALUES (%s,%s,%s,'active','i1') ON CONFLICT (org_id) DO NOTHING", (o, o.title(), now)))

        def mkuser(email, global_roles=(), password=GOOD_PW):
            u = EnterpriseUser(user_id=new_id("usr"), email=email, display_name=email.split("@")[0],
                               status=UserStatus.ACTIVE, is_platform_admin=(ROLE_PLATFORM_ADMIN in global_roles),
                               global_roles=tuple(global_roles),
                               password_hash=(pw.hash_password(password, n=2 ** 12) if password else None),
                               password_changed_at=now, must_change_password=False, failed_login_count=0,
                               locked_until=None, last_login_at=None, created_at=now, created_by="seed",
                               updated_at=now)
            cls.store.put_user(u)
            return u

        cls.padmin = mkuser("padmin@acme.test", (ROLE_PLATFORM_ADMIN,))
        cls.acme_tadmin = mkuser("tadmin@acme.test")
        cls.acme_operator = mkuser("op@acme.test")
        cls.acme_dev = mkuser("dev@acme.test")
        cls.acme_auditor = mkuser("aud@acme.test")
        cls.globex_tadmin = mkuser("tadmin@globex.test")

        def member(org, user, roles):
            cls.store.put_membership(TenantMembership(org, user.user_id, tuple(roles),
                                                      MembershipStatus.ACTIVE, now, "seed", now))
        member("acme", cls.acme_tadmin, (ROLE_TENANT_ADMIN,))
        member("acme", cls.acme_operator, (ROLE_SECURITY_OPERATOR,))
        member("acme", cls.acme_dev, (ROLE_DEVELOPER,))
        member("acme", cls.acme_auditor, (ROLE_READONLY_AUDITOR,))
        member("globex", cls.globex_tadmin, (ROLE_TENANT_ADMIN,))

    def _login(self, email, org_id=None, password=GOOD_PW):
        user, session, access, refresh, csrf = self.svc.login(email, password, org_id=org_id)
        return user, session, access, refresh, csrf

    def _actor(self, email, org):
        u = self.store.get_user_by_email(email)
        return self.svc.access_for(u, org)


class Persistence(PgRedisCase):
    def test_users_memberships_durable(self):
        self.assertEqual(self.store.get_user_by_email("dev@acme.test").email, "dev@acme.test")
        m = self.store.get_membership("acme", self.acme_dev.user_id)
        self.assertEqual(m.roles, (ROLE_DEVELOPER,))

    def test_email_uniqueness_case_insensitive(self):
        with self.assertRaises(Exception):                    # unique index lower(email)
            self.store.put_user(dataclasses.replace(self.acme_dev, user_id=new_id("usr"),
                                                    email="DEV@ACME.TEST"))

    def test_platform_role_on_membership_rejected_by_db(self):
        # the SQL CHECK constraint is defence-in-depth behind sanitize_tenant_roles
        with self.assertRaises(Exception):
            self.store.put_membership(TenantMembership("acme", self.acme_dev.user_id,
                                                       (ROLE_PLATFORM_ADMIN,),
                                                       MembershipStatus.ACTIVE, self.clock.now(),
                                                       "t", self.clock.now()))

    def test_audit_append_only(self):
        before = len(self.store.list_audit(limit=1000))
        self.svc.login("dev@acme.test", GOOD_PW, org_id="acme")
        after = self.store.list_audit(limit=1000)
        self.assertGreater(len(after), before)
        # the DB trigger must refuse UPDATE/DELETE on audit_events
        ev_id = after[0].event_id
        with self.assertRaises(Exception):
            self.db.run("tamper_audit", lambda c: c.execute(
                "UPDATE audit_events SET reason='x' WHERE event_id=%s", (ev_id,)))
        with self.assertRaises(Exception):
            self.db.run("del_audit", lambda c: c.execute(
                "DELETE FROM audit_events WHERE event_id=%s", (ev_id,)))


class SessionLifecyclePg(PgRedisCase):
    def test_login_rate_limited_against_redis(self):
        from agent_identity.security import EnterpriseAuthService
        r = RedisBackend(rcfg("s8rl" + secrets.token_hex(5)))
        cfg = dataclasses.replace(self.config, login_burst=2, login_rate_per_min=1)
        svc = EnterpriseAuthService(self.store, cfg, backend=r, logger=self.logger, clock=self.clock)
        got = 0
        for _ in range(6):
            try:
                svc.login("ratelimit-probe@acme.test", "bad-password-999")
            except RateLimitedError:
                got += 1
            except AuthenticationError:
                pass
        r.close()
        self.assertGreater(got, 0)              # the Redis token bucket refused some attempts

    def test_login_refresh_rotate_logout(self):
        user, session, access, refresh, csrf = self._login("dev@acme.test", org_id="acme")
        s2, u2, access2, refresh2, csrf2 = self.svc.refresh(refresh)
        self.assertNotEqual(refresh, refresh2)
        self.assertTrue(self.svc.logout(access2))
        with self.assertRaises(AuthenticationError):
            self.svc.resolve_context(access2)

    def test_short_lived_access_token_and_rotation_persisted(self):
        user, session, access, refresh, csrf = self._login("dev@acme.test", org_id="acme")
        claims = self.svc.sessions.verify_access(access)
        self.assertLessEqual(claims.exp - int(self.clock.now()), self.config.access_ttl_s)
        # the raw refresh token is never stored: only its digest
        self.assertIsNone(self.store.get_refresh(refresh))
        from agent_identity.security.tokens import digest
        self.assertIsNotNone(self.store.get_refresh(digest(refresh)))


class TenantIsolationNegative(PgRedisCase):
    """The core Step 8 negative security suite, run against REAL PostgreSQL + Redis."""

    def test_cross_tenant_membership_query_is_scoped(self):
        # RLS + explicit scoping: a tenant-scoped listing never returns another tenant's rows
        with self.db.tenant_scope("acme"):
            acme_members = self.store.list_memberships(org_id="acme")
        with self.db.tenant_scope("globex"):
            globex_members = self.store.list_memberships(org_id="globex")
        self.assertTrue(all(m.org_id == "acme" for m in acme_members))
        self.assertTrue(all(m.org_id == "globex" for m in globex_members))
        self.assertNotEqual({m.user_id for m in acme_members}, {m.user_id for m in globex_members})

    def test_rls_hides_other_tenant_for_a_non_owner_role(self):
        """RLS is enforced for a NON-OWNER login: the app connects as a limited role in production.
        A tenant scope can only ever see its own rows; an unset scope sees nothing (fail closed)."""
        role = "s8_lim_" + secrets.token_hex(4)
        pw_r = secrets.token_hex(12)
        from psycopg import sql as _sql
        with _conn(self.dbname, PG_USER, PG_PW) as c:
            c.execute(_sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER").format(
                _sql.Identifier(role), _sql.Literal(pw_r)))
            c.execute(_sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(_sql.Identifier(role)))
            c.execute(_sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA public TO {}").format(_sql.Identifier(role)))
        try:
            def visible(org, fresh=False):
                with _conn(self.dbname, role, pw_r) as c:
                    if not fresh:
                        c.execute("SELECT set_config('app.current_org', %s, false)", (org,))
                    return [r[0] for r in c.execute("SELECT org_id FROM tenant_memberships").fetchall()]

            acme = visible("acme")
            self.assertTrue(acme)
            self.assertTrue(all(o == "acme" for o in acme), acme)      # no globex leaked into acme
            globex = visible("globex")
            self.assertTrue(globex)
            self.assertTrue(all(o == "globex" for o in globex), globex)  # no acme leaked into globex
            self.assertEqual(visible("", fresh=True), [])             # unset scope => nothing visible
        finally:
            from psycopg import sql as _sql
            with _conn(self.dbname, PG_USER, PG_PW) as c:
                try:
                    c.execute(_sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}").format(
                        _sql.Identifier(role)))
                    c.execute(_sql.SQL("REVOKE ALL ON SCHEMA public FROM {}").format(_sql.Identifier(role)))
                    c.execute(_sql.SQL("DROP ROLE {}").format(_sql.Identifier(role)))
                except Exception:
                    pass                                  # role name is unique; the test DB is dropped anyway

    def test_tenant_admin_cannot_manage_other_tenant_user(self):
        actor = self._actor("tadmin@acme.test", "acme")
        with self.assertRaises(ForbiddenError):
            self.ops.suspend_user(actor, self.globex_tadmin.user_id, "attempt")

    def test_tenant_admin_cannot_create_platform_admin(self):
        actor = self._actor("tadmin@acme.test", "acme")
        with self.assertRaises(ForbiddenError):
            self.ops.set_global_roles(actor, self.acme_dev.user_id, (ROLE_PLATFORM_ADMIN,))

    def test_tenant_admin_cannot_escalate_self_via_membership_roles(self):
        actor = self._actor("tadmin@acme.test", "acme")
        with self.assertRaises(ForbiddenError):
            self.ops.set_membership_roles(actor, org_id="acme", user_id=self.acme_tadmin.user_id,
                                          roles=(ROLE_TENANT_ADMIN, ROLE_PLATFORM_ADMIN))

    def test_cross_tenant_resource_access_denied(self):
        actor = self._actor("tadmin@acme.test", "acme")
        # add_membership into globex must be denied for an acme-only tenant admin
        with self.assertRaises(ForbiddenError):
            self.ops.add_membership(actor, org_id="globex", user_id=self.acme_dev.user_id,
                                    roles=(ROLE_DEVELOPER,))

    def test_authorize_denies_on_cross_tenant_scope(self):
        user, session, access, refresh, csrf = self._login("tadmin@acme.test", org_id="acme")
        ctx = self.svc.authorize(access, permission=rbac.P_AGENT_WRITE)     # own tenant: ok
        self.assertEqual(ctx.org_id, "acme")
        from agent_identity.api.enterprise_http import enforce_control_plane
        with self.assertRaises(ForbiddenError):
            # a call that carries another tenant's org_id for a non-platform-admin
            enforce_control_plane(self.svc, "POST", "/v1/agents",
                                  {"org_id": "globex"}, {"Authorization": f"Bearer {access}"}, {})


class RefreshReplayNegative(PgRedisCase):
    def test_replay_of_rotated_refresh_token_revokes_family(self):
        user, session, access, refresh, csrf = self._login("op@acme.test", org_id="acme")
        s2, u2, a2, r2, c2 = self.svc.refresh(refresh)
        with self.assertRaises(AuthenticationError):
            self.svc.refresh(refresh)                          # reuse => theft
        self.assertEqual(self.store.get_session(session.session_id).status, "revoked")
        with self.assertRaises(AuthenticationError):
            self.svc.resolve_context(a2)                       # the family is dead
        # and an audit event recorded the reuse
        events = [e.event for e in self.store.list_audit(limit=200)]
        self.assertIn("session.refresh_reuse_detected", events)


class RbacEnforcementPg(PgRedisCase):
    def test_readonly_auditor_cannot_mutate(self):
        user, session, access, refresh, csrf = self._login("aud@acme.test", org_id="acme")
        ctx = self.svc.authorize(access, permission=rbac.P_AUDIT_READ)     # read ok
        self.assertIn(rbac.P_AUDIT_READ, ctx.permissions)
        with self.assertRaises(ForbiddenError):
            self.svc.authorize(access, permission=rbac.P_AGENT_WRITE)      # write denied

    def test_developer_can_issue_but_not_revoke(self):
        user, session, access, refresh, csrf = self._login("dev@acme.test", org_id="acme")
        self.svc.authorize(access, permission=rbac.P_CREDENTIAL_ISSUE)
        with self.assertRaises(ForbiddenError):
            self.svc.authorize(access, permission=rbac.P_CREDENTIAL_REVOKE)

    def test_permission_change_invalidates_cache(self):
        # developer issues fine; then their role is changed and the CACHE must not grant stale rights
        user, session, access, refresh, csrf = self._login("dev@acme.test", org_id="acme")
        self.svc.authorize(access, permission=rbac.P_CREDENTIAL_ISSUE)
        padmin_actor = self._actor("padmin@acme.test", None)
        self.ops.set_membership_roles(padmin_actor, org_id="acme", user_id=self.acme_dev.user_id,
                                      roles=(ROLE_READONLY_AUDITOR,))
        with self.assertRaises(ForbiddenError):
            self.svc.authorize(access, permission=rbac.P_CREDENTIAL_ISSUE)
        # restore
        self.ops.set_membership_roles(padmin_actor, org_id="acme", user_id=self.acme_dev.user_id,
                                      roles=(ROLE_DEVELOPER,))

    def test_suspended_account_loses_session_immediately(self):
        user, session, access, refresh, csrf = self._login("op@acme.test", org_id="acme")
        padmin_actor = self._actor("padmin@acme.test", None)
        self.ops.suspend_user(padmin_actor, self.acme_operator.user_id, "compromise")
        with self.assertRaises(AuthenticationError):
            self.svc.resolve_context(access)
        # restore for other tests
        self.ops.reactivate_user(padmin_actor, self.acme_operator.user_id)

    def test_last_platform_admin_protected(self):
        actor = self._actor("padmin@acme.test", None)
        with self.assertRaises(ConflictError):
            self.ops.set_global_roles(actor, self.padmin.user_id, ())
        with self.assertRaises(ConflictError):
            self.ops.suspend_user(actor, self.padmin.user_id, "attempt")


class RedisKeyNamespaceNegative(PgRedisCase):
    def test_permission_cache_is_tenant_namespaced(self):
        keys = SecurityKeys("development")
        k_acme = keys.permission("acme", "user-1")
        k_globex = keys.permission("globex", "user-1")
        self.assertNotEqual(k_acme, k_globex)
        self.assertIn("{development.acme}", k_acme)
        self.assertIn("{development.globex}", k_globex)

    def test_cache_invalidation_after_role_change(self):
        # populate the cache for dev@acme, then demote; the value must be evicted
        _ = self.svc.access_for(self.store.get_user_by_email("dev@acme.test"), "acme")
        padmin_actor = self._actor("padmin@acme.test", None)
        self.ops.set_membership_roles(padmin_actor, org_id="acme", user_id=self.acme_dev.user_id,
                                      roles=(ROLE_READONLY_AUDITOR,))
        fresh = self.svc.access_for(self.store.get_user_by_email("dev@acme.test"), "acme")
        self.assertFalse(fresh.has(rbac.P_CREDENTIAL_ISSUE))
        self.ops.set_membership_roles(padmin_actor, org_id="acme", user_id=self.acme_dev.user_id,
                                      roles=(ROLE_DEVELOPER,))

    def test_oidc_login_state_is_single_use_in_redis(self):
        from agent_identity.security.models import IdpConfig, IdpType
        from agent_identity.security.oidc import LoginTxnStore, OidcError
        idp = IdpConfig("idp-x", "acme", IdpType.OIDC, "https://i.test", "c", "REF", ("openid",),
                        "https://app/cb", "")
        txns = LoginTxnStore(self.redis, SecurityKeys("development"))
        txn = txns.create(idp, code_verifier="v", nonce="n", redirect_uri="https://app/cb",
                          return_to=None, ip=None, user_agent=None, now=self.clock.now(), ttl_s=600)
        txns.consume_for("acme", txn.txn_id, now=self.clock.now())
        with self.assertRaises(OidcError):
            txns.consume_for("acme", txn.txn_id, now=self.clock.now())


class BootstrapPg(PgRedisCase):
    def test_bootstrap_one_time_and_no_default_password(self):
        # a platform administrator already exists in THIS database -> bootstrap must refuse
        with self.assertRaises(ConflictError):
            bootstrap_platform_admin(self.store, self.svc.audit, email="root@acme.test", password=GOOD_PW)
        # the one-time rule + password policy, exercised on a FRESH store (no DB state)
        fresh = MemoryEnterpriseStore()
        with self.assertRaises(ValidationError):               # weak password refused (no default!)
            bootstrap_platform_admin(fresh, self.svc.audit, email="root@acme.test", password="weak")
        u = bootstrap_platform_admin(fresh, self.svc.audit, email="root@acme.test", password=GOOD_PW)
        self.assertTrue(u.is_platform_admin)
        with self.assertRaises(ConflictError):                 # second bootstrap refused
            bootstrap_platform_admin(fresh, self.svc.audit, email="root2@acme.test", password=GOOD_PW)


if __name__ == "__main__":
    unittest.main()
