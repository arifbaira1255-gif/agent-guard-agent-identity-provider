"""Phase 8 tests: the management API platform, CLI and observability.

These tests exercise the *real* wiring: a real :class:`EnterpriseAuthService` (memory store), the
real RBAC engine, the real :class:`ManagementApi` dispatcher and the real CLI parser. Nothing is
mocked except the optional security planes, which are deliberately left unconfigured so the tests
also prove the "honest availability" behaviour (``available: false`` rather than fabricated data).
"""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_identity.api.management import ManagementApi, _HANDLERS
from agent_identity.api.platform import (ApiError, RateLimiter, error_envelope, paginate,
                                         parse_filters, parse_pagination, parse_time_range,
                                         redact_mapping)
from agent_identity.core.clock import FixedClock
from agent_identity.observability.logging import SecurityLogger
from agent_identity.observability.phase8 import INSTRUMENTED_PATHS, Observability
from agent_identity.security import (AdminOps, EnterpriseAuthConfig, EnterpriseAuthService,
                                     MemoryEnterpriseStore)
from agent_identity.security import passwords as pw
from agent_identity.security.ids import new_id
from agent_identity.security.models import (ROLE_DEVELOPER, ROLE_PLATFORM_ADMIN,
                                            ROLE_READONLY_AUDITOR, ROLE_SECURITY_ANALYST,
                                            ROLE_TENANT_ADMIN, EnterpriseUser, MembershipStatus,
                                            TenantMembership, UserStatus)
from agent_identity.state.backend import MemoryBackend

GOOD_PW = "Correct-Horse-Battery-9!"


# --------------------------------------------------------------------------- fixtures
def _service(**cfg):
    store = MemoryEnterpriseStore()
    logger = SecurityLogger(use_python_logging=False)
    clock = FixedClock()
    config = EnterpriseAuthConfig(environment="development", session_secret=b"k" * 32,
                                  cookie_secure=False, **cfg)
    svc = EnterpriseAuthService(store, config, backend=MemoryBackend(), logger=logger, clock=clock)
    return svc, store, clock


def _user(store, *, email, global_roles=(), password=GOOD_PW, display_name="U",
          status=UserStatus.ACTIVE):
    now = 1_800_000_000.0
    u = EnterpriseUser(user_id=new_id("usr"), email=email, display_name=display_name, status=status,
                       is_platform_admin=(ROLE_PLATFORM_ADMIN in global_roles),
                       global_roles=tuple(global_roles),
                       password_hash=(pw.hash_password(password, n=2 ** 12) if password else None),
                       password_changed_at=now, must_change_password=False, failed_login_count=0,
                       locked_until=None, last_login_at=None, created_at=now, created_by="t",
                       updated_at=now)
    store.put_user(u)
    return u


def _membership(store, org_id, user_id, roles):
    now = 1_800_000_000.0
    store.put_membership(TenantMembership(org_id, user_id, tuple(roles),
                                          MembershipStatus.ACTIVE, now, "t", now))


def _api(**kw):
    svc, store, clock = _service()
    ops = AdminOps(store, svc.audit, svc.config, permission_cache=svc.permission_cache,
                   sessions=svc.sessions, clock=clock)
    obs = Observability(logger=SecurityLogger(use_python_logging=False))
    api = ManagementApi(auth_service=svc, admin_ops=ops, config=svc.config, clock=clock,
                        observability=obs, **kw)
    return api, svc, store, clock


def _login(svc, email, password=GOOD_PW, org_id=None):
    """Create a real session for an existing user and return (access_token, csrf_token)."""
    user = svc.store.get_user_by_email(email)
    _session, access, _refresh, csrf = svc.sessions.create(user, org_id=org_id,
                                                           auth_method="password")
    return access, csrf


def _call(api, method, path, *, token=None, csrf=None, body=None, query=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if csrf:
        headers["X-CSRF-Token"] = csrf
    return api.handle(method, path, query or {}, body or {}, headers, {})


# =========================================================================== platform primitives
class PlatformPrimitiveTests(unittest.TestCase):
    def test_pagination_clamps_and_validates(self):
        self.assertEqual(parse_pagination({"limit": "10", "offset": "5"}), (5, 10))
        self.assertEqual(parse_pagination({"limit": "99999"})[1], 200)      # clamped to MAX_PAGE_SIZE
        with self.assertRaises(Exception):
            parse_pagination({"limit": "0"})
        with self.assertRaises(Exception):
            parse_pagination({"offset": "-1"})
        with self.assertRaises(Exception):
            parse_pagination({"limit": "abc"})

    def test_paginate_metadata(self):
        p = paginate(list(range(10)), offset=0, limit=4)
        self.assertEqual(p.items, [0, 1, 2, 3])
        self.assertEqual(p.total, 10)
        self.assertTrue(p.has_more)
        self.assertEqual(p.to_dict()["page"]["next_offset"], 4)
        p2 = paginate(list(range(3)), offset=0, limit=4)
        self.assertFalse(p2.has_more)
        self.assertIsNone(p2.to_dict()["page"]["next_offset"])

    def test_filters_allow_list(self):
        self.assertEqual(parse_filters({"status": "active", "evil": "x"}, allowed=("status",)),
                         {"status": "active"})
        with self.assertRaises(Exception):
            parse_filters({"status": "x" * 500}, allowed=("status",))

    def test_time_range_bounds(self):
        self.assertEqual(parse_time_range({"since": "1", "until": "2"}), (1.0, 2.0))
        with self.assertRaises(Exception):
            parse_time_range({"since": "5", "until": "1"})
        with self.assertRaises(Exception):
            parse_time_range({"since": "0", "until": str(10 ** 9)})       # too wide

    def test_error_envelope_is_consistent_and_secret_free(self):
        status, body = error_envelope(ApiError(403, "forbidden", "nope"), correlation_id="c1")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "forbidden")
        self.assertEqual(body["error"]["correlation_id"], "c1")
        # an unexpected exception collapses to a generic 500 with no internals
        status2, body2 = error_envelope(RuntimeError("secret dsn postgres://u:p@h/db"))
        self.assertEqual(status2, 500)
        self.assertEqual(body2["error"]["code"], "internal_error")
        self.assertNotIn("postgres", json.dumps(body2))

    def test_redaction_removes_secret_looking_fields(self):
        out = redact_mapping({"password": "hunter2", "nested": {"api_key": "abc"},
                              "ok": "visible", "token": "x"})
        self.assertEqual(out["password"], "[REDACTED]")
        self.assertEqual(out["nested"]["api_key"], "[REDACTED]")
        self.assertEqual(out["token"], "[REDACTED]")
        self.assertEqual(out["ok"], "visible")

    def test_rate_limiter_fails_closed(self):
        rl = RateLimiter(rate_per_s=0.0, burst=2)
        rl.check("t", "u")
        rl.check("t", "u")
        with self.assertRaises(Exception):
            rl.check("t", "u")

    def test_every_route_has_a_handler(self):
        api, *_ = _api()
        for spec in api.registry.all():
            self.assertIn((spec.method, spec.path), _HANDLERS,
                          f"route {spec.method} {spec.path} has no handler")

    def test_openapi_generation_covers_registry(self):
        api, *_ = _api()
        doc = api.openapi()
        self.assertEqual(doc["openapi"], "3.1.0")
        for spec in api.registry.all():
            self.assertIn(spec.path, doc["paths"])
            self.assertIn(spec.method.lower(), doc["paths"][spec.path])


# =========================================================================== authN / authZ
class ManagementAuthTests(unittest.TestCase):
    def test_unauthenticated_is_401(self):
        api, *_ = _api()
        status, body, _ = _call(api, "GET", "/v2/session")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "authentication_failed")

    def test_unknown_route_is_404(self):
        api, svc, store, _ = _api()
        _user(store, email="a@x.test", global_roles=(ROLE_PLATFORM_ADMIN,))
        token, _ = _login(svc, "a@x.test")
        status, body, _ = _call(api, "GET", "/v2/does-not-exist", token=token)
        self.assertEqual(status, 404)

    def test_session_returns_effective_permissions(self):
        api, svc, store, _ = _api()
        _user(store, email="a@x.test", global_roles=(ROLE_PLATFORM_ADMIN,))
        token, _ = _login(svc, "a@x.test")
        status, body, headers = _call(api, "GET", "/v2/session", token=token)
        self.assertEqual(status, 200)
        self.assertIn("agent:read", body["permissions"])
        self.assertTrue(any(h[0] == "X-Correlation-Id" for h in headers))

    def test_readonly_auditor_cannot_suspend_agent(self):
        api, svc, store, _ = _api()
        u = _user(store, email="ro@x.test")
        _membership(store, "acme", u.user_id, (ROLE_READONLY_AUDITOR,))
        token, csrf = _login(svc, "ro@x.test", org_id="acme")
        status, body, _ = _call(api, "POST", "/v2/agents/agt_1/suspend", token=token, csrf=csrf,
                                body={"reason": "administrative_action"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "forbidden")

    def test_developer_cannot_decide_approvals(self):
        api, svc, store, _ = _api()
        u = _user(store, email="dev@x.test")
        _membership(store, "acme", u.user_id, (ROLE_DEVELOPER,))
        token, csrf = _login(svc, "dev@x.test", org_id="acme")
        status, _, _ = _call(api, "POST", "/v2/approvals/apr_1/decide", token=token, csrf=csrf,
                             body={"approved": True})
        self.assertEqual(status, 403)

    def test_security_analyst_can_read_but_not_admin(self):
        api, svc, store, _ = _api()
        u = _user(store, email="an@x.test")
        _membership(store, "acme", u.user_id, (ROLE_SECURITY_ANALYST,))
        token, csrf = _login(svc, "an@x.test", org_id="acme")
        # read allowed
        status, _, _ = _call(api, "GET", "/v2/incidents", token=token)
        self.assertEqual(status, 200)
        # admin-only retention purge denied
        status2, _, _ = _call(api, "POST", "/v2/admin/retention/apply", token=token, csrf=csrf,
                              body={})
        self.assertEqual(status2, 403)

    def test_csrf_required_on_mutating_route(self):
        api, svc, store, _ = _api()
        u = _user(store, email="ta@x.test")
        _membership(store, "acme", u.user_id, (ROLE_TENANT_ADMIN,))
        token, _ = _login(svc, "ta@x.test", org_id="acme")
        status, body, _ = _call(api, "POST", "/v2/admin/retention/apply", token=token, body={})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")

    def test_cross_tenant_denied(self):
        api, svc, store, _ = _api()
        u = _user(store, email="ta@x.test")
        _membership(store, "acme", u.user_id, (ROLE_TENANT_ADMIN,))
        token, _ = _login(svc, "ta@x.test", org_id="acme")
        status, body, _ = _call(api, "GET", "/v2/agents", token=token, query={"org_id": "globex"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "forbidden")

    def test_platform_admin_may_cross_tenant(self):
        api, svc, store, _ = _api()
        _user(store, email="pa@x.test", global_roles=(ROLE_PLATFORM_ADMIN,))
        token, _ = _login(svc, "pa@x.test")
        status, _, _ = _call(api, "GET", "/v2/agents", token=token, query={"org_id": "globex"})
        self.assertEqual(status, 200)

    def test_rate_limit_returns_429(self):
        api, svc, store, _ = _api()
        _user(store, email="pa@x.test", global_roles=(ROLE_PLATFORM_ADMIN,))
        token, _ = _login(svc, "pa@x.test")
        api.limiter = RateLimiter(rate_per_s=0.0, burst=3)
        codes = [_call(api, "GET", "/v2/session", token=token)[0] for _ in range(6)]
        self.assertIn(429, codes)


# =========================================================================== honest availability
class AvailabilityTests(unittest.TestCase):
    def _admin_token(self, api, svc, store):
        _user(store, email="pa@x.test", global_roles=(ROLE_PLATFORM_ADMIN,))
        return _login(svc, "pa@x.test")[0]

    def test_unconfigured_planes_report_unavailable_not_fake_data(self):
        api, svc, store, _ = _api()          # no planes wired
        token = self._admin_token(api, svc, store)
        for path in ("/v2/policies", "/v2/incidents", "/v2/approvals", "/v2/recommendations",
                     "/v2/siem/destinations", "/v2/egress/policies", "/v2/anomalies"):
            status, body, _ = _call(api, "GET", path, token=token)
            self.assertEqual(status, 200, path)
            self.assertIs(body.get("available"), False, path)
            self.assertEqual(body.get("items"), [], path)

    def test_health_reports_planes_and_instrumented_paths(self):
        api, svc, store, _ = _api()
        token = self._admin_token(api, svc, store)
        status, body, _ = _call(api, "GET", "/v2/health", token=token)
        self.assertEqual(status, 200)
        self.assertIn("planes", body)
        self.assertEqual(body["planes"]["policy"], False)
        self.assertEqual(set(body["instrumented_paths"]), set(INSTRUMENTED_PATHS))

    def test_livez_and_readyz_are_unauthenticated(self):
        api, *_ = _api()
        s1, b1, _ = _call(api, "GET", "/v2/livez")
        self.assertEqual(s1, 200)
        self.assertEqual(b1["status"], "alive")
        s2, b2, _ = _call(api, "GET", "/v2/readyz")
        self.assertIn(s2, (200, 503))

    def test_metrics_endpoint_requires_auth(self):
        api, *_ = _api()
        status, _, _ = _call(api, "GET", "/v2/metrics")
        self.assertEqual(status, 401)

    def test_metrics_records_requests(self):
        api, svc, store, _ = _api()
        token = self._admin_token(api, svc, store)
        _call(api, "GET", "/v2/session", token=token)
        status, body, _ = _call(api, "GET", "/v2/metrics", token=token)
        self.assertEqual(status, 200)
        counters = body["metrics"]["counters"]
        self.assertTrue(any("agentguard_api_requests_total" in k for k in counters))


# =========================================================================== pagination on real routes
class PaginationRouteTests(unittest.TestCase):
    def _api_with_agents(self, n=7):
        """Wire a minimal identity stub so the agents route returns real, paginated rows."""
        class _Reg:
            def __init__(self, rows):
                self._rows = rows

            def list_all(self):
                return list(self._rows)

        class _Identity:
            def __init__(self, rows):
                self.agents = _Reg(rows)

        rows = [{"agent_id": f"agt_{i}", "agent_name": f"agent-{i}", "agent_type": "autonomous",
                 "status": "active", "owner": "acme", "org_id": "acme",
                 "created_at": f"2026-01-{i + 1:02d}T00:00:00Z"} for i in range(n)]
        api, svc, store, _ = _api(identity_service=_Identity(rows))
        _user(store, email="pa@x.test", global_roles=(ROLE_PLATFORM_ADMIN,))
        token, _ = _login(svc, "pa@x.test")
        return api, token

    def test_agents_pagination_shape(self):
        api, token = self._api_with_agents(7)
        status, body, _ = _call(api, "GET", "/v2/agents", token=token,
                                query={"limit": "5", "offset": "0"})
        self.assertEqual(status, 200)
        self.assertIn("page", body)
        self.assertEqual(body["page"]["limit"], 5)
        self.assertEqual(body["page"]["total"], 7)
        self.assertEqual(len(body["items"]), 5)
        self.assertTrue(body["page"]["has_more"])
        self.assertEqual(body["page"]["next_offset"], 5)

    def test_agents_second_page(self):
        api, token = self._api_with_agents(7)
        status, body, _ = _call(api, "GET", "/v2/agents", token=token,
                                query={"limit": "5", "offset": "5"})
        self.assertEqual(status, 200)
        self.assertEqual(len(body["items"]), 2)
        self.assertFalse(body["page"]["has_more"])

    def test_agents_filter_applied(self):
        api, token = self._api_with_agents(7)
        status, body, _ = _call(api, "GET", "/v2/agents", token=token,
                                query={"status": "terminated"})
        self.assertEqual(status, 200)
        self.assertEqual(body["page"]["total"], 0)

    def test_bad_pagination_is_400(self):
        api, token = self._api_with_agents(3)
        status, body, _ = _call(api, "GET", "/v2/agents", token=token, query={"limit": "0"})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "validation_error")


# =========================================================================== CLI
class CliTests(unittest.TestCase):
    def _cli(self):
        from agent_identity import cli
        return cli

    def test_parser_builds_and_has_expected_commands(self):
        cli = self._cli()
        p = cli.build_parser()
        for cmd in ("login", "session", "agents", "policies", "resources", "tools", "events",
                    "incidents", "approvals", "audit", "health", "metrics", "config"):
            self.assertIn(cmd, p._subparsers._group_actions[0].choices)

    def test_high_impact_refused_without_yes_non_interactive(self):
        cli = self._cli()
        args = cli.build_parser().parse_args(
            ["--non-interactive", "agents", "suspend", "agt_1"])
        self.assertFalse(cli._confirm(args, "suspend agent agt_1"))

    def test_high_impact_allowed_with_yes(self):
        cli = self._cli()
        args = cli.build_parser().parse_args(["--yes", "agents", "suspend", "agt_1"])
        self.assertTrue(cli._confirm(args, "suspend agent agt_1"))

    def test_exit_code_mapping(self):
        cli = self._cli()
        self.assertEqual(cli._STATUS_TO_EXIT[401], cli.EXIT_AUTH)
        self.assertEqual(cli._STATUS_TO_EXIT[403], cli.EXIT_FORBIDDEN)
        self.assertEqual(cli._STATUS_TO_EXIT[404], cli.EXIT_NOT_FOUND)
        self.assertEqual(cli._STATUS_TO_EXIT[429], cli.EXIT_RATE_LIMITED)
        self.assertEqual(cli._STATUS_TO_EXIT[500], cli.EXIT_SERVER)

    def test_token_resolution_prefers_flag_then_env(self):
        cli = self._cli()
        args = cli.build_parser().parse_args(["--token", "abc", "session"])
        self.assertEqual(cli._resolve_token(args), "abc")
        os.environ["AGENTGUARD_TOKEN"] = "envtok"
        try:
            args2 = cli.build_parser().parse_args(["session"])
            self.assertEqual(cli._resolve_token(args2), "envtok")
        finally:
            os.environ.pop("AGENTGUARD_TOKEN", None)

    def test_config_validation_reports_missing_token(self):
        cli = self._cli()
        client = cli.ApiClient("http://127.0.0.1:1", None)
        args = cli.build_parser().parse_args(["config"])
        rc = cli._cmd_config(client, args)
        self.assertEqual(rc, cli.EXIT_USAGE)

    def test_cases_file_validation(self):
        cli = self._cli()
        with self.assertRaises(cli.CliError):
            cli._load_cases(None)


# =========================================================================== console asset
class ConsoleAssetTests(unittest.TestCase):
    def test_console_html_exists_and_is_self_contained(self):
        path = os.path.join(os.path.dirname(__file__), "..", "console", "index.html")
        self.assertTrue(os.path.exists(path), "console/index.html must exist")
        with open(path, "r", encoding="utf-8") as fh:
            html = fh.read()
        # no external script/style dependencies (self-contained)
        self.assertNotIn("<script src=", html)
        self.assertNotIn("<link rel=\"stylesheet\"", html)
        # the 11 required views are present
        for v in ("agents", "health", "policies", "permissions", "egress", "anomalies",
                  "incidents", "approvals", "audit", "siem", "metrics"):
            self.assertIn(f'data-view="{v}"', html)
        # accessibility + honest states
        self.assertIn("Skip to main content", html)
        self.assertIn("aria-live", html)
        self.assertIn("Permission denied", html)
        self.assertIn("Not available", html)


if __name__ == "__main__":
    unittest.main()
