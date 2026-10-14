"""Step 8 enterprise HTTP surface: authentication, session, and administration routes, plus a
**guard** that reviews and protects the existing (Step 1-7) control-plane routes.

Design
------
* ``EnterpriseRouter.handle`` serves ``/v1/auth/*`` and ``/v1/admin/*``.
* Cookies: the short-lived access token is carried in an ``HttpOnly`` cookie (``ag_session``); a
  separate non-HttpOnly ``ag_csrf`` cookie carries the CSRF token, which the client echoes in the
  ``X-CSRF-Token`` header. State-changing authenticated routes REQUIRE a valid CSRF token.
* Every route validates its inputs (types/lengths) and returns **safe** errors — a stable ``error``
  code plus a short message; internal details are never leaked.
* ``ControlPlaneGuard`` maps each Step 1-7 route to the permission it needs and enforces it against
  the caller's verified ``AuthContext`` (RBAC role → permission), and binds the request to the
  caller's tenant scope. Cross-tenant attempts (a body ``org_id`` that is not the caller's verified
  tenant, for a non-platform-admin) are denied. The existing routes keep working unchanged when no
  enterprise service is configured (backwards compatible).
"""
from __future__ import annotations

import hmac
import json
import time
from typing import Callable, Optional, Tuple

from ..core.errors import (AuthenticationError, ConflictError, CsrfError, ForbiddenError,
                           IdentityError, NotFoundError, RateLimitedError, UnauthorizedError,
                           ValidationError)
from ..security.auth_service import EnterpriseAuthService, _safe_return_to
from ..security.config import EnterpriseAuthConfig
from ..security.rbac import (P_AGENT_READ, P_AGENT_REVOKE, P_AGENT_SPAWN, P_AGENT_WRITE,
                            P_AUDIT_READ, P_CREDENTIAL_ISSUE, P_CREDENTIAL_READ, P_CREDENTIAL_REVOKE,
                            P_CREDENTIAL_ROTATE, P_IDP_READ, P_IDP_WRITE, P_INSTANCE_READ,
                            P_INSTANCE_REVOKE, P_PLATFORM_ADMIN, P_RBAC_READ, P_SESSION_READ,
                            P_SESSION_REVOKE, P_TENANT_CREATE, P_TENANT_READ, P_TENANT_WRITE,
                            P_USER_DELETE, P_USER_READ, P_USER_WRITE, P_MEMBERSHIP_WRITE,
                            P_ROLE_ASSIGN, P_RUNTIME_READ, P_RUNTIME_ADMIN,
                            P_RESPONSE_READ, P_RESPONSE_ADMIN, P_RESPONSE_APPROVE)
from ..security.models import AuthContext
from ..security.oidc import OidcError

MAX_BODY = 64 * 1024

_STATUS = {
    ValidationError: 400,
    AuthenticationError: 401,
    UnauthorizedError: 401,
    CsrfError: 403,
    ForbiddenError: 403,
    NotFoundError: 404,
    ConflictError: 409,
    RateLimitedError: 429,
}
# Unauthenticated (no-CSRF-required) routes: login / refresh / SSO handshake / whoami
_PUBLIC_PATHS = {
    ("POST", "v1/auth/login"),
    ("POST", "v1/auth/refresh"),
    ("GET", "v1/auth/session"),
}


def _err(exc: Exception) -> Tuple[int, dict]:
    for t, s in _STATUS.items():
        if isinstance(exc, t):
            return s, {"error": getattr(exc, "code", "error"), "message": str(exc)}
    if isinstance(exc, IdentityError):
        return 400, {"error": getattr(exc, "code", "error"), "message": str(exc)}
    return 500, {"error": "internal_error"}          # never leak internals


def parse_cookies(header: str) -> dict:
    out = {}
    for part in (header or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _egress_request_from_body(body: dict):
    """Build an :class:`EgressRequest` from a governed-request body (Phase 4)."""
    from ..egress.gateway import EgressRequest
    return EgressRequest(url=body.get("url"), method=body.get("method", "GET"),
                         headers=body.get("headers"), body=body.get("body"),
                         resource_id=body.get("resource_id"), operation=body.get("operation"),
                         context=body.get("context"))


def cookie_headers(config: EnterpriseAuthConfig, access_token: Optional[str] = None,
                   csrf_token: Optional[str] = None, *, clear: bool = False) -> list:
    """Build Set-Cookie headers with secure attributes."""
    out = []
    attrs = [f"Path={config.cookie_path}"]
    if config.cookie_domain:
        attrs.append(f"Domain={config.cookie_domain}")
    if config.cookie_secure:
        attrs.append("Secure")
    attrs.append(f"SameSite={config.cookie_samesite}")
    if clear:
        out.append(_set_cookie(config.cookie_name, "", attrs + ["Max-Age=0", "HttpOnly"]))
        out.append(_set_cookie(config.csrf_cookie_name, "", attrs + ["Max-Age=0"]))
        return out
    if access_token is not None:
        out.append(_set_cookie(config.cookie_name, access_token, attrs + ["HttpOnly"]))
    if csrf_token is not None:
        out.append(_set_cookie(config.csrf_cookie_name, csrf_token, attrs))     # readable by JS
    return out


def _set_cookie(name: str, value: str, attrs: list) -> str:
    return f"{name}={value}; " + "; ".join(attrs)


class EnterpriseRouter:
    """Route table for /v1/auth/* and /v1/admin/*. Pure: takes structured data, returns structured
    data + Set-Cookie headers (the thin server wrapper writes them)."""

    def __init__(self, service: EnterpriseAuthService, admin_ops, config: EnterpriseAuthConfig,
                 *, policy_service=None, governance_service=None, egress_service=None,
                 runtime_service=None, response_service=None, assurance_service=None):
        self.service = service
        self.admin = admin_ops
        self.config = config
        # Step 10: optional policy administration surface. When absent, /v1/admin/policies returns
        # 404 (the policy engine is simply not configured) — existing behaviour is unchanged.
        self.policy = policy_service
        # Step 11: optional tool & resource governance administration surface. When absent,
        # /v1/admin/resources and /v1/admin/tools return 404 — existing behaviour is unchanged.
        self.governance = governance_service
        # Phase 4: optional egress/DLP administration + governed-request surface. When absent,
        # /v1/admin/egress* and /v1/egress/request return 404 — existing behaviour is unchanged.
        self.egress = egress_service
        # Phase 5: optional runtime-monitoring / agent-behaviour-intelligence surface. When absent,
        # /v1/runtime* and /v1/admin/runtime* return 404 (the monitoring plane is not configured)
        # -- existing behaviour is unchanged.
        self.runtime = runtime_service
        # Phase 6: optional autonomous-response surface (loop detection, budgets, approvals,
        # incidents, containment, evidence, audit). When absent, /v1/response* and
        # /v1/admin/response* return 404 -- existing behaviour is unchanged.
        self.response = response_service
        # Phase 7: optional assurance surface (self-healing policy intelligence, tamper-evident
        # audit, compliance evidence, SIEM integration, correlation). When absent, /v1/assurance*
        # and /v1/admin/assurance* return 404 -- existing behaviour is unchanged.
        self.assurance = assurance_service

    def _now(self) -> float:
        return time.time()

    def _access_token(self, headers: dict, cookies: dict) -> str:
        auth = headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        return cookies.get(self.config.cookie_name, "")

    def _require_csrf(self, access_token: str, headers: dict) -> None:
        provided = headers.get(self.config.csrf_header)
        if not self.service.check_csrf(access_token, provided):
            raise CsrfError("missing or invalid CSRF token")

    def handle(self, method: str, path: str, body: dict, headers: dict, cookies: dict
               ) -> Tuple[int, object, list]:
        parts = [p for p in path.split("?")[0].split("/") if p]
        route = "/".join(parts)
        try:
            return self._dispatch(method, parts, route, body, headers, cookies)
        except KeyError:
            return 400, {"error": "validation_error", "message": "missing required field"}, []
        except Exception as e:                                     # noqa: BLE001
            status, payload = _err(e)
            return status, payload, []

    # ------------------------------------------------------------------ dispatch
    def _dispatch(self, method, parts, route, body, headers, cookies):
        # ---- public / session routes -----------------------------------------------------------
        if route == "v1/auth/login" and method == "POST":
            return self._login(body, headers)
        if route == "v1/auth/refresh" and method == "POST":
            return self._refresh(body, headers)
        if route == "v1/auth/session" and method == "GET":
            return self._session(headers, cookies)
        if route == "v1/auth/tenant" and method == "POST":
            return self._switch_tenant(body, headers, cookies)
        if route == "v1/auth/logout" and method == "POST":
            return self._logout(headers, cookies)
        # ---- SSO -------------------------------------------------------------------------------
        if len(parts) == 4 and parts[:2] == ["v1", "auth"] and parts[2] == "sso" and method == "GET":
            if parts[3] == "providers":
                return self._sso_providers(body, headers, cookies)
        if len(parts) == 5 and parts[:2] == ["v1", "auth"] and parts[2] == "sso" \
                and parts[4] == "start" and method == "GET":
            return self._sso_start(parts[3], body, headers)
        if len(parts) == 5 and parts[:2] == ["v1", "auth"] and parts[2] == "sso" \
                and parts[4] == "callback" and method in ("GET", "POST"):
            return self._sso_callback(parts[3], body, headers)
        # ---- authenticated admin/user routes ---------------------------------------------------
        ctx = self._authenticate(headers, cookies)                 # raises on failure
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            self._require_csrf(self._access_token(headers, cookies), headers)
        return self._dispatch_admin(method, parts, route, body, headers, ctx)

    # ------------------------------------------------------------------ auth endpoints
    def _login(self, body, headers):
        email = body.get("email")
        password = body.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            raise ValidationError("email and password are required")
        if len(email) > 320 or len(password) > 1024:
            raise ValidationError("invalid credentials format")
        org_id = body.get("org_id")
        if org_id is not None and not isinstance(org_id, str):
            raise ValidationError("org_id must be a string")
        user, session, access, refresh, csrf = self.service.login(
            email, password, org_id=org_id, ip=headers.get("X-Forwarded-For"),
            user_agent=headers.get("User-Agent"))
        return 200, {"user": user.public_dict(), "session": session.public_dict(),
                     "access_token": access, "refresh_token": refresh, "csrf_token": csrf,
                     "expires_in": self.config.access_ttl_s}, \
            cookie_headers(self.config, access, csrf)

    def _refresh(self, body, headers):
        token = body.get("refresh_token")
        if not isinstance(token, str) or not token:
            raise ValidationError("refresh_token is required")
        session, user, access, refresh, csrf = self.service.refresh(
            token, ip=headers.get("X-Forwarded-For"), user_agent=headers.get("User-Agent"))
        return 200, {"user": user.public_dict(), "session": session.public_dict(),
                     "access_token": access, "refresh_token": refresh, "csrf_token": csrf,
                     "expires_in": self.config.access_ttl_s}, cookie_headers(self.config, access, csrf)

    def _session(self, headers, cookies):
        token = self._access_token(headers, cookies)
        if not token:
            raise AuthenticationError("not authenticated")
        ctx = self.service.resolve_context(token)
        csrf = self.service.csrf_token(token)
        return 200, {"user_id": ctx.user_id, "org_id": ctx.org_id, "roles": list(ctx.roles),
                     "permissions": sorted(ctx.permissions), "is_platform_admin": ctx.is_platform_admin,
                     "session_id": ctx.session_id, "amr": list(ctx.amr),
                     "csrf_token": csrf}, []

    def _switch_tenant(self, body, headers, cookies):
        token = self._access_token(headers, cookies)
        if not token:
            raise AuthenticationError("not authenticated")
        self._require_csrf(token, headers)
        org_id = body.get("org_id")
        if not isinstance(org_id, str) or not org_id:
            raise ValidationError("org_id is required")
        user, session, access, refresh, csrf = self.service.switch_tenant(
            token, org_id, ip=headers.get("X-Forwarded-For"), user_agent=headers.get("User-Agent"))
        return 200, {"user": user.public_dict(), "session": session.public_dict(),
                     "access_token": access, "refresh_token": refresh, "csrf_token": csrf}, \
            cookie_headers(self.config, access, csrf)

    def _logout(self, headers, cookies):
        token = self._access_token(headers, cookies)
        if not token:
            return 200, {"revoked": False}, cookie_headers(self.config, clear=True)
        self._require_csrf(token, headers)
        ok = self.service.logout(token, ip=headers.get("X-Forwarded-For"),
                                 user_agent=headers.get("User-Agent"))
        return 200, {"revoked": ok}, cookie_headers(self.config, clear=True)

    def _sso_providers(self, body, headers, cookies):
        # public: enumerate ENABLED providers so a login page can render buttons (no secrets exposed)
        out = []
        for idp in self.service.store.list_idp(org_id=None):
            if idp.enabled:
                out.append({"idp_id": idp.idp_id, "org_id": idp.org_id, "issuer": idp.issuer})
        return 200, {"providers": out}, []

    def _sso_start(self, idp_id, body, headers):
        url, state = self.service.start_oidc_login(idp_id, return_to=body.get("return_to"),
                                                  ip=headers.get("X-Forwarded-For"),
                                                  user_agent=headers.get("User-Agent"))
        return 200, {"authorization_url": url, "state": state}, []

    def _sso_callback(self, idp_id, body, headers):
        params = body or {}
        state = params.get("state")
        code = params.get("code")
        if not isinstance(state, str) or not isinstance(code, str) or not state or not code:
            raise ValidationError("state and code are required")
        org_hint = params.get("org_id") if isinstance(params.get("org_id"), str) else None
        user, session, access, refresh, csrf, return_to = self.service.complete_oidc_login(
            idp_id, state, code, org_hint=org_hint, ip=headers.get("X-Forwarded-For"),
            user_agent=headers.get("User-Agent"))
        return 200, {"user": user.public_dict(), "session": session.public_dict(),
                     "access_token": access, "refresh_token": refresh, "csrf_token": csrf,
                     "return_to": return_to}, cookie_headers(self.config, access, csrf)

    # ------------------------------------------------------------------ admin endpoints
    def _authenticate(self, headers, cookies) -> AuthContext:
        token = self._access_token(headers, cookies)
        if not token:
            raise AuthenticationError("not authenticated")
        return self.service.resolve_context(token)

    def _dispatch_admin(self, method, parts, route, body, headers, ctx: AuthContext):
        actor = self.service.access_for(self.service.store.get_user(ctx.user_id), ctx.org_id)
        # --- users ------------------------------------------------------------------------------
        if route == "v1/admin/users" and method == "GET":
            org = body.get("org_id")
            users = self.admin.list_users(actor, org_id=org, limit=body.get("limit", 50),
                                         offset=body.get("offset", 0))
            return 200, {"users": [u.public_dict() for u in users]}, []
        if route == "v1/admin/users" and method == "POST":
            u = self.admin.create_user(
                actor, email=body.get("email"), display_name=body.get("display_name"),
                global_roles=body.get("global_roles") or (), password=body.get("password"),
                org_id=body.get("org_id"), tenant_roles=body.get("tenant_roles") or (),
                must_change_password=body.get("must_change_password"))
            return 201, u.public_dict(), []
        if len(parts) == 4 and parts[:3] == ["v1", "admin", "users"] and method == "POST":
            # /v1/admin/users/{id}/<action>
            return self._user_action(parts[3], body, actor)
        if len(parts) == 5 and parts[:3] == ["v1", "admin", "users"] and method == "POST" \
                and parts[4] == "roles":
            u = self.admin.set_global_roles(actor, parts[3], body.get("global_roles") or ())
            return 200, u.public_dict(), []
        if len(parts) == 5 and parts[:3] == ["v1", "admin", "users"] and parts[4] == "sessions" \
                and method == "GET":
            return 200, {"sessions": [s.public_dict() for s in
                                      self.admin.list_user_sessions(actor, parts[3])]}, []
        # --- memberships ------------------------------------------------------------------------
        if route == "v1/admin/memberships" and method == "POST":
            m = self.admin.add_membership(actor, org_id=body["org_id"], user_id=body["user_id"],
                                          roles=body.get("roles") or ())
            return 201, m.public_dict(), []
        if route == "v1/admin/memberships/roles" and method == "POST":
            m = self.admin.set_membership_roles(actor, org_id=body["org_id"], user_id=body["user_id"],
                                                roles=body.get("roles") or ())
            return 200, m.public_dict(), []
        if route == "v1/admin/memberships/suspend" and method == "POST":
            m = self.admin.suspend_membership(actor, org_id=body["org_id"], user_id=body["user_id"],
                                              reason=body.get("reason", "admin"))
            return 200, m.public_dict(), []
        if route == "v1/admin/memberships/reactivate" and method == "POST":
            m = self.admin.reactivate_membership(actor, org_id=body["org_id"], user_id=body["user_id"])
            return 200, m.public_dict(), []
        if route == "v1/admin/memberships" and method == "DELETE":
            self.admin.remove_membership(actor, org_id=body["org_id"], user_id=body["user_id"])
            return 200, {"removed": True}, []
        # --- sessions ---------------------------------------------------------------------------
        if route == "v1/admin/sessions/revoke" and method == "POST":
            n = self.admin.revoke_user_sessions(actor, body["user_id"],
                                                except_session_id=body.get("except_session_id"))
            return 200, {"revoked": n}, []
        if len(parts) == 5 and parts[:3] == ["v1", "admin", "sessions"] and parts[4] == "revoke" \
                and method == "POST":
            return 200, {"revoked": self.admin.revoke_session(actor, parts[3])}, []
        # --- audit / roles ----------------------------------------------------------------------
        if route == "v1/admin/audit" and method == "GET":
            events = self.admin.list_audit(actor, org_id=body.get("org_id"),
                                           limit=body.get("limit", 100),
                                           actor_user_id=body.get("actor_user_id"),
                                           event=body.get("event"))
            return 200, {"events": [e.public_dict() for e in events]}, []
        if route == "v1/admin/roles" and method == "GET":
            return 200, {"matrix": self.admin.role_matrix(actor)}, []
        # --- identity providers -----------------------------------------------------------------
        if route == "v1/admin/idps" and method == "GET":
            idps = self.admin.list_idps(actor, org_id=body.get("org_id"))
            return 200, {"idps": [i.public_dict() for i in idps]}, []
        if route == "v1/admin/idps" and method == "POST":
            cfg = self.admin.create_idp(
                actor, issuer=body["issuer"], client_id=body["client_id"],
                client_secret_ref=body["client_secret_ref"], redirect_uri=body["redirect_uri"],
                scopes=body.get("scopes") or ("openid", "profile", "email"), org_id=body.get("org_id"),
                jwks_uri=body.get("jwks_uri", ""), authorization_endpoint=body.get("authorization_endpoint", ""),
                token_endpoint=body.get("token_endpoint", ""),
                allowed_email_domains=body.get("allowed_email_domains") or (),
                require_verified_email=body.get("require_verified_email", True))
            return 201, cfg.public_dict(), []
        if route == "v1/admin/idps" and method == "DELETE":
            self.admin.delete_idp(actor, body["idp_id"])
            return 200, {"deleted": True}, []
        # --- Step 10: policy administration / JIT / approvals -----------------------------------
        if self.policy is not None and (route.startswith("v1/admin/policies")
                                        or route.startswith("v1/admin/jit")
                                        or route.startswith("v1/admin/approvals")):
            return self._dispatch_policy(method, parts, route, body, actor)
        # --- Step 11: tool & resource governance administration ---------------------------------
        if self.governance is not None and (route.startswith("v1/admin/resources")
                                            or route.startswith("v1/admin/tools")):
            return self._dispatch_governance(method, parts, route, body, actor)
        # --- Phase 4: egress/DLP administration + governed outbound requests --------------------
        if self.egress is not None and (route.startswith("v1/admin/egress")
                                        or route.startswith("v1/egress")):
            return self._dispatch_egress(method, parts, route, body, actor, ctx)
        # --- Phase 5: runtime monitoring, behaviour intelligence, intent graph, drift, risk, alerts
        if self.runtime is not None and (route.startswith("v1/runtime")
                                         or route.startswith("v1/admin/runtime")):
            return self._dispatch_runtime(method, parts, route, body, actor, ctx)
        # --- Phase 6: autonomous response (loop detection, budgets, approvals, incidents,
        # containment, evidence, audit) ---------------------------------------------------------
        if self.response is not None and (route.startswith("v1/response")
                                          or route.startswith("v1/admin/response")):
            return self._dispatch_response(method, parts, route, body, actor, ctx)
        # --- Phase 7: assurance (policy intelligence, tamper-evident audit, compliance, SIEM) -----
        if self.assurance is not None and (route.startswith("v1/assurance")
                                           or route.startswith("v1/admin/assurance")):
            return self._dispatch_assurance(method, parts, route, body, actor, ctx)
        return 404, {"error": "not_found"}, []

    # ------------------------------------------------------------------ Step 10 policy admin
    def _dispatch_policy(self, method, parts, route, body, actor):
        """Policy lifecycle, JIT grant and approval administration. All calls are RBAC-checked
        inside ``PolicyDecisionService`` (policy:read / policy:write / policy:activate)."""
        ps = self.policy
        # ---- policies --------------------------------------------------------------------------
        if route == "v1/admin/policies" and method == "GET":
            return 200, {"policies": [p.public_dict() for p in
                                      ps.list_policies(actor, org_id=body.get("org_id"))]}, []
        if route == "v1/admin/policies" and method == "POST":
            p = ps.create_policy(actor, name=body.get("name"), description=body.get("description", ""),
                                 org_id=body.get("org_id"), rego_source=body.get("rego_source"))
            return 201, p.public_dict(), []
        if len(parts) == 4 and parts[:3] == ["v1", "admin", "policies"]:
            pid = parts[3]
            if method == "GET":
                return 200, ps.get_policy(actor, pid).public_dict(), []
            if method == "DELETE":
                ps.delete_policy(actor, pid)
                return 200, {"deleted": True}, []
        if len(parts) == 5 and parts[:3] == ["v1", "admin", "policies"]:
            pid, action = parts[3], parts[4]
            if action == "versions" and method == "GET":
                return 200, {"versions": [v.public_dict() for v in ps.list_versions(actor, pid)]}, []
            if action == "versions" and method == "POST":
                v = ps.create_version(actor, pid, rego_source=body.get("rego_source"))
                return 201, v.public_dict(), []
            if action == "validate" and method == "POST":
                return 200, ps.validate(actor, pid, int(body["version"])), []
            if action == "test" and method == "POST":
                return 200, ps.test(actor, pid, int(body["version"]), cases=body.get("cases") or []), []
            if action == "activate" and method == "POST":
                return 200, ps.activate(actor, pid, int(body["version"])).public_dict(), []
            if action == "rollback" and method == "POST":
                return 200, ps.rollback(actor, pid, to_version=int(body["to_version"])).public_dict(), []
            if action == "disable" and method == "POST":
                return 200, ps.disable(actor, pid).public_dict(), []
        # ---- JIT grants ------------------------------------------------------------------------
        if route == "v1/admin/jit/grants" and method == "GET":
            grants = ps.jit.live_grants_for(org_id=body["org_id"], agent_id=body["agent_id"])
            return 200, {"grants": [g.public_dict() for g in grants]}, []
        if route == "v1/admin/jit/grants" and method == "POST":
            g = ps.jit.issue(org_id=body["org_id"], agent_id=body["agent_id"], action=body["action"],
                             resource=body["resource"], ttl_seconds=body.get("ttl_seconds"),
                             instance_id=body.get("instance_id"),
                             policy_version=body.get("policy_version"),
                             issued_by=actor.user_id, reason=body.get("reason", ""))
            return 201, g.public_dict(), []
        if route == "v1/admin/jit/grants/revoke" and method == "POST":
            g = ps.jit.revoke(body["grant_id"], reason=body.get("reason", "revoked"),
                              revoked_by=actor.user_id)
            return 200, {"revoked": g is not None}, []
        # ---- approvals (minimal; Step 17 owns the full workflow) --------------------------------
        if route == "v1/admin/approvals" and method == "POST":
            if ps.approvals is None:
                return 404, {"error": "not_found"}, []
            a = ps.approvals.request(org_id=body["org_id"], agent_id=body["agent_id"],
                                     action=body["action"], resource=body["resource"],
                                     requested_by=actor.user_id, reason=body.get("reason", ""))
            return 201, a.public_dict(), []
        if route == "v1/admin/approvals/decide" and method == "POST":
            if ps.approvals is None:
                return 404, {"error": "not_found"}, []
            a = ps.approvals.decide(body["approval_id"], approved=bool(body.get("approved")),
                                    decided_by=actor.user_id, reason=body.get("reason", ""))
            return 200, a.public_dict(), []
        return 404, {"error": "not_found"}, []

    # ------------------------------------------------------------------ Step 11 governance admin
    def _dispatch_governance(self, method, parts, route, body, actor):
        """Resource/tool registry administration. Every call is RBAC-checked INSIDE the registries
        (resource:read|write|admin, tool:read|write|approve|admin), so this router only shapes input.
        """
        gov = self.governance
        # ---- resources -------------------------------------------------------------------------
        if route == "v1/admin/resources" and method == "GET":
            return 200, {"resources": [r.public_dict() for r in
                                       gov.resources.list_resources(actor, org_id=body.get("org_id"))]}, []
        if route == "v1/admin/resources" and method == "POST":
            r = gov.resources.register_resource(
                actor, resource_id=body.get("resource_id"), org_id=body.get("org_id"),
                resource_type=body.get("resource_type"), name=body.get("name"),
                owner=body.get("owner"), sensitivity=body.get("sensitivity"),
                permitted_operations=body.get("permitted_operations") or (),
                policy_refs=body.get("policy_refs") or (), description=body.get("description", ""),
                metadata=body.get("metadata"), enabled=body.get("enabled", True))
            return 201, r.public_dict(), []
        if len(parts) == 4 and parts[:3] == ["v1", "admin", "resources"]:
            rid = parts[3]
            if method == "GET":
                return 200, gov.resources.get_resource(actor, rid).public_dict(), []
            if method == "DELETE":
                gov.resources.delete_resource(actor, rid)
                return 200, {"deleted": True}, []
        if len(parts) == 5 and parts[:3] == ["v1", "admin", "resources"] and method == "POST":
            rid, action = parts[3], parts[4]
            if action == "update":
                r = gov.resources.update_resource(
                    actor, rid, permitted_operations=body.get("permitted_operations"),
                    sensitivity=body.get("sensitivity"), policy_refs=body.get("policy_refs"),
                    description=body.get("description"), metadata=body.get("metadata"),
                    owner=body.get("owner"))
                return 200, r.public_dict(), []
            if action == "enable":
                return 200, gov.resources.set_enabled(actor, rid, True).public_dict(), []
            if action == "disable":
                return 200, gov.resources.set_enabled(actor, rid, False).public_dict(), []
        # ---- tools -----------------------------------------------------------------------------
        if route == "v1/admin/tools" and method == "GET":
            return 200, {"tools": [t.public_dict() for t in
                                   gov.tools.list_tools(actor, org_id=body.get("org_id"))]}, []
        if route == "v1/admin/tools" and method == "POST":
            t = gov.tools.register_tool(
                actor, org_id=body.get("org_id"), name=body.get("name"),
                version=body.get("version") or "0", owner=body.get("owner"),
                manifest=body.get("manifest"), resource_id=body.get("resource_id"),
                policy_refs=body.get("policy_refs") or (), description=body.get("description", ""),
                risk=body.get("risk"),
                requested_capabilities=body.get("requested_capabilities") or ())
            return 201, t.public_dict(), []
        if len(parts) == 4 and parts[:3] == ["v1", "admin", "tools"]:
            tid = parts[3]
            if method == "GET":
                return 200, gov.tools.get_tool(actor, tid).public_dict(), []
            if method == "DELETE":
                gov.tools.delete_tool(actor, tid)
                return 200, {"deleted": True}, []
        if len(parts) == 5 and parts[:3] == ["v1", "admin", "tools"] and method == "POST":
            tid, action = parts[3], parts[4]
            if action == "approve":
                t = gov.tools.approve_tool(
                    actor, tid, approved_capabilities=body.get("approved_capabilities") or (),
                    resource_id=body.get("resource_id"), policy_refs=body.get("policy_refs"),
                    risk=body.get("risk"))
                return 200, t.public_dict(), []
            if action == "enable":
                return 200, gov.tools.set_enabled(actor, tid, True).public_dict(), []
            if action == "disable":
                return 200, gov.tools.set_enabled(actor, tid, False).public_dict(), []
        return 404, {"error": "not_found"}, []

    # ------------------------------------------------------------------ Phase 4 egress admin + requests
    def _dispatch_egress(self, method, parts, route, body, actor, ctx):
        """Egress/DLP policy administration and the governed outbound-request endpoint.

        Policy administration is RBAC-checked (``policy:read`` / ``policy:write``) via the same
        ``Authorizer`` the rest of the admin surface uses. The governed-request endpoint runs the
        request through the egress gateway and returns the structured decision; it never executes a
        non-ALLOW.
        """
        from ..security.rbac import Authorizer, P_POLICY_READ, P_POLICY_WRITE
        eg = self.egress
        # A platform admin may act on an explicit org; a tenant admin is pinned to their own org.
        org_id = body.get("org_id") or ctx.org_id
        # ---- governed outbound request ---------------------------------------------------------
        if route == "v1/egress/request" and method == "POST":
            Authorizer.require(actor, P_POLICY_READ, org_id=org_id)
            out = eg.request(
                agent_id=body.get("agent_id") or ctx.user_id, tenant=org_id,
                request=_egress_request_from_body(body), instance_id=body.get("instance_id"),
                claimed_capabilities=tuple(body.get("claimed_capabilities") or ()),
                environment=body.get("environment", "development"),
                correlation_id=ctx.correlation_id)
            return 200, out, []
        # ---- policy administration -------------------------------------------------------------
        if route == "v1/admin/egress/policies" and method == "GET":
            Authorizer.require(actor, P_POLICY_READ, org_id=org_id)
            return 200, {"policies": [p.public_dict() for p in eg.list_policies(org_id=org_id)]}, []
        if route == "v1/admin/egress/policies" and method == "POST":
            Authorizer.require(actor, P_POLICY_WRITE, org_id=org_id)
            rec = eg.register_policy(
                org_id=org_id, name=body.get("name"), host_patterns=body.get("host_patterns"),
                protocols=body.get("protocols"), ports=body.get("ports"),
                action=body.get("action", "ALLOW"), priority=body.get("priority", 100),
                rate_limit=body.get("rate_limit"), max_request_bytes=body.get("max_request_bytes"),
                max_response_bytes=body.get("max_response_bytes"), timeout_ms=body.get("timeout_ms"),
                allow_redirects=body.get("allow_redirects", False),
                dlp_enabled=body.get("dlp_enabled", True), description=body.get("description", ""),
                created_by=actor.user_id)
            return 201, rec.public_dict(), []
        if len(parts) == 5 and parts[:4] == ["v1", "admin", "egress", "policies"]:
            pid = parts[4]
            if method == "GET":
                Authorizer.require(actor, P_POLICY_READ, org_id=org_id)
                return 200, eg.registry.get(pid, org_id=org_id).public_dict(), []
            if method == "DELETE":
                Authorizer.require(actor, P_POLICY_WRITE, org_id=org_id)
                eg.delete_policy(pid, org_id=org_id)
                return 200, {"deleted": True}, []
        if len(parts) == 6 and parts[:4] == ["v1", "admin", "egress", "policies"] and method == "POST":
            pid, action = parts[4], parts[5]
            Authorizer.require(actor, P_POLICY_WRITE, org_id=org_id)
            if action == "enable":
                return 200, eg.registry.set_enabled(pid, org_id=org_id,
                                                    enabled=True).public_dict(), []
            if action == "disable":
                return 200, eg.registry.set_enabled(pid, org_id=org_id,
                                                    enabled=False).public_dict(), []
        # ---- audit + metrics -------------------------------------------------------------------
        if route == "v1/admin/egress/audit" and method == "GET":
            Authorizer.require(actor, P_POLICY_READ, org_id=org_id)
            return 200, {"events": eg.store.list_audit(org_id=org_id,
                                                       limit=body.get("limit", 100))}, []
        if route == "v1/admin/egress/metrics" and method == "GET":
            Authorizer.require(actor, P_POLICY_READ, org_id=org_id)
            return 200, eg.metrics(), []
        return 404, {"error": "not_found"}, []

    # ------------------------------------------------------------------ Phase 5 runtime monitoring
    def _runtime_org(self, body, actor, ctx):
        """Resolve the tenant a runtime call acts on, FAIL CLOSED on cross-tenant attempts.

        A platform admin may name any org; every other caller is pinned to their own verified
        tenant and an explicit mismatched ``org_id`` is rejected rather than silently ignored.
        """
        from ..core.errors import ForbiddenError
        requested = body.get("org_id") if isinstance(body, dict) else None
        if requested is not None and not getattr(actor, "is_platform_admin", False):
            if requested != ctx.org_id:
                raise ForbiddenError("not permitted in this tenant")
            return ctx.org_id
        return requested or ctx.org_id

    def _dispatch_runtime(self, method, parts, route, body, actor, ctx):
        """Phase 5 runtime-monitoring surface (read = ``runtime:read``, manage = ``runtime:admin``).

        Reads serve the investigation views; the admin routes manage alert rules, behaviour
        baselines, retention and alert lifecycle. NOTHING here enforces: a response action only ever
        DELEGATES to the existing policy/JIT mechanisms, so the policy engine stays authoritative.
        """
        from ..core.errors import ValidationError
        from ..security.rbac import (Authorizer, P_RUNTIME_ADMIN, P_RUNTIME_READ)
        rt = self.runtime
        org_id = self._runtime_org(body, actor, ctx)

        # ---- reads -----------------------------------------------------------------------------
        if route == "v1/runtime/events" and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            items, cursor = rt.list_events(
                org_id=org_id, agent_id=body.get("agent_id"),
                event_type=body.get("event_type"), correlation_id=body.get("correlation_id"),
                trace_id=body.get("trace_id"), since=body.get("since"), until=body.get("until"),
                limit=body.get("limit", 100), cursor=body.get("cursor"))
            return 200, {"events": [e.public_dict() for e in items], "next_cursor": cursor}, []
        if route == "v1/runtime/investigate" and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            return 200, rt.investigate(
                org_id=org_id, agent_id=body.get("agent_id"),
                correlation_id=body.get("correlation_id"), trace_id=body.get("trace_id"),
                since=body.get("since"), until=body.get("until"), limit=body.get("limit", 200)), []
        if route == "v1/runtime/profiles" and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            return 200, {"profiles": [p.public_dict()
                                       for p in rt.profiles.list(org_id=org_id,
                                                                 limit=body.get("limit", 100))]}, []
        if len(parts) == 4 and parts[:3] == ["v1", "runtime", "profiles"] and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            p = rt.profiles.get(org_id=org_id, agent_id=parts[3])
            if p is None:
                return 404, {"error": "not_found"}, []
            return 200, p.public_dict(), []
        if route == "v1/runtime/findings" and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            items = rt.store.list_findings(org_id=org_id, agent_id=body.get("agent_id"),
                                           classification=body.get("classification"),
                                           since=body.get("since"), limit=body.get("limit", 100))
            return 200, {"findings": [f.to_dict() for f in items]}, []
        if route == "v1/runtime/risk" and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            items = rt.store.list_assessments(org_id=org_id, agent_id=body.get("agent_id"),
                                             since=body.get("since"), limit=body.get("limit", 100))
            return 200, {"assessments": [a.to_dict() for a in items],
                         "thresholds": rt.risk_rule_summary()}, []
        if route == "v1/runtime/graph/suspicious" and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            return 200, {"chains": rt.graph.suspicious_chains(
                org_id=org_id, agent_id=body.get("agent_id"),
                max_depth=body.get("max_depth", 3), limit=body.get("limit", 50))}, []
        if route == "v1/runtime/graph" and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            agent_id = body.get("agent_id")
            if not agent_id:
                return 200, rt.graph.stats(org_id=org_id), []
            return 200, rt.graph.agent_toolchain(org_id=org_id, agent_id=agent_id,
                                                 limit=body.get("limit", 200)), []
        if route == "v1/runtime/alerts" and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            return 200, {"alerts": [a.to_dict() for a in rt.alerts.list_alerts(
                org_id=org_id, state=body.get("state"), agent_id=body.get("agent_id"),
                limit=body.get("limit", 100))]}, []
        if len(parts) == 4 and parts[:3] == ["v1", "runtime", "alerts"] and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            try:
                return 200, rt.alerts.investigation_view(org_id=org_id, alert_id=parts[3]), []
            except Exception:                                       # noqa: BLE001 - not found
                return 404, {"error": "not_found"}, []
        if route == "v1/runtime/health" and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            return 200, rt.health(), []
        if route == "v1/runtime/metrics" and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            return 200, rt.metrics(), []

        # ---- ingest / analysis -----------------------------------------------------------------
        if route == "v1/runtime/ingest" and method == "POST":
            Authorizer.require(actor, P_RUNTIME_ADMIN, org_id=org_id)
            raw = body.get("events")
            if isinstance(raw, dict):
                raw = [raw]
            if not isinstance(raw, list) or not raw:
                raise ValidationError("events must be a non-empty list")
            return 202, {"results": [r.to_dict() for r in rt.ingest_many(raw, claimed_org=org_id)]}, []
        if route == "v1/runtime/observe" and method == "POST":
            Authorizer.require(actor, P_RUNTIME_ADMIN, org_id=org_id)
            agent_id = body.get("agent_id")
            raw = body.get("events")
            if not isinstance(agent_id, str) or not agent_id:
                raise ValidationError("agent_id is required")
            if not isinstance(raw, list) or not raw:
                raise ValidationError("events must be a non-empty list")
            return 200, rt.observe(
                org_id=org_id, agent_id=agent_id, raw_events=raw,
                declared_capabilities=body.get("declared_capabilities"),
                declared_tools=body.get("declared_tools"),
                declared_destinations=body.get("declared_destinations")), []

        # ---- rule administration ----------------------------------------------------------------
        if route == "v1/admin/runtime/rules" and method == "GET":
            Authorizer.require(actor, P_RUNTIME_READ, org_id=org_id)
            return 200, {"rules": [r.public_dict() for r in rt.alerts.list_rules(org_id=org_id)]}, []
        if route == "v1/admin/runtime/rules" and method == "POST":
            Authorizer.require(actor, P_RUNTIME_ADMIN, org_id=org_id)
            rule = rt.alerts.register_rule(
                org_id=org_id, name=body.get("name"), min_severity=body.get("min_severity", "medium"),
                event_types=body.get("event_types") or (), drift_classes=body.get("drift_classes") or (),
                risk_threshold=body.get("risk_threshold"), auto_actions=body.get("auto_actions") or (),
                dedup_window_s=body.get("dedup_window_s"), rate_window_s=body.get("rate_window_s"),
                max_per_window=body.get("max_per_window"), description=body.get("description", ""),
                actor_user_id=actor.user_id)
            return 201, rule.public_dict(), []
        if len(parts) == 5 and parts[:4] == ["v1", "admin", "runtime", "rules"]:
            if method == "DELETE":
                Authorizer.require(actor, P_RUNTIME_ADMIN, org_id=org_id)
                rt.alerts.delete_rule(org_id=org_id, rule_id=parts[4], actor_user_id=actor.user_id)
                return 200, {"deleted": True}, []

        # ---- baseline management ---------------------------------------------------------------
        if len(parts) == 6 and parts[:4] == ["v1", "admin", "runtime", "profiles"] \
                and method == "POST":
            agent_id, action = parts[4], parts[5]
            Authorizer.require(actor, P_RUNTIME_ADMIN, org_id=org_id)
            if action == "rebuild":
                p = rt.profiles.build(org_id=org_id, agent_id=agent_id)
                return 200, p.public_dict(), []
            if action == "reset":
                rt.profiles.reset(org_id=org_id, agent_id=agent_id,
                                  reason=body.get("reason", "manual_reset"),
                                  actor_user_id=actor.user_id)
                return 200, {"reset": True}, []
            if action == "retrain":
                p = rt.profiles.retrain(org_id=org_id, agent_id=agent_id,
                                        actor_user_id=actor.user_id)
                return 200, p.public_dict(), []

        # ---- alert lifecycle --------------------------------------------------------------------
        if len(parts) == 6 and parts[:4] == ["v1", "admin", "runtime", "alerts"] \
                and method == "POST":
            alert_id, action = parts[4], parts[5]
            Authorizer.require(actor, P_RUNTIME_ADMIN, org_id=org_id)
            mapping = {"acknowledge": "acknowledged", "investigate": "investigating",
                       "resolve": "resolved", "suppress": "suppressed"}
            target = mapping.get(action)
            if target is None:
                return 404, {"error": "not_found"}, []
            return 200, rt.alerts.transition(org_id=org_id, alert_id=alert_id, new_state=target,
                                             actor_user_id=actor.user_id,
                                             note=body.get("note", "")).to_dict(), []

        # ---- retention + graph reset ------------------------------------------------------------
        if route == "v1/admin/runtime/retention" and method == "POST":
            Authorizer.require(actor, P_RUNTIME_ADMIN, org_id=org_id)
            return 200, {"purged": rt.apply_retention(org_id=org_id)}, []
        if route == "v1/admin/runtime/graph/clear" and method == "POST":
            Authorizer.require(actor, P_RUNTIME_ADMIN, org_id=org_id)
            return 200, {"removed": rt.graph.clear(org_id=org_id, actor_user_id=actor.user_id)}, []
        return 404, {"error": "not_found"}, []

    # ------------------------------------------------------------------ Phase 6 autonomous response
    def _dispatch_assurance(self, method, parts, route, body, actor, ctx):
        """Phase 7 assurance surface.

        Reads = ``assurance:read``; evidence/analysis/compliance-seeding/SIEM = ``assurance:admin``;
        the policy-proposal lifecycle delegates to ``PolicyLifecycleService``, which enforces
        ``policy:write`` (author), ``policy:read`` (validate/simulate), ``assurance:approve``
        (decide) and ``policy:activate`` (canary/activate/rollback) itself. NOTHING here activates a
        policy: a proposal must be validated, approved by an authorized human and explicitly
        activated. ``actor`` is always the caller's VERIFIED identity.
        """
        from ..core.errors import ValidationError
        from ..security.rbac import (Authorizer, P_ASSURANCE_ADMIN, P_ASSURANCE_READ)
        asv = self.assurance
        org_id = self._runtime_org(body, actor, ctx)

        # ---- reads -----------------------------------------------------------------------------
        if route == "v1/assurance/recommendations" and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            return 200, {"recommendations": asv.list_recommendations(
                org_id=org_id, status=body.get("status"), limit=body.get("limit", 100))}, []
        if len(parts) == 4 and parts[:3] == ["v1", "assurance", "recommendations"] and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            r = asv.get_recommendation(org_id=org_id, recommendation_id=parts[3])
            if r is None:
                return 404, {"error": "not_found"}, []
            return 200, r, []
        if route == "v1/assurance/proposals" and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            return 200, {"proposals": [p.public_dict() for p in
                                       asv.list_proposals(actor, org_id=org_id,
                                                          status=body.get("status"))]}, []
        if len(parts) == 4 and parts[:3] == ["v1", "assurance", "proposals"] and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            return 200, asv.get_proposal(actor, parts[3], org_id=org_id).public_dict(
                include_source=True), []
        if route == "v1/assurance/audit" and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            rows = asv.list_audit(org_id=org_id, limit=body.get("limit", 100))
            return 200, {"audit": list(reversed(rows))}, []
        if route == "v1/assurance/audit/verify" and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            return 200, asv.verify_audit(org_id=org_id), []
        if route == "v1/assurance/audit/checkpoints" and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            cps = asv.store.list_checkpoints(org_id=org_id, limit=body.get("limit", 100))
            return 200, {"checkpoints": [c.public_dict() for c in cps]}, []
        if route == "v1/assurance/compliance/controls" and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            return 200, {"controls": asv.list_controls(framework=body.get("framework"))}, []
        if route == "v1/assurance/compliance/report" and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            return 200, asv.compliance_report(framework=body.get("framework"), org_id=org_id), []
        if route == "v1/assurance/siem/destinations" and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            return 200, {"destinations": asv.siem.list_destinations()}, []
        if route == "v1/assurance/siem/deliveries" and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            return 200, {"deliveries": asv.siem.list_deliveries(
                destination_id=body.get("destination_id"), status=body.get("status"),
                limit=body.get("limit", 200))}, []
        if route == "v1/assurance/correlations" and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            return 200, {"correlations": asv.list_correlations(org_id=org_id,
                                                               limit=body.get("limit", 200))}, []
        if route == "v1/assurance/health" and method == "GET":
            Authorizer.require(actor, P_ASSURANCE_READ, org_id=org_id)
            return 200, asv.health(), []

        # ---- evidence + analysis ---------------------------------------------------------------
        if route == "v1/admin/assurance/evidence" and method == "POST":
            Authorizer.require(actor, P_ASSURANCE_ADMIN, org_id=org_id)
            kind = body.get("kind")
            summary = body.get("summary")
            if not kind or not summary:
                raise ValidationError("kind and summary are required")
            e = asv.record_evidence(org_id=org_id, kind=kind, summary=summary,
                                    source=body.get("source", ""), agent_id=body.get("agent_id"),
                                    ref=body.get("ref"), payload=body.get("payload"),
                                    severity=body.get("severity", "medium"),
                                    count=body.get("count", 1),
                                    correlation_id=body.get("correlation_id"),
                                    detail=body.get("detail"))
            return 201, e.public_dict(), []
        if route == "v1/admin/assurance/analyze" and method == "POST":
            Authorizer.require(actor, P_ASSURANCE_ADMIN, org_id=org_id)
            return 200, {"recommendations": asv.analyze(org_id=org_id,
                                                        persist=bool(body.get("persist", True)))}, []

        # ---- policy proposal lifecycle (RBAC enforced inside the lifecycle service) -------------
        if route == "v1/admin/assurance/proposals" and method == "POST":
            p = asv.create_proposal(actor, org_id=org_id, proposed_rego=body.get("proposed_rego"),
                                    title=body.get("title", ""), rationale=body.get("rationale", ""),
                                    policy_id=body.get("policy_id"),
                                    base_version=body.get("base_version"),
                                    recommendation_id=body.get("recommendation_id"),
                                    impact_level=body.get("impact_level", "medium"))
            return 201, p.public_dict(include_source=True), []
        if len(parts) == 6 and parts[:3] == ["v1", "admin", "assurance"] \
                and parts[3] == "proposals" and method == "POST":
            proposal_id, action = parts[4], parts[5]
            if action == "validate":
                return 200, asv.validate_proposal(actor, proposal_id,
                                                  org_id=org_id).public_dict(), []
            if action == "simulate":
                return 200, asv.simulate_proposal(actor, proposal_id, org_id=org_id,
                                                  cases=body.get("cases", [])).public_dict(), []
            if action == "submit":
                return 200, asv.submit_proposal(actor, proposal_id,
                                                org_id=org_id).public_dict(), []
            if action == "decide":
                return 200, asv.decide_proposal(actor, proposal_id, org_id=org_id,
                                                decision=body.get("decision"),
                                                reason=body.get("reason", "")).public_dict(), []
            if action == "canary":
                return 200, asv.start_canary(actor, proposal_id, org_id=org_id).public_dict(), []
            if action == "canary-record":
                return 200, asv.record_canary(actor, proposal_id, org_id=org_id,
                                              samples=body.get("samples", 0),
                                              deny_delta=body.get("deny_delta", 0.0)).public_dict(), []
            if action == "activate":
                return 200, asv.activate_proposal(actor, proposal_id,
                                                  org_id=org_id).public_dict(), []
            if action == "rollback":
                return 200, asv.rollback_proposal(actor, proposal_id, org_id=org_id,
                                                  to_version=body.get("to_version")).public_dict(), []
            return 404, {"error": "not_found"}, []
        if route == "v1/admin/assurance/emergency" and method == "POST":
            p = asv.emergency_change(actor, org_id=org_id, proposed_rego=body.get("proposed_rego"),
                                     title=body.get("title", "emergency change"),
                                     rationale=body.get("rationale", ""),
                                     policy_id=body.get("policy_id"),
                                     base_version=body.get("base_version"))
            return 201, p.public_dict(include_source=True), []

        # ---- compliance + SIEM + correlation ---------------------------------------------------
        if route == "v1/admin/assurance/compliance/seed" and method == "POST":
            Authorizer.require(actor, P_ASSURANCE_ADMIN, org_id=org_id)
            return 200, {"installed": asv.seed_compliance(actor=actor.user_id)}, []
        if route == "v1/admin/assurance/siem/events" and method == "POST":
            Authorizer.require(actor, P_ASSURANCE_ADMIN, org_id=org_id)
            raw = body.get("event")
            if not isinstance(raw, dict):
                raise ValidationError("event is required")
            ev = asv.correlation.normalize(
                org_id=org_id, category=raw.get("category", "generic"),
                action=raw.get("action", ""), outcome=raw.get("outcome", ""),
                source=raw.get("source", "api"), severity=raw.get("severity", "medium"),
                agent_id=raw.get("agent_id"), correlation_id=raw.get("correlation_id"),
                classification=raw.get("classification", "internal"),
                incident_id=raw.get("incident_id"), policy_id=raw.get("policy_id"),
                policy_version=raw.get("policy_version"), fields=raw.get("fields"),
                subject=raw.get("subject"))
            return 202, asv.export_event(ev), []
        if route == "v1/admin/assurance/siem/flush" and method == "POST":
            Authorizer.require(actor, P_ASSURANCE_ADMIN, org_id=org_id)
            return 200, asv.flush_siem(max_batches=body.get("max_batches", 100)), []
        if route == "v1/admin/assurance/correlate" and method == "POST":
            Authorizer.require(actor, P_ASSURANCE_ADMIN, org_id=org_id)
            return 200, {"findings": asv.correlate(org_id=org_id, window_s=body.get("window_s"),
                                                   min_events=body.get("min_events", 3))}, []
        if route == "v1/admin/assurance/audit/checkpoint" and method == "POST":
            Authorizer.require(actor, P_ASSURANCE_ADMIN, org_id=org_id)
            cp = asv.checkpoint(org_id=org_id)
            return 200, {"checkpoint": cp}, []
        return 404, {"error": "not_found"}, []

    def _dispatch_response(self, method, parts, route, body, actor, ctx):
        """Phase 6 autonomous-response surface.

        Reads = ``response:read``; budgets/emergency-stops/incidents/containment = ``response:admin``;
        deciding an approval = ``response:approve``. NOTHING here enforces directly: containment only
        ever DELEGATES to the existing policy/JIT/identity/egress/governance mechanisms, so the policy
        engine stays authoritative. ``authorized_by`` is always the caller's VERIFIED user id -- an
        agent-supplied string in the body is never accepted as authorization.
        """
        from ..core.errors import ValidationError
        from ..security.rbac import (Authorizer, P_RESPONSE_ADMIN, P_RESPONSE_APPROVE,
                                     P_RESPONSE_READ)
        rs = self.response
        org_id = self._runtime_org(body, actor, ctx)
        actor_user_id = actor.user_id

        # ---- reads -----------------------------------------------------------------------------
        if route == "v1/response/findings" and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            return 200, {"findings": rs.list_findings(
                org_id=org_id, agent_id=body.get("agent_id"), pattern=body.get("pattern"),
                since=body.get("since"), limit=body.get("limit", 100))}, []
        if route == "v1/response/budgets" and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            return 200, {"budgets": [b.public_dict() for b in
                                     rs.budgets.list_budgets(org_id=org_id,
                                                             limit=body.get("limit", 200))]}, []
        if route == "v1/response/emergency-stops" and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            return 200, {"stops": [s.to_dict() for s in rs.budgets.list_stops(
                org_id=org_id, active_only=bool(body.get("active_only", False)),
                limit=body.get("limit", 200))]}, []
        if route == "v1/response/approvals" and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            return 200, {"approvals": [a.public_dict() for a in rs.approvals.list(
                org_id=org_id, status=body.get("status"), agent_id=body.get("agent_id"),
                limit=body.get("limit", 100))]}, []
        if len(parts) == 4 and parts[:3] == ["v1", "response", "approvals"] and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            a = rs.approvals.get(org_id=org_id, approval_id=parts[3])
            if a is None:
                return 404, {"error": "not_found"}, []
            return 200, a.public_dict(), []
        if route == "v1/response/incidents" and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            return 200, {"incidents": [i.public_dict() for i in rs.incidents.list(
                org_id=org_id, status=body.get("status"), agent_id=body.get("agent_id"),
                since=body.get("since"), limit=body.get("limit", 100))]}, []
        if len(parts) == 4 and parts[:3] == ["v1", "response", "incidents"] and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            try:
                return 200, rs.incidents.investigation_view(org_id=org_id,
                                                            incident_id=parts[3]), []
            except Exception:                                       # noqa: BLE001 - not found
                return 404, {"error": "not_found"}, []
        if route == "v1/response/executions" and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            return 200, {"executions": rs.list_responses(
                org_id=org_id, incident_id=body.get("incident_id"),
                agent_id=body.get("agent_id"), limit=body.get("limit", 100))}, []
        if len(parts) == 4 and parts[:3] == ["v1", "response", "executions"] and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            ex = rs.get_response(org_id=org_id, response_id=parts[3])
            if ex is None:
                return 404, {"error": "not_found"}, []
            return 200, ex, []
        if route == "v1/response/evidence" and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            return 200, {"evidence": [e.to_dict() for e in rs.evidence.list(
                org_id=org_id, incident_id=body.get("incident_id"),
                limit=body.get("limit", 200))]}, []
        if route == "v1/response/audit" and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            # The store returns insertion order (oldest first) for chain verification; the API shows
            # newest first, which is what an operator wants to read.
            rows = rs.list_audit(org_id=org_id, limit=body.get("limit", 100))
            return 200, {"audit": list(reversed(rows))}, []
        if route == "v1/response/audit/verify" and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            return 200, rs.verify_audit(org_id=org_id, limit=body.get("limit", 10_000)), []
        if route == "v1/response/health" and method == "GET":
            Authorizer.require(actor, P_RESPONSE_READ, org_id=org_id)
            return 200, {"status": "ok", "plane": "response",
                         "auto_containment": rs.cfg.containment_allow_auto,
                         "high_impact_requires_approval":
                             rs.cfg.containment_high_impact_requires_approval}, []

        # ---- detection -------------------------------------------------------------------------
        if route == "v1/response/evaluate" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            agent_id = body.get("agent_id")
            if not agent_id:
                raise ValidationError("agent_id is required")
            return 200, {"findings": rs.evaluate_agent(
                org_id=org_id, agent_id=agent_id, task_id=body.get("task_id"),
                persist=bool(body.get("persist", True)))}, []
        if route == "v1/response/observe" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            raw = body.get("events")
            if isinstance(raw, dict):
                raw = [raw]
            if not isinstance(raw, list) or not raw:
                raise ValidationError("events must be a non-empty list")
            # Normalize through the EXISTING Phase 5 pipeline (validation, redaction, tenant binding)
            # and then feed the resulting events into the loop detector -- one event pipeline, not two.
            if self.runtime is None:
                raise ValidationError("the runtime pipeline is not configured")
            results = self.runtime.ingest_many(raw, claimed_org=org_id)
            accepted = [r.event for r in results if getattr(r, "stored", False)
                        and r.event is not None]
            return 202, {"observed": rs.observe_events(accepted),
                         "results": [r.to_dict() for r in results]}, []

        # ---- budgets + emergency stops ---------------------------------------------------------
        if route == "v1/admin/response/budgets" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            b = rs.budgets.set_budget(
                org_id=org_id, agent_id=body.get("agent_id"), task_id=body.get("task_id"),
                scope=body.get("scope"), max_actions=body.get("max_actions"),
                max_retries=body.get("max_retries"), max_requests=body.get("max_requests"),
                max_concurrency=body.get("max_concurrency"), max_tokens=body.get("max_tokens"),
                max_cost=body.get("max_cost"), deadline_s=body.get("deadline_s"),
                actor_user_id=actor_user_id)
            return 201, b.public_dict(), []
        if len(parts) == 5 and parts[:4] == ["v1", "admin", "response", "budgets"] \
                and method == "DELETE":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            rs.budgets.delete_budget(org_id=org_id, budget_id=parts[4],
                                     actor_user_id=actor_user_id)
            return 200, {"deleted": parts[4]}, []
        if route == "v1/admin/response/emergency-stop" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            s = rs.budgets.emergency_stop(
                org_id=org_id, agent_id=body.get("agent_id"), task_id=body.get("task_id"),
                requested_by=actor_user_id, reason=body.get("reason", "emergency_stop"))
            return 201, s.to_dict(), []
        if len(parts) == 5 and parts[:4] == ["v1", "admin", "response", "emergency-stop"] \
                and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            s = rs.budgets.release_stop(org_id=org_id, stop_id=parts[4],
                                        released_by=actor_user_id,
                                        reason=body.get("reason", "released"))
            return 200, s.to_dict(), []

        # ---- approvals -------------------------------------------------------------------------
        if route == "v1/response/approvals" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            a = rs.approvals.request(
                org_id=org_id, agent_id=body.get("agent_id"), action=body.get("action"),
                resource=body.get("resource"), requested_by=actor_user_id,
                reason=body.get("reason", ""), params=body.get("params"),
                risk_score=body.get("risk_score"), risk_band=body.get("risk_band"),
                risk_evidence=body.get("risk_evidence") or (), policy_id=body.get("policy_id"),
                policy_version=body.get("policy_version"), incident_id=body.get("incident_id"),
                ttl_s=body.get("ttl_s"))
            return 201, a.public_dict(), []
        if len(parts) == 5 and parts[:4] == ["v1", "response", "approvals", "decide"] \
                and method == "POST":
            Authorizer.require(actor, P_RESPONSE_APPROVE, org_id=org_id)
            a = rs.approvals.decide(
                org_id=org_id, approval_id=parts[4], approved=bool(body.get("approved")),
                decided_by=actor_user_id, reason=body.get("reason", ""),
                approver_org_id=ctx.org_id,
                approver_is_platform_admin=bool(getattr(actor, "is_platform_admin", False)),
                approver_permissions=sorted(getattr(actor, "permissions", ()) or ()),
                required_permission=P_RESPONSE_APPROVE)
            return 200, a.public_dict(), []
        if len(parts) == 5 and parts[:4] == ["v1", "response", "approvals", "cancel"] \
                and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            a = rs.approvals.cancel(org_id=org_id, approval_id=parts[4],
                                    cancelled_by=actor_user_id,
                                    reason=body.get("reason", "cancelled"))
            return 200, a.public_dict(), []
        if len(parts) == 5 and parts[:4] == ["v1", "response", "approvals", "delegate"] \
                and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            a = rs.approvals.delegate(org_id=org_id, approval_id=parts[4],
                                      delegated_to=body.get("delegated_to"),
                                      delegated_by=actor_user_id)
            return 200, a.public_dict(), []

        # ---- incidents -------------------------------------------------------------------------
        if route == "v1/admin/response/incidents" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            inc = rs.incidents.open_or_correlate(
                org_id=org_id, title=body.get("title", "manual incident"),
                agent_id=body.get("agent_id"), subject=body.get("subject"),
                severity=body.get("severity", "medium"), detection_source="manual",
                resources=body.get("resources") or (), owner=actor_user_id)
            return 201, inc.public_dict(), []
        if len(parts) == 6 and parts[:4] == ["v1", "admin", "response", "incidents"] \
                and parts[5] == "transition" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            inc = rs.incidents.transition(org_id=org_id, incident_id=parts[4],
                                          new_status=body.get("status"),
                                          actor_user_id=actor_user_id,
                                          note=body.get("note", ""))
            return 200, inc.public_dict(), []
        if len(parts) == 6 and parts[:4] == ["v1", "admin", "response", "incidents"] \
                and parts[5] == "resolve" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            inc = rs.incidents.resolve(org_id=org_id, incident_id=parts[4],
                                       resolution=body.get("resolution", ""),
                                       actor_user_id=actor_user_id)
            return 200, inc.public_dict(), []
        if len(parts) == 6 and parts[:4] == ["v1", "admin", "response", "incidents"] \
                and parts[5] == "post-review" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            inc = rs.incidents.post_review(org_id=org_id, incident_id=parts[4],
                                           review=body.get("review", ""),
                                           actor_user_id=actor_user_id)
            return 200, inc.public_dict(), []

        # ---- containment -----------------------------------------------------------------------
        if route == "v1/admin/response/contain" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            ex = rs.contain(
                org_id=org_id, level=body.get("level"), agent_id=body.get("agent_id"),
                incident_id=body.get("incident_id"), authorized_by=actor_user_id,
                approved=bool(body.get("approved", False)), auto=bool(body.get("auto", False)),
                destination=body.get("destination"), tool_id=body.get("tool_id"),
                reason=body.get("reason", ""), idempotency_key=body.get("idempotency_key"))
            return 201, ex.public_dict(), []
        if len(parts) == 6 and parts[:4] == ["v1", "admin", "response", "executions"] \
                and parts[5] == "rollback" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            ex = rs.rollback(org_id=org_id, response_id=parts[4], authorized_by=actor_user_id,
                             reason=body.get("reason", "rollback"))
            return 200, ex.public_dict(), []

        # ---- evidence + retention ---------------------------------------------------------------
        if route == "v1/admin/response/evidence" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            e = rs.evidence.preserve(
                org_id=org_id, kind=body.get("kind", "generic"),
                summary=body.get("summary", ""), ref=body.get("ref"), payload=body.get("payload"),
                incident_id=body.get("incident_id"), agent_id=body.get("agent_id"),
                source="manual", seal=bool(body.get("seal", False)))
            return 201, e.to_dict(), []
        if len(parts) == 6 and parts[:4] == ["v1", "admin", "response", "evidence"] \
                and parts[5] == "seal" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            e = rs.evidence.seal(org_id=org_id, evidence_id=parts[4], actor_user_id=actor_user_id)
            return 200, e.to_dict(), []
        if route == "v1/admin/response/retention" and method == "POST":
            Authorizer.require(actor, P_RESPONSE_ADMIN, org_id=org_id)
            return 200, {"purged": rs.evidence.apply_retention(org_id=org_id)}, []
        return 404, {"error": "not_found"}, []

    def _user_action(self, action, body, actor):
        if action == "suspend":
            return 200, self.admin.suspend_user(actor, body["user_id"], body.get("reason", "admin")
                                                ).public_dict(), []
        if action == "reactivate":
            return 200, self.admin.reactivate_user(actor, body["user_id"]).public_dict(), []
        if action == "disable":
            return 200, self.admin.disable_user(actor, body["user_id"]).public_dict(), []
        if action == "password":
            return 200, self.admin.admin_set_password(actor, body["user_id"],
                                                       body["new_password"]).public_dict(), []
        return 404, {"error": "not_found"}, []


# --------------------------------------------------------------------------------- control-plane guard
#: Maps each EXISTING (Step 1-7) transport route to the permission a caller must hold. This is the
#: "review every control-plane endpoint" deliverable: no route is left unauthorised except the
#: unauthenticated probes (/livez, /readyz) and the platform admin-token path handled upstream.
CONTROL_PLANE_PERMISSIONS = {
    ("POST", "v1/organizations"): P_TENANT_CREATE,
    ("POST", "v1/agents"): P_AGENT_WRITE,
    ("POST", "v1/instances"): P_AGENT_WRITE,
    ("POST", "v1/credentials/issue"): P_CREDENTIAL_ISSUE,
    ("POST", "v1/credentials/rotate"): P_CREDENTIAL_ROTATE,
    ("POST", "v1/credentials/verify"): P_CREDENTIAL_READ,
    ("POST", "v1/credentials/revoke"): P_CREDENTIAL_REVOKE,
    ("POST", "v1/agents/spawn"): P_AGENT_SPAWN,
    ("GET", "v1/agents"): P_AGENT_READ,
    ("GET", "v1/credentials"): P_CREDENTIAL_READ,
    # Phase 5 (runtime monitoring). The full surface is served by the enterprise router, which
    # enforces these same permissions via ``Authorizer.require``; the entries here keep the
    # control-plane permission map complete and machine-checkable.
    ("GET", "v1/runtime/events"): P_RUNTIME_READ,
    ("GET", "v1/runtime/investigate"): P_RUNTIME_READ,
    ("GET", "v1/runtime/profiles"): P_RUNTIME_READ,
    ("GET", "v1/runtime/findings"): P_RUNTIME_READ,
    ("GET", "v1/runtime/risk"): P_RUNTIME_READ,
    ("GET", "v1/runtime/graph"): P_RUNTIME_READ,
    ("GET", "v1/runtime/graph/suspicious"): P_RUNTIME_READ,
    ("GET", "v1/runtime/alerts"): P_RUNTIME_READ,
    ("GET", "v1/runtime/health"): P_RUNTIME_READ,
    ("GET", "v1/runtime/metrics"): P_RUNTIME_READ,
    ("POST", "v1/runtime/ingest"): P_RUNTIME_ADMIN,
    ("POST", "v1/runtime/observe"): P_RUNTIME_ADMIN,
    ("GET", "v1/admin/runtime/rules"): P_RUNTIME_READ,
    ("POST", "v1/admin/runtime/rules"): P_RUNTIME_ADMIN,
    ("POST", "v1/admin/runtime/retention"): P_RUNTIME_ADMIN,
    ("POST", "v1/admin/runtime/graph/clear"): P_RUNTIME_ADMIN,
    # Phase 6 (autonomous response). The full surface is served by the enterprise router, which
    # enforces these same permissions via ``Authorizer.require``; the entries here keep the
    # control-plane permission map complete and machine-checkable.
    ("GET", "v1/response/findings"): P_RESPONSE_READ,
    ("GET", "v1/response/budgets"): P_RESPONSE_READ,
    ("GET", "v1/response/emergency-stops"): P_RESPONSE_READ,
    ("GET", "v1/response/approvals"): P_RESPONSE_READ,
    ("GET", "v1/response/incidents"): P_RESPONSE_READ,
    ("GET", "v1/response/executions"): P_RESPONSE_READ,
    ("GET", "v1/response/evidence"): P_RESPONSE_READ,
    ("GET", "v1/response/audit"): P_RESPONSE_READ,
    ("GET", "v1/response/audit/verify"): P_RESPONSE_READ,
    ("GET", "v1/response/health"): P_RESPONSE_READ,
    ("POST", "v1/response/evaluate"): P_RESPONSE_ADMIN,
    ("POST", "v1/response/observe"): P_RESPONSE_ADMIN,
    ("POST", "v1/response/approvals"): P_RESPONSE_ADMIN,
    ("POST", "v1/admin/response/budgets"): P_RESPONSE_ADMIN,
    ("POST", "v1/admin/response/emergency-stop"): P_RESPONSE_ADMIN,
    ("POST", "v1/admin/response/incidents"): P_RESPONSE_ADMIN,
    ("POST", "v1/admin/response/contain"): P_RESPONSE_ADMIN,
    ("POST", "v1/admin/response/evidence"): P_RESPONSE_ADMIN,
    ("POST", "v1/admin/response/retention"): P_RESPONSE_ADMIN,
}
#: Routes whose body carries a tenant id that MUST equal the caller's verified tenant scope.
_TENANT_KEYS = {"v1/organizations": "org_id", "v1/agents": "org_id", "v1/agents/spawn": "org_id"}


def required_permission(method: str, path: str) -> Optional[str]:
    """The permission an existing control-plane route requires, or None if it is not a known route."""
    clean = "/".join(p for p in path.split("?")[0].split("/") if p)
    # GET /v1/agents/{id}, GET /v1/credentials/{id}/status → read
    parts = clean.split("/")
    if method == "GET" and len(parts) >= 3 and parts[:2] == ["v1", "agents"]:
        return P_AGENT_READ
    if method == "GET" and len(parts) >= 3 and parts[:2] == ["v1", "credentials"]:
        return P_CREDENTIAL_READ
    # Phase 5: runtime reads are runtime:read; the write/analysis endpoints are runtime:admin.
    if len(parts) >= 2 and parts[0] == "v1" and parts[1] in ("runtime", "admin"):
        if parts[1] == "runtime":
            return P_RUNTIME_READ if method == "GET" else P_RUNTIME_ADMIN
        if len(parts) >= 4 and parts[2] == "runtime":
            return P_RUNTIME_READ if method == "GET" else P_RUNTIME_ADMIN
    # Phase 6: response reads are response:read; deciding an approval is response:approve; every
    # other response mutation (budgets, stops, incidents, containment, evidence) is response:admin.
    if len(parts) >= 2 and parts[0] == "v1" and parts[1] == "response":
        if method == "GET":
            return P_RESPONSE_READ
        if len(parts) >= 4 and parts[2] == "approvals" and parts[3] == "decide":
            return P_RESPONSE_APPROVE
        return P_RESPONSE_ADMIN
    if len(parts) >= 3 and parts[:2] == ["v1", "admin"] and parts[2] == "response":
        return P_RESPONSE_READ if method == "GET" else P_RESPONSE_ADMIN
    return CONTROL_PLANE_PERMISSIONS.get((method, clean))


def enforce_control_plane(service: EnterpriseAuthService, method: str, path: str, body: dict,
                          headers: dict, cookies: dict) -> AuthContext:
    """Authorize a call to an EXISTING control-plane route against the caller's verified context.

    Raises ``ForbiddenError``/``AuthenticationError`` on failure. Binds nothing here; the caller is
    responsible for running the operation inside ``db.tenant_scope(ctx.org_id)`` so that RLS is also
    active for the query.
    """
    token = headers.get("Authorization", "")
    token = token[7:] if token.startswith("Bearer ") else cookies.get(service.config.cookie_name, "")
    if not token:
        raise AuthenticationError("not authenticated")
    ctx = service.resolve_context(token)
    perm = required_permission(method, path)
    if perm is None:
        return ctx                                            # unknown route: handled elsewhere (404)
    clean = "/".join(p for p in path.split("?")[0].split("/") if p)
    requested_org = None
    key = _TENANT_KEYS.get(clean)
    if key and isinstance(body, dict):
        requested_org = body.get(key)
    actor = service.access_for(service.store.get_user(ctx.user_id), ctx.org_id)
    from ..security.rbac import Authorizer
    # tenant scope: a non-platform-admin may only act within their own verified tenant
    if requested_org is not None and not actor.is_platform_admin:
        if ctx.org_id != requested_org:
            service._audit_deny(ctx.user_id, org_id=ctx.org_id, target_type="tenant",
                                target_id=str(requested_org), reason="cross_tenant_denied",
                                correlation_id=ctx.correlation_id)
            raise ForbiddenError("not permitted in this tenant")
    Authorizer.require(actor, perm, org_id=(requested_org if requested_org is not None else None))
    return ctx


def _parse_query(path: str) -> dict:
    """Parse a URL query string into a flat dict (last value wins). Never raises."""
    from urllib.parse import parse_qs
    qs = path.split("?", 1)[1] if "?" in path else ""
    if not qs:
        return {}
    out = {}
    for k, v in parse_qs(qs, keep_blank_values=True).items():
        out[k] = v[-1] if v else ""
    return out


def handle_enterprise(router: EnterpriseRouter, service: EnterpriseAuthService, method: str, path: str,
                      body: dict, headers: dict, cookies: dict,
                      fallback: Optional[Callable] = None,
                      management=None) -> Tuple[int, object, list]:
    """Try enterprise routes, else guard + delegate to ``fallback`` (the Step 1-7 handler).

    Phase 8: when a ``management`` API is supplied, ``/v2/*`` is served by it (the versioned
    console/CLI/SDK surface). It is an OPTIONAL argument, so every existing caller and test keeps
    working unchanged and the ``/v2`` surface simply 404s when it is not wired.
    """
    clean = "/".join(p for p in path.split("?")[0].split("/") if p)
    if management is not None and (clean == "v2" or clean.startswith("v2/")):
        return management.handle(method, path, _parse_query(path), body, headers, cookies)
    if clean.startswith("v1/auth/") or clean.startswith("v1/admin/") \
            or clean.startswith("v1/runtime/") or clean.startswith("v1/response/"):
        return router.handle(method, path, body, headers, cookies)
    if fallback is None:
        return 404, {"error": "not_found"}, []
    # authorize the existing route BEFORE running it (review requirement)
    if clean not in ("livez", "readyz", "metrics"):
        enforce_control_plane(service, method, path, body, headers, cookies)
    status, payload = fallback(method, path, body, headers)
    return status, payload, []
