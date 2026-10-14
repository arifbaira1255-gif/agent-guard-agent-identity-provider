"""Phase 8 management API (``/v2/*``) -- the versioned, console-facing surface.

This is the API platform the Enterprise Console, the CLI and the SDKs all talk to. It is a *thin,
uniform* layer over the existing Phase 1-7 services:

* **No second authorization path.** Every route resolves the caller's verified
  :class:`~agent_identity.security.models.AuthContext` through the existing
  :class:`~agent_identity.security.auth_service.EnterpriseAuthService` and enforces its permission
  with the existing :class:`~agent_identity.security.rbac.Authorizer`. Frontend visibility is never
  an authorization mechanism.
* **No second database.** Reads go straight to the existing stores/services (identity registry,
  policy service, governance, egress, runtime monitoring, response, assurance).
* **Honest availability.** When an optional plane is not wired, its routes return
  ``{"available": false, "reason": ...}`` (or 404 for a missing resource) -- never fabricated data.

Cross-cutting behaviour (pagination, filters, rate limiting, request-size limits, correlation ids,
consistent errors, redaction, idempotency) lives in :mod:`agent_identity.api.platform`.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ..core.errors import (AuthenticationError, CsrfError, ForbiddenError, NotFoundError,
                           ValidationError)
from ..observability.phase8 import INSTRUMENTED_PATHS, Observability
from ..security.models import AuthContext
from ..security.rbac import (Authorizer, P_AGENT_READ, P_AGENT_REVOKE, P_ASSURANCE_ADMIN,
                             P_ASSURANCE_READ, P_AUDIT_READ, P_CREDENTIAL_READ,
                             P_POLICY_READ, P_RESPONSE_ADMIN, P_RESPONSE_APPROVE, P_RESPONSE_READ,
                             P_RESOURCE_READ, P_RUNTIME_ADMIN, P_RUNTIME_READ, P_TOOL_READ)
from .platform import (API_PREFIX, API_VERSION, MAX_BODY_BYTES, ApiError, RouteRegistry, RouteSpec,
                       RateLimiter, clamp_limit, error_envelope, idempotency_fingerprint, paginate,
                       parse_filters, parse_pagination, parse_time_range, redact_mapping)

# --------------------------------------------------------------------------- helpers
_OBJ_SKIP = {"password_hash", "csrf_secret", "client_secret_ref", "token_hash", "code_verifier",
             "nonce", "private_key", "secret"}


def _obj_dict(obj: Any) -> Any:
    """Best-effort, secret-free dict view of a domain object."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj
    for name in ("public_dict", "to_dict", "as_dict"):
        fn = getattr(obj, name, None)
        if callable(fn):
            try:
                return fn()
            except Exception:                                    # noqa: BLE001
                pass
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in vars(obj).items() if k not in _OBJ_SKIP and not k.startswith("_")}
    return str(obj)


def _list_agents(registry: Any) -> List[Any]:
    """List agents from the identity registry without assuming one exact method name."""
    for name in ("list_all", "list_agents", "all", "list"):
        fn = getattr(registry, name, None)
        if callable(fn):
            try:
                return list(fn())
            except TypeError:
                continue
            except Exception:                                    # noqa: BLE001
                continue
    d = getattr(registry, "_agents", None)
    if isinstance(d, dict):
        return list(d.values())
    return []


def _iso(ts: Optional[float]) -> Optional[str]:
    from ..core.models import iso
    return iso(ts)


class ManagementApi:
    """The ``/v2`` management API. Pure: takes structured data, returns structured data."""

    def __init__(self, *, auth_service, admin_ops, config=None, clock=None,
                 identity_service=None, policy_service=None, governance_service=None,
                 egress_service=None, runtime_service=None, response_service=None,
                 assurance_service=None, observability: Optional[Observability] = None,
                 rate_limiter: Optional[RateLimiter] = None):
        self.auth = auth_service
        self.admin = admin_ops
        self.config = config or getattr(auth_service, "config", None)
        self.clock = clock
        self.identity = identity_service
        self.policy = policy_service
        self.governance = governance_service
        self.egress = egress_service
        self.runtime = runtime_service
        self.response = response_service
        self.assurance = assurance_service
        self.obs = observability or Observability()
        self.limiter = rate_limiter or RateLimiter()
        self.registry = RouteRegistry()
        self._register_routes()

    # ------------------------------------------------------------------ time
    def _now(self) -> float:
        return self.clock.now() if self.clock is not None else time.time()

    # ------------------------------------------------------------------ route table
    def _register_routes(self) -> None:
        r = self.registry
        # --- session / identity ---------------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/session", P_AGENT_READ, "Current session + effective permissions",
                        "session", tenant_scoped=False))
        r.add(RouteSpec("GET", "/v2/me/permissions", P_AGENT_READ, "Effective permission set",
                        "session", tenant_scoped=False))
        # --- agents ---------------------------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/agents", P_AGENT_READ, "List agents (paginated)",
                        "agents", query=("status", "agent_type", "owner", "q", "limit", "offset")))
        r.add(RouteSpec("GET", "/v2/agents/{agent_id}", P_AGENT_READ, "Agent detail", "agents",
                        params=("agent_id",)))
        r.add(RouteSpec("GET", "/v2/agents/{agent_id}/health", P_AGENT_READ, "Agent runtime health",
                        "agents", params=("agent_id",)))
        r.add(RouteSpec("GET", "/v2/agents/{agent_id}/activity", P_RUNTIME_READ,
                        "Agent runtime activity", "agents", params=("agent_id",),
                        query=("since", "until", "limit", "offset")))
        r.add(RouteSpec("POST", "/v2/agents/{agent_id}/suspend", P_AGENT_REVOKE,
                        "Suspend an agent (high impact)", "agents", params=("agent_id",),
                        mutating=True, high_impact=True))
        # --- policies -------------------------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/policies", P_POLICY_READ, "List policies", "policies",
                        query=("status", "limit", "offset")))
        r.add(RouteSpec("GET", "/v2/policies/{policy_id}", P_POLICY_READ, "Policy detail", "policies",
                        params=("policy_id",)))
        r.add(RouteSpec("GET", "/v2/policies/{policy_id}/versions", P_POLICY_READ,
                        "Policy versions", "policies", params=("policy_id",)))
        r.add(RouteSpec("POST", "/v2/policies/{policy_id}/simulate", P_POLICY_READ,
                        "Simulate a policy version against cases", "policies",
                        params=("policy_id",), mutating=False))
        # --- permissions / governance ---------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/permissions", P_RESOURCE_READ, "Role/permission matrix",
                        "permissions", tenant_scoped=False))
        r.add(RouteSpec("GET", "/v2/resources", P_RESOURCE_READ, "Governed resources", "permissions",
                        query=("limit", "offset")))
        r.add(RouteSpec("GET", "/v2/tools", P_TOOL_READ, "Tool registry", "permissions",
                        query=("limit", "offset")))
        # --- egress / DLP ---------------------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/egress/policies", P_POLICY_READ, "Egress policies", "egress",
                        query=("limit", "offset")))
        r.add(RouteSpec("GET", "/v2/egress/findings", P_POLICY_READ, "DLP findings", "egress",
                        query=("since", "until", "limit", "offset")))
        r.add(RouteSpec("GET", "/v2/egress/metrics", P_POLICY_READ, "Egress/DLP metrics", "egress"))
        # --- anomalies / risk -----------------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/anomalies", P_RUNTIME_READ, "Behavioural anomalies / drift",
                        "anomalies", query=("agent_id", "class", "since", "until", "limit", "offset")))
        r.add(RouteSpec("GET", "/v2/risk", P_RUNTIME_READ, "Risk assessments", "anomalies",
                        query=("agent_id", "limit", "offset")))
        # --- alerts / incidents ---------------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/alerts", P_RUNTIME_READ, "Security alerts", "incidents",
                        query=("state", "severity", "since", "until", "limit", "offset")))
        r.add(RouteSpec("GET", "/v2/incidents", P_RESPONSE_READ, "Incidents", "incidents",
                        query=("status", "agent_id", "since", "until", "limit", "offset")))
        r.add(RouteSpec("GET", "/v2/incidents/{incident_id}", P_RESPONSE_READ,
                        "Incident investigation view", "incidents", params=("incident_id",)))
        r.add(RouteSpec("GET", "/v2/containment", P_RESPONSE_READ, "Containment executions",
                        "incidents", query=("incident_id", "agent_id", "limit", "offset")))
        # --- approvals ------------------------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/approvals", P_RESPONSE_READ, "Approval requests", "approvals",
                        query=("status", "agent_id", "limit", "offset")))
        r.add(RouteSpec("POST", "/v2/approvals/{approval_id}/decide", P_RESPONSE_APPROVE,
                        "Decide an approval (high impact)", "approvals", params=("approval_id",),
                        mutating=True, high_impact=True))
        # --- audit ----------------------------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/audit", P_AUDIT_READ, "Administrative audit events", "audit",
                        query=("since", "until", "limit", "offset")))
        r.add(RouteSpec("GET", "/v2/audit/integrity", P_ASSURANCE_READ,
                        "Tamper-evident audit chain verification", "audit"))
        r.add(RouteSpec("GET", "/v2/audit/checkpoints", P_ASSURANCE_READ, "Signed audit checkpoints",
                        "audit", query=("limit", "offset")))
        # --- assurance ------------------------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/recommendations", P_ASSURANCE_READ,
                        "Self-healing policy recommendations", "assurance",
                        query=("status", "limit", "offset")))
        r.add(RouteSpec("GET", "/v2/proposals", P_ASSURANCE_READ, "Policy proposals", "assurance",
                        query=("status", "limit", "offset")))
        r.add(RouteSpec("GET", "/v2/compliance/controls", P_ASSURANCE_READ, "Compliance controls",
                        "assurance", query=("framework", "limit", "offset")))
        r.add(RouteSpec("GET", "/v2/compliance/report", P_ASSURANCE_READ, "Compliance evidence report",
                        "assurance", query=("framework",)))
        # --- SIEM -----------------------------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/siem/destinations", P_ASSURANCE_READ, "SIEM destinations",
                        "siem", query=("limit", "offset")))
        r.add(RouteSpec("GET", "/v2/siem/deliveries", P_ASSURANCE_READ, "SIEM delivery status",
                        "siem", query=("destination_id", "status", "limit", "offset")))
        r.add(RouteSpec("GET", "/v2/correlations", P_ASSURANCE_READ, "Correlated security findings",
                        "siem", query=("limit", "offset")))
        # --- observability --------------------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/health", P_RUNTIME_READ, "System health + dependency status",
                        "observability", tenant_scoped=False))
        r.add(RouteSpec("GET", "/v2/metrics", P_RUNTIME_READ, "Operational metrics (JSON)",
                        "observability", tenant_scoped=False))
        r.add(RouteSpec("GET", "/v2/metrics/prometheus", P_RUNTIME_READ,
                        "Operational metrics (Prometheus text)", "observability",
                        tenant_scoped=False))
        # --- admin / config -------------------------------------------------------------------
        r.add(RouteSpec("GET", "/v2/admin/integrations", P_ASSURANCE_ADMIN,
                        "Integration configuration (SIEM destinations)", "admin",
                        query=("limit", "offset")))
        r.add(RouteSpec("POST", "/v2/admin/retention/apply", P_RUNTIME_ADMIN,
                        "Apply retention purge (high impact)", "admin", mutating=True,
                        high_impact=True))
        r.add(RouteSpec("GET", "/v2/admin/audit", P_AUDIT_READ, "Admin audit log", "admin",
                        query=("limit", "offset")))

    # ------------------------------------------------------------------ entry point
    def handle(self, method: str, path: str, query: dict, body: dict, headers: dict,
               cookies: dict) -> Tuple[int, object, list]:
        """Dispatch a ``/v2`` request. Returns ``(status, body, extra_headers)``."""
        clean = "/" + "/".join(p for p in path.split("?")[0].split("/") if p)
        correlation_id = (headers.get("X-Correlation-Id") or headers.get("x-correlation-id")
                          or _new_correlation_id())
        t0 = time.perf_counter()
        route_class = "unknown"
        try:
            # --- unauthenticated, sanitized probes (orchestrator must reach them) -------------
            if clean in ("/v2/livez", "/v2/readyz"):
                payload = (self.obs.liveness() if clean == "/v2/livez"
                           else self.obs.readiness(planes=self._plane_states()))
                status = 200 if payload.get("status") in ("alive", "ready") else 503
                return status, payload, [("X-Correlation-Id", correlation_id)]

            match = self.registry.match(method, clean)
            if match is None:
                raise ApiError(404, "not_found", "no such route")
            spec, path_params = match
            route_class = spec.tag

            # --- request-size limit -----------------------------------------------------------
            if method in ("POST", "PUT", "PATCH") and _body_size(body) > MAX_BODY_BYTES:
                raise ApiError(413, "payload_too_large", "request body too large")

            # --- authenticate -----------------------------------------------------------------
            ctx = self._authenticate(headers, cookies)
            # --- CSRF for state-changing routes ------------------------------------------------
            if spec.mutating:
                self._require_csrf(headers, cookies)
            # --- rate limit (per principal, per route class) -----------------------------------
            self.limiter.check(spec.tag, ctx.user_id)

            actor = self.auth.access_for(self.auth.store.get_user(ctx.user_id), ctx.org_id)
            org_id = self._resolve_org(body, query, actor, ctx, spec)
            if spec.tenant_scoped:
                Authorizer.require(actor, spec.permission, org_id=org_id)
            else:
                Authorizer.require(actor, spec.permission)

            status, payload = self._dispatch(spec, path_params, query, body, actor, ctx, org_id)
            payload = redact_mapping(payload)
            seconds = time.perf_counter() - t0
            self.obs.record_request(route_class=route_class, status=status, seconds=seconds,
                                    correlation_id=correlation_id)
            return status, payload, [("X-Correlation-Id", correlation_id)]
        except Exception as exc:                                     # noqa: BLE001
            status, payload = error_envelope(exc, correlation_id=correlation_id)
            payload = redact_mapping(payload)
            self.obs.record_request(route_class=route_class, status=status,
                                    seconds=time.perf_counter() - t0,
                                    correlation_id=correlation_id)
            return status, payload, [("X-Correlation-Id", correlation_id)]

    # ------------------------------------------------------------------ auth helpers
    def _authenticate(self, headers: dict, cookies: dict) -> AuthContext:
        token = self._access_token(headers, cookies)
        if not token:
            raise AuthenticationError("not authenticated")
        return self.auth.resolve_context(token)

    def _access_token(self, headers: dict, cookies: dict) -> str:
        auth = headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        name = getattr(self.config, "cookie_name", "ag_session")
        return cookies.get(name, "")

    def _require_csrf(self, headers: dict, cookies: dict) -> None:
        token = self._access_token(headers, cookies)
        header = getattr(self.config, "csrf_header", "X-CSRF-Token")
        if not self.auth.check_csrf(token, headers.get(header)):
            raise CsrfError("missing or invalid CSRF token")

    def _resolve_org(self, body: dict, query: dict, actor, ctx: AuthContext, spec: RouteSpec
                     ) -> Optional[str]:
        """Resolve the tenant a request acts on, FAIL CLOSED on cross-tenant attempts."""
        requested = None
        if isinstance(body, dict) and body.get("org_id"):
            requested = body.get("org_id")
        elif isinstance(query, dict) and query.get("org_id"):
            requested = query.get("org_id")
        if requested is not None and not getattr(actor, "is_platform_admin", False):
            if requested != ctx.org_id:
                raise ForbiddenError("not permitted in this tenant")
            return ctx.org_id
        return requested or ctx.org_id

    def _plane_states(self) -> Dict[str, bool]:
        return {"policy": self.policy is not None, "governance": self.governance is not None,
                "egress": self.egress is not None, "runtime": self.runtime is not None,
                "response": self.response is not None, "assurance": self.assurance is not None}

    # ------------------------------------------------------------------ dispatch
    def _dispatch(self, spec: RouteSpec, params: dict, query: dict, body: dict, actor, ctx,
                  org_id: Optional[str]) -> Tuple[int, object]:
        key = (spec.method, spec.path)
        handler = _HANDLERS.get(key)
        if handler is None:
            raise ApiError(404, "not_found", "no such route")
        return handler(self, params, query, body, actor, ctx, org_id)

    # ================================================================== handlers
    def _h_session(self, params, query, body, actor, ctx, org_id):
        return 200, {"user_id": ctx.user_id, "org_id": ctx.org_id, "roles": list(ctx.roles),
                     "permissions": sorted(ctx.permissions),
                     "is_platform_admin": ctx.is_platform_admin, "session_id": ctx.session_id,
                     "amr": list(ctx.amr), "api_version": API_VERSION}

    def _h_me_permissions(self, params, query, body, actor, ctx, org_id):
        from ..security.rbac import permission_matrix
        return 200, {"user_id": ctx.user_id, "org_id": ctx.org_id,
                     "permissions": sorted(ctx.permissions), "roles": list(ctx.roles),
                     "matrix": permission_matrix()}

    # --- agents -------------------------------------------------------------------------------
    def _h_agents_list(self, params, query, body, actor, ctx, org_id):
        # Validate caller input FIRST: a malformed request is a 400 regardless of whether the
        # backing plane happens to be configured.
        offset, limit = parse_pagination(query)
        filters = parse_filters(query, allowed=("status", "agent_type", "owner"))
        if self.identity is None:
            return 200, {"available": False, "reason": "identity service not configured",
                         "items": [], "page": {"total": 0, "offset": offset, "limit": limit,
                                               "count": 0, "has_more": False, "next_offset": None}}
        rows = []
        for a in _list_agents(self.identity.agents):
            d = _obj_dict(a)
            if not isinstance(d, dict):
                continue
            if org_id is not None and d.get("org_id") not in (None, org_id):
                continue
            if filters.get("status") and str(d.get("status")) != filters["status"]:
                continue
            if filters.get("agent_type") and str(d.get("agent_type")) != filters["agent_type"]:
                continue
            if filters.get("owner") and str(d.get("owner")) != filters["owner"]:
                continue
            q = query.get("q")
            if q and q.lower() not in str(d.get("agent_name", "")).lower():
                continue
            rows.append(d)
        rows.sort(key=lambda d: str(d.get("created_at") or ""), reverse=True)
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_agent_detail(self, params, query, body, actor, ctx, org_id):
        if self.identity is None:
            raise ApiError(404, "not_found", "identity service not configured")
        try:
            d = self.identity.get_agent_identity(params["agent_id"])
        except Exception:                                            # noqa: BLE001
            raise NotFoundError("agent not found")
        if org_id is not None and isinstance(d, dict) and d.get("org_id") not in (None, org_id):
            raise ForbiddenError("not permitted in this tenant")
        return 200, d

    def _h_agent_health(self, params, query, body, actor, ctx, org_id):
        agent_id = params["agent_id"]
        out = {"agent_id": agent_id, "planes": {}}
        if self.runtime is not None:
            try:
                prof = self.runtime.store.get_profile(org_id=org_id, agent_id=agent_id)
                out["planes"]["runtime"] = {"profile_present": prof is not None}
            except Exception:                                        # noqa: BLE001
                out["planes"]["runtime"] = {"available": False}
        else:
            out["planes"]["runtime"] = {"available": False, "reason": "not configured"}
        if self.response is not None:
            try:
                out["planes"]["response"] = {"findings": len(self.response.list_findings(
                    org_id=org_id, agent_id=agent_id, limit=1))}
            except Exception:                                        # noqa: BLE001
                out["planes"]["response"] = {"available": False}
        else:
            out["planes"]["response"] = {"available": False, "reason": "not configured"}
        return 200, out

    def _h_agent_activity(self, params, query, body, actor, ctx, org_id):
        if self.runtime is None:
            return 200, {"available": False, "reason": "runtime monitoring not configured",
                         "items": [], "page": {"total": 0, "offset": 0, "limit": 0, "count": 0,
                                               "has_more": False, "next_offset": None}}
        offset, limit = parse_pagination(query)
        since, until = parse_time_range(query, now=self._now())
        events = self.runtime.list_events(org_id=org_id, agent_id=params["agent_id"], since=since,
                                          until=until, limit=clamp_limit(query.get("limit"),
                                                                         default=1000))
        rows = [_obj_dict(e) for e in events]
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_agent_suspend(self, params, query, body, actor, ctx, org_id):
        if self.identity is None:
            raise ApiError(404, "not_found", "identity service not configured")
        from ..core.models import RevocationReason
        reason = body.get("reason") or "administrative_action"
        try:
            r = RevocationReason(reason)
        except ValueError:
            raise ValidationError("invalid revocation reason")
        self.identity.revoke_agent(params["agent_id"], r, actor.user_id)
        self.obs.log.emit("admin.agent.suspend", actor=actor.user_id, target_type="agent",
                          target_id=params["agent_id"], result="ok", correlation_id=ctx.correlation_id)
        return 200, {"agent_id": params["agent_id"], "suspended": True, "reason": reason}

    # --- policies -----------------------------------------------------------------------------
    def _h_policies_list(self, params, query, body, actor, ctx, org_id):
        if self.policy is None:
            return 200, {"available": False, "reason": "policy engine not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = [_obj_dict(p) for p in self.policy.list_policies(actor, org_id=org_id)]
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_policy_detail(self, params, query, body, actor, ctx, org_id):
        if self.policy is None:
            raise ApiError(404, "not_found", "policy engine not configured")
        return 200, _obj_dict(self.policy.get_policy(actor, params["policy_id"]))

    def _h_policy_versions(self, params, query, body, actor, ctx, org_id):
        if self.policy is None:
            raise ApiError(404, "not_found", "policy engine not configured")
        offset, limit = parse_pagination(query)
        rows = [_obj_dict(v) for v in self.policy.list_versions(actor, params["policy_id"])]
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_policy_simulate(self, params, query, body, actor, ctx, org_id):
        if self.policy is None:
            raise ApiError(404, "not_found", "policy engine not configured")
        version = body.get("version")
        cases = body.get("cases")
        if not isinstance(version, int):
            raise ValidationError("version (int) is required")
        if not isinstance(cases, list) or not cases:
            raise ValidationError("cases (non-empty list) is required")
        if len(cases) > 200:
            raise ValidationError("too many cases (max 200)")
        return 200, _obj_dict(self.policy.test(actor, params["policy_id"], version, cases=cases))

    # --- permissions / governance -------------------------------------------------------------
    def _h_permissions(self, params, query, body, actor, ctx, org_id):
        from ..security.rbac import permission_matrix
        return 200, {"matrix": permission_matrix(), "roles": sorted(permission_matrix().keys())}

    def _h_resources(self, params, query, body, actor, ctx, org_id):
        if self.governance is None:
            return 200, {"available": False, "reason": "governance not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = self._governance_list("list_resources", org_id)
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_tools(self, params, query, body, actor, ctx, org_id):
        if self.governance is None:
            return 200, {"available": False, "reason": "governance not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = self._governance_list("list_tools", org_id)
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _governance_list(self, method: str, org_id: Optional[str]) -> List[dict]:
        store = getattr(self.governance, "store", None)
        for target in (store, self.governance):
            fn = getattr(target, method, None)
            if callable(fn):
                try:
                    return [_obj_dict(x) for x in fn(org_id=org_id)]
                except TypeError:
                    try:
                        return [_obj_dict(x) for x in fn()]
                    except Exception:                                # noqa: BLE001
                        continue
                except Exception:                                    # noqa: BLE001
                    continue
        return []

    # --- egress / DLP -------------------------------------------------------------------------
    def _h_egress_policies(self, params, query, body, actor, ctx, org_id):
        if self.egress is None:
            return 200, {"available": False, "reason": "egress gateway not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = [_obj_dict(p) for p in self.egress.list_policies(org_id=org_id)]
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_egress_findings(self, params, query, body, actor, ctx, org_id):
        if self.egress is None:
            return 200, {"available": False, "reason": "egress gateway not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        since, until = parse_time_range(query, now=self._now())
        rows = self._egress_audit(org_id, since, until)
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _egress_audit(self, org_id, since, until) -> List[dict]:
        store = getattr(self.egress, "store", None)
        for target in (store, self.egress):
            fn = getattr(target, "list_audit", None)
            if callable(fn):
                try:
                    rows = fn(org_id=org_id, limit=1000)
                except TypeError:
                    try:
                        rows = fn(org_id=org_id)
                    except Exception:                                # noqa: BLE001
                        continue
                except Exception:                                    # noqa: BLE001
                    continue
                out = []
                for r in rows:
                    d = _obj_dict(r)
                    if not isinstance(d, dict):
                        continue
                    ts = d.get("ts") or d.get("timestamp")
                    if since is not None and isinstance(ts, (int, float)) and ts < since:
                        continue
                    if until is not None and isinstance(ts, (int, float)) and ts > until:
                        continue
                    out.append(d)
                return out
        return []

    def _h_egress_metrics(self, params, query, body, actor, ctx, org_id):
        if self.egress is None:
            return 200, {"available": False, "reason": "egress gateway not configured"}
        out = {}
        for name in ("metrics", "health"):
            fn = getattr(self.egress, name, None)
            if callable(fn):
                try:
                    out[name] = fn()
                except Exception:                                    # noqa: BLE001
                    out[name] = {"available": False}
        return 200, out

    # --- anomalies / risk ---------------------------------------------------------------------
    def _h_anomalies(self, params, query, body, actor, ctx, org_id):
        if self.runtime is None:
            return 200, {"available": False, "reason": "runtime monitoring not configured",
                         "items": [], "page": {"total": 0, "offset": 0, "limit": 0, "count": 0,
                                               "has_more": False, "next_offset": None}}
        offset, limit = parse_pagination(query)
        since, until = parse_time_range(query, now=self._now())
        rows = []
        try:
            findings = self.runtime.store.list_findings(org_id=org_id, agent_id=query.get("agent_id"),
                                                        limit=clamp_limit(query.get("limit"),
                                                                          default=1000))
            rows = [_obj_dict(f) for f in findings]
        except Exception:                                            # noqa: BLE001
            rows = []
        cls = query.get("class")
        if cls:
            rows = [r for r in rows if isinstance(r, dict) and str(r.get("drift_class")) == cls]
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_risk(self, params, query, body, actor, ctx, org_id):
        if self.runtime is None:
            return 200, {"available": False, "reason": "runtime monitoring not configured",
                         "items": [], "page": {"total": 0, "offset": 0, "limit": 0, "count": 0,
                                               "has_more": False, "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = []
        try:
            assessments = self.runtime.store.list_assessments(org_id=org_id,
                                                              agent_id=query.get("agent_id"),
                                                              limit=clamp_limit(query.get("limit"),
                                                                                default=1000))
            rows = [_obj_dict(a) for a in assessments]
        except Exception:                                            # noqa: BLE001
            rows = []
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    # --- alerts / incidents -------------------------------------------------------------------
    def _h_alerts(self, params, query, body, actor, ctx, org_id):
        if self.runtime is None:
            return 200, {"available": False, "reason": "runtime monitoring not configured",
                         "items": [], "page": {"total": 0, "offset": 0, "limit": 0, "count": 0,
                                               "has_more": False, "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = []
        try:
            alerts = self.runtime.store.list_alerts(org_id=org_id, state=query.get("state"),
                                                    limit=clamp_limit(query.get("limit"),
                                                                      default=1000))
            rows = [_obj_dict(a) for a in alerts]
        except Exception:                                            # noqa: BLE001
            rows = []
        sev = query.get("severity")
        if sev:
            rows = [r for r in rows if isinstance(r, dict) and str(r.get("severity")) == sev]
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_incidents(self, params, query, body, actor, ctx, org_id):
        if self.response is None:
            return 200, {"available": False, "reason": "response plane not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        since, until = parse_time_range(query, now=self._now())
        rows = [_obj_dict(i) for i in self.response.incidents.list(
            org_id=org_id, status=query.get("status"), agent_id=query.get("agent_id"), since=since,
            limit=clamp_limit(query.get("limit"), default=1000))]
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_incident_detail(self, params, query, body, actor, ctx, org_id):
        if self.response is None:
            raise ApiError(404, "not_found", "response plane not configured")
        try:
            return 200, self.response.incidents.investigation_view(org_id=org_id,
                                                                   incident_id=params["incident_id"])
        except Exception:                                            # noqa: BLE001
            raise NotFoundError("incident not found")

    def _h_containment(self, params, query, body, actor, ctx, org_id):
        if self.response is None:
            return 200, {"available": False, "reason": "response plane not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = self.response.list_responses(org_id=org_id, incident_id=query.get("incident_id"),
                                            agent_id=query.get("agent_id"),
                                            limit=clamp_limit(query.get("limit"), default=1000))
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    # --- approvals ----------------------------------------------------------------------------
    def _h_approvals(self, params, query, body, actor, ctx, org_id):
        if self.response is None:
            return 200, {"available": False, "reason": "response plane not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = [_obj_dict(a) for a in self.response.approvals.list(
            org_id=org_id, status=query.get("status"), agent_id=query.get("agent_id"),
            limit=clamp_limit(query.get("limit"), default=1000))]
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_approval_decide(self, params, query, body, actor, ctx, org_id):
        if self.response is None:
            raise ApiError(404, "not_found", "response plane not configured")
        approved = body.get("approved")
        if not isinstance(approved, bool):
            raise ValidationError("approved (bool) is required")
        a = self.response.approvals.decide(
            org_id=org_id, approval_id=params["approval_id"], approved=approved,
            decided_by=actor.user_id, reason=body.get("reason", ""), approver_org_id=ctx.org_id,
            approver_is_platform_admin=bool(getattr(actor, "is_platform_admin", False)),
            approver_permissions=sorted(getattr(actor, "permissions", ()) or ()),
            required_permission=P_RESPONSE_APPROVE)
        self.obs.log.emit("admin.approval.decide", actor=actor.user_id, target_type="approval",
                          target_id=params["approval_id"], result="ok",
                          correlation_id=ctx.correlation_id)
        return 200, _obj_dict(a)

    # --- audit --------------------------------------------------------------------------------
    def _h_audit(self, params, query, body, actor, ctx, org_id):
        offset, limit = parse_pagination(query)
        since, until = parse_time_range(query, now=self._now())
        rows = []
        try:
            rows = [_obj_dict(e) for e in self.admin.list_audit(actor, org_id=org_id,
                                                                limit=clamp_limit(query.get("limit"),
                                                                                  default=1000))]
        except Exception:                                            # noqa: BLE001
            rows = []
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_audit_integrity(self, params, query, body, actor, ctx, org_id):
        if self.assurance is None:
            return 200, {"available": False, "reason": "assurance plane not configured"}
        result = self.assurance.verify_audit(org_id=org_id)
        self.obs.record_audit_verification(ok=bool(result.get("ok")))
        return 200, result

    def _h_audit_checkpoints(self, params, query, body, actor, ctx, org_id):
        if self.assurance is None:
            return 200, {"available": False, "reason": "assurance plane not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        cps = self.assurance.store.list_checkpoints(org_id=org_id,
                                                    limit=clamp_limit(query.get("limit"),
                                                                      default=1000))
        rows = [_obj_dict(c) for c in cps]
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    # --- assurance ----------------------------------------------------------------------------
    def _h_recommendations(self, params, query, body, actor, ctx, org_id):
        if self.assurance is None:
            return 200, {"available": False, "reason": "assurance plane not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = self.assurance.list_recommendations(org_id=org_id, status=query.get("status"),
                                                   limit=clamp_limit(query.get("limit"),
                                                                     default=1000))
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_proposals(self, params, query, body, actor, ctx, org_id):
        if self.assurance is None:
            return 200, {"available": False, "reason": "assurance plane not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = [_obj_dict(p) for p in self.assurance.list_proposals(actor, org_id=org_id,
                                                                    status=query.get("status"))]
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_compliance_controls(self, params, query, body, actor, ctx, org_id):
        if self.assurance is None:
            return 200, {"available": False, "reason": "assurance plane not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = self.assurance.list_controls(framework=query.get("framework"))
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_compliance_report(self, params, query, body, actor, ctx, org_id):
        if self.assurance is None:
            return 200, {"available": False, "reason": "assurance plane not configured"}
        return 200, self.assurance.compliance_report(framework=query.get("framework"), org_id=org_id)

    # --- SIEM ---------------------------------------------------------------------------------
    def _h_siem_destinations(self, params, query, body, actor, ctx, org_id):
        if self.assurance is None:
            return 200, {"available": False, "reason": "assurance plane not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = self.assurance.siem.list_destinations()
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_siem_deliveries(self, params, query, body, actor, ctx, org_id):
        if self.assurance is None:
            return 200, {"available": False, "reason": "assurance plane not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = self.assurance.siem.list_deliveries(destination_id=query.get("destination_id"),
                                                   status=query.get("status"),
                                                   limit=clamp_limit(query.get("limit"),
                                                                     default=1000))
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    def _h_correlations(self, params, query, body, actor, ctx, org_id):
        if self.assurance is None:
            return 200, {"available": False, "reason": "assurance plane not configured", "items": [],
                         "page": {"total": 0, "offset": 0, "limit": 0, "count": 0, "has_more": False,
                                  "next_offset": None}}
        offset, limit = parse_pagination(query)
        rows = self.assurance.list_correlations(org_id=org_id,
                                                limit=clamp_limit(query.get("limit"), default=1000))
        page = paginate(rows, offset=offset, limit=limit)
        return 200, page.to_dict(key="items")

    # --- observability ------------------------------------------------------------------------
    def _h_health(self, params, query, body, actor, ctx, org_id):
        planes = self._plane_states()
        out = self.obs.health(planes=planes)
        out["api_version"] = API_VERSION
        out["planes_configured"] = planes
        return 200, out

    def _h_metrics(self, params, query, body, actor, ctx, org_id):
        return 200, {"metrics": self.obs.snapshot(),
                     "instrumented_paths": list(INSTRUMENTED_PATHS)}

    def _h_metrics_prometheus(self, params, query, body, actor, ctx, org_id):
        return 200, self.obs.render_prometheus()

    # --- admin --------------------------------------------------------------------------------
    def _h_admin_integrations(self, params, query, body, actor, ctx, org_id):
        out = {"siem": {"available": self.assurance is not None, "destinations": []}}
        if self.assurance is not None:
            out["siem"]["destinations"] = self.assurance.siem.list_destinations()
        return 200, out

    def _h_admin_retention_apply(self, params, query, body, actor, ctx, org_id):
        out = {}
        if self.runtime is not None:
            out["runtime_purged"] = self.runtime.apply_retention(org_id=org_id)
        else:
            out["runtime_purged"] = None
            out["runtime_available"] = False
        self.obs.log.emit("admin.retention.apply", actor=actor.user_id, result="ok",
                          correlation_id=ctx.correlation_id)
        return 200, out

    def _h_admin_audit(self, params, query, body, actor, ctx, org_id):
        return self._h_audit(params, query, body, actor, ctx, org_id)

    # ------------------------------------------------------------------ OpenAPI
    def openapi(self, *, server_url: str = "https://agentguard.internal") -> dict:
        """Generate an OpenAPI 3.1 document from the route registry (never drifts from the code)."""
        paths: Dict[str, dict] = {}
        for spec in self.registry.all():
            oapi_path = spec.path
            op: Dict[str, Any] = {
                "operationId": f"{spec.method.lower()}_{spec.tag}_{spec.path.strip('/').replace('/', '_').replace('{', '').replace('}', '')}",
                "summary": spec.summary,
                "tags": [spec.tag],
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {"description": "Success",
                            "content": {"application/json": {"schema": {"type": "object"}}}},
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "401": {"$ref": "#/components/responses/Unauthenticated"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                    "429": {"$ref": "#/components/responses/RateLimited"},
                },
            }
            params = []
            for p in spec.params:
                params.append({"name": p, "in": "path", "required": True,
                               "schema": {"type": "string"}})
            for q in spec.query:
                if q in ("limit", "offset"):
                    params.append({"name": q, "in": "query", "required": False,
                                   "schema": {"type": "integer", "minimum": 0}})
                elif q in ("since", "until"):
                    params.append({"name": q, "in": "query", "required": False,
                                   "schema": {"type": "number"}})
                else:
                    params.append({"name": q, "in": "query", "required": False,
                                   "schema": {"type": "string"}})
            if params:
                op["parameters"] = params
            if spec.mutating:
                op["requestBody"] = {"required": False,
                                     "content": {"application/json": {"schema": {"type": "object"}}}}
                if spec.idempotent:
                    op["parameters"] = op.get("parameters", []) + [
                        {"name": "Idempotency-Key", "in": "header", "required": False,
                         "schema": {"type": "string"}}]
            if spec.high_impact:
                op["description"] = ("HIGH IMPACT: requires explicit confirmation in the CLI and "
                                     "an explicit permission; audited.")
            paths.setdefault(oapi_path, {})[spec.method.lower()] = op
        return {
            "openapi": "3.1.0",
            "info": {"title": "AgentGuard Management API", "version": API_VERSION,
                     "description": ("Versioned management API for the AgentGuard enterprise console, "
                                     "CLI and SDKs. Server-side authorization and tenant isolation "
                                     "are enforced on every route; frontend visibility is never an "
                                     "authorization mechanism.")},
            "servers": [{"url": server_url}],
            "components": {
                "securitySchemes": {
                    "bearerAuth": {"type": "http", "scheme": "bearer"},
                    "cookieAuth": {"type": "apiKey", "in": "cookie", "name": "ag_session"},
                },
                "schemas": {
                    "Error": {"type": "object", "properties": {
                        "error": {"type": "object", "properties": {
                            "code": {"type": "string"}, "message": {"type": "string"},
                            "correlation_id": {"type": "string"}}}}},
                    "Page": {"type": "object", "properties": {
                        "total": {"type": "integer"}, "offset": {"type": "integer"},
                        "limit": {"type": "integer"}, "count": {"type": "integer"},
                        "has_more": {"type": "boolean"}, "next_offset": {"type": ["integer", "null"]}}},
                },
                "responses": {
                    "BadRequest": {"description": "Validation error",
                                   "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    "Unauthenticated": {"description": "Not authenticated",
                                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    "Forbidden": {"description": "Not authorized / cross-tenant denied",
                                  "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    "NotFound": {"description": "Not found",
                                 "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    "RateLimited": {"description": "Rate limit exceeded",
                                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                },
            },
            "paths": paths,
        }


def _body_size(body: Any) -> int:
    import json
    try:
        return len(json.dumps(body, default=str).encode("utf-8"))
    except Exception:                                                # noqa: BLE001
        return 0


def _new_correlation_id() -> str:
    from ..security.ids import new_id
    return new_id("cor")


#: Route table: (method, path) -> bound handler. Kept beside the registry so a missing handler is a
#: test failure (see tests/test_phase8_platform.py::test_every_route_has_a_handler).
_HANDLERS: Dict[Tuple[str, str], Callable] = {
    ("GET", "/v2/session"): ManagementApi._h_session,
    ("GET", "/v2/me/permissions"): ManagementApi._h_me_permissions,
    ("GET", "/v2/agents"): ManagementApi._h_agents_list,
    ("GET", "/v2/agents/{agent_id}"): ManagementApi._h_agent_detail,
    ("GET", "/v2/agents/{agent_id}/health"): ManagementApi._h_agent_health,
    ("GET", "/v2/agents/{agent_id}/activity"): ManagementApi._h_agent_activity,
    ("POST", "/v2/agents/{agent_id}/suspend"): ManagementApi._h_agent_suspend,
    ("GET", "/v2/policies"): ManagementApi._h_policies_list,
    ("GET", "/v2/policies/{policy_id}"): ManagementApi._h_policy_detail,
    ("GET", "/v2/policies/{policy_id}/versions"): ManagementApi._h_policy_versions,
    ("POST", "/v2/policies/{policy_id}/simulate"): ManagementApi._h_policy_simulate,
    ("GET", "/v2/permissions"): ManagementApi._h_permissions,
    ("GET", "/v2/resources"): ManagementApi._h_resources,
    ("GET", "/v2/tools"): ManagementApi._h_tools,
    ("GET", "/v2/egress/policies"): ManagementApi._h_egress_policies,
    ("GET", "/v2/egress/findings"): ManagementApi._h_egress_findings,
    ("GET", "/v2/egress/metrics"): ManagementApi._h_egress_metrics,
    ("GET", "/v2/anomalies"): ManagementApi._h_anomalies,
    ("GET", "/v2/risk"): ManagementApi._h_risk,
    ("GET", "/v2/alerts"): ManagementApi._h_alerts,
    ("GET", "/v2/incidents"): ManagementApi._h_incidents,
    ("GET", "/v2/incidents/{incident_id}"): ManagementApi._h_incident_detail,
    ("GET", "/v2/containment"): ManagementApi._h_containment,
    ("GET", "/v2/approvals"): ManagementApi._h_approvals,
    ("POST", "/v2/approvals/{approval_id}/decide"): ManagementApi._h_approval_decide,
    ("GET", "/v2/audit"): ManagementApi._h_audit,
    ("GET", "/v2/audit/integrity"): ManagementApi._h_audit_integrity,
    ("GET", "/v2/audit/checkpoints"): ManagementApi._h_audit_checkpoints,
    ("GET", "/v2/recommendations"): ManagementApi._h_recommendations,
    ("GET", "/v2/proposals"): ManagementApi._h_proposals,
    ("GET", "/v2/compliance/controls"): ManagementApi._h_compliance_controls,
    ("GET", "/v2/compliance/report"): ManagementApi._h_compliance_report,
    ("GET", "/v2/siem/destinations"): ManagementApi._h_siem_destinations,
    ("GET", "/v2/siem/deliveries"): ManagementApi._h_siem_deliveries,
    ("GET", "/v2/correlations"): ManagementApi._h_correlations,
    ("GET", "/v2/health"): ManagementApi._h_health,
    ("GET", "/v2/metrics"): ManagementApi._h_metrics,
    ("GET", "/v2/metrics/prometheus"): ManagementApi._h_metrics_prometheus,
    ("GET", "/v2/admin/integrations"): ManagementApi._h_admin_integrations,
    ("POST", "/v2/admin/retention/apply"): ManagementApi._h_admin_retention_apply,
    ("GET", "/v2/admin/audit"): ManagementApi._h_admin_audit,
}


def handle_management(api: ManagementApi, method: str, path: str, query: dict, body: dict,
                      headers: dict, cookies: dict) -> Tuple[int, object, list]:
    """Entry point the HTTP server calls for any ``/v2/*`` request."""
    return api.handle(method, path, query, body, headers, cookies)
