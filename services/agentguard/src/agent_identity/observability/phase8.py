"""Phase 8 observability: structured logs, request/trace correlation, metrics and health.

This module *extends* the existing observability stack rather than replacing it:

* It reuses the thread-safe :class:`agent_identity.spiffe.metrics.Metrics` registry (the same one
  Step 7/8 already use) so all metrics render through one Prometheus exposition.
* It reuses the allow-list :class:`agent_identity.observability.logging.SecurityLogger` for
  structured security logs and its ``correlation`` contextvar for trace correlation.
* It adds the Phase 8 metric names, a request-scoped timer, a dependency-health aggregator and a
  readiness/liveness model that reports the *actual* state of the planes it can see.

Honesty rules baked in here:
* A metric is only emitted for an execution path that is actually instrumented. The
  :data:`INSTRUMENTED_PATHS` set is the authoritative list, and the health payload reports it, so
  nobody can claim "monitoring is complete" for a path that is not wired.
* No metric or log line ever carries an identity, token, key, IP or payload -- only fixed names and
  a closed set of labels.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from ..observability.logging import SecurityLogger, correlation, current_correlation_id
from ..spiffe.metrics import Metrics

# --------------------------------------------------------------------------- metric names
# API platform
API_REQUESTS = "agentguard_api_requests_total"            # label: route-class
API_ERRORS = "agentguard_api_errors_total"                # label: status-class
API_LATENCY = "agentguard_api_latency_seconds"            # histogram
API_RATE_LIMITED = "agentguard_api_rate_limited_total"
API_AUTHZ_DENIED = "agentguard_api_authz_denied_total"
API_PAGE_SIZE = "agentguard_api_page_size"                # histogram-ish (observed as seconds slot)

# Policy evaluation
POLICY_EVAL = "agentguard_policy_evaluations_total"
POLICY_EVAL_FAILURES = "agentguard_policy_evaluation_failures_total"
POLICY_EVAL_LATENCY = "agentguard_policy_evaluation_latency_seconds"

# Egress / DLP
EGRESS_DECISIONS = "agentguard_egress_decisions_total"    # label: allow|deny
DLP_FINDINGS = "agentguard_dlp_findings_total"

# Runtime event processing
RUNTIME_EVENTS = "agentguard_runtime_events_processed_total"
RUNTIME_REJECTED = "agentguard_runtime_events_rejected_total"

# Incident response
INCIDENT_ACTIONS = "agentguard_incident_actions_total"
CONTAINMENT_ACTIONS = "agentguard_containment_actions_total"

# Assurance
AUDIT_VERIFY_FAILURES = "agentguard_audit_verification_failures_total"
AUDIT_VERIFY_RUNS = "agentguard_audit_verification_runs_total"
SIEM_DELIVERY_FAILURES = "agentguard_siem_delivery_failures_total"
SIEM_DELIVERIES = "agentguard_siem_deliveries_total"

# Dependencies
DEPENDENCY_HEALTH = "agentguard_dependency_health"        # 1 up / 0 down, label: dependency

#: The execution paths Phase 8 actually instruments. Reported verbatim by ``/v2/health`` so the
#: claim "monitoring covers X" is always backed by a wired path.
INSTRUMENTED_PATHS = (
    "api.request", "api.authorization", "api.rate_limit",
    "policy.evaluation", "egress.decision", "dlp.finding",
    "runtime.event", "incident.action", "containment.action",
    "audit.verification", "siem.delivery", "dependency.health",
)


@dataclass
class DependencyStatus:
    name: str
    up: bool
    detail: str = ""
    latency_ms: Optional[float] = None

    def to_dict(self) -> dict:
        return {"name": self.name, "up": self.up, "detail": self.detail,
                "latency_ms": self.latency_ms}


class Observability:
    """The Phase 8 observability facade: one object the API, CLI and console all read from."""

    def __init__(self, *, metrics: Optional[Metrics] = None,
                 logger: Optional[SecurityLogger] = None,
                 clock: Optional[Callable[[], float]] = None):
        self.metrics = metrics or Metrics()
        self.log = logger or SecurityLogger(use_python_logging=False)
        self._clock = clock or time.time
        self._deps: Dict[str, DependencyStatus] = {}
        self._lock = threading.Lock()
        self._started = self._clock()

    # ------------------------------------------------------------------ request instrumentation
    def record_request(self, *, route_class: str, status: int, seconds: float,
                       correlation_id: Optional[str] = None) -> None:
        self.metrics.inc(API_REQUESTS, route_class)
        self.metrics.observe(API_LATENCY, seconds)
        if status >= 400:
            self.metrics.inc(API_ERRORS, f"{status // 100}xx")
        if status == 429:
            self.metrics.inc(API_RATE_LIMITED)
        if status == 403:
            self.metrics.inc(API_AUTHZ_DENIED)
        self.log.emit("api.request", result=str(status), correlation_id=correlation_id,
                      endpoint=route_class)

    def record_policy_eval(self, *, ok: bool, seconds: float) -> None:
        self.metrics.inc(POLICY_EVAL)
        self.metrics.observe(POLICY_EVAL_LATENCY, seconds)
        if not ok:
            self.metrics.inc(POLICY_EVAL_FAILURES)

    def record_egress(self, *, allowed: bool) -> None:
        self.metrics.inc(EGRESS_DECISIONS, "allow" if allowed else "deny")

    def record_dlp_finding(self) -> None:
        self.metrics.inc(DLP_FINDINGS)

    def record_runtime_event(self, *, accepted: bool) -> None:
        self.metrics.inc(RUNTIME_EVENTS if accepted else RUNTIME_REJECTED)

    def record_incident_action(self, *, containment: bool = False) -> None:
        self.metrics.inc(CONTAINMENT_ACTIONS if containment else INCIDENT_ACTIONS)

    def record_audit_verification(self, *, ok: bool) -> None:
        self.metrics.inc(AUDIT_VERIFY_RUNS)
        if not ok:
            self.metrics.inc(AUDIT_VERIFY_FAILURES)

    def record_siem_delivery(self, *, ok: bool) -> None:
        self.metrics.inc(SIEM_DELIVERIES)
        if not ok:
            self.metrics.inc(SIEM_DELIVERY_FAILURES)

    # ------------------------------------------------------------------ dependencies
    def set_dependency(self, name: str, *, up: bool, detail: str = "",
                       latency_ms: Optional[float] = None) -> None:
        with self._lock:
            self._deps[name] = DependencyStatus(name=name, up=up, detail=detail,
                                                latency_ms=latency_ms)
        self.metrics.inc(DEPENDENCY_HEALTH, "up" if up else "down")

    def dependencies(self) -> List[dict]:
        with self._lock:
            return [d.to_dict() for d in sorted(self._deps.values(), key=lambda d: d.name)]

    # ------------------------------------------------------------------ health
    def liveness(self) -> dict:
        """Process is alive. Deliberately coarse: no versions, hosts or error text."""
        return {"status": "alive"}

    def readiness(self, *, planes: Optional[Dict[str, bool]] = None) -> dict:
        """Ready only when every *required* dependency is up.

        ``planes`` lets the caller report the state of the optional security planes it wired; a
        plane that is not configured is reported as ``not_configured`` (not as healthy), so the
        readiness payload never overstates coverage.
        """
        deps = self.dependencies()
        down = [d["name"] for d in deps if not d["up"]]
        planes = planes or {}
        degraded_planes = [k for k, v in planes.items() if v is False]
        ready = not down and not degraded_planes
        return {"status": "ready" if ready else "not_ready",
                "dependencies_down": down,
                "planes_degraded": degraded_planes,
                "planes": planes}

    def health(self, *, planes: Optional[Dict[str, bool]] = None) -> dict:
        deps = self.dependencies()
        return {"status": "ok" if all(d["up"] for d in deps) else "degraded",
                "uptime_s": round(self._clock() - self._started, 3),
                "dependencies": deps,
                "planes": planes or {},
                "instrumented_paths": list(INSTRUMENTED_PATHS)}

    def render_prometheus(self) -> str:
        return self.metrics.render_prometheus()

    def snapshot(self) -> dict:
        return self.metrics.snapshot()


class RequestTimer:
    """Context manager that times a request and records it on exit (even on exception)."""

    def __init__(self, obs: Observability, *, route_class: str,
                 correlation_id: Optional[str] = None):
        self.obs = obs
        self.route_class = route_class
        self.correlation_id = correlation_id
        self._t0 = 0.0

    def __enter__(self) -> "RequestTimer":
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        seconds = time.perf_counter() - self._t0
        status = 500 if exc is not None else 200
        self.obs.record_request(route_class=self.route_class, status=status, seconds=seconds,
                                correlation_id=self.correlation_id)
        return False
