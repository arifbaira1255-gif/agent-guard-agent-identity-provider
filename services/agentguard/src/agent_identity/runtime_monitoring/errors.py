"""Phase 5 runtime-monitoring error hierarchy.

Aligned with ``core/errors.py`` so the existing HTTP error mapper (``api/enterprise_http.py:_err``)
turns these into stable status codes without any change. Messages never contain secrets, payloads or
raw prompts.
"""
from __future__ import annotations

from ..core.errors import IdentityError


class RuntimeMonitoringError(IdentityError):
    code = "runtime_monitoring_error"


class EventValidationError(RuntimeMonitoringError):
    """A raw event could not be normalized (missing/unknown type, bad tenant, out-of-range field).

    Malformed input is REJECTED at the pipeline boundary -- it is never silently coerced into a
    well-formed event, because a coerced event would be indistinguishable from real telemetry.
    """

    code = "event_validation_error"


class TenantBoundaryError(RuntimeMonitoringError):
    """A cross-tenant write/read was attempted. Always a hard failure (never a partial write)."""

    code = "tenant_boundary_violation"


class ProfileError(RuntimeMonitoringError):
    code = "profile_error"


class DriftError(RuntimeMonitoringError):
    code = "drift_error"


class GraphError(RuntimeMonitoringError):
    code = "graph_error"


class RiskError(RuntimeMonitoringError):
    code = "risk_error"


class AlertError(RuntimeMonitoringError):
    code = "alert_error"


class ResponseActionError(RuntimeMonitoringError):
    """An automated containment/response action was requested but is not permitted or failed.

    Response actions delegate to the EXISTING enforcement mechanisms; this error never means the
    monitoring plane itself enforced anything.
    """

    code = "response_action_error"
