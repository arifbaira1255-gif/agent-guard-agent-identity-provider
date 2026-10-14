"""Phase 6 response-plane error hierarchy.

Aligned with ``core/errors.py`` so the existing HTTP error mapper
(``api/enterprise_http.py:_err``) turns these into stable status codes without any change. Messages
never contain secrets, payloads or raw prompts.
"""
from __future__ import annotations

from ..core.errors import IdentityError


class ResponsePlaneError(IdentityError):
    code = "response_plane_error"


class LoopDetectionError(ResponsePlaneError):
    code = "loop_detection_error"


class BudgetExceededError(ResponsePlaneError):
    """A server-side execution budget was exhausted.

    This is an ENFORCEMENT outcome produced by the budget boundary, not a monitoring observation --
    it is raised at the point where an action would otherwise be admitted.
    """

    code = "budget_exceeded"


class EmergencyStopError(ResponsePlaneError):
    """An emergency stop is in force for the agent/task, so the operation is refused."""

    code = "emergency_stop"


class ApprovalError(ResponsePlaneError):
    code = "approval_error"


class ApprovalMismatchError(ApprovalError):
    """An approval was presented for an operation it does not authorize (fingerprint mismatch).

    A modified request MUST NOT reuse an approval granted for a different action, resource, tenant
    or parameter set -- this error is the enforcement of that rule.
    """

    code = "approval_mismatch"


class IncidentError(ResponsePlaneError):
    code = "incident_error"


class ContainmentError(ResponsePlaneError):
    code = "containment_error"


class ResponseOrchestrationError(ResponsePlaneError):
    code = "response_orchestration_error"


class EvidenceError(ResponsePlaneError):
    code = "evidence_error"


class TenantBoundaryError(ResponsePlaneError):
    """A cross-tenant read/write was attempted. Always a hard failure (never a partial write)."""

    code = "tenant_boundary_violation"
