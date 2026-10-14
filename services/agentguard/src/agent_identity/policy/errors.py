"""Step 10 policy-plane errors.

All are subclasses of the existing :class:`IdentityError` so the HTTP transport's error mapping
keeps working. Messages never contain secrets or policy source.
"""
from __future__ import annotations

from ..core.errors import IdentityError


class PolicyError(IdentityError):
    """Base class for policy-plane failures."""

    code = "policy_error"


class PolicyNotFoundError(PolicyError):
    code = "policy_not_found"


class PolicyValidationError(PolicyError):
    """A policy failed validation (malformed Rego, forbidden builtins, missing entrypoint)."""

    code = "policy_validation_error"


class PolicyConflictError(PolicyError):
    code = "policy_conflict"


class PolicyEngineUnavailableError(PolicyError):
    """The policy engine (OPA) could not be reached or exceeded its resource limits.

    Callers MUST treat this as INDETERMINATE -> deny (fail closed). It is never an allow.
    """

    code = "policy_engine_unavailable"


class JitGrantError(PolicyError):
    code = "jit_grant_error"


class ApprovalError(PolicyError):
    code = "approval_error"
