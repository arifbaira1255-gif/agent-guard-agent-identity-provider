"""Step 11 governance-plane errors.

They are aligned with the EXISTING core hierarchy so the transports' error mapping keeps working
(a registry validation error is a ``ValidationError`` -> HTTP 400; a missing resource/tool is a
``NotFoundError`` -> 404; a governance deny is a ``ForbiddenError`` -> 403). They additionally
subclass :class:`GovernanceError` so a caller can catch the whole governance plane at once.

Messages are stable reason codes and NEVER contain secrets, payloads or credentials.
"""
from __future__ import annotations

from ..core.errors import ForbiddenError, IdentityError, NotFoundError, ValidationError


class GovernanceError(IdentityError):
    """Base class for governance-plane failures."""

    code = "governance_error"


class UnknownResourceError(ForbiddenError, GovernanceError):
    """The target resource is not registered/classified — the guard fails closed."""

    code = "unknown_resource"


class ResourceNotFoundError(NotFoundError, GovernanceError):
    code = "resource_not_found"


class RegistryValidationError(ValidationError, GovernanceError):
    """A resource/tool registration was rejected (malformed, wildcard, or unsafe metadata)."""

    code = "registry_validation_error"


class ToolNotRegisteredError(NotFoundError, GovernanceError):
    code = "tool_not_registered"


class OperationNotPermittedError(ForbiddenError, GovernanceError):
    """The resource is governed but does not permit the requested operation (least privilege)."""

    code = "operation_not_permitted"
