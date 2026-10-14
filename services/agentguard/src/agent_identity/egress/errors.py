"""Phase 4 egress/DLP errors.

Aligned with the EXISTING core hierarchy so the transports' error mapping keeps working (a
validation error -> HTTP 400; a deny -> 403; a rate limit -> 429). They additionally subclass
:class:`EgressError` so a caller can catch the whole egress plane at once.

Messages are stable reason codes and NEVER contain secrets, payloads or credentials.
"""
from __future__ import annotations

from ..core.errors import ForbiddenError, IdentityError, RateLimitedError, ValidationError


class EgressError(IdentityError):
    """Base class for egress-plane failures."""

    code = "egress_error"


class EgressDeniedError(ForbiddenError, EgressError):
    """The outbound request was denied (policy, SSRF protection, or DLP block)."""

    code = "egress_denied"


class DlpBlockedError(ForbiddenError, EgressError):
    """The outbound payload was blocked by a DLP rule."""

    code = "dlp_blocked"


class EgressValidationError(ValidationError, EgressError):
    """A malformed egress request or policy registration."""

    code = "egress_validation_error"


class RateLimitedEgressError(RateLimitedError, EgressError):
    """The tenant/agent exceeded its configured egress rate limit."""

    code = "egress_rate_limited"
