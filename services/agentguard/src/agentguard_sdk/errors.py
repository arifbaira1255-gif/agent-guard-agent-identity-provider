"""AgentGuard SDK error hierarchy.

Every error carries a stable machine-readable ``code`` and an optional ``correlation_id`` so a
failure can be tied back to the server-side audit trail. Errors NEVER carry credentials, tokens,
private keys or other secrets \u2014 only ids, codes and short messages.
"""
from __future__ import annotations

from typing import Optional


class AgentGuardError(Exception):
    code = "agentguard_error"
    retryable = False

    def __init__(self, message: str = "", *, code: Optional[str] = None,
                 correlation_id: Optional[str] = None, status: Optional[int] = None):
        super().__init__(message or self.code)
        if code:
            self.code = code
        self.message = message or self.code
        self.correlation_id = correlation_id
        self.status = status

    def __str__(self) -> str:                       # never include secrets in the message
        return self.message

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, status={self.status!r})"


class ConfigurationError(AgentGuardError):
    code = "configuration_error"


class ValidationError(AgentGuardError):
    code = "validation_error"


class TransportError(AgentGuardError):
    """Network-level failure (DNS, connection refused, TLS failure, truncated body)."""
    code = "transport_error"
    retryable = True


class TimeoutError(TransportError):                 # noqa: A001 - intentional SDK name
    code = "timeout"


class CancelledError(AgentGuardError):
    code = "cancelled"


class AuthenticationError(AgentGuardError):
    code = "authentication_failed"


class CredentialExpiredError(AuthenticationError):
    code = "credential_expired"


class CredentialRevokedError(AuthenticationError):
    code = "credential_revoked"


class AuthorizationError(AgentGuardError):
    """Authenticated but the authorization decision was DENY (or could not be verified)."""
    code = "forbidden"


class PolicyUnavailableError(AuthorizationError):
    """The policy decision point could not be reached \u2014 the SDK fails CLOSED (deny)."""
    code = "policy_unavailable"


class NotFoundError(AgentGuardError):
    code = "not_found"


class ConflictError(AgentGuardError):
    code = "conflict"


class RateLimitedError(AgentGuardError):
    code = "rate_limited"
    retryable = True


class ServerError(AgentGuardError):
    code = "server_error"
    retryable = True
