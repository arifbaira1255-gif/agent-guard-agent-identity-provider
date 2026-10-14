"""Structured errors for the agent platform.

Every error carries a stable machine-readable ``code`` so a caller can branch on the failure
without parsing prose, and so the same code appears in the trace, the metrics and the audit event
for one incident.  Budget failures additionally carry ``kind`` so "slow" and "hostile" are
distinguishable.
"""
from __future__ import annotations

from typing import List, Optional

__all__ = [
    "PlatformError",
    "ConfigError",
    "BudgetExceeded",
    "BUDGET_KINDS",
    "ModelError",
    "ProviderUnavailable",
    "ToolError",
    "UnknownTool",
    "InvalidToolArguments",
    "AuthorizationDenied",
    "SandboxUnavailable",
    "RunCancelled",
    "InvalidModelOutput",
]

#: The budget dimensions the platform can exhaust.
BUDGET_KINDS = ("wall_clock", "steps", "tool_calls", "tokens", "cost", "cancelled")


class PlatformError(Exception):
    """Base class for every platform failure."""

    code = "platform_error"

    def __init__(self, message: str = "", *, errors: Optional[List[str]] = None,
                 field: Optional[str] = None) -> None:
        self.message = message or self.code
        self.errors: List[str] = list(errors or [])
        self.field = field
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.errors:
            return f"{self.message}: " + "; ".join(self.errors)
        return self.message

    def to_dict(self) -> dict:
        out = {"code": self.code, "message": self.message}
        if self.field:
            out["field"] = self.field
        if self.errors:
            out["errors"] = list(self.errors)
        return out


class ConfigError(PlatformError):
    """The platform configuration is invalid or unsafe (fails closed)."""

    code = "config_error"


class BudgetExceeded(PlatformError):
    """A run budget was exhausted.  ``kind`` is one of :data:`BUDGET_KINDS`."""

    code = "budget_exceeded"

    def __init__(self, kind: str, message: str = "", *, limit: Optional[float] = None,
                 observed: Optional[float] = None) -> None:
        self.kind = kind if kind in BUDGET_KINDS else "steps"
        self.limit = limit
        self.observed = observed
        super().__init__(message or f"{self.kind} budget exceeded", field=self.kind)


class ModelError(PlatformError):
    """A model provider failed or returned something unusable."""

    code = "model_error"


class ProviderUnavailable(ModelError):
    """No provider could serve the request (all routes failed).  Fails closed, never fabricates."""

    code = "provider_unavailable"


class ToolError(PlatformError):
    """A tool failed while executing (as opposed to refusing to execute)."""

    code = "tool_error"


class UnknownTool(ToolError):
    """The model asked for a tool that is not registered."""

    code = "unknown_tool"


class InvalidToolArguments(ToolError):
    """The model supplied arguments that do not satisfy the tool's declared schema."""

    code = "invalid_tool_arguments"


class AuthorizationDenied(PlatformError):
    """A protected operation was refused by the authorization gate."""

    code = "authorization_denied"

    def __init__(self, message: str = "", *, action: Optional[str] = None,
                 resource: Optional[str] = None, reason: Optional[str] = None) -> None:
        self.action = action
        self.resource = resource
        self.reason = reason
        super().__init__(message or "operation denied by authorization")


class SandboxUnavailable(PlatformError):
    """No usable OS isolation backend; untrusted code is NOT run on the host."""

    code = "sandbox_unavailable"


class RunCancelled(PlatformError):
    """The run was cancelled cooperatively."""

    code = "cancelled"


class InvalidModelOutput(ModelError):
    """The model returned output that cannot be interpreted as text or a tool call."""

    code = "invalid_model_output"
