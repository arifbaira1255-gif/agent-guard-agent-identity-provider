"""Generic tool-calling guard: authorize BEFORE executing, never execute on DENY.

This is the SDK's answer to "do not execute arbitrary tool calls merely because an SDK method was
invoked". A tool is wrapped so that:
  1. the call is normalized into an authorization request (action ``tool:<name>``);
  2. a policy decision is obtained (fail closed);
  3. the underlying callable runs ONLY on an explicit ALLOW;
  4. the outcome (allow/deny/error) is reported as a security event with a correlation id.

It is framework-agnostic on purpose: any framework that can call a Python function can be guarded.
"""
from __future__ import annotations

import functools
import time
from typing import Any, Callable, Optional

from ..errors import AuthorizationError
from ..models import Decision, ToolCall


class ToolGuardError(AuthorizationError):
    code = "tool_denied"


class GuardedTool:
    """A callable wrapper that enforces authorization around a tool implementation."""

    def __init__(self, guard: "ToolGuard", name: str, fn: Callable[..., Any], *,
                 resource: Optional[str] = None):
        self._guard = guard
        self.name = name
        self._fn = fn
        self._resource = resource
        functools.update_wrapper(self, fn)

    def __call__(self, *args, **kwargs) -> Any:
        return self._guard.execute(self.name, self._fn, args=args, kwargs=kwargs,
                                   resource=self._resource)

    def __repr__(self) -> str:
        return f"GuardedTool(name={self.name!r})"


class ToolGuard:
    def __init__(self, client, *, audience: Optional[str] = None,
                 default_resource: Optional[str] = None):
        self._client = client
        self._audience = audience
        self._default_resource = default_resource

    # ------------------------------------------------------------------ decision
    def authorize_tool(self, tool: str, arguments: Optional[dict] = None, *,
                       resource: Optional[str] = None,
                       correlation_id: Optional[str] = None) -> Decision:
        call = ToolCall(tool=tool, arguments=arguments or {},
                        resource=resource or self._default_resource)
        return self._client.authorization.authorize(
            action=call.action(), resource=call.resource or tool,
            context=call.to_authorization_body()["context"], correlation_id=correlation_id)

    # ------------------------------------------------------------------ execution
    def execute(self, tool: str, fn: Callable[..., Any], *, args=(), kwargs=None,
                resource: Optional[str] = None, correlation_id: Optional[str] = None) -> Any:
        kwargs = kwargs or {}
        started = time.time()
        decision = self.authorize_tool(tool, dict(kwargs), resource=resource,
                                       correlation_id=correlation_id)
        if not decision.allowed:
            self._report("tool.denied", outcome="denied", tool=tool, resource=resource,
                         reason=decision.reason, correlation_id=correlation_id,
                         latency_ms=int((time.time() - started) * 1000))
            raise ToolGuardError(f"tool {tool!r} denied: {decision.reason or 'denied'}")
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:                          # noqa: BLE001 - report then re-raise
            self._report("tool.error", outcome="error", tool=tool, resource=resource,
                         reason=type(exc).__name__, correlation_id=correlation_id,
                         latency_ms=int((time.time() - started) * 1000))
            raise
        self._report("tool.allowed", outcome="ok", tool=tool, resource=resource,
                     reason=decision.reason, correlation_id=correlation_id,
                     latency_ms=int((time.time() - started) * 1000))
        return result

    def guard(self, name: str, fn: Callable[..., Any], *,
              resource: Optional[str] = None) -> GuardedTool:
        """Wrap ``fn`` so every call is authorized first."""
        return GuardedTool(self, name, fn, resource=resource)

    def _report(self, event_type: str, *, outcome: str, tool: str, resource: Optional[str],
                reason: Optional[str], correlation_id: Optional[str], latency_ms: int) -> None:
        try:
            self._client.events.report(event_type, outcome=outcome, action=f"tool:{tool}",
                                       resource=resource, reason=reason,
                                       correlation_id=correlation_id,
                                       metadata={"tool": tool, "latency_ms": latency_ms})
        except Exception:                                # noqa: BLE001 - reporting is best-effort
            pass
