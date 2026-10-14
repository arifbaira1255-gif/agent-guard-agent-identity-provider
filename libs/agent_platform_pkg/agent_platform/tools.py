"""Tools: declaration, validation and the authorization gate every protected call passes through.

THE ONE RULE
------------
An agent may *ask* for anything; nothing happens until the gate allows it.  ``ToolGuard.invoke`` is
the only path from a model's tool-call request to a real side effect, and it runs, in order:

1. registry lookup            -> unknown tool is refused (never "helpfully" guessed)
2. allowlist check            -> a tool outside the deployment's allowlist is refused
3. schema validation          -> malformed arguments are refused with the exact problems
4. budget charge              -> a call past the tool-call ceiling is refused before it runs
5. authorization gate         -> the authoritative decision (AgentGuard in production)
6. the handler                -> only now
7. an audit event             -> allow and deny are both recorded

The gate defaults to DENY-ALL.  A deployment that wants calls to happen must wire a real gate in,
which means a misconfigured platform refuses work instead of quietly performing it.
"""
from __future__ import annotations

import inspect
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from .errors import InvalidToolArguments, UnknownTool
from .types import ToolCall
from .validation import SchemaError, check_schema, redact, truncate, validate_against_schema

__all__ = [
    "ToolSpec", "ToolResult", "ToolRegistry", "ToolGuard",
    "AuthorizationGate", "DenyAllGate", "AllowAllGate", "CallableGate", "ContractGate",
    "AUTHORIZED", "DENIED",
]

#: Event names emitted to the platform's event sink (namespaced for the audit chain).
AUTHORIZED = "platform.tool.authorized"
DENIED = "platform.tool.denied"

_MAX_RESULT_CHARS = 16_384


@dataclass
class ToolResult:
    """The structured outcome of one tool invocation (success or a typed refusal)."""

    name: str
    ok: bool
    content: str = ""
    error: Optional[str] = None
    error_code: Optional[str] = None
    duration_ms: float = 0.0
    denied: bool = False
    decision: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        out: Dict[str, Any] = {"name": self.name, "ok": self.ok, "content": self.content,
                              "duration_ms": self.duration_ms, "denied": self.denied}
        if self.error is not None:
            out["error"] = self.error
        if self.error_code is not None:
            out["error_code"] = self.error_code
        if self.decision is not None:
            out["decision"] = self.decision
        if self.metadata:
            out["metadata"] = self.metadata
        return out

    def as_model_content(self) -> str:
        """Render for the model's next turn: bounded, and never carrying a secret."""
        if self.ok:
            return truncate(self.content, _MAX_RESULT_CHARS)
        payload = {"error": self.error or "tool failed", "error_code": self.error_code,
                   "denied": self.denied}
        return truncate(json.dumps(redact(payload), sort_keys=True), _MAX_RESULT_CHARS)


@dataclass
class ToolSpec:
    """A tool's declaration.  ``protected`` marks a call that touches a real external resource.

    A protected tool is *always* gated.  An unprotected tool is still schema-validated and budgeted,
    but is not required to consult the authorization gate -- used for pure computation helpers where
    requiring a policy decision would add latency without adding safety.
    """

    name: str
    description: str
    parameters: Dict[str, Any]
    handler: Callable[..., Any]
    protected: bool = True
    action: Optional[str] = None
    resource_arg: Optional[str] = None
    requires_sandbox: bool = False
    timeout_s: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise SchemaError("tool name must be a non-empty string")
        check_schema(self.parameters or {}, where=f"tool {self.name!r} parameters")
        if not callable(self.handler):
            raise SchemaError(f"tool {self.name!r} handler must be callable")

    def openai_schema(self) -> Dict[str, Any]:
        return {"name": self.name, "description": self.description,
                "parameters": self.parameters or {"type": "object", "properties": {}}}

    def resolve_resource(self, arguments: Mapping[str, Any]) -> str:
        """The governed resource target: taken from the declaration, never from the model's prose."""
        key = self.resource_arg
        if key and isinstance(arguments, Mapping) and arguments.get(key) is not None:
            return str(arguments[key])
        for candidate in ("path", "url", "host", "target", "resource", "name", "command"):
            if isinstance(arguments, Mapping) and arguments.get(candidate) is not None:
                return str(arguments[candidate])
        return "unspecified"


class ToolRegistry:
    """A bounded, name-keyed set of tool declarations."""

    def __init__(self, *, max_tools: int = 128) -> None:
        self._tools: Dict[str, ToolSpec] = {}
        self.max_tools = int(max_tools)

    def register(self, spec: ToolSpec) -> ToolSpec:
        if spec.name in self._tools:
            raise SchemaError(f"tool {spec.name!r} is already registered")
        if len(self._tools) >= self.max_tools:
            raise SchemaError(f"tool registry is full ({self.max_tools})")
        self._tools[spec.name] = spec
        return spec

    def tool(self, name: str, description: str, *, parameters: Optional[Dict[str, Any]] = None,
             protected: bool = True, action: Optional[str] = None,
             resource_arg: Optional[str] = None, requires_sandbox: bool = False,
             timeout_s: Optional[float] = None, **metadata: Any):
        """Decorator form: ``@registry.tool("read_file", "...", parameters={...})``."""

        def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.register(ToolSpec(name=name, description=description,
                                   parameters=parameters or {"type": "object", "properties": {}},
                                   handler=fn, protected=protected, action=action or name,
                                   resource_arg=resource_arg, requires_sandbox=requires_sandbox,
                                   timeout_s=timeout_s, metadata=dict(metadata)))
            return fn

        return decorate

    def get(self, name: str) -> ToolSpec:
        spec = self._tools.get(name)
        if spec is None:
            raise UnknownTool(f"unknown tool {name!r}", field="name")
        return spec

    def has(self, name: str) -> bool:
        return name in self._tools

    def names(self) -> List[str]:
        return sorted(self._tools)

    def all(self) -> List[ToolSpec]:
        return [self._tools[name] for name in self.names()]

    def openai_schemas(self, *, allowlist: Sequence[str] = ()) -> List[Dict[str, Any]]:
        """The tool list handed to a model: only tools the deployment allows it to see at all."""
        allowed = set(allowlist)
        return [spec.openai_schema() for spec in self.all()
                if not allowed or spec.name in allowed]

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: object) -> bool:
        return name in self._tools


# ---------------------------------------------------------------------------------------------
# Authorization gates
# ---------------------------------------------------------------------------------------------
class AuthorizationGate:
    """Decides whether a protected operation may run.

    ``authorize`` MUST fail closed: raise on uncertainty rather than returning allowed.  The return
    value is a mapping carrying at least ``{"allowed": bool, "reason": str}``.
    """

    def authorize(self, *, action: str, resource: str, tool: str,
                  context: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        raise NotImplementedError

    @property
    def name(self) -> str:
        return type(self).__name__


class DenyAllGate(AuthorizationGate):
    """The default: refuse every protected call.  Safe, and impossible to mistake for a policy."""

    def authorize(self, *, action: str, resource: str, tool: str,
                  context: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        return {"allowed": False, "reason": "no_authorization_gate_configured",
                "decision": "DENY", "gate": self.name}


class AllowAllGate(AuthorizationGate):
    """Allows everything.  FOR TESTS AND LOCAL DEMOS ONLY -- the name says so at every call site."""

    def __init__(self, reason: str = "allow_all_gate_test_only") -> None:
        self.reason = reason

    def authorize(self, *, action: str, resource: str, tool: str,
                  context: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        return {"allowed": True, "reason": self.reason, "decision": "ALLOW", "gate": self.name}


class CallableGate(AuthorizationGate):
    """Adapts ``fn(action=..., resource=..., tool=..., context=...)`` into a gate.

    The callable's own exceptions become a denial -- an erroring gate must never read as allow.
    """

    def __init__(self, fn: Callable[..., Any], *, name: str = "callable") -> None:
        if not callable(fn):
            raise SchemaError("CallableGate requires a callable")
        self._fn = fn
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def authorize(self, *, action: str, resource: str, tool: str,
                  context: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        try:
            raw = self._fn(action=action, resource=resource, tool=tool,
                           context=dict(context or {}))
        except Exception as exc:  # noqa: BLE001 - fail closed
            return {"allowed": False, "reason": f"gate_error:{type(exc).__name__}",
                    "decision": "INDETERMINATE", "gate": self.name}
        if isinstance(raw, Mapping):
            return {"allowed": bool(raw.get("allowed")), "reason": str(raw.get("reason") or ""),
                    "decision": str(raw.get("decision")
                                    or ("ALLOW" if raw.get("allowed") else "DENY")),
                    "gate": self.name, **dict(raw)}
        return {"allowed": bool(raw), "reason": "" if raw else "denied",
                "decision": "ALLOW" if raw else "DENY", "gate": self.name}


class ContractGate(AuthorizationGate):
    """Reuses the existing integration contract's authorizer (no re-implementation of the seam).

    The contract already defines the versioned request/decision models and a fail-closed HTTP PDP
    against AgentGuard's ``POST /v1/authorize``.  This adapter lets the platform benefit from that
    work instead of growing a second, divergent authorization path.
    """

    def __init__(self, authorizer: Any) -> None:
        for required in ("authorize_operation", "audit"):
            if not hasattr(authorizer, required):
                raise SchemaError(f"ContractGate requires an authorizer exposing {required}()")
        self._authorizer = authorizer

    def authorize(self, *, action: str, resource: str, tool: str,
                  context: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        try:
            decision = self._authorizer.authorize_operation(
                tool, args={"path": resource, "url": resource, "resource": resource},
                requested_capabilities=(tool,))
        except Exception as exc:  # noqa: BLE001 - fail closed
            return {"allowed": False, "reason": f"authorizer_error:{type(exc).__name__}",
                    "decision": "INDETERMINATE", "gate": self.name}
        allowed = bool(getattr(decision, "allowed", False))
        return {"allowed": allowed,
                "reason": str(getattr(decision, "reason", "") or ""),
                "decision": str(getattr(getattr(decision, "decision", None), "value", "")
                                or ("ALLOW" if allowed else "DENY")),
                "policy": getattr(decision, "policy", None),
                "correlation_id": getattr(decision, "correlation_id", None),
                "gate": self.name}


# ---------------------------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------------------------
class ToolGuard:
    """The single path from a model's tool request to a real side effect."""

    def __init__(self, registry: ToolRegistry, *, gate: Optional[AuthorizationGate] = None,
                 allowlist: Sequence[str] = (), charge: Optional[Callable[[], None]] = None,
                 on_event: Optional[Callable[..., None]] = None,
                 tracer: Any = None, clock: Callable[[], float] = time.monotonic) -> None:
        self.registry = registry
        self.gate = gate or DenyAllGate()
        self.allowlist = tuple(allowlist)
        self._charge = charge
        self._on_event = on_event
        self.tracer = tracer
        self._clock = clock
        self.audit: List[Dict[str, Any]] = []

    # -- helpers -----------------------------------------------------------------------------
    def _record(self, **fields: Any) -> None:
        self.audit.append(redact(fields))
        if len(self.audit) > 2000:
            del self.audit[:500]

    def _emit(self, event_type: str, *, tool: str, action: str, resource: str,
              outcome: str, reason: str = "", correlation_id: Optional[str] = None,
              extra: Optional[Mapping[str, Any]] = None) -> None:
        if self._on_event is None:
            return
        try:
            self._on_event(event_type=event_type, outcome=outcome, tool=tool, action=action,
                           resource=resource, reason=reason, correlation_id=correlation_id,
                           metadata=dict(extra or {}))
        except Exception:  # noqa: BLE001 - reporting must never break enforcement
            pass

    def _is_visible(self, name: str) -> bool:
        return not self.allowlist or name in self.allowlist

    # -- invocation --------------------------------------------------------------------------
    def invoke(self, call: ToolCall, *, correlation_id: Optional[str] = None,
               agent_id: Optional[str] = None,
               context: Optional[Mapping[str, Any]] = None) -> ToolResult:
        """Run ``call`` through validation, budgeting and authorization, then the handler."""
        started = self._clock()
        name = (call.name or "").strip()

        # 1. visibility / registration
        if not self._is_visible(name):
            result = ToolResult(name=name, ok=False, denied=True,
                                error=f"tool {name!r} is not in this deployment's allowlist",
                                error_code="not_allowed",
                                duration_ms=(self._clock() - started) * 1000.0)
            self._record(tool=name, action=name, resource="unspecified", outcome="denied",
                         reason="not_allowed", correlation_id=correlation_id)
            self._emit(DENIED, tool=name, action=name, resource="unspecified", outcome="denied",
                       reason="not_allowed", correlation_id=correlation_id)
            return result
        try:
            spec = self.registry.get(name)
        except UnknownTool as exc:
            result = ToolResult(name=name, ok=False, denied=True, error=str(exc),
                                error_code="unknown_tool",
                                duration_ms=(self._clock() - started) * 1000.0)
            self._record(tool=name, action=name, resource="unspecified", outcome="denied",
                         reason="unknown_tool", correlation_id=correlation_id)
            self._emit(DENIED, tool=name, action=name, resource="unspecified", outcome="denied",
                       reason="unknown_tool", correlation_id=correlation_id)
            return result

        arguments = dict(call.arguments or {})
        action = spec.action or spec.name
        resource = spec.resolve_resource(arguments)
        span = None
        if self.tracer is not None:
            span = self.tracer.span("tool.invoke", tool=name, action=action, resource=resource,
                                    protected=spec.protected)

        # 2. schema validation (refuse, and tell the model exactly what was wrong)
        problems = validate_against_schema(arguments, spec.parameters or {"type": "object"})
        if problems:
            if call.raw_arguments:
                problems.append(f"raw arguments received: {truncate(call.raw_arguments, 512)}")
            result = ToolResult(name=name, ok=False, error="invalid tool arguments",
                                error_code="invalid_tool_arguments",
                                metadata={"problems": problems},
                                duration_ms=(self._clock() - started) * 1000.0)
            self._record(tool=name, action=action, resource=resource, outcome="invalid",
                         reason="invalid_tool_arguments", problems=problems,
                         correlation_id=correlation_id)
            if span is not None:
                span.finish(error="invalid_tool_arguments")
            return result

        # 3. budget (before the side effect, not after)
        if self._charge is not None:
            try:
                self._charge()
            except Exception as exc:  # noqa: BLE001 - a budget refusal is a normal outcome
                result = ToolResult(name=name, ok=False, error=str(exc),
                                    error_code=getattr(exc, "code", "budget_exceeded"),
                                    metadata={"budget_kind": getattr(exc, "kind", None)},
                                    duration_ms=(self._clock() - started) * 1000.0)
                self._record(tool=name, action=action, resource=resource, outcome="budget",
                             reason=getattr(exc, "kind", None) or "budget_exceeded",
                             correlation_id=correlation_id)
                if span is not None:
                    span.finish(error="budget_exceeded")
                return result

        # 4. authorization (protected tools only, and it FAILS CLOSED)
        decision: Optional[Dict[str, Any]] = None
        if spec.protected:
            try:
                raw_decision = self.gate.authorize(action=action, resource=resource, tool=name,
                                                   context=dict(context or {}))
                decision = dict(raw_decision) if isinstance(raw_decision, Mapping) else {
                    "allowed": bool(raw_decision)}
            except Exception as exc:  # noqa: BLE001 - a broken gate denies
                decision = {"allowed": False, "reason": f"gate_error:{type(exc).__name__}",
                            "decision": "INDETERMINATE", "gate": self.gate.name}
            if not decision.get("allowed"):
                reason = str(decision.get("reason") or "denied")
                result = ToolResult(name=name, ok=False, denied=True,
                                    error=f"not authorized ({reason})",
                                    error_code="authorization_denied", decision=redact(decision),
                                    duration_ms=(self._clock() - started) * 1000.0)
                self._record(tool=name, action=action, resource=resource, outcome="denied",
                             reason=reason, correlation_id=correlation_id)
                self._emit(DENIED, tool=name, action=action, resource=resource, outcome="denied",
                           reason=reason, correlation_id=correlation_id,
                           extra={"agent_id": agent_id, "decision": decision.get("decision")})
                if span is not None:
                    span.finish(error="authorization_denied", reason=reason)
                return result

        # 5. execute
        try:
            value = self._call_handler(spec, arguments)
        except Exception as exc:  # noqa: BLE001 - a tool failure is data, not a crash
            result = ToolResult(name=name, ok=False, error=f"{type(exc).__name__}: {exc}",
                                error_code=getattr(exc, "code", "tool_error"),
                                duration_ms=(self._clock() - started) * 1000.0)
            self._record(tool=name, action=action, resource=resource, outcome="error",
                         reason=type(exc).__name__, correlation_id=correlation_id)
            if span is not None:
                span.finish(error=type(exc).__name__)
            return result

        content = value if isinstance(value, str) else json.dumps(redact(value), sort_keys=True,
                                                                 default=str)
        result = ToolResult(name=name, ok=True, content=truncate(content),
                            decision=redact(decision) if decision else None,
                            duration_ms=(self._clock() - started) * 1000.0)
        self._record(tool=name, action=action, resource=resource, outcome="ok",
                     correlation_id=correlation_id)
        self._emit(AUTHORIZED, tool=name, action=action, resource=resource, outcome="ok",
                   correlation_id=correlation_id,
                   extra={"agent_id": agent_id, "decision": (decision or {}).get("decision")})
        if span is not None:
            span.finish(bytes=len(content))
        return result

    def _call_handler(self, spec: ToolSpec, arguments: Mapping[str, Any]) -> Any:
        """Call the handler with only the arguments it declares (kwargs-safe, positional-safe)."""
        try:
            signature = inspect.signature(spec.handler)
        except (TypeError, ValueError):  # builtins and partials
            return spec.handler(**dict(arguments))
        accepts_kwargs = any(p.kind is inspect.Parameter.VAR_KEYWORD
                             for p in signature.parameters.values())
        if accepts_kwargs:
            return spec.handler(**dict(arguments))
        allowed = {name for name, p in signature.parameters.items()
                   if p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD,
                                 inspect.Parameter.KEYWORD_ONLY)}
        unknown = sorted(set(arguments) - allowed)
        if unknown:
            raise InvalidToolArguments(
                f"unexpected argument(s) for {spec.name!r}: {unknown}; "
                f"it accepts {sorted(allowed)}")
        return spec.handler(**{k: v for k, v in arguments.items() if k in allowed})

    def summary(self) -> Dict[str, Any]:
        denials = [r for r in self.audit if r.get("outcome") == "denied"]
        return {"tool_calls": len(self.audit), "denials": len(denials),
                "gate": self.gate.name, "allowlist": list(self.allowlist),
                "registered": len(self.registry)}
