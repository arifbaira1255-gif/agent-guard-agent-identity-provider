"""Integrated execution: compile -> validate -> authorize -> run, with a structured result.

This is the orchestration the task asks for.  A real Happy LANG ``.hpy`` artifact is compiled by the
**existing** Happy compiler, its declared capabilities/effects are read from the **existing** IR, the
request is validated, the declared resource requirements are authorized by AgentGuard **before**
anything executes, and the program then runs under Happy's **existing** ``RuntimeContext`` with the
:class:`AgentGuardAuthorizer` installed so every sensitive operation is checked against AgentGuard.

Every outcome is a distinct :class:`ExecutionResult` discriminant -- successful validation,
authorization denial, compilation failure, runtime failure, policy violation, resource-limit
violation, cancellation and timeout -- and a failing execution can never take the caller (or the
security service) down with it.
"""
from __future__ import annotations

import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .authorizer import AgentGuardAuthorizer, _denial_error
from .config import IntegrationConfig
from .errors import ContractError, ValidationError
from .events import EventForwarder, http_event_sink
from .models import (
    ArtifactRef,
    AuthorizationRequest,
    EventType,
    ExecutionLimits,
    ExecutionRequest,
    ExecutionResource,
    ExecutionResult,
    ResultKind,
    SecurityEventOutcome,
    SourceLocation,
)
from .std_guard import install_std_guard, std_guard_installed, uninstall_std_guard
from .validation import canonical_json, sha256_hex

# ---------------------------------------------------------------------------------------------
# Happy LANG error codes -> structured result kinds
# ---------------------------------------------------------------------------------------------
#: ``Rxxxx`` diagnostic codes that represent an authorization/policy failure rather than a bug.
_DENIAL_CODES = frozenset({"R2001", "R2002"})
#: ``Rxxxx`` codes for a violated contract / invariant / rule (a policy violation in the wide sense).
_POLICY_CODES = frozenset({"R1001", "R1002", "R1003", "R1004", "R1005", "R3001"})
#: Marker substrings for the runtime's own timeout / memory guards.
_TIMEOUT_MARKERS = ("timed out", "timeout", "run timeout", "exceeded the time budget")
_MEMORY_MARKERS = ("memory limit", "memory budget", "exceeded the memory")
#: Markers for the integration's own enforced budgets.  Happy's runtime wraps an exception raised
#: inside a program into a ``HappyRuntimeError`` (code ``R0002``), so the *message* is the reliable
#: signal -- matching on it is what makes an output flood report as a resource limit rather than a
#: generic runtime error.  Verified by running a flooding program, not by reading the code.
_OUTPUT_MARKERS = ("output budget", "output limit", "output-size")
_OPERATION_MARKERS = ("operation budget", "operation limit", "tool-call budget")


def _error_code(err: Any) -> Optional[str]:
    return getattr(err, "code", None) or getattr(type(err), "code", None)


def _classify_runtime_error(err: Any) -> Tuple[ResultKind, Optional[str]]:
    """Map a Happy runtime error onto a structured :class:`ResultKind` (never guesses ALLOW)."""
    name = type(err).__name__
    code = _error_code(err)
    message = str(err).lower()
    if name in ("_RunTimeout", "HappyTimeoutError") or code in ("R9001", "R9002"):
        return ResultKind.TIMEOUT, code
    if name == "_RunMemoryLimit" or code == ("R9003",):
        return ResultKind.RESOURCE_LIMIT, code
    if any(marker in message for marker in _MEMORY_MARKERS):
        return ResultKind.RESOURCE_LIMIT, code
    if any(marker in message for marker in _OUTPUT_MARKERS):
        return ResultKind.RESOURCE_LIMIT, code
    if any(marker in message for marker in _OPERATION_MARKERS):
        return ResultKind.RESOURCE_LIMIT, code
    if any(marker in message for marker in _TIMEOUT_MARKERS):
        return ResultKind.TIMEOUT, code
    if name in ("CapabilityDenied", "PermissionDenied") or code in _DENIAL_CODES:
        return ResultKind.AUTHORIZATION_DENIED, code
    if name in ("ContractViolation", "PreconditionViolation", "PostconditionViolation",
                "InvariantViolation", "RuleViolation", "SecretLeakError") or code in _POLICY_CODES:
        return ResultKind.POLICY_VIOLATION, code
    if name in ("CancelledError", "HappyCancelledError"):
        return ResultKind.CANCELLED, code
    return ResultKind.RUNTIME_ERROR, code


@dataclass
class CompiledArtifact:
    """A compiled Happy program plus the metadata the integration needs about it."""

    source: str
    filename: Optional[str]
    ok: bool
    program: Any = None
    module: Any = None
    diagnostics: Tuple[str, ...] = ()
    capabilities: Tuple[str, ...] = ()
    effects: Tuple[str, ...] = ()
    contracts: Tuple[str, ...] = ()
    agents: Tuple[str, ...] = ()

    @property
    def digest(self) -> str:
        return sha256_hex(self.source)


def compile_artifact(source: str, *, filename: Optional[str] = None,
                     optimize: bool = True) -> CompiledArtifact:
    """Compile Happy ``source`` with the project's own pipeline and extract its declarations."""
    from happy.pipeline import compile_source                          # Happy owns this

    compiled = compile_source(source, filename=filename, optimize=optimize)
    module = getattr(compiled, "module", None)
    capabilities: List[str] = []
    for cap in (getattr(module, "capabilities", None) or ()):
        capabilities.extend(getattr(cap, "grants", None) or ())
    capabilities = sorted({str(c) for c in capabilities})
    effects = sorted({str(e) for e in (getattr(module, "effects", None) or ())})
    contracts: List[str] = []
    for rule in (getattr(module, "rules", None) or ()):
        contracts.append(str(getattr(rule, "name", rule)))
    agents = tuple(str(getattr(a, "name", a)) for a in (getattr(module, "agents", None) or ()))
    diagnostics = tuple(str(d) for d in (getattr(compiled, "diagnostics", None) or ()))
    return CompiledArtifact(
        source=source, filename=filename, ok=bool(compiled.ok),
        program=getattr(compiled, "program", None), module=module, diagnostics=diagnostics,
        capabilities=tuple(capabilities), effects=tuple(effects),
        contracts=tuple(contracts), agents=agents)


class IntegratedExecutor:
    """Run a Happy LANG artifact with AgentGuard as the authoritative authorization point."""

    def __init__(
        self,
        config: Optional[IntegrationConfig] = None,
        *,
        authorizer: Optional[AgentGuardAuthorizer] = None,
        forwarder: Optional[EventForwarder] = None,
        isolation_policy: Any = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config or IntegrationConfig.from_env()
        self._clock = clock
        self.forwarder = forwarder
        if self.forwarder is None:
            sink = None
            if self.config.enabled and self.config.emit_events:
                sink = http_event_sink(self.config)
            self.forwarder = EventForwarder(sink, buffer_size=self.config.max_events_buffer,
                                            enabled=self.config.enabled and self.config.emit_events)
        self.authorizer = authorizer
        self.isolation_policy = isolation_policy
        # Close the ``_CHECKER is None`` bypass: while the integration is active every ``happy.std``
        # module points at a deny-by-default checker, so an unlisted operation is refused rather
        # than silently allowed.  ``close()`` restores the previous state.
        self._std_guard_installed = False
        if self.config.enabled and self.config.install_std_guard:
            self._install_std_guard()

    # -- std guard ---------------------------------------------------------------------------
    def _install_std_guard(self) -> None:
        if not std_guard_installed():
            install_std_guard()
        self._std_guard_installed = True

    def close(self) -> None:
        """Restore Happy LANG's previous ``std`` checkers (used when the integration is disabled)."""
        if self._std_guard_installed:
            uninstall_std_guard()
            self._std_guard_installed = False

    # -- checkers ----------------------------------------------------------------------------
    def _make_authorizer(self, artifact: CompiledArtifact,
                         checker: Any = None) -> AgentGuardAuthorizer:
        return AgentGuardAuthorizer(
            self.config, checker=checker,
            forwarder=self.forwarder,
            artifact=ArtifactRef(digest=artifact.digest, entry="main",
                                 filename=artifact.filename,
                                 bytes_size=len(artifact.source.encode("utf-8"))),
            effects=artifact.effects, contracts=artifact.contracts)

    # -- isolation ---------------------------------------------------------------------------
    def _isolation_status(self) -> Optional[Dict[str, Any]]:
        try:                                                # pragma: no cover - depends on import
            from happy.ai.isolation import isolation_status

            return isolation_status(self.isolation_policy)
        except Exception:                                   # noqa: BLE001 - standalone use
            return None

    def _check_isolation(self) -> Optional[ExecutionResult]:
        if not self.config.require_isolation:
            return None
        status = self._isolation_status()
        if status is None:
            return None
        if not status.get("os_isolated"):
            return ExecutionResult(
                result=ResultKind.ISOLATION_UNAVAILABLE, ok=False, request_id="",
                correlation_id="",
                error="no usable OS-level isolation backend and require_isolation is set",
                error_code="isolation_unavailable",
                metadata={"isolation": status})
        return None

    # -- validation --------------------------------------------------------------------------
    @staticmethod
    def validate_request(request: ExecutionRequest) -> Tuple[bool, Tuple[str, ...]]:
        """Validate a structured request.  Returns ``(ok, problems)``; never raises.

        All problems are collected and reported together, so a caller fixes one payload rather than
        discovering them one rejection at a time.
        """
        problems: List[str] = []
        try:
            request.validate()
        except ContractError as exc:
            problems.extend(exc.errors or [str(exc)])
        if not request.requested_capabilities:
            problems.append("requested_capabilities: at least one capability is required")
        if not request.declared_resources:
            problems.append("declared_resources: at least one resource is required")
        seen: set = set()
        unique: List[str] = []
        for problem in problems:
            if problem not in seen:
                seen.add(problem)
                unique.append(problem)
        return (not unique), tuple(unique)

    # -- main entry point --------------------------------------------------------------------
    def execute(
        self,
        request: ExecutionRequest,
        source: str,
        *,
        should_cancel: Optional[Callable[[], bool]] = None,
        install_authorizer: bool = True,
    ) -> ExecutionResult:
        """Execute ``source`` under the request's limits and AgentGuard's authority."""
        started = self._clock()
        correlation_id = request.correlation_id
        request_id = request.request_id

        def finish(result: ResultKind, *, ok: bool = False, output: str = "", error: Optional[str] = None,
                   error_code: Optional[str] = None, decision=None, diagnostics: Sequence[str] = (),
                   source_loc: Optional[SourceLocation] = None,
                   metadata: Optional[Mapping[str, Any]] = None) -> ExecutionResult:
            outcome = ExecutionResult(
                result=result, ok=ok, request_id=request_id, correlation_id=correlation_id,
                output=output, error=error, error_code=error_code, decision=decision,
                source_loc=source_loc, diagnostics=tuple(diagnostics),
                duration_ms=round((self._clock() - started) * 1000, 3), metadata=dict(metadata or {}))
            self._emit_outcome(outcome, request)
            return outcome

        # ---- 1. validate the request (reject malformed / incomplete / out-of-bounds) --------
        ok, problems = self.validate_request(request)
        if not ok:
            return finish(ResultKind.VALIDATION_ERROR, error="invalid execution request",
                          error_code="validation_error", diagnostics=problems,
                          metadata={"problems": list(problems)})

        # ---- 2. isolation gate --------------------------------------------------------------
        isolation_failure = self._check_isolation()
        if isolation_failure is not None:
            isolation_failure = ExecutionResult(
                **{**isolation_failure.__dict__, "request_id": request_id,
                   "correlation_id": correlation_id})
            self._emit_outcome(isolation_failure, request)
            return isolation_failure

        # ---- 3. cancellation before doing any work ------------------------------------------
        if should_cancel is not None and should_cancel():
            return finish(ResultKind.CANCELLED, error="cancelled before execution",
                          error_code="cancelled")

        # ---- 4. compile (Happy's own compiler) ----------------------------------------------
        try:
            artifact = compile_artifact(source, filename=request.artifact.filename)
        except RecursionError:
            return finish(ResultKind.COMPILE_ERROR, error="program is too deeply nested to compile",
                          error_code="recursion_error")
        except Exception as exc:                                # noqa: BLE001 - never crash the caller
            return finish(ResultKind.COMPILE_ERROR, error=f"{type(exc).__name__}: {exc}",
                          error_code="compile_exception")
        if not artifact.ok:
            return finish(ResultKind.COMPILE_ERROR, error="compilation failed",
                          error_code="compile_error", diagnostics=artifact.diagnostics,
                          metadata={"capabilities": list(artifact.capabilities)})

        # ---- 5. pre-authorize the DECLARED resource requirements ----------------------------
        # A declaration is a claim: AgentGuard decides, and a denial stops the run before any
        # user code is executed.
        if self.config.enabled and self.config.mode != "off":
            auth = self.authorizer or self._make_authorizer(artifact)
            denied = self._pre_authorize(auth, artifact, request)
            if denied is not None:
                return finish(ResultKind.AUTHORIZATION_DENIED, error=denied[0],
                              error_code="authorization_denied", decision=denied[1],
                              metadata={"stage": "pre_authorization"})

        # ---- 6. run under Happy's RuntimeContext with the authorizer installed --------------
        # Belt and braces: even if the executor was built before the integration was enabled, the
        # guard is in place before any user code runs.
        if self.config.enabled and self.config.install_std_guard and not std_guard_installed():
            self._install_std_guard()
        try:
            from happy.runtime import RuntimeContext
        except Exception as exc:                                # noqa: BLE001 - Happy must be present
            return finish(ResultKind.INTEGRATION_ERROR,
                          error=f"Happy runtime unavailable: {exc}",
                          error_code="runtime_import_error")

        checker = getattr(artifact, "module", None)
        runtime_ctx = RuntimeContext(
            filename=request.artifact.filename, source=source, module=artifact.module,
            sourcemap=getattr(artifact.program, "sourcemap", None),
            timeout=request.limits.timeout_s, max_memory_mb=request.limits.max_memory_mb)
        used_authorizer: Optional[AgentGuardAuthorizer] = None
        if install_authorizer:
            used_authorizer = self.authorizer or self._make_authorizer(artifact)
            runtime_ctx.capabilities = used_authorizer          # the pluggable hook
        else:
            used_authorizer = self._make_authorizer(artifact, checker=runtime_ctx.capabilities)

        if should_cancel is not None and should_cancel():
            return finish(ResultKind.CANCELLED, error="cancelled before run", error_code="cancelled")

        try:
            run_result = artifact.program.run(runtime_ctx, entry=request.entry)
        except Exception as exc:                                # noqa: BLE001 - classify, never crash
            kind, code = _classify_runtime_error(exc)
            return finish(kind, error=f"{type(exc).__name__}: {exc}", error_code=code or kind.value,
                          metadata={"stage": "run_exception",
                                    "authorization": _auth_summary(used_authorizer)})

        # ---- 7. interpret the runtime result -----------------------------------------------
        output = _bound_output(getattr(run_result, "output", "") or "",
                               request.limits.max_output_bytes)
        error = getattr(run_result, "error", None)
        if getattr(run_result, "ok", False):
            return finish(ResultKind.OK, ok=True, output=output,
                          metadata={"capabilities": list(artifact.capabilities),
                                    "effects": list(artifact.effects),
                                    "agents": list(artifact.agents),
                                    "authorization": _auth_summary(used_authorizer)})
        kind, code = _classify_runtime_error(error if error is not None else Exception("runtime error"))
        return finish(kind, output=output, error=str(error) if error is not None else "runtime error",
                      error_code=code or kind.value,
                      source_loc=_source_loc(getattr(error, "location", None), artifact),
                      metadata={"stage": "run_result",
                                "authorization": _auth_summary(used_authorizer),
                                "error_output": _bound_output(
                                    getattr(run_result, "error_output", "") or "", 4096)})

    # -- helpers -----------------------------------------------------------------------------
    def _pre_authorize(self, authorizer: AgentGuardAuthorizer, artifact: CompiledArtifact,
                       request: ExecutionRequest) -> Optional[Tuple[str, Any]]:
        """Authorize the declared resource requirements before any user code runs."""
        for resource in request.declared_resources:
            operation = _operation_for(resource)
            try:
                decision = authorizer.authorize_operation(
                    operation, agent=None, loc=None,
                    args={"path": resource.target} if resource.kind in ("file", "path") else None,
                    requested_capabilities=tuple(request.requested_capabilities))
            except Exception as exc:                                # noqa: BLE001 - fail closed
                return (f"authorization unavailable for {resource.target}: {type(exc).__name__}",
                        None)
            if not decision.allowed:
                return (f"declared resource denied by AgentGuard ({decision.decision.value}: "
                        f"{decision.reason})", decision)
        return None

    def _emit_outcome(self, outcome: ExecutionResult, request: ExecutionRequest) -> None:
        try:
            event = outcome.to_security_event(agent_id=request.agent_id,
                                              instance_id=request.instance_id,
                                              org_id=request.org_id)
            self.forwarder.report(event)
        except Exception:                                        # noqa: BLE001 - best effort
            pass

    def flush_events(self) -> int:
        return self.forwarder.flush()

    # -- convenience -------------------------------------------------------------------------
    def execute_source(
        self,
        source: str,
        *,
        agent_id: str = "happy-agent-unknown",
        requested_capabilities: Sequence[str] = ("file_write", ),
        declared_resources: Sequence[ExecutionResource] = (),
        policy_id: Optional[str] = None,
        policy_version: str = "unset",
        limits: Optional[ExecutionLimits] = None,
        filename: Optional[str] = None,
        entry: str = "main",
        **kwargs,
    ) -> ExecutionResult:
        """Build a request from a source string and execute it (used by tests and embedders)."""
        resources = tuple(declared_resources) or (
            ExecutionResource(kind="none", target="unspecified", access="read"), )
        request = ExecutionRequest(
            request_id=f"req_{sha256_hex(source)[:24]}", agent_id=agent_id,
            artifact=ArtifactRef(digest=sha256_hex(source), entry=entry, filename=filename,
                                 bytes_size=len(source.encode("utf-8"))),
            requested_capabilities=tuple(requested_capabilities), declared_resources=resources,
            policy_id=policy_id, policy_version=policy_version,
            limits=limits or ExecutionLimits())
        return self.execute(request, source, **kwargs)


def _auth_summary(authorizer: Optional[AgentGuardAuthorizer]) -> Dict[str, Any]:
    if authorizer is None:
        return {"installed": False}
    return {
        "installed": True,
        "checks": len(authorizer.audit),
        "denials": len(authorizer.denials),
        "remote_checks": sum(1 for r in authorizer.audit if r.asked_remote),
    }


def _operation_for(resource: ExecutionResource) -> str:
    """Map a declared resource kind onto the Happy operation whose capability it needs."""
    mapping = {
        "file": {"read": "read_file", "write": "write_file", "read_write": "write_file",
                 "execute": "read_file"},
        "path": {"read": "read_file", "write": "write_file", "read_write": "write_file",
                 "execute": "read_file"},
        "directory": {"read": "list_dir", "write": "make_dir", "read_write": "make_dir",
                      "execute": "list_dir"},
        "network": {"read": "http_get", "write": "http_post", "read_write": "http_post",
                    "execute": "http_get"},
        "url": {"read": "http_get", "write": "http_post", "read_write": "http_post",
                "execute": "http_get"},
        "process": {"read": "process", "write": "process", "read_write": "process",
                    "execute": "process"},
        "env": {"read": "getenv", "write": "setenv", "read_write": "setenv", "execute": "getenv"},
        "database": {"read": "read_file", "write": "write_file", "read_write": "write_file",
                     "execute": "read_file"},
    }
    per_kind = mapping.get(resource.kind)
    if per_kind is None:
        return "write_file" if resource.access in ("write", "read_write") else "read_file"
    return per_kind.get(resource.access, "read_file")


def _source_loc(location: Any, artifact: CompiledArtifact) -> Optional[SourceLocation]:
    if location is None:
        return None
    if isinstance(location, (tuple, list)) and len(location) >= 2:
        return SourceLocation(file=(location[0] if len(location) >= 3 else artifact.filename),
                              line=location[-2] if len(location) >= 3 else location[0],
                              column=location[-1] if len(location) >= 3 else location[1])
    if hasattr(location, "line"):
        return SourceLocation(file=artifact.filename, line=getattr(location, "line", None),
                              column=getattr(location, "column", None))
    return None


def _bound_output(text: str, max_bytes: int) -> str:
    if text is None:
        return ""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="replace") + "...<truncated>"


class GuardedEgress:
    """Route Happy LANG network operations through AgentGuard's egress gateway.

    ``happy.std.net`` denies by capability but does **not** apply SSRF/DLP policy.  When
    ``route_egress`` is enabled the request is forwarded to AgentGuard's existing
    ``POST /v1/egress/request``, which owns destination policy, address protection and DLP; a
    non-ALLOW answer raises instead of performing the request.
    """

    def __init__(self, config: Optional[IntegrationConfig] = None,
                 *, forwarder: Optional[EventForwarder] = None) -> None:
        self.config = config or IntegrationConfig.from_env()
        self.forwarder = forwarder

    def _post(self, url: str, payload: dict) -> dict:
        import json
        import ssl

        data = canonical_json(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", "happy-agentguard-integration/1.0")
        context = None
        if self.config.base_url.startswith("https://"):
            context = (ssl.create_default_context(cafile=self.config.ca_bundle)
                       if self.config.ca_bundle else ssl.create_default_context())
        with urllib.request.urlopen(request, timeout=self.config.timeout_seconds,
                                   context=context) as response:      # noqa: S310 - configured URL
            return json.loads(response.read(self.config.max_response_bytes).decode("utf-8"))

    def http_get(self, url: str, headers: Optional[Mapping[str, str]] = None,
                 timeout: float = 30.0) -> str:
        return self.request("GET", url, headers=headers, timeout=timeout)

    def http_post(self, url: str, body: str = "", headers: Optional[Mapping[str, str]] = None,
                  timeout: float = 30.0) -> str:
        return self.request("POST", url, body=body, headers=headers, timeout=timeout)

    def request(self, method: str, url: str, *, body: Optional[str] = None,
                headers: Optional[Mapping[str, str]] = None, timeout: float = 30.0) -> str:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            raise _denial_error(
                f"egress denied: unsupported scheme {parsed.scheme!r}", location=None,
                decision=__import__("agentguard_happy_contract.models", fromlist=["Authorization"])
                .AuthorizationDecision.deny("egress_scheme_not_allowed"), suggestion="use http(s)")
        payload = {"url": url, "method": method.upper(), "headers": dict(headers or {}),
                   "body": body, "operation": "net", "context": {"source": "happy-lang"}}
        try:
            result = self._post(self.config.egress_url(), payload)
        except Exception as exc:                                # noqa: BLE001 - fail closed
            raise _denial_error(
                f"egress denied: AgentGuard egress gateway unavailable ({type(exc).__name__})",
                location=None,
                decision=__import__("agentguard_happy_contract.models", fromlist=["Authorization"])
                .AuthorizationDecision.make_indeterminate("egress_unavailable"),
                suggestion="retry when AgentGuard is reachable") from exc
        decision = (result or {}).get("decision") or {}
        if not decision.get("allowed"):
            from .models import AuthorizationDecision

            raise _denial_error(
                f"egress denied by AgentGuard: {decision.get('reason') or 'denied'}", location=None,
                decision=AuthorizationDecision.deny(str(decision.get("reason") or "denied")),
                suggestion="the destination is not permitted by the egress policy")
        return ((result or {}).get("response") or {}).get("body", "") or ""


__all__ = [
    "IntegratedExecutor", "CompiledArtifact", "compile_artifact", "GuardedEgress",
]
