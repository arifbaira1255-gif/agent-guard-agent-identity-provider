"""Secure execution runtime: the control plane for untrusted Happy LANG programs.

LIFECYCLE (exactly the one the task specifies)
----------------------------------------------
``request -> authenticate -> authorize -> validate -> prepare isolation -> execute -> enforce
limits -> collect evidence -> terminate -> cleanup``

Each stage is a separate method and each has a structured failure, so an operator can see *which*
stage refused a run.  The control plane never executes untrusted code itself: it authenticates,
authorizes and validates, then hands the work to a :class:`~agentguard_happy_contract.worker_pool.WorkerPool`
whose workers own the jail.  A worker crash is captured as a failed outcome and cannot take the
control plane (or the AgentGuard security service) down.

WHAT IS ACTUALLY ENFORCED
--------------------------
* **Isolation** -- the program runs inside Happy LANG's own OS jail (docker/podman/bwrap/namespaces).
  If no backend is usable the run is **refused** (``isolation_unavailable``); untrusted code is never
  executed directly on the host.
* **Network** -- deny by default: the jail has an empty network namespace, so an unauthorized
  outbound connection is impossible rather than merely denied.
* **Filesystem / process / secrets** -- the jail's rootfs is read-only and contains no host files;
  capabilities are dropped and ``no_new_privs`` is set.
* **Capabilities** -- a deny-by-default checker is installed into every ``happy.std`` module inside
  the jail, so the ``_CHECKER is None`` bypass is unreachable.
* **Budgets** -- wall-clock (jail timeout + kill-group), output size and operation count are real
  controls; memory/CPU are carried into the jail's own limits.
* **Cancellation** -- a token checked before submission and by the worker; a cancelled run never
  leaves a privileged operation silently running.

HONEST LIMITS
-------------
The isolation guarantees are the *backend's*, and are reported from observed escape probes
(:meth:`isolation_report`), never assumed.  See ``docs/SECURE_RUNTIME.md`` for the platform-specific
limitations -- no claim of "full sandbox security" is made.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .authorizer import AgentGuardAuthorizer
from .config import IntegrationConfig
from .errors import ContractError
from .events import EventForwarder, http_event_sink
from .isolation import (
    IsolationReport,
    JailSpec,
    cleanup_workdir,
    make_world_readable,
    make_workdir,
    probe_isolation,
    run_in_jail,
)
from .limits import CancellationToken, ExecutionBudget, ResourceLimitExceeded
from .models import (
    ArtifactRef,
    ExecutionLimits,
    ExecutionRequest,
    ExecutionResource,
    ExecutionResult,
    ResultKind,
)
from .validation import sha256_hex
from .worker_pool import ExecutionJob, JobOutcome, QueueFull, WorkerPool

__all__ = ["CallerCredential", "SecureExecutionRuntime", "RuntimeEvidence"]

#: Harness file name inside the jail (the work directory is mounted at ``/work``).
_HARNESS = "_jail_harness.py"
_JAIL_WORKDIR = "/work"

#: Harness ``kind`` -> structured result kind.
_KIND_MAP = {
    "ok": ResultKind.OK,
    "compile_error": ResultKind.COMPILE_ERROR,
    "authorization_denied": ResultKind.AUTHORIZATION_DENIED,
    "policy_violation": ResultKind.POLICY_VIOLATION,
    "runtime_error": ResultKind.RUNTIME_ERROR,
    "resource_limit": ResultKind.RESOURCE_LIMIT,
    "timeout": ResultKind.TIMEOUT,
    "cancelled": ResultKind.CANCELLED,
    "isolation_unavailable": ResultKind.ISOLATION_UNAVAILABLE,
    "integration_error": ResultKind.INTEGRATION_ERROR,
}


@dataclass(frozen=True)
class CallerCredential:
    """The caller's credential.  AgentGuard verifies it; the integration never trusts it blindly."""

    token: Optional[str] = None
    proof: Optional[Mapping[str, Any]] = None

    @property
    def present(self) -> bool:
        return bool(self.token) or bool(self.proof)


@dataclass
class RuntimeEvidence:
    """The evidence collected for one execution (auditable, secret-free)."""

    request_id: str
    correlation_id: str
    stage: str
    isolation: Optional[Dict[str, Any]] = None
    budget: Dict[str, Any] = field(default_factory=dict)
    jail: Dict[str, Any] = field(default_factory=dict)
    authorization: Dict[str, Any] = field(default_factory=dict)
    cleanup_ok: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {"request_id": self.request_id, "correlation_id": self.correlation_id,
                "stage": self.stage, "isolation": self.isolation, "budget": self.budget,
                "jail": self.jail, "authorization": self.authorization,
                "cleanup_ok": self.cleanup_ok}


class SecureExecutionRuntime:
    """Control plane for jailed Happy LANG execution."""

    def __init__(
        self,
        config: Optional[IntegrationConfig] = None,
        *,
        authorizer: Optional[AgentGuardAuthorizer] = None,
        forwarder: Optional[EventForwarder] = None,
        pool: Optional[WorkerPool] = None,
        isolation_mode: str = "auto",
        isolation_backend: str = "auto",
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config or IntegrationConfig.from_env()
        self._clock = clock
        self.authorizer = authorizer
        self.isolation_mode = isolation_mode
        self.isolation_backend = isolation_backend
        if forwarder is None:
            sink = None
            if self.config.enabled and self.config.emit_events:
                sink = http_event_sink(self.config)
            forwarder = EventForwarder(sink, buffer_size=self.config.max_events_buffer,
                                       enabled=self.config.enabled and self.config.emit_events)
        self.forwarder = forwarder
        self.pool = pool or WorkerPool(max_concurrency=2, queue_capacity=8,
                                       workdir_factory=make_workdir, cleanup=cleanup_workdir)
        self._owns_pool = pool is None
        self._isolation_cache: Optional[IsolationReport] = None

    # -- lifecycle ---------------------------------------------------------------------------
    def start(self) -> "SecureExecutionRuntime":
        self.pool.start()
        return self

    def shutdown(self, *, wait: bool = True) -> None:
        if self._owns_pool:
            self.pool.shutdown(wait=wait)

    def __enter__(self) -> "SecureExecutionRuntime":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.shutdown()

    def health(self) -> Dict[str, Any]:
        return self.pool.health().to_dict()

    def isolation_report(self, *, refresh: bool = False) -> IsolationReport:
        """Observed isolation state of this host (cached; ``refresh=True`` re-probes)."""
        if self._isolation_cache is None or refresh:
            self._isolation_cache = probe_isolation(mode=self.isolation_mode,
                                                    backend=self.isolation_backend)
        return self._isolation_cache

    # -- main entry point --------------------------------------------------------------------
    def execute(
        self,
        request: ExecutionRequest,
        source: str,
        *,
        credential: Optional[CallerCredential] = None,
        token: Optional[CancellationToken] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> ExecutionResult:
        """Run ``source`` through the full lifecycle and return a structured result."""
        started = self._clock()
        evidence = RuntimeEvidence(request_id=request.request_id,
                                   correlation_id=request.correlation_id, stage="request")
        cancel_token = token or CancellationToken()

        def finish(kind: ResultKind, *, ok: bool = False, output: str = "",
                   error: Optional[str] = None, error_code: Optional[str] = None,
                   decision: Any = None, diagnostics: Sequence[str] = (),
                   metadata: Optional[Mapping[str, Any]] = None) -> ExecutionResult:
            merged: Dict[str, Any] = {"stage": evidence.stage, "evidence": evidence.to_dict()}
            merged.update(dict(metadata or {}))
            outcome = ExecutionResult(
                result=kind, ok=ok, request_id=request.request_id,
                correlation_id=request.correlation_id, output=output, error=error,
                error_code=error_code, decision=decision, diagnostics=tuple(diagnostics),
                duration_ms=round((self._clock() - started) * 1000, 3), metadata=merged)
            self._emit(outcome, request)
            return outcome

        # ---- 1. authenticate ---------------------------------------------------------------
        evidence.stage = "authenticate"
        if self.config.enabled and self.config.mode == "enforce":
            if credential is None or not credential.present:
                return finish(ResultKind.AUTHORIZATION_DENIED,
                              error="unauthenticated: no caller credential was presented",
                              error_code="unauthenticated")
            if self.authorizer is not None:
                try:
                    self.authorizer.set_credentials(token=credential.token,
                                                    proof=dict(credential.proof or {}))
                except Exception as exc:                        # noqa: BLE001 - fail closed
                    return finish(ResultKind.AUTHORIZATION_DENIED,
                                  error=f"credential rejected: {type(exc).__name__}",
                                  error_code="unauthenticated")

        # ---- 2. validate -------------------------------------------------------------------
        evidence.stage = "validate"
        ok, problems = self._validate(request)
        if not ok:
            return finish(ResultKind.VALIDATION_ERROR, error="invalid execution request",
                          error_code="validation_error", diagnostics=problems,
                          metadata={"problems": list(problems)})

        # ---- 3. authorize the DECLARED resources (before anything runs) ---------------------
        evidence.stage = "authorize"
        if self.config.enabled and self.config.mode != "off":
            authorizer = self.authorizer or self._make_authorizer(request, source)
            denied = self._pre_authorize(authorizer, request)
            evidence.authorization = self._auth_summary(authorizer)
            if denied is not None:
                return finish(ResultKind.AUTHORIZATION_DENIED, error=denied[0],
                              error_code="authorization_denied", decision=denied[1],
                              metadata={"stage": "pre_authorization"})

        # ---- 4. prepare isolation ----------------------------------------------------------
        evidence.stage = "prepare_isolation"
        report = self.isolation_report()
        evidence.isolation = report.to_dict()
        if not report.os_isolated:
            return finish(ResultKind.ISOLATION_UNAVAILABLE,
                          error=("no usable OS-level isolation backend; refusing to run untrusted "
                                 "code directly on the host"),
                          error_code="isolation_unavailable",
                          metadata={"isolation": report.to_dict()})

        # ---- 5. cancellation before submission ---------------------------------------------
        if cancel_token.cancelled or (should_cancel is not None and should_cancel()):
            return finish(ResultKind.CANCELLED, error="cancelled before execution",
                          error_code="cancelled")

        # ---- 6. execute (in a worker, inside the jail) -------------------------------------
        evidence.stage = "execute"
        budget = self._budget_for(request)
        allowed = self._allowed_operations(request)
        job = ExecutionJob(
            job_id=f"job_{sha256_hex(request.request_id + request.correlation_id)[:20]}",
            fn=lambda tracker, workdir: self._run_jailed(tracker, workdir, request, source, allowed,
                                                         evidence),
            budget=budget, token=cancel_token)
        try:
            outcome = self.pool.submit(job, timeout=float(budget.wall_clock_s) + 30.0)
        except QueueFull as exc:
            return finish(ResultKind.RESOURCE_LIMIT, error=str(exc), error_code="queue_full",
                          metadata={"limit_kind": "concurrency"})
        except ContractError as exc:
            return finish(ResultKind.INTEGRATION_ERROR, error=str(exc),
                          error_code=getattr(exc, "code", "worker_unavailable"))

        # ---- 7. enforce limits / interpret the outcome -------------------------------------
        evidence.stage = "enforce_limits"
        evidence.budget = dict(outcome.budget or {})
        evidence.cleanup_ok = bool(outcome.cleanup_ok)
        if not outcome.ok:
            kind = _KIND_MAP.get(str(outcome.error_kind or ""), ResultKind.RUNTIME_ERROR)
            if outcome.error_kind == "timeout":
                kind = ResultKind.TIMEOUT
            elif outcome.error_kind in ("output", "operations", "memory", "tool_calls"):
                kind = ResultKind.RESOURCE_LIMIT
            elif outcome.error_kind == "cancelled":
                kind = ResultKind.CANCELLED
            return finish(kind, error=outcome.error, error_code=outcome.error_kind,
                          metadata={"limit_kind": outcome.error_kind})

        payload = outcome.value if isinstance(outcome.value, dict) else {}
        kind = _KIND_MAP.get(str(payload.get("kind") or ""), ResultKind.RUNTIME_ERROR)
        evidence.stage = "collect_evidence"
        evidence.jail = dict(payload.get("jail") or {})
        if kind is ResultKind.OK:
            return finish(ResultKind.OK, ok=True, output=str(payload.get("output") or ""),
                          metadata={"capabilities": list(request.requested_capabilities),
                                    "authorization": evidence.authorization})
        return finish(kind, output=str(payload.get("output") or ""),
                      error=str(payload.get("error") or "execution failed"),
                      error_code=payload.get("error_code") or kind.value,
                      diagnostics=tuple(payload.get("diagnostics") or ()),
                      metadata={"limit_kind": payload.get("limit_kind")})

    # -- stages ------------------------------------------------------------------------------
    @staticmethod
    def _validate(request: ExecutionRequest) -> Tuple[bool, Tuple[str, ...]]:
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

    def _make_authorizer(self, request: ExecutionRequest, source: str) -> AgentGuardAuthorizer:
        return AgentGuardAuthorizer(
            self.config, checker=None, forwarder=self.forwarder,
            artifact=ArtifactRef(digest=sha256_hex(source), entry=request.entry,
                                 filename=request.artifact.filename,
                                 bytes_size=len(source.encode("utf-8"))))

    def _pre_authorize(self, authorizer: AgentGuardAuthorizer,
                       request: ExecutionRequest) -> Optional[Tuple[str, Any]]:
        """Authorize every declared resource.  A declaration grants nothing by itself."""
        from .executor import _operation_for

        for resource in request.declared_resources:
            operation = _operation_for(resource)
            try:
                decision = authorizer.authorize_operation(
                    operation, agent=None, loc=None,
                    args={"path": resource.target} if resource.kind in ("file", "path") else None,
                    requested_capabilities=tuple(request.requested_capabilities))
            except Exception as exc:                            # noqa: BLE001 - fail closed
                return (f"authorization unavailable for {resource.target}: {type(exc).__name__}",
                        None)
            if not decision.allowed:
                return (f"declared resource denied by AgentGuard ({decision.decision.value}: "
                        f"{decision.reason})", decision)
        return None

    @staticmethod
    def _auth_summary(authorizer: Optional[AgentGuardAuthorizer]) -> Dict[str, Any]:
        if authorizer is None:
            return {"installed": False}
        return {"installed": True, "checks": len(authorizer.audit),
                "denials": len(authorizer.denials)}

    @staticmethod
    def _budget_for(request: ExecutionRequest) -> ExecutionBudget:
        limits: ExecutionLimits = request.limits
        return ExecutionBudget(
            wall_clock_s=float(limits.timeout_s), memory_mb=float(limits.max_memory_mb),
            output_bytes=int(limits.max_output_bytes), max_operations=int(limits.max_operations),
            max_tool_calls=max(1, int(limits.max_operations) // 10))

    @staticmethod
    def _allowed_operations(request: ExecutionRequest) -> List[str]:
        """The operations the control plane pre-authorized, enforced locally inside the jail.

        Derived from the *declared* resources, which AgentGuard has already approved.  Anything not
        in this list is refused by the in-jail deny-by-default checker.
        """
        from .executor import _operation_for

        allowed: List[str] = []
        for resource in request.declared_resources:
            if resource.kind == "none":
                continue
            operation = _operation_for(resource)
            if operation not in allowed:
                allowed.append(operation)
        return allowed

    # -- the worker's job --------------------------------------------------------------------
    def _run_jailed(self, tracker: Any, workdir: str, request: ExecutionRequest, source: str,
                    allowed: Sequence[str], evidence: RuntimeEvidence) -> Dict[str, Any]:
        """Populate the private work directory and run the harness inside the jail."""
        tracker.check_deadline()
        self._populate(workdir, source, request, allowed)
        tracker.charge_operation()
        spec = JailSpec(
            workdir=workdir, python=sys.executable,
            timeout_s=float(request.limits.timeout_s),
            memory_mb=int(request.limits.max_memory_mb),
            mode=self.isolation_mode, backend=self.isolation_backend)
        result = run_in_jail(
            [sys.executable, f"{_JAIL_WORKDIR}/{_HARNESS}", f"{_JAIL_WORKDIR}/job.json"],
            spec, max_output_bytes=int(request.limits.max_output_bytes) + 65536)
        evidence.jail = result.to_dict()
        if result.timed_out:
            return {"kind": "timeout", "error": "execution exceeded its wall-clock budget",
                    "error_code": "timeout", "jail": result.to_dict()}
        payload = _parse_harness_stdout(result.stdout)
        if payload is None:
            return {"kind": "integration_error",
                    "error": (result.error or "jail produced no structured result"),
                    "error_code": "jail_no_result", "jail": result.to_dict()}
        payload["jail"] = result.to_dict()
        return payload

    @staticmethod
    def _populate(workdir: str, source: str, request: ExecutionRequest,
                  allowed: Sequence[str]) -> None:
        """Write the harness, the job and the packages into the private work directory."""
        if not workdir or not os.path.isdir(workdir):
            raise ContractError("worker has no work directory")
        for name in ("happy", "agentguard_happy_contract"):
            src = _locate_package(name)
            if src is None:
                continue
            dst = os.path.join(workdir, name)
            if os.path.isdir(dst):
                continue
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
                            copy_function=_link_or_copy)
        harness_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), _HARNESS)
        shutil.copy2(harness_src, os.path.join(workdir, _HARNESS))
        job = {
            "source": source, "filename": request.artifact.filename or "<jailed>",
            "entry": request.entry, "allowed_operations": list(allowed),
            "timeout_s": float(request.limits.timeout_s),
            "max_memory_mb": float(request.limits.max_memory_mb),
            "max_output_bytes": int(request.limits.max_output_bytes),
            "max_operations": int(request.limits.max_operations),
            "correlation_id": request.correlation_id,
        }
        with open(os.path.join(workdir, "job.json"), "w", encoding="utf-8") as handle:
            json.dump(job, handle)
        # The jail runs the program as an unprivileged user (uid 65534) and mounts this directory
        # READ-ONLY.  That user must still be able to traverse and read it, so the tree is made
        # world-readable -- it holds only the program and the Happy packages, never secrets.  The
        # directory itself stays 0700 on the host until this point, so nothing else can read it
        # while it is being populated.
        make_world_readable(workdir)

    # -- evidence ----------------------------------------------------------------------------
    def _emit(self, outcome: ExecutionResult, request: ExecutionRequest) -> None:
        try:
            event = outcome.to_security_event(agent_id=request.agent_id,
                                              instance_id=request.instance_id,
                                              org_id=request.org_id)
            self.forwarder.report(event)
        except Exception:                                        # noqa: BLE001 - best effort
            pass

    def flush_events(self) -> int:
        return self.forwarder.flush()


def _locate_package(name: str) -> Optional[str]:
    """Find a package directory to copy into the jail.

    ``happy`` lives in the sibling ``happy-lang/`` tree and ``agentguard_happy_contract`` in
    ``contract/``, so neither is a child of this file's directory.  Resolution order: the import
    system (authoritative -- it is the copy actually being used), then the known sibling layouts.
    """
    try:
        from importlib.util import find_spec

        spec = find_spec(name)
        if spec is not None and spec.origin and spec.origin.endswith("__init__.py"):
            return os.path.dirname(spec.origin)
    except Exception:                                           # noqa: BLE001 - fall through
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    integration = os.path.dirname(os.path.dirname(here))
    for candidate in (
        os.path.join(integration, "happy-lang", name),
        os.path.join(integration, "contract", name),
        os.path.join(os.path.dirname(here), name),
    ):
        if os.path.isdir(candidate):
            return candidate
    return None


def _link_or_copy(src: str, dst: str) -> str:
    """Hard-link when possible (fast, no extra disk), else copy."""
    try:
        os.link(src, dst)
        return dst
    except OSError:
        return shutil.copy2(src, dst)


def _parse_harness_stdout(stdout: str) -> Optional[Dict[str, Any]]:
    """Extract the harness's JSON object from stdout (tolerating stray output)."""
    if not stdout:
        return None
    text = stdout.strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except Exception:                                           # noqa: BLE001 - scan for the object
        pass
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict) and "kind" in parsed:
                    return parsed
            except Exception:                                   # noqa: BLE001 - keep scanning
                continue
    return None
