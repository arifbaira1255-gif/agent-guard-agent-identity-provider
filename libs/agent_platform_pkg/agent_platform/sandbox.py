"""Sandbox bridge: run agent-produced artifacts through the existing secure execution runtime.

WHY A BRIDGE AND NOT A NEW SANDBOX
---------------------------------
The M2 work already built the OS-isolation, budgets, bounded worker pool and structured results.  A
second sandbox would be a second set of guarantees to get wrong.  This module adapts the platform's
call shape onto ``SecureExecutionRuntime`` -- imported from the integration contract -- and adds the
three things an agent needs that a raw runtime call does not do:

* it **refuses** when no usable isolation backend exists (never runs untrusted code on the host);
* it validates and bounds the artifact size *before* it reaches the runtime;
* it maps the runtime's structured result onto the platform's vocabulary, so a caller sees one
  ``SandboxResult`` shape regardless of which layer refused.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .errors import SandboxUnavailable
from .validation import sha256_hex, truncate

__all__ = ["SandboxResult", "SandboxBridge", "ImportContractRuntime"]

#: Largest artifact the bridge will forward (a runaway generator must be stopped here, not in the jail).
MAX_ARTIFACT_BYTES = 1_048_576


def ImportContractRuntime(*args: Any, **kwargs: Any) -> Any:
    """Return a live ``SecureExecutionRuntime`` from the integration contract.

    Imported lazily so the platform stays importable without the contract on ``sys.path`` -- the same
    discipline the contract itself uses, so neither package forces the other to be installed.
    """
    from agentguard_happy_contract.secure_runtime import SecureExecutionRuntime

    return SecureExecutionRuntime(*args, **kwargs)


@dataclass
class SandboxResult:
    """The platform's view of a sandboxed run (one shape whatever refused it)."""

    ok: bool
    kind: str
    output: str = ""
    error: Optional[str] = None
    error_code: Optional[str] = None
    duration_ms: float = 0.0
    backend: Optional[str] = None
    isolates: bool = False
    cleanup_ok: bool = True
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "kind": self.kind, "output": self.output,
                "error": self.error, "error_code": self.error_code,
                "duration_ms": self.duration_ms, "backend": self.backend,
                "isolates": self.isolates, "cleanup_ok": self.cleanup_ok,
                "evidence": self.evidence}

    @property
    def denied(self) -> bool:
        return self.kind in ("authorization_denied", "policy_violation", "isolation_unavailable")


class SandboxBridge:
    """Validate, forward to the contract runtime, and normalise the structured result."""

    def __init__(self, runtime: Any = None, *, require_isolation: bool = True,
                 isolation_probe: Optional[Any] = None, on_event: Optional[Any] = None,
                 max_artifact_bytes: int = MAX_ARTIFACT_BYTES) -> None:
        self._runtime = runtime
        self.require_isolation = bool(require_isolation)
        self._probe = isolation_probe
        self._on_event = on_event
        self.max_artifact_bytes = int(max_artifact_bytes)
        self.runs = 0
        self.refusals = 0

    # -- availability ------------------------------------------------------------------------
    def isolation_report(self, *, refresh: bool = False) -> Dict[str, Any]:
        """Observed isolation state (from the runtime when available, else the supplied probe)."""
        if self._runtime is not None:
            try:
                report = self._runtime.isolation_report(refresh=refresh)
                return report.to_dict() if hasattr(report, "to_dict") else dict(report)
            except Exception as exc:  # noqa: BLE001 - reported, never guessed
                return {"os_isolated": False, "error": f"probe_failed:{type(exc).__name__}"}
        if self._probe is not None:
            try:
                report = self._probe()
                return report if isinstance(report, dict) else {"os_isolated": bool(report)}
            except Exception as exc:  # noqa: BLE001
                return {"os_isolated": False, "error": f"probe_failed:{type(exc).__name__}"}
        return {"os_isolated": False, "error": "no_runtime_configured"}

    def available(self) -> bool:
        """True only when a live backend is actually observed (not assumed)."""
        return bool(self.isolation_report().get("os_isolated"))

    def ensure_available(self) -> None:
        """Raise :class:`SandboxUnavailable` unless a usable backend is observed.

        Called before a sandbox-requiring tool is allowed to allocate work, so the refusal happens
        early and is structural -- a deployment with no isolation simply cannot reach a host run.
        """
        if self._runtime is None:
            raise SandboxUnavailable("no secure execution runtime is configured; refusing to run "
                                     "untrusted code on the host")
        if self.require_isolation and not self.isolation_report().get("os_isolated"):
            raise SandboxUnavailable("no usable OS isolation backend; refusing to run untrusted "
                                     "code on the host")

    # -- execution ---------------------------------------------------------------------------
    def run(self, source: str, *, request: Any = None, credential: Any = None,
            token: Any = None) -> SandboxResult:
        """Run ``source`` in the jail.  Refuses -- with a typed result -- when it cannot."""
        started = time.monotonic()
        encoded = source.encode("utf-8", errors="replace")
        if len(encoded) > self.max_artifact_bytes:
            self.refusals += 1
            return SandboxResult(
                ok=False, kind="validation_error",
                error=f"artifact exceeds the {self.max_artifact_bytes}-byte bridge limit "
                      f"({len(encoded)} bytes)", error_code="artifact_too_large",
                duration_ms=(time.monotonic() - started) * 1000.0, isolates=False)
        if self._runtime is None:
            self.refusals += 1
            self._emit("platform.sandbox.unavailable", "error", "no_runtime_configured")
            return SandboxResult(ok=False, kind="isolation_unavailable",
                                 error="no secure execution runtime is configured; refusing to run "
                                       "untrusted code on the host",
                                 error_code="isolation_unavailable",
                                 duration_ms=(time.monotonic() - started) * 1000.0)

        report = self.isolation_report()
        if self.require_isolation and not report.get("os_isolated"):
            self.refusals += 1
            self._emit("platform.sandbox.unavailable", "error", "no_usable_backend")
            return SandboxResult(ok=False, kind="isolation_unavailable",
                                 error="no usable OS isolation backend; refusing to run untrusted "
                                       "code on the host", error_code="isolation_unavailable",
                                 duration_ms=(time.monotonic() - started) * 1000.0,
                                 evidence={"isolation": report})

        try:
            raw = self._runtime.execute(request, source, credential=credential, token=token)
        except Exception as exc:  # noqa: BLE001 - a runtime failure is a typed result, not a crash
            self.refusals += 1
            return SandboxResult(ok=False, kind="integration_error",
                                 error=f"sandbox runtime failed: {type(exc).__name__}",
                                 error_code="runtime_error",
                                 duration_ms=(time.monotonic() - started) * 1000.0,
                                 evidence={"isolation": report})
        self.runs += 1
        return self._normalise(raw, report, started)

    def _normalise(self, raw: Any, report: Dict[str, Any], started: float) -> SandboxResult:
        """Map the contract's ``ExecutionResult`` onto a :class:`SandboxResult`."""
        to_dict = getattr(raw, "to_dict", None)
        payload = to_dict() if callable(to_dict) else dict(raw or {})
        metadata = payload.get("metadata") or {}
        evidence = metadata.get("evidence") or {}
        kind = str(payload.get("result") or payload.get("kind") or "runtime_error")
        ok = bool(payload.get("ok"))
        jail = evidence.get("jail") or {}
        result = SandboxResult(
            ok=ok, kind=kind, output=truncate(str(payload.get("output") or ""), 16_384),
            error=(str(payload.get("error")) if payload.get("error") else None),
            error_code=payload.get("error_code"),
            duration_ms=float(payload.get("duration_ms") or (time.monotonic() - started) * 1000.0),
            backend=jail.get("backend") or report.get("selected"),
            isolates=bool(report.get("os_isolated")),
            cleanup_ok=bool(evidence.get("cleanup_ok", True)),
            evidence={"isolation": report, "jail": jail,
                      "limit_kind": metadata.get("limit_kind")})
        self._emit("platform.sandbox.completed", "ok" if ok else "error", kind)
        return result

    def _emit(self, event_type: str, outcome: str, reason: str) -> None:
        if self._on_event is None:
            return
        try:
            self._on_event(event_type=event_type, outcome=outcome, reason=reason,
                           metadata={"kind": event_type})
        except Exception:  # noqa: BLE001 - reporting must never break a run
            pass

    def summary(self) -> Dict[str, Any]:
        return {"runs": self.runs, "refusals": self.refusals,
                "require_isolation": self.require_isolation,
                "available": self.available()}


def workspace_snapshot(root: str, *, max_files: int = 200,
                       max_bytes: int = 200_000) -> Dict[str, Any]:
    """A bounded read-only listing of a workspace directory, for grounding without exfiltration.

    Returns names and sizes only -- never file contents -- so a tool can describe a workspace to a
    model without turning the filesystem into a prompt-injection channel.
    """
    import os

    entries: List[Dict[str, Any]] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d != "__pycache__")
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            path = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            entries.append({"path": os.path.relpath(path, root), "bytes": size,
                            "digest": None})
            total += size
            if len(entries) >= max_files or total > max_bytes:
                return {"root": root, "entries": entries, "truncated": True, "total_bytes": total}
    return {"root": root, "entries": entries, "truncated": False, "total_bytes": total}
