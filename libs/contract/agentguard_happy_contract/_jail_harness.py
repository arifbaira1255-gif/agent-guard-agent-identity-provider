"""In-jail harness: runs ONE Happy LANG program inside the OS jail and reports JSON.

This file is copied into the per-execution work directory and executed *inside* the jail (see
``isolation.run_in_jail``).  It is the only place untrusted Happy LANG code is ever executed, and it
always runs with:

* a **deny-by-default** capability checker installed into every ``happy.std`` module, so the
  ``_CHECKER is None`` bypass cannot be reached;
* a **hard output cap** enforced at the point of emission, so a runaway ``println`` loop is stopped
  rather than allowed to exhaust memory;
* the jail's own wall-clock timeout, read-only rootfs, empty network namespace and dropped
  capabilities.

It prints exactly one JSON object on stdout and never raises: any failure becomes a structured
``kind`` the control plane maps onto a :class:`~agentguard_happy_contract.models.ResultKind`.
"""
from __future__ import annotations

import json
import os
import sys


def _emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()


class _OutputLimit(Exception):
    """Raised when the program exceeds its output budget (a real, enforced control)."""


class _OperationLimit(Exception):
    """Raised when the program exceeds its operation budget."""


def _install_checker(allowed):
    """Point every ``happy.std`` module at a deny-by-default checker.

    This is the in-jail half of the bypass fix: ``_CHECKER`` is never ``None``, so an operation that
    was not pre-authorized by the control plane is *refused* instead of silently allowed.
    """
    from agentguard_happy_contract.std_guard import StaticAllowlistChecker

    checker = StaticAllowlistChecker(allowed)
    from importlib import import_module

    for name in ("io", "fs", "net", "process", "env", "crypto"):
        try:
            module = import_module(f"happy.std.{name}")
        except Exception:                                       # noqa: BLE001 - module absent
            continue
        if hasattr(module, "use_checker"):
            module.use_checker(checker)
    return checker


def _classify(exc: BaseException):
    """Map a runtime exception onto ``(kind, code)`` using the shared classifier."""
    try:
        from agentguard_happy_contract.executor import _classify_runtime_error

        kind, code = _classify_runtime_error(exc)
        return kind.value, code
    except Exception:                                           # noqa: BLE001 - classifier absent
        return "runtime_error", None


def _limit_kind_for(message: str):
    """Recover the specific budget kind from an error message, or ``None``.

    Happy's runtime wraps an exception raised inside a program into a ``HappyRuntimeError``, so a
    budget breach surfaces as a *failed run result* rather than at the raise site.  The message is
    therefore the reliable signal.  The marker sets are imported from the classifier so the harness
    and the control plane can never disagree about what counts as a limit breach.
    """
    try:
        from agentguard_happy_contract.executor import (
            _MEMORY_MARKERS,
            _OPERATION_MARKERS,
            _OUTPUT_MARKERS,
        )
    except Exception:                                           # noqa: BLE001 - markers unavailable
        return None
    lowered = (message or "").lower()
    for markers, limit_kind in ((_OUTPUT_MARKERS, "output"), (_OPERATION_MARKERS, "operations"),
                                (_MEMORY_MARKERS, "memory")):
        if any(marker in lowered for marker in markers):
            return limit_kind
    return None


def main() -> int:
    job_path = sys.argv[1] if len(sys.argv) > 1 else "/work/job.json"
    workdir = os.path.dirname(os.path.abspath(job_path))
    # The jail mounts the work directory read-only; make the copied packages importable.
    if workdir not in sys.path:
        sys.path.insert(0, workdir)
    try:
        with open(job_path, encoding="utf-8") as handle:
            job = json.load(handle)
    except Exception as exc:                                    # noqa: BLE001 - malformed job
        _emit({"kind": "integration_error", "error": f"unreadable job: {type(exc).__name__}"})
        return 0

    source = job.get("source") or ""
    filename = job.get("filename") or "<jailed>"
    entry = job.get("entry") or "main"
    max_output = int(job.get("max_output_bytes") or 1_048_576)
    max_operations = int(job.get("max_operations") or 100_000)

    try:
        _install_checker(job.get("allowed_operations") or [])
    except Exception as exc:                                    # noqa: BLE001 - guard must exist
        _emit({"kind": "integration_error",
               "error": f"capability guard unavailable: {type(exc).__name__}: {exc}"})
        return 0

    # ---- compile with Happy's own compiler ------------------------------------------------
    try:
        from happy.pipeline import compile_source

        compiled = compile_source(source, filename=filename)
    except RecursionError:
        _emit({"kind": "compile_error", "diagnostics": ["program is too deeply nested"]})
        return 0
    except Exception as exc:                                    # noqa: BLE001 - never crash
        _emit({"kind": "compile_error", "diagnostics": [f"{type(exc).__name__}: {exc}"]})
        return 0
    if not compiled.ok:
        _emit({"kind": "compile_error",
               "diagnostics": [str(d) for d in (compiled.diagnostics or [])]})
        return 0

    # ---- run under Happy's RuntimeContext, with the output cap enforced -------------------
    try:
        from happy.runtime import RuntimeContext

        ctx = RuntimeContext(
            filename=filename, source=source, module=getattr(compiled, "module", None),
            sourcemap=getattr(getattr(compiled, "program", None), "sourcemap", None),
            timeout=float(job.get("timeout_s") or 10.0),
            max_memory_mb=float(job.get("max_memory_mb") or 256.0))

        emitted = {"bytes": 0}
        original_emit = ctx.emit

        def _capped_emit(text: str) -> None:
            emitted["bytes"] += len(str(text).encode("utf-8", errors="replace"))
            if emitted["bytes"] > max_output:
                raise _OutputLimit(f"output budget of {max_output} bytes exceeded")
            original_emit(text)

        ctx.emit = _capped_emit                            # type: ignore[method-assign]

        operations = {"count": 0}
        original_check = ctx.capabilities.check_operation

        def _counted_check(operation, agent=None, loc=None):
            operations["count"] += 1
            if operations["count"] > max_operations:
                raise _OperationLimit(f"operation budget of {max_operations} exceeded")
            return original_check(operation, agent=agent, loc=loc)

        ctx.capabilities.check_operation = _counted_check   # type: ignore[method-assign]

        run_result = compiled.program.run(ctx, entry=entry)
    except _OutputLimit as exc:
        _emit({"kind": "resource_limit", "error": str(exc), "limit_kind": "output"})
        return 0
    except _OperationLimit as exc:
        _emit({"kind": "resource_limit", "error": str(exc), "limit_kind": "operations"})
        return 0
    except Exception as exc:                                    # noqa: BLE001 - classify, never crash
        kind, code = _classify(exc)
        payload = {"kind": kind, "error": f"{type(exc).__name__}: {exc}", "error_code": code}
        limit_kind = _limit_kind_for(str(exc))
        if limit_kind:
            payload["limit_kind"] = limit_kind
        _emit(payload)
        return 0

    output = getattr(run_result, "output", "") or ""
    if getattr(run_result, "ok", False):
        _emit({"kind": "ok", "output": output[:max_output]})
        return 0
    error = getattr(run_result, "error", None)
    kind, code = _classify(error if error is not None else Exception("runtime error"))
    payload = {"kind": kind, "output": output[:max_output],
               "error": str(error) if error is not None else "runtime error", "error_code": code}
    limit_kind = _limit_kind_for(str(error) if error is not None else "")
    if limit_kind:
        payload["limit_kind"] = limit_kind
    _emit(payload)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:                                # noqa: BLE001 - last-resort guard
        _emit({"kind": "integration_error", "error": f"harness failure: {type(exc).__name__}"})
        raise SystemExit(0)
