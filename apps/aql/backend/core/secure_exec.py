"""Code execution for agents: ``python_exec`` and ``happy_run`` - isolated, or refused.

Modes for ``python_exec`` (setting ``python_exec_mode``):

``disabled``   (default)  Refuse. Safe on any deployment.
``isolated``              Run inside Happy LANG's kernel-enforced jail (docker/podman/bwrap/
                          namespaces) via ``agentguard_happy_contract.isolation.run_in_jail``.
                          If no isolation backend is observed the run is REFUSED - never
                          downgraded to the host.
``unsafe_dev``            Plain subprocess on the host. NOT a sandbox. Refused in production.
                          The child gets a scrubbed environment so it cannot read this
                          process's secrets (API keys, admin token, ...).

Results keep the original shape: ``{ok, stdout, stderr, returncode, error}`` plus ``mode`` and
``isolated`` so callers (and the posture endpoint) can see what actually happened.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

__all__ = ["EXEC_MODES", "run_python", "run_happy", "isolation_status"]

EXEC_MODES = ("disabled", "isolated", "unsafe_dev")
MAX_CODE_BYTES = 64 * 1024
MAX_OUTPUT_CHARS = 16 * 1024


def _result(ok: bool, *, mode: str, isolated: bool, stdout: str = "", stderr: str = "",
            returncode: int = -1, error: Optional[str] = None, backend: Optional[str] = None) -> Dict[str, Any]:
    return {
        "ok": ok,
        "stdout": (stdout or "").strip()[:MAX_OUTPUT_CHARS],
        "stderr": (stderr or "").strip()[:MAX_OUTPUT_CHARS],
        "returncode": returncode,
        "error": None if ok else (error or (stderr or "").strip()[:MAX_OUTPUT_CHARS] or "failed"),
        "mode": mode,
        "isolated": isolated,
        "backend": backend,
    }


def _refuse(mode: str, why: str) -> Dict[str, Any]:
    return _result(False, mode=mode, isolated=False, error=why)


def isolation_status() -> Dict[str, Any]:
    """Observed (not assumed) isolation availability."""
    try:
        from agentguard_happy_contract.isolation import probe_isolation

        report = probe_isolation()
        data = report.to_dict() if hasattr(report, "to_dict") else dict(report)
        return {"available": bool(getattr(report, "achieved", data.get("achieved", False))), "report": data}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": f"probe_failed:{type(exc).__name__}"}


def _happy_root() -> Optional[str]:
    explicit = os.environ.get("HAPPY_LANG_PATH")
    candidates = [explicit] if explicit else []
    here = Path(__file__).resolve()
    candidates += [str(p / "libs" / "happy-lang") for p in here.parents]
    candidates.append("/opt/platform/libs/happy-lang")
    for c in candidates:
        if c and (Path(c) / "happy" / "__init__.py").is_file():
            return str(Path(c))
    return None


def _jail_run(argv_builder, files: Dict[str, str], *, timeout: int, mode: str, extra_env: Dict[str, str],
              copy_trees: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    try:
        from agentguard_happy_contract.isolation import (
            JailSpec, cleanup_workdir, isolation_available, make_workdir, run_in_jail,
        )
    except Exception as exc:  # noqa: BLE001
        return _refuse(mode, f"isolation_unavailable:contract_not_importable:{type(exc).__name__}")
    if not isolation_available():
        return _refuse(mode, "isolation_unavailable: no usable OS isolation backend; refusing to run on the host")
    workdir = make_workdir()
    try:
        for name, content in files.items():
            Path(workdir, name).write_text(content, encoding="utf-8")
        # The jail only sees its private work directory (mounted at /work), so packages the
        # program needs are copied in - the same approach the contract's own runtime uses.
        for name, src in (copy_trees or {}).items():
            shutil.copytree(src, os.path.join(workdir, name),
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        spec = JailSpec(workdir=workdir, python=sys.executable, timeout_s=float(min(max(int(timeout or 5), 1), 60)),
                        memory_mb=256, max_pids=32, env=dict(extra_env))
        res = run_in_jail(argv_builder(spec), spec)
    except Exception as exc:  # noqa: BLE001 - a failure is data, not a crash
        return _refuse(mode, f"jail_error:{type(exc).__name__}")
    finally:
        try:
            cleanup_workdir(workdir)
        except Exception:  # noqa: BLE001
            pass
    err = res.error or ("timed out" if res.timed_out else None)
    return _result(bool(res.ok), mode=mode, isolated=True, stdout=res.stdout, stderr=res.stderr,
                   returncode=res.returncode if res.returncode is not None else -1, error=err, backend=res.backend)


def run_python(code: str, timeout: int = 5, *, mode: str = "disabled", app_env: str = "development") -> Dict[str, Any]:
    """Execute a Python snippet according to ``mode`` (see module docstring)."""
    mode = (mode or "disabled").strip().lower()
    code = code or ""
    if mode not in EXEC_MODES:
        return _refuse("disabled", f"unknown python_exec_mode {mode!r}; refusing")
    if len(code.encode("utf-8", errors="replace")) > MAX_CODE_BYTES:
        return _refuse(mode, f"code exceeds {MAX_CODE_BYTES} bytes")
    if mode == "disabled":
        return _refuse(mode, "python_exec is disabled (set python_exec_mode=isolated on a host with Docker/bwrap)")
    if mode == "isolated":
        return _jail_run(lambda spec: [spec.python, "-I", "-c", code], {}, timeout=timeout, mode=mode, extra_env={})
    # unsafe_dev
    if (app_env or "").lower() == "production":
        return _refuse(mode, "python_exec_mode=unsafe_dev is not permitted when app_env=production")
    safe_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONIOENCODING": "utf-8", "LANG": "C.UTF-8"}
    try:
        proc = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                              timeout=min(max(int(timeout or 5), 1), 60), env=safe_env)
        return _result(proc.returncode == 0, mode=mode, isolated=False, stdout=proc.stdout,
                       stderr=proc.stderr, returncode=proc.returncode)
    except subprocess.TimeoutExpired:
        return _result(False, mode=mode, isolated=False, error=f"timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001
        return _result(False, mode=mode, isolated=False, error=f"{type(exc).__name__}: {exc}")


def run_happy(source: str, timeout: int = 10, *, enabled: bool = True) -> Dict[str, Any]:
    """Run a Happy (.hpy) program. ALWAYS jailed - there is no host fallback."""
    mode = "isolated"
    if not enabled:
        return _refuse(mode, "happy_run is disabled")
    source = source or ""
    if len(source.encode("utf-8", errors="replace")) > MAX_CODE_BYTES:
        return _refuse(mode, f"source exceeds {MAX_CODE_BYTES} bytes")
    root = _happy_root()
    if root is None:
        return _refuse(mode, "happy_lang_not_found: set HAPPY_LANG_PATH")
    # ``-I`` would ignore PYTHONPATH, so put the copied Happy package on sys.path explicitly.
    boot = (
        "import sys, runpy; sys.path.insert(0, '/work'); "
        "sys.argv = ['happy', 'run', '/work/program.hpy']; "
        "runpy.run_module('happy', run_name='__main__')"
    )
    return _jail_run(lambda spec: [spec.python, "-c", boot], {"program.hpy": source},
                     timeout=timeout, mode=mode, extra_env={},
                     copy_trees={"happy": str(Path(root, "happy"))})
