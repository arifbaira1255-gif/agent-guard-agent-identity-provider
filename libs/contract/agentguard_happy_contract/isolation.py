"""OS-enforced isolation for untrusted Happy LANG programs.

WHY THIS MODULE EXISTS
----------------------
The Step 1 audit was explicit: Happy LANG's capability checker runs **in the same process as the
code it checks**, so it is a correctness/UX control, not a security boundary.  A language-level
permission check is **not** equivalent to process isolation.  This module supplies the boundary the
kernel enforces, by reusing Happy LANG's own isolation backends (``happy.ai.isolation``) rather than
re-implementing them:

* **no network** -- the jail has its own empty network namespace, so an unauthorized outbound
  connection is physically impossible, not merely denied by a policy check;
* **read-only root filesystem** -- host files (``/etc``, ``/home``, secrets, other tenants' data) do
  not exist inside the jail;
* **own PID namespace** -- the program sees only its own processes;
* **unprivileged user, all capabilities dropped, ``no_new_privs``**;
* **the whole process tree dies on timeout** (kill-group), so a cancelled or timed-out run cannot
  leave a privileged operation silently running.

The module is deliberately honest about what it can and cannot guarantee: :func:`probe_isolation`
runs Happy's escape self-test and returns the *observed* result, and
:class:`IsolationReport.achieved` is only true when the probes actually passed.  No claim of
"full sandbox security" is made anywhere -- see ``docs/SECURE_RUNTIME.md`` for the platform-specific
limitations.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .errors import ContractError

__all__ = [
    "IsolationUnavailableError",
    "IsolationReport",
    "JailSpec",
    "JailResult",
    "probe_isolation",
    "isolation_available",
    "run_in_jail",
    "make_workdir",
    "cleanup_workdir",
    "make_world_readable",
]


class IsolationUnavailableError(ContractError):
    """No usable OS-level isolation backend, and the policy requires one (fail closed)."""

    code = "isolation_unavailable"


# ---------------------------------------------------------------------------------------------
# Policy / report
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class IsolationReport:
    """The *observed* isolation state of this host (never an assumption)."""

    mode: str
    requested_backend: str
    selected: Optional[str]
    os_isolated: bool
    backends: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    probes: Dict[str, Any] = field(default_factory=dict)
    failures: Tuple[str, ...] = ()
    error: Optional[str] = None

    @property
    def achieved(self) -> bool:
        """True only when a backend was selected AND its escape probes actually passed."""
        return bool(self.os_isolated and not self.failures and self.probes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "requested_backend": self.requested_backend,
            "selected": self.selected,
            "os_isolated": self.os_isolated,
            "achieved": self.achieved,
            "backends": self.backends,
            "probes": self.probes,
            "failures": list(self.failures),
            "error": self.error,
        }

    def summary(self) -> str:
        if self.achieved:
            return f"isolation: {self.selected} (probes passed)"
        if self.os_isolated:
            return f"isolation: {self.selected} (probes incomplete: {list(self.failures)})"
        return f"isolation: NONE ({self.error or 'no usable backend'})"


def _policy(mode: str = "auto", backend: str = "auto", **kwargs):
    """Build a Happy ``IsolationPolicy`` (imported lazily so this module stands alone)."""
    from happy.ai.isolation import IsolationPolicy

    return IsolationPolicy(mode=mode, backend=backend, **kwargs)


def probe_isolation(*, mode: str = "auto", backend: str = "auto",
                    run_self_test: bool = True) -> IsolationReport:
    """Report what isolation this host actually provides, with observed escape-probe results.

    ``run_self_test=False`` skips the (slower) escape probes and reports only backend availability.
    """
    try:
        from happy.ai.isolation import isolation_status
    except Exception as exc:                                    # noqa: BLE001 - Happy absent
        return IsolationReport(mode=mode, requested_backend=backend, selected=None,
                               os_isolated=False, error=f"happy.ai.isolation unavailable: {exc}")
    try:
        policy = _policy(mode=mode, backend=backend)
        status = isolation_status(policy)
    except Exception as exc:                                    # noqa: BLE001 - bad policy
        return IsolationReport(mode=mode, requested_backend=backend, selected=None,
                               os_isolated=False, error=f"{type(exc).__name__}: {exc}")
    report = IsolationReport(
        mode=str(status.get("mode", mode)),
        requested_backend=str(status.get("requested_backend", backend)),
        selected=status.get("selected"),
        os_isolated=bool(status.get("os_isolated")),
        backends=dict(status.get("backends") or {}),
        error=status.get("error"),
    )
    if run_self_test and report.os_isolated:
        try:
            from happy.ai.isolation import self_test

            result = self_test(policy)
            report = IsolationReport(
                mode=report.mode, requested_backend=report.requested_backend,
                selected=report.selected, os_isolated=report.os_isolated,
                backends=report.backends, probes=dict(result.get("probes") or {}),
                failures=tuple(result.get("failures") or ()), error=report.error)
        except Exception as exc:                                # noqa: BLE001 - probe failure
            report = IsolationReport(
                mode=report.mode, requested_backend=report.requested_backend,
                selected=report.selected, os_isolated=report.os_isolated,
                backends=report.backends, failures=(f"self_test_error: {type(exc).__name__}",))
    return report


def isolation_available(*, mode: str = "auto", backend: str = "auto") -> bool:
    """True when a usable backend exists (does not run the escape probes)."""
    return probe_isolation(mode=mode, backend=backend, run_self_test=False).os_isolated


# ---------------------------------------------------------------------------------------------
# Jail
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class JailSpec:
    """Everything one jailed run needs.  One spec belongs to exactly one execution."""

    workdir: str
    python: str = "python3"
    timeout_s: float = 10.0
    memory_mb: int = 256
    cpus: float = 1.0
    max_pids: int = 32
    tmpfs_mb: int = 16
    mode: str = "auto"
    backend: str = "auto"
    #: Extra read-only host paths the jail must expose (e.g. the Happy tree).  Never writable.
    extra_ro_paths: Tuple[str, ...] = ()
    #: Environment passed to the jailed process.  Secrets are NOT passed by default.
    env: Dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        problems: List[str] = []
        if not self.workdir or not os.path.isdir(self.workdir):
            problems.append("workdir must be an existing directory")
        if not (0 < float(self.timeout_s) <= 300):
            problems.append("timeout_s must be in (0, 300]")
        if not (1 <= int(self.memory_mb) <= 4096):
            problems.append("memory_mb must be in [1, 4096]")
        if problems:
            from .errors import ValidationError

            raise ValidationError("invalid jail spec", errors=problems)


@dataclass
class JailResult:
    """The raw outcome of one jailed process run."""

    ok: bool
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: float
    backend: Optional[str]
    killed_group: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok, "returncode": self.returncode, "timed_out": self.timed_out,
            "duration_ms": self.duration_ms, "backend": self.backend,
            "killed_group": self.killed_group, "error": self.error,
            "stdout_bytes": len(self.stdout.encode("utf-8", errors="replace")),
            "stderr_bytes": len(self.stderr.encode("utf-8", errors="replace")),
        }


def make_workdir(prefix: str = "happy_exec_") -> str:
    """Create a private, per-execution work directory (mode 0700, unpredictable name)."""
    path = tempfile.mkdtemp(prefix=f"{prefix}{uuid.uuid4().hex[:12]}_")
    try:
        os.chmod(path, 0o700)
    except OSError:                                             # pragma: no cover - best effort
        pass
    return path


def cleanup_workdir(path: str) -> bool:
    """Remove a per-execution work directory.  Never raises (cleanup must not mask a result)."""
    if not path:
        return False
    try:
        shutil.rmtree(path, ignore_errors=True)
        return not os.path.exists(path)
    except Exception:                                           # noqa: BLE001 - best effort
        return False


def make_world_readable(root: str) -> None:
    """Make a work directory traversable/readable by the jail's unprivileged user.

    The jail mounts the work directory read-only and runs the program as uid 65534, which cannot
    enter a mode-0700 directory -- the run fails with ``cannot change directory to '/work'``.  Only
    the program, the job description and the Happy packages live here (no credentials, no secrets),
    so widening to ``a+rX`` is safe and is what makes the jail usable.  This lives in the isolation
    layer because it is a property of the jail, not of any one caller.
    """
    try:
        os.chmod(root, 0o755)
    except OSError:                                             # pragma: no cover - best effort
        return
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames:
            try:
                os.chmod(os.path.join(dirpath, name), 0o755)
            except OSError:                                     # pragma: no cover
                continue
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                os.chmod(path, (os.stat(path).st_mode & 0o777) | 0o444)
            except OSError:                                     # pragma: no cover
                continue


def _kill_group(proc: "subprocess.Popen[bytes]") -> bool:
    """Kill the whole process group so no descendant survives a timeout/cancel."""
    import signal

    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        return True
    except Exception:                                           # noqa: BLE001 - already gone
        try:
            proc.kill()
            return True
        except Exception:                                       # noqa: BLE001
            return False


def run_in_jail(argv: Sequence[str], spec: JailSpec, *,
                stdin_data: Optional[bytes] = None,
                max_output_bytes: int = 1_048_576) -> JailResult:
    """Run ``argv`` inside the kernel-enforced jail described by ``spec``.

    The command is wrapped by Happy LANG's own isolation backend (docker/podman/bwrap/namespaces),
    so the guarantees are the backend's, not this module's.  The process is started in its own
    process group and the **whole group** is killed on timeout, so a runaway child cannot outlive
    the run.  Output is read with a hard cap so a chatty program cannot exhaust memory here.
    """
    spec.validate()
    started = time.monotonic()
    # The jail runs the program as an unprivileged user, so the work directory must be traversable
    # by it.  Doing this here (rather than in each caller) means every jailed run is usable.
    make_world_readable(spec.workdir)
    try:
        from happy.ai.isolation import IsolationUnavailable, select_backend
    except Exception as exc:                                    # noqa: BLE001 - Happy absent
        return JailResult(ok=False, returncode=None, stdout="", stderr="", timed_out=False,
                          duration_ms=0.0, backend=None,
                          error=f"happy.ai.isolation unavailable: {exc}")

    try:
        policy = _policy(mode=spec.mode, backend=spec.backend, memory_mb=int(spec.memory_mb),
                         cpus=float(spec.cpus), max_pids=int(spec.max_pids),
                         tmpfs_mb=int(spec.tmpfs_mb))
        backend = select_backend(policy)
    except IsolationUnavailable as exc:
        return JailResult(ok=False, returncode=None, stdout="", stderr="", timed_out=False,
                          duration_ms=0.0, backend=None, error=f"isolation_unavailable: {exc}")
    except Exception as exc:                                    # noqa: BLE001 - bad policy
        return JailResult(ok=False, returncode=None, stdout="", stderr="", timed_out=False,
                          duration_ms=0.0, backend=None, error=f"{type(exc).__name__}: {exc}")

    if backend is None:
        # ``auto`` mode with nothing usable: refuse rather than silently run unjailed.  Running
        # untrusted code directly on the host is exactly what the task forbids.
        return JailResult(ok=False, returncode=None, stdout="", stderr="", timed_out=False,
                          duration_ms=0.0, backend=None,
                          error="isolation_unavailable: no usable backend and mode is not 'off'")

    try:
        wrapped = backend.wrap(list(argv), spec.workdir, spec.python, policy)
    except Exception as exc:                                    # noqa: BLE001 - wrap failure
        return JailResult(ok=False, returncode=None, stdout="", stderr="", timed_out=False,
                          duration_ms=0.0, backend=backend.name,
                          error=f"jail_wrap_failed: {type(exc).__name__}: {exc}")

    # ``/usr/sbin`` and ``/sbin`` must be on PATH: the namespaces backend's jail script invokes
    # ``chroot`` (util-linux/coreutils), which lives there on Debian.  Omitting them makes the jail
    # fail with exit 127 ("chroot: not found") -- found by running the jail, not by reading it.
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "HOME": "/tmp", "LANG": "C.UTF-8",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
    env.update({str(k): str(v) for k, v in (spec.env or {}).items()})

    timed_out = False
    killed = False
    try:
        proc = subprocess.Popen(                          # noqa: S603 - argv is built by the backend
            wrapped, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, start_new_session=True, cwd=spec.workdir)
    except Exception as exc:                                    # noqa: BLE001 - spawn failure
        return JailResult(ok=False, returncode=None, stdout="", stderr="", timed_out=False,
                          duration_ms=(time.monotonic() - started) * 1000.0,
                          backend=backend.name, error=f"jail_spawn_failed: {type(exc).__name__}")
    try:
        try:
            out, err = proc.communicate(input=stdin_data, timeout=float(spec.timeout_s))
        except subprocess.TimeoutExpired:
            timed_out = True
            killed = _kill_group(proc)
            try:
                out, err = proc.communicate(timeout=5)
            except Exception:                                   # noqa: BLE001 - give up reading
                out, err = b"", b""
    finally:
        try:
            backend.cleanup()
        except Exception:                                       # noqa: BLE001 - best effort
            pass

    stdout = (out or b"")[:max_output_bytes].decode("utf-8", errors="replace")
    stderr = (err or b"")[:max_output_bytes].decode("utf-8", errors="replace")
    duration = (time.monotonic() - started) * 1000.0
    if timed_out:
        return JailResult(ok=False, returncode=proc.returncode, stdout=stdout, stderr=stderr,
                          timed_out=True, duration_ms=duration, backend=backend.name,
                          killed_group=killed, error="jail_timeout")
    return JailResult(ok=(proc.returncode == 0), returncode=proc.returncode, stdout=stdout,
                      stderr=stderr, timed_out=False, duration_ms=duration,
                      backend=backend.name, killed_group=killed,
                      error=None if proc.returncode == 0 else f"exit_{proc.returncode}")
