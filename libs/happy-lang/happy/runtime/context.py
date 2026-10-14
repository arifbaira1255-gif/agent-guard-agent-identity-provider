"""The Happy runtime context — the single object a generated program runs in.

A :class:`RuntimeContext` owns the four runtime services and exposes a small
``__ctx__`` facade that generated Python calls into:

* :mod:`contracts` — dynamic ``requires`` / ``ensures`` / ``invariant`` checks;
* :mod:`capability` — capability & permission enforcement for sensitive ops;
* :mod:`secrets` — the :class:`~happy.runtime.secrets.SecretGuard` policy;
* :mod:`async_runtime` — the :class:`~happy.runtime.async_runtime.Scheduler`.

It also carries the *source map* and *filename* so any failure can be resolved
back to a ``.hpy`` line, plus an output sink so tests can capture program output
without touching ``sys.stdout``.

The generated module receives the context through a module-level global, and
the context installs every builtin from :mod:`happy.std.core` (and whatever the
program imports from ``std.*``) into that module's ``__dict__``::

    ctx = RuntimeContext(filename="demo.hpy", source=src, module=ir_module)
    ctx.prepare(module_globals)          # install builtins
    ctx.run(main_coroutine_or_function)  # execute, translating errors
"""

from __future__ import annotations

import ctypes
import io
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TextIO, Tuple

from .async_runtime import Channel, Scheduler, Task, gather, sleep, spawn
from .capability import CapabilityChecker, CapabilityPolicy, CapabilityRegistry
from .contracts import ContractChecker, ContractPolicy
from .errors import HappyRuntimeError, translate_python_error
from .secrets import Secret, SecretGuard, reveal, secret
from .values import UNIT, Err, Ok, Option, Result, Some, to_display

__all__ = ["RuntimeContext", "RunResult"]

#: Default wall-clock budget for a single program run (seconds).
DEFAULT_RUN_TIMEOUT = 10.0

#: Default cap on how much *additional* memory one run may allocate (MiB).
DEFAULT_RUN_MEMORY_MB = 1024

#: How often the memory guard samples the resident set size (seconds).
_MEMORY_POLL_INTERVAL = 0.02


def _current_rss_bytes() -> int:
    """Best-effort resident set size of this process, in bytes (0 = unknown)."""
    try:
        with open("/proc/self/statm", "rb") as fh:
            pages = int(fh.read().split()[1])
        import os

        return pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError, AttributeError):
        pass
    try:  # macOS / BSD: peak RSS only, which still bounds growth
        import resource
        import sys

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return peak if sys.platform == "darwin" else peak * 1024
    except Exception:  # pragma: no cover - platform specific
        return 0


def _raise_in_thread(thread_id: int, exc_type: type) -> None:
    """Asynchronously raise ``exc_type`` in the thread ``thread_id``."""
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_ulong(thread_id), ctypes.py_object(exc_type)
    )
    if res > 1:  # pragma: no cover - defensive rollback
        ctypes.pythonapi.PyThreadState_SetAsyncExc(
            ctypes.c_ulong(thread_id), ctypes.py_object(None)
        )


class _RunTimeout(HappyRuntimeError):
    """Raised inside a running program when it exceeds its time budget."""

    def __init__(self, seconds: float = 0.0) -> None:
        super().__init__(
            message=(
                f"program exceeded the {seconds:g}s execution time limit"
                if seconds
                else "program exceeded its execution time limit"
            ),
            code="R6001",
            suggestion=(
                "the program did not terminate; check for an infinite loop or "
                "raise the timeout"
            ),
        )


class _RunMemoryLimit(HappyRuntimeError):
    """Raised inside a running program when it exceeds its memory budget."""

    def __init__(self, megabytes: float = 0.0) -> None:
        super().__init__(
            message=(
                f"program exceeded the {megabytes:g} MiB memory limit"
                if megabytes
                else "program exceeded its memory limit"
            ),
            code="R6002",
            suggestion=(
                "the program allocated too much memory; check for unbounded "
                "growth of a list or string, or raise max_memory_mb"
            ),
        )


class _MemoryGuard(threading.Thread):
    """Polls RSS and aborts the run when it grows past the budget.

    A per-process ``setrlimit`` would also constrain the embedding host (the
    REPL, the language server), so the limit is enforced from a watchdog
    thread instead.  A single huge allocation can overshoot between two
    samples; the run is still stopped immediately afterwards.
    """

    def __init__(self, target_id: int, limit_mb: float) -> None:
        super().__init__(daemon=True, name="happy-memory-guard")
        self._target_id = target_id
        self._limit_mb = float(limit_mb)
        self._limit_bytes = int(limit_mb * 1024 * 1024)
        self._baseline = _current_rss_bytes()
        self._halt = threading.Event()
        self.fired = False

    def run(self) -> None:
        if self._baseline <= 0:
            return  # cannot measure on this platform
        while not self._halt.wait(_MEMORY_POLL_INTERVAL):
            if _current_rss_bytes() - self._baseline > self._limit_bytes:
                self.fired = True
                _raise_in_thread(self._target_id, _RunMemoryLimit)
                return

    def stop(self) -> None:
        self._halt.set()


@dataclass
class RunResult:
    """The outcome of running a program under a :class:`RuntimeContext`."""

    ok: bool
    value: Any = None
    error: Optional[HappyRuntimeError] = None
    output: str = ""
    error_output: str = ""
    duration_ms: float = 0.0

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.output


class _Sink(io.TextIOBase):
    """A text sink that forwards writes to a callback (context.emit)."""

    def __init__(self, on_write: Callable[[str], None]) -> None:
        self._on_write = on_write

    def write(self, s: str) -> int:  # type: ignore[override]
        if s:
            self._on_write(s)
        return len(s)

    def flush(self) -> None:  # pragma: no cover - nothing buffered
        return None


class RuntimeContext:
    """Owns the services a generated Happy program needs at run time."""

    def __init__(
        self,
        filename: Optional[str] = None,
        source: Optional[str] = None,
        module: Any = None,
        contract_policy: Optional[ContractPolicy] = None,
        capability_policy: Optional[CapabilityPolicy] = None,
        secret_guard: Optional[SecretGuard] = None,
        sourcemap: Any = None,
        stdout: Optional[TextIO] = None,
        stderr: Optional[TextIO] = None,
        ai_provider: Any = None,
        ai_offline: bool = True,
        timeout: Optional[float] = DEFAULT_RUN_TIMEOUT,
        max_memory_mb: Optional[float] = DEFAULT_RUN_MEMORY_MB,
    ) -> None:
        self.filename = filename
        self.source = source
        self.module = module
        self.sourcemap = sourcemap
        self._ai_provider = ai_provider
        self._ai_offline = ai_offline
        # Wall-clock budget for a single run; ``None`` disables the limit.
        self.timeout = timeout
        # Extra memory one run may allocate (MiB); ``None`` disables the guard.
        self.max_memory_mb = max_memory_mb

        # Output capture.
        self._out = io.StringIO()
        self._err = io.StringIO()
        self._stdout = stdout
        self._stderr = stderr

        # Services.
        self.contracts = ContractChecker(
            policy=contract_policy, filename=filename, source=source
        )
        self.capabilities = CapabilityChecker(
            registry=CapabilityRegistry.from_module(module) if module is not None
            else CapabilityRegistry(),
            policy=capability_policy,
            filename=filename,
            source=source,
        )
        self.secrets = secret_guard or SecretGuard()
        self.scheduler = Scheduler()

        # AI-native support (lazily constructed so program startup stays cheap).
        self._ai_runner: Any = None

        # Async support.
        self.Task = Task
        self.Channel = Channel

    # -- output ---------------------------------------------------------
    def emit(self, text: str) -> None:
        self._out.write(text)
        if self._stdout is not None:
            self._stdout.write(text)

    def emit_error(self, text: str) -> None:
        self._err.write(text + "\n")
        if self._stderr is not None:
            self._stderr.write(text + "\n")

    @property
    def output(self) -> str:
        return self._out.getvalue()

    # -- AI (Step 10) ---------------------------------------------------
    @property
    def ai(self) -> Any:
        """The AI runner bound to this context (created on first use).

        Connecting to a *live* model is strictly opt-in: an injected
        ``ai_provider`` is used verbatim, a runner configured with
        ``ai_offline=False`` resolves one from the environment, and otherwise
        the runner stays fully offline.  A program therefore never silently
        makes a network call just because an API key happens to be present.
        """
        if self._ai_runner is None:
            from ..ai.runtime import AIRunner

            if self._ai_provider is not None:
                self._ai_runner = AIRunner(provider=self._ai_provider)
            elif not self._ai_offline:
                self._ai_runner = AIRunner.from_env()
            else:
                self._ai_runner = AIRunner(provider=None)
        return self._ai_runner

    def ai_complete(self, prompt: Any) -> str:
        """Run an ``ai`` expression, returning its text (never raising)."""
        return self.ai.complete(prompt)

    @property
    def error_output(self) -> str:
        return self._err.getvalue()

    # -- source location resolution ------------------------------------
    def resolve_location(self, generated_line: int) -> Optional[object]:
        """Map a generated Python line to a ``(filename, line, column)`` tuple."""
        if self.sourcemap is None:
            return None
        entry = self.sourcemap.resolve(generated_line)
        if entry is None:
            return None
        return (self.filename, entry.happy_line, entry.happy_column)

    # -- builtin installation ------------------------------------------
    def prepare(self, globals_dict: Dict[str, Any], imports: Optional[object] = None) -> None:
        """Install builtins (and any ``std.*`` imports) into ``globals_dict``."""
        from ..std import core

        # Bind ``__ctx__`` so builtins can route output / effects.
        for name, fn in core.BUILTINS.items():
            globals_dict[name] = _bind_ctx(fn, self)

        # Async primitives.
        globals_dict["spawn"] = spawn
        globals_dict["gather"] = gather
        globals_dict["await_all"] = gather
        globals_dict["sleep"] = sleep
        globals_dict["Task"] = Task
        globals_dict["Channel"] = Channel

        # Value constructors.
        globals_dict["Some"] = Some
        globals_dict["Ok"] = Ok
        globals_dict["Err"] = Err
        globals_dict["None"] = None
        globals_dict["Unit"] = UNIT
        globals_dict["secret"] = lambda value, label="secret": secret(
            value, label=label, guard=self.secrets
        )
        globals_dict["reveal"] = reveal

        # Runtime access for generated helpers.
        globals_dict["__happy_ctx__"] = self
        globals_dict["__happy_contracts__"] = self.contracts
        globals_dict["__happy_caps__"] = self.capabilities
        globals_dict["__happy_call__"] = _happy_call

        # Sensitive builtins are available without an explicit import (they are
        # listed in the compiler's ENFORCEMENT_MAP); each is capability-gated.
        from ..std import io as _std_io

        _std_io.use_checker(self.capabilities)
        for _n in (
            "read_file",
            "write_file",
            "append_file",
            "file_exists",
            "http_get",
            "http_post",
        ):
            globals_dict.setdefault(_n, getattr(_std_io, _n))

        # User imports: ``import std.io`` -> install its public functions.
        self._install_imports(globals_dict, imports or getattr(self.module, "imports", []))
    def _install_imports(self, globals_dict: Dict[str, Any], imports: Any) -> None:
        import importlib

        for imp in imports or []:
            modname = getattr(imp, "module", None)
            if not modname or not modname.startswith("std."):
                continue
            short = modname.split(".", 1)[1]
            try:
                std_mod = importlib.import_module(f"happy.std.{short}")
            except Exception:  # pragma: no cover - unknown std module
                continue
            # Share this context's capability checker with the std module so
            # sensitive std operations are enforced at runtime.
            use_checker = getattr(std_mod, "use_checker", None)
            if callable(use_checker):
                use_checker(self.capabilities)
            names = getattr(imp, "symbols", []) or []
            public = getattr(std_mod, "PUBLIC", None)
            if names:
                for n in names:
                    if hasattr(std_mod, n):
                        globals_dict[n] = _bind_ctx_value(getattr(std_mod, n), self)
            elif public:
                for n in public:
                    globals_dict[n] = _bind_ctx_value(getattr(std_mod, n), self)

    # -- execution ------------------------------------------------------
    def run(self, target: Any, *args: Any, **kwargs: Any) -> RunResult:
        """Run ``target`` (a coroutine, async fn or plain callable) to completion."""
        import time

        global _ACTIVE_CONTEXT
        # Remember whichever context was active so a nested run (a program
        # that runs another program) restores it instead of clearing it --
        # clearing would silently disable the outer run's capability gate.
        _previous_context = _ACTIVE_CONTEXT
        _ACTIVE_CONTEXT = self
        _restore_std = _rebind_std_checkers(self.capabilities)
        start = time.perf_counter()
        watchdog = self._start_watchdog()
        memory_guard = self._start_memory_guard()
        try:
            result = self._invoke(target, args, kwargs)
        except HappyRuntimeError as err:
            self._enrich(err)
            return RunResult(
                ok=False,
                error=err,
                output=self.output,
                error_output=self.error_output,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )
        except BaseException as exc:  # noqa: BLE001 - translate everything
            err = translate_python_error(
                exc,
                filename=self.filename,
                source=self.source,
                location=self._python_location(exc),
            )
            self._enrich(err, exc)
            return RunResult(
                ok=False,
                error=err,
                output=self.output,
                error_output=self.error_output,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )
        finally:
            self._stop_watchdog(watchdog)
            if memory_guard is not None:
                memory_guard.stop()
            _ACTIVE_CONTEXT = _previous_context
            _restore_std()
        return RunResult(
            ok=True,
            value=result,
            output=self.output,
            error_output=self.error_output,
            duration_ms=(time.perf_counter() - start) * 1000.0,
        )

    # -- timeout watchdog ----------------------------------------------
    def _start_watchdog(self) -> Optional[threading.Timer]:
        """Start a timer that aborts the run once ``self.timeout`` elapses."""
        if not self.timeout or self.timeout <= 0:
            return None
        target_id = threading.get_ident()
        seconds = float(self.timeout)

        def _fire() -> None:
            _raise_in_thread(target_id, _RunTimeout)

        timer = threading.Timer(seconds, _fire)
        timer.daemon = True
        timer.start()
        return timer

    def _start_memory_guard(self) -> Optional[_MemoryGuard]:
        if not self.max_memory_mb or self.max_memory_mb <= 0:
            return None
        guard = _MemoryGuard(threading.get_ident(), self.max_memory_mb)
        guard.start()
        return guard

    @staticmethod
    def _stop_watchdog(timer: Optional[threading.Timer]) -> None:
        if timer is not None:
            timer.cancel()

    def _invoke(self, target: Any, args: Any, kwargs: Any) -> Any:
        import inspect

        if inspect.iscoroutine(target):
            return self.scheduler.run(target)
        if inspect.iscoroutinefunction(target):
            return self.scheduler.run(target(*args, **kwargs))
        # A plain function; a returned coroutine is still driven to completion.
        result = target(*args, **kwargs)
        if inspect.iscoroutine(result):
            return self.scheduler.run(result)
        return result

    # -- error enrichment (sourcemap + traceback) ----------------------
    def _python_location(self, exc: BaseException) -> Optional[object]:
        tb = exc.__traceback__
        # Find the innermost generated frame (it carries the sourcemap).
        location = None
        while tb is not None:
            filename = tb.tb_frame.f_code.co_filename
            if filename == "<happy-generated>" or filename.endswith(".hpy.py"):
                location = self.resolve_location(tb.tb_lineno)
            tb = tb.tb_next
        return location

    def _enrich(self, err: HappyRuntimeError, exc: Optional[BaseException] = None) -> None:
        if err.filename is None:
            err.filename = self.filename
        if err.source is None:
            err.source = self.source
        if err.location is None:
            src_exc = exc or err.cause
            if src_exc is not None:
                err.location = self._python_location(src_exc)
        if not err.happy_trace:
            err.happy_trace = self._happy_trace()

    def _happy_trace(self) -> List[Any]:
        """Best-effort Happy call stack derived from the Python stack."""
        trace: List[Any] = []
        frame = sys._getframe(1)
        while frame is not None:
            if frame.f_code.co_filename == "<happy-generated>":
                name = frame.f_code.co_name
                loc = self.resolve_location(frame.f_lineno)
                trace.append((name, loc))
            frame = frame.f_back
        return list(reversed(trace))

    # -- misc -----------------------------------------------------------
    @property
    def ok(self) -> bool:
        return self.contracts.ok and self.capabilities.ok

    def summary(self) -> str:
        return (
            f"contracts: {self.contracts.summary()}; "
            f"capabilities: {self.capabilities.summary()}; "
            f"secrets revealed: {self.secrets.reveal_count}"
        )


def _bind_ctx(fn: Callable, ctx: RuntimeContext) -> Callable:
    """Return a wrapper that injects ``__ctx__=ctx`` into a builtin call."""
    import functools

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        kwargs.setdefault("__ctx__", ctx)
        return fn(*args, **kwargs)

    return wrapper


def _bind_ctx_value(value: Any, ctx: RuntimeContext) -> Any:
    if callable(value) and not isinstance(value, type):
        # std functions accept ``__ctx__``; plain callables are passed through.
        code = getattr(value, "__code__", None)
        if code is not None and "__ctx__" in code.co_varnames:
            return _bind_ctx(value, ctx)
    return value


def _rebind_std_checkers(checker: Any) -> Callable[[], None]:
    """Point every loaded ``happy.std.*`` module at ``checker``.

    Returns a callable that restores the previous checkers.  Std modules keep
    their checker in a module global, so without this a nested run (or a run
    that starts after another context was built) would be authorised against
    the *wrong* context's capabilities.
    """
    previous: List[Tuple[Any, Any]] = []
    for name, mod in list(sys.modules.items()):
        if not name.startswith("happy.std.") or mod is None:
            continue
        if callable(getattr(mod, "use_checker", None)) and hasattr(mod, "_CHECKER"):
            previous.append((mod, getattr(mod, "_CHECKER")))
            mod.use_checker(checker)

    def _restore() -> None:
        for mod, old in previous:
            mod._CHECKER = old

    return _restore


#: The context currently executing (used by generated secret wrapping).
_ACTIVE_CONTEXT: Optional[RuntimeContext] = None


def _bind_secret_guard() -> Optional[SecretGuard]:
    """Return the active context's secret guard (or ``None`` outside a run)."""
    if _ACTIVE_CONTEXT is not None:
        return _ACTIVE_CONTEXT.secrets
    return None


def _happy_call(fn: Callable, operation: str, agent: Optional[str], loc: Any, *args: Any, **kwargs: Any) -> Any:
    """Capability-gated call used by generated code for sensitive operations.

    The backend rewrites ``write_file(p, data)`` inside an agent into
    ``__happy_call__(write_file, 'write_file', 'Agent', (file, line, col), p, data)``.
    This checks the operation against the active capability checker and then
    invokes the real callee, so the call is never skipped.
    """
    ctx = _ACTIVE_CONTEXT
    if ctx is None:
        # Fail closed: a capability-gated call that is not running inside a
        # RuntimeContext has no checker to consult, so it must not proceed.
        from .errors import CapabilityDenied

        raise CapabilityDenied(
            message=(
                f"capability denied: '{operation}' was invoked with no active "
                "runtime context to authorise it"
            ),
            location=loc,
            suggestion="run the program through RuntimeContext.run()",
        )
    ctx.capabilities.check_operation(operation, agent=agent, loc=loc)
    return fn(*args, **kwargs)
