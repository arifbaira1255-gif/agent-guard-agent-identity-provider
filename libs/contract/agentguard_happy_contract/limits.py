"""Strict execution budgets and cancellation for the integrated runtime.

Every limit here is a *real* control, not a declaration: the tracker is consulted at the point of
use, and exceeding a budget raises :class:`ResourceLimitExceeded` which the worker converts into a
structured :data:`~agentguard_happy_contract.models.ResultKind.RESOURCE_LIMIT` result.

Limits provided (the task's list):

* **wall-clock timeout** -- a monotonic deadline, re-checked at every enforcement point and
  enforced by the process-level watchdog for the out-of-process worker.
* **CPU / memory** -- carried into the isolation/rlimit layer (see ``isolation.py``); the in-process
  tracker additionally bounds allocation growth via the output and operation counters.
* **output-size** -- every byte the program emits is charged here, so a runaway ``println`` loop
  cannot exhaust memory or the transport.
* **concurrency** -- enforced by the worker pool (``worker.py``), which refuses to exceed the
  configured cap and applies backpressure instead of unbounded queueing.
* **max tool calls / max operations** -- a single counter with two ceilings, so a program that polls
  a sensitive tool in a loop is stopped rather than silently allowed to run.
* **cancellation** -- a thread-safe token that any control-plane call may trip; every enforcement
  point checks it, so a cancelled run stops at the next check and never leaves a protected
  operation half-done.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .errors import ContractError

__all__ = [
    "ResourceLimitExceeded",
    "CancellationToken",
    "ExecutionBudget",
    "BudgetTracker",
    "LIMIT_KINDS",
]

#: The limit kinds a caller may see in a structured result.
LIMIT_KINDS = ("timeout", "memory", "output", "operations", "tool_calls", "concurrency",
               "cancelled")


class ResourceLimitExceeded(ContractError):
    """A budget was exceeded.  ``kind`` is one of :data:`LIMIT_KINDS`.

    This is a *structured* failure: the worker maps it onto the right
    :class:`~agentguard_happy_contract.models.ResultKind` (``resource_limit`` or ``timeout``) and
    reports the kind, so the caller can distinguish a slow program from a hostile one.
    """

    code = "resource_limit_exceeded"

    def __init__(self, kind: str, message: str = "", *, limit: Optional[float] = None,
                 observed: Optional[float] = None) -> None:
        self.kind = kind if kind in LIMIT_KINDS else "operations"
        self.limit = limit
        self.observed = observed
        super().__init__(message or f"{self.kind} limit exceeded", field=self.kind)


class CancellationToken:
    """A thread-safe, one-way cancellation signal shared with a worker.

    ``cancel()`` is idempotent and safe to call from the control plane at any time; ``raise_if_set``
    is the enforcement point workers call between steps so a cancelled run terminates promptly and
    predictably.
    """

    __slots__ = ("_event", "_reason")

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason: Optional[str] = None

    def cancel(self, reason: str = "cancelled by control plane") -> None:
        self._reason = reason or "cancelled"
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> Optional[str]:
        return self._reason

    def raise_if_set(self) -> None:
        if self._event.is_set():
            raise ResourceLimitExceeded("cancelled", self._reason or "cancelled")

    # An already-cancelled token is easy to build for the "cancel before start" case.
    @classmethod
    def pre_cancelled(cls, reason: str = "cancelled before start") -> "CancellationToken":
        token = cls()
        token.cancel(reason)
        return token


@dataclass(frozen=True)
class ExecutionBudget:
    """The ceilings for one execution.  Mirrors the request's ``limits`` plus runtime-only caps."""

    wall_clock_s: float = 10.0
    cpu_s: Optional[float] = None
    memory_mb: Optional[float] = 256.0
    output_bytes: int = 1_048_576
    max_operations: int = 100_000
    max_tool_calls: int = 1_000
    max_concurrency: int = 1
    queue_capacity: int = 8

    def validate(self) -> None:
        problems = []
        if not (0 < float(self.wall_clock_s) <= 300.0):
            problems.append("wall_clock_s must be in (0, 300]")
        if self.cpu_s is not None and not (0 < float(self.cpu_s) <= 300.0):
            problems.append("cpu_s must be in (0, 300]")
        if self.memory_mb is not None and not (1 <= float(self.memory_mb) <= 4096):
            problems.append("memory_mb must be in [1, 4096]")
        if not (1 <= int(self.output_bytes) <= 8 * 1024 * 1024):
            problems.append("output_bytes must be in [1, 8388608]")
        if not (1 <= int(self.max_operations) <= 1_000_000):
            problems.append("max_operations must be in [1, 1000000]")
        if not (1 <= int(self.max_tool_calls) <= 100_000):
            problems.append("max_tool_calls must be in [1, 100000]")
        if not (1 <= int(self.max_concurrency) <= 64):
            problems.append("max_concurrency must be in [1, 64]")
        if not (0 <= int(self.queue_capacity) <= 1024):
            problems.append("queue_capacity must be in [0, 1024]")
        if problems:
            from .errors import ValidationError

            raise ValidationError("invalid execution budget", errors=problems)


class BudgetTracker:
    """Enforce one :class:`ExecutionBudget` for one execution.

    A single instance belongs to a single execution: sharing one across executions would let one
    program spend another's budget, so the worker builds a fresh tracker per run.
    """

    def __init__(self, budget: ExecutionBudget, *, clock: Callable[[], float] = time.monotonic,
                 token: Optional[CancellationToken] = None) -> None:
        budget.validate()
        self.budget = budget
        self._clock = clock
        self._token = token or CancellationToken()
        self._started = clock()
        self._operations = 0
        self._tool_calls = 0
        self._output_bytes = 0
        self._lock = threading.Lock()

    # -- accessors ---------------------------------------------------------------------------
    @property
    def token(self) -> CancellationToken:
        return self._token

    @property
    def elapsed_s(self) -> float:
        return max(0.0, self._clock() - self._started)

    @property
    def remaining_s(self) -> float:
        return max(0.0, float(self.budget.wall_clock_s) - self.elapsed_s)

    @property
    def operations(self) -> int:
        return self._operations

    @property
    def tool_calls(self) -> int:
        return self._tool_calls

    @property
    def output_bytes(self) -> int:
        return self._output_bytes

    # -- enforcement -------------------------------------------------------------------------
    def check_deadline(self) -> None:
        """Raise when the wall clock is spent or the run was cancelled."""
        self._token.raise_if_set()
        if self.elapsed_s >= float(self.budget.wall_clock_s):
            raise ResourceLimitExceeded(
                "timeout",
                f"wall-clock budget of {self.budget.wall_clock_s}s exceeded",
                limit=float(self.budget.wall_clock_s), observed=self.elapsed_s)

    def charge_operation(self, n: int = 1) -> None:
        """Count a program step.  Raises ``operations`` when the ceiling is passed."""
        self.check_deadline()
        with self._lock:
            self._operations += int(n)
            observed = self._operations
        if observed > int(self.budget.max_operations):
            raise ResourceLimitExceeded(
                "operations",
                f"operation budget of {self.budget.max_operations} exceeded",
                limit=float(self.budget.max_operations), observed=float(observed))

    def charge_tool_call(self, n: int = 1) -> None:
        """Count a *protected* operation (a tool call).  This is the security-relevant counter."""
        self.check_deadline()
        with self._lock:
            self._tool_calls += int(n)
            observed = self._tool_calls
        if observed > int(self.budget.max_tool_calls):
            raise ResourceLimitExceeded(
                "tool_calls",
                f"tool-call budget of {self.budget.max_tool_calls} exceeded",
                limit=float(self.budget.max_tool_calls), observed=float(observed))

    def charge_output(self, n: int) -> None:
        """Count emitted bytes.  Raises ``output`` before the buffer can grow without bound."""
        with self._lock:
            self._output_bytes += max(0, int(n))
            observed = self._output_bytes
        if observed > int(self.budget.output_bytes):
            raise ResourceLimitExceeded(
                "output",
                f"output budget of {self.budget.output_bytes} bytes exceeded",
                limit=float(self.budget.output_bytes), observed=float(observed))

    def snapshot(self) -> dict:
        return {
            "elapsed_s": round(self.elapsed_s, 6),
            "remaining_s": round(self.remaining_s, 6),
            "operations": self._operations,
            "tool_calls": self._tool_calls,
            "output_bytes": self._output_bytes,
            "limits": {
                "wall_clock_s": float(self.budget.wall_clock_s),
                "max_operations": int(self.budget.max_operations),
                "max_tool_calls": int(self.budget.max_tool_calls),
                "output_bytes": int(self.budget.output_bytes),
                "memory_mb": self.budget.memory_mb,
                "max_concurrency": int(self.budget.max_concurrency),
            },
            "cancelled": self._token.cancelled,
        }
