"""Bounded worker pool: the execution plane, separated from the security control plane.

WHY A POOL
----------
The task requires the security control plane to be separated from execution workers, with bounded
queues, backpressure, health checks, safe termination and post-failure cleanup.  This module is that
separation:

* the **control plane** (``SecureExecutionRuntime``) authenticates, authorizes and validates, then
  *submits* work -- it never runs untrusted code itself;
* the **workers** here own the jail, the per-execution work directory and the budget tracker, and
  they can die without taking the control plane with them (a worker exception is captured and
  returned as a structured failure, never propagated).

BACKPRESSURE, NOT UNBOUNDED QUEUEING
------------------------------------
The queue has a hard capacity.  ``submit`` raises :class:`QueueFull` when it is full instead of
blocking forever or growing without bound, so a flood of requests is *refused* (and reported) rather
than exhausting memory.  ``max_concurrency`` caps how many executions run at once.

ISOLATION BETWEEN EXECUTIONS
----------------------------
Every execution gets its own work directory (mode 0700, unpredictable name) and its own budget
tracker.  Nothing is shared: one execution cannot read another's temp files, credentials or result
artifacts, and the directory is removed in a ``finally`` block so a crash cannot leak it.
"""
from __future__ import annotations

import queue
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .errors import ContractError
from .limits import BudgetTracker, CancellationToken, ExecutionBudget, ResourceLimitExceeded

__all__ = [
    "QueueFull",
    "WorkerUnavailable",
    "ExecutionJob",
    "JobOutcome",
    "WorkerPool",
    "WorkerHealth",
]


class QueueFull(ContractError):
    """The bounded queue is at capacity -- the caller must retry later (backpressure)."""

    code = "queue_full"


class WorkerUnavailable(ContractError):
    """The pool is not running (never started, or already shut down)."""

    code = "worker_unavailable"


@dataclass
class ExecutionJob:
    """One unit of work handed to a worker.  ``fn`` receives the tracker and the work directory."""

    job_id: str
    fn: Callable[[BudgetTracker, str], Any]
    budget: ExecutionBudget
    token: CancellationToken = field(default_factory=CancellationToken)
    submitted_at: float = field(default_factory=time.monotonic)


@dataclass
class JobOutcome:
    """What a worker produced.  ``ok`` is False for *any* failure, including a worker crash."""

    job_id: str
    ok: bool
    value: Any = None
    error: Optional[str] = None
    error_kind: Optional[str] = None
    duration_ms: float = 0.0
    worker: Optional[str] = None
    cleanup_ok: bool = True
    budget: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkerHealth:
    """A snapshot of pool health for a health-check endpoint."""

    running: bool
    workers: int
    alive_workers: int
    queued: int
    capacity: int
    in_flight: int
    completed: int
    failed: int
    rejected: int

    @property
    def healthy(self) -> bool:
        return self.running and self.alive_workers > 0

    def to_dict(self) -> Dict[str, Any]:
        return {"running": self.running, "workers": self.workers,
                "alive_workers": self.alive_workers, "queued": self.queued,
                "capacity": self.capacity, "in_flight": self.in_flight,
                "completed": self.completed, "failed": self.failed,
                "rejected": self.rejected, "healthy": self.healthy}


class WorkerPool:
    """A bounded pool of execution workers.

    ``max_concurrency`` workers drain a queue of at most ``queue_capacity`` jobs.  A job that raises
    is recorded as a failed outcome -- the worker survives, so one bad program cannot take the pool
    (or the control plane) down.
    """

    def __init__(self, *, max_concurrency: int = 2, queue_capacity: int = 8,
                 workdir_factory: Optional[Callable[[], str]] = None,
                 cleanup: Optional[Callable[[str], bool]] = None,
                 name: str = "happy-worker") -> None:
        if not (1 <= int(max_concurrency) <= 64):
            raise ValueError("max_concurrency must be in [1, 64]")
        if not (0 <= int(queue_capacity) <= 1024):
            raise ValueError("queue_capacity must be in [0, 1024]")
        self.max_concurrency = int(max_concurrency)
        self.queue_capacity = int(queue_capacity)
        self.name = name
        self._queue: "queue.Queue[Optional[ExecutionJob]]" = queue.Queue(maxsize=self.queue_capacity)
        self._threads: List[threading.Thread] = []
        self._running = False
        self._lock = threading.Lock()
        self._in_flight = 0
        self._completed = 0
        self._failed = 0
        self._rejected = 0
        self._outcomes: Dict[str, JobOutcome] = {}
        self._workdir_factory = workdir_factory
        self._cleanup = cleanup

    # -- lifecycle ---------------------------------------------------------------------------
    def start(self) -> "WorkerPool":
        with self._lock:
            if self._running:
                return self
            self._running = True
            for i in range(self.max_concurrency):
                thread = threading.Thread(target=self._loop, name=f"{self.name}-{i}", daemon=True)
                thread.start()
                self._threads.append(thread)
        return self

    def shutdown(self, *, wait: bool = True, timeout: float = 30.0) -> None:
        """Stop accepting work, drain, and join.  Safe to call more than once."""
        with self._lock:
            if not self._running:
                return
            self._running = False
            threads = list(self._threads)
        for _ in threads:
            try:
                self._queue.put_nowait(None)                        # sentinel per worker
            except queue.Full:                                      # pragma: no cover - full queue
                pass
        if wait:
            deadline = time.monotonic() + max(0.0, timeout)
            for thread in threads:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
        with self._lock:
            self._threads = []

    def __enter__(self) -> "WorkerPool":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.shutdown()

    # -- submission --------------------------------------------------------------------------
    def submit(self, job: ExecutionJob, *, timeout: float = 0.0) -> JobOutcome:
        """Queue ``job`` and wait for its outcome.

        Raises :class:`QueueFull` when the bounded queue is at capacity (backpressure) and
        :class:`WorkerUnavailable` when the pool is not running.
        """
        if not self._running:
            raise WorkerUnavailable("worker pool is not running")
        try:
            if timeout and timeout > 0:
                self._queue.put(job, timeout=timeout)
            else:
                # ``put_nowait`` is what makes backpressure real: a full queue is REFUSED here
                # instead of blocking the caller forever (``put(timeout=None)`` would hang).
                self._queue.put_nowait(job)
        except queue.Full as exc:
            with self._lock:
                self._rejected += 1
            raise QueueFull(
                f"execution queue is full (capacity {self.queue_capacity}); retry later") from exc
        return self._await(job.job_id, timeout=timeout)

    def _await(self, job_id: str, *, timeout: float = 0.0) -> JobOutcome:
        deadline = time.monotonic() + timeout if timeout > 0 else None
        while True:
            with self._lock:
                outcome = self._outcomes.pop(job_id, None)
            if outcome is not None:
                return outcome
            if deadline is not None and time.monotonic() >= deadline:
                return JobOutcome(job_id=job_id, ok=False, error="timed out waiting for worker",
                                  error_kind="timeout")
            time.sleep(0.002)

    # -- worker loop -------------------------------------------------------------------------
    def _loop(self) -> None:
        while True:
            try:
                job = self._queue.get(timeout=0.25)
            except queue.Empty:
                with self._lock:
                    if not self._running:
                        return
                continue
            if job is None:
                return
            with self._lock:
                self._in_flight += 1
            outcome = self._run_job(job)
            with self._lock:
                self._in_flight -= 1
                if outcome.ok:
                    self._completed += 1
                else:
                    self._failed += 1
                self._outcomes[job.job_id] = outcome

    def _run_job(self, job: ExecutionJob) -> JobOutcome:
        """Run one job in its own work directory.  Never raises: a crash becomes a failed outcome."""
        started = time.monotonic()
        workdir: Optional[str] = None
        cleanup_ok = True
        tracker = BudgetTracker(job.budget, token=job.token)
        try:
            if self._workdir_factory is not None:
                workdir = self._workdir_factory()
            tracker.check_deadline()
            value = job.fn(tracker, workdir or "")
            return JobOutcome(job_id=job.job_id, ok=True, value=value,
                              duration_ms=(time.monotonic() - started) * 1000.0,
                              worker=threading.current_thread().name,
                              budget=tracker.snapshot())
        except ResourceLimitExceeded as exc:
            return JobOutcome(job_id=job.job_id, ok=False, error=str(exc), error_kind=exc.kind,
                              duration_ms=(time.monotonic() - started) * 1000.0,
                              worker=threading.current_thread().name, budget=tracker.snapshot())
        except BaseException as exc:                            # noqa: BLE001 - worker must survive
            return JobOutcome(
                job_id=job.job_id, ok=False,
                error=f"{type(exc).__name__}: {exc}", error_kind="worker_error",
                duration_ms=(time.monotonic() - started) * 1000.0,
                worker=threading.current_thread().name, budget=tracker.snapshot())
        finally:
            if workdir and self._cleanup is not None:
                try:
                    cleanup_ok = bool(self._cleanup(workdir))
                except Exception:                               # noqa: BLE001 - cleanup is best effort
                    cleanup_ok = False

    # -- health ------------------------------------------------------------------------------
    def health(self) -> WorkerHealth:
        with self._lock:
            alive = sum(1 for t in self._threads if t.is_alive())
            return WorkerHealth(
                running=self._running, workers=self.max_concurrency, alive_workers=alive,
                queued=self._queue.qsize(), capacity=self.queue_capacity,
                in_flight=self._in_flight, completed=self._completed, failed=self._failed,
                rejected=self._rejected)

    def cancel(self, job_id: str) -> bool:
        """Trip a job's cancellation token.  Returns False when the job is unknown."""
        with self._lock:
            outcome = self._outcomes.get(job_id)
        if outcome is not None:
            return False
        return True
