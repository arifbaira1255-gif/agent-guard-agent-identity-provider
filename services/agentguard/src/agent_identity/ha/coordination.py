"""Multi-instance coordination for scheduled security jobs (Step 7).

Design rule: **do not introduce distributed locks where DB transactions or idempotent operations
suffice.** This module is used ONLY for the jobs that genuinely must not run twice concurrently
across replicas:

  * ``purge_expired_material``  — delete service-held ephemeral keys of expired/revoked credentials
  * ``purge_idempotency``       — bounded retention of the idempotency ledger
  * ``reconcile``               — periodic consistency check (orphaned orgs, expired credentials)

Serialisation uses a PostgreSQL **session advisory lock** (``pg_try_advisory_lock``) held on a
dedicated connection for the duration of the job. This is stronger than a Redis lock: it is tied
to the database that owns the authoritative state, it is released automatically if the instance
dies (connection drop), and it cannot be lost by a Redis failover. A job that cannot take the lock
is simply SKIPPED on this instance — another replica is already running it.

Every job is also written to ``coordination_jobs`` so operators can see which instance last ran it
and whether it succeeded. The ledger is bookkeeping only; correctness never depends on it.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from ..spiffe import metrics as _M

log = logging.getLogger("agentguard.coordination")

JOB_RUNS = "agentguard_coordination_job_runs_total"
JOB_SKIPPED = "agentguard_coordination_job_skipped_total"
JOB_FAILURES = "agentguard_coordination_job_failures_total"
JOB_LATENCY = "agentguard_coordination_job_latency_seconds"
JOB_LAST_SUCCESS = "agentguard_coordination_job_last_success_timestamp"

#: stable advisory-lock keys (arbitrary constants; one per job name)
_LOCK_KEYS = {
    "purge_expired_material": 7_424_101,
    "purge_idempotency": 7_424_102,
    "reconcile": 7_424_103,
}


@dataclass(frozen=True)
class JobResult:
    name: str
    ran: bool
    status: str            # ok | failed | skipped
    detail: str = ""
    value: int = 0


class CoordinationRunner:
    """Runs named jobs under a PostgreSQL advisory lock, recording the outcome.

    ``db`` is the existing ``storage.postgres.db.Database``. The lock is taken on a single pooled
    connection for the whole job; if the pool cannot give one, the job is skipped (never run
    unlocked).
    """

    def __init__(self, db, *, instance_id: str, metrics: Optional[_M.Metrics] = None,
                 clock: Callable[[], float] = time.time):
        self.db = db
        self.instance_id = instance_id
        self.metrics = metrics or _M.Metrics()
        self._clock = clock
        self._l = threading.Lock()

    # ------------------------------------------------------------------ lock helpers
    def _try_lock(self, conn, key: int) -> bool:
        return bool(conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (key,)).fetchone()["ok"])

    def _unlock(self, conn, key: int) -> None:
        try:
            conn.execute("SELECT pg_advisory_unlock(%s)", (key,))
        except Exception:  # noqa: BLE001 - connection may already be gone; lock dies with it
            pass

    # ------------------------------------------------------------------ run
    def run(self, name: str, fn: Callable[[], int], *, lock_key: Optional[int] = None) -> JobResult:
        """Run ``fn`` under the advisory lock for ``name``. ``fn`` returns an int (e.g. rows purged)."""
        key = lock_key if lock_key is not None else _LOCK_KEYS.get(name)
        if key is None:
            raise ValueError(f"no advisory-lock key registered for job {name!r}")
        t0 = time.perf_counter()
        with self._l:                       # one job at a time per process (cheap, avoids self-contention)
            try:
                with self.db._pool.connection() as conn:      # dedicated connection holds the lock
                    if not self._try_lock(conn, key):
                        self.metrics.inc(JOB_SKIPPED, name)
                        self._record(name, "skipped", "another instance holds the lock", 0)
                        return JobResult(name, ran=False, status="skipped",
                                         detail="another instance holds the lock")
                    try:
                        value = int(fn())
                    finally:
                        self._unlock(conn, key)
                self.metrics.inc(JOB_RUNS, name)
                self.metrics.observe(JOB_LATENCY, time.perf_counter() - t0)
                self.metrics.inc(JOB_LAST_SUCCESS, name, int(self._clock()))
                self._record(name, "ok", "", value)
                return JobResult(name, ran=True, status="ok", value=value)
            except Exception as e:  # noqa: BLE001 - a failed job must never crash the caller
                self.metrics.inc(JOB_FAILURES, name)
                log.warning("coordination job %s failed type=%s", name, type(e).__name__)
                self._record(name, "failed", type(e).__name__, 0)
                return JobResult(name, ran=False, status="failed", detail=type(e).__name__)

    def _record(self, name: str, status: str, detail: str, value: int) -> None:
        now = self._clock()
        try:
            self.db.run("coord_record", lambda c: c.execute(
                "INSERT INTO coordination_jobs (job_name, last_started_at, last_finished_at,"
                " last_status, last_instance, last_detail, run_count)"
                " VALUES (%s,%s,%s,%s,%s,%s,1)"
                " ON CONFLICT (job_name) DO UPDATE SET last_started_at=EXCLUDED.last_started_at,"
                " last_finished_at=EXCLUDED.last_finished_at, last_status=EXCLUDED.last_status,"
                " last_instance=EXCLUDED.last_instance, last_detail=EXCLUDED.last_detail,"
                " run_count=coordination_jobs.run_count + 1",
                (name, now, now, status, self.instance_id, detail[:256])))
        except Exception:  # noqa: BLE001 - bookkeeping must never break the job result
            log.warning("could not record coordination job %s", name)

    def status(self) -> Dict[str, dict]:
        """Operator view of the coordination ledger (no secrets)."""
        try:
            rows = self.db.run("coord_status", lambda c: c.execute(
                "SELECT job_name, last_finished_at, last_status, last_instance, run_count"
                " FROM coordination_jobs ORDER BY job_name").fetchall())
        except Exception:  # noqa: BLE001
            return {}
        return {r["job_name"]: {"last_finished_at": r["last_finished_at"], "last_status": r["last_status"],
                                "last_instance": r["last_instance"], "run_count": r["run_count"]}
                for r in rows}


class PeriodicScheduler:
    """Runs a set of jobs on a fixed interval in a background daemon thread.

    Each tick calls ``runner.run`` for every job; the advisory lock makes duplicate execution across
    replicas impossible, so it is safe for every replica to run the same schedule. The first tick is
    delayed by ``initial_delay_seconds`` so a rolling restart does not stampede the database.
    """

    def __init__(self, runner: CoordinationRunner, jobs: Dict[str, Callable[[], int]], *,
                 interval_seconds: float = 300.0, initial_delay_seconds: float = 30.0,
                 sleep: Callable[[float], None] = time.sleep):
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        self.runner, self.jobs = runner, dict(jobs)
        self.interval, self.initial_delay = interval_seconds, initial_delay_seconds
        self._sleep = sleep
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "PeriodicScheduler":
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="coordination", daemon=True)
            self._thread.start()
        return self

    def _loop(self):
        if self._stop.wait(self.initial_delay):
            return
        while not self._stop.is_set():
            for name, fn in self.jobs.items():
                if self._stop.is_set():
                    break
                self.runner.run(name, fn)
            self._stop.wait(self.interval)

    def run_once(self) -> Dict[str, JobResult]:
        return {name: self.runner.run(name, fn) for name, fn in self.jobs.items()}

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
