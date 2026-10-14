"""Tests for the bounded worker pool: backpressure, health, crash survival, cleanup."""
from __future__ import annotations

import os
import threading
import time

import pytest

from agentguard_happy_contract.isolation import cleanup_workdir, make_workdir
from agentguard_happy_contract.limits import ExecutionBudget, ResourceLimitExceeded
from agentguard_happy_contract.worker_pool import (
    ExecutionJob,
    QueueFull,
    WorkerPool,
    WorkerUnavailable,
)


def _pool(**kwargs) -> WorkerPool:
    kwargs.setdefault("max_concurrency", 1)
    kwargs.setdefault("queue_capacity", 4)
    kwargs.setdefault("workdir_factory", make_workdir)
    kwargs.setdefault("cleanup", cleanup_workdir)
    return WorkerPool(**kwargs).start()


class TestLifecycle:
    def test_submit_returns_the_job_value(self):
        with _pool() as pool:
            outcome = pool.submit(ExecutionJob(job_id="j1", fn=lambda t, w: "done",
                                               budget=ExecutionBudget()))
        assert outcome.ok is True and outcome.value == "done"

    def test_submit_before_start_is_refused(self):
        pool = WorkerPool(max_concurrency=1, queue_capacity=1)
        with pytest.raises(WorkerUnavailable):
            pool.submit(ExecutionJob(job_id="j1", fn=lambda t, w: None,
                                     budget=ExecutionBudget()))

    def test_shutdown_is_idempotent(self):
        pool = _pool()
        pool.shutdown()
        pool.shutdown()
        assert pool.health().running is False


class TestBackpressure:
    def test_full_queue_is_refused_rather_than_growing(self):
        """A flood must be refused (and reported), never queued without bound."""
        release = threading.Event()
        pool = _pool(max_concurrency=1, queue_capacity=1)
        try:
            blocker = threading.Thread(
                target=lambda: pool.submit(ExecutionJob(
                    job_id="block", fn=lambda t, w: release.wait(5), budget=ExecutionBudget())))
            blocker.start()
            deadline = time.monotonic() + 3
            while pool.health().in_flight == 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            queued = threading.Thread(
                target=lambda: pool.submit(ExecutionJob(
                    job_id="queued", fn=lambda t, w: None, budget=ExecutionBudget())))
            queued.start()
            deadline = time.monotonic() + 3
            while pool.health().queued == 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            with pytest.raises(QueueFull):
                pool.submit(ExecutionJob(job_id="overflow", fn=lambda t, w: None,
                                         budget=ExecutionBudget()))
            assert pool.health().rejected == 1
            release.set()
            blocker.join(timeout=5)
            queued.join(timeout=5)
        finally:
            release.set()
            pool.shutdown()


class TestCrashSurvival:
    def test_a_raising_job_does_not_kill_the_worker(self):
        with _pool() as pool:
            bad = pool.submit(ExecutionJob(job_id="bad", fn=_boom, budget=ExecutionBudget()))
            assert bad.ok is False and bad.error_kind == "worker_error"
            good = pool.submit(ExecutionJob(job_id="good", fn=lambda t, w: "alive",
                                            budget=ExecutionBudget()))
            assert good.ok is True and good.value == "alive"
            assert pool.health().healthy is True

    def test_a_budget_breach_is_reported_with_its_kind(self):
        with _pool() as pool:
            outcome = pool.submit(ExecutionJob(job_id="limit", fn=_spend, budget=ExecutionBudget(
                max_operations=1)))
        assert outcome.ok is False and outcome.error_kind == "operations"

    def test_health_reports_counters(self):
        with _pool() as pool:
            pool.submit(ExecutionJob(job_id="a", fn=lambda t, w: None, budget=ExecutionBudget()))
            pool.submit(ExecutionJob(job_id="b", fn=_boom, budget=ExecutionBudget()))
            health = pool.health()
        assert health.completed == 1 and health.failed == 1
        assert health.healthy is True
        assert health.to_dict()["capacity"] == 4


class TestIsolationBetweenExecutions:
    def test_each_execution_gets_its_own_workdir_and_it_is_cleaned_up(self):
        seen = []

        def record(tracker, workdir):
            seen.append(workdir)
            assert os.path.isdir(workdir)
            return workdir

        with _pool() as pool:
            first = pool.submit(ExecutionJob(job_id="1", fn=record, budget=ExecutionBudget()))
            second = pool.submit(ExecutionJob(job_id="2", fn=record, budget=ExecutionBudget()))
        assert first.value != second.value
        assert len(set(seen)) == 2
        for path in seen:
            assert not os.path.exists(path), "work directory leaked after the run"

    def test_workdir_is_cleaned_up_even_when_the_job_crashes(self):
        seen = []

        def crash(tracker, workdir):
            seen.append(workdir)
            raise RuntimeError("boom")

        with _pool() as pool:
            pool.submit(ExecutionJob(job_id="c", fn=crash, budget=ExecutionBudget()))
        assert seen and not os.path.exists(seen[0])


def _boom(tracker, workdir):
    raise RuntimeError("intentional failure")


def _spend(tracker, workdir):
    tracker.charge_operation()
    tracker.charge_operation()
    raise AssertionError("should have raised ResourceLimitExceeded")
