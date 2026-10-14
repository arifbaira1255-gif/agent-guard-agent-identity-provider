"""Unit tests for the strict execution budgets and cancellation (``limits.py``)."""
from __future__ import annotations

import threading
import time

import pytest

from agentguard_happy_contract.errors import ValidationError
from agentguard_happy_contract.limits import (
    BudgetTracker,
    CancellationToken,
    ExecutionBudget,
    ResourceLimitExceeded,
)


class _Clock:
    """A controllable monotonic clock so timeout tests are deterministic, not timing-dependent."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestExecutionBudget:
    def test_defaults_are_valid(self):
        ExecutionBudget().validate()

    @pytest.mark.parametrize("kwargs", [
        {"wall_clock_s": 0},
        {"wall_clock_s": 301},
        {"memory_mb": 0},
        {"memory_mb": 5000},
        {"output_bytes": 0},
        {"max_operations": 0},
        {"max_tool_calls": 0},
        {"max_concurrency": 0},
        {"max_concurrency": 65},
        {"queue_capacity": -1},
    ])
    def test_out_of_range_is_rejected(self, kwargs):
        with pytest.raises(ValidationError):
            ExecutionBudget(**kwargs).validate()


class TestCancellationToken:
    def test_starts_uncancelled(self):
        token = CancellationToken()
        assert token.cancelled is False
        token.raise_if_set()

    def test_cancel_is_idempotent_and_raises(self):
        token = CancellationToken()
        token.cancel("stop")
        token.cancel("stop again")
        assert token.cancelled is True
        with pytest.raises(ResourceLimitExceeded) as exc:
            token.raise_if_set()
        assert exc.value.kind == "cancelled"

    def test_pre_cancelled(self):
        assert CancellationToken.pre_cancelled().cancelled is True

    def test_cancel_from_another_thread_is_visible(self):
        token = CancellationToken()
        threading.Thread(target=lambda: (time.sleep(0.01), token.cancel())).start()
        deadline = time.monotonic() + 2
        while not token.cancelled and time.monotonic() < deadline:
            time.sleep(0.005)
        assert token.cancelled is True


class TestBudgetTracker:
    def test_wall_clock_timeout_is_enforced(self):
        clock = _Clock()
        tracker = BudgetTracker(ExecutionBudget(wall_clock_s=5.0), clock=clock)
        tracker.check_deadline()
        clock.advance(5.0)
        with pytest.raises(ResourceLimitExceeded) as exc:
            tracker.check_deadline()
        assert exc.value.kind == "timeout"
        assert exc.value.limit == 5.0

    def test_operation_budget_is_enforced(self):
        tracker = BudgetTracker(ExecutionBudget(max_operations=3))
        for _ in range(3):
            tracker.charge_operation()
        with pytest.raises(ResourceLimitExceeded) as exc:
            tracker.charge_operation()
        assert exc.value.kind == "operations"
        assert tracker.operations == 4

    def test_tool_call_budget_is_enforced(self):
        tracker = BudgetTracker(ExecutionBudget(max_tool_calls=2))
        tracker.charge_tool_call()
        tracker.charge_tool_call()
        with pytest.raises(ResourceLimitExceeded) as exc:
            tracker.charge_tool_call()
        assert exc.value.kind == "tool_calls"

    def test_output_budget_is_enforced(self):
        tracker = BudgetTracker(ExecutionBudget(output_bytes=10))
        tracker.charge_output(10)
        with pytest.raises(ResourceLimitExceeded) as exc:
            tracker.charge_output(1)
        assert exc.value.kind == "output"

    def test_cancellation_beats_every_other_check(self):
        tracker = BudgetTracker(ExecutionBudget(), token=CancellationToken.pre_cancelled())
        with pytest.raises(ResourceLimitExceeded) as exc:
            tracker.charge_operation()
        assert exc.value.kind == "cancelled"

    def test_snapshot_reports_usage_and_limits(self):
        clock = _Clock()
        tracker = BudgetTracker(ExecutionBudget(wall_clock_s=10.0, max_operations=5), clock=clock)
        tracker.charge_operation(2)
        clock.advance(4.0)
        snap = tracker.snapshot()
        assert snap["operations"] == 2
        assert snap["elapsed_s"] == 4.0
        assert snap["remaining_s"] == 6.0
        assert snap["limits"]["max_operations"] == 5
        assert snap["cancelled"] is False

    def test_trackers_do_not_share_state(self):
        """One execution must not be able to spend another's budget."""
        first = BudgetTracker(ExecutionBudget(max_operations=1))
        second = BudgetTracker(ExecutionBudget(max_operations=1))
        first.charge_operation()
        second.charge_operation()          # must not raise: separate budgets
        assert first.operations == 1 and second.operations == 1
