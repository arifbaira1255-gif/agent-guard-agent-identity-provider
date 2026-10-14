"""Run budgets: real, point-of-use enforcement for the agent loop.

A budget is only a control if it is consulted *before* the thing it bounds.  Every charge method
here checks the wall clock and the cancellation token first, then increments and compares, so an
exhausted budget always raises at the call site rather than being reported after the fact.

Dimensions (the task's list, applied to an agent run):

* ``wall_clock`` -- monotonic deadline, checked at every enforcement point.
* ``steps`` -- loop iterations (an unbounded agent loop is the classic cost runaway).
* ``tool_calls`` -- protected operations, the security-relevant counter.
* ``tokens`` / ``cost`` -- hard ceilings on model spend.
* ``cancelled`` -- a cooperative token the control plane may trip at any time.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .errors import BudgetExceeded

__all__ = ["RunBudget", "BudgetAccountant", "CancellationToken"]


class CancellationToken:
    """One-way, thread-safe cancellation shared with a run.

    ``raise_if_set`` is the enforcement point called between steps, so a cancelled run stops
    promptly and never leaves half-finished work behind it.
    """

    __slots__ = ("_event", "_reason")

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason: Optional[str] = None

    def cancel(self, reason: str = "cancelled by operator") -> None:
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
            raise BudgetExceeded("cancelled", self._reason or "cancelled")

    @classmethod
    def pre_cancelled(cls, reason: str = "cancelled before start") -> "CancellationToken":
        token = cls()
        token.cancel(reason)
        return token


@dataclass(frozen=True)
class RunBudget:
    """Ceilings for one run.  ``None`` means "not bounded on this dimension"."""

    wall_clock_s: float = 120.0
    max_steps: int = 12
    max_tool_calls: int = 24
    max_tokens: Optional[int] = 200_000
    max_cost_usd: Optional[float] = 2.0

    def validate(self) -> None:
        problems = []
        if not (0 < float(self.wall_clock_s) <= 3600.0):
            problems.append("wall_clock_s must be in (0, 3600]")
        if not (1 <= int(self.max_steps) <= 100):
            problems.append("max_steps must be in [1, 100]")
        if not (0 <= int(self.max_tool_calls) <= 1000):
            problems.append("max_tool_calls must be in [0, 1000]")
        if self.max_tokens is not None and not (1 <= int(self.max_tokens) <= 10_000_000):
            problems.append("max_tokens must be in [1, 10000000]")
        if self.max_cost_usd is not None and not (0 < float(self.max_cost_usd) <= 1000.0):
            problems.append("max_cost_usd must be in (0, 1000]")
        if problems:
            from .errors import ConfigError

            raise ConfigError("invalid run budget", errors=problems)

    def to_dict(self) -> dict:
        return {"wall_clock_s": self.wall_clock_s, "max_steps": self.max_steps,
                "max_tool_calls": self.max_tool_calls, "max_tokens": self.max_tokens,
                "max_cost_usd": self.max_cost_usd}


class BudgetAccountant:
    """Enforce one :class:`RunBudget` for one run.  Never share an accountant between runs."""

    def __init__(self, budget: RunBudget, *, clock: Callable[[], float] = time.monotonic,
                 token: Optional[CancellationToken] = None) -> None:
        budget.validate()
        self.budget = budget
        self._clock = clock
        self._token = token or CancellationToken()
        self._started = clock()
        self._steps = 0
        self._tool_calls = 0
        self._tokens = 0
        self._cost = 0.0
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
    def steps(self) -> int:
        return self._steps

    @property
    def tool_calls(self) -> int:
        return self._tool_calls

    @property
    def tokens(self) -> int:
        return self._tokens

    @property
    def cost_usd(self) -> float:
        return self._cost

    # -- enforcement -------------------------------------------------------------------------
    def check_deadline(self) -> None:
        """Raise on cancellation or an exhausted wall clock.  Called before every unit of work."""
        self._token.raise_if_set()
        if self.elapsed_s >= float(self.budget.wall_clock_s):
            raise BudgetExceeded("wall_clock",
                                 f"wall-clock budget of {self.budget.wall_clock_s}s exceeded",
                                 limit=float(self.budget.wall_clock_s), observed=self.elapsed_s)

    def charge_step(self, n: int = 1) -> None:
        self.check_deadline()
        with self._lock:
            self._steps += int(n)
            observed = self._steps
        if observed > int(self.budget.max_steps):
            raise BudgetExceeded("steps", f"step budget of {self.budget.max_steps} exceeded",
                                 limit=float(self.budget.max_steps), observed=float(observed))

    def charge_tool_call(self, n: int = 1) -> None:
        self.check_deadline()
        with self._lock:
            self._tool_calls += int(n)
            observed = self._tool_calls
        if observed > int(self.budget.max_tool_calls):
            raise BudgetExceeded("tool_calls",
                                 f"tool-call budget of {self.budget.max_tool_calls} exceeded",
                                 limit=float(self.budget.max_tool_calls), observed=float(observed))

    def charge_tokens(self, total_tokens: int) -> None:
        if self.budget.max_tokens is None:
            return
        with self._lock:
            self._tokens += max(0, int(total_tokens))
            observed = self._tokens
        if observed > int(self.budget.max_tokens):
            raise BudgetExceeded("tokens", f"token budget of {self.budget.max_tokens} exceeded",
                                 limit=float(self.budget.max_tokens), observed=float(observed))

    def charge_cost(self, usd: float) -> None:
        if self.budget.max_cost_usd is None:
            return
        with self._lock:
            self._cost = round(self._cost + max(0.0, float(usd)), 8)
            observed = self._cost
        if observed > float(self.budget.max_cost_usd):
            raise BudgetExceeded("cost", f"cost budget of ${self.budget.max_cost_usd} exceeded",
                                 limit=float(self.budget.max_cost_usd), observed=float(observed))

    def charge_usage(self, *, total_tokens: int = 0, cost_usd: float = 0.0) -> None:
        """Charge a model call's token and money cost in one place (order-independent totals)."""
        self.charge_tokens(total_tokens)
        self.charge_cost(cost_usd)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "elapsed_s": round(self.elapsed_s, 6),
            "remaining_s": round(self.remaining_s, 6),
            "steps": self._steps,
            "tool_calls": self._tool_calls,
            "tokens": self._tokens,
            "cost_usd": round(self._cost, 8),
            "cancelled": self._token.cancelled,
            "limits": self.budget.to_dict(),
        }
