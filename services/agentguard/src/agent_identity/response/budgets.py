"""Phase 6 execution budgets and emergency stops -- the SERVER-SIDE enforcement boundary.

This module is deliberately different in kind from the rest of the response plane: it does not
observe, it **enforces**. :meth:`BudgetService.guard` is the single entry point a server-side
execution boundary calls before admitting an operation, and it raises rather than returning a
suggestion. That is the requirement "enforce limits at the relevant server-side execution boundary --
do not depend solely on the agent or SDK voluntarily obeying instructions".

Controls provided:

  * maximum action counts, retry counts, request counts, concurrency, tokens and cost,
  * execution deadlines,
  * per-agent and per-task scoping (a task budget is more specific than an agent budget),
  * emergency stop requests (agent- or task-scoped), with an authenticated release path.

Failure handling (requirement 10):

* ``budget_fail_closed`` (default **True**) -- if the budget store cannot be read, a protected
  operation is REFUSED rather than admitted. The decision records ``fail_closed=True`` so the caller
  can distinguish "over budget" from "could not establish a budget".
* An active emergency stop always refuses, regardless of budget state.

Honest limitation (documented, not hidden): this boundary can only refuse operations that actually
pass through it. An agent runtime that never calls ``guard`` is not constrained by it -- see
``docs/PHASE6_SECURITY_LIMITATIONS.md``.
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional

from ..security.ids import new_id
from .config import ResponseConfig
from .errors import BudgetExceededError, EmergencyStopError, ResponsePlaneError
from .models import BudgetDecision, BudgetScope, EmergencyStop, ExecutionBudget

#: Dimensions a caller may consume. Closed vocabulary: an unknown dimension is a programming error.
DIMENSIONS = ("actions", "retries", "requests", "concurrency", "tokens", "cost")

_LIMIT_ATTR = {"actions": "max_actions", "retries": "max_retries", "requests": "max_requests",
               "concurrency": "max_concurrency", "tokens": "max_tokens", "cost": "max_cost"}
_USED_ATTR = {"actions": "actions_used", "retries": "retries_used", "requests": "requests_used",
              "concurrency": "concurrency_used", "tokens": "tokens_used", "cost": "cost_used"}


class BudgetService:
    """Server-side budget + emergency-stop enforcement."""

    def __init__(self, store, *, config: Optional[ResponseConfig] = None, audit=None, clock=None):
        self.store = store
        self.cfg = config or ResponseConfig()
        self.audit = audit
        self._clock = clock
        self._lock = threading.RLock()

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ budgets
    def set_budget(self, *, org_id: str, agent_id: Optional[str] = None,
                   task_id: Optional[str] = None, scope: Optional[str] = None,
                   max_actions: Optional[int] = None, max_retries: Optional[int] = None,
                   max_requests: Optional[int] = None, max_concurrency: Optional[int] = None,
                   max_tokens: Optional[int] = None, max_cost: Optional[float] = None,
                   deadline_s: Optional[int] = None, actor_user_id: Optional[str] = None,
                   budget_id: Optional[str] = None) -> ExecutionBudget:
        """Create or replace a budget. Unspecified limits fall back to the configured defaults."""
        if not agent_id and not task_id:
            raise ResponsePlaneError("a budget must be scoped to an agent or a task")
        now = self._now()
        resolved_scope = (BudgetScope.coerce(scope).value if scope else
                          (BudgetScope.TASK.value if task_id else BudgetScope.AGENT.value))
        existing = None
        if budget_id:
            existing = self.store.get_budget(budget_id, org_id=org_id)
        if existing is None:
            existing = self.store.find_budget(org_id=org_id, agent_id=agent_id, task_id=task_id)
        b = ExecutionBudget(
            budget_id=budget_id or (existing.budget_id if existing else new_id("bdg")),
            org_id=org_id, scope=resolved_scope, agent_id=agent_id, task_id=task_id,
            max_actions=(max_actions if max_actions is not None else
                         (existing.max_actions if existing else self.cfg.budget_default_max_actions)),
            max_retries=(max_retries if max_retries is not None else
                         (existing.max_retries if existing else self.cfg.budget_default_max_retries)),
            max_requests=(max_requests if max_requests is not None else
                          (existing.max_requests if existing else
                           self.cfg.budget_default_max_requests)),
            max_concurrency=(max_concurrency if max_concurrency is not None else
                             (existing.max_concurrency if existing else
                              self.cfg.budget_default_max_concurrency)),
            max_tokens=(max_tokens if max_tokens is not None else
                        (existing.max_tokens if existing else self.cfg.budget_default_max_tokens)),
            max_cost=(max_cost if max_cost is not None else
                      (existing.max_cost if existing else self.cfg.budget_default_max_cost)),
            deadline_s=(deadline_s if deadline_s is not None else
                        (existing.deadline_s if existing else self.cfg.budget_default_deadline_s)),
            started_at=(existing.started_at if existing else now), updated_at=now,
            actions_used=(existing.actions_used if existing else 0),
            retries_used=(existing.retries_used if existing else 0),
            requests_used=(existing.requests_used if existing else 0),
            concurrency_used=(existing.concurrency_used if existing else 0),
            tokens_used=(existing.tokens_used if existing else 0),
            cost_used=(existing.cost_used if existing else 0.0),
            enabled=True)
        for name in ("max_actions", "max_retries", "max_requests", "max_concurrency",
                     "max_tokens"):
            v = getattr(b, name)
            if v is not None and v < 0:
                raise ResponsePlaneError(f"{name} must be >= 0")
        if b.max_cost is not None and b.max_cost < 0:
            raise ResponsePlaneError("max_cost must be >= 0")
        self.store.put_budget(b)
        self._audit("response.budget.set", org_id=org_id, agent_id=agent_id,
                    actor_user_id=actor_user_id, extra={"budget_id": b.budget_id,
                                                        "scope": b.scope})
        return b

    def get_budget(self, *, org_id: str, agent_id: Optional[str] = None,
                   task_id: Optional[str] = None) -> Optional[ExecutionBudget]:
        return self.store.find_budget(org_id=org_id, agent_id=agent_id, task_id=task_id)

    def list_budgets(self, *, org_id: str, limit: int = 200) -> List[ExecutionBudget]:
        return self.store.list_budgets(org_id=org_id, limit=limit)

    def delete_budget(self, *, org_id: str, budget_id: str,
                      actor_user_id: Optional[str] = None) -> None:
        self.store.delete_budget(budget_id, org_id=org_id)
        self._audit("response.budget.deleted", org_id=org_id, actor_user_id=actor_user_id,
                    extra={"budget_id": budget_id})

    # ------------------------------------------------------------------ checks
    def check(self, *, org_id: str, agent_id: Optional[str] = None,
              task_id: Optional[str] = None, dimension: str = "actions",
              amount: float = 1.0, now: Optional[float] = None) -> BudgetDecision:
        """Evaluate one dimension WITHOUT consuming it. Never raises; returns a decision."""
        if dimension not in DIMENSIONS:
            raise ResponsePlaneError(f"unknown budget dimension: {dimension}")
        current = now if now is not None else self._now()
        try:
            b = self.store.find_budget(org_id=org_id, agent_id=agent_id, task_id=task_id)
        except Exception:  # noqa: BLE001 - a store failure must not silently admit traffic
            if self.cfg.budget_fail_closed:
                return BudgetDecision(allowed=False, reason="budget_store_unavailable",
                                      dimension=dimension, fail_closed=True)
            return BudgetDecision(allowed=True, reason="budget_store_unavailable_fail_open",
                                  dimension=dimension, fail_closed=False)
        if b is None:
            return BudgetDecision(allowed=True, reason="no_budget_configured", dimension=dimension)
        if not b.enabled:
            return BudgetDecision(allowed=True, reason="budget_disabled", dimension=dimension,
                                  budget_id=b.budget_id)
        if b.deadline_s is not None and b.started_at and \
                current > b.started_at + b.deadline_s:
            return BudgetDecision(allowed=False, reason="deadline_exceeded", dimension="deadline",
                                  limit=b.deadline_s, used=round(current - b.started_at, 3),
                                  budget_id=b.budget_id)
        limit = getattr(b, _LIMIT_ATTR[dimension])
        used = getattr(b, _USED_ATTR[dimension])
        if limit is None:
            return BudgetDecision(allowed=True, reason="dimension_unlimited", dimension=dimension,
                                  budget_id=b.budget_id)
        if used + amount > limit:
            return BudgetDecision(allowed=False, reason="budget_exceeded", dimension=dimension,
                                  limit=limit, used=used, budget_id=b.budget_id)
        return BudgetDecision(allowed=True, reason="within_budget", dimension=dimension,
                              limit=limit, used=used, budget_id=b.budget_id)

    def consume(self, *, org_id: str, agent_id: Optional[str] = None,
                task_id: Optional[str] = None, dimension: str = "actions",
                amount: float = 1.0, now: Optional[float] = None) -> BudgetDecision:
        """Atomically consume ``amount`` of ``dimension`` and return the decision.

        The increment is performed by the STORE (a single ``UPDATE ... RETURNING`` in PostgreSQL, a
        lock-guarded read-modify-write in memory), so two concurrent callers cannot both slip past
        the same limit.
        """
        if dimension not in DIMENSIONS:
            raise ResponsePlaneError(f"unknown budget dimension: {dimension}")
        current = now if now is not None else self._now()
        try:
            b = self.store.find_budget(org_id=org_id, agent_id=agent_id, task_id=task_id)
        except Exception:  # noqa: BLE001
            if self.cfg.budget_fail_closed:
                return BudgetDecision(allowed=False, reason="budget_store_unavailable",
                                      dimension=dimension, fail_closed=True)
            return BudgetDecision(allowed=True, reason="budget_store_unavailable_fail_open",
                                  dimension=dimension, fail_closed=False)
        if b is None:
            return BudgetDecision(allowed=True, reason="no_budget_configured", dimension=dimension)
        if not b.enabled:
            return BudgetDecision(allowed=True, reason="budget_disabled", dimension=dimension,
                                  budget_id=b.budget_id)
        if b.deadline_s is not None and b.started_at and \
                current > b.started_at + b.deadline_s:
            return BudgetDecision(allowed=False, reason="deadline_exceeded", dimension="deadline",
                                  limit=b.deadline_s, used=round(current - b.started_at, 3),
                                  budget_id=b.budget_id)
        limit = getattr(b, _LIMIT_ATTR[dimension])
        if limit is None:
            return BudgetDecision(allowed=True, reason="dimension_unlimited", dimension=dimension,
                                  budget_id=b.budget_id)
        # The increment is conditional and atomic INSIDE the store: it is applied only when it stays
        # within ``limit``. ``None`` is returned when it would exceed (or the budget vanished), so a
        # refused operation never advances the counter.
        updated = self.store.consume_budget(b.budget_id, org_id=org_id, dimension=dimension,
                                            amount=amount, now=current, limit=limit)
        if updated is None:
            if self.cfg.budget_fail_closed:
                return BudgetDecision(allowed=False, reason="budget_store_unavailable",
                                      dimension=dimension, fail_closed=True)
            return BudgetDecision(allowed=True, reason="budget_store_unavailable_fail_open",
                                  dimension=dimension, fail_closed=False)
        used = getattr(updated, _USED_ATTR[dimension])
        if used > limit:
            return BudgetDecision(allowed=False, reason="budget_exceeded", dimension=dimension,
                                  limit=limit, used=used, budget_id=updated.budget_id)
        return BudgetDecision(allowed=True, reason="within_budget", dimension=dimension,
                              limit=limit, used=used, budget_id=updated.budget_id)

    def release(self, *, org_id: str, agent_id: Optional[str] = None,
                task_id: Optional[str] = None, dimension: str = "concurrency",
                amount: float = 1.0, now: Optional[float] = None) -> None:
        """Release a previously consumed slot (e.g. a concurrency slot on completion)."""
        if dimension not in DIMENSIONS:
            raise ResponsePlaneError(f"unknown budget dimension: {dimension}")
        current = now if now is not None else self._now()
        b = self.store.find_budget(org_id=org_id, agent_id=agent_id, task_id=task_id)
        if b is None:
            return
        with self._lock:
            self.store.consume_budget(b.budget_id, org_id=org_id, dimension=dimension,
                                      amount=-abs(amount), now=current)

    # ------------------------------------------------------------------ emergency stops
    def emergency_stop(self, *, org_id: str, agent_id: Optional[str] = None,
                       task_id: Optional[str] = None, requested_by: str,
                       reason: str = "emergency_stop") -> EmergencyStop:
        """Raise an emergency stop. Idempotent: an existing active stop is returned unchanged."""
        if not agent_id and not task_id:
            raise ResponsePlaneError("an emergency stop must be scoped to an agent or a task")
        existing = self.store.find_active_stop(org_id=org_id, agent_id=agent_id, task_id=task_id)
        if existing is not None:
            return existing
        s = EmergencyStop(stop_id=new_id("est"), org_id=org_id, agent_id=agent_id, task_id=task_id,
                          requested_by=requested_by, reason=reason[:512], ts=self._now(),
                          active=True)
        self.store.put_stop(s)
        self._audit("response.emergency_stop.raised", org_id=org_id, agent_id=agent_id,
                    actor_user_id=requested_by, extra={"stop_id": s.stop_id,
                                                       "task_id": task_id})
        return s

    def release_stop(self, *, org_id: str, stop_id: str, released_by: str,
                     reason: str = "released") -> EmergencyStop:
        """Release an emergency stop through the documented, authenticated administrative path."""
        s = self.store.get_stop(stop_id, org_id=org_id)
        if s is None:
            raise ResponsePlaneError("unknown emergency stop")
        if not s.active:
            return s
        import dataclasses
        s2 = dataclasses.replace(s, active=False, released_by=released_by,
                                 released_at=self._now(), release_reason=reason[:512])
        self.store.put_stop(s2)
        self._audit("response.emergency_stop.released", org_id=org_id, agent_id=s.agent_id,
                    actor_user_id=released_by, extra={"stop_id": stop_id})
        return s2

    def active_stop(self, *, org_id: str, agent_id: Optional[str] = None,
                    task_id: Optional[str] = None) -> Optional[EmergencyStop]:
        return self.store.find_active_stop(org_id=org_id, agent_id=agent_id, task_id=task_id)

    def list_stops(self, *, org_id: str, active_only: bool = False,
                   limit: int = 200) -> List[EmergencyStop]:
        return self.store.list_stops(org_id=org_id, active_only=active_only, limit=limit)

    # ------------------------------------------------------------------ the boundary
    def guard(self, *, org_id: str, agent_id: Optional[str] = None,
              task_id: Optional[str] = None, dimension: str = "actions", amount: float = 1.0,
              now: Optional[float] = None) -> BudgetDecision:
        """The enforcement entry point. Raises on refusal; returns the decision on admission.

        Order matters: an active emergency stop is checked FIRST, so a stop cannot be bypassed by a
        generous budget. Then the budget is consumed atomically.
        """
        stop = self.store.find_active_stop(org_id=org_id, agent_id=agent_id, task_id=task_id)
        if stop is not None:
            self._audit("response.guard.refused", org_id=org_id, agent_id=agent_id,
                        outcome="denied", reason="emergency_stop",
                        extra={"stop_id": stop.stop_id, "dimension": dimension})
            raise EmergencyStopError(
                f"emergency stop {stop.stop_id} is in force for this agent/task")
        decision = self.consume(org_id=org_id, agent_id=agent_id, task_id=task_id,
                                dimension=dimension, amount=amount, now=now)
        if not decision.allowed:
            self._audit("response.guard.refused", org_id=org_id, agent_id=agent_id,
                        outcome="denied", reason=decision.reason,
                        extra={"dimension": dimension, "limit": decision.limit,
                               "used": decision.used, "fail_closed": decision.fail_closed})
            raise BudgetExceededError(
                f"execution budget refused the operation ({decision.reason}"
                f"{'' if decision.dimension is None else ':' + str(decision.dimension)})")
        return decision

    # ------------------------------------------------------------------ audit helper
    def _audit(self, event: str, *, org_id: Optional[str] = None, agent_id: Optional[str] = None,
               outcome: str = "ok", reason: Optional[str] = None,
               actor_user_id: Optional[str] = None, extra: Optional[dict] = None) -> None:
        if self.audit is not None:
            self.audit.record(event, org_id=org_id, agent_id=agent_id, outcome=outcome,
                              reason=reason, actor_user_id=actor_user_id, extra=extra)
