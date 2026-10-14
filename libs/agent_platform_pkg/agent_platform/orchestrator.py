"""The orchestrator: the bounded ReAct loop that turns a goal into an auditable result.

WHAT IT DOES
------------
One entry point, :meth:`AgentOrchestrator.run`, and it does exactly five things per iteration:

1. **enforce budget** (``check_deadline``) before any work -- so a slow or hostile run stops at the
   boundary rather than after the damage;
2. **ask the model** (through the router, with only the tools this deployment allows it to see);
3. **act on tool calls** (through the :class:`~agent_platform.tools.ToolGuard`, which authorizes every
   protected call);
4. **record the step** (transcript, span, metrics, usage) so the run is replayable;
5. **loop or stop** -- stop on a final text answer, on a budget, on a denial, or on an unrecoverable
   error, each producing a distinct :class:`~agent_platform.types.RunOutcome`.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not swallow an exception to keep going, does not treat an empty model answer as success, and
does not run a tool the guard refused.  Every terminal condition is a named outcome with a reason, so
"the run failed" is never the whole story.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from .budget import BudgetAccountant, CancellationToken, RunBudget
from .config import PlatformConfig
from .events import EventBus
from .errors import (
    BudgetExceeded,
    ModelError,
    PlatformError,
    ProviderUnavailable,
    SandboxUnavailable,
    UnknownTool,
)
from .ids import new_id
from .memory import EpisodicMemory, WorkingMemory
from .router import ModelRouter
from .tools import ToolGuard, ToolResult
from .tracing import NOOP_TRACER, Tracer
from .types import Message, RunOutcome, RunResult, StepRecord, ToolCall, Usage
from .validation import truncate

__all__ = ["AgentOrchestrator", "Planner", "NullPlanner", "StaticPlanner", "PlanResult",
           "DEFAULT_SYSTEM_PROMPT"]

#: Terminal outcomes that mean "the loop stopped because a control refused", not "the agent finished".
_STOPPED_OUTCOMES = {
    RunOutcome.BUDGET_EXCEEDED, RunOutcome.CANCELLED, RunOutcome.TOOL_DENIED,
    RunOutcome.INVALID_MODEL_OUTPUT, RunOutcome.SANDBOX_UNAVAILABLE, RunOutcome.VALIDATION_ERROR,
}

DEFAULT_SYSTEM_PROMPT = (
    "You are a careful autonomous agent operating inside AgentGuard, a security control plane.\n"
    "Rules you must follow:\n"
    "1. Use the provided tools to gather facts; do not invent results.\n"
    "2. Some tool calls require authorization and may be denied. If a call is denied, do NOT retry it "
    "through another tool or another path -- report the denial instead.\n"
    "3. Never place credentials, tokens or private keys in your answer or in tool arguments.\n"
    "4. When you have enough information, answer directly with no further tool calls.\n"
    "5. Keep the answer concise and state clearly when you could not complete part of the task."
)


@dataclass
class PlanResult:
    """What a planner returns: an ordered list of steps plus any planning notes."""

    steps: List[str] = field(default_factory=list)
    rationale: str = ""
    raw: str = ""
    planner: str = "static"

    def to_dict(self) -> dict:
        return {"planner": self.planner, "steps": list(self.steps),
                "rationale": truncate(self.rationale, 2000)}


class Planner:
    """Turns a goal into steps.  ``plan`` must be side-effect free and must never raise."""

    name = "planner"

    def plan(self, goal: str, *, context: Optional[Mapping[str, Any]] = None) -> PlanResult:
        raise NotImplementedError


class NullPlanner(Planner):
    """No planning: the loop is pure ReAct.  The honest default when no planner is needed."""

    name = "none"

    def plan(self, goal: str, *, context: Optional[Mapping[str, Any]] = None) -> PlanResult:
        return PlanResult(steps=[], rationale="planning disabled", planner=self.name)


class StaticPlanner(Planner):
    """A one-shot planner that asks the model for a short numbered plan (bounded, single call).

    Any failure degrades to :class:`NullPlanner` behaviour with an empty plan, because a failed
    planning call must never prevent the actual task from being attempted.
    """

    name = "static"

    def __init__(self, router: ModelRouter, *, max_steps: int = 6, tracer: Any = None) -> None:
        self.router = router
        self.max_steps = max(1, int(max_steps))
        self.tracer = tracer

    def plan(self, goal: str, *, context: Optional[Mapping[str, Any]] = None) -> PlanResult:
        tools = (context or {}).get("tools") or []
        names = ", ".join(str(t) for t in tools) or "none"
        prompt = [
            Message.system(
                "Write a short numbered plan (at most "
                f"{self.max_steps} steps) to achieve the goal using only these tools: {names}. "
                "Output only the numbered steps, one per line."),
            Message.user(goal),
        ]
        try:
            response = self.router.complete(prompt, tools=())
        except Exception:  # noqa: BLE001 - planning is best effort by design
            return PlanResult(steps=[], rationale="planning call failed", planner=self.name)
        steps: List[str] = []
        for line in (response.text or "").splitlines():
            cleaned = line.strip().lstrip("0123456789.-) ").strip()
            if cleaned:
                steps.append(truncate(cleaned, 240))
            if len(steps) >= self.max_steps:
                break
        return PlanResult(steps=steps, rationale="model-generated plan", raw=response.text,
                          planner=self.name)


class AgentOrchestrator:
    """Runs one goal to a structured :class:`RunResult`.

    Construct it once per deployment (it is safe to reuse) and call :meth:`run` per task.  All
    collaborators are injected, which is what makes the whole loop testable without a network.
    """

    def __init__(self, router: ModelRouter, guard: ToolGuard, *, config: Optional[PlatformConfig] = None,
                 memory: Optional[EpisodicMemory] = None,
                 working_memory: Optional[WorkingMemory] = None,
                 planner: Optional[Planner] = None, tracer: Optional[Tracer] = None,
                 events: Optional[EventBus] = None,
                 sandbox: Optional[Any] = None,
                 system_prompt: str = DEFAULT_SYSTEM_PROMPT,
                 tool_schemas: Optional[Callable[[], List[Dict[str, Any]]]] = None,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self.router = router
        self.guard = guard
        self.config = config or router.config
        # The deployment's declared allowlist is authoritative: if the config restricts the tool set,
        # the guard must honour it even when whoever constructed the guard forgot to pass it through.
        # A restriction that only applies on some entry paths is not a restriction.
        if not self.guard.allowlist and self.config.tool_allowlist:
            self.guard.allowlist = tuple(self.config.tool_allowlist)
        self.memory = memory
        self.working_memory = working_memory or WorkingMemory(
            max_messages=self.config.working_memory_max_messages, summariser=self._summarise)
        self.planner = planner or NullPlanner()
        self.tracer = tracer or NOOP_TRACER
        self.events = events or EventBus(enabled=False)
        self.sandbox = sandbox
        self.system_prompt = system_prompt
        self._tool_schemas = tool_schemas
        self._clock = clock
        self._monotonic = monotonic

    # -- tool list ---------------------------------------------------------------------------
    def tool_schemas(self) -> List[Dict[str, Any]]:
        if self._tool_schemas is not None:
            return self._tool_schemas()
        return self.guard.registry.openai_schemas(allowlist=self.guard.allowlist)

    # -- summariser hook ---------------------------------------------------------------------
    def _summarise(self, dropped: Sequence[Message]) -> Optional[str]:
        """Optional model-backed compaction.  Off by default; the local summary is the safe path."""
        return None

    # -- the loop ----------------------------------------------------------------------------
    def run(self, goal: str, *, budget: Optional[RunBudget] = None,
            token: Optional[CancellationToken] = None,
            context: Optional[Mapping[str, Any]] = None,
            correlation_id: Optional[str] = None,
            agent_id: Optional[str] = None,
            plan: bool = False) -> RunResult:
        """Execute ``goal`` and return the complete, auditable result."""
        if not isinstance(goal, str) or not goal.strip():
            raise PlatformError("goal must be a non-empty string", field="goal")
        run_id = new_id("run")
        correlation_id = correlation_id or run_id
        agent_id = agent_id or self.config.agent_id
        started = self._monotonic()
        budget_obj = budget or RunBudget(
            wall_clock_s=self.config.wall_clock_s, max_steps=self.config.max_steps,
            max_tool_calls=self.config.max_tool_calls, max_tokens=self.config.max_tokens,
            max_cost_usd=self.config.max_cost_usd)
        accountant = BudgetAccountant(budget_obj, clock=self._monotonic, token=token)
        # Wire this run's tool-call ceiling into the guard for the duration of the run.  The budget is a
        # per-run object, so a caller cannot wire it once at construction time; doing it here means the
        # ceiling is enforced at the point of use on EVERY entry path (CLI, tests, embedders) rather
        # than only where someone remembered to pass a charge callback.
        previous_charge = getattr(self.guard, "_charge", None)
        self.guard._charge = accountant.charge_tool_call

        run_span = None
        if getattr(self.tracer, "enabled", False):
            run_span = self.tracer.span("run", run_id=run_id, goal=truncate(goal, 240),
                                        correlation_id=correlation_id, agent_id=agent_id)

        self.events.record(event_type="platform.run.started", outcome="started", run_id=run_id,
                           correlation_id=correlation_id, agent_id=agent_id,
                           metadata={"goal": truncate(goal, 240)})

        # -- planning (optional, best effort, never fatal)
        plan_result = PlanResult(steps=[], planner="disabled")
        if plan:
            try:
                plan_result = self.planner.plan(
                    goal, context=dict(dict(context or {}), tools=self.guard.registry.names()))
            except Exception:  # noqa: BLE001 - planning must never block the task
                plan_result = PlanResult(steps=[], rationale="planner raised",
                                         planner=getattr(self.planner, "name", "unknown"))

        # -- seed the transcript
        working = self.working_memory
        working.extend([Message.system(self.system_prompt)])
        if self.memory is not None and self.config.memory_enabled:
            recalled = self.memory.render(goal, top_k=self.config.memory_top_k)
            if recalled:
                working.add(Message.system(recalled))
        if plan_result.steps:
            plan_text = "Plan to follow:\n" + "\n".join(
                f"{i}. {step}" for i, step in enumerate(plan_result.steps, 1))
            working.add(Message.system(plan_text))
        working.add(Message.user(goal))

        tools = self.tool_schemas()
        step_records: List[StepRecord] = []
        usage = Usage()
        outcome = RunOutcome.OK
        error: Optional[str] = None
        error_code: Optional[str] = None
        final_text = ""
        tool_call_count = 0

        try:
            while True:
                # Check the step ceiling BEFORE charging, so a run that uses its whole step budget
                # ends as the precise MAX_STEPS outcome with an exact step count -- rather than as a
                # budget exception one step past the limit.
                if accountant.steps >= int(budget_obj.max_steps):
                    outcome = RunOutcome.MAX_STEPS
                    error = (f"reached the step budget ({budget_obj.max_steps}) "
                             "without a final answer")
                    error_code = "max_steps"
                    break
                accountant.charge_step()
                step_started = self._monotonic()
                record = StepRecord(index=accountant.steps)
                step_span = None
                if run_span is not None:
                    step_span = self.tracer.start_span("step", index=accountant.steps)

                # -- model call
                try:
                    response = self.router.complete(working.messages(), tools=tools)
                except ProviderUnavailable as exc:
                    outcome, error, error_code = RunOutcome.MODEL_ERROR, str(exc), exc.code
                    break
                except ModelError as exc:
                    outcome, error, error_code = RunOutcome.MODEL_ERROR, str(exc), exc.code
                    break
                usage = usage + response.usage
                # Charge token/cost budgets at the moment the spend is incurred.  ``usage`` is updated
                # first so the failed run's accounting is still accurate when the ceiling trips.
                accountant.charge_usage(total_tokens=response.usage.total_tokens,
                                        cost_usd=response.usage.cost_usd)
                record.model = response.model
                record.usage = response.usage

                # -- a response with neither text nor tool calls is not a final answer
                if response.is_empty:
                    outcome = RunOutcome.INVALID_MODEL_OUTPUT
                    error = "model returned neither text nor a tool call"
                    error_code = "invalid_model_output"
                    break

                # -- final answer
                if not response.has_tool_calls:
                    final_text = response.text
                    record.thought = truncate(final_text, 2000)
                    record.duration_ms = (self._monotonic() - step_started) * 1000.0
                    step_records.append(record)
                    working.add(Message.assistant(final_text))
                    if step_span is not None:
                        self.tracer.end_span(step_span, finish="final")
                    break

                # -- tool calls
                record.tool_calls = [c.to_dict() for c in response.tool_calls]
                working.add(Message.assistant(response.text, tool_calls=response.tool_calls))
                denied = False
                denial_reason: Optional[str] = None
                for call in response.tool_calls:
                    tool_call_count += 1
                    result = self._invoke(call, correlation_id=correlation_id, agent_id=agent_id,
                                          context=context)
                    record.tool_results.append(result.to_dict())
                    working.add(Message.tool_result(result.as_model_content(),
                                                    tool_call_id=call.id or call.name,
                                                    name=call.name))
                    if result.error_code == "authorization_denied":
                        denied = True
                        # Keep the gate's own reason: "denied" alone is not actionable evidence.
                        denial_reason = denial_reason or (result.error or "")
                record.duration_ms = (self._monotonic() - step_started) * 1000.0
                step_records.append(record)
                if step_span is not None:
                    self.tracer.end_span(step_span, tools=len(response.tool_calls))
                if denied:
                    outcome = RunOutcome.TOOL_DENIED
                    error = denial_reason or "a protected operation was denied by authorization"
                    error_code = "authorization_denied"
                    break

        except BudgetExceeded as exc:
            outcome = (RunOutcome.CANCELLED if exc.kind == "cancelled"
                       else RunOutcome.BUDGET_EXCEEDED)
            error = str(exc)
            error_code = exc.code
        except SandboxUnavailable as exc:
            outcome, error, error_code = RunOutcome.SANDBOX_UNAVAILABLE, str(exc), exc.code
        except Exception as exc:  # noqa: BLE001 - an unexpected fault is an outcome, not a crash
            outcome = RunOutcome.INTERNAL_ERROR
            error = f"{type(exc).__name__}: {exc}"
            error_code = "internal_error"

        # -- the step loop can also end by exhaustion rather than by a final answer
        if (outcome == RunOutcome.OK and not final_text
                and accountant.steps >= int(budget_obj.max_steps)):
            outcome = RunOutcome.MAX_STEPS
            error = f"reached the step budget ({budget_obj.max_steps}) without a final answer"
            error_code = "max_steps"

        self.guard._charge = previous_charge
        duration_ms = (self._monotonic() - started) * 1000.0
        snapshot = accountant.snapshot()
        result = RunResult(run_id=run_id, outcome=outcome, goal=goal, correlation_id=correlation_id,
                           ok=(outcome == RunOutcome.OK), final_text=final_text,
                           steps=accountant.steps, tool_calls=tool_call_count, usage=usage,
                           duration_ms=duration_ms, error=error, error_code=error_code,
                           transcript=working.messages(), step_records=step_records,
                           plan=plan_result.to_dict() if plan_result.steps else None,
                           budget=snapshot,
                           metadata={"agent_id": agent_id, "mode": self.config.mode,
                                     "gate": self.guard.gate.name,
                                     "routes": self.router.route_names})

        if run_span is not None:
            self.tracer.end_span(run_span, outcome=outcome.value, steps=accountant.steps,
                                 tool_calls=tool_call_count, error=error_code)
        self._emit_run_event(result)
        # A run's audit trail must actually be delivered, not merely buffered: a short run would
        # otherwise sit in the buffer until some future run happened to overflow it.
        self.events.flush()
        if self.memory is not None and self.config.memory_enabled:
            self._remember(result)
        return result

    # -- helpers -----------------------------------------------------------------------------
    def _invoke(self, call: ToolCall, *, correlation_id: str, agent_id: str,
                context: Optional[Mapping[str, Any]]) -> ToolResult:
        """Route one tool call, applying the sandbox rule before the guard allocates work."""
        try:
            spec = self.guard.registry.get(call.name)
        except UnknownTool:
            return self.guard.invoke(call, correlation_id=correlation_id, agent_id=agent_id,
                                     context=context)
        if spec.requires_sandbox and self.sandbox is not None:
            try:
                self.sandbox.ensure_available()
            except Exception as exc:  # noqa: BLE001 - a refusal is a structured result
                return ToolResult(name=call.name, ok=False, denied=True, error=str(exc),
                                  error_code=getattr(exc, "code", "sandbox_unavailable"))
        return self.guard.invoke(call, correlation_id=correlation_id, agent_id=agent_id,
                                 context=context)

    def _emit_run_event(self, result: RunResult) -> None:
        outcome = "ok" if result.ok else ("denied" if result.outcome in _STOPPED_OUTCOMES
                                          else "error")
        self.events.record(event_type="platform.run.finished", outcome=outcome,
                           run_id=result.run_id, correlation_id=result.correlation_id,
                           agent_id=result.metadata.get("agent_id"),
                           reason=result.error or result.outcome.value,
                           metadata={"steps": result.steps, "tool_calls": result.tool_calls,
                                     "tokens": result.usage.total_tokens,
                                     "cost_usd": result.usage.cost_usd,
                                     "duration_ms": result.duration_ms,
                                     "outcome": result.outcome.value})

    def _remember(self, result: RunResult) -> None:
        """Persist a short, redacted episode so a later run can reuse the lesson, not the tokens."""
        try:
            lesson = result.error or truncate(result.final_text, 500) or result.outcome.value
            self.memory.remember(
                key=truncate(result.goal, 240),
                value=f"outcome={result.outcome.value}; steps={result.steps}; "
                      f"tool_calls={result.tool_calls}; lesson={lesson}",
                kind="run",
                tags=[result.outcome.value],
                metadata={"run_id": result.run_id, "ok": result.ok,
                          "correlation_id": result.correlation_id})
        except Exception:  # noqa: BLE001 - memory is an optimisation, never a correctness need
            pass

    def run_many(self, goals: Sequence[str], **kwargs: Any) -> List[RunResult]:
        """Run several goals in order (sequential on purpose: a shared guard must stay auditable)."""
        return [self.run(goal, **kwargs) for goal in goals]

    def describe(self) -> Dict[str, Any]:
        return {"router": self.router.describe(), "tools": self.guard.registry.names(),
                "allowlist": list(self.guard.allowlist), "gate": self.guard.gate.name,
                "planner": getattr(self.planner, "name", "unknown"),
                "memory": (self.memory.stats() if self.memory is not None else None),
                "sandbox": (self.sandbox.summary() if self.sandbox is not None else None),
                "config": {"enabled": self.config.enabled,
                           "environment": self.config.environment,
                           "mode": self.config.mode}}
