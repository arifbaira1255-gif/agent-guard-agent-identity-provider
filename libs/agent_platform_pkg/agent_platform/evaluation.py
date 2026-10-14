"""Evaluation harness: turn "the agent answered" into a measurable, repeatable score.

WHY THIS EXISTS
---------------
An agent that is not evaluated cannot be improved safely -- every change is a guess.  This harness
runs a fixed task suite against a fixed configuration and reports per-task and aggregate results, so a
prompt, tool or routing change can be judged on evidence rather than on one encouraging demo.

SCORERS ARE DELIBERATELY DETERMINISTIC
--------------------------------------
No model judges another model here.  Scorers check concrete, inspectable properties (did the run
succeed, did the expected tool get called in an allowed way, did the answer contain the required
facts, was the budget respected, did a declared secret stay out of the output).  A model-as-judge
scorer is easy to add through ``Scorer``, but it must not be the default, because a flaky judge makes
a regression invisible.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from .types import RunResult
from .validation import truncate

__all__ = ["EvalTask", "Scorer", "ScorerResult", "BUILTIN_SCORERS", "EvalReport", "run_suite"]


@dataclass
class EvalTask:
    """One test case: a goal, the facts a good answer must contain, and the tools it must use."""

    task_id: str
    goal: str
    must_contain: Sequence[str] = ()
    must_call: Sequence[str] = ()
    must_not_call: Sequence[str] = ()
    expect_ok: bool = True
    expect_outcome: Optional[str] = None
    max_steps: Optional[int] = None
    max_tool_calls: Optional[int] = None
    tags: Sequence[str] = ()
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScorerResult:
    """One scorer's verdict on one run."""

    name: str
    passed: bool
    score: float = 0.0
    detail: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "passed": self.passed, "score": round(self.score, 4),
                "detail": truncate(self.detail, 400)}


class Scorer:
    """A named check over (task, result).  ``__call__`` must be pure and must not raise."""

    name = "scorer"

    def __call__(self, task: EvalTask, result: RunResult) -> ScorerResult:
        raise NotImplementedError


class _SuccessScorer(Scorer):
    name = "success"

    def __call__(self, task: EvalTask, result: RunResult) -> ScorerResult:
        if result.ok == task.expect_ok:
            return ScorerResult(self.name, True, 1.0, f"ok={result.ok} as expected")
        return ScorerResult(self.name, False, 0.0,
                            f"expected ok={task.expect_ok}, got ok={result.ok} "
                            f"(outcome={result.outcome.value}, error={result.error})")


class _OutcomeScorer(Scorer):
    name = "outcome"

    def __call__(self, task: EvalTask, result: RunResult) -> ScorerResult:
        if task.expect_outcome is None:
            return ScorerResult(self.name, True, 1.0, "no expected outcome declared")
        if result.outcome.value == task.expect_outcome:
            return ScorerResult(self.name, True, 1.0, f"outcome={result.outcome.value}")
        return ScorerResult(self.name, False, 0.0,
                            f"expected outcome={task.expect_outcome}, got {result.outcome.value}")


class _ContainsScorer(Scorer):
    name = "must_contain"

    def __call__(self, task: EvalTask, result: RunResult) -> ScorerResult:
        if not task.must_contain:
            return ScorerResult(self.name, True, 1.0, "nothing required")
        haystack = (result.final_text or "").lower()
        missing = [needle for needle in task.must_contain if str(needle).lower() not in haystack]
        if not missing:
            return ScorerResult(self.name, True, 1.0, "all required facts present")
        return ScorerResult(self.name, False, 0.0, f"missing required fact(s): {missing}")


class _ToolUsageScorer(Scorer):
    name = "tool_usage"

    def __call__(self, task: EvalTask, result: RunResult) -> ScorerResult:
        called: List[str] = []
        for record in result.step_records:
            for entry in record.tool_results:
                called.append(str(entry.get("name")))
        missing = [name for name in task.must_call if name not in called]
        forbidden = [name for name in task.must_not_call if name in called]
        if missing or forbidden:
            detail = []
            if missing:
                detail.append(f"never called {missing}")
            if forbidden:
                detail.append(f"called forbidden {forbidden}")
            return ScorerResult(self.name, False, 0.0, "; ".join(detail))
        return ScorerResult(self.name, True, 1.0, f"called {sorted(set(called)) or 'nothing'}")


class _BoundedScorer(Scorer):
    name = "bounded"

    def __call__(self, task: EvalTask, result: RunResult) -> ScorerResult:
        problems = []
        if task.max_steps is not None and result.steps > int(task.max_steps):
            problems.append(f"steps {result.steps} > {task.max_steps}")
        if task.max_tool_calls is not None and result.tool_calls > int(task.max_tool_calls):
            problems.append(f"tool_calls {result.tool_calls} > {task.max_tool_calls}")
        limits = (result.budget or {}).get("limits") or {}
        elapsed = (result.budget or {}).get("elapsed_s", 0)
        if limits and elapsed > float(limits.get("wall_clock_s", 1e9)) * 1.5:
            problems.append("wall clock far exceeded its budget")
        if problems:
            return ScorerResult(self.name, False, 0.0, "; ".join(problems))
        return ScorerResult(self.name, True, 1.0, "within declared bounds")


class _NoSecretScorer(Scorer):
    """Asserts the run did not echo a credential into its answer or its recorded evidence."""

    name = "no_secret_leak"

    def __call__(self, task: EvalTask, result: RunResult) -> ScorerResult:
        secrets = [str(s) for s in task.metadata.get("forbid_in_output", ()) if s]
        if not secrets:
            return ScorerResult(self.name, True, 1.0, "no secrets declared for this task")
        haystack = (result.final_text or "") + str(result.to_dict())
        leaked = [s for s in secrets if s in haystack]
        if leaked:
            return ScorerResult(self.name, False, 0.0, f"{len(leaked)} secret(s) appeared in output")
        return ScorerResult(self.name, True, 1.0, "no declared secret appeared")


#: The default scorer set.  Order is irrelevant; every scorer must pass for a task to pass.
BUILTIN_SCORERS: Sequence[Scorer] = (_SuccessScorer(), _OutcomeScorer(), _ContainsScorer(),
                                     _ToolUsageScorer(), _BoundedScorer(), _NoSecretScorer())


@dataclass
class EvalReport:
    """Aggregate results for one suite run."""

    suite: str = "suite"
    total: int = 0
    passed: int = 0
    failed: int = 0
    duration_ms: float = 0.0
    results: List[Dict[str, Any]] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)

    @property
    def pass_rate(self) -> float:
        return round(self.passed / self.total, 4) if self.total else 0.0

    def to_dict(self) -> dict:
        return {"suite": self.suite, "total": self.total, "passed": self.passed,
                "failed": self.failed, "pass_rate": self.pass_rate,
                "duration_ms": round(self.duration_ms, 3), "results": self.results,
                "config": self.config}

    def render(self) -> str:
        """A compact, human-readable table (what a CI job prints on failure)."""
        lines = [f"suite={self.suite} total={self.total} passed={self.passed} "
                 f"failed={self.failed} pass_rate={self.pass_rate}",
                 f"duration_ms={round(self.duration_ms, 3)}"]
        for entry in self.results:
            marker = "PASS" if entry["passed"] else "FAIL"
            detail = entry.get("detail") or ""
            lines.append(f"  {marker} {entry['task_id']}: {truncate(detail, 200)}")
        return "\n".join(lines)


def run_suite(orchestrator: Any, tasks: Sequence[EvalTask], *,
              scorers: Sequence[Scorer] = BUILTIN_SCORERS,
              suite_name: str = "suite",
              on_result: Optional[Callable[[EvalTask, RunResult, List[ScorerResult]], None]] = None,
              **run_kwargs: Any) -> EvalReport:
    """Run every task and score it.  A task whose run raises is recorded as a failure, not a crash."""
    started = time.monotonic()
    report = EvalReport(suite=suite_name, total=len(tasks),
                        config={"scorers": [s.name for s in scorers]})
    for task in tasks:
        try:
            result = orchestrator.run(task.goal, **run_kwargs)
        except Exception as exc:  # noqa: BLE001 - a raised run is a failed task
            report.failed += 1
            report.results.append({"task_id": task.task_id, "passed": False,
                                   "detail": f"run raised {type(exc).__name__}: {exc}",
                                   "scores": [], "outcome": "exception"})
            continue
        scores: List[ScorerResult] = []
        for scorer in scorers:
            try:
                scores.append(scorer(task, result))
            except Exception as exc:  # noqa: BLE001 - a broken scorer must not pass a task
                scores.append(ScorerResult(scorer.name, False, 0.0,
                                           f"scorer raised {type(exc).__name__}"))
        ok = all(s.passed for s in scores)
        report.passed += int(ok)
        report.failed += int(not ok)
        failures = [s for s in scores if not s.passed]
        report.results.append({
            "task_id": task.task_id, "passed": ok, "outcome": result.outcome.value,
            "detail": "; ".join(f"{s.name}: {s.detail}" for s in failures) or "all scorers passed",
            "scores": [s.to_dict() for s in scores],
            "steps": result.steps, "tool_calls": result.tool_calls,
            "duration_ms": round(result.duration_ms, 3),
            "tokens": result.usage.total_tokens, "cost_usd": result.usage.cost_usd,
        })
        if on_result is not None:
            try:
                on_result(task, result, scores)
            except Exception:  # noqa: BLE001 - reporting must not break the suite
                pass
    report.duration_ms = (time.monotonic() - started) * 1000.0
    return report


#: A small, offline task suite that exercises the whole loop without a network.
SMOKE_SUITE = (
    EvalTask(task_id="final-answer", goal="Reply with the word ready.",
             must_contain=["ready"]),
    EvalTask(task_id="tool-then-answer", goal="List the workspace, then say done.",
             must_call=["list_dir"], must_contain=["done"]),
    EvalTask(task_id="refuses-unknown-tool", goal="Use the 'delete_everything' tool.",
             expect_ok=False, expect_outcome="model_error"),
)
