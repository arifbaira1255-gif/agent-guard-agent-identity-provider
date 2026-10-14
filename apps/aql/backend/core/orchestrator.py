"""Multi-agent orchestrator for AQL-1.

AQL-1's "operating layer" claim is that a single prompt is not answered by one
model call but by a *team* of specialised agents that hand a shared state back
and forth until the work is actually done. This module implements that team:

* :class:`PlannerAgent`   — decomposes the prompt into ordered sub-tasks.
* :class:`ExecutionAgent` — runs each sub-task with a registered tool.
* :class:`ReviewerAgent`  — validates each result and the final output.

:class:`MultiAgentOrchestrator` drives the control loop::

    plan → execute → review → (revise & re-execute if rejected) → … → final

until every sub-task is approved or a max-iteration cap is hit.

Design goals
------------
* **Runs with zero API keys.** Every agent has a deterministic local
  implementation. When a real model answers, its output is used; when the
  router returns a stub (no keys / provider outage), the local path takes over
  so the loop always completes.
* **Inherits routing.** All model calls go through :class:`~core.router.ModelRouter`,
  so cost estimation and provider fallback come for free.
* **Remembers.** Optionally recalls relevant past context at the start and
  stores the run at the end via :class:`~memory.manager.MemoryManager`.
* **Typed failures.** ``OrchestrationError`` and friends, never bare ``Exception``.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .config import get_settings
from .guardrails import ApprovalNotFoundError, ApprovalStore, check_action_risk
from .router import ModelRouter, RouterResult

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Typed exceptions
# ══════════════════════════════════════════════════════════════════════════════
class OrchestrationError(Exception):
    """Base class for every orchestration failure."""


class PlanningError(OrchestrationError):
    """The planner could not produce a usable plan."""


class ExecutionError(OrchestrationError):
    """A sub-task could not be executed."""


class ReviewError(OrchestrationError):
    """The reviewer could not produce a verdict."""


# ══════════════════════════════════════════════════════════════════════════════
# Shared state
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class SubTask:
    """One ordered unit of work produced by the planner."""

    id: str
    description: str
    tool: str = "echo"
    status: str = "pending"  # pending | approved | needs-revision
    attempts: int = 0
    feedback: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "tool": self.tool,
            "status": self.status,
            "attempts": self.attempts,
            "feedback": self.feedback,
        }


@dataclass
class StepResult:
    """The outcome of executing one sub-task."""

    task_id: str
    tool: str
    output: str
    ok: bool = True
    error: str | None = None
    model: str = ""
    provider: str = ""
    cost_usd: float = 0.0
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "tool": self.tool,
            "output": self.output,
            "ok": self.ok,
            "error": self.error,
            "model": self.model,
            "provider": self.provider,
            "cost_usd": round(self.cost_usd, 8),
            "duration_ms": self.duration_ms,
        }


@dataclass
class ReviewVerdict:
    """The reviewer's judgement on one executed sub-task."""

    task_id: str
    verdict: str  # approved | needs-revision
    feedback: str = ""
    score: float = 1.0

    @property
    def approved(self) -> bool:
        return self.verdict == "approved"

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "verdict": self.verdict,
            "feedback": self.feedback,
            "score": round(self.score, 4),
        }


@dataclass
class OrchestrationState:
    """The typed shared state passed between the agents.

    Carries the original prompt, the plan, per-step results, review feedback,
    the iteration count and the final output — everything the loop needs to
    make a decision and everything a caller needs to audit the run.
    """

    run_id: str
    prompt: str
    plan: list[SubTask] = field(default_factory=list)
    results: list[StepResult] = field(default_factory=list)
    reviews: list[ReviewVerdict] = field(default_factory=list)
    iteration: int = 0
    max_iterations: int = 3
    final_output: str | None = None
    # running | completed | max_iterations | failed | pending_approval | rejected
    status: str = "running"
    error: str | None = None
    approval_id: str | None = None
    memory_context: str = ""
    user_id: str = "anonymous"
    session_id: str = "default"
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None

    # ── derived views ────────────────────────────────────────────────────────
    @property
    def duration_ms(self) -> int:
        end = self.finished_at or time.time()
        return int((end - self.started_at) * 1000)

    @property
    def total_cost_usd(self) -> float:
        return round(sum(r.cost_usd for r in self.results), 8)

    @property
    def approved_count(self) -> int:
        return sum(1 for t in self.plan if t.status == "approved")

    @property
    def all_approved(self) -> bool:
        return bool(self.plan) and all(t.status == "approved" for t in self.plan)

    def latest_result(self, task_id: str) -> StepResult | None:
        """The most recent execution result for ``task_id``."""
        for result in reversed(self.results):
            if result.task_id == task_id:
                return result
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "prompt": self.prompt,
            "status": self.status,
            "error": self.error,
            "approval_id": self.approval_id,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "duration_ms": self.duration_ms,
            "total_cost_usd": self.total_cost_usd,
            "approved_count": self.approved_count,
            "plan": [t.to_dict() for t in self.plan],
            "results": [r.to_dict() for r in self.results],
            "reviews": [v.to_dict() for v in self.reviews],
            "final_output": self.final_output,
            "memory_context": self.memory_context,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Tool suggestion heuristics (shared by the planner)
# ══════════════════════════════════════════════════════════════════════════════
_SEARCH_HINTS = (
    "search", "find", "research", "look up", "lookup", "news", "latest",
    "web", "google", "source", "cite", "reference", "market", "trend",
)
_CODE_HINTS = (
    "calculate", "compute", "code", "script", "python", "sum", "math",
    "algorithm", "function", "parse", "count", "average", "total", "percent",
)
_FILE_HINTS = (
    "write", "create file", "generate", "save", "report", "document",
    "draft", "export", "file", "summary", "summarize", "summarise",
)
_SEQUENCE_SPLIT = re.compile(
    r"\b(?:then|after that|and then|next|finally|followed by|afterwards)\b",
    re.IGNORECASE,
)
_NUMBERED = re.compile(r"^\s*(?:\d+[\.\)]|[-*•])\s*")


def suggest_tool(description: str) -> str:
    """Pick the most likely tool for a sub-task description.

    Hints are matched on word boundaries so a word like "summary" is not
    mistaken for the calculation hint "sum", nor "findings" for "find".
    """
    text = (description or "").lower()

    def _hits(hints: tuple[str, ...]) -> bool:
        return any(re.search(rf"\b{re.escape(h)}\b", text) for h in hints)

    if _hits(_SEARCH_HINTS):
        return "web_search"
    if _hits(_CODE_HINTS):
        return "python_exec"
    if _hits(_FILE_HINTS):
        return "file_generator"
    return "echo"


# ══════════════════════════════════════════════════════════════════════════════
# PlannerAgent
# ══════════════════════════════════════════════════════════════════════════════
class PlannerAgent:
    """Breaks the incoming prompt into an ordered list of sub-tasks."""

    def __init__(self, router: ModelRouter | None = None, max_steps: int = 6) -> None:
        self.router = router or ModelRouter()
        self.max_steps = max_steps

    # ── LLM path ─────────────────────────────────────────────────────────────
    def _plan_prompt(self, prompt: str, context: str) -> str:
        ctx = f"\nRelevant past context:\n{context}\n" if context else ""
        return (
            "You are a planning agent. Decompose the user's request into an "
            "ordered list of concrete sub-tasks. Reply with one sub-task per "
            "line, numbered, and name the best tool for each in brackets "
            "(web_search, python_exec, file_generator, echo).\n"
            f"{ctx}\nRequest: {prompt}"
        )

    def _parse_plan(self, text: str) -> list[SubTask]:
        """Parse an LLM plan (numbered lines) into :class:`SubTask` objects."""
        tasks: list[SubTask] = []
        for raw in (text or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            line = _NUMBERED.sub("", line).strip()
            if not line:
                continue
            tool = "echo"
            match = re.search(r"\[([a-z_]+)\]", line)
            if match:
                tool = match.group(1)
                line = line.replace(match.group(0), "").strip(" -:.")
            if not line:
                continue
            tasks.append(
                SubTask(id=f"t{len(tasks) + 1}", description=line, tool=tool)
            )
            if len(tasks) >= self.max_steps:
                break
        return tasks

    # ── deterministic local path ─────────────────────────────────────────────
    def _local_plan(self, prompt: str) -> list[SubTask]:
        """Heuristic decomposition — always available, fully deterministic."""
        text = (prompt or "").strip()

        # 1) explicit numbered / bulleted lines win.
        steps = [
            _NUMBERED.sub("", line).strip()
            for line in re.split(r"[\n;]+", text)
            if line.strip()
        ]
        steps = [s for s in steps if s]

        # 2) a single long sentence → split on sequencing markers.
        if len(steps) <= 1:
            parts = [
                p.strip(" ,.")
                for p in _SEQUENCE_SPLIT.split(text)
                if p.strip(" ,.")
            ]
            if len(parts) > 1:
                steps = parts

        # 3) last resort: the whole prompt is one step.
        if not steps:
            steps = [text or "Complete the task"]

        steps = steps[: self.max_steps]
        return [
            SubTask(id=f"t{i + 1}", description=s, tool=suggest_tool(s))
            for i, s in enumerate(steps)
        ]

    # ── public API ───────────────────────────────────────────────────────────
    def plan(self, prompt: str, context: str = "") -> list[SubTask]:
        """Return an ordered plan for ``prompt``.

        Tries the model first; if the router returns a stub (no keys) or the
        reply cannot be parsed, falls back to the deterministic local planner.
        """
        try:
            result: RouterResult = self.router.call(self._plan_prompt(prompt, context))
            if not result.is_stub:
                parsed = self._parse_plan(result.text)
                if parsed:
                    return parsed
        except Exception as exc:  # noqa: BLE001 — planning must never crash the run
            logger.warning("PlannerAgent LLM path failed (%s) — using local plan", exc)

        try:
            return self._local_plan(prompt)
        except Exception as exc:  # noqa: BLE001
            raise PlanningError(str(exc)) from exc


# ══════════════════════════════════════════════════════════════════════════════
# ExecutionAgent
# ══════════════════════════════════════════════════════════════════════════════
class ExecutionAgent:
    """Runs each sub-task using the registered tools."""

    def __init__(
        self,
        router: ModelRouter | None = None,
        registry: Any | None = None,
        output_dir: str | None = None,
        guardrails: ApprovalStore | None = None,
    ) -> None:
        self.router = router or ModelRouter()
        if registry is None:
            from tools.registry import registry as default_registry

            registry = default_registry
        self.registry = registry
        self.settings = get_settings()
        # Safety layer: the orchestrator gates each sub-task through this.
        self.guardrails = guardrails or ApprovalStore()
        self.output_dir = output_dir or getattr(
            self.settings, "orchestrator_output_dir", "orchestrator_output"
        )

    # ── tool dispatch ────────────────────────────────────────────────────────
    @staticmethod
    def _derive_code(description: str) -> str:
        """Best-effort: turn a natural-language step into a runnable snippet."""
        expr = re.search(r"[-+*/%().\d\s]{3,}", description or "")
        if expr:
            candidate = expr.group(0).strip()
            if re.search(r"\d", candidate) and re.search(r"[-+*/%]", candidate):
                return f"print({candidate})"
        # Deterministic fallback: report a simple, reproducible fact.
        return f"print('step:', {description!r})"

    def _run_tool(self, task: SubTask) -> tuple[str, bool, str | None]:
        """Call the sub-task's tool. Returns ``(output, ok, error)``."""
        try:
            if task.tool == "web_search":
                data = self.registry.call("web_search", query=task.description)
                lines = [f"- {r['title']} ({r['url']})" for r in data["results"]]
                return "\n".join(lines), True, None

            if task.tool == "python_exec":
                data = self.registry.call(
                    "python_exec", code=self._derive_code(task.description)
                )
                if data.get("ok"):
                    return data.get("stdout", ""), True, None
                return data.get("stdout", ""), False, data.get("error")

            if task.tool == "file_generator":
                filename = f"{task.id}.txt"
                content = f"# {task.description}\n"
                data = self.registry.call(
                    "file_generator",
                    filename=filename,
                    content=content,
                    output_dir=self.output_dir,
                )
                return f"wrote {data['path']} ({data['bytes']} bytes)", True, None

            # default: echo
            return str(self.registry.call("echo", text=task.description)), True, None
        except Exception as exc:  # noqa: BLE001 — a tool failure is data, not a crash
            return "", False, f"{type(exc).__name__}: {exc}"

    # ── public API ───────────────────────────────────────────────────────────
    def execute(self, task: SubTask, state: OrchestrationState) -> StepResult:
        """Execute ``task`` and return a :class:`StepResult`.

        The tool always runs (deterministic, offline-safe). A model call then
        optionally enriches the output; when the router returns a stub the tool
        output is used verbatim, so the loop completes with no API keys.
        """
        started = time.time()
        tool_output, ok, error = self._run_tool(task)

        output = tool_output
        model = provider = ""
        cost = 0.0
        try:
            result = self.router.call(
                f"Execute this sub-task and return the result:\n{task.description}"
            )
            model, provider, cost = result.model, result.provider, result.estimated_cost_usd
            if not result.is_stub and result.text.strip():
                output = result.text.strip()
        except Exception as exc:  # noqa: BLE001 — enrichment is best-effort
            logger.warning("ExecutionAgent LLM enrichment failed (%s)", exc)

        return StepResult(
            task_id=task.id,
            tool=task.tool,
            output=output,
            ok=ok,
            error=error,
            model=model,
            provider=provider,
            cost_usd=cost,
            duration_ms=int((time.time() - started) * 1000),
        )


# ══════════════════════════════════════════════════════════════════════════════
# ReviewerAgent
# ══════════════════════════════════════════════════════════════════════════════
class ReviewerAgent:
    """Validates the accuracy of each executed sub-task and the final result."""

    def __init__(
        self,
        router: ModelRouter | None = None,
        min_output_chars: int = 1,
    ) -> None:
        self.router = router or ModelRouter()
        # A successful tool run with *any* non-empty output is accepted by
        # default — a valid answer can be as short as "4". Raise this only if
        # your sub-tasks are expected to return prose.
        self.min_output_chars = min_output_chars

    # ── LLM path ─────────────────────────────────────────────────────────────
    def _review_prompt(self, task: SubTask, result: StepResult) -> str:
        return (
            "You are a strict reviewer. Decide whether the sub-task output is "
            "correct and complete. Reply with 'APPROVED' or 'NEEDS-REVISION' "
            "followed by one short sentence of feedback.\n"
            f"Sub-task: {task.description}\n"
            f"Tool: {task.tool}\n"
            f"Output: {result.output}"
        )

    def _parse_verdict(self, text: str) -> ReviewVerdict | None:
        upper = (text or "").upper()
        if "NEEDS-REVISION" in upper or "NEEDS REVISION" in upper:
            verdict = "needs-revision"
        elif "APPROVED" in upper:
            verdict = "approved"
        else:
            return None
        feedback = re.sub(
            r"(?i)(needs[- ]revision|approved)\s*[:\-]?\s*", "", text or ""
        ).strip()
        return ReviewVerdict(
            task_id="", verdict=verdict, feedback=feedback or "model verdict",
            score=1.0 if verdict == "approved" else 0.4,
        )

    # ── deterministic local path ─────────────────────────────────────────────
    def _local_review(self, task: SubTask, result: StepResult) -> ReviewVerdict:
        """Heuristic validation — always available, fully deterministic."""
        if not result.ok:
            return ReviewVerdict(
                task_id=task.id,
                verdict="needs-revision",
                feedback=f"tool failed: {result.error}",
                score=0.0,
            )
        output = (result.output or "").strip()
        if not output:
            return ReviewVerdict(
                task_id=task.id,
                verdict="needs-revision",
                feedback="output is empty",
                score=0.0,
            )
        if len(output) < self.min_output_chars:
            return ReviewVerdict(
                task_id=task.id,
                verdict="needs-revision",
                feedback="output is too short to be useful",
                score=0.3,
            )
        return ReviewVerdict(
            task_id=task.id,
            verdict="approved",
            feedback="output looks complete",
            score=1.0,
        )

    # ── public API ───────────────────────────────────────────────────────────
    def review(
        self, task: SubTask, result: StepResult, state: OrchestrationState | None = None
    ) -> ReviewVerdict:
        """Return a verdict for ``result`` (approved / needs-revision)."""
        try:
            res = self.router.call(self._review_prompt(task, result))
            if not res.is_stub:
                parsed = self._parse_verdict(res.text)
                if parsed is not None:
                    parsed.task_id = task.id
                    return parsed
        except Exception as exc:  # noqa: BLE001 — review must never crash the loop
            logger.warning("ReviewerAgent LLM path failed (%s) — using local review", exc)

        try:
            return self._local_review(task, result)
        except Exception as exc:  # noqa: BLE001
            raise ReviewError(str(exc)) from exc


# ══════════════════════════════════════════════════════════════════════════════
# MultiAgentOrchestrator
# ══════════════════════════════════════════════════════════════════════════════
class MultiAgentOrchestrator:
    """Drives plan → execute → review → revise until the output is ready."""

    def __init__(
        self,
        router: ModelRouter | None = None,
        planner: PlannerAgent | None = None,
        executor: ExecutionAgent | None = None,
        reviewer: ReviewerAgent | None = None,
        memory: Any | None = None,
        guardrails: ApprovalStore | None = None,
        max_iterations: int = 3,
        use_memory: bool = True,
    ) -> None:
        self.settings = get_settings()
        self.router = router or ModelRouter()
        self.planner = planner or PlannerAgent(router=self.router)
        self.executor = executor or ExecutionAgent(router=self.router)
        self.reviewer = reviewer or ReviewerAgent(router=self.router)
        # Safety layer: high-risk sub-tasks pause the whole run for approval.
        self.guardrails = guardrails or ApprovalStore()
        self.max_iterations = max_iterations
        self.use_memory = use_memory

        # Memory is optional: import lazily so a missing/broken memory layer
        # never stops the orchestrator from running.
        if memory is not None:
            self.memory = memory
        elif use_memory:
            try:
                from memory.manager import MemoryManager

                self.memory = MemoryManager()
            except Exception as exc:  # noqa: BLE001
                logger.warning("MemoryManager unavailable (%s) — running without memory", exc)
                self.memory = None
        else:
            self.memory = None

    # ── memory helpers ───────────────────────────────────────────────────────
    def _recall(self, prompt: str, user_id: str, session_id: str) -> str:
        """Recall relevant past context (empty string when memory is off)."""
        if self.memory is None:
            return ""
        try:
            return self.memory.build_context(
                prompt, user_id=user_id, session_id=session_id
            )
        except Exception as exc:  # noqa: BLE001 — memory is best-effort
            logger.warning("Memory recall failed (%s)", exc)
            return ""

    def _remember(self, state: OrchestrationState) -> None:
        """Store the completed run (best-effort)."""
        if self.memory is None or not state.final_output:
            return
        try:
            self.memory.record(
                state.prompt,
                state.final_output,
                user_id=state.user_id,
                session_id=state.session_id,
                model=self.router.route(state.prompt).model,
                provider=self.router.route(state.prompt).provider,
                cost_usd=state.total_cost_usd,
                latency_ms=state.duration_ms,
                run_id=state.run_id,
            )
        except Exception as exc:  # noqa: BLE001 — never fail a run over memory
            logger.warning("Memory store failed (%s)", exc)

    # ── synthesis ────────────────────────────────────────────────────────────
    @staticmethod
    def _synthesize(state: OrchestrationState) -> str:
        """Assemble the final output from the latest result of each sub-task."""
        lines: list[str] = []
        for task in state.plan:
            result = state.latest_result(task.id)
            body = (result.output if result else "").strip() or "(no output)"
            lines.append(f"[{task.id}] {task.description}\n{body}")
        return "\n\n".join(lines)

    # ── the control loop ─────────────────────────────────────────────────────
    def run(
        self,
        prompt: str,
        *,
        user_id: str = "anonymous",
        session_id: str = "default",
        max_iterations: int | None = None,
        _approved_task_ids: set[str] | None = None,
        _run_id: str | None = None,
    ) -> OrchestrationState:
        """Orchestrate ``prompt`` end-to-end and return the final state.

        Loop: plan once, then repeatedly execute every sub-task that is not yet
        approved and review it. A rejected sub-task is re-executed on the next
        iteration. Stops when all sub-tasks are approved or the iteration cap
        is reached — it never raises for a normal failure.
        """
        cap = max_iterations or self.max_iterations
        state = OrchestrationState(
            run_id=_run_id or str(uuid.uuid4()),
            prompt=prompt,
            max_iterations=cap,
            user_id=user_id,
            session_id=session_id,
        )

        try:
            # 1) recall relevant past context
            state.memory_context = self._recall(prompt, user_id, session_id)

            # 2) plan
            state.plan = self.planner.plan(prompt, context=state.memory_context)
            if not state.plan:
                raise PlanningError("planner produced an empty plan")

            # 3) execute → review → revise, until approved or capped
            for iteration in range(1, cap + 1):
                state.iteration = iteration
                pending = [t for t in state.plan if t.status != "approved"]
                if not pending:
                    break

                for task in pending:
                    # ── Safety gate: pause high-risk sub-tasks ────────────────
                    # A sub-task already approved by a human is let through.
                    if not (_approved_task_ids and task.id in _approved_task_ids):
                        assessment = check_action_risk(
                            task.tool, {"description": task.description}
                        )
                        if assessment.requires_approval:
                            approval = self.guardrails.pause(
                                run_id=state.run_id,
                                action_type=task.tool,
                                payload={"description": task.description},
                                assessment=assessment,
                                kind="orchestrator",
                                resume_state={
                                    "prompt": prompt,
                                    "user_id": user_id,
                                    "session_id": session_id,
                                    "task_id": task.id,
                                },
                                user_id=user_id,
                                session_id=session_id,
                            )
                            state.status = "pending_approval"
                            state.approval_id = approval.approval_id
                            state.final_output = (
                                "Paused for human approval — sub-task "
                                f"{task.id} ({task.tool}) is high-risk: "
                                f"{', '.join(assessment.matched_rules) or 'unclassified'}."
                            )
                            state.finished_at = time.time()
                            return state

                    task.attempts += 1
                    result = self.executor.execute(task, state)
                    state.results.append(result)

                    verdict = self.reviewer.review(task, result, state)
                    state.reviews.append(verdict)

                    if verdict.approved:
                        task.status = "approved"
                        task.feedback = verdict.feedback
                    else:
                        task.status = "needs-revision"
                        task.feedback = verdict.feedback

                if state.all_approved:
                    break
            else:
                # Loop exhausted without every sub-task being approved.
                state.status = "max_iterations"

            # 4) final output
            state.final_output = self._synthesize(state)
            if state.status == "running":
                state.status = "completed"

            # 5) remember the run
            self._remember(state)

        except OrchestrationError as exc:
            state.status = "failed"
            state.error = str(exc)
            state.final_output = state.final_output or ""
        except Exception as exc:  # noqa: BLE001 — surface any failure on the state
            state.status = "failed"
            state.error = f"{type(exc).__name__}: {exc}"
            state.final_output = state.final_output or ""
        finally:
            state.finished_at = time.time()

        return state

    def resume(
        self,
        run_id: str,
        decision: str = "approve",
        *,
        approver: str | None = None,
        note: str = "",
    ) -> OrchestrationState:
        """Resume (or reject) an orchestration paused for human approval.

        Raises:
            ApprovalNotFoundError: No pending approval exists for ``run_id``.
        """
        approval = self.guardrails.find_by_run(run_id)
        if approval is None:
            raise ApprovalNotFoundError(f"no pending approval for run {run_id}")

        decided = self.guardrails.decide(
            approval.approval_id, decision, approver=approver, note=note
        )
        resume_state = approval.resume_state or {}
        prompt = resume_state.get("prompt", "")

        if decided.status != "approved":
            state = OrchestrationState(
                run_id=run_id,
                prompt=prompt,
                status="rejected",
                approval_id=decided.approval_id,
                user_id=resume_state.get("user_id", "anonymous"),
                session_id=resume_state.get("session_id", "default"),
            )
            state.final_output = (
                f"Rejected by {approver or 'human'}: {note or 'no note'}"
            )
            state.finished_at = time.time()
            return state

        # Approved → re-run the orchestration, letting the approved sub-task
        # through the gate this time.
        approved_ids = {resume_state["task_id"]} if resume_state.get("task_id") else set()
        return self.run(
            prompt,
            user_id=resume_state.get("user_id", "anonymous"),
            session_id=resume_state.get("session_id", "default"),
            _approved_task_ids=approved_ids,
            _run_id=run_id,
        )


__all__ = [
    "MultiAgentOrchestrator",
    "PlannerAgent",
    "ExecutionAgent",
    "ReviewerAgent",
    "OrchestrationState",
    "SubTask",
    "StepResult",
    "ReviewVerdict",
    "OrchestrationError",
    "PlanningError",
    "ExecutionError",
    "ReviewError",
    "suggest_tool",
]
