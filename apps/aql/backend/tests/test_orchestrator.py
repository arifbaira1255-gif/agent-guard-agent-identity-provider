"""Tests for the multi-agent orchestrator.

Covers: planning produces ordered sub-tasks, the execute→review loop, a
revision cycle when the reviewer rejects, the max-iteration cap, and the
no-keys fallback path.
"""

from __future__ import annotations

from core.orchestrator import (
    ExecutionAgent,
    MultiAgentOrchestrator,
    OrchestrationState,
    PlannerAgent,
    ReviewerAgent,
    StepResult,
    SubTask,
    suggest_tool,
)
from tools.registry import registry


# ── helpers ──────────────────────────────────────────────────────────────────
class _RejectOnceReviewer(ReviewerAgent):
    """Rejects a given task on its first review, then approves it."""

    def __init__(self, reject_task_id: str = "t1") -> None:
        super().__init__()
        self.reject_task_id = reject_task_id
        self.seen: dict[str, int] = {}

    def review(self, task, result, state=None):  # type: ignore[override]
        count = self.seen.get(task.id, 0) + 1
        self.seen[task.id] = count
        if task.id == self.reject_task_id and count == 1:
            from core.orchestrator import ReviewVerdict

            return ReviewVerdict(
                task_id=task.id,
                verdict="needs-revision",
                feedback="first pass rejected",
                score=0.2,
            )
        return super().review(task, result, state)


class _AlwaysRejectReviewer(ReviewerAgent):
    """Rejects every sub-task, every time — forces the iteration cap."""

    def review(self, task, result, state=None):  # type: ignore[override]
        from core.orchestrator import ReviewVerdict

        return ReviewVerdict(
            task_id=task.id,
            verdict="needs-revision",
            feedback="never good enough",
            score=0.0,
        )


# ── tool registry additions ──────────────────────────────────────────────────
def test_orchestrator_tools_registered():
    names = {t.name for t in registry.list()}
    assert {"web_search", "python_exec", "file_generator"} <= names


def test_web_search_tool_shape():
    data = registry.call("web_search", query="aql-1", max_results=2)
    assert data["query"] == "aql-1"
    assert len(data["results"]) == 2
    assert {"title", "url", "snippet"} <= set(data["results"][0])


def test_python_exec_tool_runs():
    data = registry.call("python_exec", code="print(2 + 2)")
    assert data["ok"] is True
    assert data["stdout"] == "4"


def test_python_exec_tool_reports_errors():
    data = registry.call("python_exec", code="raise ValueError('boom')")
    assert data["ok"] is False
    assert "boom" in (data["error"] or "")


def test_file_generator_tool_writes(tmp_path):
    data = registry.call(
        "file_generator",
        filename="note.txt",
        content="hello",
        output_dir=str(tmp_path),
    )
    assert data["bytes"] == 5
    assert (tmp_path / "note.txt").read_text() == "hello"


# ── planning ─────────────────────────────────────────────────────────────────
def test_plan_produces_ordered_subtasks():
    plan = PlannerAgent().plan("First gather data, then analyze it, finally write a report")
    assert len(plan) >= 3
    assert [t.id for t in plan] == [f"t{i + 1}" for i in range(len(plan))]
    assert plan[0].description.lower().startswith("first gather")


def test_plan_numbered_lines():
    plan = PlannerAgent().plan("1. search the web\n2. compute the total\n3. write a file")
    assert len(plan) == 3
    assert plan[0].tool == "web_search"
    assert plan[1].tool == "python_exec"
    assert plan[2].tool == "file_generator"


def test_plan_single_prompt_is_one_step():
    plan = PlannerAgent().plan("Say hello")
    assert len(plan) == 1
    assert plan[0].id == "t1"


def test_plan_respects_max_steps():
    plan = PlannerAgent(max_steps=2).plan("1. a\n2. b\n3. c\n4. d")
    assert len(plan) == 2


def test_suggest_tool_heuristics():
    assert suggest_tool("search the web for news") == "web_search"
    assert suggest_tool("calculate the sum") == "python_exec"
    assert suggest_tool("write a report file") == "file_generator"
    assert suggest_tool("just say hi") == "echo"


def test_suggest_tool_word_boundary():
    # "summary" must not be mistaken for the calculation hint "sum".
    assert suggest_tool("write a summary file") == "file_generator"
    assert suggest_tool("summarize the findings") == "file_generator"


# ── execute → review loop ────────────────────────────────────────────────────
def test_execute_review_loop_completes():
    orch = MultiAgentOrchestrator(use_memory=False)
    state = orch.run("First search for AI news, then write a summary file")

    assert state.status == "completed"
    assert state.plan, "planner produced no plan"
    assert state.results, "no sub-task was executed"
    assert state.reviews, "no review was produced"
    assert state.all_approved
    assert state.final_output
    assert state.iteration >= 1


def test_state_to_dict_is_serialisable():
    orch = MultiAgentOrchestrator(use_memory=False)
    payload = orch.run("Say hello").to_dict()
    assert payload["status"] == "completed"
    assert isinstance(payload["plan"], list)
    assert isinstance(payload["results"], list)
    assert "total_cost_usd" in payload


def test_execution_agent_returns_step_result():
    task = SubTask(id="t1", description="echo this", tool="echo")
    state = OrchestrationState(run_id="r1", prompt="echo this")
    result = ExecutionAgent().execute(task, state)
    assert isinstance(result, StepResult)
    assert result.ok is True
    assert result.output


def test_reviewer_approves_good_output():
    task = SubTask(id="t1", description="do it", tool="echo")
    result = StepResult(task_id="t1", tool="echo", output="a solid answer")
    verdict = ReviewerAgent().review(task, result)
    assert verdict.approved


def test_reviewer_rejects_failed_tool():
    task = SubTask(id="t1", description="do it", tool="python_exec")
    result = StepResult(
        task_id="t1", tool="python_exec", output="", ok=False, error="boom"
    )
    verdict = ReviewerAgent().review(task, result)
    assert not verdict.approved
    assert "boom" in verdict.feedback


# ── revision cycle ───────────────────────────────────────────────────────────
def test_revision_cycle_reexecutes_rejected_task():
    orch = MultiAgentOrchestrator(
        reviewer=_RejectOnceReviewer("t1"), use_memory=False
    )
    state = orch.run("First search for data, then write a report")

    assert state.status == "completed"
    assert state.iteration >= 2, "should have needed a second iteration"
    # t1 was executed twice: once rejected, once approved.
    t1_results = [r for r in state.results if r.task_id == "t1"]
    assert len(t1_results) == 2
    assert state.plan[0].attempts == 2
    assert state.plan[0].status == "approved"


# ── max-iteration cap ────────────────────────────────────────────────────────
def test_max_iteration_cap_is_respected():
    orch = MultiAgentOrchestrator(
        reviewer=_AlwaysRejectReviewer(), max_iterations=2, use_memory=False
    )
    state = orch.run("First do A, then do B")

    assert state.status == "max_iterations"
    assert state.iteration == 2
    # every sub-task was attempted once per iteration
    assert all(t.attempts == 2 for t in state.plan)
    assert state.final_output  # still produces output, never hard-fails


def test_run_level_max_iterations_override():
    orch = MultiAgentOrchestrator(
        reviewer=_AlwaysRejectReviewer(), max_iterations=5, use_memory=False
    )
    state = orch.run("First do A, then do B", max_iterations=1)
    assert state.iteration == 1
    assert state.status == "max_iterations"


# ── no-keys fallback path ────────────────────────────────────────────────────
def test_runs_without_api_keys():
    # No keys configured → every model call returns a stub, yet the loop must
    # still plan, execute, review and finish.
    orch = MultiAgentOrchestrator(use_memory=False)
    state = orch.run("First search the web, then calculate 2 + 2, then write a file")

    assert state.status == "completed"
    assert len(state.plan) >= 2
    assert state.all_approved
    assert state.final_output
    assert state.error is None


def test_memory_disabled_is_safe():
    orch = MultiAgentOrchestrator(use_memory=False)
    assert orch.memory is None
    state = orch.run("Say hello")
    assert state.status == "completed"
    assert state.memory_context == ""


def test_orchestrator_never_raises_on_bad_prompt():
    orch = MultiAgentOrchestrator(use_memory=False)
    state = orch.run("")
    assert state.status in {"completed", "max_iterations", "failed"}
    assert state.finished_at is not None
