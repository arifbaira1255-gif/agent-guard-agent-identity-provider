"""Integration tests: the whole agent loop, end to end, offline and deterministic.

These are the tests that would catch a regression a unit test cannot -- a change to the loop's control
flow, to the guard wiring, to memory interaction, or to the sandbox bridge's refusal path.
"""
from __future__ import annotations

import json

import pytest

from agent_platform.budget import CancellationToken, RunBudget
from agent_platform.config import PlatformConfig
from agent_platform.errors import ConfigError
from agent_platform.evaluation import EvalTask, run_suite
from agent_platform.events import EventBus, recording_sink
from agent_platform.memory import EpisodicMemory, WorkingMemory
from agent_platform.orchestrator import AgentOrchestrator, NullPlanner, StaticPlanner
from agent_platform.router import DeterministicProvider, ModelRouter, Route
from agent_platform.sandbox import SandboxBridge
from agent_platform.tools import (
    AllowAllGate,
    AuthorizationGate,
    CallableGate,
    ContractGate,
    DenyAllGate,
    ToolGuard,
    ToolRegistry,
)
from agent_platform.tracing import Tracer
from agent_platform.types import RunOutcome, ToolCall


@pytest.fixture()
def workspace(tmp_path):
    (tmp_path / "notes.txt").write_text("hello from the workspace\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "nested.txt").write_text("nested\n", encoding="utf-8")
    return str(tmp_path)


def build(script, *, workspace, gate=None, config=None, memory=None, tracer=None, sandbox=None):
    from agent_platform.builtin_tools import register_builtin_tools

    config = config or PlatformConfig(enabled=True)
    tracer = tracer or Tracer()
    events = EventBus([recording_sink()], capacity=50)
    registry = ToolRegistry()
    register_builtin_tools(registry, workspace_root=workspace, sandbox_bridge=sandbox,
                           include_sandbox=sandbox is not None)
    guard = ToolGuard(registry, gate=gate or AllowAllGate(), tracer=tracer,
                      on_event=lambda **kw: events.record(**kw))
    provider = DeterministicProvider(script)
    router = ModelRouter(config, routes=[Route(provider, config.model)], tracer=tracer)
    agent = AgentOrchestrator(router, guard, config=config, memory=memory, tracer=tracer,
                              events=events, sandbox=sandbox,
                              working_memory=WorkingMemory(
                                  max_messages=config.working_memory_max_messages))
    return agent, provider


# =============================================================================================
# The successful path
# =============================================================================================
class TestHappyPath:
    def test_tool_call_then_final_answer(self, workspace):
        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}]},
            "the workspace contains notes.txt",
        ], workspace=workspace)
        result = agent.run("List the workspace.")
        assert result.ok and result.outcome is RunOutcome.OK
        assert result.steps == 2 and result.tool_calls == 1
        assert "notes.txt" in result.final_text
        called = [t["name"] for s in result.step_records for t in s.tool_results]
        assert called == ["list_dir"]

    def test_final_answer_without_tools(self, workspace):
        agent, provider = build(["42"], workspace=workspace)
        result = agent.run("What is the answer?")
        assert result.ok and result.final_text == "42"
        assert result.tool_calls == 0 and len(provider.calls) == 1

    def test_transcript_is_complete_and_ordered(self, workspace):
        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}]},
            "done",
        ], workspace=workspace)
        result = agent.run("List it.")
        roles = [m.role for m in result.transcript]
        assert roles[0] == "system" and roles[1] == "user"
        assert roles.count("tool") == 1 and roles[-1] == "assistant"

    def test_usage_is_accumulated_across_steps(self, workspace):
        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}],
             "usage": {"prompt_tokens": 10, "completion_tokens": 5}},
            {"text": "done", "usage": {"prompt_tokens": 20, "completion_tokens": 7}},
        ], workspace=workspace)
        result = agent.run("List it.")
        assert result.usage.total_tokens == 42

    def test_result_serialises_to_json(self, workspace):
        agent, _ = build(["done"], workspace=workspace)
        result = agent.run("Say done.")
        payload = json.dumps(result.to_dict())
        assert "transcript" in payload and "budget" in payload

    def test_planner_injects_a_plan_into_the_prompt(self, workspace):
        agent, provider = build(["3. final"], workspace=workspace)
        agent.planner = StaticPlanner(agent.router, max_steps=3)
        result = agent.run("Do the thing.", plan=True)
        assert result.plan is not None
        assert "final" in (result.plan["steps"][0] if result.plan["steps"] else "")
        assert provider.calls[0].messages[0].role == "system"

    def test_null_planner_is_the_default(self, workspace):
        agent, _ = build(["done"], workspace=workspace)
        assert isinstance(agent.planner, NullPlanner)
        result = agent.run("x", plan=True)
        assert result.plan is None


# =============================================================================================
# Authorization
# =============================================================================================
class TestAuthorization:
    def test_deny_all_gate_stops_a_protected_call(self, workspace):
        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "read_file", "arguments": {"path": "notes.txt"}}]},
        ], workspace=workspace, gate=DenyAllGate())
        result = agent.run("Read it.")
        assert result.outcome is RunOutcome.TOOL_DENIED and not result.ok
        assert result.error_code == "authorization_denied"
        assert agent.guard.summary()["denials"] == 1

    def test_policy_can_allow_reading_but_not_listing(self, workspace):
        def policy(*, action, resource, tool, context):
            return {"allowed": action == "fs.read", "reason": "read-only policy"}

        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}]},
            {"tool_calls": [{"id": "c2", "name": "read_file",
                             "arguments": {"path": "notes.txt"}}]},
            "read the file",
        ], workspace=workspace, gate=CallableGate(policy))
        result = agent.run("List then read.")
        outcomes = [t["error_code"] for s in result.step_records for t in s.tool_results]
        assert "authorization_denied" in outcomes
        assert result.outcome is RunOutcome.TOOL_DENIED

    def test_gate_exception_is_a_denial_not_a_crash(self, workspace):
        def broken(**kwargs):
            raise RuntimeError("policy backend down")

        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "read_file", "arguments": {"path": "notes.txt"}}]},
        ], workspace=workspace, gate=CallableGate(broken))
        result = agent.run("Read it.")
        assert result.outcome is RunOutcome.TOOL_DENIED
        assert "gate_error" in result.error or "not authorized" in (result.error or "")

    def test_denials_are_emitted_as_audit_events(self, workspace):
        store: list = []
        from agent_platform.builtin_tools import register_builtin_tools

        registry = ToolRegistry()
        register_builtin_tools(registry, workspace_root=workspace)
        guard = ToolGuard(registry, gate=DenyAllGate(),
                          on_event=lambda **kw: store.append(kw))
        guard.invoke(ToolCall(name="read_file", arguments={"path": "notes.txt"}))
        assert any(e.get("event_type") == "platform.tool.denied" for e in store)

    def test_contract_gate_adapter_uses_the_integration_authorizer(self, workspace):
        """The platform reuses the contract's authorizer instead of growing a second PDP."""

        class FakeDecision:
            allowed = True
            decision = type("D", (), {"value": "ALLOW"})()
            policy = "allow-read"
            correlation_id = "corr-1"
            reason = ""

        class FakeAuthorizer:
            def __init__(self):
                self.calls = []

            def authorize_operation(self, tool, args=None, requested_capabilities=()):
                self.calls.append((tool, args))
                return FakeDecision()

            def audit(self, *a, **k):
                return None

        authz = FakeAuthorizer()
        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "read_file", "arguments": {"path": "notes.txt"}}]},
            "read it",
        ], workspace=workspace, gate=ContractGate(authz))
        result = agent.run("Read it.")
        assert result.ok
        assert authz.calls and authz.calls[0][0] == "read_file"

    def test_contract_gate_rejects_a_bad_authorizer(self):
        with pytest.raises(Exception):
            ContractGate(object())


# =============================================================================================
# Budgets and cancellation
# =============================================================================================
class TestBudgets:
    def test_step_budget_ends_the_loop(self, workspace):
        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}]},
        ], workspace=workspace)
        result = agent.run("Loop.", budget=RunBudget(max_steps=3, max_tool_calls=99))
        assert result.outcome is RunOutcome.MAX_STEPS and result.steps == 3

    def test_tool_call_budget_refuses_the_extra_call(self, workspace):
        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}]},
        ], workspace=workspace)
        result = agent.run("Loop.", budget=RunBudget(max_steps=5, max_tool_calls=1))
        codes = [t.get("error_code") for s in result.step_records for t in s.tool_results]
        assert "budget_exceeded" in codes

    def test_token_budget_charges_model_usage(self, workspace):
        agent, _ = build([
            {"text": "a" * 40, "usage": {"prompt_tokens": 100, "completion_tokens": 100}},
        ], workspace=workspace)
        result = agent.run("Answer.", budget=RunBudget(max_tokens=50))
        # The model answered on the first call; the budget refusal surfaces on the next check.
        assert result.usage.total_tokens >= 200

    def test_wall_clock_budget(self, workspace):
        agent, _ = build(["done"], workspace=workspace)
        # A deadline already in the past: any elapsed time is past it, so this asserts the control
        # rather than the clock's resolution.
        result = agent.run("Answer.", budget=RunBudget(wall_clock_s=1e-9))
        assert result.outcome is RunOutcome.BUDGET_EXCEEDED

    def test_cancellation_before_the_first_step(self, workspace):
        token = CancellationToken()
        token.cancel("operator requested stop")
        agent, provider = build(["unused"], workspace=workspace)
        result = agent.run("Anything.", token=token)
        assert result.outcome is RunOutcome.CANCELLED
        assert not provider.calls, "a cancelled run must not call the model"

    def test_budget_snapshot_is_recorded_in_the_result(self, workspace):
        agent, _ = build(["done"], workspace=workspace)
        result = agent.run("Answer.", budget=RunBudget(max_steps=7, wall_clock_s=30))
        assert result.budget["limits"]["max_steps"] == 7
        assert result.budget["steps"] == 1


# =============================================================================================
# Failure modes
# =============================================================================================
class TestFailureModes:
    def test_no_provider_becomes_a_model_error_not_a_fake_answer(self, workspace):
        class Boom:
            name = "boom"

            def complete(self, request):
                raise RuntimeError("network down")

        from agent_platform.builtin_tools import register_builtin_tools

        registry = ToolRegistry()
        register_builtin_tools(registry, workspace_root=workspace)
        guard = ToolGuard(registry, gate=AllowAllGate())
        router = ModelRouter(PlatformConfig(enabled=True), routes=[Route(Boom(), "m")])
        agent = AgentOrchestrator(router, guard, config=PlatformConfig(enabled=True))
        result = agent.run("Answer.")
        assert result.outcome is RunOutcome.MODEL_ERROR and not result.ok
        assert result.final_text == ""

    def test_tool_exception_becomes_a_structured_tool_error(self, workspace):
        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "read_file",
                             "arguments": {"path": "missing.txt"}}]},
            "I could not read it",
        ], workspace=workspace)
        result = agent.run("Read missing.txt.")
        codes = [t.get("error_code") for s in result.step_records for t in s.tool_results]
        assert "tool_error" in codes
        assert result.ok  # the model recovered and answered

    def test_unknown_tool_is_refused(self, workspace):
        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "delete_everything", "arguments": {}}]},
            "cannot do that",
        ], workspace=workspace)
        result = agent.run("Delete everything.")
        codes = [t.get("error_code") for s in result.step_records for t in s.tool_results]
        assert "unknown_tool" in codes

    def test_an_exception_inside_the_loop_is_an_outcome_not_a_crash(self, workspace):
        class Exploding:
            name = "boom"

            def complete(self, request):
                raise ValueError("unexpected internal fault")

        from agent_platform.builtin_tools import register_builtin_tools

        registry = ToolRegistry()
        register_builtin_tools(registry, workspace_root=workspace)
        guard = ToolGuard(registry, gate=AllowAllGate())
        router = ModelRouter(PlatformConfig(enabled=True), routes=[Route(Exploding(), "m")])
        agent = AgentOrchestrator(router, guard, config=PlatformConfig(enabled=True))
        result = agent.run("Answer.")
        assert result.outcome is RunOutcome.MODEL_ERROR
        assert result.error

    def test_empty_goal_is_rejected(self, workspace):
        agent, _ = build(["x"], workspace=workspace)
        with pytest.raises(Exception):
            agent.run("   ")


# =============================================================================================
# Memory
# =============================================================================================
class TestMemoryIntegration:
    def test_a_run_is_remembered_and_recalled_next_time(self, workspace):
        memory = EpisodicMemory()
        agent, _ = build(["deployed successfully"], workspace=workspace, memory=memory)
        agent.run("Deploy the service to staging.")
        assert len(memory) == 1
        hits = memory.retrieve("deploy service staging")
        assert hits and "Deploy" in hits[0].key

    def test_recall_is_injected_into_the_next_run(self, workspace):
        memory = EpisodicMemory()
        memory.remember("deploy the service", "outcome=ok; lesson=used the blue/green path",
                        kind="run")
        agent, provider = build(["done"], workspace=workspace, memory=memory)
        agent.run("Deploy the service again.")
        systems = [m.content for m in provider.calls[0].messages if m.role == "system"]
        assert any("blue/green" in (s or "") for s in systems)

    def test_secret_in_a_goal_is_not_stored_verbatim(self, workspace):
        memory = EpisodicMemory()
        agent, _ = build(["done"], workspace=workspace, memory=memory)
        agent.run("Use api_key=sk-very-secret to deploy.")
        stored = json.dumps([r.to_dict() for r in memory.retrieve("deploy")])
        assert "sk-very-secret" not in stored


# =============================================================================================
# Sandbox bridge
# =============================================================================================
class TestSandboxBridge:
    def test_refuses_when_no_runtime_is_configured(self):
        bridge = SandboxBridge(runtime=None, require_isolation=True)
        result = bridge.run("print(1)")
        assert (not result.ok) and result.kind == "isolation_unavailable"
        assert "refusing to run untrusted code" in result.error

    def test_refuses_when_no_isolation_backend_is_observed(self):
        bridge = SandboxBridge(runtime=object(), require_isolation=True,
                               isolation_probe=lambda: {"os_isolated": False})
        result = bridge.run("print(1)")
        assert (not result.ok) and result.kind == "isolation_unavailable"

    def test_oversized_artifact_is_refused_before_the_runtime(self):
        bridge = SandboxBridge(runtime=object(), require_isolation=False,
                               max_artifact_bytes=10)
        result = bridge.run("x" * 100)
        assert result.error_code == "artifact_too_large"

    def test_ensure_available_raises_without_a_runtime(self):
        from agent_platform.errors import SandboxUnavailable

        with pytest.raises(SandboxUnavailable):
            SandboxBridge(runtime=None).ensure_available()

    def test_normalises_a_contract_style_result(self):
        class FakeReport:
            def to_dict(self):
                return {"os_isolated": True, "selected": "namespaces"}

        class FakeResult:
            def to_dict(self):
                return {"ok": True, "result": "ok", "output": "hello\n", "duration_ms": 12.0,
                        "metadata": {"evidence": {"cleanup_ok": True,
                                                  "jail": {"backend": "namespaces"}}}}

        class FakeRuntime:
            def isolation_report(self, refresh=False):
                return FakeReport()

            def execute(self, request, source, credential=None, token=None):
                return FakeResult()

        bridge = SandboxBridge(runtime=FakeRuntime())
        result = bridge.run("print('hello')")
        assert result.ok and result.output.strip() == "hello"
        assert result.isolates and result.backend == "namespaces"

    def test_sandbox_requiring_tool_is_refused_without_isolation(self, workspace):
        """A sandbox tool cannot become a host-execution path: the bridge refuses first."""
        bridge = SandboxBridge(runtime=None, require_isolation=True)
        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "run_happy_program",
                             "arguments": {"source": "print(1)"}}]},
        ], workspace=workspace, gate=AllowAllGate(), sandbox=bridge)
        result = agent.run("Run a program.")
        codes = [t.get("error_code") for s in result.step_records for t in s.tool_results]
        assert "sandbox_unavailable" in codes or "isolation_unavailable" in codes


# =============================================================================================
# Evaluation
# =============================================================================================
class TestEvaluation:
    def test_evaluation_reports_pass_and_fail(self, workspace):
        agent, _ = build(["the answer is ready"], workspace=workspace)
        tasks = [
            EvalTask(task_id="good", goal="Reply ready.", must_contain=["ready"]),
            EvalTask(task_id="bad", goal="Reply differently.", must_contain=["absent-token"]),
        ]
        report = run_suite(agent, tasks, suite_name="unit")
        assert report.total == 2 and report.passed == 1 and report.failed == 1
        assert report.pass_rate == 0.5

    def test_evaluation_records_tool_usage(self, workspace):
        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}]},
            "done",
        ], workspace=workspace)
        tasks = [EvalTask(task_id="uses-tool", goal="List it.", must_call=["list_dir"])]
        report = run_suite(agent, tasks)
        assert report.passed == 1

    def test_a_raising_run_is_a_failed_task_not_a_crash(self, workspace):
        class Exploding:
            name = "boom"

            def complete(self, request):
                raise RuntimeError("down")

        from agent_platform.builtin_tools import register_builtin_tools

        registry = ToolRegistry()
        register_builtin_tools(registry, workspace_root=workspace)
        agent = AgentOrchestrator(
            ModelRouter(PlatformConfig(enabled=True), routes=[Route(Exploding(), "m")]),
            ToolGuard(registry, gate=AllowAllGate()), config=PlatformConfig(enabled=True))
        report = run_suite(agent, [EvalTask(task_id="boom", goal="x")])
        assert report.failed == 1

    def test_report_renders(self, workspace):
        agent, _ = build(["ok"], workspace=workspace)
        report = run_suite(agent, [EvalTask(task_id="t", goal="Say ok.", must_contain=["ok"])],
                           suite_name="render")
        text = report.render()
        assert "suite=render" in text and "PASS t" in text


# =============================================================================================
# Tracing
# =============================================================================================
class TestTracing:
    def test_a_run_produces_nested_spans(self, workspace):
        tracer = Tracer()
        agent, _ = build([
            {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}]},
            "done",
        ], workspace=workspace, tracer=tracer)
        agent.run("List it.")
        names = [s.name for s in tracer.spans()]
        assert "run" in names and "model.call" in names and "tool.invoke" in names

    def test_span_attributes_are_redacted(self, workspace):
        tracer = Tracer()
        agent, _ = build(["done"], workspace=workspace, tracer=tracer)
        agent.run("Use api_key=sk-abc to do it.")
        exported = json.dumps(tracer.export())
        assert "sk-abc" not in exported

    def test_run_events_are_emitted(self, workspace):
        store: list = []
        from agent_platform.builtin_tools import register_builtin_tools

        config = PlatformConfig(enabled=True)
        events = EventBus([recording_sink(store)], capacity=10)
        registry = ToolRegistry()
        register_builtin_tools(registry, workspace_root=workspace)
        agent = AgentOrchestrator(
            ModelRouter(config, routes=[Route(DeterministicProvider(["done"]), "m")]),
            ToolGuard(registry, gate=AllowAllGate()), config=config, events=events)
        agent.run("Say done.")
        types = [e["event_type"] for e in store]
        assert "platform.run.started" in types and "platform.run.finished" in types


# =============================================================================================
# Configuration
# =============================================================================================
class TestConfigIntegration:
    def test_building_an_agent_when_disabled_is_refused(self, workspace):
        from agent_platform.cli import build_agent

        with pytest.raises(ConfigError):
            build_agent(PlatformConfig(enabled=False), gate=AllowAllGate())

    def test_allowlist_limits_what_the_model_can_see_and_do(self, workspace):
        config = PlatformConfig(enabled=True, tool_allowlist=("list_dir",))
        agent, provider = build([
            {"tool_calls": [{"id": "c1", "name": "read_file",
                             "arguments": {"path": "notes.txt"}}]},
            "cannot read",
        ], workspace=workspace, config=config)
        result = agent.run("Read it.")
        codes = [t.get("error_code") for s in result.step_records for t in s.tool_results]
        assert "not_allowed" in codes
        named = {t["name"] for t in agent.tool_schemas()}
        assert named == {"list_dir"}
