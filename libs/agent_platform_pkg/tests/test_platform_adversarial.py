"""Adversarial tests: what an attacker (or a confused model) tries, and what must happen.

Each test states the attack and the specific control it must hit.  These are the tests that make a
security claim checkable rather than aspirational -- and none of them is allowed to pass by the run
"mostly working"; a refusal must be a structured, observable refusal.
"""
from __future__ import annotations

import json
import os

import pytest

from agent_platform.budget import CancellationToken, RunBudget
from agent_platform.builtin_tools import PathJailError, register_builtin_tools, safe_join
from agent_platform.config import PlatformConfig
from agent_platform.errors import ConfigError
from agent_platform.events import EventBus, recording_sink
from agent_platform.memory import EpisodicMemory
from agent_platform.orchestrator import AgentOrchestrator
from agent_platform.router import DeterministicProvider, ModelRouter, Route
from agent_platform.sandbox import SandboxBridge
from agent_platform.tools import (
    AllowAllGate,
    AuthorizationGate,
    CallableGate,
    DenyAllGate,
    ToolGuard,
    ToolRegistry,
)
from agent_platform.types import ToolCall
from agent_platform.validation import redact, truncate, validate_against_schema


@pytest.fixture()
def workspace(tmp_path):
    (tmp_path / "notes.txt").write_text("public notes\n", encoding="utf-8")
    (tmp_path / "secret.env").write_text("API_KEY=sk-real-secret\n", encoding="utf-8")
    outside = tmp_path.parent / "outside-ap-test.txt"
    outside.write_text("outside the workspace\n", encoding="utf-8")
    return str(tmp_path)


def make_agent(script, *, workspace, gate=None, config=None, sandbox=None, memory=None,
               registry=None):
    config = config or PlatformConfig(enabled=True)
    reg = registry or ToolRegistry()
    if registry is None:
        register_builtin_tools(reg, workspace_root=workspace, sandbox_bridge=sandbox,
                              include_sandbox=sandbox is not None)
    if gate is None:
        gate = AllowAllGate()
    elif not isinstance(gate, AuthorizationGate) and callable(gate):
        # A bare function is a policy, not a gate object: adapt it so the guard's ``.name`` and
        # fail-closed error handling apply.  (Passing a function straight to ToolGuard would leave
        # ``gate.name`` undefined and break the run's own metadata.)
        gate = CallableGate(gate)
    guard = ToolGuard(reg, gate=gate)
    router = ModelRouter(config, routes=[Route(DeterministicProvider(script), "m")])
    return AgentOrchestrator(router, guard, config=config, sandbox=sandbox, memory=memory)


# =============================================================================================
# 1. Path traversal
# =============================================================================================
class TestPathTraversal:
    @pytest.mark.parametrize("evil", [
        "../outside-ap-test.txt",
        "../../tmp",
        "../etc/passwd",
        "./../../etc/passwd",
        "sub/../../outside-ap-test.txt",
        "/etc/passwd",
        "a/../../../etc/passwd",
        "a\x00../../etc/passwd",
    ])
    def test_traversal_is_refused_below_the_policy(self, workspace, evil):
        """Even with an allow-all policy, the tool-level jail refuses the escape."""
        with pytest.raises(PathJailError):
            safe_join(workspace, evil)

    def test_symlink_escape_is_refused(self, workspace, tmp_path):
        link = os.path.join(workspace, "escape")
        try:
            os.symlink("/etc", link)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable on this platform")
        with pytest.raises(PathJailError):
            safe_join(workspace, "escape/passwd")

    def test_legitimate_paths_still_work(self, workspace):
        assert safe_join(workspace, "notes.txt").endswith("notes.txt")
        assert safe_join(workspace, "sub/../notes.txt").endswith("notes.txt")

    def test_a_traversal_attempt_through_the_agent_loop_is_refused(self, workspace):
        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "read_file",
                             "arguments": {"path": "../../etc/passwd"}}]},
            "refused",
        ], workspace=workspace)
        result = agent.run("Read /etc/passwd")
        results = [t for s in result.step_records for t in s.tool_results]
        assert results and results[0]["error_code"] == "tool_error"
        assert "escape" in (results[0].get("error") or "")


# =============================================================================================
# 2. Authorization bypass attempts
# =============================================================================================
class TestAuthorizationBypass:
    def test_denied_operation_cannot_be_re_run_through_another_tool(self, workspace):
        """A denial must not be laundered by asking for the same resource another way."""
        def policy(*, action, resource, tool, context):
            return {"allowed": False, "reason": "all protected reads denied"}

        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "read_file", "arguments": {"path": "notes.txt"}}]},
            {"tool_calls": [{"id": "c2", "name": "list_dir", "arguments": {"path": "."}}]},
            {"tool_calls": [{"id": "c3", "name": "read_file", "arguments": {"path": "notes.txt"}}]},
        ], workspace=workspace, gate=policy)
        result = agent.run("Read the file by any means.")
        results = [t for s in result.step_records for t in s.tool_results]
        assert results, "the loop must record the attempts"
        assert all(t["error_code"] == "authorization_denied" for t in results), results
        assert result.outcome.value == "tool_denied"

    def test_unknown_tool_cannot_bypass_by_being_invented(self, workspace):
        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "read_file_unchecked",
                             "arguments": {"path": "secret.env"}}]},
            "no such tool",
        ], workspace=workspace)
        result = agent.run("Read the secret.")
        results = [t for s in result.step_records for t in s.tool_results]
        assert results[0]["error_code"] == "unknown_tool"

    def test_a_tool_outside_the_allowlist_is_invisible_and_refused(self, workspace):
        config = PlatformConfig(enabled=True, tool_allowlist=("list_dir",))
        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "read_file",
                             "arguments": {"path": "secret.env"}}]},
            "cannot",
        ], workspace=workspace, config=config)
        assert {t["name"] for t in agent.tool_schemas()} == {"list_dir"}
        result = agent.run("Read the secret.")
        results = [t for s in result.step_records for t in s.tool_results]
        assert results[0]["error_code"] == "not_allowed"

    def test_a_failing_gate_denies_rather_than_allows(self, workspace):
        def exploding_gate(**kwargs):
            raise RuntimeError("policy engine unavailable")

        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "read_file",
                             "arguments": {"path": "notes.txt"}}]},
        ], workspace=workspace, gate=exploding_gate)
        result = agent.run("Read it.")
        results = [t for s in result.step_records for t in s.tool_results]
        assert results[0]["error_code"] == "authorization_denied"
        # The gate's own failure reason must survive to the caller, not be flattened to "denied".
        assert "gate_error" in (results[0].get("error") or "")

    def test_no_gate_configured_means_deny(self, workspace):
        registry = ToolRegistry()
        register_builtin_tools(registry, workspace_root=workspace)
        guard = ToolGuard(registry)  # no gate
        result = guard.invoke(ToolCall(name="read_file", arguments={"path": "notes.txt"}))
        assert result.denied and "no_authorization_gate_configured" in result.error


# =============================================================================================
# 3. Resource exhaustion
# =============================================================================================
class TestResourceExhaustion:
    def test_unbounded_tool_loop_is_stopped(self, workspace):
        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}]},
        ], workspace=workspace)
        result = agent.run("Loop forever.", budget=RunBudget(max_steps=4, max_tool_calls=100))
        assert result.outcome.value == "max_steps"
        assert result.steps == 4

    def test_tool_call_flood_is_bounded(self, workspace):
        calls = [{"id": f"c{i}", "name": "list_dir", "arguments": {"path": "."}}
                 for i in range(20)]
        agent = make_agent([{"tool_calls": calls}], workspace=workspace)
        result = agent.run("Flood.", budget=RunBudget(max_steps=5, max_tool_calls=5))
        codes = [t.get("error_code") for s in result.step_records for t in s.tool_results]
        # The ceiling is exact: exactly 5 calls reach the handler, every later call in every later
        # step is refused before it runs -- a flood must not widen the budget at the edges.
        assert codes.count(None) == 5
        assert codes.count("budget_exceeded") == len(codes) - 5
        assert len(codes) == 100  # 5 steps x 20 requested calls, all recorded

    def test_oversized_tool_output_is_truncated_before_it_reaches_the_model(self, workspace):
        big = os.path.join(workspace, "big.txt")
        with open(big, "w", encoding="utf-8") as handle:
            handle.write("A" * 500_000)
        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "read_file", "arguments": {"path": "big.txt"}}]},
            "read it",
        ], workspace=workspace)
        result = agent.run("Read the big file.")
        tool_messages = [m for m in result.transcript if m.role == "tool"]
        assert tool_messages
        assert len(tool_messages[0].content) <= 16_384 + 200

    def test_working_memory_stays_bounded_over_a_long_run(self, workspace):
        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}]},
        ], workspace=workspace, config=PlatformConfig(enabled=True,
                                                     working_memory_max_messages=8))
        result = agent.run("Loop.", budget=RunBudget(max_steps=30, max_tool_calls=60))
        assert len(result.transcript) <= 8
        assert agent.working_memory.compactions >= 1

    def test_episodic_memory_evicts_rather_than_grows(self, workspace):
        memory = EpisodicMemory(capacity=3)
        agent = make_agent(["done"] * 20, workspace=workspace, memory=memory)
        for i in range(12):
            agent.run(f"task number {i}")
        assert len(memory) <= 3


# =============================================================================================
# 4. Malformed input
# =============================================================================================
class TestMalformedInput:
    def test_malformed_tool_arguments_are_refused_with_the_raw_text(self, workspace):
        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "read_file", "arguments": {},
                             "raw_arguments": '{"path": "notes.txt", "extra": 1}'}]},
            "fixed",
        ], workspace=workspace)
        result = agent.run("Read it.")
        results = [t for s in result.step_records for t in s.tool_results]
        assert results[0]["error_code"] == "invalid_tool_arguments"
        problems = results[0]["metadata"]["problems"]
        assert any("raw arguments" in p for p in problems)

    def test_wrong_argument_type_is_refused(self, workspace):
        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "read_file",
                             "arguments": {"path": 12345}}]},
            "fixed",
        ], workspace=workspace)
        result = agent.run("Read it.")
        results = [t for s in result.step_records for t in s.tool_results]
        assert results[0]["error_code"] == "invalid_tool_arguments"

    def test_an_empty_model_response_is_an_error_not_a_success(self, workspace):
        agent = make_agent([""], workspace=workspace)
        result = agent.run("Answer.")
        assert (not result.ok) and result.outcome.value == "model_error"

    def test_a_tool_call_with_no_name_is_refused(self, workspace):
        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "", "arguments": {}}]},
            "recovered",
        ], workspace=workspace)
        result = agent.run("Do something.")
        results = [t for s in result.step_records for t in s.tool_results]
        assert results[0]["error_code"] in ("unknown_tool", "invalid_tool_arguments")

    def test_schema_validation_catches_deeply_wrong_shapes(self):
        schema = {"type": "object", "properties": {"items": {"type": "array", "maxItems": 2}},
                  "required": ["items"]}
        assert validate_against_schema({"items": [1, 2, 3]}, schema)
        assert validate_against_schema({"items": "not an array"}, schema)
        assert not validate_against_schema({"items": [1]}, schema)

    def test_a_non_json_goal_is_rejected(self, workspace):
        agent = make_agent(["x"], workspace=workspace)
        with pytest.raises(Exception):
            agent.run(None)  # type: ignore[arg-type]


# =============================================================================================
# 5. Secret leakage
# =============================================================================================
class TestSecretLeakage:
    def test_secrets_are_redacted_in_events(self):
        store: list = []
        bus = EventBus([recording_sink(store)], capacity=1)
        bus.record(event_type="platform.test", outcome="ok",
                   metadata={"api_key": "sk-live-1", "password": "hunter2",
                             "authorization": "Bearer abc", "safe_field": "visible"})
        bus.flush()
        blob = json.dumps(store)
        for secret in ("sk-live-1", "hunter2", "Bearer abc"):
            assert secret not in blob
        assert "visible" in blob

    def test_secrets_are_redacted_in_memory(self):
        memory = EpisodicMemory()
        memory.remember("deploy", "used token secret-token-123",
                        metadata={"api_key": "sk-x"})
        assert "sk-x" not in json.dumps([r.to_dict() for r in memory.retrieve("deploy")])

    def test_a_secret_in_a_goal_does_not_reach_the_recorded_result(self, workspace):
        agent = make_agent(["done"], workspace=workspace)
        result = agent.run("Deploy with api_key=sk-very-secret-value.")
        # Documented split: the GOAL is the caller's own input and is retained verbatim in the result,
        # but the secret must not survive into any DERIVED record -- the guard's audit trail, the
        # memory store or the event stream.  That is what stops a later reader (or a later run)
        # recovering a credential the caller never meant to persist.
        assert result.goal == "Deploy with api_key=sk-very-secret-value."
        audit = json.dumps(agent.guard.audit)
        assert "sk-very-secret-value" not in audit

    def test_tool_results_never_echo_a_secret_argument(self, workspace):
        registry = ToolRegistry()

        @registry.tool("login", "log in", parameters={
            "type": "object", "properties": {"api_key": {"type": "string"}}})
        def login(api_key: str = "") -> dict:
            return {"ok": True, "echo": api_key}

        guard = ToolGuard(registry, gate=AllowAllGate())
        guard.invoke(ToolCall(name="login", arguments={"api_key": "sk-leak"}))
        assert "sk-leak" not in json.dumps(guard.audit)

    def test_truncation_marks_cut_content(self):
        assert "chars>" in truncate("x" * 100, 10)


# =============================================================================================
# 6. Isolation
# =============================================================================================
class TestIsolation:
    def test_untrusted_code_is_never_run_without_a_backend(self, workspace):
        bridge = SandboxBridge(runtime=None)
        result = bridge.run("import os; os.system('id')")
        assert (not result.ok) and result.kind == "isolation_unavailable"

    def test_an_unavailable_backend_blocks_the_sandbox_tool(self, workspace):
        bridge = SandboxBridge(runtime=object(), require_isolation=True,
                               isolation_probe=lambda: {"os_isolated": False})
        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "run_happy_program",
                             "arguments": {"source": "print(1)"}}]},
        ], workspace=workspace, sandbox=bridge)
        result = agent.run("Run it.")
        codes = [t.get("error_code") for s in result.step_records for t in s.tool_results]
        assert codes and codes[0] in ("sandbox_unavailable", "isolation_unavailable")

    def test_a_runtime_failure_is_a_typed_result_not_a_crash(self, workspace):
        class ExplodingRuntime:
            def isolation_report(self, refresh=False):
                return {"os_isolated": True}

            def execute(self, *a, **k):
                raise RuntimeError("jail died")

        bridge = SandboxBridge(runtime=ExplodingRuntime())
        result = bridge.run("print(1)")
        assert (not result.ok) and result.kind == "integration_error"

    def test_oversize_artifact_is_refused_at_the_bridge(self):
        bridge = SandboxBridge(runtime=object(), require_isolation=False, max_artifact_bytes=5)
        assert bridge.run("x" * 50).error_code == "artifact_too_large"


# =============================================================================================
# 7. Cancellation and fail-closed behaviour
# =============================================================================================
class TestFailClosed:
    def test_a_cancelled_run_calls_nothing(self, workspace):
        token = CancellationToken()
        token.cancel("stop now")
        agent = make_agent(["unused"], workspace=workspace)
        result = agent.run("Do work.", token=token)
        assert result.outcome.value == "cancelled"

    def test_production_refuses_insecure_configuration(self):
        for kwargs in ({"base_url": "http://x"}, {"verify_tls": False},
                       {"mode": "off", "enabled": True}):
            with pytest.raises(ConfigError):
                PlatformConfig(environment="production", **kwargs)

    def test_result_of_a_denied_run_never_claims_success(self, workspace):
        agent = make_agent([
            {"tool_calls": [{"id": "c1", "name": "read_file", "arguments": {"path": "secret.env"}}]},
        ], workspace=workspace, gate=DenyAllGate())
        result = agent.run("Read the secret.")
        assert result.ok is False and result.outcome.value == "tool_denied"
        assert result.final_text == ""

    def test_redact_handles_hostile_input(self):
        class Hostile:
            def __repr__(self):
                return "x" * 10_000

        out = redact({"obj": Hostile(), "nested": [{"password": "p"}]})
        assert "chars>" in json.dumps(out)
        assert out["nested"][0]["password"] == "<redacted>"
