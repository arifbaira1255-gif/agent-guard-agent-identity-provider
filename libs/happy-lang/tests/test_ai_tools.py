"""Tests for the Step 10 AI tool-calling loop, sandbox integration and runtime.

Everything here is fully offline: the model is a deterministic
:class:`MockProvider`, so the suite never needs a network or an API key.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from happy.ai.providers import (  # noqa: E402
    AIProviderError,
    AIRequest,
    AIResponse,
    Message,
    MockProvider,
    ProviderUnavailable,
    Role,
    ToolCall,
    get_provider,
    provider_from_env,
    register_provider,
    resolve_provider,
)
from happy.ai.runtime import AIRunner  # noqa: E402
from happy.ai.tools import ToolRegistry, run_tool_loop  # noqa: E402


class _ScriptedProvider(MockProvider):
    """A mock provider that plays a fixed script of responses."""

    def __init__(self, responses):
        super().__init__()
        self._script = list(responses)
        self.calls = 0

    def complete(self, request):
        self.calls += 1
        if self._script:
            return self._script.pop(0)
        return AIResponse(text="done", model="scripted", provider="scripted")


def _resp(text="", tool_calls=None):
    return AIResponse(
        text=text, tool_calls=tool_calls or [], model="scripted",
        provider="scripted",
    )


class ProviderTests(unittest.TestCase):
    def test_mock_provider_is_deterministic(self):
        p = MockProvider()
        a = p.complete(AIRequest.from_prompt("hello"))
        b = p.complete(AIRequest.from_prompt("hello"))
        self.assertEqual(a.text, b.text)
        self.assertIn("hello", a.text)

    def test_mock_provider_capability_flags(self):
        p = MockProvider()
        self.assertTrue(p.supports_tools)
        self.assertTrue(p.supports_json)
        self.assertTrue(p.is_local)
        self.assertTrue(p.is_available())

    def test_registry_get_and_register(self):
        from happy.ai.providers import MockProvider as MP

        register_provider("my-mock", MP)
        self.assertEqual(get_provider("my-mock").name, "mock")

    def test_resolve_unknown_provider(self):
        with self.assertRaises(ProviderUnavailable):
            resolve_provider("definitely-not-a-provider")

    def test_provider_from_env_without_keys(self):
        saved = {
            k: os.environ.pop(k, None)
            for k in (
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "GEMINI_API_KEY",
                "GOOGLE_API_KEY",
                "HAPPY_LOCAL_LLM_URL",
            )
        }
        try:
            # With every key absent the resolver falls back to the offline
            # mock provider rather than raising.
            provider = provider_from_env()
            self.assertIn(provider.name, {"mock", "local"})
            self.assertTrue(provider.is_available())
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v


class ToolRegistryTests(unittest.TestCase):
    def test_register_and_invoke(self):
        reg = ToolRegistry()
        reg.register("add", lambda a, b: a + b, "add two numbers")
        result = reg.invoke(ToolCall(name="add", arguments={"a": 2, "b": 3}))
        self.assertTrue(result.ok)
        self.assertEqual(result.value, 5)

    def test_unknown_tool_fails(self):
        reg = ToolRegistry()
        result = reg.invoke(ToolCall(name="nope", arguments={}))
        self.assertFalse(result.ok)
        self.assertIn("unknown tool", result.error)

    def test_tool_exception_is_captured(self):
        def boom():
            raise ValueError("kaboom")

        reg = ToolRegistry()
        reg.register("boom", boom)
        result = reg.invoke(ToolCall(name="boom", arguments={}))
        self.assertFalse(result.ok)
        self.assertIn("kaboom", result.error)

    def test_schemas_sorted_and_stable(self):
        reg = ToolRegistry()
        reg.register("z", lambda: 1)
        reg.register("a", lambda: 2)
        self.assertEqual([s["name"] for s in reg.schemas()], ["a", "z"])

    def test_sandbox_denies_capability(self):
        class Sandbox:
            granted_capabilities = {"file_read"}

        reg = ToolRegistry(sandbox=Sandbox())
        reg.register(
            "write", lambda: "wrote", required_capability="file_write"
        )
        result = reg.invoke(ToolCall(name="write", arguments={}))
        self.assertFalse(result.ok)
        self.assertIn("sandbox denied", result.error)

    def test_sandbox_allows_capability(self):
        class Sandbox:
            granted_capabilities = {"file_write"}

        reg = ToolRegistry(sandbox=Sandbox())
        reg.register("write", lambda: "wrote", required_capability="file_write")
        result = reg.invoke(ToolCall(name="write", arguments={}))
        self.assertTrue(result.ok)
        self.assertEqual(result.value, "wrote")

    def test_history_is_recorded(self):
        reg = ToolRegistry()
        reg.register("noop", lambda: None)
        reg.invoke(ToolCall(name="noop", arguments={}))
        reg.invoke(ToolCall(name="missing", arguments={}))
        self.assertEqual(len(reg.history), 2)


class RunToolLoopTests(unittest.TestCase):
    def test_single_round_without_tools(self):
        provider = _ScriptedProvider([_resp("final answer")])
        reg = ToolRegistry()
        loop = run_tool_loop(provider, AIRequest.from_prompt("hi"), reg)
        self.assertEqual(loop.response.text, "final answer")
        self.assertEqual(loop.iterations, 1)
        self.assertEqual(loop.stopped_reason, "completed")

    def test_tool_call_then_answer(self):
        provider = _ScriptedProvider(
            [
                _resp("", [ToolCall(name="add", arguments={"a": 1, "b": 2}, call_id="c1")]),
                _resp("the answer is 3"),
            ]
        )
        reg = ToolRegistry()
        reg.register("add", lambda a, b: a + b)
        loop = run_tool_loop(provider, AIRequest.from_prompt("add"), reg)
        self.assertEqual(loop.response.text, "the answer is 3")
        self.assertEqual(loop.iterations, 2)
        self.assertEqual(loop.results[0].value, 3)
        # The tool result was fed back as a `tool` message.
        self.assertTrue(
            any(m.role == Role.TOOL for m in loop.messages)
        )

    def test_loop_is_bounded(self):
        def always_tool():
            return None

        provider = _ScriptedProvider(
            [
                _resp("", [ToolCall(name="t", arguments={}, call_id=f"c{i}")])
                for i in range(20)
            ]
        )
        reg = ToolRegistry()
        reg.register("t", always_tool)
        loop = run_tool_loop(provider, AIRequest.from_prompt("spin"), reg,
                             max_iterations=3)
        self.assertEqual(loop.iterations, 3)
        self.assertEqual(loop.stopped_reason, "max_iterations")

    def test_failed_tool_still_returns_to_model(self):
        provider = _ScriptedProvider(
            [
                _resp("", [ToolCall(name="broken", arguments={}, call_id="c1")]),
                _resp("recovered"),
            ]
        )
        reg = ToolRegistry()
        reg.register("broken", lambda: (_ for _ in ()).throw(RuntimeError("nope")))
        loop = run_tool_loop(provider, AIRequest.from_prompt("x"), reg)
        self.assertFalse(loop.results[0].ok)
        self.assertEqual(loop.response.text, "recovered")


class AIRunnerTests(unittest.TestCase):
    def test_offline_when_no_provider(self):
        runner = AIRunner(provider=None)
        result = runner.call("summarise this")
        self.assertFalse(result.live)
        self.assertEqual(result.provider, "offline")
        self.assertIn("summarise this", result.text)

    def test_live_with_scripted_provider(self):
        runner = AIRunner(provider=_ScriptedProvider([_resp("live!")]))
        result = runner.call("hi")
        self.assertTrue(result.live)
        self.assertEqual(result.text, "live!")

    def test_provider_error_falls_back_deterministically(self):
        class Failing(MockProvider):
            def complete(self, request):
                raise AIProviderError("boom")

        runner = AIRunner(provider=Failing())
        result = runner.call("q")
        self.assertFalse(result.live)
        self.assertIn("boom", result.error)
        self.assertIn("q", result.text)

    def test_history_is_kept(self):
        runner = AIRunner(provider=_ScriptedProvider([_resp("1"), _resp("2")]))
        runner.call("a")
        runner.call("b")
        self.assertEqual(len(runner.history), 2)

    def test_complete_returns_text(self):
        runner = AIRunner(provider=_ScriptedProvider([_resp("hello")]))
        self.assertEqual(runner.complete("x"), "hello")

    def test_with_tools_routes_through_loop(self):
        reg = ToolRegistry()
        reg.register("add", lambda a, b: a + b)
        provider = _ScriptedProvider(
            [
                _resp("", [ToolCall(name="add", arguments={"a": 4, "b": 5}, call_id="c")]),
                _resp("9"),
            ]
        )
        runner = AIRunner(provider=provider)
        runner.with_tools(reg)
        result = runner.call("add 4 and 5")
        self.assertEqual(result.text, "9")
        self.assertEqual(reg.history[0].value, 9)


class ContextAITests(unittest.TestCase):
    def test_context_ai_offline_by_default(self):
        # Even when API keys exist in the environment, the runtime must not
        # auto-connect: live AI is opt-in via ai_provider / ai_offline=False.
        from happy.runtime import RuntimeContext

        ctx = RuntimeContext(filename="t.hpy")
        out = ctx.ai_complete("hello world")
        self.assertIn("hello world", out)
        self.assertFalse(ctx.ai.live)

    def test_context_ai_with_injected_provider(self):
        from happy.runtime import RuntimeContext

        ctx = RuntimeContext(
            filename="t.hpy",
            ai_provider=_ScriptedProvider([_resp("injected")]),
        )
        self.assertEqual(ctx.ai_complete("q"), "injected")


if __name__ == "__main__":
    unittest.main()
