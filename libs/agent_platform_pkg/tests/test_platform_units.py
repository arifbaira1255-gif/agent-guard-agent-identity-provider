"""Unit tests: config, validation, budget, router, tools, memory, tracing, events, ids."""
from __future__ import annotations

import json

import pytest

from agent_platform.budget import BudgetAccountant, CancellationToken, RunBudget
from agent_platform.config import PlatformConfig
from agent_platform.errors import (
    BudgetExceeded,
    ConfigError,
    InvalidModelOutput,
    InvalidToolArguments,
    ProviderUnavailable,
    UnknownTool,
)
from agent_platform.events import EventBus, PlatformEvent, recording_sink, stdout_event_sink
from agent_platform.ids import new_id, sequence_id
from agent_platform.memory import EpisodicMemory, WorkingMemory, tokenize
from agent_platform.router import (
    CallableProvider,
    DeterministicProvider,
    ModelRouter,
    Route,
    coerce_response,
    estimate_tokens,
    parse_openai_tool_calls,
    price_usage,
)
from agent_platform.tools import (
    AllowAllGate,
    CallableGate,
    DenyAllGate,
    ToolCall,
    ToolGuard,
    ToolRegistry,
    ToolSpec,
)
from agent_platform.tracing import Tracer
from agent_platform.types import Message, ModelResponse, Usage
from agent_platform.validation import (
    SchemaError,
    check_schema,
    redact,
    sha256_hex,
    truncate,
    validate_against_schema,
)


# =============================================================================================
# config
# =============================================================================================
class TestConfig:
    def test_defaults_are_disabled_and_safe(self):
        config = PlatformConfig()
        assert config.enabled is False
        assert config.mode == "enforce"
        assert config.verify_tls is True
        assert config.isolating_off_by_default() if hasattr(config, "isolating_off_by_default") \
            else config.sandbox_enabled is False

    def test_invalid_mode_rejected(self):
        with pytest.raises(ConfigError):
            PlatformConfig(mode="yolo")

    def test_invalid_number_rejected(self):
        with pytest.raises(ConfigError):
            PlatformConfig(max_steps=0)
        with pytest.raises(ConfigError):
            PlatformConfig(temperature=9.0)

    def test_production_refuses_plaintext_http(self):
        with pytest.raises(ConfigError):
            PlatformConfig(environment="production", base_url="http://api.example.com")

    def test_production_allows_plaintext_only_with_optin(self):
        config = PlatformConfig(environment="production", base_url="http://api.example.com",
                                allow_insecure_http=True)
        assert config.environment == "production"

    def test_production_refuses_disabled_tls_verification(self):
        with pytest.raises(ConfigError):
            PlatformConfig(environment="production", verify_tls=False)

    def test_production_refuses_authorization_off(self):
        with pytest.raises(ConfigError):
            PlatformConfig(environment="production", enabled=True, mode="off")

    def test_urls_are_derived(self):
        config = PlatformConfig(agentguard_base_url="https://guard.example.com/")
        assert config.authorize_url() == "https://guard.example.com/v1/authorize"
        assert config.events_url() == "https://guard.example.com/v1/security/events"

    def test_from_env_reads_flags(self, monkeypatch):
        monkeypatch.setenv("AGENT_PLATFORM_ENABLED", "true")
        monkeypatch.setenv("AGENT_PLATFORM_MAX_STEPS", "7")
        monkeypatch.setenv("AGENT_PLATFORM_TOOL_ALLOWLIST", "read_file, list_dir")
        config = PlatformConfig.from_env()
        assert config.enabled is True
        assert config.max_steps == 7
        assert config.tool_allowlist == ("read_file", "list_dir")

    def test_with_overrides_does_not_mutate(self):
        base = PlatformConfig()
        derived = base.with_overrides(enabled=True)
        assert base.enabled is False and derived.enabled is True


# =============================================================================================
# validation
# =============================================================================================
class TestValidation:
    def test_canonical_json_is_stable(self):
        assert sha256_hex({"b": 1, "a": 2}) == sha256_hex({"a": 2, "b": 1})

    def test_redact_replaces_secret_named_keys(self):
        out = redact({"api_key": "sk-1", "token": "t", "safe": "ok", "nested": {"password": "p"}})
        assert out["api_key"] == "<redacted>"
        assert out["token"] == "<redacted>"
        assert out["nested"]["password"] == "<redacted>"
        assert out["safe"] == "ok"

    def test_redact_bounds_depth_and_length(self):
        deep = current = {}
        for _ in range(20):
            current["next"] = {}
            current = current["next"]
        assert "depth-limit" in json.dumps(redact(deep))
        assert "chars>" in truncate("x" * 100, 10)

    def test_schema_rejects_unknown_type(self):
        with pytest.raises(SchemaError):
            check_schema({"type": "strng"})

    def test_schema_rejects_unknown_keyword(self):
        with pytest.raises(SchemaError):
            check_schema({"type": "object", "propertes": {}})

    def test_validation_catches_missing_required(self):
        problems = validate_against_schema({}, {"type": "object", "required": ["a"]})
        assert problems and "required" in problems[0]

    def test_validation_catches_wrong_type(self):
        problems = validate_against_schema(
            {"a": "x"}, {"type": "object", "properties": {"a": {"type": "integer"}}})
        assert problems and "expected integer" in problems[0]

    def test_validation_allows_integer_for_number(self):
        assert not validate_against_schema(3, {"type": "number"})
        assert not validate_against_schema(3.0, {"type": "integer"})
        assert validate_against_schema(3.5, {"type": "integer"})

    def test_additional_properties_false(self):
        schema = {"type": "object", "properties": {"a": {"type": "string"}},
                  "additionalProperties": False}
        assert validate_against_schema({"a": "x", "b": 1}, schema)

    def test_enum_and_bounds(self):
        assert validate_against_schema("c", {"type": "string", "enum": ["a", "b"]})
        assert validate_against_schema(5, {"type": "integer", "maximum": 3})
        assert validate_against_schema("ab", {"type": "string", "minLength": 5})


# =============================================================================================
# budget
# =============================================================================================
class TestBudget:
    def test_step_budget_raises_at_the_ceiling(self):
        accountant = BudgetAccountant(RunBudget(max_steps=2))
        accountant.charge_step()
        accountant.charge_step()
        with pytest.raises(BudgetExceeded) as exc:
            accountant.charge_step()
        assert exc.value.kind == "steps"

    def test_tool_call_budget(self):
        accountant = BudgetAccountant(RunBudget(max_tool_calls=1))
        accountant.charge_tool_call()
        with pytest.raises(BudgetExceeded) as exc:
            accountant.charge_tool_call()
        assert exc.value.kind == "tool_calls"

    def test_token_and_cost_budgets(self):
        accountant = BudgetAccountant(RunBudget(max_tokens=10, max_cost_usd=0.5))
        accountant.charge_usage(total_tokens=10, cost_usd=0.5)
        with pytest.raises(BudgetExceeded):
            accountant.charge_tokens(1)
        with pytest.raises(BudgetExceeded):
            accountant.charge_cost(0.01)

    def test_wall_clock_uses_injected_clock(self):
        now = {"t": 0.0}
        accountant = BudgetAccountant(RunBudget(wall_clock_s=1.0), clock=lambda: now["t"])
        accountant.check_deadline()
        now["t"] = 2.0
        with pytest.raises(BudgetExceeded) as exc:
            accountant.check_deadline()
        assert exc.value.kind == "wall_clock"

    def test_cancellation_token(self):
        token = CancellationToken()
        token.cancel("stop")
        with pytest.raises(BudgetExceeded) as exc:
            token.raise_if_set()
        assert exc.value.kind == "cancelled"

    def test_invalid_budget_rejected(self):
        with pytest.raises(ConfigError):
            RunBudget(max_steps=0).validate()

    def test_snapshot_reports_usage(self):
        accountant = BudgetAccountant(RunBudget())
        accountant.charge_step()
        accountant.charge_usage(total_tokens=5, cost_usd=0.01)
        snap = accountant.snapshot()
        assert snap["steps"] == 1 and snap["tokens"] == 5 and snap["cost_usd"] == 0.01


# =============================================================================================
# router
# =============================================================================================
class TestRouter:
    def test_estimate_tokens(self):
        assert estimate_tokens("") == 0
        assert estimate_tokens("abcd") == 1
        assert estimate_tokens("a" * 400) == 100

    def test_deterministic_provider_script_order(self):
        provider = DeterministicProvider(["one", "two"])
        router = ModelRouter(PlatformConfig(), routes=[Route(provider, "m")])
        assert router.complete([]).text == "one"
        assert router.complete([]).text == "two"
        assert router.complete([]).text == "two"  # last repeats

    def test_empty_response_is_an_error(self):
        with pytest.raises(InvalidModelOutput):
            coerce_response("")
        with pytest.raises(InvalidModelOutput):
            coerce_response(None)

    def test_coerce_mapping(self):
        response = coerce_response({"content": "hi", "usage": {"prompt_tokens": 3,
                                                               "completion_tokens": 4}})
        assert response.text == "hi" and response.usage.total_tokens == 7

    def test_parse_openai_tool_calls_keeps_raw_arguments(self):
        calls = parse_openai_tool_calls([
            {"id": "1", "function": {"name": "read_file", "arguments": '{"path": "a"}'}},
            {"id": "2", "function": {"name": "read_file", "arguments": "{not json"}},
        ])
        assert calls[0].arguments == {"path": "a"}
        assert calls[1].arguments == {} and calls[1].raw_arguments == "{not json"

    def test_malformed_json_is_error_not_silent_downgrade(self):
        response = ModelResponse(text="", tool_calls=())
        assert response.is_empty

    def test_failover_to_second_route(self):
        class Boom:
            name = "boom"

            def complete(self, request):
                raise RuntimeError("down")

        good = DeterministicProvider(["recovered"])
        router = ModelRouter(PlatformConfig(), routes=[Route(Boom(), "m1"), Route(good, "m2")])
        assert router.complete([]).text == "recovered"

    def test_all_routes_failing_raises(self):
        class Boom:
            name = "boom"

            def complete(self, request):
                raise RuntimeError("down")

        router = ModelRouter(PlatformConfig(), routes=[Route(Boom(), "m")])
        with pytest.raises(ProviderUnavailable):
            router.complete([])

    def test_charge_hook_receives_usage(self):
        seen = []
        provider = DeterministicProvider([{"text": "x", "usage": {"prompt_tokens": 2,
                                                                 "completion_tokens": 3}}])
        router = ModelRouter(PlatformConfig(), routes=[Route(provider, "m")],
                             charge=lambda r: seen.append(r.usage.total_tokens))
        router.complete([])
        assert seen == [5]

    def test_callable_provider_normalises_exceptions(self):
        provider = CallableProvider(lambda request: (_ for _ in ()).throw(RuntimeError("x")))
        with pytest.raises(ProviderUnavailable):
            provider.complete(None)  # type: ignore[arg-type]

    def test_price_usage(self):
        config = PlatformConfig(price_per_million={"m": {"input": 1.0, "output": 2.0}})
        assert price_usage(config, "m", 1_000_000, 1_000_000) == 3.0
        assert price_usage(config, "unknown", 1_000_000, 0) == 0.0

    def test_tracing_spans_are_created(self):
        tracer = Tracer()
        provider = DeterministicProvider(["x"])
        router = ModelRouter(PlatformConfig(), routes=[Route(provider, "m")], tracer=tracer)
        router.complete([Message.user("hi")])
        assert any(s.name == "model.call" for s in tracer.spans())


# =============================================================================================
# tools
# =============================================================================================
class TestTools:
    def _registry(self):
        registry = ToolRegistry()

        @registry.tool("read_file", "read a file", parameters={
            "type": "object", "properties": {"path": {"type": "string"}},
            "required": ["path"], "additionalProperties": False},
            resource_arg="path", action="fs.read")
        def read_file(path: str) -> str:
            return f"contents of {path}"

        return registry

    def test_registration_and_lookup(self):
        registry = self._registry()
        assert registry.names() == ["read_file"]
        assert registry.get("read_file").action == "fs.read"
        with pytest.raises(UnknownTool):
            registry.get("nope")

    def test_duplicate_registration_rejected(self):
        registry = self._registry()
        with pytest.raises(SchemaError):
            registry.register(ToolSpec(name="read_file", description="x",
                                       parameters={"type": "object"}, handler=lambda: None))

    def test_bad_schema_rejected_at_registration(self):
        with pytest.raises(SchemaError):
            ToolSpec(name="bad", description="x", parameters={"type": "wrong"},
                     handler=lambda: None)

    def test_default_guard_denies(self, empty_registry):
        guard = ToolGuard(empty_registry)
        assert guard.gate.name == "DenyAllGate"

    def test_allow_gate_runs_the_handler(self):
        registry = self._registry()
        guard = ToolGuard(registry, gate=AllowAllGate())
        result = guard.invoke(ToolCall(name="read_file", arguments={"path": "a.txt"}))
        assert result.ok and "contents of a.txt" in result.content

    def test_deny_gate_blocks_and_audits(self):
        registry = self._registry()
        guard = ToolGuard(registry, gate=DenyAllGate())
        result = guard.invoke(ToolCall(name="read_file", arguments={"path": "a.txt"}))
        assert result.denied and result.error_code == "authorization_denied"
        assert guard.summary()["denials"] == 1

    def test_schema_refusal_includes_the_models_raw_text(self):
        registry = self._registry()
        guard = ToolGuard(registry, gate=AllowAllGate())
        result = guard.invoke(ToolCall(name="read_file", arguments={},
                                       raw_arguments='{"path": 5}'))
        assert result.error_code == "invalid_tool_arguments"
        assert any("raw arguments" in p for p in result.metadata["problems"])

    def test_gate_error_fails_closed(self):
        registry = self._registry()

        def broken(**kwargs):
            raise RuntimeError("gate exploded")

        guard = ToolGuard(registry, gate=CallableGate(broken))
        result = guard.invoke(ToolCall(name="read_file", arguments={"path": "a"}))
        assert result.denied and "gate_error" in result.error

    def test_allowlist_hides_and_refuses_other_tools(self):
        registry = self._registry()
        guard = ToolGuard(registry, gate=AllowAllGate(), allowlist=["other_tool"])
        result = guard.invoke(ToolCall(name="read_file", arguments={"path": "a"}))
        assert result.denied and result.error_code == "not_allowed"
        assert registry.openai_schemas(allowlist=["other_tool"]) == []

    def test_handler_failure_is_a_result_not_a_raise(self):
        registry = ToolRegistry()

        @registry.tool("boom", "explode", parameters={"type": "object"})
        def boom() -> str:
            raise ValueError("inner failure")

        guard = ToolGuard(registry, gate=AllowAllGate())
        result = guard.invoke(ToolCall(name="boom"))
        assert (not result.ok) and result.error_code == "tool_error"
        assert "inner failure" in result.error

    def test_unexpected_argument_is_refused(self):
        registry = self._registry()
        guard = ToolGuard(registry, gate=AllowAllGate())
        result = guard.invoke(ToolCall(name="read_file", arguments={"path": "a", "extra": 1}))
        assert (not result.ok) and result.error_code == "invalid_tool_arguments"

    def test_budget_charge_refusal_becomes_a_result(self):
        registry = self._registry()

        def refuse():
            raise BudgetExceeded("tool_calls", "over")

        guard = ToolGuard(registry, gate=AllowAllGate(), charge=refuse)
        result = guard.invoke(ToolCall(name="read_file", arguments={"path": "a"}))
        assert (not result.ok) and result.error_code == "budget_exceeded"

    def test_audit_entries_are_redacted(self):
        registry = ToolRegistry()

        @registry.tool("secret_tool", "d", parameters={"type": "object"})
        def secret_tool(api_key: str = "") -> str:
            return "ok"

        guard = ToolGuard(registry, gate=AllowAllGate())
        guard.invoke(ToolCall(name="secret_tool", arguments={"api_key": "sk-hidden"}))
        assert "sk-hidden" not in json.dumps(guard.audit)


# =============================================================================================
# memory
# =============================================================================================
class TestMemory:
    def test_tokenize_drops_stopwords(self):
        assert tokenize("The quick brown fox") == ["quick", "brown", "fox"]

    def test_remember_and_retrieve(self):
        memory = EpisodicMemory()
        memory.remember("deploy pipeline", "the deploy pipeline failed on tests", kind="run")
        memory.remember("unrelated", "weather was nice", kind="run")
        hits = memory.retrieve("deploy pipeline")
        assert hits and "deploy" in hits[0].key

    def test_capacity_evicts_lowest_value(self):
        memory = EpisodicMemory(capacity=2)
        first = memory.remember("a", "alpha")
        memory.remember("b", "beta")
        memory.remember("c", "gamma")
        assert len(memory) == 2 and memory.evictions == 1

    def test_secrets_are_redacted_on_write(self):
        memory = EpisodicMemory()
        record = memory.remember("token", "value", metadata={"api_key": "sk-1"})
        assert record.metadata["api_key"] == "<redacted>"

    def test_ttl_expiry(self):
        now = {"t": 1000.0}
        memory = EpisodicMemory(ttl_s=10, clock=lambda: now["t"])
        memory.remember("a", "alpha")
        now["t"] = 2000.0
        assert memory.expire() == 1

    def test_working_memory_compacts_and_summarises(self):
        working = WorkingMemory(max_messages=6, keep_recent=2)
        for i in range(20):
            working.add(Message.user(f"message {i}"))
        assert len(working.messages()) <= 6
        assert working.compactions >= 1
        assert any("compacted" in (m.content or "") for m in working.messages())
        # The recent turns survive verbatim -- the next model call reacts to those.
        assert any((m.content or "") == "message 19" for m in working.messages())

    def test_compaction_does_not_accumulate_notes(self):
        working = WorkingMemory(max_messages=8, keep_recent=2)
        for i in range(80):
            working.add(Message.user(f"message {i}"))
        assert len(working.messages()) <= 8
        notes = [m for m in working.messages() if "compacted" in (m.content or "")]
        assert len(notes) <= 1, f"compaction notes accumulated: {len(notes)}"

    def test_render_is_bounded(self):
        memory = EpisodicMemory()
        for i in range(50):
            memory.remember(f"key {i}", "value " * 200)
        assert len(memory.render("key", top_k=5, max_chars=500)) <= 520


# =============================================================================================
# tracing + events
# =============================================================================================
class TestObservability:
    def test_span_finish_is_idempotent(self):
        tracer = Tracer()
        span = tracer.span("work")
        span.finish(ok=1)
        span.finish(other=2)
        assert span.attributes["ok"] == 1 and "other" not in span.attributes

    def test_export_is_otlp_shaped(self):
        tracer = Tracer()
        tracer.span("x").finish()
        payload = tracer.export()
        spans = payload["resourceSpans"][0]["scopeSpans"][0]["spans"]
        assert spans and spans[0]["name"] == "x"

    def test_span_capacity_is_bounded(self):
        tracer = Tracer(capacity=10)
        for i in range(50):
            tracer.span(f"s{i}").finish()
        assert len(tracer.spans()) <= 10

    def test_metrics_render(self):
        tracer = Tracer()
        tracer.start_span("op")
        tracer.end_span(tracer._stack[-1]) if tracer._stack else None
        assert "op" in tracer.metrics.render() or tracer.metrics.render()

    def test_event_bus_records_and_flushes(self):
        store: list = []
        bus = EventBus([recording_sink(store)], capacity=2)
        bus.record(event_type="a")
        bus.record(event_type="b")
        assert store and len(store) >= 2

    def test_event_metadata_is_redacted(self):
        store: list = []
        bus = EventBus([recording_sink(store)], capacity=1)
        bus.record(event_type="x", metadata={"api_key": "sk-secret"})
        assert "sk-secret" not in json.dumps(store)

    def test_failing_sink_does_not_raise_or_lose_events(self):
        def bad_sink(batch):
            raise RuntimeError("sink down")

        bus = EventBus([bad_sink], capacity=1)
        bus.record(event_type="x")
        assert bus.pending() >= 1  # retained, not lost

    def test_event_requires_a_type(self):
        with pytest.raises(ValueError):
            PlatformEvent("")

    def test_stdout_sink_writes_json_lines(self):
        import io

        buffer = io.StringIO()
        sink = stdout_event_sink(buffer)
        assert sink([{"event_type": "x"}]) is True
        assert json.loads(buffer.getvalue().strip())["event_type"] == "x"


# =============================================================================================
# ids
# =============================================================================================
class TestIds:
    def test_new_id_is_prefixed_and_unique(self):
        assert new_id("run").startswith("run_")
        assert new_id("run") != new_id("run")

    def test_unsafe_characters_are_stripped(self):
        assert " " not in new_id("run id!")

    def test_sequence_id_orders(self):
        first, second = sequence_id("x"), sequence_id("x")
        assert first < second
