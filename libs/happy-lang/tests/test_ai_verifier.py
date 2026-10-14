"""Tests for the Happy Step-5 AI-native layer.

These tests exercise the AI provider abstraction, the planning/sandbox layer,
the trust-state verification pipeline and the static security analyzer.  They
are deliberately **offline**: every model interaction goes through
:class:`~happy.ai.providers.MockProvider`, so the suite is deterministic and
needs no API keys.

The central claim under test is that *untrusted AI output is never executed*:
invalid or unsafe code is systematically rejected at the right rung of the
trust ladder (RAW -> PARSED -> GROUNDED -> VERIFIED -> TESTED -> APPROVED).

Run with::

    python -m pytest tests/test_ai_verifier.py -v
    # or, without pytest:
    python tests/test_ai_verifier.py
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.ai import (  # noqa: E402
    AgentSandbox,
    AIProvider,
    AIRequest,
    AIResponse,
    ClaudeProvider,
    GeminiProvider,
    LocalLLMProvider,
    MockProvider,
    OpenAIProvider,
    Plan,
    PlanError,
    PlanGenerator,
    PlanStep,
    ProviderUnavailable,
    SandboxViolation,
    StepKind,
    TrustState,
    VerificationPipeline,
    get_provider,
    provider_from_env,
    resolve_provider,
)
from happy.ai.providers import parse_json_response  # noqa: E402
from happy.security import SecurityAnalyzer, analyze_security  # noqa: E402

EXAMPLES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"
)


# ---------------------------------------------------------------------------
# Fixtures — the exact snippets validated during development
# ---------------------------------------------------------------------------
SECRET_EXPOSURE = """
module t
type Account {
    id: Int
    secret pin: Byte
}
function leak(a: Account) -> Unit {
    print(a.pin)
}
"""

UNVERIFIED_PAYMENT = """
module t
function charge(amount: Float) -> Float {
    return pay(amount)
}
"""

UNSAFE_EVAL = """
module t
function f(x: String) -> Unit {
    eval(x)
}
"""

PERMISSION_ESCALATION = """
module t
permission P {
    can read
    cannot payments
}
capability C {
    grants payments
}
agent A {
    permission [P]
    capability [C]
    function go() -> Unit {
        pay(1.0)
    }
}
"""

CLEAN_PROGRAM = """
module t
function add(a: Int, b: Int) -> Int {
    return a + b
}
"""

PARSE_ERROR = "module t\nfunction f( {"

TYPE_ERROR = """
module t
function f() -> Int {
    return "not an int"
}
"""


def _plan_json(goal: str = "do the thing") -> str:
    return (
        '{"goal": "%s", "steps": ['
        '{"id": "s1", "kind": "generate", "description": "write code", "capability": "ai"},'
        '{"id": "s2", "kind": "verify", "description": "check it", "depends_on": ["s1"]}'
        "]}" % goal
    )


# ---------------------------------------------------------------------------
# 1. Provider abstraction
# ---------------------------------------------------------------------------
class TestProviders(unittest.TestCase):
    def test_mock_provider_returns_response(self):
        provider = MockProvider(responses=["hello world"])
        resp = provider.complete("hi")
        self.assertIsInstance(resp, AIResponse)
        self.assertEqual(resp.text, "hello world")
        self.assertTrue(resp.mocked)
        self.assertEqual(provider.call_count, 1)

    def test_mock_provider_responder_callable(self):
        provider = MockProvider(responder=lambda req: "echo:" + req.all_messages()[-1].content)
        resp = provider.complete("ping")
        self.assertEqual(resp.text, "echo:ping")

    def test_mock_provider_records_requests(self):
        provider = MockProvider()
        provider.complete(AIRequest.from_prompt("a", system="sys"))
        self.assertEqual(len(provider.requests), 1)
        self.assertEqual(provider.requests[0].all_messages()[0].role, "system")

    def test_registry_and_resolve(self):
        self.assertIsInstance(get_provider("mock"), MockProvider)
        self.assertIsInstance(resolve_provider("mock"), MockProvider)
        # Auto-detection always yields a usable provider (mock when no keys).
        self.assertIsInstance(resolve_provider(None), AIProvider)
        self.assertIsInstance(resolve_provider(lambda r: "x"), MockProvider)

    def test_unknown_provider_raises(self):
        with self.assertRaises(ProviderUnavailable):
            get_provider("does-not-exist")

    def test_cloud_providers_unavailable_without_key(self):
        for cls in (OpenAIProvider, ClaudeProvider, GeminiProvider):
            provider = cls(api_key=None)
            # Force the "no key" state regardless of the ambient environment.
            provider.api_key = None
            self.assertFalse(provider.is_available())
            with self.assertRaises(ProviderUnavailable):
                provider.complete("hi")

    def test_local_provider_is_available_without_key(self):
        provider = LocalLLMProvider()
        self.assertTrue(provider.is_available())

    def test_provider_from_env_falls_back_to_mock(self):
        provider = provider_from_env(prefer=["openai", "claude", "gemini", "local", "mock"])
        self.assertIsNotNone(provider)

    def test_parse_json_response_strips_fences(self):
        fenced = '```json\n{"a": 1}\n```'
        self.assertEqual(parse_json_response(fenced), {"a": 1})
        self.assertEqual(parse_json_response('{"b": 2}'), {"b": 2})


# ---------------------------------------------------------------------------
# 2. Planning + sandbox
# ---------------------------------------------------------------------------
class TestPlanning(unittest.TestCase):
    def test_valid_plan_parsed(self):
        provider = MockProvider(responses=[_plan_json("ship it")])
        plan = PlanGenerator(provider).generate(prompt="p", goal="ship it")
        self.assertIsInstance(plan, Plan)
        self.assertEqual(plan.goal, "ship it")
        self.assertEqual(len(plan.steps), 2)
        self.assertEqual(plan.steps[0].kind, StepKind.GENERATE)
        self.assertEqual(plan.steps[1].depends_on, ["s1"])

    def test_invalid_plan_rejected(self):
        # A real (non-mock) provider returning garbage must raise, not pass.
        provider = MockProvider(responses=["this is not json"], mark_mocked=False)
        with self.assertRaises(PlanError):
            PlanGenerator(provider).generate(prompt="p", goal="g")

    def test_plan_missing_goal_rejected(self):
        provider = MockProvider(responses=['{"steps": []}'], mark_mocked=False)
        with self.assertRaises(PlanError):
            PlanGenerator(provider).generate(prompt="p", goal="g")

    def test_plan_unknown_step_kind_rejected(self):
        bad = '{"goal": "g", "steps": [{"id": "s1", "kind": "teleport", "description": "d"}]}'
        provider = MockProvider(responses=[bad], mark_mocked=False)
        with self.assertRaises(PlanError):
            PlanGenerator(provider).generate(prompt="p", goal="g")

    def test_plan_cycle_rejected(self):
        cyclic = (
            '{"goal": "g", "steps": ['
            '{"id": "s1", "kind": "generate", "description": "d", "depends_on": ["s2"]},'
            '{"id": "s2", "kind": "verify", "description": "d", "depends_on": ["s1"]}'
            "]}"
        )
        provider = MockProvider(responses=[cyclic], mark_mocked=False)
        with self.assertRaises(PlanError):
            PlanGenerator(provider).generate(prompt="p", goal="g")

    def test_mock_fallback_plan(self):
        provider = MockProvider(responses=["not json at all"])
        plan = PlanGenerator(provider).generate(prompt="p", goal="g")
        self.assertTrue(plan.mocked)
        self.assertGreaterEqual(len(plan.steps), 1)

    def test_plan_serialisation_roundtrip(self):
        plan = Plan.from_dict(
            {
                "goal": "g",
                "steps": [{"id": "s1", "kind": "read", "description": "d", "target": "a.txt"}],
            }
        )
        self.assertEqual(Plan.from_dict(plan.to_dict()).to_dict(), plan.to_dict())


class TestAgentSandbox(unittest.TestCase):
    def setUp(self):
        self.sandbox = AgentSandbox(
            read_paths=["src/**"],
            write_paths=["out/**"],
            execute_commands=["pytest"],
            capabilities=["file_read"],
            allow_network=False,
            allow_execute=True,
        )

    def test_allows_in_scope_read(self):
        self.assertTrue(self.sandbox.check_read("src/main.hpy"))

    def test_denies_out_of_scope_read(self):
        with self.assertRaises(SandboxViolation):
            self.sandbox.check_read("secrets/keys.txt")

    def test_allows_in_scope_write(self):
        self.assertTrue(self.sandbox.check_write("out/result.txt"))

    def test_denies_out_of_scope_write(self):
        with self.assertRaises(SandboxViolation):
            self.sandbox.check_write("etc/passwd")

    def test_denies_network_by_default(self):
        with self.assertRaises(SandboxViolation):
            self.sandbox.check_network("https://example.com")

    def test_denies_unlisted_command(self):
        with self.assertRaises(SandboxViolation):
            self.sandbox.check_execute("rm -rf /")

    def test_allows_listed_command(self):
        self.assertTrue(self.sandbox.check_execute("pytest"))

    def test_capability_grant_enforced(self):
        self.assertTrue(self.sandbox.check_capability("file_read"))
        with self.assertRaises(SandboxViolation):
            self.sandbox.check_capability("payments")

    def test_check_plan_all_or_nothing(self):
        good = Plan(
            goal="g",
            steps=[PlanStep(id="s1", kind=StepKind.READ, description="d", target="src/a.hpy")],
        )
        self.assertTrue(self.sandbox.check_plan(good))
        bad = Plan(
            goal="g",
            steps=[PlanStep(id="s1", kind=StepKind.WRITE, description="d", target="/etc/hosts")],
        )
        with self.assertRaises(SandboxViolation):
            self.sandbox.check_plan(bad)

    def test_audit_records_denials(self):
        try:
            self.sandbox.check_read("nope.txt")
        except SandboxViolation:
            pass
        self.assertEqual(len(self.sandbox.denials), 1)


# ---------------------------------------------------------------------------
# 3. Security analyzer
# ---------------------------------------------------------------------------
class TestSecurityAnalyzer(unittest.TestCase):
    def test_secret_exposure_rejected(self):
        report = analyze_security(SECRET_EXPOSURE, filename="t.hpy")
        self.assertFalse(report.ok)
        self.assertIn("SEC001", report.codes())

    def test_unverified_payment_rejected(self):
        report = analyze_security(UNVERIFIED_PAYMENT, filename="t.hpy")
        self.assertFalse(report.ok)
        self.assertIn("SEC002", report.codes())

    def test_unsafe_eval_rejected(self):
        report = analyze_security(UNSAFE_EVAL, filename="t.hpy")
        self.assertFalse(report.ok)
        self.assertIn("SEC004", report.codes())

    def test_permission_escalation_rejected(self):
        report = analyze_security(PERMISSION_ESCALATION, filename="t.hpy")
        self.assertFalse(report.ok)
        self.assertIn("SEC003", report.codes())

    def test_clean_program_has_no_blocking_findings(self):
        report = analyze_security(CLEAN_PROGRAM, filename="t.hpy")
        self.assertTrue(report.ok, report.format())

    def test_findings_carry_locations(self):
        report = analyze_security(SECRET_EXPOSURE, filename="t.hpy")
        blocking = report.blocking
        self.assertTrue(blocking)
        self.assertIsNotNone(blocking[0].location)
        self.assertGreater(blocking[0].location.line, 0)

    def test_report_renders_diagnostics(self):
        report = analyze_security(UNVERIFIED_PAYMENT, filename="t.hpy")
        text = report.format()
        self.assertIn("SEC002", text)
        self.assertIn("t.hpy", text)


# ---------------------------------------------------------------------------
# 4. Verification pipeline (trust ladder)
# ---------------------------------------------------------------------------
class TestVerificationPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = VerificationPipeline(run_tests=False, security=SecurityAnalyzer())

    def test_clean_program_reaches_approved(self):
        result = self.pipeline.verify(CLEAN_PROGRAM, filename="clean.hpy")
        self.assertEqual(result.state, TrustState.APPROVED)
        self.assertTrue(result.approved)
        self.assertTrue(result.reached(TrustState.VERIFIED))

    def test_parse_error_rejected_at_parsed(self):
        result = self.pipeline.verify(PARSE_ERROR, filename="bad.hpy")
        self.assertEqual(result.state, TrustState.REJECTED)
        self.assertEqual(result.failed_gate.name, "parse")
        self.assertFalse(result.reached(TrustState.PARSED))

    def test_type_error_rejected_at_grounded(self):
        result = self.pipeline.verify(TYPE_ERROR, filename="types.hpy")
        self.assertEqual(result.state, TrustState.REJECTED)
        self.assertEqual(result.failed_gate.name, "typecheck")

    def test_secret_exposure_rejected_at_security(self):
        result = self.pipeline.verify(SECRET_EXPOSURE, filename="leak.hpy")
        self.assertEqual(result.state, TrustState.REJECTED)
        self.assertEqual(result.failed_gate.name, "security")
        # It got all the way to the security gate before being stopped.
        self.assertTrue(result.reached(TrustState.TESTED))

    def test_unverified_payment_rejected_at_security(self):
        result = self.pipeline.verify(UNVERIFIED_PAYMENT, filename="pay.hpy")
        self.assertEqual(result.state, TrustState.REJECTED)
        self.assertEqual(result.failed_gate.name, "security")

    def test_empty_source_rejected_at_raw(self):
        result = self.pipeline.verify("   ", filename="empty.hpy")
        self.assertEqual(result.state, TrustState.REJECTED)
        self.assertEqual(result.failed_gate.name, "raw")

    def test_trust_ladder_is_monotonic(self):
        result = self.pipeline.verify(CLEAN_PROGRAM, filename="clean.hpy")
        ranks = [TrustState.rank(g.state) for g in result.gates if g.passed]
        self.assertEqual(ranks, sorted(ranks))

    def test_report_lists_every_gate(self):
        result = self.pipeline.verify(CLEAN_PROGRAM, filename="clean.hpy")
        names = [g.name for g in result.gates]
        for expected in ("raw", "parse", "typecheck", "contracts", "tests", "security"):
            self.assertIn(expected, names)

    def test_tests_gate_passes_on_green_tests(self):
        pipeline = VerificationPipeline(run_tests=True)
        result = pipeline.verify(
            CLEAN_PROGRAM, filename="clean.hpy", tests="print('ok')\n"
        )
        self.assertEqual(result.state, TrustState.APPROVED)

    def test_tests_gate_fails_on_red_tests(self):
        pipeline = VerificationPipeline(run_tests=True)
        result = pipeline.verify(
            CLEAN_PROGRAM, filename="clean.hpy", tests="raise SystemExit(1)\n"
        )
        self.assertEqual(result.state, TrustState.REJECTED)
        self.assertEqual(result.failed_gate.name, "tests")

    def test_banking_example_reaches_approved(self):
        # The demo uses a dynamic URL (a warning, not a defect), so verify it
        # with the non-strict analyzer — the default posture for real code.
        pipeline = VerificationPipeline(run_tests=False, security=SecurityAnalyzer(strict=False))
        path = os.path.join(EXAMPLES, "banking.hpy")
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        result = pipeline.verify(source, filename="banking.hpy")
        self.assertEqual(result.state, TrustState.APPROVED, result.report())


# ---------------------------------------------------------------------------
# 5. End-to-end: mocked AI output -> verification
# ---------------------------------------------------------------------------
class TestEndToEndAI(unittest.TestCase):
    def test_mocked_ai_good_code_is_approved(self):
        """A mock model returns valid code; the pipeline approves it."""
        provider = MockProvider(responses=[CLEAN_PROGRAM])
        generated = provider.complete("write a function").text
        result = VerificationPipeline(run_tests=False, security=SecurityAnalyzer()).verify(
            generated, filename="ai_generated.hpy"
        )
        self.assertTrue(result.approved, result.report())

    def test_mocked_ai_unsafe_code_is_rejected(self):
        """A mock model returns unsafe code; the pipeline rejects it."""
        provider = MockProvider(responses=[SECRET_EXPOSURE])
        generated = provider.complete("write a login").text
        result = VerificationPipeline(run_tests=False, security=SecurityAnalyzer()).verify(
            generated, filename="ai_generated.hpy"
        )
        self.assertTrue(result.rejected)
        self.assertEqual(result.failed_gate.name, "security")

    def test_mocked_ai_broken_code_is_rejected(self):
        """A mock model returns syntactically broken code; rejected at parse."""
        provider = MockProvider(responses=[PARSE_ERROR])
        generated = provider.complete("write anything").text
        result = VerificationPipeline(run_tests=False).verify(
            generated, filename="ai_generated.hpy"
        )
        self.assertTrue(result.rejected)
        self.assertEqual(result.failed_gate.name, "parse")

    def test_plan_then_verify_flow(self):
        """The full AI-native flow: plan -> (mock) generate -> verify."""
        planner = PlanGenerator(MockProvider(responses=[_plan_json("add two ints")]))
        plan = planner.generate(prompt="add two ints", goal="add two ints")
        self.assertGreaterEqual(len(plan.steps), 1)

        generator = MockProvider(responses=[CLEAN_PROGRAM])
        code = generator.complete(plan.to_json()).text
        result = VerificationPipeline(run_tests=False, security=SecurityAnalyzer()).verify(
            code, filename="flow.hpy"
        )
        self.assertTrue(result.approved, result.report())


if __name__ == "__main__":
    unittest.main(verbosity=2)
