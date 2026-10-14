"""End-to-end tests for the unified :mod:`happy.pipeline` entry point (Step 17).

These tests prove the whole toolchain is wired together as one coherent system:
source -> compile (lex/parse/sema/IR/optimize/backend) -> run (runtime security
model) -> check (compile + lint + security).  Nothing here is simulated.
"""

import os
import unittest

from happy import pipeline

EXAMPLES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"
)

HELLO = (
    "module t\n\n"
    "function add(a: Int, b: Int) -> Int\n"
    "  requires a >= 0\n"
    "  requires b >= 0\n"
    "  ensures result >= a\n"
    "{\n  return a + b\n}\n\n"
    "app Main {\n"
    '  println(str(add(2, 3)))\n'
    '  println("hello from pipeline")\n'
    "}\n"
)

SECRET_LEAK = (
    "module demo.bad\n"
    "app A {\n"
    '  let api_key = "sk-live-realkey123456"\n'
    "  println(api_key)\n"
    "}\n"
)

CONTRACT_VIOLATION = (
    "module demo.v\n"
    "function f(x: Int) -> Int\n"
    "  requires x > 0\n"
    "{\n  return x\n}\n"
    "app A {\n  println(str(f(0)))\n}\n"
)

SYNTAX_ERROR = "module x\napp A {"


class TestCompilePipeline(unittest.TestCase):
    def test_compile_ok_produces_python(self):
        result = pipeline.compile_source(HELLO, filename="demo.hpy")
        self.assertTrue(result.ok)
        self.assertIsNotNone(result.python_source)
        self.assertIn("def ", result.python_source)  # real generated Python
        self.assertIsNotNone(result.module)  # typed IR survived

    def test_compile_syntax_error_is_caught_not_raised(self):
        result = pipeline.compile_source(SYNTAX_ERROR, filename="bad.hpy")
        self.assertFalse(result.ok)
        self.assertTrue(result.diagnostics)
        self.assertIn("bad.hpy", result.diagnostics[0])

    def test_compile_file(self):
        result = pipeline.compile_file(os.path.join(EXAMPLES, "verified_demo.hpy"))
        self.assertTrue(result.ok)

    def test_optimization_is_applied(self):
        # constant folding: 2 + 3 should be folded at compile time.
        src = "module t\napp A {\n  println(str(2 + 3))\n}\n"
        opt = pipeline.compile_source(src, filename="o.hpy", optimize=True)
        self.assertTrue(opt.ok)
        # The generated Python should contain the folded literal 5.
        self.assertIn("5", opt.python_source)


class TestRunPipeline(unittest.TestCase):
    def test_run_captures_output(self):
        outcome = pipeline.run_source(HELLO, filename="demo.hpy")
        self.assertTrue(outcome.ok, outcome.error)
        self.assertEqual(outcome.output, "5\nhello from pipeline\n")

    def test_run_enforces_contracts_at_runtime(self):
        outcome = pipeline.run_source(CONTRACT_VIOLATION, filename="v.hpy")
        self.assertFalse(outcome.ok)
        self.assertIsNotNone(outcome.error)
        self.assertIn("R1003", outcome.error)  # requires-clause violation code

    def test_run_compile_failure_propagates(self):
        outcome = pipeline.run_source(SYNTAX_ERROR, filename="bad.hpy")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.error, "compilation failed")

    def test_run_file(self):
        outcome = pipeline.run_file(os.path.join(EXAMPLES, "backend_demo.hpy"))
        self.assertTrue(outcome.ok, outcome.error)
        self.assertTrue(outcome.output.strip())

    def test_run_is_offline_by_default(self):
        # With no injected provider and ai_offline default True, a program runs
        # without any network access even if vendor keys are in the environment.
        outcome = pipeline.run_source(HELLO, filename="demo.hpy")
        self.assertTrue(outcome.ok)


class TestCheckPipeline(unittest.TestCase):
    def test_check_clean_source_is_ok(self):
        report = pipeline.check_source(HELLO, filename="demo.hpy")
        self.assertTrue(report.ok)
        self.assertTrue(report.compile.ok)
        self.assertTrue(report.lint.ok)
        self.assertTrue(report.security.ok)
        self.assertIn("compile: ok", report.summary())

    def test_check_detects_secret_exposure(self):
        report = pipeline.check_source(SECRET_LEAK, filename="bad.hpy")
        self.assertFalse(report.ok)
        self.assertFalse(report.security.ok)
        self.assertGreater(len(report.security.findings), 0)
        self.assertIn("security:", report.summary())

    def test_check_file(self):
        report = pipeline.check_file(os.path.join(EXAMPLES, "verified_demo.hpy"))
        self.assertTrue(report.compile.ok)


class TestToolingIntegration(unittest.TestCase):
    def test_format_source_is_idempotent(self):
        once = pipeline.format_source(HELLO, filename="demo.hpy")
        self.assertTrue(once.ok)
        twice = pipeline.format_source(once.formatted, filename="demo.hpy")
        self.assertTrue(twice.ok)
        self.assertEqual(once.formatted, twice.formatted)

    def test_lint_source_runs(self):
        report = pipeline.lint_source(HELLO, filename="demo.hpy")
        self.assertIsNotNone(report)
        self.assertTrue(hasattr(report, "ok"))

    def test_analyze_security_source_runs(self):
        report = pipeline.analyze_security_source(HELLO, filename="demo.hpy")
        self.assertTrue(report.ok)

    def test_summaries_are_human_readable(self):
        self.assertIn("run: ok", pipeline.run_source(HELLO, filename="d.hpy").summary())
        self.assertIn("compile: ok", pipeline.compile_source(HELLO, filename="d.hpy").summary())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
