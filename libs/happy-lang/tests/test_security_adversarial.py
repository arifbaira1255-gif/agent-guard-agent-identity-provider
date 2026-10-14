"""Adversarial security tests for the Happy language (Step-18 hardening).

These tests take an *attacker's* point of view.  Each one tries to make the
toolchain do something it must never do — import the host's ``os``, open a file,
write to disk, spawn a process, or run with a permission/capability it was never
granted — and asserts that every attempt is **blocked or rejected** at the
earliest possible stage (compiler, verifier, or runtime).

They run fully offline and touch nothing real on the host: file/process paths
point at throwaway locations under the system temp directory, and every write
that could ever succeed is removed again.  Nothing here replaces an existing
test — the suite is purely additive.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from happy import pipeline  # noqa: E402
from happy.ai.verifier import TrustState, verify_source  # noqa: E402
from happy.compiler import SemanticOptions, analyze, parse  # noqa: E402
from happy.runtime import CapabilityPolicy, RuntimeContext  # noqa: E402
from happy.security.analyzer import analyze_security  # noqa: E402


def _tmp_path(name: str) -> str:
    return os.path.join(tempfile.gettempdir(), name)


def _codes(report) -> set:
    return set(report.codes())


# ---------------------------------------------------------------------------
# 1. Unknown / unlisted function calls must be hard compile errors
# ---------------------------------------------------------------------------
class UnknownFunctionTests(unittest.TestCase):
    def test_open_is_unknown_function_error(self):
        src = (
            "module t\n"
            "app A {\n"
            '    let f = open("/etc/passwd")\n'
            "    println(f)\n"
            "}\n"
        )
        # Default semantic options stay lenient (back-compat)...
        self.assertTrue(analyze(parse(src, filename="t.hpy"), filename="t.hpy").ok)
        # ...but the security-strict mode the pipeline/CLI use rejects it.
        result = analyze(
            parse(src, filename="t.hpy"),
            filename="t.hpy",
            options=SemanticOptions(semantic_security_strict=True),
        )
        self.assertFalse(result.ok)
        self.assertIn("E3001", {d.code for d in result.errors})

    def test_import_builtin_is_unknown_function_error(self):
        src = (
            "module t\n"
            "app A {\n"
            '    __import__("os").system("echo pwned")\n'
            "}\n"
        )
        result = analyze(
            parse(src, filename="t.hpy"),
            filename="t.hpy",
            options=SemanticOptions(semantic_security_strict=True),
        )
        self.assertFalse(result.ok)
        self.assertIn("E3001", {d.code for d in result.errors})

    def test_getattr_eval_exec_are_unknown(self):
        for call in ("exec(\"1\")", "eval(\"1\")", "getattr(o, \"x\")", "globals()"):
            src = f"module t\napp A {{\n    {call}\n}}\n"
            result = analyze(
                parse(src, filename="t.hpy"),
                filename="t.hpy",
                options=SemanticOptions(semantic_security_strict=True),
            )
            self.assertFalse(result.ok, f"{call} should be rejected")
            self.assertIn("E3001", {d.code for d in result.errors})

    def test_pipeline_compile_rejects_unknown_call(self):
        src = 'module t\napp A {\n    open("/etc/passwd")\n}\n'
        compiled = pipeline.compile_source(src, filename="t.hpy")
        self.assertFalse(compiled.ok)


# ---------------------------------------------------------------------------
# 2. The runtime denies capability-less sensitive operations (the bypass)
# ---------------------------------------------------------------------------
class RuntimeCapabilityBypassTests(unittest.TestCase):
    def tearDown(self):
        # Never leave an attacker artefact behind, even if a test is buggy.
        for p in (_tmp_path("hpy_adv_write.txt"), _tmp_path("hpy_adv_append.txt")):
            if os.path.exists(p):
                os.remove(p)

    def test_app_body_write_file_is_denied_and_writes_nothing(self):
        target = _tmp_path("hpy_adv_write.txt")
        if os.path.exists(target):
            os.remove(target)
        src = (
            "module t\n"
            "app A {\n"
            f'    write_file("{target}", "pwned")\n'
            '    println("wrote")\n'
            "}\n"
        )
        outcome = pipeline.run_source(src, filename="t.hpy")
        self.assertFalse(outcome.ok)
        self.assertFalse(os.path.exists(target), "no file may be written")

    def test_checker_enforce_default_denies_without_agent(self):
        from happy.runtime.capability import CapabilityChecker

        checker = CapabilityChecker(policy=CapabilityPolicy(mode="enforce"))
        with self.assertRaises(Exception):
            checker.check_operation("write_file", loc=None)

    def test_agent_without_matching_capability_denied(self):
        src = (
            "module t\n"
            "capability NetOnly { grants net }\n"
            "agent A {\n"
            "    capability [NetOnly]\n"
            "    function save(p: String) -> Unit {\n"
            '        write_file(p, "x")\n'
            "        return\n"
            "    }\n"
            "}\n"
            "app Main {\n"
            f'    A.save("{_tmp_path("hpy_adv_write.txt")}")\n'
            "}\n"
        )
        outcome = pipeline.run_source(src, filename="t.hpy")
        self.assertFalse(outcome.ok)
        self.assertFalse(os.path.exists(_tmp_path("hpy_adv_write.txt")))

    def test_host_option_can_opt_back_in(self):
        # A trusted host that wraps the runtime may opt into default-allow;
        # this documents the escape hatch and keeps the policy honest.
        target = _tmp_path("hpy_adv_write.txt")
        if os.path.exists(target):
            os.remove(target)
        src = (
            "module t\n"
            "app A {\n"
            f'    write_file("{target}", "ok")\n'
            "}\n"
        )
        compiled = pipeline.compile_source(src, filename="t.hpy")
        self.assertTrue(compiled.ok, compiled.diagnostics)
        ctx = RuntimeContext(
            filename="t.hpy",
            source=src,
            module=compiled.module,
            sourcemap=compiled.program.sourcemap,
            capability_policy=CapabilityPolicy(mode="enforce", default_allow=True),
        )
        result = compiled.program.run(ctx)
        self.assertTrue(result.ok)
        self.assertTrue(os.path.exists(target))


# ---------------------------------------------------------------------------
# 3. Static analyzer: capability bypass (SEC011) + existing rules
# ---------------------------------------------------------------------------
class StaticBypassTests(unittest.TestCase):
    def test_app_body_sensitive_op_flagged(self):
        src = (
            "module t\n"
            "app A {\n"
            '    write_file("/tmp/x", "data")\n'
            '    http_get("https://example.com/")\n'
            "}\n"
        )
        report = analyze_security(src, filename="t.hpy")
        self.assertFalse(report.ok)
        self.assertIn("SEC011", _codes(report))

    def test_agent_covered_op_not_flagged_as_bypass(self):
        src = (
            "module t\n"
            "capability IO { grants file_write }\n"
            "agent W {\n"
            "    capability [IO]\n"
            "    function save(p: String) -> Unit {\n"
            '        write_file(p, "data")\n'
            "        return\n"
            "    }\n"
            "}\n"
            "app A {\n"
            "    W.save(\"/tmp/x\")\n"
            "}\n"
        )
        report = analyze_security(src, filename="t.hpy")
        self.assertNotIn("SEC011", _codes(report))

    def test_secret_exposure_still_detected(self):
        src = (
            "module t\n"
            'let api_key = "sk-live-abcdef1234567890"\n'
            "app A {\n"
            "    println(api_key)\n"
            "}\n"
        )
        self.assertFalse(analyze_security(src, filename="t.hpy").ok)


# ---------------------------------------------------------------------------
# 4. Verifier trust ladder forces REJECTED on unsafe candidates
# ---------------------------------------------------------------------------
class VerifierRejectionTests(unittest.TestCase):
    def test_unknown_call_rejected_at_typecheck(self):
        result = verify_source(
            'module t\napp A {\n    open("/etc/passwd")\n}\n',
            filename="a.hpy",
            run_tests=False,
        )
        self.assertEqual(result.state, TrustState.REJECTED)
        self.assertEqual(result.failed_gate.name, "typecheck")

    def test_import_os_rejected_at_typecheck(self):
        result = verify_source(
            'module t\napp A {\n    __import__("os")\n}\n',
            filename="a.hpy",
            run_tests=False,
        )
        self.assertEqual(result.state, TrustState.REJECTED)
        # The sandbox gate now runs first and rejects the dunder escape before
        # the type checker ever sees it.
        self.assertEqual(result.failed_gate.name, "sandbox")

    def test_capability_bypass_rejected_at_security(self):
        from happy.security.analyzer import SecurityAnalyzer

        result = verify_source(
            'module t\napp A {\n    write_file("/tmp/x", "d")\n}\n',
            filename="a.hpy",
            run_tests=False,
            security=SecurityAnalyzer(),
        )
        self.assertEqual(result.state, TrustState.REJECTED)
        self.assertEqual(result.failed_gate.name, "security")

    def test_contract_violation_rejected_during_execution(self):
        src = (
            "module t\n"
            "type P {\n    v: Int\n    invariant v >= 0, \"non-negative\"\n}\n"
            "app A {\n"
            "    let p = P { v: -1 }\n"
            "    println(str(p.v))\n"
            "}\n"
        )
        outcome = pipeline.run_source(src, filename="t.hpy")
        self.assertFalse(outcome.ok)

    def test_clean_candidate_approved(self):
        src = (
            "module t\n"
            "function add(a: Int, b: Int) -> Int { return a + b }\n"
            "app A { println(str(add(2, 3))) }\n"
        )
        result = verify_source(src, filename="a.hpy", run_tests=False)
        self.assertEqual(result.state, TrustState.APPROVED)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
