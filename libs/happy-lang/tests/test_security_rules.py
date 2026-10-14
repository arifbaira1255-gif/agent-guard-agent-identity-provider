"""Tests for the extended security rules (Step 11) and runtime enforcement."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from happy.security.analyzer import (  # noqa: E402
    SecurityAnalyzer,
    Severity,
    aggregate_reports,
    analyze_security,
)


def codes(source: str, strict: bool = True):
    report = SecurityAnalyzer(strict=strict).analyze(source, filename="t.hpy")
    return {f.code for f in report.findings}


class StaticRuleTests(unittest.TestCase):
    def test_ssrf_non_literal_url(self):
        src = (
            "module m\n"
            "function fetch(u: String) -> String {\n"
            "  return http_get(\"https://x/\" + u)\n"
            "}\n"
            "app A { println(\"x\") }\n"
        )
        self.assertIn("SEC005", codes(src))

    def test_path_traversal(self):
        src = (
            "module m\n"
            "function read(p: String) -> String {\n"
            "  return read_file(\"../../etc/passwd\")\n"
            "}\n"
            "app A { println(\"x\") }\n"
        )
        self.assertIn("SEC006", codes(src))

    def test_insecure_deserialization(self):
        src = (
            "module m\n"
            "function load(s: String) -> String {\n"
            "  return json_decode(s)\n"
            "}\n"
            "app A { println(\"x\") }\n"
        )
        self.assertIn("SEC007", codes(src))

    def test_weak_crypto(self):
        src = (
            "module m\n"
            "function h(s: String) -> String {\n"
            "  return md5(s)\n"
            "}\n"
            "app A { println(\"x\") }\n"
        )
        self.assertIn("SEC008", codes(src))

    def test_command_injection(self):
        src = (
            "module m\n"
            "function run(u: String) -> String {\n"
            "  return exec(\"ls \" + u)\n"
            "}\n"
            "app A { println(\"x\") }\n"
        )
        self.assertIn("SEC009", codes(src))

    def test_hardcoded_secret(self):
        src = (
            "module m\n"
            'let api_key = "sk-live-abcdef123456"\n'
            "app A { println(\"x\") }\n"
        )
        self.assertIn("SEC010", codes(src))

    def test_placeholder_secret_is_not_flagged(self):
        src = (
            "module m\n"
            'let api_key = "changeme"\n'
            "app A { println(\"x\") }\n"
        )
        self.assertNotIn("SEC010", codes(src))

    def test_clean_source_has_no_findings(self):
        src = (
            "module m\n"
            "function add(a: Int, b: Int) -> Int {\n"
            "  return a + b\n"
            "}\n"
            "app A { println(\"ok\") }\n"
        )
        report = analyze_security(src, filename="clean.hpy")
        self.assertTrue(report.ok, report.format())


class AggregationTests(unittest.TestCase):
    def test_aggregate_merges_findings(self):
        r1 = analyze_security(
            "module a\nfunction f() -> Int { return md5(\"x\") }\napp A { }\n",
            filename="a.hpy",
        )
        r2 = analyze_security(
            "module b\nlet api_key = \"sk-live-9999999abcdef\"\napp B { }\n",
            filename="b.hpy",
        )
        merged = aggregate_reports([r1, r2], filename="proj")
        self.assertGreaterEqual(len(merged.findings), 2)
        self.assertEqual(len(merged.errors), len(merged.blocking))
        # rendering never raises
        self.assertIsInstance(merged.format(), str)
        self.assertIsInstance(merged.summary(), str)


class RuntimeEnforcementTests(unittest.TestCase):
    def test_capability_denied_raises_at_runtime(self):
        from happy.runtime.capability import (
            CapabilityChecker,
            CapabilityPolicy,
            PermissionDenied,
        )
        from happy.runtime.errors import HappyRuntimeError

        checker = CapabilityChecker(
            policy=CapabilityPolicy(mode="enforce", default_allow=False)
        )
        with self.assertRaises((PermissionDenied, HappyRuntimeError)):
            checker.check_operation("http_get", loc=None)

    def test_capability_allowed_when_default_allow(self):
        from happy.runtime.capability import CapabilityChecker, CapabilityPolicy

        checker = CapabilityChecker(
            policy=CapabilityPolicy(mode="enforce", default_allow=True)
        )
        # must not raise
        checker.check_operation("http_get", loc=None)

    def test_secret_guard_blocks_leak(self):
        from happy.runtime.secrets import SecretGuard, SecretLeakError, secret

        guard = SecretGuard(strict=True)
        box = secret("hunter2", label="pw", guard=guard)
        with self.assertRaises(SecretLeakError):
            str(box)

    def test_secret_guard_redacts_when_not_strict(self):
        from happy.runtime.secrets import REDACTED, SecretGuard, secret

        guard = SecretGuard(strict=False)
        box = secret("hunter2", label="pw", guard=guard)
        self.assertEqual(str(box), REDACTED)
        self.assertEqual(box.reveal("use it"), "hunter2")
        self.assertEqual(guard.reveal_count, 1)


if __name__ == "__main__":
    unittest.main()
