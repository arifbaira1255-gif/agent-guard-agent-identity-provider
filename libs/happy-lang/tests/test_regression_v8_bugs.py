"""Regression tests for the 13 reported happy-lang v8 (hardened) bugs.

Each test pins the *fixed* behaviour so the bug cannot silently return:

  #1  sandbox escape via ``__class__.__mro__[1].__subclasses__()``
  #2  ``happy fmt`` destroying trait/impl declarations
  #3  verifier ``tests`` stage running arbitrary host Python
  #4  environment variables readable/writable without a capability
  #5  optimizer folding ``7 / 2`` to ``3`` instead of ``3.5``
  #6  secret leak via ``_value`` and ``==``
  #7  emoji crash / ``len("😀") == 2``
  #8  raw traceback on deeply nested input
  #9  no runtime timeout for ``while true { }``
  #10 non-exhaustive ``match`` only warning instead of a compile error
  #11 LSP server dying on a malformed JSON message
  #12 ``happy publish`` writing a machine path into the manifest
  #13 single-line ``requires ... {``, ``reveal()`` without import,
      Hindi identifiers, BOM-prefixed files

Plus regression tests for the *new* issues found by the extra attack pass
(unreachable / duplicate ``match`` arms).
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.ai.sandbox import run_sandboxed_python, scan_happy, scan_python  # noqa: E402
from happy.ai.verifier import VerificationPipeline  # noqa: E402
from happy.compiler import analyze, parse  # noqa: E402
from happy.compiler.errors import HappyError  # noqa: E402
from happy.pipeline import compile_source, run_source  # noqa: E402
from happy.runtime import SecretLeakError  # noqa: E402
from happy.tools.fmt import format_source  # noqa: E402
from happy.tools.lsp import ProtocolError, _read_message  # noqa: E402
from happy.tools.publish import create_package  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# #1 sandbox escape
# ---------------------------------------------------------------------------
class TestSandboxEscape(unittest.TestCase):
    def test_dunder_escape_rejected(self):
        src = (
            'app demo {\n'
            '  let x = "x"\n'
            '  let subs = x.__class__.__mro__[1].__subclasses__()\n'
            '}\n'
        )
        res = VerificationPipeline(run_tests=False).verify(src, filename="e.hpy")
        self.assertFalse(res.approved)
        self.assertEqual(res.failed_gate.name, "sandbox")

    def test_scan_happy_flags_dunders(self):
        self.assertTrue(scan_happy('let x = "x".__class__'))
        self.assertTrue(scan_happy("let x = ().__subclasses__()"))
        self.assertFalse(scan_happy("let x = 1 + 2"))

    def test_scan_python_flags_escapes(self):
        self.assertTrue(scan_python("import os"))
        self.assertTrue(scan_python("().__class__.__bases__"))
        self.assertTrue(scan_python("eval('1')"))
        self.assertFalse(scan_python("print(1 + 1)"))


# ---------------------------------------------------------------------------
# #2 fmt must not destroy data
# ---------------------------------------------------------------------------
class TestFmtSafety(unittest.TestCase):
    def test_language_tour_not_destroyed(self):
        path = os.path.join(ROOT, "examples", "language_tour.hpy")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        res = format_source(src, filename=path)
        self.assertTrue(res.ok)
        self.assertNotIn("unformattable", res.formatted)
        # The formatted output must still compile and keep trait/impl.
        self.assertTrue(compile_source(res.formatted, filename="tour.hpy").ok)
        self.assertIn("trait Shape", res.formatted)
        self.assertIn("impl", res.formatted)

    def test_unformattable_returns_original(self):
        # A construct the formatter cannot re-print must leave the source
        # untouched (never a lossy overwrite).
        from happy.tools import fmt as fmt_mod

        class _Weird:
            pass

        original = "app demo {\n  let x = 1\n}\n"
        # Simulate an unformattable program by monkeypatching the formatter.
        real = fmt_mod.Formatter

        class _Fake(real):
            def format(self, program):
                self.unformattable = True
                return "// <unformattable>"

        fmt_mod.Formatter = _Fake
        try:
            res = fmt_mod.format_source(original, filename="w.hpy")
        finally:
            fmt_mod.Formatter = real
        self.assertTrue(res.unformattable)
        self.assertEqual(res.formatted, original)


# ---------------------------------------------------------------------------
# #3 verifier tests stage is sandboxed
# ---------------------------------------------------------------------------
class TestVerifierTestsSandbox(unittest.TestCase):
    def test_host_python_not_executed(self):
        marker = os.path.join(tempfile.gettempdir(), "happy_reg_pwn.txt")
        if os.path.exists(marker):
            os.remove(marker)
        tests = 'import os\nopen(%r, "w").write("pwned")\n' % marker
        VerificationPipeline(run_tests=True).verify(
            'app demo {\n  let x = 1\n}\n', filename="t.hpy", tests=tests
        )
        self.assertFalse(os.path.exists(marker))

    def test_benign_tests_still_run(self):
        res = VerificationPipeline(run_tests=True).verify(
            'app demo {\n  let x = 1\n}\n', filename="t.hpy", tests='print("ok")\n'
        )
        self.assertNotEqual(str(res.state), "REJECTED")

    def test_sandbox_runner_blocks_imports(self):
        ok, out = run_sandboxed_python("import os\nprint(os.getcwd())\n", timeout=10)
        self.assertFalse(ok)
        self.assertIn("forbidden import", out)


# ---------------------------------------------------------------------------
# #4 env capability gating
# ---------------------------------------------------------------------------
class TestEnvCapability(unittest.TestCase):
    def test_env_read_denied_without_capability(self):
        os.environ["HAPPY_REG_API_KEY"] = "sk-reg-secret"
        out = run_source(
            'import std.env { get_or }\n'
            'app A { println(get_or("HAPPY_REG_API_KEY", "x")) }\n',
            filename="e.hpy",
        )
        self.assertFalse(out.ok)
        self.assertNotIn("sk-reg-secret", out.output or "")

    def test_env_direct_call_fail_closed(self):
        import happy.std.env as env

        os.environ["HAPPY_REG_API_KEY"] = "sk-reg-secret"
        with self.assertRaises(Exception):
            env.get("HAPPY_REG_API_KEY")


# ---------------------------------------------------------------------------
# #5 division
# ---------------------------------------------------------------------------
class TestDivision(unittest.TestCase):
    def test_true_division(self):
        out = run_source(
            'app demo {\n  println(7 / 2)\n  let x: Float = 7 / 2\n  println(x)\n}\n',
            filename="d.hpy",
        )
        self.assertTrue(out.ok, out.error)
        self.assertEqual(out.output.strip(), "3.5\n3.5")

    def test_negative_division(self):
        out = run_source('app demo {\n  println(-7 / 2)\n}\n', filename="d.hpy")
        self.assertTrue(out.ok)
        self.assertEqual(out.output.strip(), "-3.5")


# ---------------------------------------------------------------------------
# #6 secret protection
# ---------------------------------------------------------------------------
class TestSecretProtection(unittest.TestCase):
    def test_value_attribute_refused(self):
        out = run_source(
            'type U {\n  secret pin: String\n}\n'
            'app d {\n  let u = U { pin: "1234" }\n  println(u.pin._value)\n}\n',
            filename="s.hpy",
        )
        self.assertFalse(out.ok)
        self.assertNotIn("1234", out.output or "")

    def test_equality_refused(self):
        out = run_source(
            'type U {\n  secret pin: String\n}\n'
            'app d {\n  let u = U { pin: "1234" }\n'
            '  if u.pin == "1234" { println("guessed") }\n}\n',
            filename="s.hpy",
        )
        self.assertFalse(out.ok)
        self.assertNotIn("guessed", out.output or "")

    def test_reveal_works(self):
        out = run_source(
            'type U {\n  secret pin: String\n}\n'
            'app d {\n  let u = U { pin: "1234" }\n  println(reveal(u.pin))\n}\n',
            filename="s.hpy",
        )
        self.assertTrue(out.ok, out.error)
        self.assertIn("1234", out.output)


# ---------------------------------------------------------------------------
# #7 emoji / unicode
# ---------------------------------------------------------------------------
class TestUnicode(unittest.TestCase):
    def test_emoji_prints_and_len(self):
        out = run_source(
            'app demo {\n  println("😀")\n  println(len("😀"))\n}\n',
            filename="e.hpy",
        )
        self.assertTrue(out.ok, out.error)
        self.assertEqual(out.output.strip(), "😀\n1")

    def test_hindi_identifier(self):
        out = run_source('app demo {\n  let नाम = 5\n  println(नाम)\n}\n', filename="hi.hpy")
        self.assertTrue(out.ok, out.error)
        self.assertEqual(out.output.strip(), "5")


# ---------------------------------------------------------------------------
# #8 deep nesting -> clean errors
# ---------------------------------------------------------------------------
class TestDeepNesting(unittest.TestCase):
    def _assert_clean(self, src):
        out = run_source(src, filename="deep.hpy")
        err = out.error or ""
        self.assertNotIn("Traceback (most recent call last)", err)
        self.assertNotIn("RecursionError", err)

    def test_many_parens(self):
        self._assert_clean("app demo {\n  let x = " + "(" * 200 + "1" + ")" * 200 + "\n}\n")

    def test_long_plus_chain(self):
        self._assert_clean("app demo {\n  let x = " + " + ".join(["1"] * 500) + "\n}\n")

    def test_huge_number(self):
        self._assert_clean("app demo {\n  let x = " + "9" * 5000 + "\n}\n")


# ---------------------------------------------------------------------------
# #9 runtime timeout
# ---------------------------------------------------------------------------
class TestRuntimeTimeout(unittest.TestCase):
    def test_infinite_loop_times_out(self):
        code = (
            "import sys; sys.path.insert(0, %r)\n"
            "from happy.pipeline import run_source\n"
            "o = run_source('app demo {\\n  while true { }\\n}\\n', filename='l.hpy')\n"
            "print('OK' if not o.ok else 'HUNG')\n" % ROOT
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=30
        )
        self.assertIn("OK", proc.stdout)


# ---------------------------------------------------------------------------
# #10 non-exhaustive match
# ---------------------------------------------------------------------------
class TestMatchExhaustiveness(unittest.TestCase):
    def test_non_exhaustive_is_error(self):
        src = (
            'enum Color {\n  Red\n  Green\n  Blue\n}\n'
            'function f(c: Color) -> Int {\n'
            '  match c {\n    Red -> { return 1 }\n  }\n  return 0\n}\n'
            'app demo { let x = 1 }\n'
        )
        res = analyze(parse(src, filename="m.hpy"), filename="m.hpy")
        self.assertFalse(res.ok)
        self.assertIn("E4012", [d.code for d in res.diagnostics])

    def test_exhaustive_ok(self):
        src = (
            'enum Color {\n  Red\n  Green\n}\n'
            'function f(c: Color) -> Int {\n'
            '  match c {\n    Red -> { return 1 }\n    Green -> { return 2 }\n  }\n'
            '  return 0\n}\napp demo { let x = 1 }\n'
        )
        res = analyze(parse(src, filename="m.hpy"), filename="m.hpy")
        self.assertTrue(res.ok, [d.message for d in res.diagnostics])


# ---------------------------------------------------------------------------
# #11 LSP robustness
# ---------------------------------------------------------------------------
class TestLspRobustness(unittest.TestCase):
    def test_malformed_json_raises_protocol_error(self):
        with self.assertRaises(ProtocolError):
            _read_message(io.BytesIO(b"Content-Length: 5\r\n\r\n{bad}"))

    def test_bad_content_length(self):
        with self.assertRaises(ProtocolError):
            _read_message(io.BytesIO(b"Content-Length: abc\r\n\r\n{}"))


# ---------------------------------------------------------------------------
# #12 publish manifest path
# ---------------------------------------------------------------------------
class TestPublishManifest(unittest.TestCase):
    def test_entry_is_project_relative(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj = os.path.join(tmp, "proj")
            os.makedirs(os.path.join(proj, "src"))
            with open(os.path.join(proj, "src", "main.hpy"), "w") as fh:
                fh.write("app demo { let x = 1 }\n")
            with open(os.path.join(proj, "happy.toml"), "w") as fh:
                fh.write('[package]\nname="demo"\nversion="0.1.0"\nentry="src/main.hpy"\n')
            info = create_package(root=proj, output=os.path.join(tmp, "p.hpyz"))
            self.assertFalse(os.path.isabs(info.entry))
            self.assertNotIn(tmp, info.entry)
            self.assertEqual(info.entry, "src/main.hpy")


# ---------------------------------------------------------------------------
# #13 small things
# ---------------------------------------------------------------------------
class TestSmallFixes(unittest.TestCase):
    def test_requires_one_line(self):
        src = (
            'function f(a: Int) -> Int requires a > 0 { return a }\n'
            'app demo { let x = 1 }\n'
        )
        parse(src, filename="r.hpy")  # must not raise

    def test_reveal_without_import(self):
        out = run_source(
            'type U {\n  secret pin: String\n}\n'
            'app d {\n  let u = U { pin: "1" }\n  println(reveal(u.pin))\n}\n',
            filename="r.hpy",
        )
        self.assertTrue(out.ok, out.error)
        self.assertNotIn("unknown function", out.error or "")

    def test_bom_file(self):
        out = run_source('\ufeffapp demo {\n  let x = 1\n}\n', filename="bom.hpy")
        self.assertTrue(out.ok, out.error)


# ---------------------------------------------------------------------------
# New issues found by the extra attack pass
# ---------------------------------------------------------------------------
class TestUnreachableMatchArms(unittest.TestCase):
    def _codes(self, src):
        res = analyze(parse(src, filename="m.hpy"), filename="m.hpy")
        return [d.code for d in res.diagnostics]

    def test_duplicate_variant_arm(self):
        src = (
            'enum E {\n  A\n  B\n}\n'
            'function f(e: E) -> Int {\n'
            '  match e {\n    A -> { return 1 }\n    A -> { return 2 }\n    B -> { return 3 }\n  }\n'
            '  return 0\n}\napp d { let x = 1 }\n'
        )
        self.assertIn("E4013", self._codes(src))

    def test_arm_after_wildcard(self):
        src = (
            'enum E {\n  A\n  B\n}\n'
            'function f(e: E) -> Int {\n'
            '  match e {\n    _ -> { return 0 }\n    A -> { return 1 }\n  }\n'
            '  return 0\n}\napp d { let x = 1 }\n'
        )
        self.assertIn("E4013", self._codes(src))

    def test_duplicate_literal_arm(self):
        src = (
            'function f(n: Int) -> Int {\n'
            '  match n {\n    1 -> { return 10 }\n    1 -> { return 20 }\n    _ -> { return 0 }\n  }\n'
            '  return 0\n}\napp d { let x = 1 }\n'
        )
        self.assertIn("E4013", self._codes(src))

    def test_distinct_literals_ok(self):
        src = (
            'function f(n: Int) -> Int {\n'
            '  match n {\n    1 -> { return 10 }\n    2 -> { return 20 }\n    _ -> { return 0 }\n  }\n'
            '  return 0\n}\napp d { let x = 1 }\n'
        )
        self.assertNotIn("E4013", self._codes(src))


if __name__ == "__main__":
    unittest.main()
