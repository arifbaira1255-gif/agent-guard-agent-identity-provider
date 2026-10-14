"""Full-pipeline integration & regression tests (Step 13).

Each test drives the *whole* Happy toolchain end to end:

    source -> lexer -> parser -> AST -> semantic/type-check -> IR
           -> optimizer -> Python backend -> runtime (+ security, AI, CLI)

Nothing is mocked at the language level: real source goes in, real behaviour
comes out.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = str(Path(__file__).resolve().parents[1])


def _run(source: str, filename: str = "prog.hpy") -> str:
    """Compile + run ``source``; return the program's stdout."""
    from happy.backend import compile_source
    from happy.runtime import RuntimeContext

    program = compile_source(source, filename=filename)
    ctx = RuntimeContext(filename=filename, module=program.module)
    result = program.run(ctx)
    return result.output


class PipelineIntegrationTests(unittest.TestCase):
    def test_arithmetic_and_control_flow(self):
        src = (
            "module m\n"
            "function fib(n: Int) -> Int {\n"
            "  if n < 2 { return n }\n"
            "  return fib(n - 1) + fib(n - 2)\n"
            "}\n"
            "app Main {\n"
            "  var i = 0\n"
            "  var acc = 0\n"
            "  while i < 10 {\n"
            "    acc = acc + fib(i)\n"
            "    i = i + 1\n"
            "  }\n"
            "  println(str(acc))\n"
            "}\n"
        )
        self.assertIn("88", _run(src))

    def test_struct_and_enum_and_match(self):
        src = (
            "module m\n"
            "type Point {\n  x: Int\n  y: Int\n}\n"
            "enum Shape {\n"
            "  Circle(Int)\n"
            "  Square(Int)\n"
            "}\n"
            "function area(s: Shape) -> Int {\n"
            "  match s {\n"
            "    Circle(r) -> { return r * r * 3 }\n"
            "    Square(w) -> { return w * w }\n"
            "  }\n"
            "}\n"
            "app Main {\n"
            "  let p = Point { x: 1, y: 2 }\n"
            "  println(str(p.x + p.y))\n"
            "  println(str(area(Circle(2))))\n"
            "  println(str(area(Square(3))))\n"
            "}\n"
        )
        out = _run(src)
        self.assertIn("3", out)
        self.assertIn("12", out)
        self.assertIn("9", out)

    def test_traits_dispatch(self):
        src = (
            "module m\n"
            "trait Greeter {\n"
            "  function greet(self) -> String\n"
            "}\n"
            "type Robot { name: String }\n"
            "impl Greeter for Robot {\n"
            "  function greet(self) -> String { return \"beep \" + self.name }\n"
            "}\n"
            "app Main {\n"
            "  let r = Robot { name: \"R2\" }\n"
            "  println(r.greet())\n"
            "}\n"
        )
        self.assertIn("beep R2", _run(src))

    def test_contract_violation_is_reported(self):
        src = (
            "module m\n"
            "function safe_div(a: Int, b: Int) -> Int\n"
            "  requires b != 0, \"division by zero\"\n"
            "{ return a / b }\n"
            "app Main { println(str(safe_div(10, 0))) }\n"
        )
        from happy.backend import compile_source
        from happy.runtime import RuntimeContext

        program = compile_source(src, filename="c.hpy")
        ctx = RuntimeContext(filename="c.hpy", module=program.module)
        result = program.run(ctx)
        self.assertFalse(result.ok)

    def test_optimizer_preserves_behaviour(self):
        src = (
            "module m\n"
            "function add(a: Int, b: Int) -> Int { return a + b }\n"
            "app Main {\n"
            "  let x = 2 + 3 * 4\n"
            "  if true { println(str(x)) }\n"
            "  println(str(add(x, 1)))\n"
            "}\n"
        )
        optimized = _run(src)
        from happy.backend import compile_source
        from happy.runtime import RuntimeContext

        # Optimizer off must produce identical output.
        program = compile_source(src, filename="p.hpy", optimize=False)
        ctx = RuntimeContext(filename="p.hpy", module=program.module)
        unoptimized = program.run(ctx).output
        self.assertEqual(optimized.strip(), unoptimized.strip())
        self.assertIn("14", optimized)

    def test_sourcemap_points_back_to_source(self):
        src = (
            "module m\n"
            "function boom(a: Int, b: Int) -> Int { return a / b }\n"
            "app Main { println(str(boom(1, 0))) }\n"
        )
        from happy.backend import compile_source

        program = compile_source(src, filename="srcmap.hpy")
        # every anchor must resolve to a line within the source
        lines = src.splitlines()
        for entry in program.sourcemap.entries:
            self.assertTrue(1 <= entry.happy_line <= len(lines))

    def test_security_blocks_before_running(self):
        from happy.security.analyzer import analyze_security

        src = (
            "module m\n"
            'let api_key = "sk-live-deadbeefcafe"\n'
            "app Main { println(\"x\") }\n"
        )
        report = analyze_security(src, filename="sec.hpy")
        self.assertFalse(report.ok)
        self.assertIn("SEC010", report.codes())


class MultiModuleRegressionTests(unittest.TestCase):
    def test_two_module_project_runs(self):
        from happy.backend import compile_project
        from happy.runtime import RuntimeContext

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "math.hpy"), "w", encoding="utf-8") as fh:
                fh.write(
                    "module demo.math\n"
                    "export square\n"
                    "function square(x: Int) -> Int { return x * x }\n"
                )
            main = os.path.join(tmp, "main.hpy")
            with open(main, "w", encoding="utf-8") as fh:
                fh.write(
                    "module demo.main\n"
                    "import demo.math { square }\n"
                    "app Main { println(str(square(9))) }\n"
                )
            program = compile_project(main)
            ctx = RuntimeContext(filename=main, module=program.module)
            result = program.run(ctx)
            self.assertIn("81", result.output)


class RegressionGuardTests(unittest.TestCase):
    """Guards that lock in the behaviour of earlier build steps."""

    def test_plugin_free_import_still_works(self):
        # importing std modules must not raise
        src = (
            "module m\n"
            "import std.io\n"
            "import std.json\n"
            "app Main { println(\"ok\") }\n"
        )
        self.assertIn("ok", _run(src))

    def test_new_keywords_are_usable_as_declarations(self):
        # trait/impl/export/match must parse and run for real
        src = (
            "module m\n"
            "export helper\n"
            "function helper(x: Int) -> Int { return x + 1 }\n"
            "app Main { println(str(helper(41))) }\n"
        )
        self.assertIn("42", _run(src))

    def test_std_math_and_encoding(self):
        from happy.std import math as smath
        from happy.std import encoding

        self.assertEqual(smath.clamp(5, 1, 3), 3)
        self.assertEqual(encoding.base64_decode(encoding.base64_encode("hi")), "hi")

    def test_version_is_1_0_0(self):
        from happy import __version__

        self.assertEqual(__version__, "1.0.0")


class CLIIntegrationTests(unittest.TestCase):
    def test_check_build_run_cycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "p.hpy")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(
                    "module m\n"
                    "app Main { println(\"cycle-ok\") }\n"
                )
            for cmd in (["check", path], ["build", path], ["run", path]):
                proc = subprocess.run(
                    [sys.executable, "-m", "happy.cli", *cmd],
                    cwd=ROOT, capture_output=True, text=True,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("cycle-ok", subprocess.run(
                [sys.executable, "-m", "happy.cli", "run", path],
                cwd=ROOT, capture_output=True, text=True,
            ).stdout)


if __name__ == "__main__":
    unittest.main()
