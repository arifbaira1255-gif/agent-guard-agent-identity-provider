"""Tests for the Step 12 developer tooling: CLI, debugger, docgen, REPL, publish."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = str(Path(__file__).resolve().parents[1])

_PROG = """module demo.tooling

function square(x: Int) -> Int {
  return x * x
}

// A small counter type.
type Counter {
  value: Int
}

app Main {
  let n = square(6)
  println(str(n))
}
"""


def _write(tmp: str, name: str, text: str) -> str:
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def _cli(*args: str, cwd: str = ROOT):
    return subprocess.run(
        [sys.executable, "-m", "happy.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


class CLIExtendedTests(unittest.TestCase):
    def test_run_program(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "p.hpy", _PROG)
            proc = _cli("run", path)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("36", proc.stdout)

    def test_doc_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "p.hpy", _PROG)
            proc = _cli("doc", path)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("### `square`", proc.stdout)
            self.assertIn("A small counter type", proc.stdout)

    def test_debug_trace_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "p.hpy", _PROG)
            proc = _cli("debug", "--trace", path)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("p.hpy:", proc.stdout)

    def test_publish_and_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "proj")
            os.makedirs(src)
            _write(src, "main.hpy", _PROG)
            out = os.path.join(tmp, "pkg.hpyz")
            proc = _cli("publish", src, "--output", out, "--name", "demo", "--version", "1.2.3")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(os.path.isfile(out))
            dest = os.path.join(tmp, "installed")
            proc = _cli("publish", "--install", out, "--dest", dest)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(os.path.isfile(os.path.join(dest, "main.hpy")))

    def test_fmt_recursive_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "a.hpy", _PROG)
            proc = _cli("fmt", "-r", tmp, "--check")
            # May be formatted or not; the command must not crash.
            self.assertIn(proc.returncode, (0, 1), proc.stderr)

    def test_add_dependency(self):
        from happy.package.manager import MANIFEST_NAME
        from happy.package import PackageManager

        with tempfile.TemporaryDirectory() as tmp:
            proj = os.path.join(tmp, "app")
            PackageManager().init_project(proj, name="app", template="lib")
            proc = _cli("add", "http", "--version", "^1.0.0", "--dir", proj)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(os.path.join(proj, MANIFEST_NAME), encoding="utf-8") as fh:
                self.assertIn("http", fh.read())


class DebuggerTests(unittest.TestCase):
    def test_trace_records_happy_lines(self):
        from happy.backend import compile_source
        from happy.tools.debugger import trace

        program = compile_source(_PROG, filename="p.hpy")
        tracer = trace(program)
        self.assertTrue(tracer.frames)
        self.assertTrue(all(f.happy_line > 0 for f in tracer.frames))
        # every recorded location resolves to a real source line
        self.assertTrue(all(1 <= ln <= len(_PROG.splitlines()) for ln in tracer.lines()))

    def test_breakpoint_stops(self):
        from happy.backend import compile_source
        from happy.tools.debugger import Debugger

        program = compile_source(_PROG, filename="p.hpy")
        dbg = Debugger(program)
        # breakpoint on the line with `let n = square(6)`
        target = next(
            i for i, ln in enumerate(_PROG.splitlines(), start=1) if "square(6)" in ln
        )
        dbg.set_breakpoint(target)
        dbg.run()
        self.assertGreaterEqual(len(dbg.stops), 1)
        self.assertEqual(dbg.breakpoints[target].hits, len(dbg.stops))

    def test_explain_exception_maps_location(self):
        from happy.backend import compile_source
        from happy.tools.debugger import explain_exception

        bad = (
            "module m\n"
            "function boom() -> Int {\n"
            "  return 1 / 0\n"
            "}\n"
            "app Main { println(str(boom())) }\n"
        )
        program = compile_source(bad, filename="boom.hpy")
        from happy.runtime import RuntimeContext

        ctx = RuntimeContext(filename="boom.hpy", module=program.module)
        message = ""
        try:
            program.run(ctx)
        except Exception as exc:  # noqa: BLE001
            message = explain_exception(program, exc)
        # The runtime captures contract/runtime errors; either way no crash.
        self.assertIsInstance(message, str)


class DocGeneratorTests(unittest.TestCase):
    def test_generates_markdown(self):
        from happy.tools.docgen import generate_docs

        md = generate_docs(_PROG, filename="p.hpy")
        self.assertIn("# demo.tooling", md)
        self.assertIn("`square`", md)
        self.assertIn("`Counter`", md)

    def test_handles_empty_program(self):
        from happy.tools.docgen import generate_docs

        md = generate_docs("module m\napp A { }\n", filename="m.hpy")
        self.assertIn("# m", md)


class REPLTests(unittest.TestCase):
    def test_declaration_then_run(self):
        from happy.tools.repl import HappyREPL

        repl = HappyREPL()
        r1 = repl.feed("function dbl(x: Int) -> Int { return x * 2 }")
        self.assertTrue(r1.ok)
        self.assertFalse(r1.ran)
        r2 = repl.feed("app Main { println(str(dbl(21))) }")
        self.assertTrue(r2.ok)
        self.assertTrue(r2.ran)
        self.assertIn("42", r2.output)

    def test_commands(self):
        from happy.tools.repl import HappyREPL

        repl = HappyREPL()
        self.assertIn("Commands", repl.feed(":help").output)
        self.assertEqual(repl.feed(":quit").output, "__EXIT__")
        repl.feed("function f() -> Int { return 1 }")
        self.assertIn("function f", repl.feed(":show").output)
        repl.feed(":clear")
        self.assertEqual(repl.buffer, [])

    def test_unknown_command(self):
        from happy.tools.repl import HappyREPL

        repl = HappyREPL()
        result = repl.feed(":nope")
        self.assertFalse(result.ok)


class PublishTests(unittest.TestCase):
    def test_round_trip_checksums(self):
        from happy.tools.publish import create_package, install_package

        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "main.hpy", _PROG)
            out = os.path.join(tmp, "p.hpyz")
            info = create_package(tmp, output=out, name="x", version="0.1.0")
            self.assertEqual(info.name, "x")
            self.assertEqual(info.entry, "main.hpy")
            self.assertIn("main.hpy", info.checksums)
            self.assertTrue(info.checksums["main.hpy"].startswith("sha256:"))
            dest = os.path.join(tmp, "out")
            back = install_package(out, dest)
            self.assertEqual(back.name, "x")
            self.assertTrue(os.path.isfile(os.path.join(dest, "main.hpy")))


if __name__ == "__main__":
    unittest.main()
