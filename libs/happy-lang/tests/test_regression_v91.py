"""Regression tests for the v9.1 round: fuzzers, empty app, fmt, memory guard."""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest

from happy.backend import compile_source as backend_compile
from happy.pipeline import run_source
from happy.runtime import RuntimeContext
from happy.tools.fmt import format_source

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_tool(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "tools", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class EmptyAppTests(unittest.TestCase):
    def test_empty_app_runs_and_prints_nothing(self):
        r = run_source("app A {\n}", filename="t.hpy")
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.output, "")

    def test_app_whose_only_statement_is_dead_code_runs(self):
        r = run_source('app A {\n if false {\n println("x")\n }\n}', filename="t.hpy")
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.output, "")

    def test_module_without_app_still_reports_missing_entry_point(self):
        r = run_source("function f() -> Int { return 1 }", filename="t.hpy")
        self.assertFalse(r.ok)
        self.assertIn("R8001", r.error or "")

    def test_user_main_still_wins_over_empty_app(self):
        src = 'function main() {\n println("user")\n}\napp A {\n}'
        r = run_source(src, filename="t.hpy")
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.output, "user\n")


class FormatterUnaryTests(unittest.TestCase):
    def test_nested_unary_minus_is_parenthesised(self):
        for e in ["-(-5)", "-(-(7 * 3))", "+(+2)", "-(+2)", "!(!true)"]:
            src = f"app A {{\n println(str({e}))\n}}\n"
            if e.startswith("!"):
                src = f"app A {{\n println(str({e}))\n}}\n"
            once = format_source(src)
            self.assertTrue(once.ok, f"{e}: {once.error}")
            self.assertNotIn("--", once.formatted)
            self.assertNotIn("++", once.formatted)
            a = run_source(src, filename="t.hpy")
            b = run_source(once.formatted, filename="t.hpy")
            self.assertEqual((a.ok, a.output), (b.ok, b.output), e)
            self.assertEqual(format_source(once.formatted).formatted, once.formatted)


class FuzzerSmokeTests(unittest.TestCase):
    """Fixed-seed runs keep both fuzzers (and the bugs they found) pinned."""

    def _run(self, name, count, seed):
        mod = _load_tool(name)
        old = sys.argv
        sys.argv = [name, str(count), str(seed)]
        try:
            return mod.main()
        finally:
            sys.argv = old

    def test_differential_expressions(self):
        for seed in (11, 12):
            self.assertEqual(self._run("fuzz_differential", 120, seed), 0, f"seed {seed}")

    def test_scope_programs_match_reference_interpreter(self):
        for seed in (21, 22):
            self.assertEqual(self._run("fuzz_scopes", 80, seed), 0, f"seed {seed}")


class MemoryGuardTests(unittest.TestCase):
    HOG = 'app A {\n var s = "abcdefgh"\n while true {\n s = s + s\n }\n}'

    def _ctx(self, src, **kw):
        prog = backend_compile(src, filename="m.hpy", strict=True)
        return prog, RuntimeContext(filename="m.hpy", module=prog.module, sourcemap=prog.sourcemap, **kw)

    def test_runaway_allocation_is_stopped_with_r6002(self):
        prog, ctx = self._ctx(self.HOG, max_memory_mb=200)
        res = prog.run(ctx)
        self.assertFalse(res.ok)
        self.assertEqual(getattr(res.error, "code", None), "R6002")

    def test_normal_programs_unaffected(self):
        prog, ctx = self._ctx('app A {\n println("ok")\n}', max_memory_mb=200)
        res = prog.run(ctx)
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.output, "ok\n")

    def test_guard_can_be_disabled(self):
        prog, ctx = self._ctx('app A {\n println("ok")\n}', max_memory_mb=None)
        self.assertTrue(prog.run(ctx).ok)

    def test_host_process_keeps_working_after_a_stopped_run(self):
        prog, ctx = self._ctx(self.HOG, max_memory_mb=200)
        prog.run(ctx)
        r = run_source('app A {\n println(str(1 + 1))\n}', filename="t.hpy")
        self.assertEqual(r.output, "2\n")


if __name__ == "__main__":
    unittest.main()
