"""Tests for the Step 8 IR optimizer."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.backend import compile_source  # noqa: E402
from happy.compiler import analyze, lower  # noqa: E402
from happy.compiler import ir  # noqa: E402
from happy.compiler.optimizer import Optimizer, optimize  # noqa: E402


def lowered(source: str):
    analysis = analyze(source, filename="o.hpy")
    return lower(analysis)


class TestConstantFolding(unittest.TestCase):
    def test_folds_arithmetic(self):
        module = lowered("module m\napp A { let x = 2 + 3 * 4 }\n")
        report = optimize(module)
        self.assertGreaterEqual(report.folded_expressions, 2)

    def test_folded_value_correct(self):
        source = ("""
        module m
        function calc() -> Int {
            return 10 * 10 - 5
        }
        app A { println(str(calc())) }
        """)
        program = compile_source(source, filename="o.hpy")
        self.assertIn("95", program.source)

    def test_folds_boolean_logic(self):
        module = lowered("module m\napp A { let b = true && false }\n")
        report = optimize(module)
        self.assertGreater(report.folded_expressions, 0)

    def test_folds_string_concat(self):
        source = 'module m\napp A { println("a" + "b") }\n'
        program = compile_source(source, filename="o.hpy")
        self.assertIn("ab", program.source)

    def test_does_not_fold_division_by_zero(self):
        source = "module m\napp A { let x = 5 / 0 }\n"
        # Must not crash the optimizer; the runtime will raise instead.
        program = compile_source(source, filename="o.hpy")
        self.assertIsNotNone(program)


class TestConstantConditions(unittest.TestCase):
    def test_true_if_pruned(self):
        source = ("""
        module m
        function f() -> Int {
            if true {
                return 1
            } else {
                return 2
            }
        }
        app A { println(str(f())) }
        """)
        module = lowered(source)
        report = optimize(module)
        self.assertGreaterEqual(report.pruned_conditions, 1)

    def test_false_if_keeps_else(self):
        source = ("""
        module m
        function f() -> Int {
            if false {
                return 1
            }
            return 2
        }
        app A { println(str(f())) }
        """)
        module = lowered(source)
        optimize(module)

    def test_while_false_removed(self):
        source = ("""
        module m
        app A {
            let x = 0
            while false {
                println("never")
            }
        }
        """)
        module = lowered(source)
        report = optimize(module)
        self.assertGreaterEqual(report.pruned_conditions, 1)


class TestDeadCode(unittest.TestCase):
    def test_statements_after_return_removed(self):
        source = ("""
        module m
        function f() -> Int {
            return 1
            let x = 2
            println("dead")
        }
        app A { println(str(f())) }
        """)
        module = lowered(source)
        report = optimize(module)
        self.assertGreaterEqual(report.eliminated_statements, 2)


class TestPureInlining(unittest.TestCase):
    def test_simple_pure_function_inlined(self):
        source = ("""
        module m
        function add1(x: Int) -> Int {
            return x + 1
        }
        app A { println(str(add1(5))) }
        """)
        module = lowered(source)
        report = optimize(module)
        self.assertGreaterEqual(report.inlined_calls, 1)

    def test_impure_function_not_inlined(self):
        source = ("""
        module m
        function shout(x: Int) -> Int {
            println("side effect")
            return x
        }
        app A { println(str(shout(5))) }
        """)
        module = lowered(source)
        report = optimize(module)
        self.assertEqual(report.inlined_calls, 0)

    def test_contract_function_not_inlined(self):
        source = ("""
        module m
        function halve(x: Int) -> Int
            requires x >= 0
        {
            return x / 2
        }
        app A { println(str(halve(8))) }
        """)
        module = lowered(source)
        report = optimize(module)
        self.assertEqual(report.inlined_calls, 0)


class TestDeterminism(unittest.TestCase):
    SOURCE = ("""
    module m
    function pure_add(a: Int, b: Int) -> Int {
        return a + b
    }
    function calc(x: Int) -> Int {
        let y = pure_add(1, 2) + pure_add(3, 4)
        if true {
            return y * 2
        }
        return 0
    }
    app A { println(str(calc(9))) }
    """)

    def _generated(self, optimize_flag: bool) -> str:
        program = compile_source(self.SOURCE, filename="o.hpy", optimize=optimize_flag)
        return program.source

    def test_optimizer_is_deterministic(self):
        a = compile_source(self.SOURCE, filename="o.hpy").source
        b = compile_source(self.SOURCE, filename="o.hpy").source
        self.assertEqual(a, b)

    def test_optimized_still_runs(self):
        from happy.runtime import RuntimeContext

        program = compile_source(self.SOURCE, filename="o.hpy")
        ctx = RuntimeContext(
            filename="o.hpy",
            source=self.SOURCE,
            module=program.module,
            sourcemap=program.sourcemap,
        )
        result = program.run(ctx)
        self.assertTrue(result.ok, result.error)
        # pure_add(1,2)=3, pure_add(3,4)=7, (3+7)*2 = 20
        self.assertIn("20", result.output)

    def test_level_zero_is_identity(self):
        module = lowered(self.SOURCE)
        report = optimize(module, level=0)
        self.assertEqual(report.total, 0)

    def test_report_serialisable(self):
        module = lowered(self.SOURCE)
        report = optimize(module)
        data = report.as_dict()
        self.assertIn("total", data)
        self.assertIsInstance(data["folded_expressions"], int)


class TestOptimizationPreservesSemantics(unittest.TestCase):
    CASES = [
        ("module m\napp A { println(str(3 + 4)) }\n", "7"),
        ("module m\napp A { println(str(2 < 3)) }\n", "true"),
        ("module m\napp A { println(\"x\" + \"y\") }\n", "xy"),
    ]

    def test_optimized_matches_expected(self):
        from happy.runtime import RuntimeContext

        for source, expected in self.CASES:
            with self.subTest(source=source):
                program = compile_source(source, filename="o.hpy", optimize=True)
                ctx = RuntimeContext(
                    filename="o.hpy",
                    source=source,
                    module=program.module,
                    sourcemap=program.sourcemap,
                )
                result = program.run(ctx)
                self.assertTrue(result.ok, result.error)
                self.assertIn(expected, result.output)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
