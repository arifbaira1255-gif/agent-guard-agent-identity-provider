"""Tests for Step 7 language features: traits / interfaces and pattern matching.

These tests exercise the full pipeline — lexer, parser, semantic analysis, IR,
Python code generation and the Happy runtime — for the ``trait``/``impl`` and
``match`` constructs added in Step 7.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.backend import compile_source  # noqa: E402
from happy.compiler import analyze  # noqa: E402
from happy.runtime import RuntimeContext  # noqa: E402


def run_source(source: str, filename: str = "demo.hpy", **ctx_kwargs):
    program = compile_source(source, filename=filename)
    ctx = RuntimeContext(
        filename=filename,
        source=source,
        module=program.module,
        sourcemap=program.sourcemap,
        **ctx_kwargs,
    )
    return program.run(ctx), program


def errors(source: str):
    res = analyze(source, filename="t.hpy")
    return [(d.code, d.message) for d in res.diagnostics if d.severity == "error"]


def warnings(source: str):
    res = analyze(source, filename="t.hpy")
    return [(d.code, d.message) for d in res.diagnostics if d.severity == "warning"]


# ---------------------------------------------------------------------------
# Traits / interfaces
# ---------------------------------------------------------------------------
TRAIT_SRC = """module t

trait Greeter {
    function greet(self) -> String
}

type Person implements Greeter {
    name: String
}

impl Greeter for Person {
    function greet(self) -> String {
        return "Hello, " + self.name
    }
}

app A {
    let p = Person { name: "Ada" }
    println(p.greet())
}
"""


class TestTraits(unittest.TestCase):
    def test_trait_parses_and_lowers(self):
        from happy.compiler import lower

        res = analyze(TRAIT_SRC, filename="t.hpy")
        self.assertEqual([e for e in errors(TRAIT_SRC) if e[0] != "W3101"], [])
        module = lower(res.program)
        self.assertEqual([t.name for t in module.traits], ["Greeter"])
        self.assertEqual(len(module.impls), 1)
        self.assertEqual(module.impls[0].trait, "Greeter")
        self.assertEqual(module.impls[0].for_type, "Person")
        self.assertEqual([m.name for m in module.impls[0].methods], ["greet"])
        self.assertEqual(module.types[0].implements, ["Greeter"])

    def test_impl_method_available_at_runtime(self):
        out, _ = run_source(TRAIT_SRC, filename="t.hpy")
        self.assertIn("Hello, Ada", out.output)

    def test_isinstance_relationship(self):
        from happy.runtime import RuntimeContext
        from happy.backend import compile_source as _cs

        program = _cs(TRAIT_SRC, filename="t.hpy")
        ctx = RuntimeContext(
            filename="t.hpy",
            source=TRAIT_SRC,
            module=program.module,
            sourcemap=program.sourcemap,
        )
        ns: dict = {"__name__": "__happy_main__"}
        ctx.prepare(ns, getattr(program.module, "imports", []))
        exec(program.compile(), ns)  # noqa: S102 - generated module
        person = ns["Person"](name="Ada")
        self.assertIsInstance(person, ns["Greeter"])
        from happy.runtime.values import Trait

        self.assertTrue(issubclass(ns["Greeter"], Trait))

    def test_missing_trait_method_is_rejected(self):
        src = """module t

trait Shape {
    function area(self) -> Float
    function name(self) -> String
}

type Sq implements Shape { s: Float }

impl Shape for Sq {
    function area(self) -> Float {
        return self.s * self.s
    }
}

app A { println("x") }
"""
        codes = [c for c, _ in errors(src)]
        self.assertIn("E4012", codes)

    def test_default_trait_method_is_inherited(self):
        src = """module t

trait Named {
    function name(self) -> String {
        return "anonymous"
    }
}

type Thing implements Named { id: Int }

impl Named for Thing { }

app A {
    let t = Thing { id: 1 }
    println(t.name())
}
"""
        out, _ = run_source(src, filename="t.hpy")
        self.assertIn("anonymous", out.output)

    def test_self_type_in_signature(self):
        src = """module t

trait Eq2 {
    function eq(self, other: Self) -> Bool
}

type P implements Eq2 { v: Int }

impl Eq2 for P {
    function eq(self, other: P) -> Bool {
        return self.v == other.v
    }
}

app A {
    let a = P { v: 1 }
    let b = P { v: 1 }
    println(str(a.eq(b)))
}
"""
        self.assertEqual(errors(src), [])
        out, _ = run_source(src, filename="t.hpy")
        self.assertIn("true", out.output)

    def test_impl_for_unknown_trait_is_rejected(self):
        src = """module t

type Q { v: Int }

impl Nope for Q {
    function f(self) -> Int { return 1 }
}

app A { println("x") }
"""
        codes = [c for c, _ in errors(src)]
        self.assertTrue("E4016" in codes or "E4011" in codes)


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------
MATCH_SRC = """module t

enum Shape {
    Circle(Float)
    Square(Float)
    Point
}

function describe(s: Shape) -> String {
    match s {
        Circle(r) -> "circle " + str(r)
        Square(side) -> "square " + str(side)
        Point -> "point"
    }
}

function classify(n: Int) -> String {
    match n {
        0 -> "zero"
        1 | 2 | 3 -> "small"
        _ -> "big"
    }
}

app A {
    println(describe(Circle(2.5)))
    println(describe(Point))
    println(classify(0))
    println(classify(2))
    println(classify(99))
}
"""


class TestPatternMatching(unittest.TestCase):
    def test_match_parses_and_runs(self):
        out, prog = run_source(MATCH_SRC, filename="t.hpy")
        self.assertEqual(
            out.output.splitlines(),
            ["circle 2.5", "point", "zero", "small", "big"],
        )

    def test_generated_code_uses_match_helpers(self):
        _, prog = run_source(MATCH_SRC, filename="t.hpy")
        self.assertIn("match_variant_ctor", prog.source)
        self.assertIn("match_or", prog.source)

    def test_non_exhaustive_match_is_compile_error(self):
        # A non-exhaustive match is a compile-time error (E4012), not a warning:
        # the language guarantees every variant is covered or a wildcard arm
        # exists, so an uncovered variant can never reach the runtime.
        src = """module t

enum E {
    A
    B
}

function f(e: E) -> Int {
    match e {
        A -> 1
    }
}

app A { println(str(f(A))) }
"""
        self.assertIn("E4012", [c for c, _ in errors(src)])

    def test_non_exhaustive_match_raises_at_runtime(self):
        src = """module t

enum E {
    A
    B
}

function f(e: E) -> Int {
    match e {
        A -> 1
    }
}

app A {
    println(str(f(B)))
}
"""
        res, _ = run_source(src, filename="t.hpy")
        self.assertFalse(res.ok)

    def test_binding_and_wildcard(self):
        src = """module t

function pick(x: Int) -> Int {
    match x {
        0 -> 100
        other -> other
    }
}

app A {
    println(str(pick(0)))
    println(str(pick(7)))
}
"""
        out, _ = run_source(src, filename="t.hpy")
        self.assertEqual(out.output.splitlines(), ["100", "7"])

    def test_struct_field_pattern(self):
        src = """module t

type P { x: Int }

function getx(p: P) -> Int {
    match p {
        P { x } -> x
    }
}

app A {
    let p = P { x: 42 }
    println(str(getx(p)))
}
"""
        out, _ = run_source(src, filename="t.hpy")
        self.assertIn("42", out.output)

    def test_option_match(self):
        src = """module t

function unwrap_or_zero(o: Option<Int>) -> Int {
    match o {
        Some(v) -> v
        None -> 0
    }
}

app A {
    println(str(unwrap_or_zero(Some(5))))
}
"""
        out, _ = run_source(src, filename="t.hpy")
        self.assertIn("5", out.output)

    def test_match_arm_block_body(self):
        src = """module t

function f(n: Int) -> String {
    match n {
        0 -> {
            let tag = "zero"
            return tag
        }
        _ -> "other"
    }
}

app A {
    println(f(0))
    println(f(1))
}
"""
        out, _ = run_source(src, filename="t.hpy")
        self.assertEqual(out.output.splitlines(), ["zero", "other"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
