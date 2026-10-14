"""Unit tests for the Happy semantic analyzer and type checker.

Covers both **success** and **failure** states for every semantic rule:

* primitive / generic / user-defined type checking and inference;
* ``let`` (immutable) vs ``var`` (mutable) enforcement;
* enum exhaustiveness;
* module import/export resolution;
* unused-variable, unreachable-code and type-mismatch detection;
* contract (``requires`` / ``ensures`` / ``invariant``) Bool typing;
* permission / capability conflict and effect validation.

Run with::

    python -m pytest tests/test_semantic.py -v
    # or, without pytest:
    python tests/test_semantic.py
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.compiler import analyze  # noqa: E402
from happy.compiler.semantic import (  # noqa: E402
    ModuleInterface,
    Pattern,
    SemanticAnalyzer,
    SemanticOptions,
    Severity,
    check_exhaustive,
)
from happy.compiler import types as T  # noqa: E402
from happy.compiler.symbol_table import (  # noqa: E402
    ImmutableBindingError,
    ScopeKind,
    SymbolKind,
    SymbolTable,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def codes(result):
    return {d.code for d in result.diagnostics}


def find(result, code):
    return [d for d in result.diagnostics if d.code == code]


def analyze_src(src, **kwargs):
    return analyze(src, filename="test.hpy", **kwargs)


BANKING = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "examples",
    "banking.hpy",
)


# ---------------------------------------------------------------------------
# Type-system unit tests (types.py)
# ---------------------------------------------------------------------------
class TestTypeSystem(unittest.TestCase):
    def test_primitives(self):
        self.assertEqual(str(T.PrimitiveType("Int")), "Int")
        self.assertTrue(T.is_primitive(T.PrimitiveType("Float")))
        self.assertEqual(str(T.UNIT), "Unit")

    def test_generics_render(self):
        self.assertEqual(
            str(T.OptionType(T.PrimitiveType("Int"))), "Option<Int>"
        )
        self.assertEqual(
            str(T.MapType(T.PrimitiveType("String"), T.PrimitiveType("Int"))),
            "Map<String, Int>",
        )
        self.assertEqual(
            str(T.ResultType(T.PrimitiveType("Int"), T.PrimitiveType("String"))),
            "Result<Int, String>",
        )
        self.assertEqual(str(T.ListType(T.PrimitiveType("Char"))), "List<Char>")

    def test_equality_structural_and_nominal(self):
        self.assertEqual(
            T.ListType(T.PrimitiveType("Int")),
            T.ListType(T.PrimitiveType("Int")),
        )
        self.assertNotEqual(
            T.ListType(T.PrimitiveType("Int")),
            T.ListType(T.PrimitiveType("Float")),
        )
        a = T.StructType("Account", [("id", T.PrimitiveType("Int"))])
        b = T.StructType("Account", [("id", T.PrimitiveType("Int"))])
        c = T.StructType("Other", [("id", T.PrimitiveType("Int"))])
        self.assertEqual(a, b)      # nominal: same name
        self.assertNotEqual(a, c)   # nominal: different name

    def test_assignability_numeric_widening(self):
        Int, Float, Byte = (
            T.PrimitiveType("Int"),
            T.PrimitiveType("Float"),
            T.PrimitiveType("Byte"),
        )
        self.assertTrue(T.assignable(Int, Float))
        self.assertTrue(T.assignable(Byte, Int))
        self.assertFalse(T.assignable(Float, Int))

    def test_assignability_covariance_and_none(self):
        Int, Float = T.PrimitiveType("Int"), T.PrimitiveType("Float")
        self.assertTrue(T.assignable(T.ListType(Int), T.ListType(Float)))
        self.assertTrue(
            T.assignable(T.OptionType(T.NEVER), T.OptionType(Int))
        )

    def test_unification_binds_typevar(self):
        v = T.fresh_type_var("a")
        subst = T.unify(v, T.PrimitiveType("Int"))
        self.assertEqual(T.apply_substitution(v, subst), T.PrimitiveType("Int"))

    def test_unification_conflict(self):
        with self.assertRaises(T.UnificationError):
            T.unify(T.PrimitiveType("Int"), T.PrimitiveType("String"))

    def test_common_supertype(self):
        self.assertEqual(
            T.common_supertype(T.PrimitiveType("Int"), T.PrimitiveType("Float")),
            T.PrimitiveType("Float"),
        )
        self.assertIsNone(
            T.common_supertype(T.PrimitiveType("Int"), T.PrimitiveType("String"))
        )


# ---------------------------------------------------------------------------
# Symbol-table unit tests (symbol_table.py)
# ---------------------------------------------------------------------------
class TestSymbolTable(unittest.TestCase):
    def test_nested_scopes_and_lookup(self):
        table = SymbolTable()
        table.define("x", SymbolKind.VARIABLE, type=T.PrimitiveType("Int"))
        table.push_scope(ScopeKind.FUNCTION, name="f")
        table.define("y", SymbolKind.VARIABLE, type=T.PrimitiveType("String"))
        self.assertIsNotNone(table.lookup("x"))  # visible through the parent
        self.assertIsNotNone(table.lookup("y"))
        table.pop_scope()
        self.assertIsNone(table.lookup("y"))     # out of scope now

    def test_shadowing(self):
        table = SymbolTable()
        table.define("x", SymbolKind.VARIABLE, type=T.PrimitiveType("Int"))
        table.push_scope(ScopeKind.BLOCK)
        sym = table.define("x", SymbolKind.VARIABLE, type=T.PrimitiveType("String"))
        self.assertIsNotNone(sym.shadows)
        self.assertEqual(sym.shadows.kind, SymbolKind.VARIABLE)
        table.pop_scope()

    def test_duplicate_definition_rejected(self):
        from happy.compiler.symbol_table import DuplicateDefinitionError

        table = SymbolTable()
        table.define("x", SymbolKind.VARIABLE)
        with self.assertRaises(DuplicateDefinitionError):
            table.define("x", SymbolKind.VARIABLE)

    def test_let_immutability_enforced(self):
        table = SymbolTable()
        immutable = table.define(
            "count", SymbolKind.VARIABLE, type=T.PrimitiveType("Int"), mutable=False
        )
        mutable = table.define(
            "total", SymbolKind.VARIABLE, type=T.PrimitiveType("Int"), mutable=True
        )
        with self.assertRaises(ImmutableBindingError):
            table.check_assignment(immutable)
        table.check_assignment(mutable)  # no raise


# ---------------------------------------------------------------------------
# Exhaustiveness engine (semantic.py)
# ---------------------------------------------------------------------------
class TestExhaustiveness(unittest.TestCase):
    def setUp(self):
        self.color = T.EnumType(
            "Color",
            [("Red", ()), ("Green", ()), ("Blue", ())],
        )

    def test_complete(self):
        res = check_exhaustive(
            self.color,
            [Pattern("variant", "Red"), Pattern("variant", "Green"),
             Pattern("variant", "Blue")],
        )
        self.assertTrue(res.ok)
        self.assertEqual(res.missing, [])

    def test_missing_variant(self):
        res = check_exhaustive(
            self.color, [Pattern("variant", "Red"), Pattern("variant", "Green")]
        )
        self.assertFalse(res.ok)
        self.assertEqual(res.missing, ["Blue"])

    def test_wildcard_makes_exhaustive(self):
        res = check_exhaustive(self.color, [Pattern("wildcard")])
        self.assertTrue(res.ok)

    def test_redundant_and_unreachable(self):
        res = check_exhaustive(
            self.color,
            [Pattern("variant", "Red"), Pattern("variant", "Red"), Pattern("wildcard")],
        )
        self.assertIn("Red", res.redundant)


# ---------------------------------------------------------------------------
# Semantic analysis — success states
# ---------------------------------------------------------------------------
VALID_PROGRAM = """
module demo.valid

import std.io
import { Logger, Config } from "std.core"

type Point {
    x: Int
    y: Int
    label: String = "origin"

    invariant x >= 0
}

enum Shape {
    Circle(Float)
    Square(Float)
    Empty
}

permission Draw {
    can render
    cannot erase
}

capability Admin {
    grants override
}

rule non_negative(v: Int): v >= 0

function area(shape: Shape) -> Float
    requires shape != null || true
    ensures result >= 0.0
    effects [io]
{
    let radius: Float = 1.5
    var total = 0.0
    total = total + radius
    return total
}

async function fetch(url: String) -> Float
    requires url != ""
    effects [net]
{
    let value = await http_get(url)
    return 1.0
}

function classify(point: Point) -> String {
    if point.x >= 0 {
        return "non-negative"
    } else {
        return "negative"
    }
}

agent Worker {
    goal "do work"
    permission [Draw]
    capability [Admin]
    effects [io]

    function hello(name: String) -> String {
        return "hi " + name
    }
}

ai Reviewer {
    prompt "review the change"
    goal "approve or reject"
    ensures result != null
}

app Main {
    let p = Point { x: 1, y: 2 }
    let s = classify(p)
    print(s)
}
"""


class TestSemanticSuccess(unittest.TestCase):
    def test_valid_program_is_ok(self):
        res = analyze_src(VALID_PROGRAM)
        self.assertTrue(res.ok, msg=res.format())
        self.assertEqual(res.errors, [])

    def test_types_registered(self):
        res = analyze_src(VALID_PROGRAM)
        self.assertIn("Point", res.types)
        self.assertIn("Shape", res.types)
        self.assertIsInstance(res.types["Point"], T.StructType)
        self.assertIsInstance(res.types["Shape"], T.EnumType)

    def test_functions_registered(self):
        res = analyze_src(VALID_PROGRAM)
        self.assertIn("area", res.functions)
        self.assertIn("fetch", res.functions)
        self.assertTrue(res.functions["fetch"].is_async)

    def test_exports_include_public_decls(self):
        res = analyze_src(VALID_PROGRAM)
        self.assertIn("Point", res.exports)
        self.assertIn("Worker", res.exports)

    def test_int_literal_narrows_to_byte(self):
        src = """
type Account {
    id: Int
    pin: Byte
}
app Main {
    let a = Account { id: 1, pin: 7 }
}
"""
        res = analyze_src(src)
        self.assertTrue(res.ok, msg=res.format())

    def test_generics_ok(self):
        src = """
function first(items: List<Int>) -> Int {
    return items[0]
}
app Main {
    let xs: List<Int> = [1, 2, 3]
    let n = first(xs)
    print(n)
}
"""
        res = analyze_src(src)
        self.assertTrue(res.ok, msg=res.format())


# ---------------------------------------------------------------------------
# Semantic analysis — failure states
# ---------------------------------------------------------------------------
class TestSemanticTypeErrors(unittest.TestCase):
    def test_type_mismatch(self):
        src = """
app Main {
    let x: Int = "hello"
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4002", codes(res))
        d = find(res, "E4002")[0]
        self.assertGreaterEqual(d.line, 1)
        self.assertGreater(d.column, 0)
        self.assertIn("Int", d.render())
        self.assertIn("String", d.render())

    def test_assignment_to_let_rejected(self):
        src = """
app Main {
    let x = 1
    x = 2
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E3006", codes(res))
        self.assertIn("immutable", find(res, "E3006")[0].message)

    def test_var_assignment_allowed(self):
        src = """
app Main {
    var x = 1
    x = 2
    print(x)
}
"""
        res = analyze_src(src)
        self.assertTrue(res.ok, msg=res.format())

    def test_unknown_name(self):
        src = """
app Main {
    print(mystery)
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E3001", codes(res))

    def test_unknown_type(self):
        src = """
app Main {
    let x: Widget = 1
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E3003", codes(res))

    def test_unknown_field(self):
        src = """
type Point {
    x: Int
    y: Int
}
app Main {
    let p = Point { x: 1, y: 2 }
    print(p.z)
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E3004", codes(res))

    def test_missing_struct_field(self):
        src = """
type Point {
    x: Int
    y: Int
}
app Main {
    let p = Point { x: 1 }
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4006", codes(res))

    def test_return_type_mismatch(self):
        src = """
function f() -> Int {
    return "not an int"
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4002", codes(res))

    def test_call_arity_error(self):
        src = """
function add(a: Int, b: Int) -> Int {
    return a + b
}
app Main {
    let x = add(1)
    print(x)
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4004", codes(res))

    def test_argument_type_mismatch(self):
        src = """
function need_int(n: Int) -> Int { return n }
app Main {
    let v = need_int("nope")
    print(v)
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4002", codes(res))

    def test_await_outside_future(self):
        src = """
function f() -> Int {
    let x = await 5
    return x
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4005", codes(res))

    def test_cannot_iterate_scalar(self):
        src = """
app Main {
    for x in 5 {
        print(x)
    }
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4002", codes(res))


# ---------------------------------------------------------------------------
# Contracts
# ---------------------------------------------------------------------------
class TestContracts(unittest.TestCase):
    def test_non_bool_requires(self):
        src = """
function f(x: Int) -> Int
    requires x
{
    return x
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4003", codes(res))

    def test_bool_requires_ok(self):
        src = """
function f(x: Int) -> Int
    requires x > 0
{
    return x
}
"""
        res = analyze_src(src)
        self.assertTrue(res.ok, msg=res.format())

    def test_non_bool_invariant(self):
        src = """
type Box {
    size: Int
    invariant size + 1
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4003", codes(res))

    def test_non_bool_ensures(self):
        src = """
function f() -> Int
    ensures "oops"
{
    return 1
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4003", codes(res))

    def test_ensures_can_reference_result(self):
        src = """
function f(x: Int) -> Int
    ensures result >= 0
{
    return x
}
"""
        res = analyze_src(src)
        self.assertTrue(res.ok, msg=res.format())


# ---------------------------------------------------------------------------
# Permissions / capabilities / effects
# ---------------------------------------------------------------------------
class TestPermissionsCapabilitiesEffects(unittest.TestCase):
    def test_permission_conflict(self):
        src = """
permission Weird {
    can read
    cannot read
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4010", codes(res))

    def test_agent_unknown_permission(self):
        src = """
agent A {
    goal "x"
    permission [Missing]
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4011", codes(res))

    def test_agent_unknown_capability(self):
        src = """
agent A {
    goal "x"
    capability [Missing]
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4011", codes(res))

    def test_agent_known_permission_ok(self):
        src = """
permission P { can read }
capability C { grants write }
agent A {
    goal "x"
    permission [P]
    capability [C]
    effects [io]
}
"""
        res = analyze_src(src)
        self.assertTrue(res.ok, msg=res.format())

    def test_unknown_effect_warns(self):
        src = """
function f() -> Int
    effects [teleport]
{
    return 1
}
"""
        res = analyze_src(src)
        self.assertTrue(res.ok, msg=res.format())  # warning, not error
        self.assertIn("W3109", codes(res))


# ---------------------------------------------------------------------------
# Warnings: unused variables, unreachable code, non-exhaustive match
# ---------------------------------------------------------------------------
class TestWarnings(unittest.TestCase):
    def test_unused_variable(self):
        src = """
app Main {
    let unused_thing = 42
}
"""
        res = analyze_src(src)
        self.assertIn("W3101", codes(res))
        self.assertTrue(res.ok, msg=res.format())

    def test_underscore_silences_unused(self):
        src = """
app Main {
    let _ = 42
}
"""
        res = analyze_src(src)
        self.assertNotIn("W3101", codes(res))

    def test_used_variable_not_flagged(self):
        src = """
app Main {
    let used = 42
    print(used)
}
"""
        res = analyze_src(src)
        self.assertNotIn("W3101", codes(res))

    def test_unreachable_code(self):
        src = """
function f() -> Int {
    return 1
    print("never")
}
"""
        res = analyze_src(src)
        self.assertTrue(res.ok, msg=res.format())
        self.assertIn("W3100", codes(res))

    def test_non_exhaustive_enum_if_chain(self):
        src = """
enum Color {
    Red
    Green
    Blue
}
app Main {
    let c = Red
    if c == Red {
        print("r")
    }
    if c == Green {
        print("g")
    }
}
"""
        res = analyze_src(src)
        self.assertTrue(res.ok, msg=res.format())
        self.assertIn("W3108", codes(res))
        self.assertIn("Blue", find(res, "W3108")[0].message)

    def test_exhaustive_enum_if_chain_ok(self):
        src = """
enum Color {
    Red
    Green
    Blue
}
app Main {
    let c = Red
    if c == Red { print("r") }
    if c == Green { print("g") }
    if c == Blue { print("b") }
}
"""
        res = analyze_src(src)
        self.assertNotIn("W3108", codes(res))

    def test_unused_import_note(self):
        src = """
import std.io
app Main {
    print("hi")
}
"""
        res = analyze_src(src)
        self.assertIn("N3200", codes(res))


# ---------------------------------------------------------------------------
# Forbidden control flow
# ---------------------------------------------------------------------------
class TestControlFlow(unittest.TestCase):
    def test_break_outside_loop(self):
        src = """
function f() -> Int {
    break
    return 1
}
"""
        res = analyze_src(src)
        self.assertFalse(res.ok)
        self.assertIn("E4005", codes(res))

    def test_break_inside_loop_ok(self):
        src = """
app Main {
    var i = 0
    while i < 10 {
        if i == 5 {
            break
        }
        i = i + 1
    }
}
"""
        res = analyze_src(src)
        self.assertTrue(res.ok, msg=res.format())


# ---------------------------------------------------------------------------
# Module import / export resolution
# ---------------------------------------------------------------------------
class TestModuleResolution(unittest.TestCase):
    def test_imported_symbol_used_ok(self):
        src = """
import { Logger } from "std.core"
app Main {
    Logger.log("hi")
}
"""
        res = analyze_src(src)
        self.assertTrue(res.ok, msg=res.format())

    def test_module_interface_missing_export(self):
        iface = ModuleInterface(
            name="std.core",
            functions={"Logger": T.FunctionType([T.PrimitiveType("String")], T.UNIT)},
        )
        src = """
import { NotThere } from "std.core"
app Main {
    print("x")
}
"""
        res = analyze(src, filename="test.hpy", options=None)
        # re-run with the interface supplied
        from happy.compiler.parser import parse

        analyzer = SemanticAnalyzer(
            source=src, filename="test.hpy", module_interfaces={"std.core": iface}
        )
        analyzer.set_program(parse(src))
        result = analyzer.analyze(parse(src))
        self.assertFalse(result.ok)
        self.assertIn("E3005", codes(result))

    def test_module_interface_resolves_type(self):
        iface = ModuleInterface(
            name="geo",
            types={"Point": T.StructType("Point", [("x", T.PrimitiveType("Int"))])},
        )
        src = """
import { Point } from "geo"
app Main {
    let p: Point = foo()
    print(p)
}
"""
        from happy.compiler.parser import parse

        prog = parse(src)
        analyzer = SemanticAnalyzer(
            source=src, filename="test.hpy", module_interfaces={"geo": iface}
        )
        analyzer.set_program(prog)
        result = analyzer.analyze(prog)
        # `Point` should now resolve; no 'unknown type' error.
        self.assertNotIn("E3003", codes(result))


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
class TestOptions(unittest.TestCase):
    def test_strict_unknown_functions(self):
        src = """
app Main {
    mysterious_call(1)
}
"""
        lenient = analyze_src(src)
        self.assertTrue(lenient.ok, msg=lenient.format())

        strict = analyze_src(src, options=SemanticOptions(strict_unknown_functions=True))
        self.assertFalse(strict.ok)
        self.assertIn("E3001", codes(strict))

    def test_analysis_result_serialisation(self):
        res = analyze_src(VALID_PROGRAM)
        d = res.to_dict()
        self.assertIn("summary", d)
        self.assertIn("diagnostics", d)
        self.assertEqual(d["module"], "demo.valid")


# ---------------------------------------------------------------------------
# End-to-end over the shipped banking example
# ---------------------------------------------------------------------------
class TestBankingExample(unittest.TestCase):
    def test_banking_analyzes_clean(self):
        self.assertTrue(os.path.exists(BANKING), msg=f"missing {BANKING}")
        with open(BANKING, "r", encoding="utf-8") as fh:
            source = fh.read()
        res = analyze(source, filename="examples/banking.hpy")
        self.assertTrue(res.ok, msg=res.format())
        self.assertEqual(res.errors, [])

    def test_banking_declarations_present(self):
        with open(BANKING, "r", encoding="utf-8") as fh:
            res = analyze(fh.read(), filename="examples/banking.hpy")
        self.assertIn("Account", res.types)
        self.assertIn("TransactionKind", res.types)
        self.assertIn("deposit", res.functions)
        self.assertIn("fetch_rate", res.functions)
        self.assertTrue(res.functions["fetch_rate"].is_async)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
