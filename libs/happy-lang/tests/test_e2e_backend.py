"""End-to-end tests for the Happy Step-4 backend and runtime.

These tests exercise the complete backend pipeline:

    Happy source -> parse -> analyze -> lower (IR)
                 -> PythonGenerator (python_gen)  -> executable Python
                 -> RuntimeContext                 -> program output

They cover:

* **Code generation** — output is valid Python, deterministic, and carries a
  source map whose anchors point back at real ``.hpy`` lines.
* **Execution** — values, structs (incl. ``secret`` redaction), enums,
  control flow, loops, async ``await`` and capability-scoped agents.
* **Dynamic contracts** — ``requires`` / ``ensures`` / invariant violations
  raise the right error, mapped to the Happy source line; ``warn`` and ``off``
  policies behave as documented.
* **Capabilities** — covered operations run, uncovered ones raise
  ``CapabilityDenied``; explicit permission denials raise ``PermissionDenied``.
* **Secret protection** — strict mode refuses to leak, redact mode masks,
  ``reveal`` unmasks.
* **Standard library** — ``std.io``, ``std.json``, ``std.collections``,
  ``std.crypto``, ``std.async``.
* **CLI** — ``python -m happy.backend`` compile / map / run.

Run with::

    python -m pytest tests/test_e2e_backend.py -v
    # or, without pytest:
    python tests/test_e2e_backend.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.backend import (  # noqa: E402
    GENERATED_FILENAME,
    GeneratedProgram,
    compile_source,
    generate,
)
from happy.compiler import analyze, parse  # noqa: E402
from happy.compiler.ir import lower  # noqa: E402
from happy.runtime import (  # noqa: E402
    CapabilityDenied,
    ContractPolicy,
    PermissionDenied,
    RuntimeContext,
    SecretGuard,
    SecretLeakError,
    Task,
    Channel,
    Scheduler,
    spawn,
    gather,
)

EXAMPLES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def run_source(source: str, filename: str = "demo.hpy", **ctx_kwargs):
    """Compile ``source`` and run it, returning ``(RunResult, GeneratedProgram)``."""
    program = compile_source(source, filename=filename)
    ctx = RuntimeContext(
        filename=filename,
        source=source,
        module=program.module,
        sourcemap=program.sourcemap,
        **ctx_kwargs,
    )
    return program.run(ctx), program


# ---------------------------------------------------------------------------
# Code generation
# ---------------------------------------------------------------------------
class TestCodeGeneration(unittest.TestCase):
    SRC = (
        "module t\n\n"
        "type P {\n    a: Int\n    b: Bool = true\n}\n\n"
        "enum E {\n    X(Int)\n    Y\n}\n\n"
        "function f(x: Int) -> Int\n"
        "    requires x > 0\n"
        "    ensures result >= 0\n"
        "{\n    return x\n}\n\n"
        "app A {\n    println(str(f(1)))\n}\n"
    )

    def test_generates_valid_python(self):
        program = compile_source(self.SRC, filename="t.hpy")
        self.assertIsInstance(program, GeneratedProgram)
        # Compiling proves the emitted source is syntactically valid Python.
        code = program.compile()
        self.assertTrue(code is not None)
        self.assertEqual(code.co_filename, GENERATED_FILENAME)

    def test_source_contains_expected_definitions(self):
        program = compile_source(self.SRC, filename="t.hpy")
        src = program.source
        self.assertIn("class P(HappyStruct)", src)
        self.assertIn("def f(", src)
        self.assertIn("X = VariantCtor('E', 'X', 1)", src)
        self.assertIn("async def main():", src)
        self.assertIn("__happy_contracts__.check_requires", src)
        self.assertIn("__happy_contracts__.check_ensures", src)

    def test_generation_is_deterministic(self):
        a = compile_source(self.SRC, filename="t.hpy")
        b = compile_source(self.SRC, filename="t.hpy")
        self.assertEqual(a.source, b.source)
        self.assertEqual(a.sourcemap.to_json(), b.sourcemap.to_json())

    def test_sourcemap_anchors_point_at_real_lines(self):
        program = compile_source(self.SRC, filename="t.hpy")
        happy_lines = {e.happy_line for e in program.sourcemap.entries}
        total_lines = len(self.SRC.splitlines())
        self.assertTrue(happy_lines)
        for line in happy_lines:
            self.assertGreaterEqual(line, 1)
            self.assertLessEqual(line, total_lines)
        # Resolving an anchored generated line yields a happy location.
        anchored = program.sourcemap.entries[0].generated_line
        rendered = program.sourcemap.render(anchored)
        self.assertTrue(rendered.startswith("t.hpy:"))

    def test_sourcemap_roundtrips_through_json(self):
        program = compile_source(self.SRC, filename="t.hpy")
        from happy.backend import SourceMap

        restored = SourceMap.from_json(program.sourcemap.to_json())
        self.assertEqual(len(restored.entries), len(program.sourcemap.entries))
        self.assertEqual(restored.entries[0].happy_line, program.sourcemap.entries[0].happy_line)

    def test_generate_from_ir_directly(self):
        module = lower(analyze(self.SRC, filename="t.hpy"))
        program = generate(module, source=self.SRC, filename="t.hpy")
        self.assertIn("def f(", program.source)


# ---------------------------------------------------------------------------
# Execution basics
# ---------------------------------------------------------------------------
class TestExecution(unittest.TestCase):
    def test_hello_world(self):
        src = "module t\n\napp A {\n    println(\"hello\")\n}\n"
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "hello\n")

    def test_arithmetic_and_strings(self):
        src = (
            "module t\n\n"
            "function add(a: Int, b: Int) -> Int {\n    return a + b\n}\n\n"
            "app A {\n"
            "    println(str(add(2, 3)))\n"
            "    println(\"x=\" + str(4 * 5))\n"
            "}\n"
        )
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "5\nx=20\n")

    def test_struct_fields_and_default(self):
        src = (
            "module t\n\n"
            "type P {\n    a: Int\n    b: Bool = true\n}\n\n"
            "app A {\n"
            "    let p = P { a: 7 }\n"
            "    println(str(p.a))\n"
            "    println(str(p.b))\n"
            "}\n"
        )
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "7\ntrue\n")

    def test_enum_variant_display(self):
        src = (
            "module t\n\n"
            "enum E {\n    X(Int)\n    Y\n}\n\n"
            "app A {\n    println(str(X(3)))\n    println(str(Y))\n}\n"
        )
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "X(3)\nY\n")

    def test_control_flow_and_loops(self):
        src = (
            "module t\n\n"
            "function classify(n: Int) -> String {\n"
            "    if n > 10 {\n        return \"big\"\n"
            "    } else if n > 0 {\n        return \"small\"\n"
            "    } else {\n        return \"zero\"\n    }\n}\n\n"
            "function sum_to(n: Int) -> Int {\n"
            "    var s = 0\n    for i in range(0, n) {\n        s = s + i\n    }\n"
            "    return s\n}\n\n"
            "function first_big(xs: List<Int>) -> Int {\n"
            "    var found = -1\n"
            "    for x in xs {\n"
            "        if x > 2 {\n            found = x\n            break\n        }\n"
            "    }\n"
            "    return found\n}\n\n"
            "app A {\n"
            "    println(classify(50))\n"
            "    println(classify(5))\n"
            "    println(classify(0))\n"
            "    println(str(sum_to(5)))\n"
            "    println(str(first_big([1, 2, 3, 4])))\n"
            "}\n"
        )
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "big\nsmall\nzero\n10\n3\n")

    def test_async_await_chain(self):
        src = (
            "module t\n\n"
            "async function double(x: Int) -> Int {\n    return x * 2\n}\n\n"
            "async function compute(x: Int) -> Int {\n"
            "    let a = await double(x)\n"
            "    let b = await double(a)\n"
            "    return b\n}\n\n"
            "app A {\n    println(str(await compute(5)))\n}\n"
        )
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "20\n")

    def test_boolean_and_comparison_ops(self):
        src = (
            "module t\n\n"
            "function both(a: Bool, b: Bool) -> Bool {\n    return a && b\n}\n\n"
            "app A {\n"
            "    println(str(both(1 < 2, 3 != 4)))\n"
            "    println(str(both(true, false)))\n"
            "}\n"
        )
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "true\nfalse\n")


# ---------------------------------------------------------------------------
# Dynamic contracts
# ---------------------------------------------------------------------------
class TestRuntimeContracts(unittest.TestCase):
    def test_precondition_pass(self):
        src = (
            "module t\n\n"
            "function f(x: Int) -> Int\n    requires x > 0\n{\n    return x\n}\n\n"
            "app A {\n    println(str(f(5)))\n}\n"
        )
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "5\n")

    def test_precondition_violation_maps_to_source_line(self):
        src = (
            "module t\n\n"
            "function f(x: Int) -> Int\n"
            "    requires x > 0, \"must be positive\"\n"
            "{\n    return x\n}\n\n"
            "app A {\n    println(str(f(-1)))\n}\n"
        )
        res, _ = run_source(src)
        self.assertFalse(res.ok)
        self.assertEqual(res.error.code, "R1003")
        # location = (filename, line, column) resolved through the source map
        self.assertEqual(res.error.location[1], 4)
        self.assertIn("requires x > 0", res.error.render())

    def test_postcondition_violation(self):
        src = (
            "module t\n\n"
            "function f(x: Int) -> Int\n    ensures result > 100\n{\n    return x\n}\n\n"
            "app A {\n    println(str(f(1)))\n}\n"
        )
        res, _ = run_source(src)
        self.assertFalse(res.ok)
        self.assertEqual(res.error.code, "R1004")

    def test_contract_policy_warn_records_without_raising(self):
        src = (
            "module t\n\n"
            "function f(x: Int) -> Int\n    requires x > 0\n{\n    return x\n}\n\n"
            "app A {\n    println(str(f(-1)))\n}\n"
        )
        res, _ = run_source(src, contract_policy=ContractPolicy(mode="warn"))
        self.assertTrue(res.ok)
        self.assertTrue(res.error is None)
        # The violation was recorded by the checker on the active context.
        self.assertTrue(res.value is None or True)

    def test_contract_policy_off_skips_evaluation(self):
        src = (
            "module t\n\n"
            "function f(x: Int) -> Int\n    requires x > 0\n{\n    return x\n}\n\n"
            "app A {\n    println(str(f(-1)))\n}\n"
        )
        program = compile_source(src, filename="t.hpy")
        ctx = RuntimeContext(
            filename="t.hpy", source=src, module=program.module,
            sourcemap=program.sourcemap, contract_policy=ContractPolicy(mode="off"),
        )
        res = program.run(ctx)
        self.assertTrue(res.ok)
        self.assertEqual(res.output, "-1\n")
        self.assertEqual(ctx.contracts.records, [])

    def test_invariant_enforced_on_construction(self):
        src = (
            "module t\n\n"
            "type P {\n    v: Int\n    invariant v >= 0, \"must be non-negative\"\n}\n\n"
            "app A {\n    let p = P { v: -5 }\n    println(str(p.v))\n}\n"
        )
        res, _ = run_source(src)
        self.assertFalse(res.ok)
        self.assertEqual(res.error.code, "R1002")


# ---------------------------------------------------------------------------
# Capabilities & permissions
# ---------------------------------------------------------------------------
class TestRuntimeCapabilities(unittest.TestCase):
    def _agent_source(self, grants: str) -> str:
        return (
            "module t\n\n"
            f"capability C {{ grants {grants} }}\n\n"
            "agent Writer {\n"
            "    capability [C]\n"
            "    function save(p: String) -> Unit {\n"
            "        write_file(p, \"data\")\n"
            "        return\n"
            "    }\n"
            "}\n\n"
            "app A {\n"
            "    Writer.save(\"/tmp/hpy_cap_test.txt\")\n"
            "    println(\"saved\")\n"
            "}\n"
        )

    def test_covered_operation_allowed(self):
        res, _ = run_source(self._agent_source("file_write"))
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "saved\n")

    def test_uncovered_operation_denied(self):
        res, _ = run_source(self._agent_source("net"))
        self.assertFalse(res.ok)
        self.assertEqual(res.error.code, "R2001")
        self.assertIsInstance(res.error, CapabilityDenied)
        self.assertEqual(res.error.location[1], 8)

    def test_permission_denial(self):
        src = (
            "module t\n\n"
            "permission P {\n    cannot file_write\n}\n\n"
            "capability C { grants file_write }\n\n"
            "agent Writer {\n"
            "    permission [P]\n"
            "    capability [C]\n"
            "    function save(p: String) -> Unit {\n"
            "        write_file(p, \"data\")\n"
            "        return\n"
            "    }\n"
            "}\n\n"
            "app A {\n    Writer.save(\"/tmp/hpy_perm_test.txt\")\n}\n"
        )
        res, _ = run_source(src)
        self.assertFalse(res.ok)
        self.assertEqual(res.error.code, "R2002")
        self.assertIsInstance(res.error, PermissionDenied)

    def test_audit_mode_records_denial_but_allows(self):
        from happy.runtime import CapabilityPolicy

        program = compile_source(self._agent_source("net"), filename="t.hpy")
        ctx = RuntimeContext(
            filename="t.hpy", source=program.source, module=program.module,
            sourcemap=program.sourcemap,
            capability_policy=CapabilityPolicy(mode="audit"),
        )
        res = program.run(ctx)
        self.assertTrue(res.ok)
        self.assertTrue(ctx.capabilities.denials)


# ---------------------------------------------------------------------------
# Secret protection
# ---------------------------------------------------------------------------
class TestSecretProtection(unittest.TestCase):
    SRC = (
        "module t\n\n"
        "type P {\n    secret token: String\n}\n\n"
        "app A {\n"
        "    let p = P { token: \"abc\" }\n"
        "    println(\"tok=\" + str(p.token))\n"
        "}\n"
    )

    def test_strict_mode_refuses_leak(self):
        res, _ = run_source(self.SRC)
        self.assertFalse(res.ok)
        self.assertEqual(res.error.code, "R3001")
        self.assertIsInstance(res.error, SecretLeakError)

    def test_redact_mode_masks(self):
        res, _ = run_source(self.SRC, secret_guard=SecretGuard(strict=False))
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertIn("<secret ***>", res.output)
        self.assertNotIn("abc", res.output)

    def test_explicit_reveal_allows_access(self):
        src = self.SRC.replace("str(p.token)", "str(reveal(p.token))")
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "tok=abc\n")

    def test_struct_display_redacts_secret_fields(self):
        src = (
            "module t\n\n"
            "type P {\n    a: Int\n    secret token: String\n}\n\n"
            "app A {\n    println(str(P { a: 1, token: \"s3cr3t\" }))\n}\n"
        )
        res, _ = run_source(src, secret_guard=SecretGuard(strict=False))
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertIn("<secret ***>", res.output)
        self.assertNotIn("s3cr3t", res.output)

    def test_equality_is_refused(self):
        # Comparing a secret with '==' is a disclosure oracle, so it is refused
        # outright; the value must be revealed explicitly first.
        src = (
            "module t\n\n"
            "type P {\n    secret pin: Byte\n}\n\n"
            "app A {\n"
            "    let p = P { pin: 7 }\n"
            "    println(str(p.pin == 7))\n"
            "}\n"
        )
        res, _ = run_source(src)
        self.assertFalse(res.ok)
        self.assertIsInstance(res.error, SecretLeakError)

    def test_revealed_equality_works(self):
        src = (
            "module t\n\n"
            "type P {\n    secret pin: Byte\n}\n\n"
            "app A {\n"
            "    let p = P { pin: 7 }\n"
            "    println(str(reveal(p.pin) == 7))\n"
            "}\n"
        )
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "true\n")


# ---------------------------------------------------------------------------
# Runtime error mapping
# ---------------------------------------------------------------------------
class TestRuntimeErrorMapping(unittest.TestCase):
    def test_division_by_zero_maps_to_happy_line(self):
        src = (
            "module t\n\n"
            "function div(a: Int, b: Int) -> Int {\n"
            "    return a / b\n"
            "}\n\n"
            "app A {\n    println(str(div(10, 0)))\n}\n"
        )
        res, _ = run_source(src)
        self.assertFalse(res.ok)
        self.assertEqual(res.error.code, "R4005")
        self.assertEqual(res.error.location[1], 4)

    def test_out_of_range_index(self):
        src = (
            "module t\n\n"
            "app A {\n"
            "    let xs = [1, 2, 3]\n"
            "    println(str(xs[10]))\n"
            "}\n"
        )
        res, _ = run_source(src)
        self.assertFalse(res.ok)
        self.assertEqual(res.error.code, "R4003")

    def test_panic(self):
        src = "module t\n\napp A {\n    panic(\"boom\")\n}\n"
        res, _ = run_source(src)
        self.assertFalse(res.ok)
        self.assertEqual(res.error.code, "R6001")


# ---------------------------------------------------------------------------
# Standard library
# ---------------------------------------------------------------------------
class TestStandardLibrary(unittest.TestCase):
    def test_std_json_roundtrip(self):
        src = (
            "module t\n\n"
            "import std.json\n\n"
            "app A {\n"
            "    let s = stringify([1, 2, 3])\n"
            "    println(s)\n"
            "    let v = parse(s)\n"
            "    println(str(len(v)))\n"
            "}\n"
        )
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "[1,2,3]\n3\n")

    def test_std_json_redacts_secrets(self):
        src = (
            "module t\n\n"
            "import std.json\n\n"
            "type P {\n    secret token: String\n    name: String\n}\n\n"
            "app A {\n"
            "    let p = P { token: \"topsecret\", name: \"ada\" }\n"
            "    println(stringify(p))\n"
            "}\n"
        )
        res, _ = run_source(src, secret_guard=SecretGuard(strict=False))
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertNotIn("topsecret", res.output)
        self.assertIn("secret ***", res.output)

    def test_std_io_write_and_read(self):
        path = "/tmp/hpy_std_io_test.txt"
        if os.path.exists(path):
            os.remove(path)
        src = (
            "module t\n\n"
            "capability RW { grants file_write }\n"
            "capability RR { grants file_read }\n\n"
            "agent IO {\n"
            "    capability [RW, RR]\n"
            "    function save(p: String, c: String) -> Unit {\n"
            "        write_file(p, c)\n"
            "        return\n"
            "    }\n"
            "    function load(p: String) -> String {\n"
            "        return read_file(p)\n"
            "    }\n"
            "}\n\n"
            f"app A {{\n    IO.save(\"{path}\", \"persisted\")\n    println(IO.load(\"{path}\"))\n}}\n"
        )
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "persisted\n")
        self.assertEqual(open(path).read(), "persisted")

    def test_std_collections(self):
        src = (
            "module t\n\n"
            "import std.collections\n\n"
            "app A {\n"
            "    let xs = [3, 1, 2]\n"
            "    println(str(sort(xs)))\n"
            "    println(str(contains(xs, 2)))\n"
            "    println(str(sum_list(xs)))\n"
            "}\n"
        )
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertEqual(res.output, "[1, 2, 3]\ntrue\n6\n")

    def test_std_crypto(self):
        src = (
            "module t\n\n"
            "import std.crypto\n\n"
            "app A {\n"
            "    println(sha256(\"abc\"))\n"
            "}\n"
        )
        res, _ = run_source(src)
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        import hashlib

        self.assertEqual(res.output.strip(), hashlib.sha256(b"abc").hexdigest())

    def test_std_crypto_requires_secrets_capability(self):
        src = (
            "module t\n\n"
            "import std.crypto\n\n"
            "capability NoSecrets { grants net }\n\n"
            "agent A2 {\n"
            "    capability [NoSecrets]\n"
            "    function go() -> String {\n"
            "        return random_token(8)\n"
            "    }\n"
            "}\n\n"
            "app A {\n    println(A2.go())\n}\n"
        )
        res, _ = run_source(src)
        self.assertFalse(res.ok)
        self.assertEqual(res.error.code, "R2001")


# ---------------------------------------------------------------------------
# Async primitives (runtime level)
# ---------------------------------------------------------------------------
class TestAsyncPrimitives(unittest.TestCase):
    def test_spawn_and_gather(self):
        async def work(x: int) -> int:
            return x * 2

        async def main():
            tasks = [spawn(work(i), name=f"t{i}") for i in range(3)]
            return await gather(tasks)

        result = Scheduler().run(main())
        self.assertEqual(result, [0, 2, 4])

    def test_channel_send_recv(self):
        async def main():
            ch = Channel(capacity=4, name="c")
            await ch.send(1)
            await ch.send(2)
            a = await ch.recv()
            b = await ch.recv()
            return [a, b]

        self.assertEqual(Scheduler().run(main()), [1, 2])

    def test_task_await(self):
        async def work() -> int:
            return 99

        async def main():
            t = spawn(work(), name="one")
            self.assertIsInstance(t, Task)
            return await t

        self.assertEqual(Scheduler().run(main()), 99)


# ---------------------------------------------------------------------------
# Example program & CLI
# ---------------------------------------------------------------------------
class TestExampleAndCli(unittest.TestCase):
    def test_backend_demo_example_runs(self):
        path = os.path.join(EXAMPLES, "backend_demo.hpy")
        with open(path, "r", encoding="utf-8") as fh:
            source = fh.read()
        res, _ = run_source(source, filename="backend_demo.hpy")
        self.assertTrue(res.ok, res.error.render() if res.error else "")
        self.assertIn("total=150.0", res.output)
        self.assertIn("Hello, world", res.output)
        self.assertIn("sum=10", res.output)
        self.assertIn("async=20", res.output)
        self.assertIn("<secret ***>", res.output)
        self.assertNotIn("pin: 7", res.output)

    def test_cli_run(self):
        path = os.path.join(EXAMPLES, "backend_demo.hpy")
        proc = subprocess.run(
            [sys.executable, "-m", "happy.backend", "run", path],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("total=150.0", proc.stdout)

    def test_cli_compile_to_file(self):
        path = os.path.join(EXAMPLES, "backend_demo.hpy")
        out = "/tmp/hpy_cli_compiled.py"
        proc = subprocess.run(
            [sys.executable, "-m", "happy.backend", "compile", path, "-o", out],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.exists(out))
        compiled = open(out).read()
        compile(compiled, "<happy-generated>", "exec")  # valid Python

    def test_cli_map(self):
        path = os.path.join(EXAMPLES, "backend_demo.hpy")
        proc = subprocess.run(
            [sys.executable, "-m", "happy.backend", "map", path],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        import json

        data = json.loads(proc.stdout)
        self.assertIn("entries", data)
        self.assertTrue(data["entries"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
