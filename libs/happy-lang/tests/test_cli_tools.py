"""Tests for the Happy Step-6 developer tooling.

Covers the CLI, the package manager, the formatter, the linter and the LSP
server.  Everything runs offline and deterministically.

Run with::

    python -m pytest tests/test_cli_tools.py -v
    # or, without pytest:
    python tests/test_cli_tools.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.cli.main import build_parser, main  # noqa: E402
from happy.compiler import parse  # noqa: E402
from happy.package import (  # noqa: E402
    DependencyGraph,
    Lockfile,
    PackageError,
    PackageManager,
    Registry,
    parse_lockfile,
    parse_manifest,
    render_lockfile,
    render_manifest,
)
from happy.tools.fmt import format_source  # noqa: E402
from happy.tools.lint import lint_source  # noqa: E402
from happy.tools.lsp import HappyLanguageServer  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")
BANKING = os.path.join(EXAMPLES, "banking.hpy")
DEMO = os.path.join(EXAMPLES, "backend_demo.hpy")
VERIFIED = os.path.join(EXAMPLES, "verified_demo.hpy")


def _cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "happy.cli", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------
class TestFormatter(unittest.TestCase):
    SRC = (
        "module t\n"
        "type P {\n"
        "  a:Int\n"
        "  b : Bool = true\n"
        "}\n"
        "function f(x:Int)->Int\n"
        "  requires x>0\n"
        "{\n"
        "  return x\n"
        "}\n"
        "app A {\n"
        "  println(str(f(1)))\n"
        "}\n"
    )

    def test_formats_and_reparses(self):
        result = format_source(self.SRC, filename="t.hpy")
        self.assertTrue(result.ok)
        self.assertTrue(result.changed)
        # The formatted output must still parse.
        parse(result.formatted, filename="t.hpy")
        self.assertIn("type P {", result.formatted)
        self.assertIn("a: Int", result.formatted)
        self.assertIn("function f(x: Int) -> Int", result.formatted)
        self.assertIn("requires x > 0", result.formatted)

    def test_idempotent(self):
        once = format_source(self.SRC).formatted
        twice = format_source(once).formatted
        self.assertEqual(once, twice)

    def test_deterministic(self):
        a = format_source(self.SRC).formatted
        b = format_source(self.SRC).formatted
        self.assertEqual(a, b)

    def test_parse_error_is_reported_not_raised(self):
        result = format_source("module t\nfunction (", filename="bad.hpy")
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.formatted, "module t\nfunction (")

    def test_examples_are_idempotent(self):
        for name in ("banking.hpy", "backend_demo.hpy"):
            path = os.path.join(EXAMPLES, name)
            with open(path) as fh:
                src = fh.read()
            once = format_source(src, filename=name).formatted
            twice = format_source(once, filename=name).formatted
            self.assertEqual(once, twice, name)


# ---------------------------------------------------------------------------
# Linter
# ---------------------------------------------------------------------------
class TestLinter(unittest.TestCase):
    def test_clean_program_has_no_errors(self):
        src = (
            "module t\n\n"
            "type Point {\n"
            "    x: Int\n"
            "    y: Int\n"
            "    invariant x >= 0\n"
            "}\n\n"
            "function add(a: Int, b: Int) -> Int\n"
            "    requires a >= 0\n"
            "    ensures result >= a\n"
            "{\n"
            "    return a + b\n"
            "}\n"
        )
        report = lint_source(src, filename="t.hpy")
        self.assertTrue(report.ok)
        self.assertEqual(report.errors, [])

    def test_naming_violation(self):
        src = "module t\n\nfunction BadName(x: Int) -> Int {\n    return x\n}\n"
        report = lint_source(src, filename="t.hpy")
        codes = report.codes()
        self.assertIn("L001", codes)
        self.assertTrue(report.by_code("L001"))

    def test_missing_contract(self):
        src = "module t\n\nfunction f(x: Int) -> Int {\n    return x\n}\n"
        report = lint_source(src, filename="t.hpy")
        self.assertIn("L002", report.codes())

    def test_unused_variable(self):
        src = (
            "module t\n\n"
            "function f() -> Int {\n"
            "    let unused = 5\n"
            "    return 1\n"
            "}\n"
        )
        report = lint_source(src, filename="t.hpy")
        self.assertIn("L003", report.codes())

    def test_weak_permission_model(self):
        src = (
            "module t\n\n"
            "capability C { grants payments }\n\n"
            "agent A {\n"
            "    capability [C]\n"
            "    function go() -> Unit {\n"
            "        return\n"
            "    }\n"
            "}\n"
        )
        report = lint_source(src, filename="t.hpy")
        self.assertIn("L004", report.codes())

    def test_strict_promotes_naming_to_error(self):
        src = "module t\n\nfunction BadName(x: Int) -> Int {\n    return x\n}\n"
        report = lint_source(src, filename="t.hpy", strict=True)
        self.assertFalse(report.ok)

    def test_parse_error_reported(self):
        report = lint_source("module t\nfunction (", filename="bad.hpy")
        self.assertIsNotNone(report.parse_error)
        self.assertFalse(report.ok)


# ---------------------------------------------------------------------------
# Package manager
# ---------------------------------------------------------------------------
class TestPackageManager(unittest.TestCase):
    def test_manifest_roundtrip(self):
        text = (
            "[package]\n"
            'name = "demo"\n'
            'version = "1.2.3"\n'
            'description = "a demo"\n'
            "\n"
            "[dependencies]\n"
            'http = "^1.0.0"\n'
            'json = "~2.1.0"\n'
            "\n"
            "[dev-dependencies]\n"
            'testkit = "0.1.0"\n'
        )
        m = parse_manifest(text)
        self.assertEqual(m.name, "demo")
        self.assertEqual(m.version, "1.2.3")
        self.assertEqual(m.dependencies["http"].requirement, "^1.0.0")
        self.assertIn("testkit", m.dev_dependencies)
        again = parse_manifest(render_manifest(m))
        self.assertEqual(again.name, "demo")
        self.assertEqual(set(again.dependencies), {"http", "json"})

    def test_manifest_missing_name(self):
        with self.assertRaises(Exception):
            parse_manifest("[package]\nversion = \"1.0.0\"\n")

    def test_resolution_picks_highest_compatible(self):
        reg = Registry()
        reg.add("http", "1.0.0", {"tls": "^1.0.0"})
        reg.add("http", "1.4.2", {"tls": "^1.0.0"})
        reg.add("http", "2.0.0")
        reg.add("tls", "1.0.0")
        pm = PackageManager(registry=reg)
        m = parse_manifest('[package]\nname = "d"\n\n[dependencies]\nhttp = "^1.0.0"\n')
        lock = pm.resolve(m)
        self.assertEqual(lock.by_name("http").version, "1.4.2")
        self.assertIsNotNone(lock.by_name("tls"))

    def test_unresolvable_dependency(self):
        pm = PackageManager(registry=Registry())
        m = parse_manifest('[package]\nname = "d"\n\n[dependencies]\nmissing = "^1.0.0"\n')
        with self.assertRaises(PackageError):
            pm.resolve(m)

    def test_lockfile_roundtrip(self):
        reg = Registry()
        reg.add("a", "1.0.0")
        pm = PackageManager(registry=reg)
        m = parse_manifest('[package]\nname = "d"\n\n[dependencies]\na = "^1.0.0"\n')
        lock = pm.resolve(m)
        restored = parse_lockfile(render_lockfile(lock))
        self.assertEqual(restored.by_name("a").version, "1.0.0")
        self.assertTrue(restored.by_name("a").checksum.startswith("sha256:"))

    def test_graph_topological_order(self):
        reg = Registry()
        reg.add("a", "1.0.0", {"b": "^1.0.0"})
        reg.add("b", "1.0.0", {"c": "^1.0.0"})
        reg.add("c", "1.0.0")
        pm = PackageManager(registry=reg)
        m = parse_manifest('[package]\nname = "root"\n\n[dependencies]\na = "^1.0.0"\n')
        graph = pm.build_graph(m)
        order = graph.topological_order()
        self.assertLess(order.index("c"), order.index("b"))
        self.assertLess(order.index("b"), order.index("a"))
        self.assertFalse(graph.has_cycle())

    def test_cycle_detection(self):
        g = DependencyGraph()
        g.add_edge("a", "b")
        g.add_edge("b", "c")
        g.add_edge("c", "a")
        self.assertTrue(g.has_cycle())
        with self.assertRaises(PackageError):
            g.topological_order()

    def test_init_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "proj")
            pm = PackageManager()
            m = pm.init_project(target, name="proj", template="app")
            self.assertEqual(m.name, "proj")
            self.assertTrue(os.path.isfile(os.path.join(target, "happy.toml")))
            self.assertTrue(os.path.isfile(os.path.join(target, "happy.lock")))
            self.assertTrue(os.path.isfile(os.path.join(target, "src", "main.hpy")))
            self.assertTrue(os.path.isfile(os.path.join(target, "tests", "test_main.hpy")))
            # The scaffolded entry file must compile and run.
            from happy.backend import compile_source
            from happy.runtime import RuntimeContext

            with open(os.path.join(target, "src", "main.hpy")) as fh:
                src = fh.read()
            program = compile_source(src, filename="main.hpy")
            ctx = RuntimeContext(filename="main.hpy", source=src,
                                 module=program.module, sourcemap=program.sourcemap)
            res = program.run(ctx)
            self.assertTrue(res.ok, res.error.render() if res.error else "")
            self.assertIn("Hello from proj", res.output)

    def test_init_unknown_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PackageError):
                PackageManager().init_project(os.path.join(tmp, "x"), template="nope")

    def test_init_refuses_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            pm = PackageManager()
            pm.init_project(tmp, name="x")
            with self.assertRaises(PackageError):
                pm.init_project(tmp, name="x")


# ---------------------------------------------------------------------------
# LSP
# ---------------------------------------------------------------------------
class TestLSP(unittest.TestCase):
    def setUp(self):
        self.server = HappyLanguageServer()
        with open(BANKING) as fh:
            self.text = fh.read()
        self.uri = "file:///banking.hpy"

    def test_initialize(self):
        out = self.server.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        caps = out[0]["result"]["capabilities"]
        self.assertTrue(caps["hoverProvider"])
        self.assertTrue(caps["definitionProvider"])
        self.assertTrue(caps["documentSymbolProvider"])

    def test_did_open_publishes_diagnostics(self):
        out = self.server.handle({
            "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": self.uri, "text": self.text, "version": 1}},
        })
        self.assertEqual(out[0]["method"], "textDocument/publishDiagnostics")
        self.assertIsInstance(out[0]["params"]["diagnostics"], list)

    def test_diagnostics_on_broken_source(self):
        diags = self.server.compute_diagnostics("module t\nfunction (", "file:///bad.hpy")
        self.assertTrue(diags)
        self.assertEqual(diags[0]["severity"], 1)

    def test_completion_includes_declarations(self):
        self.server.handle({
            "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": self.uri, "text": self.text, "version": 1}},
        })
        out = self.server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "textDocument/completion",
            "params": {"textDocument": {"uri": self.uri}, "position": {"line": 0, "character": 0}},
        })
        labels = {i["label"] for i in out[0]["result"]["items"]}
        self.assertIn("function", labels)   # keyword
        self.assertIn("Account", labels)    # declared type
        self.assertIn("deposit", labels)    # declared function

    def test_hover_shows_signature_and_contracts(self):
        self.server.handle({
            "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": self.uri, "text": self.text, "version": 1}},
        })
        lines = self.text.splitlines()
        line = next(i for i, ln in enumerate(lines) if "function deposit" in ln)
        col = lines[line].index("deposit") + 2
        out = self.server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "textDocument/hover",
            "params": {"textDocument": {"uri": self.uri}, "position": {"line": line, "character": col}},
        })
        value = out[0]["result"]["contents"]["value"]
        self.assertIn("function deposit", value)
        self.assertIn("Contracts", value)

    def test_definition(self):
        self.server.handle({
            "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": self.uri, "text": self.text, "version": 1}},
        })
        lines = self.text.splitlines()
        line = next(i for i, ln in enumerate(lines) if "function deposit" in ln)
        col = lines[line].index("deposit") + 2
        out = self.server.handle({
            "jsonrpc": "2.0", "id": 4, "method": "textDocument/definition",
            "params": {"textDocument": {"uri": self.uri}, "position": {"line": line, "character": col}},
        })
        self.assertEqual(out[0]["result"]["uri"], self.uri)

    def test_document_symbols(self):
        self.server.handle({
            "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": self.uri, "text": self.text, "version": 1}},
        })
        out = self.server.handle({
            "jsonrpc": "2.0", "id": 5, "method": "textDocument/documentSymbol",
            "params": {"textDocument": {"uri": self.uri}},
        })
        names = {s["name"] for s in out[0]["result"]}
        self.assertIn("Account", names)
        self.assertIn("deposit", names)

    def test_unknown_method_returns_error(self):
        out = self.server.handle(
            {"jsonrpc": "2.0", "id": 9, "method": "textDocument/nope", "params": {}}
        )
        self.assertIn("error", out[0])


# ---------------------------------------------------------------------------
# CLI (in-process + subprocess)
# ---------------------------------------------------------------------------
class TestCLI(unittest.TestCase):
    def test_parser_has_all_commands(self):
        parser = build_parser()
        # Every documented command must be registered.
        for cmd in ("new", "check", "build", "run", "test", "fmt", "lint", "verify", "ai"):
            with self.subTest(cmd=cmd):
                self.assertIn(cmd, parser._subparsers._group_actions[0].choices)

    def test_check_ok(self):
        self.assertEqual(main(["check", BANKING]), 0)

    def test_check_reports_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.hpy")
            with open(path, "w") as fh:
                fh.write("module t\n\nfunction f(x: Int) -> Int {\n    return y\n}\n")
            self.assertEqual(main(["check", path]), 1)

    def test_build_writes_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.py")
            self.assertEqual(main(["build", DEMO, "-o", out]), 0)
            with open(out) as fh:
                compile(fh.read(), "<happy-generated>", "exec")

    def test_run(self):
        self.assertEqual(main(["run", DEMO]), 0)

    def test_fmt_check_and_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "b.hpy")
            with open(BANKING) as fh:
                text = fh.read()
            with open(path, "w") as fh:
                fh.write(text)
            self.assertEqual(main(["fmt", path]), 0)
            self.assertEqual(main(["fmt", path, "--check"]), 0)

    def test_lint(self):
        self.assertEqual(main(["lint", BANKING]), 0)

    def test_verify_approves_demo(self):
        self.assertEqual(main(["verify", VERIFIED]), 0)

    def test_ai_generate_mock(self):
        rc = main(["ai", "generate", "--prompt", "do a thing", "--goal", "do it",
                   "--provider", "mock"])
        self.assertEqual(rc, 0)

    def test_new_scaffold(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "proj")
            self.assertEqual(main(["new", "app", "--name", "demo_app", "--dir", target]), 0)
            self.assertTrue(os.path.isfile(os.path.join(target, "happy.toml")))

    def test_subprocess_entrypoint(self):
        proc = _cli("check", BANKING)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
