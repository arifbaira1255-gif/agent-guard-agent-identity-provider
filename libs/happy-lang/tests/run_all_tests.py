#!/usr/bin/env python3
"""Master test runner for the Happy language toolchain (Step 6).

Runs the *entire* pipeline's test suite and a set of end-to-end smoke checks,
then prints a single consolidated report.  This is what ``happy test`` invokes.

What it does
------------
1. **Unit / integration suites** — discovers and runs every ``tests/test_*.py``
   with pytest (falling back to ``unittest`` when pytest is unavailable).
2. **CLI smoke tests** — drives the real ``happy`` CLI as a subprocess for
   ``check`` / ``build`` / ``run`` / ``fmt`` / ``lint`` / ``verify`` / ``ai
   generate`` / ``new`` and asserts each exits cleanly.
3. **Package-manager round-trip** — scaffolds a project, resolves a dependency
   graph, writes and re-reads a lockfile.
4. **LSP round-trip** — initialises the server, opens a document, and checks
   diagnostics / completion / hover / definition.

Exit status is 0 only when every stage passes.

Usage::

    python tests/run_all_tests.py
    python tests/run_all_tests.py -v
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import traceback
from typing import Callable, List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

EXAMPLES = os.path.join(ROOT, "examples")
DEMO = os.path.join(EXAMPLES, "backend_demo.hpy")
BANKING = os.path.join(EXAMPLES, "banking.hpy")
VERIFIED = os.path.join(EXAMPLES, "verified_demo.hpy")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
class Report:
    def __init__(self) -> None:
        self.results: List[Tuple[str, bool, str]] = []

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.results.append((name, ok, detail))
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {name}"
        if detail:
            line += f" — {detail}"
        print(line)

    @property
    def ok(self) -> bool:
        return all(ok for _, ok, _ in self.results)

    def summary(self) -> str:
        passed = sum(1 for _, ok, _ in self.results if ok)
        total = len(self.results)
        return f"{passed}/{total} stages passed"


# ---------------------------------------------------------------------------
# Stage 1 — pytest
# ---------------------------------------------------------------------------
def run_pytest(verbose: bool) -> bool:
    """Run the unit suite with pytest, falling back to unittest if it is absent.

    ``pytest`` is preferred; where it is not installed the standard-library
    ``unittest`` discovery runs the very same tests so the Stage-1 result stays
    meaningful and the master run keeps its 11 stages either way.
    """
    tests_dir = os.path.join(ROOT, "tests")
    if _module_available("pytest"):
        cmd = [sys.executable, "-m", "pytest", tests_dir, "-q"]
        if verbose:
            cmd = [sys.executable, "-m", "pytest", tests_dir, "-v"]
        proc = subprocess.run(cmd, cwd=ROOT)
        return proc.returncode == 0
    print("pytest not installed; falling back to unittest discovery")
    cmd = [
        sys.executable, "-m", "unittest", "discover",
        "-s", tests_dir, "-t", ROOT,
    ]
    if verbose:
        cmd.append("-v")
    proc = subprocess.run(cmd, cwd=ROOT)
    return proc.returncode == 0


def _module_available(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Stage 2 — CLI smoke tests
# ---------------------------------------------------------------------------
def _cli(*args: str, cwd: str = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "happy.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def cli_smoke(report: Report) -> None:
    # check
    p = _cli("check", BANKING)
    report.add("cli: check", p.returncode == 0, p.stdout.strip().splitlines()[-1] if p.stdout else "")

    # build to a temp file
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "out.py")
        p = _cli("build", DEMO, "-o", out)
        ok = p.returncode == 0 and os.path.isfile(out)
        if ok:
            with open(out) as fh:
                compile(fh.read(), "<happy-generated>", "exec")
        report.add("cli: build", ok, p.stdout.strip() or p.stderr.strip())

    # run
    p = _cli("run", DEMO)
    report.add("cli: run", p.returncode == 0 and "total=150.0" in p.stdout)

    # fmt --check (banking is not canonical, so --check should fail; fmt then check)
    with tempfile.TemporaryDirectory() as tmp:
        copy = os.path.join(tmp, "banking.hpy")
        with open(BANKING) as fh:
            text = fh.read()
        with open(copy, "w") as fh:
            fh.write(text)
        p1 = _cli("fmt", copy)
        p2 = _cli("fmt", copy, "--check")
        report.add("cli: fmt", p1.returncode == 0 and p2.returncode == 0)

    # lint
    p = _cli("lint", BANKING)
    report.add("cli: lint", p.returncode == 0, p.stdout.strip().splitlines()[-1] if p.stdout else "")

    # verify
    p = _cli("verify", VERIFIED)
    report.add("cli: verify", p.returncode == 0 and "APPROVED" in p.stdout)

    # ai generate (offline mock provider)
    p = _cli("ai", "generate", "--prompt", "summarise a file", "--goal", "produce a summary",
             "--provider", "mock")
    report.add("cli: ai generate", p.returncode == 0 and "plan:" in p.stdout)

    # new (scaffold into a temp dir)
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "proj")
        p = _cli("new", "app", "--name", "demo_app", "--dir", target)
        ok = (
            p.returncode == 0
            and os.path.isfile(os.path.join(target, "happy.toml"))
            and os.path.isfile(os.path.join(target, "src", "main.hpy"))
        )
        if ok:
            # the scaffolded project must itself compile and run
            r = _cli("run", os.path.join(target, "src", "main.hpy"))
            ok = r.returncode == 0 and "Hello from demo_app" in r.stdout
        report.add("cli: new + run scaffold", ok, p.stdout.strip().splitlines()[0] if p.stdout else "")


# ---------------------------------------------------------------------------
# Stage 3 — package manager round-trip
# ---------------------------------------------------------------------------
def package_roundtrip(report: Report) -> None:
    from happy.package import (
        DependencyGraph,
        Lockfile,
        PackageManager,
        Registry,
        parse_lockfile,
        parse_manifest,
        render_lockfile,
        render_manifest,
    )

    # manifest round-trip
    text = (
        "[package]\n"
        'name = "demo"\n'
        'version = "1.2.3"\n'
        "\n"
        "[dependencies]\n"
        'http = "^1.0.0"\n'
        'json = "~2.1.0"\n'
    )
    manifest = parse_manifest(text)
    assert manifest.name == "demo"
    assert manifest.dependencies["http"].requirement == "^1.0.0"
    assert parse_manifest(render_manifest(manifest)).name == "demo"

    # resolution
    reg = Registry()
    reg.add("http", "1.0.0", {"tls": "^1.0.0"})
    reg.add("http", "1.4.2", {"tls": "^1.0.0"})
    reg.add("tls", "1.0.0")
    reg.add("json", "2.1.5")
    pm = PackageManager(registry=reg)
    lock = pm.resolve(manifest)
    assert lock.by_name("http").version == "1.4.2"
    assert lock.by_name("tls") is not None
    assert lock.by_name("json").version == "2.1.5"

    # lockfile round-trip
    assert parse_lockfile(render_lockfile(lock)).by_name("http").version == "1.4.2"

    # graph + topological order
    graph = pm.build_graph(manifest, lock)
    order = graph.topological_order()
    assert order.index("tls") < order.index("http")
    assert not graph.has_cycle()

    # cycle detection
    cyc = DependencyGraph()
    cyc.add_edge("a", "b")
    cyc.add_edge("b", "a")
    assert cyc.has_cycle()

    # project init
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "proj")
        m = pm.init_project(target, name="proj", template="lib")
        assert os.path.isfile(os.path.join(target, "happy.toml"))
        assert os.path.isfile(os.path.join(target, "happy.lock"))
        assert os.path.isfile(os.path.join(target, "src", "main.hpy"))
        assert pm.load_manifest(target).name == "proj"

    report.add("package: manifest/lock/graph/init round-trip", True)


# ---------------------------------------------------------------------------
# Stage 4 — LSP round-trip
# ---------------------------------------------------------------------------
def lsp_roundtrip(report: Report) -> None:
    from happy.tools.lsp import HappyLanguageServer

    server = HappyLanguageServer()
    init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init[0]["result"]["serverInfo"]["name"] == "happy-lsp"

    with open(BANKING) as fh:
        text = fh.read()
    uri = "file:///banking.hpy"
    server.handle({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {"textDocument": {"uri": uri, "text": text, "version": 1}},
    })

    diags = server.compute_diagnostics(text, uri)
    assert isinstance(diags, list)

    comp = server.handle({
        "jsonrpc": "2.0", "id": 2, "method": "textDocument/completion",
        "params": {"textDocument": {"uri": uri}, "position": {"line": 0, "character": 0}},
    })
    assert len(comp[0]["result"]["items"]) > 20

    # hover over the `deposit` function name (line 45, 1-based -> 44)
    lines = text.splitlines()
    target_line = next(i for i, ln in enumerate(lines) if "function deposit" in ln)
    col = lines[target_line].index("deposit") + 2
    hov = server.handle({
        "jsonrpc": "2.0", "id": 3, "method": "textDocument/hover",
        "params": {"textDocument": {"uri": uri}, "position": {"line": target_line, "character": col}},
    })
    assert hov[0]["result"] is not None
    assert "function deposit" in hov[0]["result"]["contents"]["value"]

    dfn = server.handle({
        "jsonrpc": "2.0", "id": 4, "method": "textDocument/definition",
        "params": {"textDocument": {"uri": uri}, "position": {"line": target_line, "character": col}},
    })
    assert dfn[0]["result"]["uri"] == uri

    syms = server.handle({
        "jsonrpc": "2.0", "id": 5, "method": "textDocument/documentSymbol",
        "params": {"textDocument": {"uri": uri}},
    })
    assert len(syms[0]["result"]) > 3

    report.add("lsp: initialize/diagnostics/completion/hover/definition/symbols", True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_all_tests", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--skip-pytest", action="store_true", help="only run the smoke stages")
    args = parser.parse_args(argv)

    print("=" * 68)
    print("Happy language toolchain — master test run")
    print("=" * 68)

    report = Report()

    if not args.skip_pytest:
        print("\n[1/4] Unit & integration suites (pytest)")
        ok = run_pytest(args.verbose)
        report.add("pytest: tests/", ok)

    print("\n[2/4] CLI smoke tests")
    try:
        cli_smoke(report)
    except Exception:  # noqa: BLE001
        report.add("cli: smoke", False, traceback.format_exc(limit=2))

    print("\n[3/4] Package manager round-trip")
    try:
        package_roundtrip(report)
    except Exception:  # noqa: BLE001
        report.add("package: round-trip", False, traceback.format_exc(limit=2))

    print("\n[4/4] LSP round-trip")
    try:
        lsp_roundtrip(report)
    except Exception:  # noqa: BLE001
        report.add("lsp: round-trip", False, traceback.format_exc(limit=2))

    print("\n" + "=" * 68)
    print(report.summary())
    print("=" * 68)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
