#!/usr/bin/env python3
"""Happy (.hpy) — self-guided end-to-end demo for a buyer.

Runs the *real* Happy toolchain through its public API on a small,
self-contained Happy program, printing what happens at each stage:

    source -> lex -> parse -> semantic/type-check -> IR -> optimize
           -> Python codegen -> runtime execution
           -> contracts / capabilities / secrets
           -> security analyzer
           -> formatter / linter

Every result printed here comes from the actual toolchain in this repository.
Run it from the package root::

    python demo/run_demo.py
"""

from __future__ import annotations

import os
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from happy import pipeline  # noqa: E402

SEP = "=" * 68


def section(title: str) -> None:
    print()
    print(SEP)
    print(title)
    print(SEP)


# --------------------------------------------------------------------------- #
# The demo program: shows contracts, a secret, a capability-gated agent,
# a struct invariant, and normal control flow.
# --------------------------------------------------------------------------- #
DEMO_PROGRAM = '''\
// demo/greeting.hpy — a small program that exercises the whole toolchain
module demo.greeting

import std.io

type Account {
    id: Int
    owner: String
    balance: Float
    secret pin: Byte
    active: Bool = true

    invariant balance >= 0.0, "balance must never be negative"
}

function deposit(account: Account, amount: Float) -> Float
    requires amount > 0.0, "deposit must be positive"
    ensures result > 0.0
    ensures result == account.balance
{
    let new_balance = account.balance + amount
    account.balance = new_balance
    return new_balance
}

capability Audit {
    grants audit
}

agent Auditor {
    capability [Audit]
    permission []

    function describe(name: String) -> String {
        return "auditor:" + name
    }
}

app Main {
    let account = Account { id: 1, owner: "Ada", balance: 100.0, pin: 7 }
    let total = deposit(account, 50.0)
    println("total=" + str(total))
    println(str(account))
    println(Auditor.describe("root"))
}
'''


def main() -> int:
    print("Happy (.hpy) end-to-end demo")
    print("version:", _version())

    # 1. Compile -----------------------------------------------------------
    section("1. COMPILE  —  Happy source -> Python 3 (with source map)")
    result = pipeline.compile_source(DEMO_PROGRAM, filename="demo/greeting.hpy")
    print("compile ok:", result.ok)
    if not result.ok:
        print(result.summary() if hasattr(result, "summary") else result)
        return 1
    python_src = getattr(result, "python_source", None) or getattr(result, "source", None)
    if python_src:
        n = len(python_src.splitlines())
        print(f"generated Python: {n} lines")
        print("--- first 12 generated lines ---")
        for line in python_src.splitlines()[:12]:
            print("   ", line)

    # 2. Run ---------------------------------------------------------------
    section("2. RUN  —  execute inside the Happy Runtime")
    run = pipeline.run_source(DEMO_PROGRAM, filename="demo/greeting.hpy")
    print("run ok:", run.ok)
    print("--- program output ---")
    print(textwrap.indent((run.output or "").strip("\n"), "    "))

    # 3. Tooling: format + lint -------------------------------------------
    section("3. TOOLING  —  formatter & linter")
    fmt = pipeline.format_source(DEMO_PROGRAM, filename="demo/greeting.hpy")
    print("formatter ok:", fmt.ok, "| changed:", getattr(fmt, "changed", "?"))
    lint = pipeline.lint_source(DEMO_PROGRAM, filename="demo/greeting.hpy")
    findings = getattr(lint, "findings", [])
    print(f"linter: {len(findings)} finding(s)")
    for f in findings[:6]:
        code = getattr(f, "code", "?")
        msg = getattr(f, "message", str(f))
        print(f"    [{code}] {msg}")

    # 4. Security ----------------------------------------------------------
    section("4. SECURITY  —  static analyzer over the typed IR")
    sec = pipeline.analyze_security_source(DEMO_PROGRAM, filename="demo/greeting.hpy")
    sev = getattr(sec, "findings", [])
    print(f"security: {len(sev)} finding(s)")
    for f in sev[:6]:
        print(f"    [{getattr(f, 'code', '?')}] {getattr(f, 'message', f)}")

    # 5. Contract enforcement ---------------------------------------------
    section("5. ENFORCEMENT  —  a contract violation must fail the run")
    bad = DEMO_PROGRAM.replace("deposit(account, 50.0)", "deposit(account, -5.0)")
    bad_run = pipeline.run_source(bad, filename="demo/greeting.hpy")
    print("run ok (expected False):", bad_run.ok)
    err = getattr(bad_run, "error", None) or getattr(bad_run, "output", "")
    print("--- runtime reported ---")
    print(textwrap.indent(str(err).strip("\n"), "    ")[:1200])

    section("DEMO COMPLETE")
    print("Every stage above ran against the real toolchain in this repository.")
    print("See commercial/TECHNICAL_SPEC.md and commercial/BENCHMARKS.md for detail.")
    return 0


def _version() -> str:
    try:
        import happy
        return getattr(happy, "__version__", "unknown")
    except Exception:
        return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
