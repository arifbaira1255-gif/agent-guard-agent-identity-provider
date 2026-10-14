#!/usr/bin/env python3
"""Runnable demo for the Happy semantic analyzer (Step 2).

Usage::

    python examples/analyze_demo.py [path/to/script.hpy]

With no argument it analyzes ``examples/banking.hpy``.  It prints:

1. the token count and top-level declaration summary (front end reuse);
2. every semantic diagnostic, rendered with line/column/caret/help;
3. a short illustration of error diagnostics on a deliberately broken snippet.

Exit code is non-zero when the analyzed script contains **errors**.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.compiler import analyze, tokenize  # noqa: E402
from happy.compiler.errors import HappyError  # noqa: E402
from happy.compiler.semantic import Severity  # noqa: E402
from happy.compiler.lexer import TokenKind  # noqa: E402

DEFAULT_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "banking.hpy")

BROKEN_SNIPPET = """\
module demo.broken

type Account {
    id: Int
    balance: Float
}

function deposit(account: Account, amount: Float) -> Float {
    let new_balance = account.balance + amount
    account.balance = "oops"
    return new_balance
}

app Demo {
    let acct = Account { id: 1 }
    let x: Int = "not an int"
    deposit(acct)
}
"""


def declaration_summary(result) -> str:
    """Return a compact, human readable summary of the program's declarations."""
    program = result.program
    if program is None:
        return "(no program)"
    lines = []
    if result.module_name:
        lines.append(f"module {result.module_name}")
    for imp in program.imports:
        if imp.symbols:
            lines.append(f"  import {{{', '.join(imp.symbols)}}} from \"{imp.name}\"")
        else:
            alias = f" as {imp.alias}" if imp.alias else ""
            lines.append(f"  import {imp.name}{alias}")
    lines.append(f"\ndeclarations: {len(program.declarations)}")
    for decl in program.declarations:
        kind = type(decl).__name__
        name = getattr(decl, "name", "?")
        lines.append(f"  - {kind:<16} {name}")
    return "\n".join(lines)


def render_diagnostics(result) -> str:
    if not result.diagnostics:
        return "  (no diagnostics — program is clean)"
    return result.format()


def analyze_and_report(path: str) -> int:
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()

    print("=" * 70)
    print(f"Happy semantic analyzer — {path}")
    print("=" * 70)

    tokens = tokenize(source, filename=path)
    significant = [t for t in tokens if t.kind not in (TokenKind.EOF, TokenKind.NEWLINE)]
    print(f"[lexer]  {len(tokens)} tokens ({len(significant)} significant + EOF)")

    result = analyze(source, filename=path)
    print(f"[parser] declarations: {len(result.program.declarations)}")
    print()
    print(declaration_summary(result))
    print()
    print(f"[types]  registered: {', '.join(sorted(result.types)) or '(none)'}")
    print(f"[funcs]  registered: {', '.join(sorted(result.functions)) or '(none)'}")
    print()
    print(f"[semantic] {result.summary()}")
    print("-" * 70)
    print(render_diagnostics(result))
    print("-" * 70)
    print("OK — program passed semantic analysis." if result.ok else "FAILED — see errors above.")
    return 0 if result.ok else 1


def demo_error_diagnostics() -> None:
    print()
    print("=" * 70)
    print("Illustration: diagnostics on a deliberately broken snippet")
    print("=" * 70)
    result = analyze(BROKEN_SNIPPET, filename="broken.hpy")
    print(result.summary())
    print("-" * 70)
    print(result.format())
    print("-" * 70)


def main(argv):
    path = argv[1] if len(argv) > 1 else DEFAULT_SCRIPT
    try:
        code = analyze_and_report(path)
    except HappyError as exc:
        print(exc.render(), file=sys.stderr)
        return 2
    demo_error_diagnostics()
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
