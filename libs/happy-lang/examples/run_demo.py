#!/usr/bin/env python3
"""Runnable demo for the Happy compiler frontend.

Usage::

    python examples/run_demo.py [path/to/script.hpy]

Parses a ``.hpy`` script and prints a structural summary of the resulting AST,
proving the lexer + parser handle the full language surface.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.compiler import ast, parse, tokenize  # noqa: E402
from happy.compiler.errors import HappyError  # noqa: E402


def summarize(program: ast.Program) -> str:
    lines = []
    if program.module:
        lines.append(f"module {program.module.name}")
    for imp in program.imports:
        if imp.symbols:
            lines.append(f"  import {{{', '.join(imp.symbols)}}} from \"{imp.name}\"")
        else:
            alias = f" as {imp.alias}" if imp.alias else ""
            lines.append(f"  import {imp.name}{alias}")

    lines.append("")
    lines.append(f"declarations: {len(program.declarations)}")
    for decl in program.declarations:
        kind = type(decl).__name__
        name = getattr(decl, "name", "?")
        detail = ""
        if isinstance(decl, ast.StructDecl):
            detail = f" ({len(decl.fields)} fields, {len(decl.invariants)} invariants)"
        elif isinstance(decl, ast.EnumDecl):
            detail = f" ({len(decl.variants)} variants)"
        elif isinstance(decl, ast.FunctionDecl):
            flags = "async " if decl.is_async else ""
            eff = f", effects={decl.effects.effects}" if decl.effects else ""
            detail = (f" ({flags}{len(decl.params)} params, "
                      f"{len(decl.contracts)} contracts{eff})")
        elif isinstance(decl, ast.AgentDecl):
            detail = (f" (goal={decl.goal is not None}, "
                      f"perms={decl.permissions}, caps={decl.capabilities})")
        elif isinstance(decl, ast.AiDecl):
            detail = f" (prompt={decl.prompt is not None})"
        elif isinstance(decl, ast.PermissionDecl):
            detail = f" (can={decl.can}, cannot={decl.cannot})"
        elif isinstance(decl, ast.CapabilityDecl):
            detail = f" (grants={decl.grants})"
        lines.append(f"  - {kind:<16} {name}{detail}")
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "banking.hpy")

    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()

    print("=" * 64)
    print(f"Happy compiler frontend demo — parsing {os.path.basename(path)}")
    print("=" * 64)

    try:
        tokens = tokenize(source, filename=path)
        print(f"\n[lexer]  produced {len(tokens)} tokens "
              f"({len(tokens) - 1} significant + EOF)")
        program = parse(source, filename=path)
    except HappyError as exc:
        print("\n" + exc.render(), file=sys.stderr)
        return 1

    print("\n[parser] AST summary:")
    print(summarize(program))
    print("\nOK — frontend parsed the script successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
