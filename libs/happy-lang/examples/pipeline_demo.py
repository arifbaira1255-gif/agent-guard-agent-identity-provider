"""End-to-end demonstration of the Happy compiler pipeline (Steps 1–3).

Runs the full front end over a ``.hpy`` source file::

    lex  ->  parse  ->  semantic  ->  IR lower
         ->  contracts  ->  permissions/capabilities  ->  effects

and prints a compact, human-readable report at every stage, followed by the
colourised diagnostics of any stage that found problems.

Usage::

    python examples/pipeline_demo.py examples/banking.hpy
    python examples/pipeline_demo.py examples/banking.hpy --ir     # dump IR nodes
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.compiler import __version__, analyze, parse  # noqa: E402
from happy.compiler.lexer import tokenize  # noqa: E402
from happy.compiler.ir import lower  # noqa: E402
from happy.compiler.contracts import ContractEngine  # noqa: E402
from happy.compiler.permissions import PermissionEngine  # noqa: E402
from happy.compiler.effects import EffectTracker  # noqa: E402


def _rule(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def run(path: str, dump_ir: bool = False) -> int:
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    filename = os.path.basename(path)
    errors = 0

    # -- Stage 1a: lexer ------------------------------------------------
    _rule(f"[1/7] LEXER — {filename}")
    tokens = tokenize(source, filename=filename)
    significant = [t for t in tokens if t.kind.name != "EOF"]
    print(f"  produced {len(tokens)} tokens "
          f"({len(significant)} significant + EOF)")
    kinds = {}
    for t in significant:
        kinds[t.kind.name] = kinds.get(t.kind.name, 0) + 1
    top = sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
    print("  top token kinds: " + ", ".join(f"{k}×{v}" for k, v in top))

    # -- Stage 1b: parser ----------------------------------------------
    _rule(f"[2/7] PARSER — {filename}")
    program = parse(source, filename=filename)
    print(f"  module: {program.module.name if program.module else '(none)'}")
    print(f"  imports: {len(program.imports)}  "
          f"declarations: {len(program.declarations)}")
    for d in program.declarations:
        print(f"    - {type(d).__name__:<16} {getattr(d, 'name', '')}")

    # -- Stage 2: semantic ---------------------------------------------
    _rule(f"[3/7] SEMANTIC ANALYSIS — {filename}")
    analysis = analyze(source, filename=filename)
    print(f"  {analysis.summary()}")
    print(f"  types:     {', '.join(sorted(analysis.types)) or '—'}")
    print(f"  functions: {', '.join(sorted(analysis.functions)) or '—'}")
    if analysis.errors:
        errors += len(analysis.errors)
        print(analysis.format())

    # -- Stage 3a: IR lowering -----------------------------------------
    _rule(f"[4/7] IR LOWERING — {filename}")
    module = lower(analysis)
    print(f"  IR root: {module.name}   version: {__version__}")
    print(f"  deterministic fingerprint: {module.fingerprint()[:16]}…")
    print(f"  nodes: {len(module.walk())}")
    print(f"  structs={len(module.types)} enums={len(module.enums)} "
          f"functions={len(module.functions)} rules={len(module.rules)} "
          f"permissions={len(module.permissions)} "
          f"capabilities={len(module.capabilities)} "
          f"agents={len(module.agents)} ai={len(module.ai_blocks)} "
          f"apps={len(module.apps)}")
    for fn in module.functions:
        print(f"    function {fn.name}"
              f"({', '.join(p.name for p in fn.params)}) -> "
              f"{fn.returns.display() if fn.returns else '?'}"
              f"  effects={[e.canonical for e in fn.declared_effects] or '∅'}")
    if dump_ir:
        print("  --- IR node dump ---")
        for node in module.walk():
            print(f"    {node.id:>5}  {node.kind_name():<14}"
                  f" {getattr(node, 'name', '')}")

    # -- Stage 3b: contracts -------------------------------------------
    _rule(f"[5/7] CONTRACT ENGINE — {filename}")
    creport = ContractEngine(source=source, filename=filename).analyze(module)
    print(f"  {creport.summary()}")
    for info in creport.infos:
        print(f"    - {info.summary()}")
    if creport.diagnostics:
        print()
        print(creport.format())
    errors += len(creport.errors)

    # -- Stage 3c: permissions / capabilities --------------------------
    _rule(f"[6/7] RULES, PERMISSIONS & CAPABILITIES — {filename}")
    preport = PermissionEngine(source=source, filename=filename).verify(module)
    print(f"  {preport.summary()}")
    for p in preport.permissions:
        print(f"    permission {p.name}: can={list(p.can)} "
              f"cannot={list(p.cannot)} holders={list(p.holders)}")
    for c in preport.capabilities:
        print(f"    capability {c.name}: grants={list(c.grants)} "
              f"holders={list(c.holders)}")
    for r in preport.rules:
        print(f"    rule {r.name}: known={r.is_known} arity_ok={r.arity_ok} "
              f"bool={r.predicate_is_bool}")
    for pt in preport.enforcement_points:
        mark = "OK" if pt.enforced else "UNCOVERED"
        print(f"    [{mark}] {pt.agent}.{pt.function} -> {pt.operation} "
              f"({pt.reason})")
    if preport.diagnostics:
        print()
        print(preport.format())
    errors += len(preport.errors)

    # -- Stage 3d: effects ---------------------------------------------
    _rule(f"[7/7] EFFECT TRACKER — {filename}")
    ereport = EffectTracker(source=source, filename=filename).analyze(module)
    print(f"  {ereport.summary()}")
    for fe in ereport.functions:
        print(f"    {fe.summary()}")
    if ereport.diagnostics:
        print()
        print(ereport.format())
    errors += len(ereport.errors)

    # -- Verdict --------------------------------------------------------
    _rule("PIPELINE RESULT")
    if errors == 0:
        print(f"  OK — the full pipeline processed '{filename}' "
              "with no errors.")
        return 0
    print(f"  FAILED — {errors} error(s) across the pipeline.")
    return 1


def main(argv) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    dump_ir = "--ir" in argv
    path = args[0] if args else "examples/banking.hpy"
    return run(path, dump_ir=dump_ir)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
