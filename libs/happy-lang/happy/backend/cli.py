"""Command-line interface for the Happy Python backend.

Usage::

    python -m happy.backend compile demo.hpy            # print generated Python
    python -m happy.backend compile demo.hpy -o demo.py # write it to a file
    python -m happy.backend map demo.hpy                # print the source map
    python -m happy.backend run demo.hpy                # compile + execute
    python -m happy.backend ir demo.hpy                 # dump the IR summary

``run`` compiles the program, executes it under a
:class:`~happy.runtime.context.RuntimeContext` and prints the program output;
exit status is non-zero when a runtime error occurs, with the failure rendered
against the original ``.hpy`` source.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .python_gen import compile_source


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _cmd_compile(args: argparse.Namespace) -> int:
    source = _read(args.file)
    program = compile_source(source, filename=args.file)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(program.source)
        print(f"wrote {len(program.source.splitlines())} lines to {args.output}")
    else:
        sys.stdout.write(program.source)
    return 0


def _cmd_map(args: argparse.Namespace) -> int:
    source = _read(args.file)
    program = compile_source(source, filename=args.file)
    sys.stdout.write(program.sourcemap.to_json())
    return 0


def _cmd_ir(args: argparse.Namespace) -> int:
    from ..compiler import analyze, parse
    from ..compiler.ir import lower

    source = _read(args.file)
    module = lower(analyze(source, filename=args.file))
    print(f"module {module.name}")
    for t in module.types:
        print(f"  type {t.name}: {[f.name for f in t.fields]}")
    for e in module.enums:
        print(f"  enum {e.name}: {[v.name for v in e.variants]}")
    for f in module.functions:
        print(f"  fn {f.name} (async={f.is_async})")
    for a in module.agents:
        print(f"  agent {a.name}: {[fn.name for fn in a.functions]}")
    for app in module.apps:
        print(f"  app {app.name}")
    print(f"  fingerprint: {module.fingerprint()}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    from ..runtime import RuntimeContext

    source = _read(args.file)
    program = compile_source(source, filename=args.file)
    ctx = RuntimeContext(
        filename=args.file,
        source=source,
        module=program.module,
        sourcemap=program.sourcemap,
    )
    result = program.run(ctx)
    sys.stdout.write(result.output)
    if not result.ok and result.error is not None:
        sys.stderr.write("\n" + result.error.render() + "\n")
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="happy-backend", description="Happy language Python backend"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_compile = sub.add_parser("compile", help="emit Python for a .hpy file")
    p_compile.add_argument("file")
    p_compile.add_argument("-o", "--output", default=None)
    p_compile.set_defaults(func=_cmd_compile)

    p_map = sub.add_parser("map", help="print the source map as JSON")
    p_map.add_argument("file")
    p_map.set_defaults(func=_cmd_map)

    p_ir = sub.add_parser("ir", help="dump an IR summary")
    p_ir.add_argument("file")
    p_ir.set_defaults(func=_cmd_ir)

    p_run = sub.add_parser("run", help="compile and execute a .hpy file")
    p_run.add_argument("file")
    p_run.set_defaults(func=_cmd_run)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
