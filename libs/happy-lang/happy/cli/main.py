"""The Happy command-line interface (Step 6).

``happy`` is the single entry point to the whole toolchain.  Every command is a
thin, well-behaved wrapper over a library function — the CLI never re-implements
compiler logic, it only drives it and formats the result for a terminal.

Commands
--------
======================  =====================================================
``happy new <template>``  scaffold a project (``app`` / ``lib`` / ``agent``)
``happy check <file>``    parse + semantic analysis; print diagnostics
``happy build <file>``    compile to Python 3 (``-o`` to write a file)
``happy run <file>``      compile and execute under the Happy Runtime
``happy test``            run the project's test suite
``happy fmt <file>``      format source (``--check`` for CI, ``--stdout``)
``happy lint <file>``     static lint; non-zero exit on error findings
``happy verify <file>``   run the AI trust-ladder verification pipeline
``happy ai generate``     generate a structured plan from an ``ai`` declaration
======================  =====================================================

Usage::

    python -m happy.cli check examples/banking.hpy
    python -m happy.cli run   examples/backend_demo.hpy
    python -m happy.cli fmt   examples/banking.hpy --check
    python -m happy.cli lint  examples/banking.hpy
    python -m happy.cli verify examples/backend_demo.hpy
    python -m happy.cli ai generate --prompt "summarise a file" --goal "produce a summary"
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import List, Optional

__all__ = ["main", "build_parser"]

#: Exit codes.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _project_root() -> str:
    """Return the Happy project root (the directory containing ``happy/``)."""
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


# ---------------------------------------------------------------------------
# happy new
# ---------------------------------------------------------------------------
def _cmd_new(args: argparse.Namespace) -> int:
    from ..package import PackageManager, PackageError

    pm = PackageManager()
    directory = args.directory or args.name or args.template
    try:
        manifest = pm.init_project(
            directory,
            name=args.name,
            template=args.template,
            description=args.description or "",
        )
    except PackageError as exc:
        _eprint(f"error: {exc}")
        return EXIT_ERROR
    print(f"created {args.template} project '{manifest.name}' in {directory}/")
    print(f"  {directory}/happy.toml")
    print(f"  {directory}/happy.lock")
    print(f"  {directory}/src/main.hpy")
    print(f"  {directory}/tests/test_main.hpy")
    print(f"\nnext:  happy run {directory}/src/main.hpy")
    return EXIT_OK


# ---------------------------------------------------------------------------
# happy check
# ---------------------------------------------------------------------------
def _cmd_check(args: argparse.Namespace) -> int:
    from ..compiler import SemanticOptions, analyze, parse
    from ..compiler.errors import HappyError

    source = _read(args.file)
    try:
        program = parse(source, filename=args.file)
    except HappyError as exc:
        _eprint(exc.render())
        return EXIT_ERROR

    from ..compiler.semantic import Severity

    result = analyze(
        program,
        filename=args.file,
        options=SemanticOptions(
            semantic_security_strict=True,
            contract_proof_severity=(
                Severity.ERROR if getattr(args, "deny_violations", False) else Severity.WARNING
            ),
        ),
    )
    if result.diagnostics:
        print(result.format())
    print(result.summary())
    if getattr(args, "prove", False):
        proofs = result.contract_proofs
        if proofs is None:
            print("contracts: not analysed (fix the errors above first)")
        else:
            print(
                f"contracts: {proofs.proved} proved, {proofs.violated} violated, "
                f"{proofs.unknown} left to run-time checks"
            )
    return EXIT_OK if result.ok else EXIT_ERROR


# ---------------------------------------------------------------------------
# happy build
# ---------------------------------------------------------------------------
def _cmd_build(args: argparse.Namespace) -> int:
    from ..pipeline import compile_source

    source = _read(args.file)
    result = compile_source(source, filename=args.file)
    if not result.ok:
        for diag in result.diagnostics:
            _eprint(diag)
        return EXIT_ERROR
    program = result.program

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(program.source)
        print(
            f"built {args.file} -> {args.output} "
            f"({len(program.source.splitlines())} lines, "
            f"{len(program.sourcemap.entries)} source-map anchors)"
        )
    else:
        sys.stdout.write(program.source)
    return EXIT_OK


# ---------------------------------------------------------------------------
# happy run
# ---------------------------------------------------------------------------
def _cmd_run(args: argparse.Namespace) -> int:
    from ..pipeline import run_source

    source = _read(args.file)
    outcome = run_source(source, filename=args.file)
    if outcome.output:
        sys.stdout.write(outcome.output)
    if not outcome.ok:
        compile_ = getattr(outcome, "compile", None)
        if compile_ is not None and not compile_.ok and compile_.diagnostics:
            for diag in compile_.diagnostics:
                _eprint(diag)
        elif outcome.error:
            _eprint("\n" + str(outcome.error))
        return EXIT_ERROR
    return EXIT_OK


# ---------------------------------------------------------------------------
# happy test
# ---------------------------------------------------------------------------
def _cmd_test(args: argparse.Namespace) -> int:
    root = _project_root()
    runner = os.path.join(root, "tests", "run_all_tests.py")
    if os.path.isfile(runner):
        cmd = [sys.executable, runner]
    else:
        cmd = [sys.executable, "-m", "pytest", os.path.join(root, "tests"), "-q"]
    if args.verbose:
        cmd.append("-v")
    proc = subprocess.run(cmd, cwd=root)
    return proc.returncode


# ---------------------------------------------------------------------------
# happy fmt
# ---------------------------------------------------------------------------
def _cmd_fmt(args: argparse.Namespace) -> int:
    from ..tools.fmt import format_source

    if getattr(args, "recursive", False):
        return _fmt_recursive(args)

    source = _read(args.file)
    result = format_source(source, filename=args.file)
    if not result.ok:
        _eprint(result.error.render())
        return EXIT_ERROR

    if result.unformattable:
        # Never overwrite a file with lossy output.
        _eprint(result.diff_summary())
        return EXIT_ERROR

    if args.check:
        if result.changed:
            _eprint(f"{args.file}: not formatted (run 'happy fmt {args.file}')")
            return EXIT_ERROR
        print(f"{args.file}: already formatted")
        return EXIT_OK

    if args.stdout:
        sys.stdout.write(result.formatted)
        return EXIT_OK

    if result.changed:
        with open(args.file, "w", encoding="utf-8") as fh:
            fh.write(result.formatted)
        print(result.diff_summary())
    else:
        print(f"{args.file}: already formatted")
    return EXIT_OK


def _fmt_recursive(args: argparse.Namespace) -> int:
    """Format every ``.hpy`` file under a directory tree."""
    from ..tools.fmt import format_source

    root = args.file
    if not os.path.isdir(root):
        _eprint(f"error: {root} is not a directory")
        return EXIT_USAGE
    changed = 0
    checked = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__"}]
        for fn in sorted(filenames):
            if not fn.endswith(".hpy"):
                continue
            path = os.path.join(dirpath, fn)
            result = format_source(_read(path), filename=path)
            checked += 1
            if not result.ok:
                _eprint(f"{path}: {result.error.render()}")
                continue
            if result.unformattable:
                _eprint(result.diff_summary())
                continue
            if result.changed:
                changed += 1
                if args.check:
                    _eprint(f"{path}: not formatted")
                else:
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(result.formatted)
    verb = "would reformat" if args.check else "reformatted"
    print(f"{verb} {changed} of {checked} file(s)")
    if args.check and changed:
        return EXIT_ERROR
    return EXIT_OK


# ---------------------------------------------------------------------------
# happy lint
# ---------------------------------------------------------------------------
def _cmd_lint(args: argparse.Namespace) -> int:
    from ..tools.lint import lint_source

    source = _read(args.file)
    report = lint_source(source, filename=args.file, strict=args.strict)
    if report.parse_error is not None:
        _eprint(report.parse_error.render())
        return EXIT_ERROR
    if report.findings:
        print(report.format())
    print(report.summary())
    return EXIT_OK if report.ok else EXIT_ERROR


# ---------------------------------------------------------------------------
# happy verify
# ---------------------------------------------------------------------------
def _cmd_verify(args: argparse.Namespace) -> int:
    from ..ai.verifier import VerificationPipeline
    from ..security.analyzer import SecurityAnalyzer

    source = _read(args.file)
    pipeline = VerificationPipeline(
        run_tests=not args.no_tests,
        security=SecurityAnalyzer(),
    )
    result = pipeline.verify(source, filename=args.file)
    print(result.report())
    if args.json:
        print(json.dumps(
            {
                "state": result.state,
                "approved": result.approved,
                "gates": [
                    {"name": g.name, "state": g.state, "passed": g.passed}
                    for g in result.gates
                ],
            },
            indent=2,
        ))
    return EXIT_OK if result.approved else EXIT_ERROR


# ---------------------------------------------------------------------------
# happy ai generate
# ---------------------------------------------------------------------------
def _cmd_ai_generate(args: argparse.Namespace) -> int:
    from ..ai.agent import AgentSandbox, PlanGenerator
    from ..ai.providers import AIProviderError

    prompt = args.prompt or ""
    goal = args.goal or ""
    source_name = None

    if args.file:
        from ..compiler import analyze, parse
        from ..compiler.ir import lower

        text = _read(args.file)
        module = lower(analyze(parse(text, filename=args.file), filename=args.file))
        if not module.ai_blocks:
            _eprint(f"error: {args.file} declares no 'ai' block")
            return EXIT_ERROR
        block = module.ai_blocks[0]
        source_name = block.name
        prompt = prompt or _expr_text(block.prompt)
        goal = goal or _expr_text(block.goal)

    if not prompt and not goal:
        _eprint("error: provide --prompt/--goal or --file with an 'ai' block")
        return EXIT_USAGE

    sandbox = None
    if args.sandbox:
        sandbox = AgentSandbox(
            read_paths=args.read or ["**"],
            write_paths=args.write or [],
            allow_network=args.allow_network,
        )

    # Offline-by-default: connecting to a *live* model requires an explicit
    # --provider NAME or --live.  With neither flag the deterministic mock
    # provider is used, so `happy ai generate` never silently makes a network
    # call just because a vendor API key happens to be present.  This mirrors
    # the runtime's `ai_offline=True` default.
    if args.provider is not None:
        provider: Any = args.provider
    elif getattr(args, "live", False):
        from ..ai.providers import provider_from_env

        provider = provider_from_env()
    else:
        provider = "mock"

    try:
        generator = PlanGenerator(provider=provider, model=args.model)
        plan = generator.generate(prompt=prompt, goal=goal, source=source_name, sandbox=sandbox)
    except AIProviderError as exc:
        _eprint(f"error: {exc}")
        return EXIT_ERROR

    if args.json:
        print(json.dumps(plan.to_dict(), indent=2))
    else:
        print(f"plan: {plan.goal or goal or '(no goal)'}")
        for step in plan.steps:
            dep = f"  (after {', '.join(step.depends_on)})" if step.depends_on else ""
            print(f"  [{step.id}] {step.kind}: {step.description}{dep}")
        if getattr(plan, "mocked", False):
            print("(plan generated offline by the mock provider)")
    return EXIT_OK


def _expr_text(expr: object) -> str:
    """Best-effort text of an IR expression (for prompts/goals)."""
    if expr is None:
        return ""
    value = getattr(expr, "value", None)
    if isinstance(value, str):
        return value
    name = getattr(expr, "name", None)
    if isinstance(name, str):
        return name
    return ""


# ---------------------------------------------------------------------------
# happy debug
# ---------------------------------------------------------------------------
def _cmd_debug(args: argparse.Namespace) -> int:
    from ..backend import compile_source
    from ..compiler.errors import HappyError
    from ..tools.debugger import Debugger, trace

    source = _read(args.file)
    try:
        program = compile_source(source, filename=args.file, strict=True)
    except HappyError as exc:
        _eprint(getattr(exc, 'rendered', None) or exc.render())
        return EXIT_ERROR

    if args.trace:
        tracer = trace(program)
        for frame in tracer.frames:
            print(frame.render(args.file))
        return EXIT_OK

    debugger = Debugger(program)
    for line in args.breakpoint or []:
        debugger.set_breakpoint(int(line))
    if not debugger.breakpoints:
        _eprint("error: no breakpoints set (use -b <line>)")
        return EXIT_USAGE

    def _on_stop(frame, locals_):
        print(f"stopped at {frame.render(args.file)}")
        for key, value in sorted(locals_.items()):
            if key.startswith("__"):
                continue
            print(f"  {key} = {value!r}")

    debugger.on_stop = _on_stop
    try:
        debugger.run()
    except Exception as exc:  # noqa: BLE001 - report, don't crash
        _eprint(f"program error: {exc}")
        return EXIT_ERROR
    print(f"{len(debugger.stops)} breakpoint hit(s)")
    return EXIT_OK


# ---------------------------------------------------------------------------
# happy doc
# ---------------------------------------------------------------------------
def _cmd_doc(args: argparse.Namespace) -> int:
    from ..tools.docgen import generate_docs

    source = _read(args.file)
    markdown = generate_docs(source, filename=args.file)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        print(f"wrote documentation to {args.output}")
    else:
        sys.stdout.write(markdown)
    return EXIT_OK


# ---------------------------------------------------------------------------
# happy repl
# ---------------------------------------------------------------------------
def _cmd_repl(args: argparse.Namespace) -> int:
    from ..tools.repl import run_repl

    return run_repl()


# ---------------------------------------------------------------------------
# happy publish
# ---------------------------------------------------------------------------
def _cmd_publish(args: argparse.Namespace) -> int:
    from ..tools.publish import create_package, install_package

    if args.install:
        try:
            info = install_package(args.install, args.dest)
        except (ValueError, OSError) as exc:
            _eprint(f"error: cannot install {args.install}: {exc}")
            return EXIT_ERROR
        print(f"installed {info.name} {info.version} -> {info.path}")
        return EXIT_OK

    info = create_package(
        root=args.directory, output=args.output, name=args.name, version=args.version
    )
    print(f"packaged {info.name} {info.version} -> {info.path}")
    print(f"  {len(info.files)} source file(s), entry {info.entry}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# happy add
# ---------------------------------------------------------------------------
def _cmd_add(args: argparse.Namespace) -> int:
    from ..package import PackageManager, PackageError
    from ..tools.publish import read_manifest
    from ..package.manager import render_manifest, MANIFEST_NAME

    manifest = read_manifest(args.directory)
    if manifest is None:
        _eprint(f"error: no happy.toml in {args.directory}")
        return EXIT_ERROR
    pm = PackageManager()
    pm.add_dependency(
        manifest, args.package, requirement=args.version or "*", dev=args.dev
    )
    path = os.path.join(args.directory, MANIFEST_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_manifest(manifest))
    kind = "dev-dependency" if args.dev else "dependency"
    print(f"added {kind} {args.package} to {path}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# happy lsp
# ---------------------------------------------------------------------------
def _cmd_lsp(args: argparse.Namespace) -> int:
    from ..tools.lsp import serve_stdio

    if args.stdio:
        return serve_stdio()
    _eprint("error: specify --stdio (only stdio transport is supported)")
    return EXIT_USAGE


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="happy",
        description="The Happy language (.hpy) toolchain — compiler, runtime, "
        "formatter, linter, package manager and AI layer.",
    )
    parser.add_argument("--version", action="version", version="happy 1.0.0")
    parser.set_defaults(func=None)
    sub = parser.add_subparsers(dest="command", required=True)

    # new
    p_new = sub.add_parser("new", help="scaffold a new project")
    p_new.add_argument("template", choices=["app", "lib", "agent"], help="project template")
    p_new.add_argument("--name", default=None, help="package name")
    p_new.add_argument("--dir", dest="directory", default=None, help="target directory")
    p_new.add_argument("--description", default=None)
    p_new.set_defaults(func=_cmd_new)

    # check
    p_check = sub.add_parser("check", help="parse and type-check a .hpy file")
    p_check.add_argument("file")
    p_check.add_argument(
        "--prove", action="store_true",
        help="report how many contracts were proved / violated statically",
    )
    p_check.add_argument(
        "--deny-violations", action="store_true",
        help="treat contracts that are provably violated as compile errors",
    )
    p_check.set_defaults(func=_cmd_check)

    # build
    p_build = sub.add_parser("build", help="compile a .hpy file to Python 3")
    p_build.add_argument("file")
    p_build.add_argument("-o", "--output", default=None, help="write generated Python here")
    p_build.set_defaults(func=_cmd_build)

    # run
    p_run = sub.add_parser("run", help="compile and execute a .hpy file")
    p_run.add_argument("file")
    p_run.set_defaults(func=_cmd_run)

    # test
    p_test = sub.add_parser("test", help="run the project test suite")
    p_test.add_argument("-v", "--verbose", action="store_true")
    p_test.set_defaults(func=_cmd_test)

    # fmt
    p_fmt = sub.add_parser("fmt", help="format a .hpy file")
    p_fmt.add_argument("file")
    p_fmt.add_argument("--check", action="store_true", help="exit non-zero if not formatted")
    p_fmt.add_argument("--stdout", action="store_true", help="print instead of writing")
    p_fmt.add_argument("-r", "--recursive", action="store_true", help="format a whole directory tree")
    p_fmt.set_defaults(func=_cmd_fmt)

    # lint
    p_lint = sub.add_parser("lint", help="lint a .hpy file")
    p_lint.add_argument("file")
    p_lint.add_argument("--strict", action="store_true", help="promote naming warnings to errors")
    p_lint.set_defaults(func=_cmd_lint)

    # verify
    p_verify = sub.add_parser("verify", help="run the AI trust-ladder verification pipeline")
    p_verify.add_argument("file")
    p_verify.add_argument("--no-tests", action="store_true", help="skip the TESTED gate")
    p_verify.add_argument("--json", action="store_true")
    p_verify.set_defaults(func=_cmd_verify)

    # ai
    p_ai = sub.add_parser("ai", help="AI-native commands")
    ai_sub = p_ai.add_subparsers(dest="ai_command", required=True)
    p_gen = ai_sub.add_parser("generate", help="generate a structured plan")
    p_gen.add_argument("--prompt", default=None)
    p_gen.add_argument("--goal", default=None)
    p_gen.add_argument("--file", default=None, help="a .hpy file with an 'ai' block")
    p_gen.add_argument("--provider", default=None, help="openai | claude | gemini | local | mock")
    p_gen.add_argument("--live", action="store_true",
                       help="opt in to a live model: auto-detect the provider from environment API keys "
                            "(default is the deterministic offline mock provider, which never makes a network call)")
    p_gen.add_argument("--model", default=None)
    p_gen.add_argument("--json", action="store_true")
    p_gen.add_argument("--sandbox", action="store_true", help="constrain the plan with a sandbox")
    p_gen.add_argument("--read", action="append", default=None, help="allowed read glob (repeatable)")
    p_gen.add_argument("--write", action="append", default=None, help="allowed write glob (repeatable)")
    p_gen.add_argument("--allow-network", action="store_true")
    p_gen.set_defaults(func=_cmd_ai_generate)

    # debug
    p_debug = sub.add_parser("debug", help="trace or step a .hpy program")
    p_debug.add_argument("file")
    p_debug.add_argument("--trace", action="store_true", help="print the Happy execution trace")
    p_debug.add_argument("-b", "--breakpoint", action="append", default=None, help="breakpoint line (repeatable)")
    p_debug.set_defaults(func=_cmd_debug)

    # doc
    p_doc = sub.add_parser("doc", help="generate Markdown docs for a .hpy file")
    p_doc.add_argument("file")
    p_doc.add_argument("-o", "--output", default=None)
    p_doc.set_defaults(func=_cmd_doc)

    # repl
    p_repl = sub.add_parser("repl", help="start an interactive Happy session")
    p_repl.set_defaults(func=_cmd_repl)

    # publish
    p_pub = sub.add_parser("publish", help="package a project into a .hpyz archive")
    p_pub.add_argument("directory", nargs="?", default=".")
    p_pub.add_argument("-o", "--output", default=None)
    p_pub.add_argument("--name", default=None)
    p_pub.add_argument("--version", default=None)
    p_pub.add_argument("--install", default=None, help="install a .hpyz archive")
    p_pub.add_argument("--dest", default="installed", help="install destination")
    p_pub.set_defaults(func=_cmd_publish)

    # add
    p_add = sub.add_parser("add", help="add a dependency to happy.toml")
    p_add.add_argument("package")
    p_add.add_argument("--version", default=None)
    p_add.add_argument("--dir", dest="directory", default=".")
    p_add.add_argument("--dev", action="store_true")
    p_add.set_defaults(func=_cmd_add)

    # lsp
    p_lsp = sub.add_parser("lsp", help="start the Happy language server")
    p_lsp.add_argument("--stdio", action="store_true", help="use the stdio transport")
    p_lsp.set_defaults(func=_cmd_lsp)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    # Make stdout/stderr UTF-8 so programs that print non-ASCII (emoji, Hindi,
    # ...) never crash with UnicodeEncodeError on a C-locale terminal.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover - detached stream
                pass
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
