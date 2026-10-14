"""The single, coherent Happy toolchain entry point (final integration).

Every subsystem — front end, type system, IR, optimizer, backend, runtime,
security model, AI layer and developer tooling — is reachable through the rest
of the package.  This module wires them together behind one small, stable API
so that *no stage is disconnected or merely simulated*: each public function
runs the real compiler, the real security analyzer and the real runtime, in
order, and reports exactly what happened.

The canonical pipeline is::

    source
      -> lex / parse            (happy.compiler)
      -> semantic analysis      (types, traits, contracts, capabilities,
                                 permissions, effects)
      -> IR lowering            (happy.compiler.ir)
      -> optimization           (happy.compiler.optimizer)
      -> Python code generation (happy.backend)
      -> execution              (happy.runtime, with the security model
                                 enforced at run time)

Public API::

    from happy import pipeline

    result = pipeline.compile_source(src, filename="demo.hpy")
    if result.ok:
        run = pipeline.run_source(src, filename="demo.hpy")
        print(run.output)

    # One call across compile + lint + security analysis:
    check = pipeline.check_source(src, filename="demo.hpy")
    print(check.summary())

The module is import-light: backend, runtime and tooling are imported lazily
inside the functions that need them so that ``import happy.pipeline`` never
pulls in the whole toolchain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional

from .compiler import SemanticOptions, analyze, lower
from .compiler.optimizer import optimize as _optimize_ir

__all__ = [
    "CompileResult",
    "RunOutcome",
    "CheckReport",
    "compile_source",
    "compile_file",
    "run_source",
    "run_file",
    "check_source",
    "check_file",
    "format_source",
    "lint_source",
    "analyze_security_source",
]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass
class CompileResult:
    """The outcome of compiling one Happy source through the whole pipeline."""

    ok: bool
    program: Any = None            # happy.backend.GeneratedProgram (when ok)
    module: Any = None             # the typed + optimized IRModule
    analysis: Any = None           # happy.compiler.AnalysisResult
    diagnostics: List[str] = field(default_factory=list)
    filename: Optional[str] = None

    @property
    def python_source(self) -> Optional[str]:
        """The generated Python 3 source, when compilation succeeded."""
        return getattr(self.program, "source", None)

    def summary(self) -> str:
        if self.ok:
            return f"compile: ok ({self.filename or '<memory>'})"
        head = f"compile: failed ({self.filename or '<memory>'})"
        return head + ("\n" + "\n".join(self.diagnostics) if self.diagnostics else "")


@dataclass
class RunOutcome:
    """The outcome of compiling *and* executing one Happy source."""

    ok: bool
    output: str = ""
    result: Any = None             # happy.runtime RunResult (when ok)
    compile: Optional[CompileResult] = None
    error: Optional[str] = None
    filename: Optional[str] = None

    def summary(self) -> str:
        if self.ok:
            return f"run: ok ({self.filename or '<memory>'})"
        return f"run: failed ({self.filename or '<memory>'}): {self.error or 'unknown error'}"


@dataclass
class CheckReport:
    """Aggregate of compile + lint + security analysis for one source."""

    ok: bool
    compile: Optional[CompileResult] = None
    lint: Any = None               # happy.tools.lint.LintReport
    security: Any = None           # happy.security.SecurityReport
    filename: Optional[str] = None

    def summary(self) -> str:
        parts: List[str] = []
        parts.append("compile: " + ("ok" if (self.compile and self.compile.ok) else "FAILED"))
        if self.lint is not None:
            errors = len(self.lint.errors)
            warnings = len(self.lint.warnings)
            parts.append(f"lint: {errors} error(s), {warnings} warning(s)")
        if self.security is not None:
            parts.append(f"security: {len(self.security.findings)} finding(s)")
        status = "ok" if self.ok else "ISSUES FOUND"
        return f"check: {status} ({self.filename or '<memory>'}) -> " + ", ".join(parts)


# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------
def compile_source(
    source: str,
    filename: Optional[str] = None,
    optimize: bool = True,
) -> CompileResult:
    """Compile Happy ``source`` through the full pipeline to a generated program.

    Runs lex/parse, semantic analysis (types + traits + contracts +
    capabilities + permissions + effects), IR lowering, optimization and the
    Python backend.  Returns a :class:`CompileResult`; on failure ``ok`` is
    ``False`` and ``diagnostics`` carries the compiler's rendered errors.
    """
    from .backend import generate
    from .compiler.errors import HappyError

    try:
        analysis = analyze(
            source, filename=filename,
            options=SemanticOptions(semantic_security_strict=True),
        )
    except HappyError as err:
        # Lexer / parser failures raise; render them as diagnostics instead of
        # propagating, so callers get a uniform CompileResult.
        rendered = err.render() if hasattr(err, "render") else str(err)
        return CompileResult(ok=False, diagnostics=[rendered], filename=filename)
    except RecursionError:
        # Defence in depth: a pathologically nested program must produce a
        # clean diagnostic, never a raw traceback.
        return CompileResult(
            ok=False,
            diagnostics=[
                f"{filename or '<source>'}: error: program is too deeply "
                "nested to compile; simplify the expression"
            ],
            filename=filename,
        )
    if not analysis.ok:
        return CompileResult(
            ok=False,
            analysis=analysis,
            diagnostics=[analysis.format()] if hasattr(analysis, "format") else ["analysis failed"],
            filename=filename,
        )
    module = lower(analysis)
    if optimize:
        _optimize_ir(module)
    program = generate(module, source=source, filename=filename)
    return CompileResult(
        ok=True,
        program=program,
        module=module,
        analysis=analysis,
        filename=filename,
    )


def compile_file(path: str, optimize: bool = True) -> CompileResult:
    """Compile a ``.hpy`` file from disk through the full pipeline."""
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    return compile_source(source, filename=path, optimize=optimize)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
def run_source(
    source: str,
    filename: Optional[str] = None,
    optimize: bool = True,
    entry: str = "main",
    ai_provider: Any = None,
    ai_offline: bool = True,
) -> RunOutcome:
    """Compile and execute Happy ``source`` under the runtime security model.

    The program runs inside a :class:`happy.runtime.RuntimeContext`, so
    contracts, capabilities, permissions and secret protection are all enforced
    at run time.  Output written by the program is captured and returned.
    """
    from .runtime import RuntimeContext

    compiled = compile_source(source, filename=filename, optimize=optimize)
    if not compiled.ok:
        return RunOutcome(
            ok=False,
            compile=compiled,
            error="compilation failed",
            filename=filename,
        )
    ctx = RuntimeContext(
        filename=filename,
        source=source,
        module=compiled.module,
        sourcemap=compiled.program.sourcemap,
        ai_provider=ai_provider,
        ai_offline=ai_offline,
    )
    try:
        result = compiled.program.run(ctx, entry=entry)
    except Exception as exc:  # noqa: BLE001 - surface any runtime/contract error
        return RunOutcome(
            ok=False,
            compile=compiled,
            error=str(exc),
            filename=filename,
        )
    # RuntimeContext.run never raises for a handled runtime/contract error: it
    # returns a RunResult whose ``ok`` flag and ``output`` are authoritative.
    if not getattr(result, "ok", False):
        err = getattr(result, "error", None)
        return RunOutcome(
            ok=False,
            output=getattr(result, "output", ""),
            result=result,
            compile=compiled,
            error=str(err) if err is not None else "runtime error",
            filename=filename,
        )
    return RunOutcome(
        ok=True,
        output=getattr(result, "output", ""),
        result=result,
        compile=compiled,
        filename=filename,
    )


def run_file(
    path: str,
    optimize: bool = True,
    entry: str = "main",
    ai_provider: Any = None,
    ai_offline: bool = True,
) -> RunOutcome:
    """Compile and execute a ``.hpy`` file from disk."""
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    return run_source(
        source,
        filename=path,
        optimize=optimize,
        entry=entry,
        ai_provider=ai_provider,
        ai_offline=ai_offline,
    )


# ---------------------------------------------------------------------------
# Combined static check (compile + lint + security)
# ---------------------------------------------------------------------------
def check_source(
    source: str,
    filename: Optional[str] = None,
    optimize: bool = True,
    strict_security: bool = True,
) -> CheckReport:
    """Run compile + lint + security analysis over one source in a single call."""
    from .tools.lint import lint_source as _lint
    from .security import analyze_security

    compiled = compile_source(source, filename=filename, optimize=optimize)
    lint = _lint(source, filename=filename)
    security = analyze_security(source, filename=filename, strict=strict_security)
    ok = compiled.ok and lint.ok and security.ok
    return CheckReport(
        ok=ok,
        compile=compiled,
        lint=lint,
        security=security,
        filename=filename,
    )


def check_file(path: str, optimize: bool = True, strict_security: bool = True) -> CheckReport:
    """Run compile + lint + security analysis over a ``.hpy`` file from disk."""
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    return check_source(source, filename=path, optimize=optimize, strict_security=strict_security)


# ---------------------------------------------------------------------------
# Tooling re-exports (lazy, thin wrappers)
# ---------------------------------------------------------------------------
def format_source(source: str, filename: Optional[str] = None):
    """Format Happy ``source`` with the deterministic AST-based formatter."""
    from .tools.fmt import format_source as _fmt

    return _fmt(source, filename=filename)


def lint_source(source: str, filename: Optional[str] = None):
    """Lint Happy ``source`` (naming, missing contracts, unused code, weak perms)."""
    from .tools.lint import lint_source as _lint

    return _lint(source, filename=filename)


def analyze_security_source(source: str, filename: Optional[str] = None, strict: bool = True):
    """Run the static security analyzer over Happy ``source``."""
    from .security import analyze_security

    return analyze_security(source, filename=filename, strict=strict)
