"""Developer tooling for the Happy language (Steps 6 & 12).

* :mod:`happy.tools.fmt`       — the deterministic AST-based source formatter.
* :mod:`happy.tools.lint`      — the static linter (naming, contracts, dead
  code, weak permission models).
* :mod:`happy.tools.lsp`       — the Language Server Protocol implementation.
* :mod:`happy.tools.debugger`  — source-level tracing/stepping via the sourcemap.
* :mod:`happy.tools.docgen`    — Markdown documentation generator.
* :mod:`happy.tools.repl`      — an embeddable interactive REPL.
* :mod:`happy.tools.publish`   — ``.hpyz`` packaging / installation.

    from happy.tools import format_source, lint_source, HappyLanguageServer
"""

from .fmt import FormatResult, Formatter, format_program, format_source
from .lint import LintFinding, LintReport, Linter, lint_source
from .lsp import HappyLanguageServer, serve_stdio
from .debugger import Debugger, HappyTracer, trace, explain_exception
from .docgen import DocGenerator, generate_docs
from .repl import HappyREPL, run_repl
from .publish import create_package, install_package, PackageInfo

__all__ = [
    "Formatter",
    "FormatResult",
    "format_source",
    "format_program",
    "Linter",
    "LintReport",
    "LintFinding",
    "lint_source",
    "HappyLanguageServer",
    "serve_stdio",
    "Debugger",
    "HappyTracer",
    "trace",
    "explain_exception",
    "DocGenerator",
    "generate_docs",
    "HappyREPL",
    "run_repl",
    "create_package",
    "install_package",
    "PackageInfo",
]
