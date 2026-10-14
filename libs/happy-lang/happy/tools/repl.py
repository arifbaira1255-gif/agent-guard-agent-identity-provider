"""An interactive REPL for Happy (Step 12).

The REPL keeps a growing buffer of Happy source.  Each time the buffered text
forms a complete program (it parses *and* has an ``app``/``main`` entry) it is
compiled and executed, and the output is printed.  Declarations accumulate, so
you can define a function on one line and call it on the next — exactly like a
traditional REPL, but for a compiled language.

The core is :class:`HappyREPL`, whose :meth:`feed` is a pure function of the
input; the :func:`run_repl` driver only adds the terminal loop.  That split
makes the REPL fully testable without a TTY.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ..backend import compile_source
from ..compiler import parse
from ..compiler.semantic import Diagnostic, Severity

__all__ = ["REPLResult", "HappyREPL", "run_repl"]

_BANNER = "Happy REPL (happy 1.0.0) — type :help for commands, :quit to exit"


@dataclass
class REPLResult:
    """The outcome of feeding one line to the REPL."""

    ok: bool = True
    incomplete: bool = False
    output: str = ""
    diagnostics: List[Diagnostic] = field(default_factory=list)
    ran: bool = False


class HappyREPL:
    """A minimal, embeddable Happy REPL."""

    def __init__(self) -> None:
        self.buffer: List[str] = []
        #: Lines of a multi-line construct that is still being typed.
        self.pending: List[str] = []
        self.history: List[str] = []

    # -- commands -------------------------------------------------------
    def _command(self, line: str) -> Optional[REPLResult]:
        cmd = line.strip()
        if cmd in (":quit", ":q", ":exit"):
            return REPLResult(ok=True, output="__EXIT__")
        if cmd == ":help":
            return REPLResult(
                ok=True,
                output=(
                    "Commands:\n"
                    "  :help          show this help\n"
                    "  :clear         clear the current buffer\n"
                    "  :show          print the buffered source\n"
                    "  :quit          exit\n"
                    "Enter Happy declarations/functions; the REPL runs once the "
                    "buffer has an `app` entry."
                ),
            )
        if cmd == ":clear":
            self.buffer = []
            self.pending = []
            return REPLResult(ok=True, output="(buffer cleared)")
        if cmd == ":show":
            return REPLResult(ok=True, output="\n".join(self.buffer))
        if cmd.startswith(":"):
            return REPLResult(ok=False, output=f"unknown command: {cmd}")
        return None

    # -- feeding --------------------------------------------------------
    @staticmethod
    def _is_incomplete(text: str) -> bool:
        """True when ``text`` has unclosed brackets or an unterminated string,
        i.e. the user is probably mid-way through a multi-line construct."""
        depth = 0
        in_str = False
        escaped = False
        for ch in text:
            if in_str:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch in "({[":
                depth += 1
            elif ch in ")}]":
                depth -= 1
        return in_str or depth > 0

    def feed(self, line: str) -> REPLResult:
        """Feed one line; compile+run when a complete ``app`` has been entered.

        * A line that is syntactically wrong is *discarded* (it never poisons
          later input); only genuinely unfinished input stays pending.
        * Declarations accumulate in ``buffer``.  An ``app`` is run once and
          is then dropped, so defining something afterwards does not run it
          a second time.
        """
        self.history.append(line)

        cmd = self._command(line)
        if cmd is not None:
            return cmd

        if not line.strip():
            return REPLResult(ok=True)

        pending = self.pending + [line]
        chunk = "\n".join(pending)
        if self._is_incomplete(chunk):
            self.pending = pending
            return REPLResult(ok=True, incomplete=True)

        source = "\n".join(self.buffer + pending) + "\n"
        try:
            program = parse(source, filename="<repl>")
        except Exception as exc:  # noqa: BLE001 - parse errors are diagnostics
            self.pending = []  # discard the bad input; keep the buffer healthy
            diag = getattr(exc, "diagnostic", None)
            return REPLResult(
                ok=False,
                diagnostics=[diag] if diag is not None else [],
                output=str(exc),
            )
        self.pending = []

        has_entry = any(
            d.__class__.__name__ == "AppDecl" for d in program.declarations
        )
        if not has_entry:
            result = self._check(source)
            if result is not None:
                return result  # declaration with errors: not committed
            self.buffer = self.buffer + pending
            return REPLResult(ok=True, ran=False, output="")

        # Run the app together with the committed declarations, but do not
        # commit the app itself.
        return self._run(source)

    def _check(self, source: str) -> Optional[REPLResult]:
        """Compile-check a declaration-only buffer; None when it is fine."""
        try:
            compile_source(source, filename="<repl>", strict=True)
        except Exception as exc:  # noqa: BLE001
            msg = getattr(exc, "rendered", None) or str(exc)
            return REPLResult(ok=False, output=f"compile error: {msg}")
        return None

    def _run(self, source: str) -> REPLResult:
        from ..runtime import RuntimeContext

        try:
            result = compile_source(source, filename="<repl>", strict=True)
        except Exception as exc:  # noqa: BLE001
            msg = getattr(exc, "rendered", None) or str(exc)
            return REPLResult(ok=False, output=f"compile error: {msg}")

        ctx = RuntimeContext(
            filename="<repl>", module=result.module, sourcemap=result.sourcemap
        )
        try:
            run_result = result.run(ctx)
        except Exception as exc:  # noqa: BLE001 - report, never crash
            return REPLResult(ok=False, output=f"runtime error: {exc}", ran=True)
        output = getattr(run_result, "output", None) or ctx.output
        return REPLResult(ok=True, output=output, ran=True)


def run_repl(
    stdin: Optional[Callable[[], str]] = None,
    stdout: Optional[Callable[[str], None]] = None,
) -> int:
    """Drive :class:`HappyREPL` on a terminal (or injected streams)."""
    import sys

    read = stdin or (lambda: input("happy> "))
    write = stdout or print

    repl = HappyREPL()
    write(_BANNER)
    while True:
        try:
            line = read()
        except (EOFError, KeyboardInterrupt):
            write("")
            return 0
        result = repl.feed(line)
        if result.output == "__EXIT__":
            return 0
        if result.output:
            write(result.output)
