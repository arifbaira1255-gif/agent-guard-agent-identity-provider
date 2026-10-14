"""The Happy debugger (Step 12).

Provides source-level debugging on top of the generated Python + source map:

* :func:`trace` / :class:`HappyTracer` — run a program under ``sys.settrace``
  and translate every generated-Python frame back to ``.hpy`` lines;
* :func:`explain_exception` — turn a raw Python traceback into a Happy-source
  diagnostic (used by ``happy run`` and by the runtime);
* :class:`Debugger` — a small, scriptable step/inspect driver for a compiled
  program (breakpoints on ``.hpy`` lines, locals, continue).
"""

from __future__ import annotations

import sys
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..backend.python_gen import GENERATED_FILENAME, GeneratedProgram

__all__ = [
    "Frame",
    "HappyTracer",
    "trace",
    "explain_exception",
    "Debugger",
    "Breakpoint",
]


@dataclass
class Frame:
    """One executed source location, translated to Happy coordinates."""

    happy_line: int
    happy_column: int
    function: str
    generated_line: int

    def render(self, filename: Optional[str] = None) -> str:
        name = filename or "<happy>"
        return f"{name}:{self.happy_line}:{self.happy_column} in {self.function}"


def _is_generated(filename: Optional[str]) -> bool:
    if filename is None:
        return False
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    return base in (GENERATED_FILENAME, "<string>") or base.startswith(
        "happy-generated"
    )


class HappyTracer:
    """Collects the Happy-source execution path of a generated program."""

    def __init__(self, program: GeneratedProgram, target_filename: Optional[str] = None):
        self.program = program
        self.sourcemap = program.sourcemap
        self.target = target_filename or program.filename
        self.frames: List[Frame] = []

    # -- the trace hook -------------------------------------------------
    def __call__(self, frame, event, arg):
        if event != "line":
            return self.__call__
        if not _is_generated(frame.f_code.co_filename):
            return self.__call__
        entry = self.sourcemap.resolve(frame.f_lineno)
        if entry is None:
            return self.__call__
        last = self.frames[-1] if self.frames else None
        if (
            last is not None
            and last.happy_line == entry.happy_line
            and last.function == frame.f_code.co_name
        ):
            return self.__call__
        self.frames.append(
            Frame(
                happy_line=entry.happy_line,
                happy_column=entry.happy_column,
                function=frame.f_code.co_name,
                generated_line=frame.f_lineno,
            )
        )
        return self.__call__

    # -- convenience ----------------------------------------------------
    def lines(self) -> List[int]:
        return [f.happy_line for f in self.frames]

    def render(self) -> str:
        return "\n".join(f.render(self.target) for f in self.frames)


def _default_context(program: GeneratedProgram):
    from ..runtime import RuntimeContext

    return RuntimeContext(
        filename=program.filename,
        module=program.module,
        sourcemap=program.sourcemap,
    )


def trace(program: GeneratedProgram, context: Any = None) -> HappyTracer:
    """Execute ``program`` and return the collected Happy execution trace.

    The program is run exactly as :meth:`GeneratedProgram.run` would, but under
    a tracer that records Happy source lines.
    """
    tracer = HappyTracer(program)
    ctx = context if context is not None else _default_context(program)
    sys.settrace(tracer)
    try:
        program.run(ctx)
    finally:
        sys.settrace(None)
    return tracer


def explain_exception(program: GeneratedProgram, exc: BaseException) -> str:
    """Translate an exception + traceback into a Happy-source message."""
    lines = traceback.format_exception(type(exc), exc, exc.__traceback__)
    located: Optional[str] = None
    for frame_summary in traceback.extract_tb(exc.__traceback__):
        if _is_generated(frame_summary.filename):
            entry = program.sourcemap.resolve(frame_summary.lineno)
            if entry is not None:
                located = (
                    f"{program.filename or '<happy>'}:"
                    f"{entry.happy_line}:{entry.happy_column}"
                )
                break
    head = "".join(lines).rstrip()
    if located:
        return f"error at {located}\n{head}"
    return head


@dataclass
class Breakpoint:
    """A breakpoint on a Happy source line."""

    line: int
    hits: int = 0


class Debugger:
    """A scriptable, headless debugger over a compiled Happy program.

    Because Happy compiles to Python, the debugger runs the code under a trace
    hook and pauses whenever execution reaches a Happy line that has a
    breakpoint set.  A callback is invoked at each stop, so it works both
    interactively and in tests.
    """

    def __init__(self, program: GeneratedProgram, context: Any = None):
        self.program = program
        self.context = context
        self.breakpoints: Dict[int, Breakpoint] = {}
        self.stops: List[Frame] = []
        #: Called as ``on_stop(frame, locals)`` at every breakpoint hit.
        self.on_stop: Optional[Any] = None

    def set_breakpoint(self, line: int) -> Breakpoint:
        bp = Breakpoint(line=line)
        self.breakpoints[line] = bp
        return bp

    def clear_breakpoint(self, line: int) -> None:
        self.breakpoints.pop(line, None)

    def _hook(self, frame, event, arg):
        if event != "line" or not _is_generated(frame.f_code.co_filename):
            return self._hook
        entry = self.program.sourcemap.resolve(frame.f_lineno)
        if entry is None:
            return self._hook
        bp = self.breakpoints.get(entry.happy_line)
        if bp is not None:
            bp.hits += 1
            stop = Frame(
                happy_line=entry.happy_line,
                happy_column=entry.happy_column,
                function=frame.f_code.co_name,
                generated_line=frame.f_lineno,
            )
            self.stops.append(stop)
            if self.on_stop is not None:
                self.on_stop(stop, dict(frame.f_locals))
        return self._hook

    def run(self) -> Any:
        ctx = self.context if self.context is not None else _default_context(
            self.program
        )
        sys.settrace(self._hook)
        try:
            return self.program.run(ctx)
        finally:
            sys.settrace(None)
