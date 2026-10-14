"""Diagnostics and error types for the Happy compiler frontend.

Every error raised by the lexer or the parser carries a precise
:class:`SourceLocation` (1-based line/column) and can render itself as a
human-readable diagnostic with the offending source line and a caret marker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SourceLocation:
    """A 1-based line/column position inside a source file."""

    line: int
    column: int
    offset: int = 0

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.line}:{self.column}"


def format_diagnostic(
    message: str,
    location: Optional[SourceLocation] = None,
    source: Optional[str] = None,
    suggestion: Optional[str] = None,
    filename: Optional[str] = None,
    severity: str = "error",
) -> str:
    """Render a compiler diagnostic as a multi-line string.

    Example output::

        demo.hpy:12:9: error: expected ';' after expression
          12 |     let x = 1
             |             ^
             |             help: insert ';' here
    """

    where = ""
    if filename:
        where += filename
    if location is not None:
        where += (":" if where else "") + f"{location.line}:{location.column}"
    header = f"{where}: {severity}: {message}" if where else f"{severity}: {message}"

    lines = [header]

    if source is not None and location is not None:
        src_lines = source.splitlines()
        if 1 <= location.line <= len(src_lines):
            text = src_lines[location.line - 1]
            gutter = str(location.line)
            pad = " " * len(gutter)
            lines.append(f"  {gutter} | {text}")
            caret_col = max(location.column - 1, 0)
            # Preserve tabs so the caret lines up with the source text.
            prefix = "".join(
                "\t" if ch == "\t" else " " for ch in text[:caret_col]
            )
            lines.append(f"  {pad} | {prefix}^")

    if suggestion:
        lines.append(f"  help: {suggestion}")

    return "\n".join(lines)


class HappyError(Exception):
    """Base class for all Happy compiler frontend errors."""

    severity = "error"

    def __init__(
        self,
        message: str,
        location: Optional[SourceLocation] = None,
        source: Optional[str] = None,
        suggestion: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.location = location
        self.source = source
        self.suggestion = suggestion
        self.filename = filename

    def render(self) -> str:
        """Return the fully formatted diagnostic string."""
        return format_diagnostic(
            self.message,
            location=self.location,
            source=self.source,
            suggestion=self.suggestion,
            filename=self.filename,
            severity=self.severity,
        )

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.render()


class LexerError(HappyError):
    """Raised when the lexer encounters an invalid character or literal."""


class ParseError(HappyError):
    """Raised when the parser encounters an unexpected token."""
