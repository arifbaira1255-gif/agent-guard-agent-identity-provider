"""Source maps for the Happy Python backend.

The Python generator emits ordinary Python 3, but records a :class:`SourceMap`
that connects every generated Python line back to the ``.hpy`` line/column it
came from.  When generated code fails at runtime, the runner walks the Python
traceback, finds the innermost frame that belongs to the generated module and
resolves its line number through the map — so a ``ZeroDivisionError`` on
generated line 87 is reported as::

    demo.hpy:12:14: error: [R4005] DivisionByZeroError: division by zero
      12 |     return a / b

The map is deliberately tiny and JSON-serializable so a compiled artifact can
carry it alongside the generated source (``.hpy.map``).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

__all__ = ["SourceMapEntry", "SourceMap", "SourceMapBuilder"]


@dataclass
class SourceMapEntry:
    """One generated-line -> happy-location mapping."""

    generated_line: int
    happy_line: int
    happy_column: int
    node_id: str = ""
    symbol: str = ""

    def render(self, filename: Optional[str] = None) -> str:
        where = f"{filename}:" if filename else ""
        return f"{where}{self.happy_line}:{self.happy_column}"


class SourceMap:
    """A sorted collection of :class:`SourceMapEntry` records."""

    def __init__(self, filename: Optional[str] = None) -> None:
        self.filename = filename
        self.entries: List[SourceMapEntry] = []
        self.generated_lines: int = 0

    # -- building -------------------------------------------------------
    def add(
        self,
        generated_line: int,
        happy_line: int,
        happy_column: int,
        node_id: str = "",
        symbol: str = "",
    ) -> SourceMapEntry:
        entry = SourceMapEntry(
            generated_line=generated_line,
            happy_line=happy_line,
            happy_column=happy_column,
            node_id=node_id,
            symbol=symbol,
        )
        self.entries.append(entry)
        return entry

    def finalize(self, total_generated_lines: int) -> "SourceMap":
        """Record the generated size and sort entries for fast lookup."""
        self.generated_lines = total_generated_lines
        self.entries.sort(key=lambda e: e.generated_line)
        return self

    # -- lookup ---------------------------------------------------------
    def resolve(self, generated_line: int) -> Optional[SourceMapEntry]:
        """Return the nearest mapping at or before ``generated_line``.

        Statements may span several generated lines; mapping a line to the
        most recent recorded anchor keeps the reported location sensible for
        any line inside a statement's expansion.
        """
        # Strict: a line outside the generated program has no source location.
        # (Previously any line past the end resolved to the *last* anchor,
        # attributing a bogus position to the error.)
        if generated_line < 1:
            return None
        if self.generated_lines and generated_line > self.generated_lines:
            return None
        # Binary search for the right-most entry at or before the line.
        lo, hi = 0, len(self.entries)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.entries[mid].generated_line <= generated_line:
                lo = mid + 1
            else:
                hi = mid
        return self.entries[lo - 1] if lo else None

    def render(self, generated_line: int) -> str:
        entry = self.resolve(generated_line)
        if entry is None:
            return f"<generated line {generated_line}>"
        return entry.render(self.filename)

    # -- serialization --------------------------------------------------
    def to_dict(self) -> Dict[str, object]:
        return {
            "filename": self.filename,
            "generated_lines": self.generated_lines,
            "entries": [asdict(e) for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "SourceMap":
        if not isinstance(data, dict):
            raise ValueError("source map must be a JSON object")
        sm = cls(filename=data.get("filename"))  # type: ignore[arg-type]
        try:
            sm.generated_lines = int(data.get("generated_lines", 0) or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid generated_lines: {exc}") from exc
        if sm.generated_lines < 0:
            raise ValueError("generated_lines must not be negative")
        for raw in data.get("entries", []) or []:
            if not isinstance(raw, dict):
                raise ValueError("source map entry must be an object")
            try:
                entry = SourceMapEntry(**raw)  # type: ignore[arg-type]
            except TypeError as exc:
                raise ValueError(f"malformed source map entry: {exc}") from exc
            for fname in ("generated_line", "happy_line", "happy_column"):
                val = getattr(entry, fname)
                if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                    raise ValueError(f"source map entry field '{fname}' must be a non-negative integer")
            sm.entries.append(entry)
        sm.entries.sort(key=lambda e: e.generated_line)
        return sm

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, text: str) -> "SourceMap":
        return cls.from_dict(json.loads(text))


class SourceMapBuilder:
    """Convenience builder used while emitting generated source line by line."""

    def __init__(self, filename: Optional[str] = None) -> None:
        self.map = SourceMap(filename=filename)
        self._line = 0

    def emit(self, text: str) -> int:
        """Record that a generated line is about to be written."""
        self._line += 1
        return self._line

    def anchor(self, happy_line: int, happy_column: int, node_id="", symbol="") -> int:
        """Anchor the current generated line to a happy location."""
        self.map.add(self._line, happy_line, happy_column, node_id, symbol)
        return self._line

    def finalize(self) -> SourceMap:
        return self.map.finalize(self._line)
