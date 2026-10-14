"""Runtime error types for the Happy execution layer.

Every error raised while a Happy program runs is a :class:`HappyRuntimeError`.
Errors carry an optional *location* in the original ``.hpy`` source (resolved
through the backend sourcemap) so that a failure deep inside generated Python
can be reported against the Happy line the programmer actually wrote::

    demo.hpy:14:9: error: [R1001] contract violated in 'deposit': requires amount > 0.0
      14 |     requires amount > 0.0
         |         ^
      help: the precondition 'amount > 0.0' evaluated to false

The rendering reuses :func:`happy.compiler.errors.format_diagnostic`, so
runtime diagnostics look exactly like compile-time ones.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from ..compiler.errors import SourceLocation, format_diagnostic

__all__ = [
    "HappyRuntimeError",
    "ContractViolation",
    "PreconditionViolation",
    "PostconditionViolation",
    "InvariantViolation",
    "RuleViolation",
    "CapabilityDenied",
    "PermissionDenied",
    "SecretLeakError",
    "HappyTypeError",
    "HappyNameError",
    "HappyIndexError",
    "HappyKeyError",
    "DivisionByZeroError",
    "AsyncRuntimeError",
    "HappyPanic",
    "RuntimeSourceLocation",
    "format_runtime_error",
]


#: A resolved runtime location: ``(filename, line, column)``.
RuntimeSourceLocation = Tuple[Optional[str], int, int]


def _as_source_location(loc) -> Optional[SourceLocation]:
    """Coerce a variety of location shapes into a :class:`SourceLocation`."""
    if loc is None:
        return None
    if isinstance(loc, SourceLocation):
        return loc
    if isinstance(loc, (tuple, list)) and len(loc) >= 2:
        line = int(loc[-2]) if len(loc) >= 3 else int(loc[0])
        col = int(loc[-1]) if len(loc) >= 3 else 1
        if len(loc) >= 3:
            line = int(loc[1])
            col = int(loc[2])
        return SourceLocation(line=line, column=col)
    if hasattr(loc, "line"):
        return SourceLocation(
            line=int(getattr(loc, "line", 0) or 0),
            column=int(getattr(loc, "column", 0) or 0),
        )
    return None


@dataclass
class HappyRuntimeError(Exception):
    """Base class for every runtime failure.

    Attributes
    ----------
    message:
        Human-readable description of what went wrong.
    code:
        A stable machine-readable diagnostic code (``Rxxxx``).
    location:
        Where the failure occurred in the ``.hpy`` source (if known).
    source:
        The original Happy source text (used to render the caret line).
    filename:
        The ``.hpy`` file name.
    suggestion:
        An optional ``help:`` line.
    happy_trace:
        A list of ``(function_name, location)`` tuples best-effort walk of the
        Happy call stack at the point of failure.
    """

    message: str = ""
    code: str = "R0001"
    location: Optional[object] = None
    source: Optional[str] = None
    filename: Optional[str] = None
    suggestion: Optional[str] = None
    happy_trace: List[Tuple[str, Optional[object]]] = field(default_factory=list)
    cause: Optional[BaseException] = None
    severity: str = "error"

    def __post_init__(self) -> None:  # keep ``Exception`` happy
        Exception.__init__(self, self.message)

    # -- rendering ------------------------------------------------------
    @property
    def loc(self) -> Optional[SourceLocation]:
        return _as_source_location(self.location)

    def render(self) -> str:
        header = f"[{self.code}] {self.message}"
        text = format_diagnostic(
            header,
            location=self.loc,
            source=self.source,
            suggestion=self.suggestion,
            filename=self.filename,
            severity=self.severity,
        )
        if self.happy_trace:
            rows = []
            for name, loc in self.happy_trace:
                l = _as_source_location(loc)
                where = f"{self.filename}:{l.line}:{l.column}" if (l and self.filename) else (
                    f"{l.line}:{l.column}" if l else "?"
                )
                rows.append(f"    at {name} ({where})")
            text += "\n  happy traceback:\n" + "\n".join(rows)
        return text

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.render()


@dataclass
class ContractViolation(HappyRuntimeError):
    """A ``requires`` / ``ensures`` / ``rule`` clause evaluated to false."""

    code: str = "R1001"


@dataclass
class PreconditionViolation(ContractViolation):
    code: str = "R1003"


@dataclass
class PostconditionViolation(ContractViolation):
    code: str = "R1004"


@dataclass
class InvariantViolation(ContractViolation):
    code: str = "R1002"


@dataclass
class RuleViolation(ContractViolation):
    code: str = "R1005"


@dataclass
class CapabilityDenied(HappyRuntimeError):
    """A sensitive operation was attempted without the required capability."""

    code: str = "R2001"


@dataclass
class PermissionDenied(HappyRuntimeError):
    """An action was explicitly denied by a permission's ``cannot`` set."""

    code: str = "R2002"


@dataclass
class SecretLeakError(HappyRuntimeError):
    """A ``secret`` value would have escaped into output/logs."""

    code: str = "R3001"


@dataclass
class HappyTypeError(HappyRuntimeError):
    code: str = "R4001"


@dataclass
class HappyNameError(HappyRuntimeError):
    code: str = "R4002"


@dataclass
class HappyIndexError(HappyRuntimeError):
    code: str = "R4003"


@dataclass
class HappyKeyError(HappyRuntimeError):
    code: str = "R4004"


@dataclass
class DivisionByZeroError(HappyRuntimeError):
    code: str = "R4005"


@dataclass
class AsyncRuntimeError(HappyRuntimeError):
    code: str = "R5001"


@dataclass
class HappyPanic(HappyRuntimeError):
    """Raised by the ``panic`` builtin / explicit program abort."""

    code: str = "R6001"


#: Python exception class -> Happy runtime error class.
_PY_EXC_MAP: Sequence[Tuple[type, type]] = (
    (ZeroDivisionError, DivisionByZeroError),
    (IndexError, HappyIndexError),
    (KeyError, HappyKeyError),
    (NameError, HappyNameError),
    (AttributeError, HappyNameError),
    (TypeError, HappyTypeError),
    (ValueError, HappyTypeError),
)


def translate_python_error(exc: BaseException, **kwargs) -> HappyRuntimeError:
    """Wrap a raw Python exception in the closest Happy runtime error type."""
    for py_cls, happy_cls in _PY_EXC_MAP:
        if isinstance(exc, py_cls):
            return happy_cls(message=f"{type(exc).__name__}: {exc}", cause=exc, **kwargs)
    return HappyRuntimeError(
        message=f"{type(exc).__name__}: {exc}", code="R0002", cause=exc, **kwargs
    )


def format_runtime_error(err: HappyRuntimeError) -> str:
    """Render a runtime error as a Happy diagnostic string."""
    return err.render()
