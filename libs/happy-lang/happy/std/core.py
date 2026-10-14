"""``std.core`` — core runtime builtins for Happy.

These functions are installed into every generated module's global scope by the
:class:`~happy.runtime.context.RuntimeContext`, so a Happy program can call
``print``, ``len``, ``str`` … without importing anything.

Printing goes through :func:`happy.runtime.values.to_display`, which is
secret-aware: a ``secret`` value is redacted (or refused) rather than leaked.

Effects / capability mapping
----------------------------
``print`` / ``println`` / ``eprint`` are ``IO`` operations (no capability
required — see :data:`happy.compiler.permissions.ENFORCEMENT_MAP`).  The
functions take an optional ``__ctx__`` keyword that the context wrapper binds;
when present, output is routed to the context's sink and the effect is logged.
"""

from __future__ import annotations

import math
from typing import Any, Callable, Iterable, List, Optional

from ..runtime.errors import HappyPanic, HappyRuntimeError, HappyTypeError
from ..runtime.values import to_display

__all__ = [
    "print_",
    "println",
    "eprint",
    "str_",
    "int_",
    "float_",
    "bool_",
    "len_",
    "abs_",
    "min_",
    "max_",
    "clamp",
    "panic",
    "assert_",
    "typeof",
    "range_",
    "stringify",
    "BUILTINS",
    "FACTORIES",
]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def _emit(ctx: Any, text: str) -> None:
    if ctx is not None:
        ctx.emit(text)
    else:  # pragma: no cover - direct use outside a runtime
        print(text)


def print_(*values: Any, __ctx__: Any = None, **kw: Any) -> None:
    """Print each value (space-separated) without a trailing newline."""
    text = " ".join(to_display(v) for v in values)
    _emit(__ctx__, text)


def println(*values: Any, __ctx__: Any = None, **kw: Any) -> None:
    """Print each value (space-separated) followed by a newline."""
    text = " ".join(to_display(v) for v in values)
    _emit(__ctx__, text + "\n")


def eprint(*values: Any, __ctx__: Any = None, **kw: Any) -> None:
    """Print to the error stream."""
    text = " ".join(to_display(v) for v in values)
    if __ctx__ is not None:
        __ctx__.emit_error(text)
    else:  # pragma: no cover
        import sys

        print(text, file=sys.stderr)


# ---------------------------------------------------------------------------
# Conversions
# ---------------------------------------------------------------------------
def str_(value: Any, __ctx__: Any = None) -> str:
    """Convert any value to its Happy string form (secret-aware)."""
    return to_display(value)


def int_(value: Any, __ctx__: Any = None) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 10)
        except ValueError as exc:
            raise HappyTypeError(
                message=f"cannot convert {value!r} to Int", cause=exc
            ) from exc
    if isinstance(value, int):
        return value
    raise HappyTypeError(message=f"cannot convert {type(value).__name__} to Int")


def float_(value: Any, __ctx__: Any = None) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError as exc:
            raise HappyTypeError(
                message=f"cannot convert {value!r} to Float", cause=exc
            ) from exc
    raise HappyTypeError(message=f"cannot convert {type(value).__name__} to Float")


def bool_(value: Any, __ctx__: Any = None) -> bool:
    return bool(value)


def typeof(value: Any, __ctx__: Any = None) -> str:
    from ..runtime.values import HappyStruct, HappyEnumValue, Option, Result

    if value is None:
        return "Unit"
    if isinstance(value, bool):
        return "Bool"
    if isinstance(value, int):
        return "Int"
    if isinstance(value, float):
        return "Float"
    if isinstance(value, str):
        return "String"
    if isinstance(value, HappyStruct):
        return value._happy_type_name
    if isinstance(value, HappyEnumValue):
        return value.enum
    if isinstance(value, list):
        return "List"
    if isinstance(value, dict):
        return "Map"
    if isinstance(value, set):
        return "Set"
    if isinstance(value, Option):
        return "Option"
    if isinstance(value, Result):
        return "Result"
    return type(value).__name__


# ---------------------------------------------------------------------------
# Math / sequence helpers
# ---------------------------------------------------------------------------
def len_(value: Any, __ctx__: Any = None) -> int:
    try:
        return len(value)
    except TypeError as exc:
        raise HappyTypeError(
            message=f"len() is not defined for {type(value).__name__}", cause=exc
        ) from exc


def abs_(value: Any, __ctx__: Any = None) -> Any:
    return abs(value)


def min_(a: Any, b: Any, __ctx__: Any = None) -> Any:
    return a if a <= b else b


def max_(a: Any, b: Any, __ctx__: Any = None) -> Any:
    return a if a >= b else b


def clamp(value: Any, low: Any, high: Any, __ctx__: Any = None) -> Any:
    return min(max(value, low), high)


def range_(start: Any, stop: Optional[Any] = None, __ctx__: Any = None) -> List[int]:
    """Range helper: ``range_(n)`` -> ``[0..n)``, ``range_(a, b)`` -> ``[a..b)``."""
    if stop is None:
        return list(range(int(start)))
    return list(range(int(start), int(stop)))


# ---------------------------------------------------------------------------
# Panic / assertions
# ---------------------------------------------------------------------------
def panic(message: Any = "panic", __ctx__: Any = None) -> None:
    """Abort execution with a Happy panic."""
    raise HappyPanic(message=to_display(message))


def assert_(condition: Any, message: Any = "assertion failed", __ctx__: Any = None) -> None:
    """Assert ``condition``; raise a panic with ``message`` when false."""
    if not condition:
        raise HappyPanic(message=to_display(message))


def stringify(value: Any) -> str:
    """Render ``value`` as a JSON-ish string (the ``stringify`` builtin)."""
    import json

    try:
        return json.dumps(value, default=to_display, ensure_ascii=False)
    except (TypeError, ValueError):  # pragma: no cover - exotic values
        return to_display(value)


#: Functions installed directly into generated module globals.
BUILTINS: dict = {
    "print": print_,
    "println": println,
    "eprint": eprint,
    "str": str_,
    "int": int_,
    "float": float_,
    "bool": bool_,
    "len": len_,
    "abs": abs_,
    "min": min_,
    "max": max_,
    "clamp": clamp,
    "range": range_,
    "stringify": stringify,
    "panic": panic,
    "assert": assert_,
    "typeof": typeof,
}

#: Names that shadow Python builtins once context-bound.
FACTORIES: dict = {}
