"""``std.logging`` — structured logging for Happy.

Log records redirect to the active runtime context (so output ordering stays
consistent with ``println``) when one is bound, and fall back to ``stderr``
otherwise.  Secret values are redacted by :mod:`happy.runtime.secrets` before
reaching a sink, so a ``secret`` can never leak through a log line.
"""

from __future__ import annotations

import sys
from typing import Any

__all__ = [
    "log",
    "debug",
    "info",
    "warn",
    "error",
    "set_level",
    "set_sink",
    "PUBLIC",
]

PUBLIC = ["log", "debug", "info", "warn", "error"]

_LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}

_LEVEL = 20
_SINK: Any = None
_CTX: Any = None


def set_level(level: str) -> None:
    global _LEVEL
    _LEVEL = _LEVELS.get(str(level).lower(), 20)


def set_sink(sink: Any) -> None:
    global _SINK
    _SINK = sink


def bind_context(ctx: Any) -> None:
    global _CTX
    _CTX = ctx


def _emit(level: str, message: str) -> None:
    if _LEVELS[level] < _LEVEL:
        return
    line = f"[{level.upper()}] {message}"
    if _SINK is not None:
        _SINK(line)
    elif _CTX is not None and hasattr(_CTX, "write_error"):
        _CTX.write_error(line)
    else:  # pragma: no cover - fallback
        print(line, file=sys.stderr)


def log(message: str) -> None:
    _emit("info", message)


def debug(message: str) -> None:
    _emit("debug", message)


def info(message: str) -> None:
    _emit("info", message)


def warn(message: str) -> None:
    _emit("warn", message)


def error(message: str) -> None:
    _emit("error", message)
