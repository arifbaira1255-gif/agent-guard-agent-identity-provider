"""``std.io`` — input/output for Happy.

The module mirrors Happy's file / network vocabulary.  Every sensitive
operation is *capability-gated*: generated code (or a calling std function)
checks with the active context before performing the underlying action, so an
agent cannot read a file or open a socket unless it holds the matching
capability.

``write_file`` / ``read_file`` / ``http_get`` / ``http_post`` map to the
abstract actions used by the compiler (``file_write``, ``file_read``, ``net``)
via :data:`happy.compiler.permissions.ENFORCEMENT_MAP`.

A module-level :class:`~happy.runtime.capability.CapabilityChecker` can be set
with :func:`use_checker`; the runtime context points it at its own checker so
the two stay in sync.
"""

from __future__ import annotations

import json as _json
import os
import urllib.request
from typing import Any, Optional

from ..runtime.errors import HappyRuntimeError

__all__ = [
    "print",
    "println",
    "eprint",
    "read_file",
    "write_file",
    "append_file",
    "file_exists",
    "http_get",
    "http_post",
    "read_line",
    "read_input",
    "use_checker",
    "PUBLIC",
]

#: Public names exported by ``import { ... } from "std.io"``.
PUBLIC = [
    "print",
    "println",
    "eprint",
    "read_file",
    "write_file",
    "append_file",
    "file_exists",
    "http_get",
    "http_post",
    "read_line",
    "read_input",
]

#: The active capability checker (set by the runtime context).
_CHECKER: Any = None


def use_checker(checker: Any) -> None:
    """Point ``std.io`` at the active capability checker."""
    global _CHECKER
    _CHECKER = checker


def _authorize(operation: str, loc: Optional[object] = None) -> None:
    if _CHECKER is not None:
        _CHECKER.check_operation(operation, loc=loc)


# ---------------------------------------------------------------------------
# Console (pure IO, no capability required)
# ---------------------------------------------------------------------------
def print(*values: Any, __ctx__: Any = None) -> None:
    from .core import print_ as _p

    _p(*values, __ctx__=__ctx__)


def println(*values: Any, __ctx__: Any = None) -> None:
    from .core import println as _p

    _p(*values, __ctx__=__ctx__)


def eprint(*values: Any, __ctx__: Any = None) -> None:
    from .core import eprint as _p

    _p(*values, __ctx__=__ctx__)


# ---------------------------------------------------------------------------
# Files (capability: file_read / file_write)
# ---------------------------------------------------------------------------
def read_file(path: str, __ctx__: Any = None, **kw: Any) -> str:
    """Read a file's contents as a string (requires ``file_read``)."""
    _authorize("read_file")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        raise HappyRuntimeError(
            message=f"read_file('{path}') failed: {exc}", code="R4301", cause=exc
        ) from exc


def write_file(path: str, content: Any, __ctx__: Any = None, **kw: Any) -> None:
    """Write ``content`` to ``path`` (requires ``file_write``)."""
    _authorize("write_file")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("" if content is None else str(content))
    except OSError as exc:
        raise HappyRuntimeError(
            message=f"write_file('{path}') failed: {exc}", code="R4302", cause=exc
        ) from exc


def append_file(path: str, content: Any, __ctx__: Any = None, **kw: Any) -> None:
    """Append ``content`` to ``path`` (requires ``file_write``)."""
    _authorize("write_file")
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("" if content is None else str(content))
    except OSError as exc:
        raise HappyRuntimeError(
            message=f"append_file('{path}') failed: {exc}", code="R4303", cause=exc
        ) from exc


def file_exists(path: str, __ctx__: Any = None, **kw: Any) -> bool:
    """Return True when ``path`` exists (requires ``file_read``)."""
    _authorize("read_file")
    return os.path.exists(path)


# ---------------------------------------------------------------------------
# Network (capability: net)
# ---------------------------------------------------------------------------
def http_get(url: str, __ctx__: Any = None, **kw: Any) -> str:
    """Perform an HTTP GET and return the response body (requires ``net``)."""
    _authorize("http_get")
    try:
        with urllib.request.urlopen(url, timeout=kw.get("timeout", 15)) as resp:
            return resp.read().decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - surfaced as a Happy error
        raise HappyRuntimeError(
            message=f"http_get('{url}') failed: {exc}", code="R4304", cause=exc
        ) from exc


def http_post(url: str, body: Any = None, __ctx__: Any = None, **kw: Any) -> str:
    """Perform an HTTP POST and return the response body (requires ``net``)."""
    _authorize("http_post")
    data = body
    if data is not None and not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    if kw.get("content_type"):
        req.add_header("Content-Type", kw["content_type"])
    try:
        with urllib.request.urlopen(req, timeout=kw.get("timeout", 15)) as resp:
            return resp.read().decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        raise HappyRuntimeError(
            message=f"http_post('{url}') failed: {exc}", code="R4305", cause=exc
        ) from exc


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------
def read_line(__ctx__: Any = None, **kw: Any) -> str:
    """Read a single line from the context's input (or stdin)."""
    source = getattr(__ctx__, "input_stream", None)
    if source is not None:
        line = source.readline()
        return line.rstrip("\n") if line else ""
    try:
        return input()
    except EOFError:
        return ""


#: Alias matching the language-level ``read_input`` builtin.
read_input = read_line
