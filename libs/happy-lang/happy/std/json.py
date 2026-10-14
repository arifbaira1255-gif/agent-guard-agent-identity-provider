"""``std.json`` — JSON encode / decode for Happy.

Encoding is **secret-aware**: values are funnelled through
:func:`happy.runtime.values.deep_redact`, so a ``secret`` field is never
serialized in the clear — it becomes the ``<secret ***>`` marker.  This is the
runtime counterpart of the compile-time ``W3120`` secret-field warning.

Decoding maps JSON onto Happy values: objects become dicts, arrays lists,
``true``/``false`` booleans, and ``null`` the ``None`` Option.
"""

from __future__ import annotations

import json as _json
from typing import Any, Optional

from ..runtime.errors import HappyRuntimeError
from ..runtime.values import deep_redact

__all__ = ["parse", "stringify", "pretty", "get_field", "set_field", "PUBLIC"]

PUBLIC = ["parse", "stringify", "pretty", "get_field", "set_field"]


def parse(text: str, __ctx__: Any = None) -> Any:
    """Parse a JSON string into Happy values."""
    try:
        return _json.loads(text)
    except (ValueError, TypeError) as exc:
        raise HappyRuntimeError(
            message=f"json.parse failed: {exc}", code="R4401", cause=exc
        ) from exc


def _encode(value: Any) -> str:
    redacted = deep_redact(value)
    try:
        return _json.dumps(redacted, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise HappyRuntimeError(
            message=f"json.stringify failed: {exc}", code="R4402", cause=exc
        ) from exc


def stringify(value: Any, __ctx__: Any = None) -> str:
    """Serialize ``value`` to a compact JSON string (secrets redacted)."""
    return _encode(value)


def pretty(value: Any, indent: int = 2, __ctx__: Any = None) -> str:
    """Serialize ``value`` to pretty-printed JSON (secrets redacted)."""
    redacted = deep_redact(value)
    try:
        return _json.dumps(redacted, indent=indent, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise HappyRuntimeError(
            message=f"json.pretty failed: {exc}", code="R4403", cause=exc
        ) from exc


def get_field(obj: Any, key: str, default: Any = None, __ctx__: Any = None) -> Any:
    """Read ``obj[key]`` for a dict (or attribute), with a default."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def set_field(obj: Any, key: str, value: Any, __ctx__: Any = None) -> Any:
    """Set ``obj[key]`` (or attribute) and return the object."""
    if isinstance(obj, dict):
        obj[key] = value
    else:
        setattr(obj, key, value)
    return obj
