"""``std.regex`` — regular-expression helpers for Happy (built on ``re``)."""

from __future__ import annotations

import re as _re
from typing import List

__all__ = [
    "match",
    "search",
    "find_all",
    "find_groups",
    "replace",
    "split",
    "is_match",
    "escape",
    "PUBLIC",
]

PUBLIC = [
    "match",
    "search",
    "find_all",
    "find_groups",
    "replace",
    "split",
    "is_match",
    "escape",
]


def is_match(pattern: str, text: str) -> bool:
    return _re.search(pattern, text) is not None


def match(pattern: str, text: str) -> str:
    m = _re.match(pattern, text)
    return m.group(0) if m else ""


def search(pattern: str, text: str) -> str:
    m = _re.search(pattern, text)
    return m.group(0) if m else ""


def find_all(pattern: str, text: str) -> List[str]:
    return [m if isinstance(m, str) else m[0] for m in _re.findall(pattern, text)]


def find_groups(pattern: str, text: str) -> List[str]:
    m = _re.search(pattern, text)
    if not m:
        return []
    return [g if g is not None else "" for g in m.groups()]


def replace(pattern: str, replacement: str, text: str) -> str:
    return _re.sub(pattern, replacement, text)


def split(pattern: str, text: str) -> List[str]:
    return _re.split(pattern, text)


def escape(text: str) -> str:
    return _re.escape(text)
