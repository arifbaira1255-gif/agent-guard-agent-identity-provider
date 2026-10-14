"""Opaque identifier minting.

Identifiers are opaque and prefixed so a log line, trace span and audit event can be tied back to
the object class without a schema lookup.
"""
from __future__ import annotations

import uuid

#: Characters allowed in a minted identifier (matches the integration contract's SAFE_TOKEN_RE).
_SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-")


class _Counter:
    """A process-local monotonic counter (cheap, sortable, useful in traces)."""

    value = 0

    @classmethod
    def next(cls) -> int:
        cls.value += 1
        return cls.value


def new_id(prefix: str, *, short: bool = False) -> str:
    """Mint ``prefix_<hex>``.  ``short`` halves the entropy for readable test fixtures."""
    safe = "".join(ch for ch in str(prefix) if ch in _SAFE) or "id"
    raw = uuid.uuid4().hex
    return f"{safe}_{raw[:16] if short else raw}"


def sequence_id(prefix: str) -> str:
    """Mint a deterministic, process-ordered identifier (``prefix_000001``)."""
    safe = "".join(ch for ch in str(prefix) if ch in _SAFE) or "id"
    return f"{safe}_{_Counter.next():06d}"


__all__ = ["new_id", "sequence_id"]
