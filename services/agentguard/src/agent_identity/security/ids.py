"""Small id helpers for Step 8 (kept local so the security package does not reach into core internals)."""
from __future__ import annotations

import secrets
import uuid


def new_id(prefix: str = "") -> str:
    """A URL-safe, collision-resistant id, optionally namespaced by a short prefix."""
    raw = uuid.uuid4().hex + secrets.token_hex(4)
    return f"{prefix}_{raw}" if prefix else raw
