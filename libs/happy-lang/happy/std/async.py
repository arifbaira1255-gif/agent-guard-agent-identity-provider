"""``std.async`` — async & concurrency helpers for Happy.

The names re-exported here are the runtime primitives from
:mod:`happy.runtime.async_runtime`.  ``async`` is a Python keyword, so this
module can only be imported dynamically::

    import importlib
    mod = importlib.import_module("happy.std.async")

(the generated program never imports it by name — the runtime context binds its
public functions directly into module globals).
"""

from __future__ import annotations

from typing import Any, Awaitable, List, Optional, Sequence

from ..runtime.async_runtime import (
    Channel,
    Scheduler,
    Task,
    await_all,
    gather,
    select,
    sleep,
    spawn,
)

__all__ = [
    "Task",
    "Channel",
    "spawn",
    "gather",
    "await_all",
    "sleep",
    "select",
    "channel",
    "PUBLIC",
]

PUBLIC = ["Task", "Channel", "spawn", "gather", "await_all", "sleep", "select", "channel"]


def channel(capacity: int = 0, name: str = "channel", __ctx__: Any = None) -> Channel:
    """Create a buffered :class:`~happy.runtime.async_runtime.Channel`."""
    return Channel(capacity=capacity, name=name)
