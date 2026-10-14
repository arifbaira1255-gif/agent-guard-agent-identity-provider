"""Pytest configuration for the AQL-1 Python SDK tests.

The SDK's own ``pyproject.toml`` enables ``asyncio_mode = "auto"``, but when
these tests are collected by a *parent* project's pytest run (for example the
AQL-1 backend suite, whose ini does not enable auto mode), the async tests
would be silently skipped. Force auto mode here so they always execute.
"""

from __future__ import annotations

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Enable asyncio auto mode unless the caller already opted into it."""
    if getattr(config.option, "asyncio_mode", None) in (None, "strict"):
        config.option.asyncio_mode = "auto"
