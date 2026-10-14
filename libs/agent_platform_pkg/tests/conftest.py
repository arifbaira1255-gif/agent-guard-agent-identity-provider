"""Shared fixtures for the platform test suite (offline: no network, no real model)."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# The platform lives beside the contract; make both importable the same way the suite is run.
_HERE = Path(__file__).resolve()
_INTEGRATION = _HERE.parents[1]
for _extra in (_INTEGRATION / "contract", _INTEGRATION / "platform"):
    if str(_extra) not in sys.path:
        sys.path.insert(0, str(_extra))

from agent_platform.cli import build_agent  # noqa: E402
from agent_platform.config import PlatformConfig  # noqa: E402
from agent_platform.router import DeterministicProvider  # noqa: E402
from agent_platform.tools import AllowAllGate, DenyAllGate, ToolGuard, ToolRegistry  # noqa: E402


@pytest.fixture()
def workspace(tmp_path: Path) -> str:
    """A throwaway agent workspace with one known file."""
    (tmp_path / "notes.txt").write_text("hello from the workspace\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "nested.txt").write_text("nested\n", encoding="utf-8")
    return str(tmp_path)


@pytest.fixture()
def dev_config() -> PlatformConfig:
    return PlatformConfig(enabled=True, environment="development")


@pytest.fixture()
def agent_factory(dev_config: PlatformConfig, workspace: str):
    """Build an agent with a scripted provider and a chosen gate."""

    def _make(script, *, gate=None, config=None, sandbox=None, memory=None, tracer=None):
        provider = DeterministicProvider(script)
        return build_agent(config or dev_config, gate=gate or AllowAllGate(),
                           provider=provider, workspace_root=workspace), provider

    return _make


@pytest.fixture()
def empty_registry() -> ToolRegistry:
    return ToolRegistry()


@pytest.fixture()
def deny_guard(empty_registry: ToolRegistry) -> ToolGuard:
    return ToolGuard(empty_registry, gate=DenyAllGate())
