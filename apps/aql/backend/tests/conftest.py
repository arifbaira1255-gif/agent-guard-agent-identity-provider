"""Shared pytest configuration for the AQL-1 backend test suite.

The REST API ships with authentication **enabled** by default (the safe
production posture). The pre-existing tests exercise the unauthenticated
surface, so the suite runs with ``AUTH_ENABLED=false`` and the auth tests opt
back in explicitly via ``create_app(auth_enabled=True)``.

This must run before any test module imports ``main`` — pytest loads
``conftest.py`` first, which is exactly the guarantee we need.
"""

from __future__ import annotations

import os

# Deterministic for the whole suite: never inherit a developer's local .env.
os.environ["AUTH_ENABLED"] = "false"

# Legacy tests exercise real tool execution. Production defaults are SAFE (python_exec disabled,
# not on the allow-list); the suite opts in explicitly, in a development environment only.
# The secure defaults themselves are covered by tests/test_secure_tools.py.
os.environ["APP_ENV"] = "development"
os.environ["TOOL_GATE_MODE"] = "local"
os.environ["TOOL_ALLOWLIST"] = "echo,now,web_search,python_exec,file_generator,happy_run"
os.environ["PYTHON_EXEC_MODE"] = "unsafe_dev"
