"""Test configuration for the AgentGuard x Happy LANG integration suite.

Adds the integration contract package, the (unmodified) Happy LANG tree and the (unmodified)
AgentGuard tree to ``sys.path`` so the tests exercise the REAL libraries on both sides -- no
mocking of either project, and no modification of their source.
"""
import os
import sys

INTEGRATION = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

for _path in (
    os.path.join(INTEGRATION, "contract"),
    os.path.join(INTEGRATION, "happy-lang"),
    os.path.join(INTEGRATION, "agentguard", "src"),
    os.path.join(INTEGRATION, "agentguard"),
):
    if _path not in sys.path:
        sys.path.insert(0, _path)
