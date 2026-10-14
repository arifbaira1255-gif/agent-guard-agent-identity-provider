"""Framework adapters for AI-agent tool calling.

Only adapters that are actually implemented and tested are exported here. The generic
:class:`ToolGuard` works with ANY tool-calling framework (it wraps a plain callable), so it is the
supported integration today. Framework-specific adapters (LangChain, OpenAI function calling, MCP,
\u2026) are a documented extension point \u2014 see ``docs/STEP9_SDK.md`` \u2014 and are NOT claimed as
supported until implemented and tested.
"""
from .tool_guard import GuardedTool, ToolGuard, ToolGuardError

__all__ = ["ToolGuard", "GuardedTool", "ToolGuardError"]
