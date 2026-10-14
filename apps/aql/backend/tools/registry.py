"""Tool registry — the catalogue of capabilities an agent may call."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from core.secure_exec import run_happy, run_python
from core.secure_gate import ToolDenied, ToolGate, build_gate


@dataclass
class ToolSpec:
    """Declares one callable tool."""

    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable[..., Any]

    def to_schema(self) -> dict[str, Any]:
        """OpenAI-style function schema."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


def _security_settings() -> Any:
    """Return the app settings, or ``None`` if they cannot be loaded (-> fail closed)."""
    try:
        from core.config import get_settings

        return get_settings()
    except Exception:  # noqa: BLE001
        return None


def build_default_gate() -> ToolGate:
    """Build the gate from settings. Any problem yields a deny-all gate, never an open one."""
    st = _security_settings()
    if st is None:
        return build_gate("deny_all")
    try:
        return build_gate(
            getattr(st, "tool_gate_mode", "local"),
            app_env=getattr(st, "app_env", "development"),
            allow=getattr(st, "tool_allowlist", ""),
            deny=getattr(st, "tool_denylist", ""),
            agentguard_url=getattr(st, "agentguard_url", ""),
            agentguard_token=getattr(st, "agentguard_token", ""),
            agentguard_agent_id=getattr(st, "agentguard_agent_id", "aql-1"),
            agentguard_timeout_seconds=getattr(st, "agentguard_timeout_seconds", 3.0),
            agentguard_allow_insecure_http=getattr(st, "agentguard_allow_insecure_http", False),
            agentguard_verify_tls=getattr(st, "agentguard_verify_tls", True),
            agentguard_client_factory=getattr(st, "agentguard_client_factory", ""),
        )
    except Exception:  # noqa: BLE001 - misconfiguration must not open the gate
        return build_gate("deny_all")


class ToolRegistry:
    """Holds tools and dispatches calls by name - every call passes through the gate."""

    def __init__(self, gate: ToolGate | None = None) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._gate = gate

    @property
    def gate(self) -> ToolGate:
        if self._gate is None:
            self._gate = build_default_gate()
        return self._gate

    def set_gate(self, gate: ToolGate | None) -> None:
        """Install a gate (``None`` -> rebuilt from settings on next use)."""
        self._gate = gate

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def list(self) -> list[ToolSpec]:
        return list(self._tools.values())

    def schemas(self) -> list[dict[str, Any]]:
        return [t.to_schema() for t in self._tools.values()]

    def call(self, name: str, *, _agent_id: str | None = None, **kwargs: Any) -> Any:
        spec = self._tools.get(name)
        if spec is None:
            raise KeyError(f"Unknown tool: {name}")
        decision = self.gate.authorize(name, kwargs, agent_id=_agent_id)
        if not decision.allowed:
            raise ToolDenied(name, decision)
        return spec.handler(**kwargs)

    def posture(self) -> dict[str, Any]:
        """What the gate and the code-execution path are actually doing (no secrets)."""
        from core.secure_exec import isolation_status

        st = _security_settings()
        return {
            "tools": sorted(self._tools),
            "gate": self.gate.describe(),
            "recent_decisions": self.gate.recent(25),
            "python_exec_mode": getattr(st, "python_exec_mode", "disabled") if st else "disabled",
            "isolation": isolation_status(),
        }


# ── Global registry + a couple of built-in demo tools ───────────────────────
registry = ToolRegistry()


def _echo(text: str) -> str:
    return text


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


registry.register(
    ToolSpec(
        name="echo",
        description="Echo back the provided text. Useful for smoke tests.",
        parameters={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
        handler=_echo,
    )
)

registry.register(
    ToolSpec(
        name="now",
        description="Return the current UTC timestamp in ISO-8601 format.",
        parameters={"type": "object", "properties": {}},
        handler=_now,
    )
)


# ── Tools used by the multi-agent orchestrator ─────────────────────────────────────
def _web_search(query: str, max_results: int = 3) -> dict[str, Any]:
    """Offline-safe web search.

    Returns a deterministic, clearly-labelled placeholder result set so the
    orchestrator's search step always produces structured output. Swap this
    handler for a real provider (Tavily, Serper, Bing, ...) in production —
    the return shape (``{"query", "provider", "results": [{title, url,
    snippet}]}``) is what the execution agent expects.
    """
    q = (query or "").strip()
    count = max(1, min(int(max_results or 3), 10))
    return {
        "query": q,
        "provider": "stub",
        "results": [
            {
                "title": f"Result {i + 1} for: {q}",
                "url": f"https://example.com/search?q={q.replace(' ', '+')}&r={i + 1}",
                "snippet": f"Placeholder snippet {i + 1} for '{q}'.",
            }
            for i in range(count)
        ],
    }


def _python_exec(code: str, timeout: int = 5) -> dict[str, Any]:
    """Execute a short Python snippet - isolated, or refused (see ``core/secure_exec.py``)."""
    st = _security_settings()
    return run_python(
        code,
        timeout,
        mode=getattr(st, "python_exec_mode", "disabled") if st else "disabled",
        app_env=getattr(st, "app_env", "production") if st else "production",
    )


def _happy_run(source: str, timeout: int = 10) -> dict[str, Any]:
    """Run a Happy (.hpy) program inside the kernel-enforced jail. No host fallback."""
    return run_happy(source, timeout)


def _file_generator(
    filename: str, content: str = "", output_dir: str = "orchestrator_output"
) -> dict[str, Any]:
    """Write ``content`` to ``output_dir/filename`` and report the path.

    The filename is reduced to a safe basename so a sub-task can never write
    outside the output directory.
    """
    safe = os.path.basename(filename or "output.txt") or "output.txt"
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / safe
    path.write_text(content or "", encoding="utf-8")
    return {
        "path": str(path),
        "filename": safe,
        "bytes": len((content or "").encode("utf-8")),
    }


registry.register(
    ToolSpec(
        name="web_search",
        description=(
            "Search the web for a query and return ranked results "
            "(title, url, snippet)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "max_results": {"type": "integer", "default": 3},
            },
            "required": ["query"],
        },
        handler=_web_search,
    )
)

registry.register(
    ToolSpec(
        name="python_exec",
        description=(
            "Execute a short Python snippet inside an isolated jail and return "
            "its stdout/stderr. Disabled unless isolation is configured."
        ),
        parameters={
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "timeout": {"type": "integer", "default": 5},
            },
            "required": ["code"],
        },
        handler=_python_exec,
    )
)

registry.register(
    ToolSpec(
        name="file_generator",
        description="Write text content to a file and return its path.",
        parameters={
            "type": "object",
            "properties": {
                "filename": {"type": "string"},
                "content": {"type": "string"},
                "output_dir": {"type": "string", "default": "orchestrator_output"},
            },
            "required": ["filename"],
        },
        handler=_file_generator,
    )
)

registry.register(
    ToolSpec(
        name="happy_run",
        description=(
            "Compile and run a Happy (.hpy) program inside a kernel-enforced "
            "jail (contracts + capabilities enforced). Refused if no isolation."
        ),
        parameters={
            "type": "object",
            "properties": {
                "source": {"type": "string"},
                "timeout": {"type": "integer", "default": 10},
            },
            "required": ["source"],
        },
        handler=_happy_run,
    )
)
