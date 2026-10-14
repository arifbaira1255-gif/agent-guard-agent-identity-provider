"""Minimal MCP (Model Context Protocol) client.

Speaks JSON-RPC 2.0 over stdio to an MCP server process. This is a compact,
dependency-free starting point — extend with SSE/HTTP transports as needed.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MCPServerConfig:
    """How to launch/connect to an MCP server."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)


class MCPClient:
    """Spawns an MCP server and exchanges JSON-RPC messages with it."""

    def __init__(self, config: MCPServerConfig) -> None:
        self.config = config
        self._proc: subprocess.Popen | None = None
        self._next_id = 1

    def start(self) -> None:
        self._proc = subprocess.Popen(  # noqa: S603 — config is trusted
            [self.config.command, *self.config.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**self.config.env} or None,
        )

    def _send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("MCP server not started")
        req_id = self._next_id
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}
        self._proc.stdin.write(json.dumps(payload) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        return json.loads(line) if line else {}

    def initialize(self) -> dict[str, Any]:
        return self._send(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "aql-1", "version": "0.1.0"},
            },
        )

    def list_tools(self) -> list[dict[str, Any]]:
        return self._send("tools/list").get("result", {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._send("tools/call", {"name": name, "arguments": arguments})

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            self._proc = None
