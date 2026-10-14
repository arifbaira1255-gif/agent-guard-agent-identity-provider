"""Built-in tools: filesystem, HTTP and a sandboxed code runner, all gated.

Every tool here is ``protected`` and goes through the guard, so none of them can be reached without an
authorization decision.  The filesystem tool additionally enforces a **root jail in-process**: even
when a policy says "allow read_file", a path outside the declared root is refused.  That is defence in
depth -- the platform does not rely on the policy alone to keep an agent inside its workspace.

The HTTP tool denies non-``https`` schemes and refuses a redirect to a different host, so an allowed
destination cannot be turned into an SSRF pivot by a redirect.
"""
from __future__ import annotations

import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .tools import ToolRegistry, ToolSpec

__all__ = ["register_builtin_tools", "register_filesystem_tools", "register_http_tools",
           "register_sandbox_tools", "safe_join", "PathJailError"]

_MAX_READ_BYTES = 64_000
_MAX_LIST_ENTRIES = 200
_MAX_HTTP_BYTES = 64_000


class PathJailError(Exception):
    """A path resolved outside the configured root (the tool-level jail, not the policy)."""


# ---------------------------------------------------------------------------------------------
# Path jail
# ---------------------------------------------------------------------------------------------
def safe_join(root: str, relative: str) -> str:
    """Resolve ``relative`` under ``root``, refusing traversal, symlink escapes and absolute paths.

    ``os.path.realpath`` is applied to BOTH sides so a symlink inside the workspace cannot point out of
    it -- the classic way a naive ``startswith`` check is defeated.
    """
    if not isinstance(relative, str) or not relative:
        raise PathJailError("path must be a non-empty string")
    if "\x00" in relative:
        raise PathJailError("path contains a NUL byte")
    if os.path.isabs(relative) or (len(relative) > 1 and relative[1] == ":"):
        raise PathJailError("absolute paths are not allowed")
    real_root = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(real_root, relative))
    if candidate != real_root and not candidate.startswith(real_root + os.sep):
        raise PathJailError(f"path escapes the workspace root: {relative!r}")
    return candidate


def register_filesystem_tools(registry: ToolRegistry, *, root: str) -> ToolRegistry:
    """Register ``list_dir`` and ``read_file``, both confined to ``root``."""
    real_root = os.path.realpath(root)

    def list_dir(path: str = ".") -> dict:
        target = safe_join(real_root, path)
        if not os.path.isdir(target):
            raise PathJailError(f"not a directory: {path!r}")
        entries = []
        for name in sorted(os.listdir(target)):
            if name.startswith("."):
                continue
            full = os.path.join(target, name)
            entries.append({"name": name, "dir": os.path.isdir(full),
                            "bytes": (os.path.getsize(full) if os.path.isfile(full) else None)})
            if len(entries) >= _MAX_LIST_ENTRIES:
                break
        return {"path": os.path.relpath(target, real_root), "entries": entries}

    def read_file(path: str, max_bytes: int = _MAX_READ_BYTES) -> dict:
        target = safe_join(real_root, path)
        if not os.path.isfile(target):
            raise PathJailError(f"not a file: {path!r}")
        limit = max(1, min(int(max_bytes), _MAX_READ_BYTES))
        with open(target, "rb") as handle:  # noqa: PTH123 - explicit binary read
            raw = handle.read(limit + 1)
        return {"path": os.path.relpath(target, real_root),
                "bytes": len(raw),
                "truncated": len(raw) > limit,
                "text": raw[:limit].decode("utf-8", errors="replace")}

    registry.register(ToolSpec(
        name="list_dir", description="List files in the agent workspace (no contents).",
        parameters={"type": "object", "properties": {
            "path": {"type": "string", "description": "relative directory path"}},
            "additionalProperties": False},
        handler=list_dir, protected=True, action="fs.list", resource_arg="path"))
    registry.register(ToolSpec(
        name="read_file", description="Read a UTF-8 text file from the agent workspace.",
        parameters={"type": "object", "properties": {
            "path": {"type": "string", "description": "relative file path"},
            "max_bytes": {"type": "integer", "minimum": 1, "maximum": _MAX_READ_BYTES}},
            "required": ["path"], "additionalProperties": False},
        handler=read_file, protected=True, action="fs.read", resource_arg="path"))
    return registry


# ---------------------------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------------------------
def register_http_tools(registry: ToolRegistry, *, allowed_hosts: tuple = (),
                        timeout_s: float = 10.0, verify_tls: bool = True) -> ToolRegistry:
    """Register ``http_get``, restricted to https and an optional host allowlist."""
    allowed = {h.lower() for h in (allowed_hosts or ())}

    def http_get(url: str) -> dict:
        parsed = urllib.parse.urlparse(str(url or ""))
        if parsed.scheme != "https":
            raise ValueError(f"only https:// is permitted (got {parsed.scheme or 'no scheme'!r})")
        host = (parsed.hostname or "").lower()
        if not host:
            raise ValueError("url has no host")
        if allowed and host not in allowed:
            raise ValueError(f"host {host!r} is not in the allowlist")
        context = ssl.create_default_context()
        if not verify_tls:
            context = ssl._create_unverified_context()  # noqa: S323 - explicit opt-in only
        request = urllib.request.Request(str(url), method="GET")
        request.add_header("User-Agent", "agentguard-agent-platform/0.1")
        try:
            with urllib.request.urlopen(request, timeout=float(timeout_s),
                                        context=context) as response:  # noqa: S310
                # A redirect to another host would be an SSRF pivot: refuse it.
                final_host = (urllib.parse.urlparse(response.geturl()).hostname or "").lower()
                if final_host != host:
                    raise ValueError(f"redirected to a different host ({final_host!r}); refused")
                raw = response.read(_MAX_HTTP_BYTES + 1)
                status = int(getattr(response, "status", 200))
        except urllib.error.HTTPError as exc:
            return {"url": url, "status": int(getattr(exc, "code", 0)), "ok": False,
                    "error": f"HTTPError {getattr(exc, 'code', '')}"}
        return {"url": url, "status": status, "ok": 200 <= status < 300,
                "truncated": len(raw) > _MAX_HTTP_BYTES,
                "text": raw[:_MAX_HTTP_BYTES].decode("utf-8", errors="replace")}

    registry.register(ToolSpec(
        name="http_get", description="Fetch a URL over https (hosts may be restricted by policy).",
        parameters={"type": "object", "properties": {
            "url": {"type": "string", "minLength": 8}},
            "required": ["url"], "additionalProperties": False},
        handler=http_get, protected=True, action="net.get", resource_arg="url"))
    return registry


# ---------------------------------------------------------------------------------------------
# Sandboxed code execution
# ---------------------------------------------------------------------------------------------
def register_sandbox_tools(registry: ToolRegistry, *, bridge: object) -> ToolRegistry:
    """Register ``run_happy_program``, which executes ONLY inside the secure runtime.

    The handler refuses when the bridge has no usable isolation backend, so this tool can never become
    a host-execution path -- the refusal is structural, not a policy that might be misconfigured.
    """

    def run_happy_program(source: str) -> dict:
        if bridge is None:
            raise ValueError("no secure execution runtime is configured")
        result = bridge.run(source)  # type: ignore[attr-defined]
        return result.to_dict()

    registry.register(ToolSpec(
        name="run_happy_program",
        description="Execute a Happy LANG program inside the OS-isolated secure runtime.",
        parameters={"type": "object", "properties": {
            "source": {"type": "string", "minLength": 1, "maxLength": 1_048_576}},
            "required": ["source"], "additionalProperties": False},
        handler=run_happy_program, protected=True, action="exec.happy", resource_arg="source",
        requires_sandbox=True))
    return registry


def register_builtin_tools(registry: ToolRegistry, *, workspace_root: str = ".",
                           allowed_hosts: tuple = (), sandbox_bridge: object = None,
                           include_http: bool = True, include_sandbox: bool = True) -> ToolRegistry:
    """Register the standard tool set (filesystem always; http/sandbox opt-in)."""
    register_filesystem_tools(registry, root=workspace_root)
    if include_http:
        register_http_tools(registry, allowed_hosts=allowed_hosts)
    if include_sandbox and sandbox_bridge is not None:
        register_sandbox_tools(registry, bridge=sandbox_bridge)
    return registry
