"""``std.net`` — capability-gated networking for Happy.

Every outbound operation requires the ``net`` capability, enforced through the
active runtime capability checker.  Built on the Python standard library only.
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from typing import Any, Optional

from ..runtime.errors import HappyRuntimeError

__all__ = [
    "http_get",
    "http_request",
    "http_post",
    "download",
    "tcp_connect",
    "tcp_send",
    "use_checker",
    "PUBLIC",
]

PUBLIC = [
    "http_get",
    "http_request",
    "http_post",
    "download",
    "tcp_connect",
    "tcp_send",
]

_CHECKER: Any = None


def use_checker(checker: Any) -> None:
    global _CHECKER
    _CHECKER = checker


def _authorize(operation: str, loc: Optional[object] = None) -> None:
    if _CHECKER is None:
        return
    # These modules name the abstract *action* directly, so route through
    # ``require_action`` when the checker offers it.
    require = getattr(_CHECKER, "require_action", None)
    if callable(require):
        require(operation, loc=loc)
    else:  # pragma: no cover - alternate checker
        _CHECKER.check_operation(operation, loc=loc)

def http_request(
    method: str,
    url: str,
    body: Optional[str] = None,
    headers: Optional[dict] = None,
    timeout: float = 30.0,
) -> str:
    _authorize("net")
    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method.upper())
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:  # pragma: no cover - network
        raise HappyRuntimeError(
            message=f"network request failed: {exc.reason}", code="R5010"
        ) from exc


def http_get(url: str, headers: Optional[dict] = None, timeout: float = 30.0) -> str:
    return http_request("GET", url, None, headers, timeout)


def http_post(
    url: str, body: str = "", headers: Optional[dict] = None, timeout: float = 30.0
) -> str:
    return http_request("POST", url, body, headers, timeout)


def download(url: str, path: str, timeout: float = 60.0) -> str:
    """Download ``url`` to ``path`` (needs both ``net`` and ``file_write``)."""
    _authorize("net")
    _authorize("file_write")
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        payload = resp.read()
    with open(path, "wb") as fh:
        fh.write(payload)
    return path


def tcp_connect(host: str, port: int, timeout: float = 10.0) -> "socket.socket":
    _authorize("net")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, int(port)))
    except OSError as exc:  # pragma: no cover - network
        sock.close()
        raise HappyRuntimeError(
            message=f"tcp connect failed: {exc}", code="R5011"
        ) from exc
    return sock


def tcp_send(sock: "socket.socket", data: str) -> int:
    _authorize("net")
    return sock.sendall(data.encode("utf-8")) or 0
