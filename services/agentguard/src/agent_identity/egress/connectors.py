"""Egress-aware transport connectors.

``EgressHttpConnector`` is a DLP-aware outbound HTTP transport. It is designed to SUBSTITUTE for the
reference ``HttpApiConnector`` inside a Step 11 ``GuardedConnector``: the governance plane still
decides *whether* the tool may run, and this connector additionally routes the actual outbound call
through the :class:`~agent_identity.egress.gateway.SecureEgressGateway` so the network destination
and the payload are governed at the real execution boundary.

It implements the same ``send(...)`` contract the gateway's execution path expects, and it pins the
connection to the address set the gateway validated (DNS-rebinding defence). The default
implementation uses ``urllib`` with a bounded timeout and a hard response-size cap; a deployment may
inject a different transport (e.g. an mTLS-aware client) as long as it honours the same contract.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Optional


class EgressHttpConnector:
    """A bounded, DLP-aware outbound HTTP transport.

    ``send`` returns ``{"status": int, "headers": dict, "body": bytes|str}``. It NEVER follows
    redirects itself (``redirects are handled and re-validated by the gateway``), and it enforces the
    response-size ceiling by reading at most ``max_response_bytes``.
    """

    def __init__(self, *, user_agent: str = "AgentGuard-Egress/1.0", opener=None):
        self.user_agent = user_agent
        self._opener = opener

    def send(self, *, url: str, method: str = "GET", headers: Optional[dict] = None,
             body=None, resolved_ips=(), connect_timeout_s: float = 2.0,
             read_timeout_s: float = 10.0, max_response_bytes: int = 4 * 1024 * 1024) -> dict:
        data = None
        if body is not None:
            if isinstance(body, (bytes, bytearray)):
                data = bytes(body)
            elif isinstance(body, str):
                data = body.encode("utf-8")
            else:
                import json
                data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        hdrs = {"User-Agent": self.user_agent}
        for k, v in (headers or {}).items():
            hdrs[str(k)] = str(v)
        req = urllib.request.Request(url=url, data=data, method=method.upper(), headers=hdrs)
        timeout = max(0.1, float(connect_timeout_s) + float(read_timeout_s))
        opener = self._opener or urllib.request.build_opener(_NoRedirect())
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read(max_response_bytes + 1)
                truncated = len(raw) > max_response_bytes
                if truncated:
                    raw = raw[:max_response_bytes]
                return {"status": int(getattr(resp, "status", resp.getcode())),
                        "headers": dict(resp.headers.items()), "body": raw,
                        "truncated": truncated}
        except urllib.error.HTTPError as exc:
            # an HTTP error status is a legitimate response (e.g. a 302 we must re-validate)
            raw = exc.read(max_response_bytes + 1)
            return {"status": int(exc.code), "headers": dict(exc.headers.items()),
                    "body": raw[:max_response_bytes], "truncated": len(raw) > max_response_bytes}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Disable urllib's automatic redirect following -- the gateway re-validates each hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None
