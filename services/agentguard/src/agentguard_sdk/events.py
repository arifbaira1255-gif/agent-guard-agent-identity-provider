"""Security-event reporting with correlation ids.

Events are buffered and flushed in batches. The reporter is secret-safe by construction: it only
accepts a closed set of non-secret fields, and any value that looks like bearer material is
redacted before it leaves the process (reusing the core library's redaction rule).
"""
from __future__ import annotations

import threading
import time
from typing import List, Optional

from .models import SecurityEvent

_ALLOWED_METADATA_KEYS = frozenset({
    "tool", "action", "resource", "decision_id", "policy", "latency_ms", "attempt",
    "status", "endpoint", "reason", "outcome", "session_id", "user_id",
})


def _redact(value):
    from agent_identity.observability.logging import SecurityLogger
    return SecurityLogger._clean(value)


class SecurityEventReporter:
    def __init__(self, client, *, buffer_size: int = 100, auto_flush: bool = True,
                 path: str = "/v1/security/events"):
        self._client = client
        self._path = path
        self._buffer: List[dict] = []
        self._lock = threading.Lock()
        self._buffer_size = max(1, int(buffer_size))
        self._auto_flush = auto_flush

    def report(self, event_type: str, *, outcome: str = "ok", correlation_id: Optional[str] = None,
               action: Optional[str] = None, resource: Optional[str] = None,
               reason: Optional[str] = None, metadata: Optional[dict] = None) -> SecurityEvent:
        cred = self._client.authenticator.credentials.current()
        ev = SecurityEvent(
            event_type=event_type, outcome=outcome, correlation_id=correlation_id,
            agent_id=(cred.agent_id if cred else self._client.agent_id),
            instance_id=(cred.instance_id if cred else self._client.instance_id),
            org_id=(cred.org_id if cred else None), action=action, resource=resource, reason=reason,
            metadata=self._clean_metadata(metadata))
        with self._lock:
            self._buffer.append(ev.to_dict())
            full = len(self._buffer) >= self._buffer_size
        if full and self._auto_flush:
            self.flush()
        return ev

    @staticmethod
    def _clean_metadata(metadata: Optional[dict]) -> Optional[dict]:
        if not metadata:
            return None
        out = {}
        for k, v in metadata.items():
            if k not in _ALLOWED_METADATA_KEYS:
                continue
            out[k] = _redact(v)
        return out or None

    def flush(self) -> int:
        with self._lock:
            if not self._buffer:
                return 0
            batch, self._buffer = self._buffer, []
        try:
            self._client._transport.request("POST", self._path, body={"events": batch},
                                            expect=(200, 201, 202, 204))
        except Exception:                                # noqa: BLE001 - reporting must never break the agent
            with self._lock:
                self._buffer = batch + self._buffer       # keep for a later flush
            return 0
        return len(batch)

    def pending(self) -> int:
        with self._lock:
            return len(self._buffer)
