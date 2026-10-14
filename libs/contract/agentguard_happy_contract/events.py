"""Security-event forwarding from Happy LANG to AgentGuard's audit chain.

The audit gap across the seam (threat T9 in the Step 1 audit) is that a denial inside Happy LANG
never reached AgentGuard's tamper-evident audit chain.  :class:`EventForwarder` closes it: it
buffers :class:`SecurityEvent` objects and posts them, in bounded batches, to AgentGuard's EXISTING
``POST /v1/security/events`` route, which already routes them through the server-side security
logger (allow-listed fields, bearer material redacted).

Reporting is best-effort by construction: it must never break the program it is instrumenting, and
it must never block a denial.  A failed flush keeps the events for a later attempt.
"""
from __future__ import annotations

import json
import ssl
import threading
import urllib.error
import urllib.request
from typing import Callable, List, Optional, Sequence

from .config import IntegrationConfig
from .models import SecurityEvent
from .validation import canonical_json

#: A sink receives a bounded batch of already-sanitised event dictionaries.
EventSink = Callable[[List[dict]], bool]


class EventForwarder:
    """Buffer and forward Happy LANG security events to AgentGuard."""

    def __init__(self, sink: Optional[EventSink] = None, *, buffer_size: int = 100,
                 auto_flush: bool = True, enabled: bool = True) -> None:
        self._sink = sink
        self._buffer: List[dict] = []
        self._lock = threading.Lock()
        self._buffer_size = max(1, int(buffer_size))
        self._auto_flush = bool(auto_flush)
        self._enabled = bool(enabled)

    # -- reporting ---------------------------------------------------------------------------
    def report(self, event: SecurityEvent) -> Optional[dict]:
        """Buffer one event.  Never raises -- reporting must not affect execution."""
        if not self._enabled:
            return None
        try:
            event.validate()
            payload = event.to_dict()
        except Exception:                                    # noqa: BLE001 - never break the caller
            return None
        with self._lock:
            self._buffer.append(payload)
            full = len(self._buffer) >= self._buffer_size
        if full and self._auto_flush:
            self.flush()
        return payload

    def report_many(self, events: Sequence[SecurityEvent]) -> int:
        count = 0
        for event in events:
            if self.report(event) is not None:
                count += 1
        return count

    # -- delivery ----------------------------------------------------------------------------
    def pending(self) -> int:
        with self._lock:
            return len(self._buffer)

    def flush(self) -> int:
        """Send the buffered batch.  Returns the number of events accepted (0 on any failure)."""
        if self._sink is None:
            with self._lock:
                self._buffer = []
            return 0
        with self._lock:
            if not self._buffer:
                return 0
            batch, self._buffer = self._buffer, []
        try:
            ok = bool(self._sink(batch))
        except Exception:                                    # noqa: BLE001 - best effort
            ok = False
        if not ok:
            with self._lock:
                # Keep the events for a later attempt, bounded so memory cannot grow without limit.
                self._buffer = (batch + self._buffer)[-1000:]
            return 0
        return len(batch)


def _ssl_context(config: IntegrationConfig) -> Optional[ssl.SSLContext]:
    if not config.base_url.startswith("https://"):
        return None
    if not config.verify_tls:
        return ssl._create_unverified_context()              # noqa: S323 - explicit opt-out
    if config.ca_bundle:
        return ssl.create_default_context(cafile=config.ca_bundle)
    return ssl.create_default_context()


def http_event_sink(config: IntegrationConfig, *,
                    on_error: Optional[Callable[[BaseException], None]] = None) -> EventSink:
    """Build an :data:`EventSink` that POSTs to AgentGuard's ``/v1/security/events`` route."""

    def sink(batch: List[dict]) -> bool:
        body = {"events": batch, "contract_version": config and ""}
        body = {"events": batch}
        data = canonical_json(body).encode("utf-8")
        request = urllib.request.Request(config.events_url(), data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", "happy-agentguard-integration/1.0")
        if config.control_plane_token:
            request.add_header("Authorization", f"Bearer {config.control_plane_token}")
        try:
            with urllib.request.urlopen(request, timeout=config.timeout_seconds,
                                       context=_ssl_context(config)) as response:  # noqa: S310
                status = int(getattr(response, "status", 200))
                response.read(config.max_response_bytes)
            return 200 <= status < 300
        except urllib.error.HTTPError as exc:
            if on_error is not None:
                on_error(exc)
            return False
        except Exception as exc:                             # noqa: BLE001 - best effort
            if on_error is not None:
                on_error(exc)
            return False

    return sink


def stdout_event_sink(stream=None) -> EventSink:
    """A trivial sink that writes events as one JSON object per line (for tests/debugging)."""
    import sys

    target = stream if stream is not None else sys.stderr

    def sink(batch: List[dict]) -> bool:
        for event in batch:
            target.write(json.dumps(event, sort_keys=True) + "\n")
        return True

    return sink


__all__ = ["EventForwarder", "EventSink", "http_event_sink", "stdout_event_sink"]
