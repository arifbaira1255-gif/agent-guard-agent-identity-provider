"""Event forwarding: one bounded, redacted sink for everything auditable in the platform.

The platform emits security-relevant facts (authorization decisions, budget refusals, sandbox
refusals, run outcomes).  Those must reach the audit chain WITHOUT the platform becoming a second,
divergent audit system, and without a sensitive payload leaking into it.

Design rules:

* **Best effort, never blocking.**  Reporting an event must never change the outcome of the run it
  describes, so every sink here swallows its own errors and a failed flush keeps the batch buffered.
* **Redacted at the boundary.**  Events pass through :func:`redact` before they are buffered, so no
  later stage -- including a remote sink -- can receive a secret.
* **Bounded.**  The buffer has a capacity and the retained batch keeps a hard ceiling, so a down
  audit endpoint cannot exhaust memory.
"""
from __future__ import annotations

import json
import ssl
import sys
import threading
import time
import urllib.request
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from .config import PlatformConfig
from .validation import canonical_json, redact, truncate

__all__ = [
    "PlatformEvent", "EventSink", "EventBus", "http_event_sink", "recording_sink",
    "stdout_event_sink",
]

#: A sink receives a bounded batch of already-redacted event dictionaries and reports success.
EventSink = Callable[[List[dict]], bool]


class PlatformEvent:
    """A security-relevant platform fact at the moment it happened."""

    __slots__ = ("event_type", "outcome", "timestamp", "correlation_id", "run_id", "agent_id",
                 "action", "resource", "reason", "metadata", "sequence")

    def __init__(self, event_type: str, *, outcome: str = "ok",
                 correlation_id: Optional[str] = None, run_id: Optional[str] = None,
                 agent_id: Optional[str] = None, action: Optional[str] = None,
                 resource: Optional[str] = None, reason: str = "",
                 metadata: Optional[Mapping[str, Any]] = None, sequence: int = 0) -> None:
        if not event_type or not isinstance(event_type, str):
            raise ValueError("event_type must be a non-empty string")
        self.event_type = event_type
        self.outcome = outcome
        self.timestamp = time.time()
        self.correlation_id = correlation_id
        self.run_id = run_id
        self.agent_id = agent_id
        self.action = action
        self.resource = resource
        self.reason = truncate(reason or "", 512)
        self.metadata = dict(metadata or {})
        self.sequence = int(sequence)

    def to_dict(self) -> dict:
        out: Dict[str, Any] = {
            "event_type": self.event_type,
            "outcome": self.outcome,
            "timestamp": self.timestamp,
            "reason": self.reason,
            "metadata": redact(self.metadata),
        }
        for key in ("correlation_id", "run_id", "agent_id", "action", "resource"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        if self.sequence:
            out["sequence"] = self.sequence
        return out


class EventBus:
    """Bounded, thread-safe buffer that fans one event out to zero or more sinks.

    ``record`` is callable with either a :class:`PlatformEvent` or keyword arguments, which is what
    lets the tool guard, the orchestrator and the sandbox bridge share one bus without depending on
    each other's types.
    """

    def __init__(self, sinks: Optional[Sequence[EventSink]] = None, *, capacity: int = 100,
                 enabled: bool = True, max_retained: int = 1000, tracer: Any = None) -> None:
        self._sinks: List[EventSink] = list(sinks or [])
        self._buffer: List[dict] = []
        self._lock = threading.Lock()
        self._capacity = max(1, int(capacity))
        self._max_retained = max(1, int(max_retained))
        self._enabled = bool(enabled)
        self._sequence = 0
        self.tracer = tracer
        self.counters: Dict[str, int] = {}

    # -- registration ------------------------------------------------------------------------
    def add_sink(self, sink: EventSink) -> None:
        if not callable(sink):
            raise ValueError("sink must be callable")
        with self._lock:
            self._sinks.append(sink)

    @property
    def enabled(self) -> bool:
        return self._enabled

    # -- recording ---------------------------------------------------------------------------
    def record(self, event: Optional[PlatformEvent] = None, **fields: Any) -> Optional[dict]:
        """Buffer one event.  Never raises -- reporting must not change a run's outcome."""
        if not self._enabled:
            return None
        try:
            if event is None:
                event = PlatformEvent(**fields)
            with self._lock:
                self._sequence += 1
                event.sequence = self._sequence
            payload = event.to_dict()
            self.counters[event.event_type] = self.counters.get(event.event_type, 0) + 1
            with self._lock:
                self._buffer.append(payload)
                full = len(self._buffer) >= self._capacity
            if self.tracer is not None:
                try:
                    self.tracer.event(event.event_type, outcome=event.outcome,
                                      reason=event.reason)
                except Exception:  # noqa: BLE001
                    pass
            if full:
                self.flush()
            return payload
        except Exception:  # noqa: BLE001 - never break the caller
            return None

    # -- delivery ----------------------------------------------------------------------------
    def pending(self) -> int:
        with self._lock:
            return len(self._buffer)

    def drain(self) -> List[dict]:
        """Take the buffered batch (used by tests and by embedders that own delivery)."""
        with self._lock:
            batch, self._buffer = self._buffer, []
        return batch

    def flush(self) -> int:
        """Deliver to every sink.  Returns the number of events at least one sink accepted."""
        with self._lock:
            if not self._buffer:
                return 0
            batch, self._buffer = self._buffer, []
            sinks = list(self._sinks)
        accepted = 0
        for sink in sinks:
            try:
                if sink(batch):
                    accepted = len(batch)
            except Exception:  # noqa: BLE001 - a bad sink must not lose the batch for the others
                continue
        if accepted == 0 and sinks:
            with self._lock:  # nothing took it: keep it, bounded
                self._buffer = (batch + self._buffer)[-self._max_retained:]
        return accepted

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {"pending": len(self._buffer), "sinks": len(self._sinks),
                    "enabled": self._enabled, "counters": dict(self.counters)}


# ---------------------------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------------------------
def recording_sink(store: Optional[List[dict]] = None) -> EventSink:
    """A sink that appends every event to an in-memory list (tests, assertions on audit)."""
    target = store if store is not None else []

    def sink(batch: List[dict]) -> bool:
        target.extend(batch)
        return True

    sink.events = target  # type: ignore[attr-defined]
    return sink


def stdout_event_sink(stream: Any = None) -> EventSink:
    """Write one JSON object per line.  Debug aid: never enable it where logs are shared."""
    target = stream if stream is not None else sys.stderr

    def sink(batch: List[dict]) -> bool:
        for event in batch:
            target.write(json.dumps(event, sort_keys=True) + "\n")
        return True

    return sink


def _ssl_context(config: PlatformConfig) -> Optional[ssl.SSLContext]:
    if not config.events_url().startswith("https://"):
        return None
    if not config.verify_tls:
        return ssl._create_unverified_context()  # noqa: S323 - explicit opt-in only
    if config.ca_bundle:
        return ssl.create_default_context(cafile=config.ca_bundle)
    return ssl.create_default_context()


def http_event_sink(config: PlatformConfig, *,
                    on_error: Optional[Callable[[BaseException], None]] = None) -> EventSink:
    """POST batches to AgentGuard's existing ``/v1/security/events`` route.

    Reusing the route the integration contract already targets means the platform's events land in
    the SAME audit chain as Happy LANG's, rather than a parallel one.
    """
    url = config.events_url()

    def sink(batch: List[dict]) -> bool:
        data = canonical_json({"events": batch}).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", "agentguard-agent-platform/0.1")
        if config.api_key:
            request.add_header("Authorization", f"Bearer {config.api_key}")
        try:
            with urllib.request.urlopen(request, timeout=float(config.auth_timeout_s),
                                        context=_ssl_context(config)) as response:  # noqa: S310
                status = int(getattr(response, "status", 200))
                response.read(int(config.max_response_bytes))
            return 200 <= status < 300
        except Exception as exc:  # noqa: BLE001 - best effort by design
            if on_error is not None:
                on_error(exc)
            return False

    return sink
