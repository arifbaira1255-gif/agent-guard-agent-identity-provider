"""In-process tracing and metrics: enough evidence to explain a run, no external dependency.

WHAT IT IS FOR
--------------
When a run produces the wrong answer, the operator needs to answer three questions without
re-running it: *where did the time go*, *which model call and which tool call happened, in what
order*, and *what did each cost*.  Spans give the first two, counters and histograms give the third.

WHAT IT DELIBERATELY IS NOT
---------------------------
It is not a distributed tracing system and it does not try to replace one.  Spans are plain objects in
memory; :meth:`Tracer.export` produces the OTLP-shaped dictionaries an exporter would send, so a real
backend can be added later without touching a single call site.

REDACTION
---------
Span attributes pass through :func:`~agent_platform.validation.redact` on the way out, so a prompt or
an argument can never leak into a trace by accident -- even when a caller passes a whole request
object as an attribute.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from .ids import new_id
from .validation import redact, truncate

__all__ = ["Span", "Tracer", "Metrics", "NOOP_TRACER"]

_MAX_ATTRIBUTE_CHARS = 2048


@dataclass
class Span:
    """One timed operation.  ``finish`` is idempotent -- a double finish keeps the first result."""

    trace_id: str
    span_id: str
    name: str
    parent_id: Optional[str] = None
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    status: str = "running"

    @property
    def duration_ms(self) -> float:
        end = self.finished_at if self.finished_at is not None else time.time()
        return round((end - self.started_at) * 1000.0, 3)

    def set(self, **attributes: Any) -> "Span":
        for key, value in attributes.items():
            self.attributes[str(key)] = value
        return self

    def add_event(self, name: str, **attributes: Any) -> None:
        self.events.append({"name": name, "timestamp": time.time(),
                            "attributes": dict(attributes)})

    def finish(self, *, error: Optional[str] = None, **attributes: Any) -> "Span":
        if self.finished_at is not None:
            return self
        self.set(**attributes)
        self.finished_at = time.time()
        if error:
            self.error = str(error)
            self.status = "error"
        else:
            self.status = "ok"
        return self

    def to_dict(self) -> dict:
        out: Dict[str, Any] = {
            "trace_id": self.trace_id, "span_id": self.span_id, "name": self.name,
            "duration_ms": self.duration_ms, "status": self.status,
            "attributes": redact(self.attributes),
            "started_at": self.started_at,
        }
        if self.parent_id:
            out["parent_span_id"] = self.parent_id
        if self.finished_at is not None:
            out["finished_at"] = self.finished_at
        if self.error:
            out["error"] = self.error
        if self.events:
            out["events"] = [{"name": e["name"], "timestamp": e["timestamp"],
                              "attributes": redact(e["attributes"])} for e in self.events]
        return out


class Metrics:
    """Thread-safe counters and histograms with a Prometheus-shaped text export."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, float] = {}
        self._observations: Dict[str, List[float]] = {}

    def counter(self, name: str, value: float = 1.0) -> float:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0.0) + float(value)
            return self._counters[name]

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            bucket = self._observations.setdefault(name, [])
            bucket.append(float(value))
            if len(bucket) > 10_000:  # bounded: a hot loop must not grow this without limit
                del bucket[:2000]

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            out: Dict[str, Any] = {"counters": dict(self._counters)}
            histograms: Dict[str, Any] = {}
            for name, values in self._observations.items():
                if not values:
                    continue
                ordered = sorted(values)
                histograms[name] = {
                    "count": len(ordered),
                    "min": round(ordered[0], 6),
                    "max": round(ordered[-1], 6),
                    "mean": round(sum(ordered) / len(ordered), 6),
                    "p50": round(ordered[len(ordered) // 2], 6),
                    "p95": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 6),
                }
            out["histograms"] = histograms
            return out

    def render(self) -> str:
        """Prometheus text exposition (so an existing scrape config can pick it up)."""
        lines: List[str] = []
        with self._lock:
            for name, value in sorted(self._counters.items()):
                lines.append(f"# TYPE {name} counter")
                lines.append(f"{name} {value}")
            for name, values in sorted(self._observations.items()):
                if not values:
                    continue
                ordered = sorted(values)
                lines.append(f"# TYPE {name} histogram")
                lines.append(f"{name}_count {len(ordered)}")
                lines.append(f"{name}_sum {sum(ordered)}")
                lines.append(f'{name}_bucket{{quantile="0.5"}} {ordered[len(ordered) // 2]}')
                lines.append(f'{name}_bucket{{quantile="0.95"}} '
                             f"{ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]}")
        return "\n".join(lines) + "\n"


class Tracer:
    """Creates spans, keeps them bounded in memory, and exports them in an OTLP-shaped form."""

    def __init__(self, *, enabled: bool = True, capacity: int = 1000,
                 metrics: Optional[Metrics] = None,
                 trace_id: Optional[str] = None) -> None:
        self.enabled = bool(enabled)
        self.capacity = max(1, int(capacity))
        self.metrics = metrics or Metrics()
        self.trace_id = trace_id or new_id("trace")
        self._spans: List[Span] = []
        self._lock = threading.Lock()
        self._stack: List[Span] = []

    # -- spans -------------------------------------------------------------------------------
    def span(self, name: str, **attributes: Any) -> Span:
        parent = self._stack[-1] if self._stack else None
        span = Span(trace_id=self.trace_id, span_id=new_id("span", short=True), name=name,
                    parent_id=(parent.span_id if parent else None),
                    attributes=_bound_attributes(attributes))
        if self.enabled:
            with self._lock:
                self._spans.append(span)
                if len(self._spans) > self.capacity:
                    del self._spans[: self.capacity // 4]
        return span

    def start_span(self, name: str, **attributes: Any) -> Span:
        """Open a span and push it as the current parent (pair with :meth:`end_span`)."""
        span = self.span(name, **attributes)
        self._stack.append(span)
        return span

    def end_span(self, span: Span, *, error: Optional[str] = None, **attributes: Any) -> Span:
        span.finish(error=error, **attributes)
        if self._stack and self._stack[-1] is span:
            self._stack.pop()
        elif span in self._stack:
            self._stack.remove(span)
        self.metrics.observe("span_duration_ms", span.duration_ms)
        self.metrics.counter(f"span.{span.name}.count")
        if error:
            self.metrics.counter(f"span.{span.name}.errors")
        return span

    def event(self, name: str, **attributes: Any) -> None:
        if self._stack:
            self._stack[-1].add_event(name, **_bound_attributes(attributes))
        self.metrics.counter(f"event.{name}")

    # -- output ------------------------------------------------------------------------------
    def spans(self) -> List[Span]:
        with self._lock:
            return list(self._spans)

    def export(self) -> Dict[str, Any]:
        """OTLP-shaped export: ``{"resourceSpans": [{"scopeSpans": [{"spans": [...]}]}]}``."""
        with self._lock:
            spans = [s.to_dict() for s in self._spans]
        return {
            "resourceSpans": [{
                "resource": {"attributes": [{"key": "service.name",
                                              "value": {"stringValue": "agent-platform"}}]},
                "scopeSpans": [{"scope": {"name": "agent_platform",
                                           "version": "0.1.0"}, "spans": spans}],
            }],
            "metrics": self.metrics.summary(),
        }

    def reset(self) -> None:
        with self._lock:
            self._spans = []
            self._stack = []

    def __enter__(self) -> "Tracer":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


class _NoopSpan:
    """A span-shaped object for call sites that must not care whether tracing is on."""

    def __init__(self) -> None:
        self.attributes: Dict[str, Any] = {}
        self.duration_ms = 0.0

    def set(self, **attributes: Any) -> "_NoopSpan":
        return self

    def add_event(self, name: str, **attributes: Any) -> None:
        return None

    def finish(self, *args: Any, **kwargs: Any) -> "_NoopSpan":
        return self

    def to_dict(self) -> dict:
        return {}


class _NoopTracer:
    enabled = False

    def span(self, name: str, **attributes: Any) -> _NoopSpan:
        return _NoopSpan()

    def start_span(self, name: str, **attributes: Any) -> _NoopSpan:
        return _NoopSpan()

    def end_span(self, span: Any, **attributes: Any) -> Any:
        return span

    def event(self, name: str, **attributes: Any) -> None:
        return None

    def export(self) -> dict:
        return {"resourceSpans": []}

    def spans(self) -> list:
        return []


NOOP_TRACER = _NoopTracer()


def _bound_attributes(attributes: Mapping[str, Any]) -> Dict[str, Any]:
    """Bound each attribute to a sane size so a huge prompt cannot flood a trace."""
    bounded: Dict[str, Any] = {}
    for key, value in attributes.items():
        if isinstance(value, str) and len(value) > _MAX_ATTRIBUTE_CHARS:
            bounded[str(key)] = truncate(value, _MAX_ATTRIBUTE_CHARS)
        else:
            bounded[str(key)] = value
    return bounded
