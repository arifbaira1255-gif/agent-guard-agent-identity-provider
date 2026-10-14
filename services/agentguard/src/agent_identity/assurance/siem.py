"""Phase 7 SIEM / security-operations integration framework.

A modular exporter that sends normalized security events to supported platforms:

  * ``syslog_tls``   -- RFC 5424 over TLS (the preferred syslog transport),
  * ``syslog_tcp``   -- RFC 5424 over plain TCP (refused in production unless explicitly allowed),
  * ``http``         -- generic JSON over HTTPS,
  * ``splunk_hec``   -- Splunk HTTP Event Collector,
  * ``elastic_bulk`` -- Elasticsearch ``_bulk`` NDJSON,
  * ``webhook``      -- generic signed JSON webhook.

Guarantees
----------
* **TLS verification** is enforced (``siem_require_tls`` / ``siem_verify_tls``); a plaintext
  transport is refused in production.
* **Credentials never appear in logs**: the exporter redacts a closed set of field names AND any
  value that looks like a secret, and it never logs the destination's secret material.
* **Tenant + data-classification controls** are applied BEFORE export: an event whose classification
  is not in ``siem_allowed_classifications`` is suppressed (recorded, not silently dropped).
* **Bounded retries** with exponential backoff + jitter, **rate limiting**, **batching** and
  **backpressure** (``reject`` fails closed and surfaces the condition; ``drop_oldest`` is explicit).
* **Delivery status** is recorded per (destination, event) so a failure is visible, never silent.
* A SIEM outage does NOT stop the security plane (``siem_fail_closed`` defaults to False), but the
  failure is always recorded and surfaced.

Honesty: a vendor integration is only "production-ready" once it has been tested against the actual
supported interface. The transports here are code-complete and unit-tested against a fake transport;
the live vendor endpoints are NOT verified in this environment (see the limitations doc).
"""
from __future__ import annotations

import json
import random
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections import deque
from typing import Dict, List, Optional, Sequence, Tuple

from ..observability.logging import SecurityLogger
from ..security.ids import new_id
from .config import AssuranceConfig, SIEM_TRANSPORTS
from .errors import BackpressureError, RedactionError, SiemConfigError, SiemDeliveryError
from .models import DeliveryStatus, SiemDelivery, SiemEvent, normalize_severity
from .store import AssuranceStore

#: Values that look like secrets are redacted even if the field name is not on the list.
_LOOKS_SECRET = re.compile(r"(agp1\.|-----BEGIN|^[A-Za-z0-9_\-]{80,}$|^Bearer\s)", re.I)
_REDACTED = "[REDACTED]"


# --------------------------------------------------------------------------- redaction
def redact_fields(fields: Optional[dict], *, redact_names: Sequence[str],
                  max_depth: int = 6) -> dict:
    """Return a redacted copy of ``fields``. Never mutates the input.

    A field is redacted when its (lowercased) name contains any configured redact token, or when its
    value looks like a secret. Nested dicts/lists are walked to a bounded depth.
    """
    names = tuple(n.lower() for n in redact_names)

    def walk(value, depth: int):
        if depth > max_depth:
            return "[TRUNCATED]"
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if not isinstance(k, str):
                    continue
                if any(tok in k.lower() for tok in names):
                    out[k] = _REDACTED
                else:
                    out[k] = walk(v, depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            return [walk(v, depth + 1) for v in value[:100]]
        if isinstance(value, str):
            if _LOOKS_SECRET.search(value):
                return _REDACTED
            return value[:2048]
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        return str(value)[:256]

    return walk(fields or {}, 0)


# --------------------------------------------------------------------------- transports
class Transport(ABC):
    """A delivery transport. ``send`` raises ``SiemDeliveryError`` on failure."""

    kind = "abstract"
    supports_tls = True

    def __init__(self, *, config: AssuranceConfig, verify_tls: bool = True, timeout: int = 10):
        self.cfg = config
        self.verify_tls = verify_tls
        self.timeout = timeout

    @abstractmethod
    def send(self, events: Sequence[SiemEvent]) -> None: ...

    def health(self) -> bool:
        return True


class FakeTransport(Transport):
    """In-memory transport for tests. Records what it received; can be told to fail."""

    kind = "fake"

    def __init__(self, *, fail_times: int = 0, **kw):
        super().__init__(**kw)
        self.received: List[dict] = []
        self.fail_times = fail_times
        self.calls = 0

    def send(self, events: Sequence[SiemEvent]) -> None:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise SiemDeliveryError("simulated transport failure")
        for e in events:
            self.received.append(e.to_export())


class SyslogTransport(Transport):
    """RFC 5424 syslog over TCP or TLS. TLS verification is enforced when ``use_tls``."""

    kind = "syslog"

    def __init__(self, *, host: str, port: int, use_tls: bool = True, facility: int = 13,
                 app_name: str = "agentguard", ca_cert: Optional[str] = None, **kw):
        super().__init__(**kw)
        self.host = host
        self.port = int(port)
        self.use_tls = bool(use_tls)
        self.facility = int(facility)
        self.app_name = app_name
        self.ca_cert = ca_cert
        if self.use_tls and not self.verify_tls:
            raise SiemConfigError("syslog TLS requires certificate verification")

    def _pri(self, severity: str) -> int:
        sev_map = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
        return self.facility * 8 + sev_map.get(normalize_severity(severity), 4)

    def _frame(self, e: SiemEvent) -> bytes:
        payload = json.dumps(e.to_export(), sort_keys=True, separators=(",", ":"), default=str)
        msg = f"<{self._pri(e.severity)}>1 - {self.app_name} - - - {payload}"
        return (msg + "\n").encode("utf-8")

    def send(self, events: Sequence[SiemEvent]) -> None:
        try:
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as e:
            raise SiemDeliveryError("syslog connection failed") from e
        try:
            if self.use_tls:
                ctx = ssl.create_default_context(cafile=self.ca_cert)
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                raw = ctx.wrap_socket(raw, server_hostname=self.host)
            for e in events:
                raw.sendall(self._frame(e))
        except (OSError, ssl.SSLError) as e:
            raise SiemDeliveryError("syslog send failed") from e
        finally:
            try:
                raw.close()
            except OSError:
                pass


class HttpTransport(Transport):
    """Generic JSON-over-HTTPS transport. Used for ``http``, ``splunk_hec`` and ``webhook``."""

    kind = "http"

    def __init__(self, *, url: str, headers: Optional[dict] = None, token: Optional[str] = None,
                 auth_header: str = "Authorization", auth_scheme: str = "Bearer",
                 body_builder=None, **kw):
        super().__init__(**kw)
        if not url.lower().startswith("https://") and self.cfg.siem_require_tls:
            raise SiemConfigError("a plaintext HTTP SIEM endpoint is not permitted")
        self.url = url
        self.headers = dict(headers or {})
        self.token = token
        self.auth_header = auth_header
        self.auth_scheme = auth_scheme
        self.body_builder = body_builder

    def _body(self, events: Sequence[SiemEvent]) -> bytes:
        if self.body_builder is not None:
            return self.body_builder(events)
        return json.dumps({"events": [e.to_export() for e in events]},
                          separators=(",", ":"), default=str).encode("utf-8")

    def send(self, events: Sequence[SiemEvent]) -> None:
        headers = {"Content-Type": "application/json", **self.headers}
        if self.token:
            headers[self.auth_header] = f"{self.auth_scheme} {self.token}".strip()
        req = urllib.request.Request(self.url, data=self._body(events), headers=headers,
                                     method="POST")
        ctx = None
        if self.url.lower().startswith("https://"):
            ctx = ssl.create_default_context()
            if not self.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                if resp.status >= 300:
                    raise SiemDeliveryError(f"http status {resp.status}")
        except urllib.error.HTTPError as e:
            raise SiemDeliveryError(f"http status {e.code}") from e
        except (urllib.error.URLError, OSError, ssl.SSLError) as e:
            raise SiemDeliveryError("http delivery failed") from e


class ElasticBulkTransport(Transport):
    """Elasticsearch ``_bulk`` NDJSON transport."""

    kind = "elastic_bulk"

    def __init__(self, *, url: str, index: str = "agentguard", token: Optional[str] = None, **kw):
        super().__init__(**kw)
        if not url.lower().startswith("https://") and self.cfg.siem_require_tls:
            raise SiemConfigError("a plaintext Elastic endpoint is not permitted")
        self.url = url.rstrip("/")
        self.index = index
        self.token = token

    def _body(self, events: Sequence[SiemEvent]) -> bytes:
        lines = []
        for e in events:
            lines.append(json.dumps({"index": {"_index": self.index, "_id": e.event_id}}))
            lines.append(json.dumps(e.to_export(), separators=(",", ":"), default=str))
        return ("\n".join(lines) + "\n").encode("utf-8")

    def send(self, events: Sequence[SiemEvent]) -> None:
        headers = {"Content-Type": "application/x-ndjson"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(f"{self.url}/_bulk", data=self._body(events),
                                     headers=headers, method="POST")
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                if resp.status >= 300:
                    raise SiemDeliveryError(f"elastic status {resp.status}")
        except urllib.error.HTTPError as e:
            raise SiemDeliveryError(f"elastic status {e.code}") from e
        except (urllib.error.URLError, OSError, ssl.SSLError) as e:
            raise SiemDeliveryError("elastic delivery failed") from e


def build_transport(kind: str, *, config: AssuranceConfig, **kw) -> Transport:
    """Construct a transport by kind. Raises ``SiemConfigError`` for an unknown/unsafe kind."""
    if kind not in SIEM_TRANSPORTS:
        raise SiemConfigError(f"unknown SIEM transport: {kind}")
    verify = kw.pop("verify_tls", config.siem_verify_tls)
    timeout = kw.pop("timeout", config.siem_timeout_s)
    if kind == "syslog_tls":
        return SyslogTransport(config=config, use_tls=True, verify_tls=verify, timeout=timeout, **kw)
    if kind == "syslog_tcp":
        if config.siem_require_tls:
            raise SiemConfigError("syslog_tcp is not permitted while siem_require_tls is set")
        return SyslogTransport(config=config, use_tls=False, verify_tls=False, timeout=timeout, **kw)
    if kind == "http":
        return HttpTransport(config=config, verify_tls=verify, timeout=timeout, **kw)
    if kind == "splunk_hec":
        url = kw.pop("url")
        token = kw.pop("token", None)
        return HttpTransport(config=config, url=url, token=token, auth_header="Authorization",
                             auth_scheme="Splunk", verify_tls=verify, timeout=timeout, **kw)
    if kind == "webhook":
        return HttpTransport(config=config, verify_tls=verify, timeout=timeout, **kw)
    if kind == "elastic_bulk":
        return ElasticBulkTransport(config=config, verify_tls=verify, timeout=timeout, **kw)
    raise SiemConfigError(f"unknown SIEM transport: {kind}")


# --------------------------------------------------------------------------- destination
class SiemDestination:
    """A configured export target: a transport plus its tenant/classification scope."""

    def __init__(self, destination_id: str, transport: Transport, *, org_id: Optional[str] = None,
                 min_severity: str = "info", categories: Optional[Sequence[str]] = None,
                 enabled: bool = True):
        self.destination_id = destination_id
        self.transport = transport
        self.org_id = org_id
        self.min_severity = normalize_severity(min_severity)
        self.categories = tuple(categories) if categories else None
        self.enabled = enabled

    def accepts(self, e: SiemEvent) -> bool:
        from .models import severity_rank
        if not self.enabled:
            return False
        if self.org_id is not None and e.org_id != self.org_id:
            return False
        if severity_rank(e.severity) < severity_rank(self.min_severity):
            return False
        if self.categories is not None and e.category not in self.categories:
            return False
        return True


# --------------------------------------------------------------------------- service
class SiemService:
    """Export pipeline: classification gate -> redaction -> queue -> batch -> retry -> status."""

    def __init__(self, store: AssuranceStore, *, config: Optional[AssuranceConfig] = None,
                 logger: Optional[SecurityLogger] = None, clock=None, sleep=time.sleep):
        self.store = store
        self.cfg = config or AssuranceConfig()
        self.logger = logger
        self._clock = clock
        self._sleep = sleep
        self._destinations: Dict[str, SiemDestination] = {}
        self._queue: deque = deque()
        self._lock = threading.RLock()
        self._rate_window: deque = deque()
        self._metrics = {"queued": 0, "delivered": 0, "failed": 0, "suppressed": 0,
                         "retried": 0, "backpressure": 0, "dead_letter": 0}

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ destinations
    def register_destination(self, destination_id: str, transport: Transport, *,
                             org_id: Optional[str] = None, min_severity: str = "info",
                             categories: Optional[Sequence[str]] = None,
                             enabled: bool = True) -> SiemDestination:
        d = SiemDestination(destination_id, transport, org_id=org_id, min_severity=min_severity,
                            categories=categories, enabled=enabled)
        with self._lock:
            self._destinations[destination_id] = d
        return d

    def list_destinations(self) -> List[dict]:
        with self._lock:
            return [{"destination_id": d.destination_id, "kind": d.transport.kind,
                     "org_id": d.org_id, "min_severity": d.min_severity, "enabled": d.enabled}
                    for d in self._destinations.values()]

    # ------------------------------------------------------------------ classification gate
    def _classification_allowed(self, e: SiemEvent) -> bool:
        return e.classification in self.cfg.siem_allowed_classifications

    # ------------------------------------------------------------------ enqueue
    def enqueue(self, event: SiemEvent) -> dict:
        """Gate, redact and queue an event for export. Returns a status dict.

        A suppressed event (classification not allowed) is RECORDED, never silently dropped.
        """
        if not self._classification_allowed(event):
            self._metrics["suppressed"] += 1
            self._record_delivery(event, destination_id="*", status=DeliveryStatus.SUPPRESSED.value,
                                  attempts=0, error="classification_not_exportable")
            return {"queued": False, "reason": "classification_not_exportable"}
        # redact before anything is stored or exported
        safe = SiemEvent(**{**event.__dict__,
                            "fields": redact_fields(event.fields,
                                                    redact_names=self.cfg.siem_redact_fields)})
        self.store.put_siem_event(safe)
        with self._lock:
            if len(self._queue) >= self.cfg.siem_queue_max:
                if self.cfg.siem_backpressure_policy == "reject":
                    self._metrics["backpressure"] += 1
                    self._record_delivery(safe, destination_id="*",
                                          status=DeliveryStatus.FAILED.value, attempts=0,
                                          error="backpressure_queue_full")
                    if self.cfg.siem_fail_closed:
                        raise BackpressureError("SIEM delivery queue is full")
                    return {"queued": False, "reason": "backpressure"}
                # drop_oldest: explicit, recorded
                dropped = self._queue.popleft()
                self._metrics["backpressure"] += 1
                self._record_delivery(dropped, destination_id="*",
                                      status=DeliveryStatus.DEAD_LETTER.value, attempts=0,
                                      error="dropped_under_backpressure")
            self._queue.append(safe)
            self._metrics["queued"] += 1
        return {"queued": True, "event_id": safe.event_id}

    # ------------------------------------------------------------------ rate limit
    def _rate_ok(self) -> bool:
        if self.cfg.siem_rate_limit_per_s <= 0:
            return True
        now = self._now()
        with self._lock:
            while self._rate_window and now - self._rate_window[0] > 1.0:
                self._rate_window.popleft()
            if len(self._rate_window) >= self.cfg.siem_rate_limit_per_s:
                return False
            self._rate_window.append(now)
            return True

    # ------------------------------------------------------------------ flush
    def flush(self, *, max_batches: int = 100) -> dict:
        """Drain the queue, delivering in batches with bounded retries. Never raises for a delivery
        failure (it is recorded); raises only for a programming error."""
        delivered = failed = 0
        batches = 0
        while batches < max_batches:
            with self._lock:
                if not self._queue:
                    break
                batch = [self._queue.popleft() for _ in range(min(self.cfg.siem_batch_max,
                                                                  len(self._queue)))]
            batches += 1
            for dest in list(self._destinations.values()):
                targets = [e for e in batch if dest.accepts(e)]
                if not targets:
                    continue
                if not self._rate_ok():
                    # rate limited: re-queue and stop this pass (backpressure, not a drop)
                    with self._lock:
                        self._queue.extendleft(reversed(targets))
                    return {"delivered": delivered, "failed": failed, "batches": batches,
                            "rate_limited": True}
                ok = self._deliver_with_retry(dest, targets)
                if ok:
                    delivered += len(targets)
                else:
                    failed += len(targets)
        return {"delivered": delivered, "failed": failed, "batches": batches, "rate_limited": False}

    def _deliver_with_retry(self, dest: SiemDestination, events: Sequence[SiemEvent]) -> bool:
        attempts = 0
        backoff = self.cfg.siem_retry_backoff_s
        while attempts <= self.cfg.siem_max_retries:
            attempts += 1
            try:
                dest.transport.send(events)
                for e in events:
                    self._record_delivery(e, destination_id=dest.destination_id,
                                          status=DeliveryStatus.DELIVERED.value, attempts=attempts)
                self._metrics["delivered"] += len(events)
                return True
            except Exception as e:                                   # noqa: BLE001
                last = type(e).__name__
                if attempts > self.cfg.siem_max_retries:
                    for ev in events:
                        self._record_delivery(ev, destination_id=dest.destination_id,
                                              status=DeliveryStatus.DEAD_LETTER.value,
                                              attempts=attempts, error=last)
                    self._metrics["dead_letter"] += len(events)
                    self._metrics["failed"] += len(events)
                    if self.logger is not None:
                        self.logger.emit("assurance.siem.delivery_failed",
                                         outcome="error", reason=last,
                                         target_type="siem", target_id=dest.destination_id)
                    return False
                self._metrics["retried"] += 1
                jitter = random.uniform(0, backoff * 0.25)
                self._sleep(min(backoff + jitter, self.cfg.siem_retry_backoff_max_s))
                backoff = min(backoff * 2, self.cfg.siem_retry_backoff_max_s)
        return False

    def _record_delivery(self, event: SiemEvent, *, destination_id: str, status: str, attempts: int,
                         error: Optional[str] = None) -> None:
        d = SiemDelivery(delivery_id=new_id("dlv"), destination_id=destination_id,
                         event_id=event.event_id, org_id=event.org_id, status=status,
                         attempts=attempts, ts=self._now(), last_error=error)
        self.store.put_delivery(d)

    # ------------------------------------------------------------------ health / metrics
    def health(self) -> dict:
        with self._lock:
            qlen = len(self._queue)
        dests = []
        for d in self._destinations.values():
            try:
                ok = bool(d.transport.health())
            except Exception:                                        # noqa: BLE001
                ok = False
            dests.append({"destination_id": d.destination_id, "kind": d.transport.kind,
                          "healthy": ok, "enabled": d.enabled})
        return {"queue_depth": qlen, "queue_max": self.cfg.siem_queue_max,
                "backpressure_policy": self.cfg.siem_backpressure_policy,
                "destinations": dests, "metrics": dict(self._metrics),
                "ready": qlen < self.cfg.siem_queue_max}

    def metrics(self) -> dict:
        return dict(self._metrics)

    def list_deliveries(self, *, destination_id: Optional[str] = None,
                        status: Optional[str] = None, limit: int = 500) -> List[dict]:
        return [d.public_dict() for d in self.store.list_deliveries(
            destination_id=destination_id, status=status, limit=limit)]
