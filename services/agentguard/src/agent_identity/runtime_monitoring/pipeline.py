"""Phase 5 runtime event pipeline: normalization, redaction, sampling, dedup, correlation.

The pipeline is the ONLY path by which raw producer telemetry becomes a stored
:class:`~.models.RuntimeEvent`. Everything it does is designed to be *honest* about the data:

* **Normalize or reject.** A raw dict is validated against a closed event vocabulary. A malformed or
  unknown event is rejected with a reason -- never coerced into a plausible-looking event, because a
  coerced event is indistinguishable from real telemetry downstream.
* **Redact at the boundary.** Content-bearing fields never reach storage (``redaction.py``).
* **Deduplicate.** A replayed/duplicated event is dropped and reported as ``duplicate``.
* **Represent lateness.** An event whose producer timestamp lags the tenant's newest event is stored
  and flagged ``late``; it is never silently dropped and never reordered into a fiction.
* **Correlate without inventing causality.** Events are grouped by trace context when present, else
  by correlation id, else only by time. The resulting :class:`~.models.CorrelationLink` records which
  of those applied and whether a causal (parent/child) relationship was actually established.

Sampling is deterministic (a stable hash of the event id) so a sampled stream is reproducible, and
security-critical event classes are never sampled out.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from ..security.ids import new_id
from . import audit as A
from .audit import RuntimeMonitoringAudit
from .config import MonitoringConfig
from .errors import EventValidationError, TenantBoundaryError
from .models import (DERIVED_EVENT_TYPES, ActionSequence, CorrelationLink, Decision, EventType,
                     FIELD_MAX, RuntimeEvent, Severity)
from .redaction import Redactor, looks_like_secret
from .store import RuntimeMonitoringStore

#: Event classes that are NEVER sampled out (security-critical for investigation/audit).
NEVER_SAMPLED = frozenset({
    EventType.DLP_DETECTION, EventType.DLP_BLOCKED, EventType.AUTHORIZATION_FAILURE,
    EventType.POLICY_ENFORCEMENT_FAILURE, EventType.JIT_GRANT_CREATED, EventType.JIT_GRANT_REVOKED,
    EventType.JIT_GRANT_EXPIRED, EventType.POLICY_CHANGED, EventType.AGENT_TERMINATED,
    EventType.AGENT_IDENTITY_CHANGED, EventType.AGENT_ERROR, EventType.APPROVAL_REQUESTED,
    EventType.APPROVAL_DECIDED,
})

#: Raw fields that must be present for an event to be considered normalizable.
_REQUIRED = ("org_id", "event_type")

#: Aliases producers commonly use, mapped to the canonical field name.
_ALIASES = {
    "type": "event_type", "tenant": "org_id", "tenant_id": "org_id", "timestamp": "ts",
    "time": "ts", "agent": "agent_id", "resource_id": "resource", "operation": "action",
    "traceparent": "trace_id", "user_id": "actor_user_id", "tool": "action",
}


@dataclass
class IngestResult:
    """The outcome of ingesting one raw event.

    ``outcome`` is one of ``stored`` | ``duplicate`` | ``sampled_out`` | ``rejected``. A rejected or
    sampled-out event has ``event is None`` and a machine-readable ``reason``.
    """

    outcome: str
    event: Optional[RuntimeEvent] = None
    reason: Optional[str] = None

    @property
    def stored(self) -> bool:
        return self.outcome == "stored"

    def to_dict(self) -> dict:
        return {"outcome": self.outcome,
                "event": self.event.public_dict() if self.event else None,
                "reason": self.reason}


class RuntimeEventPipeline:
    """Normalizing, redacting, deduplicating ingest path plus correlation/investigation views."""

    def __init__(self, store: RuntimeMonitoringStore, *, config: Optional[MonitoringConfig] = None,
                 redactor: Optional[Redactor] = None,
                 audit: Optional[RuntimeMonitoringAudit] = None, clock=None):
        self.store = store
        self.cfg = config or MonitoringConfig()
        self.redactor = redactor or Redactor(mode=self.cfg.redaction_mode,
                                             max_depth=self.cfg.redaction_max_depth,
                                             drop_payload_fields=self.cfg.drop_payload_fields)
        self.audit = audit or RuntimeMonitoringAudit(store, enabled=self.cfg.audit_enabled,
                                                     clock=clock)
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ normalization
    def normalize(self, raw: dict, *, claimed_org: Optional[str] = None,
                  now: Optional[float] = None) -> RuntimeEvent:
        """Validate + redact one raw event into a :class:`RuntimeEvent`.

        Raises :class:`EventValidationError` for malformed input and :class:`TenantBoundaryError`
        when the event's tenant contradicts the caller's verified tenant.
        """
        if not isinstance(raw, dict):
            raise EventValidationError("event must be a mapping")
        src = {}
        for k, v in raw.items():
            if isinstance(k, str):
                src[_ALIASES.get(k.strip().lower(), k.strip().lower())] = v
            else:
                raise EventValidationError("event keys must be strings")

        for field in _REQUIRED:
            if not src.get(field):
                raise EventValidationError(f"missing required field: {field}")

        org_id = _as_id(src.get("org_id"), "org_id")
        if claimed_org is not None and org_id != claimed_org:
            raise TenantBoundaryError("event org_id does not match the caller's tenant")

        et = EventType.coerce(src.get("event_type"))
        if et is None:
            raise EventValidationError(f"unknown event_type: {src.get('event_type')!r}")
        if et in DERIVED_EVENT_TYPES:
            raise EventValidationError(f"event_type {et.value} is derived and may not be ingested")

        ts = _as_ts(src.get("ts"), "ts")
        current = now if now is not None else self._now()
        if ts > current + self.cfg.max_future_skew_s:
            raise EventValidationError("event timestamp is implausibly far in the future")
        if ts < current - self.cfg.max_event_age_s:
            raise EventValidationError("event timestamp predates the retention horizon")

        latency = src.get("latency_ms")
        if latency is not None:
            try:
                latency = int(latency)
                if latency < 0:
                    raise ValueError
            except (TypeError, ValueError):
                raise EventValidationError("latency_ms must be a non-negative integer")

        extra_raw = src.get("extra") if isinstance(src.get("extra"), dict) else {}
        # Any non-canonical scalar field the producer sent is treated as untrusted metadata and
        # passed through the redactor's allow-list (never stored verbatim unless allow-listed).
        passthrough = {k: v for k, v in src.items()
                       if k not in _CANONICAL and k not in ("extra", "dedup_key")}
        merged_extra = {**passthrough, **extra_raw}
        redacted_extra = self.redactor.redact_extra(merged_extra)
        if merged_extra:
            redacted_extra["_redaction_mode"] = self.redactor.mode

        ev = RuntimeEvent(
            event_id=_as_id(src.get("event_id"), "event_id", required=False) or new_id("rev"),
            event_type=et.value, ts=ts, org_id=org_id,
            agent_id=_as_id(src.get("agent_id"), "agent_id", required=False),
            instance_id=_as_id(src.get("instance_id"), "instance_id", required=False),
            session_id=_as_id(src.get("session_id"), "session_id", required=False),
            action=_opt_str(src.get("action")), resource=_opt_str(src.get("resource")),
            resource_type=_opt_str(src.get("resource_type")),
            decision=Decision.coerce(src.get("decision")).value if src.get("decision") else None,
            reason=_safe_text(self.redactor, src.get("reason")),
            outcome=_opt_str(src.get("outcome")) or "ok",
            policy_id=_opt_str(src.get("policy_id")),
            policy_version=_opt_str(src.get("policy_version")),
            destination=_opt_str(src.get("destination")),
            address_class=_opt_str(src.get("address_class")),
            data_classes=_as_str_tuple(src.get("data_classes")),
            dlp_rule_ids=_as_str_tuple(src.get("dlp_rule_ids")),
            severity=(None if looks_like_secret(str(src.get("severity") or ""))
                      else (Severity.coerce(src.get("severity")).value
                            if src.get("severity") else None)),
            latency_ms=latency,
            correlation_id=_opt_str(src.get("correlation_id")),
            trace_id=_opt_str(src.get("trace_id")),
            span_id=_opt_str(src.get("span_id")),
            parent_span_id=_opt_str(src.get("parent_span_id")),
            actor_user_id=_opt_str(src.get("actor_user_id")),
            task_id=_opt_str(src.get("task_id")),
            ingested_at=current,
            redacted=bool(merged_extra),
            extra=redacted_extra,
            dedup_key=_opt_str(src.get("dedup_key")),
        )
        return ev

    # ------------------------------------------------------------------ ingestion
    def ingest(self, raw: dict, *, claimed_org: Optional[str] = None,
               now: Optional[float] = None) -> IngestResult:
        """Normalize, deduplicate, sample and store one event. Never raises for bad *data*.

        Validation failures are returned as ``IngestResult(outcome="rejected", reason=...)`` so a
        single bad producer cannot take down the ingest path; a tenant-boundary violation is the one
        exception -- it is a security condition and is raised.
        """
        current = now if now is not None else self._now()
        try:
            ev = self.normalize(raw, claimed_org=claimed_org, now=current)
        except TenantBoundaryError:
            raise
        except EventValidationError as e:
            self.audit.record(A.E_INGEST_REJECTED, org_id=_safe_org(raw), outcome="denied",
                              reason=e.code, extra={"detail": str(e)[:200]})
            return IngestResult(outcome="rejected", reason=str(e))

        dedup_key = ev.dedup_key or _derive_dedup_key(ev)
        if self.store.has_dedup_key(org_id=ev.org_id, dedup_key=dedup_key):
            self.audit.record(A.E_INGEST_DUPLICATE, org_id=ev.org_id, agent_id=ev.agent_id,
                              event_id=ev.event_id, reason="duplicate_event")
            return IngestResult(outcome="duplicate", reason="duplicate event")

        latest = self.store.latest_event_ts(org_id=ev.org_id)
        late = latest is not None and ev.ts < latest - self.cfg.late_threshold_s
        sampled = not self._keep(ev)

        ev = RuntimeEvent(**{**ev.__dict__, "dedup_key": dedup_key, "late": late,
                             "sampled": sampled})
        self.store.append_event(ev)
        return IngestResult(outcome="sampled_out" if sampled else "stored", event=ev)

    def ingest_many(self, raws: Iterable[dict], *, claimed_org: Optional[str] = None,
                    now: Optional[float] = None) -> List[IngestResult]:
        """Ingest many events. A tenant-boundary violation in any item still aborts (fail closed)."""
        out = []
        for raw in raws:
            out.append(self.ingest(raw, claimed_org=claimed_org, now=now))
        return out

    def _keep(self, ev: RuntimeEvent) -> bool:
        """Deterministic sampling decision. Security-critical classes are always kept."""
        if not self.cfg.sampling_enabled:
            return True
        if ev.event_type in {t.value for t in NEVER_SAMPLED}:
            return True
        if ev.decision in (Decision.DENY.value, Decision.BLOCKED.value):
            return True
        if ev.severity in (Severity.HIGH.value, Severity.CRITICAL.value):
            return True
        digest = hashlib.sha256(f"{ev.org_id}|{ev.event_id}".encode()).digest()
        frac = int.from_bytes(digest[:8], "big") / float(1 << 64)
        return frac < self.cfg.sampling_rate

    # ------------------------------------------------------------------ correlation
    def correlate(self, *, org_id: str, correlation_id: Optional[str] = None,
                  trace_id: Optional[str] = None, agent_id: Optional[str] = None,
                  since: Optional[float] = None, until: Optional[float] = None) -> ActionSequence:
        """Correlate a run of events into an :class:`ActionSequence`.

        The link's ``established_by`` is ``trace`` when trace context grouped the events, else
        ``correlation_id``, else ``time_ordered_only`` with ``causal=False``. We never claim a causal
        relationship that the telemetry cannot establish.
        """
        if correlation_id is None and trace_id is None:
            raise EventValidationError("correlate requires a correlation_id or a trace_id")
        items, _ = self.store.list_events(org_id=org_id, correlation_id=correlation_id,
                                          trace_id=trace_id, agent_id=agent_id, since=since,
                                          until=until, limit=self.cfg.max_sequence_length)
        ordered = sorted(items, key=lambda e: (e.ts, e.event_id))
        established = "trace" if trace_id else "correlation_id"
        causal = bool(trace_id)
        links = []
        for e in ordered:
            links.append(CorrelationLink(
                event_id=e.event_id, event_type=e.event_type, ts=e.ts,
                established_by=established, causal=causal and bool(e.span_id),
                decision=e.decision, action=e.action, resource=e.resource))
        blocked = any(e.decision in (Decision.DENY.value, Decision.BLOCKED.value) for e in ordered)
        approved = any(e.decision == Decision.APPROVED.value for e in ordered)
        completed = any(e.decision == Decision.COMPLETED.value for e in ordered)
        departed = any(e.decision in (Decision.DENY.value, Decision.BLOCKED.value,
                                      Decision.REQUIRE_APPROVAL.value,
                                      Decision.INDETERMINATE.value) for e in ordered)
        note = ("ordered by trace context; causal parent/child links are present"
                if causal else
                "grouped by correlation id; ordering is temporal, causal linkage is NOT established"
                if correlation_id else "time-ordered only")
        return ActionSequence(
            correlation_id=correlation_id, org_id=org_id,
            agent_id=agent_id or (ordered[0].agent_id if ordered else None),
            links=tuple(links),
            started_at=ordered[0].ts if ordered else 0.0,
            ended_at=ordered[-1].ts if ordered else 0.0,
            blocked=blocked, approved=approved, completed=completed, departed_from_policy=departed,
            note=note)

    # ------------------------------------------------------------------ investigation view
    def investigate(self, *, org_id: str, agent_id: Optional[str] = None,
                    correlation_id: Optional[str] = None, trace_id: Optional[str] = None,
                    since: Optional[float] = None, until: Optional[float] = None,
                    limit: int = 200) -> dict:
        """A unified, tenant-scoped view of an agent's activity for an investigator.

        Answers: which agent acted; which tool/resource it touched; what decision was made; which
        actions followed; whether the run departed from policy; whether it was blocked/approved/
        completed. Relationships are reported with the honesty fields above.
        """
        items, cursor = self.store.list_events(
            org_id=org_id, agent_id=agent_id, correlation_id=correlation_id, trace_id=trace_id,
            since=since, until=until, limit=limit)
        seq = None
        if correlation_id or trace_id:
            seq = self.correlate(org_id=org_id, correlation_id=correlation_id, trace_id=trace_id,
                                 agent_id=agent_id, since=since, until=until).to_dict()
        decisions: dict = {}
        for e in items:
            if e.decision:
                decisions[e.decision] = decisions.get(e.decision, 0) + 1
        return {
            "org_id": org_id, "agent_id": agent_id, "correlation_id": correlation_id,
            "trace_id": trace_id,
            "events": [e.public_dict() for e in items],
            "count": len(items), "next_cursor": cursor,
            "decisions": decisions,
            "blocked": any(e.decision in (Decision.DENY.value, Decision.BLOCKED.value)
                           for e in items),
            "approval_required": any(e.decision == Decision.REQUIRE_APPROVAL.value for e in items),
            "sequence": seq,
            "caveat": ("telemetry covers only integrations that emit events; absence of an event is "
                       "not evidence that nothing happened"),
        }


# --------------------------------------------------------------------------- helpers
_CANONICAL = frozenset({
    "event_id", "event_type", "ts", "org_id", "agent_id", "instance_id", "session_id", "action",
    "resource", "resource_type", "decision", "reason", "outcome", "policy_id", "policy_version",
    "destination", "address_class", "data_classes", "dlp_rule_ids", "severity", "latency_ms",
    "correlation_id", "trace_id", "span_id", "parent_span_id", "actor_user_id", "task_id",
})


def _safe_text(redactor: Redactor, value) -> Optional[str]:
    """Redact an optional free-text metadata field (a reason code is normally kept verbatim; a
    secret-shaped value is pseudonymized so a producer cannot smuggle a credential into ``reason``)."""
    out, _ = redactor.redact_text(_opt_str(value))
    return out


def _opt_str(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (int, float, bool)):
        return str(value)[:FIELD_MAX]
    if not isinstance(value, str):
        return None
    v = value.replace("\n", " ").replace("\r", " ").strip()
    return v[:FIELD_MAX] if v else None


def _as_id(value, name: str, required: bool = True) -> Optional[str]:
    if value is None or value == "":
        if required:
            raise EventValidationError(f"missing required field: {name}")
        return None
    if not isinstance(value, str):
        raise EventValidationError(f"{name} must be a string")
    v = value.strip()
    if not v or len(v) > FIELD_MAX:
        raise EventValidationError(f"{name} is empty or too long")
    return v


def _as_ts(value, name: str) -> float:
    if value is None:
        raise EventValidationError(f"missing required field: {name}")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EventValidationError(f"{name} must be a number (epoch seconds)")
    ts = float(value)
    if ts != ts or ts in (float("inf"), float("-inf")):
        raise EventValidationError(f"{name} is not a finite number")
    return ts


def _as_str_tuple(value) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value[:FIELD_MAX],)
    if isinstance(value, (list, tuple)):
        return tuple(str(v)[:FIELD_MAX] for v in value if v is not None)[:32]
    return ()


def _derive_dedup_key(ev: RuntimeEvent) -> str:
    """A stable content key so an exact replay is detected as a duplicate."""
    material = "|".join(str(x) for x in (
        ev.event_type, ev.agent_id, f"{ev.ts:.6f}", ev.resource, ev.action, ev.decision,
        ev.correlation_id, ev.trace_id))
    return "dk:" + hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:32]


def _safe_org(raw) -> Optional[str]:
    if isinstance(raw, dict):
        for key in ("org_id", "tenant", "tenant_id"):
            v = raw.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()[:FIELD_MAX]
    return None
