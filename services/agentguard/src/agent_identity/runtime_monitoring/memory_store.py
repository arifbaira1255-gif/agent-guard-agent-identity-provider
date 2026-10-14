"""In-memory ``RuntimeMonitoringStore`` for unit tests and single-process development.

Semantics mirror the PostgreSQL backend closely enough for the security contract to hold:
  * every read/write is tenant-filtered explicitly,
  * events are append-only and deduplicated by ``dedup_key`` within a tenant,
  * retention is bounded (``max_events``) so an in-memory instance cannot grow without limit,
  * ``purge_before`` is the only deletion path and is org-scoped when an org is given.

It is NOT a production store: no durability, no cross-process sharing, no SQL indexes. Production
uses PostgreSQL (migration 0008).
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional, Tuple

from .models import (Alert, AlertRule, BehaviorProfile, DriftFinding, GraphEdge, GraphNode,
                     RiskAssessment, RuntimeEvent)
from .store import RuntimeMonitoringStore


def encode_cursor(ts: float, event_id: str) -> str:
    """Encode a keyset cursor for ``(ts, event_id)`` ordering.

    The float is emitted with ``repr`` (round-trip exact) rather than a fixed ``:.6f`` format: a
    truncated/rounded timestamp moves the keyset boundary and makes a page walk repeat the row that
    sat exactly on it (and therefore shift every later page). This is the ONE cursor codec -- both the
    in-memory and PostgreSQL stores use it, so the two backends paginate identically.
    """
    return f"{ts!r}|{event_id}"


def decode_cursor(cursor: Optional[str]) -> Optional[Tuple[float, str]]:
    if not cursor:
        return None
    try:
        ts_s, eid = cursor.split("|", 1)
        return float(ts_s), eid
    except (ValueError, AttributeError):
        return None


class MemoryRuntimeMonitoringStore(RuntimeMonitoringStore):
    def __init__(self, *, max_events: int = 200_000):
        self._lock = threading.RLock()
        self._events: List[RuntimeEvent] = []
        self._event_index: Dict[str, RuntimeEvent] = {}
        self._dedup: set = set()
        self._profiles: Dict[Tuple[str, str], BehaviorProfile] = {}
        self._findings: List[DriftFinding] = []
        self._nodes: Dict[Tuple[str, str], GraphNode] = {}
        self._edges: Dict[Tuple[str, str], GraphEdge] = {}
        self._assessments: List[RiskAssessment] = []
        self._rules: Dict[Tuple[str, str], AlertRule] = {}
        self._alerts: Dict[Tuple[str, str], Alert] = {}
        self._audit: List[dict] = []
        self.max_events = max(1, int(max_events))

    # ------------------------------------------------------------------ events
    def append_event(self, ev: RuntimeEvent) -> None:
        with self._lock:
            self._events.append(ev)
            self._event_index[ev.event_id] = ev
            if ev.dedup_key:
                self._dedup.add((ev.org_id, ev.dedup_key))
            if len(self._events) > self.max_events:
                drop = len(self._events) - self.max_events
                for old in self._events[:drop]:
                    self._event_index.pop(old.event_id, None)
                del self._events[:drop]

    def get_event(self, event_id: str, *, org_id: str) -> Optional[RuntimeEvent]:
        ev = self._event_index.get(event_id)
        if ev is None or ev.org_id != org_id:
            return None
        return ev

    def list_events(self, *, org_id: str, agent_id: Optional[str] = None,
                    event_type: Optional[str] = None, correlation_id: Optional[str] = None,
                    trace_id: Optional[str] = None, since: Optional[float] = None,
                    until: Optional[float] = None, limit: int = 100,
                    cursor: Optional[str] = None) -> Tuple[List[RuntimeEvent], Optional[str]]:
        limit = max(1, min(int(limit), 1000))
        cur = decode_cursor(cursor)
        with self._lock:
            items = [e for e in self._events if e.org_id == org_id]
        items = _filter_events(items, agent_id=agent_id, event_type=event_type,
                               correlation_id=correlation_id, trace_id=trace_id,
                               since=since, until=until)
        items.sort(key=lambda e: (e.ts, e.event_id), reverse=True)
        if cur is not None:
            cts, cid = cur
            items = [e for e in items if (e.ts, e.event_id) < (cts, cid)]
        page = items[:limit]
        next_cursor = (encode_cursor(page[-1].ts, page[-1].event_id)
                       if len(items) > limit and page else None)
        return page, next_cursor

    def count_events(self, *, org_id: str, agent_id: Optional[str] = None,
                     event_type: Optional[str] = None, since: Optional[float] = None,
                     until: Optional[float] = None) -> int:
        with self._lock:
            items = [e for e in self._events if e.org_id == org_id]
        return len(_filter_events(items, agent_id=agent_id, event_type=event_type, since=since,
                                  until=until))

    def aggregate_by_type(self, *, org_id: str, since: Optional[float] = None,
                          until: Optional[float] = None, agent_id: Optional[str] = None) -> dict:
        with self._lock:
            items = [e for e in self._events if e.org_id == org_id]
        out: Dict[str, int] = {}
        for e in _filter_events(items, agent_id=agent_id, since=since, until=until):
            out[e.event_type] = out.get(e.event_type, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

    def latest_event_ts(self, *, org_id: str) -> Optional[float]:
        with self._lock:
            ts = [e.ts for e in self._events if e.org_id == org_id]
        return max(ts) if ts else None

    def has_dedup_key(self, *, org_id: str, dedup_key: str) -> bool:
        with self._lock:
            return (org_id, dedup_key) in self._dedup

    def purge_before(self, cutoff_ts: float, *, org_id: Optional[str] = None) -> int:
        with self._lock:
            keep, removed = [], 0
            for e in self._events:
                if e.ts < cutoff_ts and (org_id is None or e.org_id == org_id):
                    removed += 1
                    self._event_index.pop(e.event_id, None)
                    if e.dedup_key:
                        self._dedup.discard((e.org_id, e.dedup_key))
                else:
                    keep.append(e)
            self._events = keep
            before = len(self._findings)
            self._findings = [f for f in self._findings
                              if not (f.ts < cutoff_ts and (org_id is None or f.org_id == org_id))]
            removed += before - len(self._findings)
            return removed

    # ------------------------------------------------------------------ profiles
    def put_profile(self, p: BehaviorProfile) -> None:
        with self._lock:
            self._profiles[(p.org_id, p.agent_id)] = p

    def get_profile(self, *, org_id: str, agent_id: str) -> Optional[BehaviorProfile]:
        return self._profiles.get((org_id, agent_id))

    def list_profiles(self, *, org_id: str, limit: int = 100) -> List[BehaviorProfile]:
        out = [p for (o, _), p in self._profiles.items() if o == org_id]
        return sorted(out, key=lambda p: p.agent_id)[:limit]

    def delete_profile(self, *, org_id: str, agent_id: str) -> None:
        with self._lock:
            self._profiles.pop((org_id, agent_id), None)

    # ------------------------------------------------------------------ findings
    def put_finding(self, f: DriftFinding) -> None:
        with self._lock:
            self._findings.append(f)

    def list_findings(self, *, org_id: str, agent_id: Optional[str] = None,
                      classification: Optional[str] = None, since: Optional[float] = None,
                      limit: int = 100) -> List[DriftFinding]:
        with self._lock:
            items = [f for f in self._findings if f.org_id == org_id]
        if agent_id is not None:
            items = [f for f in items if f.agent_id == agent_id]
        if classification is not None:
            items = [f for f in items if f.classification == classification]
        if since is not None:
            items = [f for f in items if f.ts >= since]
        return sorted(items, key=lambda f: (f.ts, f.finding_id), reverse=True)[:limit]

    # ------------------------------------------------------------------ graph
    def put_node(self, n: GraphNode) -> None:
        key = (n.org_id, n.node_id)
        with self._lock:
            prev = self._nodes.get(key)
            if prev is not None:
                merged = GraphNode(node_id=n.node_id, org_id=n.org_id, kind=prev.kind,
                                   label=n.label or prev.label,
                                   first_seen=min(prev.first_seen, n.first_seen),
                                   last_seen=max(prev.last_seen, n.last_seen),
                                   attributes={**prev.attributes, **n.attributes})
                self._nodes[key] = merged
            else:
                self._nodes[key] = n

    def get_node(self, node_id: str, *, org_id: str) -> Optional[GraphNode]:
        return self._nodes.get((org_id, node_id))

    def list_nodes(self, *, org_id: str, kind: Optional[str] = None,
                   limit: int = 500) -> List[GraphNode]:
        out = [n for (o, _), n in self._nodes.items() if o == org_id]
        if kind is not None:
            out = [n for n in out if n.kind == kind]
        return sorted(out, key=lambda n: (n.kind, n.node_id))[:limit]

    def put_edge(self, e: GraphEdge) -> None:
        key = (e.org_id, e.edge_id)
        with self._lock:
            prev = self._edges.get(key)
            if prev is not None:
                self._edges[key] = GraphEdge(
                    edge_id=e.edge_id, org_id=e.org_id, kind=prev.kind, src=prev.src, dst=prev.dst,
                    first_seen=min(prev.first_seen, e.first_seen),
                    last_seen=max(prev.last_seen, e.last_seen), count=prev.count + e.count,
                    confidence=max(prev.confidence, e.confidence),
                    provenance=e.provenance or prev.provenance,
                    last_event_id=e.last_event_id or prev.last_event_id)
            else:
                self._edges[key] = e

    def list_edges(self, *, org_id: str, node_id: Optional[str] = None,
                   kind: Optional[str] = None, limit: int = 1000) -> List[GraphEdge]:
        out = [e for (o, _), e in self._edges.items() if o == org_id]
        if node_id is not None:
            out = [e for e in out if e.src == node_id or e.dst == node_id]
        if kind is not None:
            out = [e for e in out if e.kind == kind]
        return sorted(out, key=lambda e: (-e.count, e.edge_id))[:limit]

    def delete_graph(self, *, org_id: str) -> int:
        with self._lock:
            n = [k for k in self._nodes if k[0] == org_id]
            e = [k for k in self._edges if k[0] == org_id]
            for k in n:
                self._nodes.pop(k, None)
            for k in e:
                self._edges.pop(k, None)
            return len(n) + len(e)

    # ------------------------------------------------------------------ assessments
    def put_assessment(self, a: RiskAssessment) -> None:
        with self._lock:
            self._assessments.append(a)

    def list_assessments(self, *, org_id: str, agent_id: Optional[str] = None,
                         since: Optional[float] = None, limit: int = 100) -> List[RiskAssessment]:
        with self._lock:
            items = [a for a in self._assessments if a.org_id == org_id]
        if agent_id is not None:
            items = [a for a in items if a.agent_id == agent_id]
        if since is not None:
            items = [a for a in items if a.ts >= since]
        return sorted(items, key=lambda a: (a.ts, a.assessment_id), reverse=True)[:limit]

    # ------------------------------------------------------------------ rules
    def put_rule(self, r: AlertRule) -> None:
        with self._lock:
            self._rules[(r.org_id, r.rule_id)] = r

    def get_rule(self, rule_id: str, *, org_id: str) -> Optional[AlertRule]:
        return self._rules.get((org_id, rule_id))

    def list_rules(self, *, org_id: str) -> List[AlertRule]:
        return sorted([r for (o, _), r in self._rules.items() if o == org_id],
                      key=lambda r: r.rule_id)

    def delete_rule(self, rule_id: str, *, org_id: str) -> None:
        with self._lock:
            self._rules.pop((org_id, rule_id), None)

    # ------------------------------------------------------------------ alerts
    def put_alert(self, a: Alert) -> None:
        with self._lock:
            self._alerts[(a.org_id, a.alert_id)] = a

    def get_alert(self, alert_id: str, *, org_id: str) -> Optional[Alert]:
        return self._alerts.get((org_id, alert_id))

    def list_alerts(self, *, org_id: str, state: Optional[str] = None,
                    agent_id: Optional[str] = None, rule_id: Optional[str] = None,
                    since: Optional[float] = None, limit: int = 100) -> List[Alert]:
        out = [a for (o, _), a in self._alerts.items() if o == org_id]
        if state is not None:
            out = [a for a in out if a.state == state]
        if agent_id is not None:
            out = [a for a in out if a.agent_id == agent_id]
        if rule_id is not None:
            out = [a for a in out if a.rule_id == rule_id]
        if since is not None:
            out = [a for a in out if a.ts >= since]
        return sorted(out, key=lambda a: (a.ts, a.alert_id), reverse=True)[:limit]

    def count_alerts(self, *, org_id: str, rule_id: str, since: float) -> int:
        return len([a for (o, _), a in self._alerts.items()
                    if o == org_id and a.rule_id == rule_id and a.ts >= since])

    def find_open_alert(self, *, org_id: str, dedup_key: str) -> Optional[Alert]:
        candidates = [a for (o, _), a in self._alerts.items()
                      if o == org_id and a.dedup_key == dedup_key and a.state not in
                      ("resolved", "suppressed")]
        if not candidates:
            return None
        return max(candidates, key=lambda a: a.last_seen)

    # ------------------------------------------------------------------ audit
    def append_audit(self, event: dict) -> None:
        with self._lock:
            self._audit.append(dict(event))

    def list_audit(self, *, org_id: Optional[str] = None, limit: int = 100) -> List[dict]:
        items = self._audit
        if org_id is not None:
            items = [e for e in items if e.get("org_id") == org_id]
        return sorted(items, key=lambda e: (e.get("ts", 0), e.get("event_id", "")),
                      reverse=True)[:limit]


def _filter_events(items: List[RuntimeEvent], *, agent_id=None, event_type=None,
                   correlation_id=None, trace_id=None, since=None, until=None) -> List[RuntimeEvent]:
    out = items
    if agent_id is not None:
        out = [e for e in out if e.agent_id == agent_id]
    if event_type is not None:
        out = [e for e in out if e.event_type == event_type]
    if correlation_id is not None:
        out = [e for e in out if e.correlation_id == correlation_id]
    if trace_id is not None:
        out = [e for e in out if e.trace_id == trace_id]
    if since is not None:
        out = [e for e in out if e.ts >= since]
    if until is not None:
        out = [e for e in out if e.ts <= until]
    return out
