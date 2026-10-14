"""PostgreSQL implementation of ``RuntimeMonitoringStore`` (authoritative).

All SQL is constant strings; every value is a bound parameter. Every tenant-scoped table additionally
runs under RLS (migration 0008), so a forgotten filter still cannot leak across tenants.

Pagination uses a **stable composite cursor** ``(ts, event_id)`` rather than an OFFSET: a
late-arriving or concurrently-inserted event therefore can neither duplicate nor skip a page
boundary, because the page is anchored to a value rather than to a row count.

Append-only tables reject UPDATE (a DB trigger); ``purge_before`` is the only delete path and is
org-scoped when an org is supplied -- so retention cannot be used to reach into another tenant.
"""
from __future__ import annotations

import json
from typing import List, Optional, Tuple

from ...core.errors import StorageError
from ...runtime_monitoring.models import (Alert, AlertRule, BehaviorProfile, DriftFinding, GraphEdge,
                                          GraphNode, RiskAssessment, RuntimeEvent)
from ...runtime_monitoring.store import RuntimeMonitoringStore
# The ONE canonical keyset-cursor codec. This module previously carried a duplicate private copy
# that formatted the timestamp as ``f"{ts:.6f}"``; because that format ROUNDS UP, the decoded
# boundary could sit above the true row, so a page walk repeated the boundary event and shifted
# every later page (observed as page N != expected and a duplicated event_id across pages).
from ...runtime_monitoring.memory_store import decode_cursor, encode_cursor


def _json(value) -> str:
    return json.dumps(value if value is not None else {}, separators=(",", ":"), default=str)


def _event(r) -> RuntimeEvent:
    return RuntimeEvent(
        event_id=r["event_id"], event_type=r["event_type"], ts=float(r["ts"]),
        org_id=r["org_id"], agent_id=r["agent_id"], instance_id=r["instance_id"],
        session_id=r["session_id"], action=r["action"], resource=r["resource"],
        resource_type=r["resource_type"], decision=r["decision"], reason=r["reason"],
        outcome=r["outcome"], policy_id=r["policy_id"], policy_version=r["policy_version"],
        destination=r["destination"], address_class=r["address_class"],
        data_classes=tuple(r["data_classes"] or ()), dlp_rule_ids=tuple(r["dlp_rule_ids"] or ()),
        severity=r["severity"], latency_ms=r["latency_ms"], correlation_id=r["correlation_id"],
        trace_id=r["trace_id"], span_id=r["span_id"], parent_span_id=r["parent_span_id"],
        actor_user_id=r["actor_user_id"], task_id=r["task_id"],
        ingested_at=float(r["ingested_at"]), late=bool(r["late"]), redacted=bool(r["redacted"]),
        sampled=bool(r["sampled"]), dedup_key=r["dedup_key"],
        extra=dict(r["extra"] or {}))


def _profile(r) -> BehaviorProfile:
    return BehaviorProfile(
        profile_id=r["profile_id"], org_id=r["org_id"], agent_id=r["agent_id"],
        version=int(r["version"]), created_at=float(r["created_at"]),
        updated_at=float(r["updated_at"]),
        window_start=(float(r["window_start"]) if r["window_start"] is not None else None),
        window_end=(float(r["window_end"]) if r["window_end"] is not None else None),
        learning_window_s=int(r["learning_window_s"]), min_samples=int(r["min_samples"]),
        total_events=int(r["total_events"]), tools=dict(r["tools"] or {}),
        resources=dict(r["resources"] or {}), destinations=dict(r["destinations"] or {}),
        actions=dict(r["actions"] or {}), decisions=dict(r["decisions"] or {}),
        data_classes=dict(r["data_classes"] or {}), hour_histogram=dict(r["hour_histogram"] or {}),
        sequences=dict(r["sequences"] or {}), denials=int(r["denials"]), failures=int(r["failures"]),
        retries=int(r["retries"]), privileged_actions=int(r["privileged_actions"]),
        sensitive_reads=int(r["sensitive_reads"]),
        max_events_per_hour=int(r["max_events_per_hour"]))


def _finding(r) -> DriftFinding:
    return DriftFinding(
        finding_id=r["finding_id"], org_id=r["org_id"], agent_id=r["agent_id"],
        ts=float(r["ts"]), classification=r["classification"], category=r["category"],
        observed=r["observed"], expected=r["expected"], corroboration=r["corroboration"],
        evidence=tuple(r["evidence"] or ()), confidence=float(r["confidence"]),
        severity=r["severity"], detail=r["detail"])


def _node(r) -> GraphNode:
    return GraphNode(node_id=r["node_id"], org_id=r["org_id"], kind=r["kind"], label=r["label"],
                     first_seen=float(r["first_seen"]), last_seen=float(r["last_seen"]),
                     attributes=dict(r["attributes"] or {}))


def _edge(r) -> GraphEdge:
    return GraphEdge(edge_id=r["edge_id"], org_id=r["org_id"], kind=r["kind"], src=r["src"],
                     dst=r["dst"], first_seen=float(r["first_seen"]),
                     last_seen=float(r["last_seen"]), count=int(r["count"]),
                     confidence=float(r["confidence"]), provenance=r["provenance"],
                     last_event_id=r["last_event_id"])


def _assessment(r) -> RiskAssessment:
    from ...runtime_monitoring.models import RiskSignal
    signals = []
    for s in (r["signals"] or []):
        signals.append(RiskSignal(kind=s.get("kind", ""), weight=float(s.get("weight", 0.0)),
                                  contribution=float(s.get("contribution", 0.0)),
                                  evidence=tuple(s.get("evidence") or ()),
                                  detail=s.get("detail", "")))
    return RiskAssessment(
        assessment_id=r["assessment_id"], org_id=r["org_id"], agent_id=r["agent_id"],
        ts=float(r["ts"]), score=float(r["score"]), band=r["band"], rule_version=r["rule_version"],
        signals=tuple(signals), evidence=tuple(r["evidence"] or ()), window_s=int(r["window_s"]))


def _rule(r) -> AlertRule:
    return AlertRule(rule_id=r["rule_id"], name=r["name"], org_id=r["org_id"],
                     min_severity=r["min_severity"], event_types=tuple(r["event_types"] or ()),
                     drift_classes=tuple(r["drift_classes"] or ()),
                     risk_threshold=(float(r["risk_threshold"])
                                     if r["risk_threshold"] is not None else None),
                     dedup_window_s=int(r["dedup_window_s"]), rate_window_s=int(r["rate_window_s"]),
                     max_per_window=int(r["max_per_window"]),
                     auto_actions=tuple(r["auto_actions"] or ()), description=r["description"],
                     enabled=bool(r["enabled"]), created_at=float(r["created_at"]))


def _alert(r) -> Alert:
    return Alert(alert_id=r["alert_id"], org_id=r["org_id"], rule_id=r["rule_id"],
                 severity=r["severity"], title=r["title"], ts=float(r["ts"]), state=r["state"],
                 dedup_key=r["dedup_key"] or "", first_seen=float(r["first_seen"]),
                 last_seen=float(r["last_seen"]), occurrence_count=int(r["occurrence_count"]),
                 suppressed_count=int(r["suppressed_count"]), agent_id=r["agent_id"],
                 drift_class=r["drift_class"],
                 risk_score=(float(r["risk_score"]) if r["risk_score"] is not None else None),
                 event_ids=tuple(r["event_ids"] or ()), actions_taken=tuple(r["actions_taken"] or ()),
                 acknowledged_by=r["acknowledged_by"], resolved_by=r["resolved_by"],
                 note=r["note"], detail=r["detail"])


def _encode_cursor(ts: float, event_id: str) -> str:
    return encode_cursor(ts, event_id)


def _decode_cursor(cursor: Optional[str]):
    return decode_cursor(cursor)


class PgRuntimeMonitoringStore(RuntimeMonitoringStore):
    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------ events
    def append_event(self, ev: RuntimeEvent) -> None:
        self.db.run("p5_append_event", lambda c: c.execute(
            "INSERT INTO runtime_events (event_id, dedup_key, event_type, ts, ingested_at, org_id,"
            " agent_id, instance_id, session_id, action, resource, resource_type, decision, reason,"
            " outcome, policy_id, policy_version, destination, address_class, data_classes,"
            " dlp_rule_ids, severity, latency_ms, correlation_id, trace_id, span_id, parent_span_id,"
            " actor_user_id, task_id, late, redacted, sampled, extra)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (event_id) DO NOTHING",
            (ev.event_id, ev.dedup_key, ev.event_type, ev.ts, ev.ingested_at, ev.org_id,
             ev.agent_id, ev.instance_id, ev.session_id, ev.action, ev.resource, ev.resource_type,
             ev.decision, ev.reason, ev.outcome, ev.policy_id, ev.policy_version, ev.destination,
             ev.address_class, list(ev.data_classes), list(ev.dlp_rule_ids), ev.severity,
             ev.latency_ms, ev.correlation_id, ev.trace_id, ev.span_id, ev.parent_span_id,
             ev.actor_user_id, ev.task_id, ev.late, ev.redacted, ev.sampled, _json(ev.extra))))

    def get_event(self, event_id: str, *, org_id: str) -> Optional[RuntimeEvent]:
        r = self.db.run("p5_get_event", lambda c: c.execute(
            "SELECT * FROM runtime_events WHERE event_id=%s AND org_id=%s",
            (event_id, org_id)).fetchone())
        return _event(r) if r else None

    def list_events(self, *, org_id: str, agent_id: Optional[str] = None,
                    event_type: Optional[str] = None, correlation_id: Optional[str] = None,
                    trace_id: Optional[str] = None, since: Optional[float] = None,
                    until: Optional[float] = None, limit: int = 100,
                    cursor: Optional[str] = None) -> Tuple[List[RuntimeEvent], Optional[str]]:
        limit = max(1, min(int(limit), 1000))
        clauses, params = ["org_id=%s"], [org_id]
        if agent_id is not None:
            clauses.append("agent_id=%s")
            params.append(agent_id)
        if event_type is not None:
            clauses.append("event_type=%s")
            params.append(event_type)
        if correlation_id is not None:
            clauses.append("correlation_id=%s")
            params.append(correlation_id)
        if trace_id is not None:
            clauses.append("trace_id=%s")
            params.append(trace_id)
        if since is not None:
            clauses.append("ts >= %s")
            params.append(since)
        if until is not None:
            clauses.append("ts <= %s")
            params.append(until)
        cur = _decode_cursor(cursor)
        if cur is not None:
            clauses.append("(ts, event_id) < (%s, %s)")
            params.extend([cur[0], cur[1]])
        params.append(limit + 1)                    # fetch one extra to detect a next page
        sql = ("SELECT * FROM runtime_events WHERE " + " AND ".join(clauses)
               + " ORDER BY ts DESC, event_id DESC LIMIT %s")
        rows = self.db.run("p5_list_events", lambda c: c.execute(sql, tuple(params)).fetchall())
        page = rows[:limit]
        next_cursor = (_encode_cursor(page[-1]["ts"], page[-1]["event_id"])
                       if len(rows) > limit and page else None)
        return [_event(r) for r in page], next_cursor

    def count_events(self, *, org_id: str, agent_id: Optional[str] = None,
                     event_type: Optional[str] = None, since: Optional[float] = None,
                     until: Optional[float] = None) -> int:
        clauses, params = ["org_id=%s"], [org_id]
        if agent_id is not None:
            clauses.append("agent_id=%s")
            params.append(agent_id)
        if event_type is not None:
            clauses.append("event_type=%s")
            params.append(event_type)
        if since is not None:
            clauses.append("ts >= %s")
            params.append(since)
        if until is not None:
            clauses.append("ts <= %s")
            params.append(until)
        r = self.db.run("p5_count_events", lambda c: c.execute(
            "SELECT count(*) AS n FROM runtime_events WHERE " + " AND ".join(clauses),
            tuple(params)).fetchone())
        return int(r["n"]) if r else 0

    def aggregate_by_type(self, *, org_id: str, since: Optional[float] = None,
                          until: Optional[float] = None, agent_id: Optional[str] = None) -> dict:
        clauses, params = ["org_id=%s"], [org_id]
        if since is not None:
            clauses.append("ts >= %s")
            params.append(since)
        if until is not None:
            clauses.append("ts <= %s")
            params.append(until)
        if agent_id is not None:
            clauses.append("agent_id=%s")
            params.append(agent_id)
        rows = self.db.run("p5_agg_events", lambda c: c.execute(
            "SELECT event_type, count(*) AS n FROM runtime_events WHERE " + " AND ".join(clauses)
            + " GROUP BY event_type ORDER BY n DESC, event_type", tuple(params)).fetchall())
        return {r["event_type"]: int(r["n"]) for r in rows}

    def latest_event_ts(self, *, org_id: str) -> Optional[float]:
        r = self.db.run("p5_latest_ts", lambda c: c.execute(
            "SELECT max(ts) AS m FROM runtime_events WHERE org_id=%s", (org_id,)).fetchone())
        return float(r["m"]) if r and r["m"] is not None else None

    def has_dedup_key(self, *, org_id: str, dedup_key: str) -> bool:
        if not dedup_key:
            return False
        r = self.db.run("p5_has_dedup", lambda c: c.execute(
            "SELECT 1 AS x FROM runtime_events WHERE org_id=%s AND dedup_key=%s LIMIT 1",
            (org_id, dedup_key)).fetchone())
        return r is not None

    def purge_before(self, cutoff_ts: float, *, org_id: Optional[str] = None) -> int:
        """Delete telemetry older than the retention cutoff. Org-scoped when an org is given."""
        def go(conn):
            removed = 0
            for table in ("runtime_drift_findings", "runtime_risk_assessments", "runtime_events"):
                if org_id is None:
                    cur = conn.execute(f"DELETE FROM {table} WHERE ts < %s", (cutoff_ts,))
                else:
                    cur = conn.execute(f"DELETE FROM {table} WHERE ts < %s AND org_id=%s",
                                       (cutoff_ts, org_id))
                removed += int(cur.rowcount or 0)
            return removed
        return self.db.run("p5_purge", go, retry=False)

    # ------------------------------------------------------------------ profiles
    def put_profile(self, p: BehaviorProfile) -> None:
        self.db.run("p5_put_profile", lambda c: c.execute(
            "INSERT INTO runtime_behavior_profiles (profile_id, org_id, agent_id, version,"
            " learning_window_s, min_samples, total_events, tools, resources, destinations, actions,"
            " decisions, data_classes, hour_histogram, sequences, denials, failures, retries,"
            " privileged_actions, sensitive_reads, max_events_per_hour, window_start, window_end,"
            " created_at, updated_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (org_id, agent_id) DO UPDATE SET profile_id=EXCLUDED.profile_id,"
            " version=EXCLUDED.version, learning_window_s=EXCLUDED.learning_window_s,"
            " min_samples=EXCLUDED.min_samples, total_events=EXCLUDED.total_events,"
            " tools=EXCLUDED.tools, resources=EXCLUDED.resources,"
            " destinations=EXCLUDED.destinations, actions=EXCLUDED.actions,"
            " decisions=EXCLUDED.decisions, data_classes=EXCLUDED.data_classes,"
            " hour_histogram=EXCLUDED.hour_histogram, sequences=EXCLUDED.sequences,"
            " denials=EXCLUDED.denials, failures=EXCLUDED.failures, retries=EXCLUDED.retries,"
            " privileged_actions=EXCLUDED.privileged_actions,"
            " sensitive_reads=EXCLUDED.sensitive_reads,"
            " max_events_per_hour=EXCLUDED.max_events_per_hour, window_start=EXCLUDED.window_start,"
            " window_end=EXCLUDED.window_end, updated_at=EXCLUDED.updated_at",
            (p.profile_id, p.org_id, p.agent_id, int(p.version), int(p.learning_window_s),
             int(p.min_samples), int(p.total_events), _json(p.tools), _json(p.resources),
             _json(p.destinations), _json(p.actions), _json(p.decisions), _json(p.data_classes),
             _json(p.hour_histogram), _json(p.sequences), int(p.denials), int(p.failures),
             int(p.retries), int(p.privileged_actions), int(p.sensitive_reads),
             int(p.max_events_per_hour), p.window_start, p.window_end, p.created_at, p.updated_at)))

    def get_profile(self, *, org_id: str, agent_id: str) -> Optional[BehaviorProfile]:
        r = self.db.run("p5_get_profile", lambda c: c.execute(
            "SELECT * FROM runtime_behavior_profiles WHERE org_id=%s AND agent_id=%s",
            (org_id, agent_id)).fetchone())
        return _profile(r) if r else None

    def list_profiles(self, *, org_id: str, limit: int = 100) -> List[BehaviorProfile]:
        rows = self.db.run("p5_list_profiles", lambda c: c.execute(
            "SELECT * FROM runtime_behavior_profiles WHERE org_id=%s ORDER BY agent_id LIMIT %s",
            (org_id, int(limit))).fetchall())
        return [_profile(r) for r in rows]

    def delete_profile(self, *, org_id: str, agent_id: str) -> None:
        self.db.run("p5_del_profile", lambda c: c.execute(
            "DELETE FROM runtime_behavior_profiles WHERE org_id=%s AND agent_id=%s",
            (org_id, agent_id)))

    # ------------------------------------------------------------------ findings
    def put_finding(self, f: DriftFinding) -> None:
        self.db.run("p5_put_finding", lambda c: c.execute(
            "INSERT INTO runtime_drift_findings (finding_id, org_id, agent_id, ts, classification,"
            " category, observed, expected, corroboration, evidence, confidence, severity, detail)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (finding_id) DO NOTHING",
            (f.finding_id, f.org_id, f.agent_id, f.ts, f.classification, f.category, f.observed,
             f.expected, f.corroboration, list(f.evidence), f.confidence, f.severity, f.detail)))

    def list_findings(self, *, org_id: str, agent_id: Optional[str] = None,
                      classification: Optional[str] = None, since: Optional[float] = None,
                      limit: int = 100) -> List[DriftFinding]:
        clauses, params = ["org_id=%s"], [org_id]
        if agent_id is not None:
            clauses.append("agent_id=%s")
            params.append(agent_id)
        if classification is not None:
            clauses.append("classification=%s")
            params.append(classification)
        if since is not None:
            clauses.append("ts >= %s")
            params.append(since)
        params.append(int(limit))
        rows = self.db.run("p5_list_findings", lambda c: c.execute(
            "SELECT * FROM runtime_drift_findings WHERE " + " AND ".join(clauses)
            + " ORDER BY ts DESC, finding_id DESC LIMIT %s", tuple(params)).fetchall())
        return [_finding(r) for r in rows]

    # ------------------------------------------------------------------ graph
    def put_node(self, n: GraphNode) -> None:
        self.db.run("p5_put_node", lambda c: c.execute(
            "INSERT INTO runtime_graph_nodes (org_id, node_id, kind, label, first_seen, last_seen,"
            " attributes) VALUES (%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (org_id, node_id) DO UPDATE SET"
            " label=EXCLUDED.label,"
            " first_seen=LEAST(runtime_graph_nodes.first_seen, EXCLUDED.first_seen),"
            " last_seen=GREATEST(runtime_graph_nodes.last_seen, EXCLUDED.last_seen),"
            " attributes=runtime_graph_nodes.attributes || EXCLUDED.attributes",
            (n.org_id, n.node_id, n.kind, n.label, n.first_seen, n.last_seen, _json(n.attributes))))

    def get_node(self, node_id: str, *, org_id: str) -> Optional[GraphNode]:
        r = self.db.run("p5_get_node", lambda c: c.execute(
            "SELECT * FROM runtime_graph_nodes WHERE org_id=%s AND node_id=%s",
            (org_id, node_id)).fetchone())
        return _node(r) if r else None

    def list_nodes(self, *, org_id: str, kind: Optional[str] = None,
                   limit: int = 500) -> List[GraphNode]:
        if kind is None:
            rows = self.db.run("p5_list_nodes", lambda c: c.execute(
                "SELECT * FROM runtime_graph_nodes WHERE org_id=%s ORDER BY kind, node_id LIMIT %s",
                (org_id, int(limit))).fetchall())
        else:
            rows = self.db.run("p5_list_nodes_kind", lambda c: c.execute(
                "SELECT * FROM runtime_graph_nodes WHERE org_id=%s AND kind=%s"
                " ORDER BY node_id LIMIT %s", (org_id, kind, int(limit))).fetchall())
        return [_node(r) for r in rows]

    def put_edge(self, e: GraphEdge) -> None:
        self.db.run("p5_put_edge", lambda c: c.execute(
            "INSERT INTO runtime_graph_edges (org_id, edge_id, kind, src, dst, first_seen, last_seen,"
            " count, confidence, provenance, last_event_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (org_id, edge_id) DO UPDATE SET"
            " first_seen=LEAST(runtime_graph_edges.first_seen, EXCLUDED.first_seen),"
            " last_seen=GREATEST(runtime_graph_edges.last_seen, EXCLUDED.last_seen),"
            " count=runtime_graph_edges.count + EXCLUDED.count,"
            " confidence=GREATEST(runtime_graph_edges.confidence, EXCLUDED.confidence),"
            " provenance=CASE WHEN EXCLUDED.provenance = '' THEN runtime_graph_edges.provenance"
            "                 ELSE EXCLUDED.provenance END,"
            " last_event_id=COALESCE(EXCLUDED.last_event_id, runtime_graph_edges.last_event_id)",
            (e.org_id, e.edge_id, e.kind, e.src, e.dst, e.first_seen, e.last_seen, int(e.count),
             float(e.confidence), e.provenance, e.last_event_id)))

    def list_edges(self, *, org_id: str, node_id: Optional[str] = None,
                   kind: Optional[str] = None, limit: int = 1000) -> List[GraphEdge]:
        clauses, params = ["org_id=%s"], [org_id]
        if node_id is not None:
            clauses.append("(src=%s OR dst=%s)")
            params.extend([node_id, node_id])
        if kind is not None:
            clauses.append("kind=%s")
            params.append(kind)
        params.append(int(limit))
        rows = self.db.run("p5_list_edges", lambda c: c.execute(
            "SELECT * FROM runtime_graph_edges WHERE " + " AND ".join(clauses)
            + " ORDER BY count DESC, edge_id LIMIT %s", tuple(params)).fetchall())
        return [_edge(r) for r in rows]

    def delete_graph(self, *, org_id: str) -> int:
        def go(conn):
            n = conn.execute("DELETE FROM runtime_graph_nodes WHERE org_id=%s", (org_id,))
            e = conn.execute("DELETE FROM runtime_graph_edges WHERE org_id=%s", (org_id,))
            return int(n.rowcount or 0) + int(e.rowcount or 0)
        return self.db.run("p5_del_graph", go, retry=False)

    # ------------------------------------------------------------------ assessments
    def put_assessment(self, a: RiskAssessment) -> None:
        signals = [s.to_dict() for s in a.signals]
        self.db.run("p5_put_assessment", lambda c: c.execute(
            "INSERT INTO runtime_risk_assessments (assessment_id, org_id, agent_id, ts, score, band,"
            " rule_version, signals, evidence, window_s) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (assessment_id) DO NOTHING",
            (a.assessment_id, a.org_id, a.agent_id, a.ts, float(a.score), a.band, a.rule_version,
             _json(signals), list(a.evidence), int(a.window_s))))

    def list_assessments(self, *, org_id: str, agent_id: Optional[str] = None,
                         since: Optional[float] = None, limit: int = 100) -> List[RiskAssessment]:
        clauses, params = ["org_id=%s"], [org_id]
        if agent_id is not None:
            clauses.append("agent_id=%s")
            params.append(agent_id)
        if since is not None:
            clauses.append("ts >= %s")
            params.append(since)
        params.append(int(limit))
        rows = self.db.run("p5_list_assessments", lambda c: c.execute(
            "SELECT * FROM runtime_risk_assessments WHERE " + " AND ".join(clauses)
            + " ORDER BY ts DESC, assessment_id DESC LIMIT %s", tuple(params)).fetchall())
        return [_assessment(r) for r in rows]

    # ------------------------------------------------------------------ rules
    def put_rule(self, r: AlertRule) -> None:
        self.db.run("p5_put_rule", lambda c: c.execute(
            "INSERT INTO runtime_alert_rules (rule_id, org_id, name, min_severity, event_types,"
            " drift_classes, risk_threshold, dedup_window_s, rate_window_s, max_per_window,"
            " auto_actions, description, enabled, created_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (rule_id) DO UPDATE SET name=EXCLUDED.name,"
            " min_severity=EXCLUDED.min_severity, event_types=EXCLUDED.event_types,"
            " drift_classes=EXCLUDED.drift_classes, risk_threshold=EXCLUDED.risk_threshold,"
            " dedup_window_s=EXCLUDED.dedup_window_s, rate_window_s=EXCLUDED.rate_window_s,"
            " max_per_window=EXCLUDED.max_per_window, auto_actions=EXCLUDED.auto_actions,"
            " description=EXCLUDED.description, enabled=EXCLUDED.enabled"
            " WHERE runtime_alert_rules.org_id = EXCLUDED.org_id",
            (r.rule_id, r.org_id, r.name, r.min_severity, list(r.event_types),
             list(r.drift_classes), r.risk_threshold, int(r.dedup_window_s), int(r.rate_window_s),
             int(r.max_per_window), list(r.auto_actions), r.description, bool(r.enabled),
             r.created_at)))

    def get_rule(self, rule_id: str, *, org_id: str) -> Optional[AlertRule]:
        r = self.db.run("p5_get_rule", lambda c: c.execute(
            "SELECT * FROM runtime_alert_rules WHERE rule_id=%s AND org_id=%s",
            (rule_id, org_id)).fetchone())
        return _rule(r) if r else None

    def list_rules(self, *, org_id: str) -> List[AlertRule]:
        rows = self.db.run("p5_list_rules", lambda c: c.execute(
            "SELECT * FROM runtime_alert_rules WHERE org_id=%s ORDER BY rule_id",
            (org_id,)).fetchall())
        return [_rule(r) for r in rows]

    def delete_rule(self, rule_id: str, *, org_id: str) -> None:
        self.db.run("p5_del_rule", lambda c: c.execute(
            "DELETE FROM runtime_alert_rules WHERE rule_id=%s AND org_id=%s", (rule_id, org_id)))

    # ------------------------------------------------------------------ alerts
    def put_alert(self, a: Alert) -> None:
        self.db.run("p5_put_alert", lambda c: c.execute(
            "INSERT INTO runtime_alerts (alert_id, org_id, rule_id, severity, title, ts, state,"
            " dedup_key, first_seen, last_seen, occurrence_count, suppressed_count, agent_id,"
            " drift_class, risk_score, event_ids, actions_taken, acknowledged_by, resolved_by, note,"
            " detail) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (alert_id) DO UPDATE SET severity=EXCLUDED.severity,"
            " title=EXCLUDED.title, state=EXCLUDED.state, dedup_key=EXCLUDED.dedup_key,"
            " last_seen=EXCLUDED.last_seen, occurrence_count=EXCLUDED.occurrence_count,"
            " suppressed_count=EXCLUDED.suppressed_count, agent_id=EXCLUDED.agent_id,"
            " drift_class=EXCLUDED.drift_class, risk_score=EXCLUDED.risk_score,"
            " event_ids=EXCLUDED.event_ids, actions_taken=EXCLUDED.actions_taken,"
            " acknowledged_by=EXCLUDED.acknowledged_by, resolved_by=EXCLUDED.resolved_by,"
            " note=EXCLUDED.note, detail=EXCLUDED.detail"
            " WHERE runtime_alerts.org_id = EXCLUDED.org_id",
            (a.alert_id, a.org_id, a.rule_id, a.severity, a.title, a.ts, a.state, a.dedup_key,
             a.first_seen, a.last_seen, int(a.occurrence_count), int(a.suppressed_count), a.agent_id,
             a.drift_class, a.risk_score, list(a.event_ids), list(a.actions_taken),
             a.acknowledged_by, a.resolved_by, a.note, a.detail)))

    def get_alert(self, alert_id: str, *, org_id: str) -> Optional[Alert]:
        r = self.db.run("p5_get_alert", lambda c: c.execute(
            "SELECT * FROM runtime_alerts WHERE alert_id=%s AND org_id=%s",
            (alert_id, org_id)).fetchone())
        return _alert(r) if r else None

    def list_alerts(self, *, org_id: str, state: Optional[str] = None,
                    agent_id: Optional[str] = None, rule_id: Optional[str] = None,
                    since: Optional[float] = None, limit: int = 100) -> List[Alert]:
        clauses, params = ["org_id=%s"], [org_id]
        if state is not None:
            clauses.append("state=%s")
            params.append(state)
        if agent_id is not None:
            clauses.append("agent_id=%s")
            params.append(agent_id)
        if rule_id is not None:
            clauses.append("rule_id=%s")
            params.append(rule_id)
        if since is not None:
            clauses.append("ts >= %s")
            params.append(since)
        params.append(int(limit))
        rows = self.db.run("p5_list_alerts", lambda c: c.execute(
            "SELECT * FROM runtime_alerts WHERE " + " AND ".join(clauses)
            + " ORDER BY ts DESC, alert_id DESC LIMIT %s", tuple(params)).fetchall())
        return [_alert(r) for r in rows]

    def count_alerts(self, *, org_id: str, rule_id: str, since: float) -> int:
        r = self.db.run("p5_count_alerts", lambda c: c.execute(
            "SELECT count(*) AS n FROM runtime_alerts WHERE org_id=%s AND rule_id=%s AND ts >= %s",
            (org_id, rule_id, since)).fetchone())
        return int(r["n"]) if r else 0

    def find_open_alert(self, *, org_id: str, dedup_key: str) -> Optional[Alert]:
        r = self.db.run("p5_find_open_alert", lambda c: c.execute(
            "SELECT * FROM runtime_alerts WHERE org_id=%s AND dedup_key=%s"
            " AND state NOT IN ('resolved','suppressed') ORDER BY last_seen DESC LIMIT 1",
            (org_id, dedup_key)).fetchone())
        return _alert(r) if r else None

    # ------------------------------------------------------------------ audit
    def append_audit(self, event: dict) -> None:
        self.db.run("p5_append_audit", lambda c: c.execute(
            "INSERT INTO runtime_monitoring_audit (event_id, ts, event, org_id, agent_id, outcome,"
            " reason, alert_id, rule_id, finding_id, assessment_id, runtime_event_id, actor_user_id,"
            " action, correlation_id, extra) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (event_id) DO NOTHING",
            (event["event_id"], event["ts"], event["event"], event.get("org_id"),
             event.get("agent_id"), event.get("outcome", "ok"), event.get("reason"),
             event.get("alert_id"), event.get("rule_id"), event.get("finding_id"),
             event.get("assessment_id"), event.get("runtime_event_id"), event.get("actor_user_id"),
             event.get("action"), event.get("correlation_id"),
             _json({k: v for k, v in event.items()
                    if k not in _AUDIT_COLUMNS and isinstance(v, (str, int, float, bool))}))))

    def list_audit(self, *, org_id: Optional[str] = None, limit: int = 100) -> List[dict]:
        if org_id is None:
            rows = self.db.run("p5_list_audit_all", lambda c: c.execute(
                "SELECT * FROM runtime_monitoring_audit ORDER BY ts DESC, event_id DESC LIMIT %s",
                (int(limit),)).fetchall())
        else:
            rows = self.db.run("p5_list_audit_org", lambda c: c.execute(
                "SELECT * FROM runtime_monitoring_audit WHERE org_id=%s"
                " ORDER BY ts DESC, event_id DESC LIMIT %s", (org_id, int(limit))).fetchall())
        return [dict(r) for r in rows]


_AUDIT_COLUMNS = frozenset({
    "event_id", "ts", "event", "org_id", "agent_id", "outcome", "reason", "alert_id", "rule_id",
    "finding_id", "assessment_id", "runtime_event_id", "actor_user_id", "action", "correlation_id",
    "extra"})


def create_runtime_monitoring_store(db) -> PgRuntimeMonitoringStore:
    if db is None:
        raise StorageError("a PostgreSQL database is required for the runtime-monitoring store")
    return PgRuntimeMonitoringStore(db)
