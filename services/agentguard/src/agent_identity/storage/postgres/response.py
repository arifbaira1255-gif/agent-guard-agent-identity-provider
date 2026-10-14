"""PostgreSQL implementation of ``ResponseStore`` (authoritative).

All SQL is constant strings; every value is a bound parameter. Every tenant-scoped table additionally
runs under RLS (migration 0009), so a forgotten filter still cannot leak across tenants.

Atomicity notes:

* ``consume_budget`` is a SINGLE ``UPDATE ... RETURNING`` with the increment expressed in SQL, so two
  concurrent callers cannot both slip past the same limit. Counters are clamped at zero with
  ``GREATEST(0, ...)`` so a release can never drive usage negative.
* ``put_response`` is an upsert keyed by ``response_id``; the UNIQUE index on
  ``(org_id, idempotency_key)`` is what makes containment idempotent under duplicate delivery.
* ``response_audit`` and ``response_loop_findings`` reject UPDATE via a trigger (append-only).
* ``purge_evidence_before`` is the only delete path and skips sealed rows.
"""
from __future__ import annotations

import json
from typing import List, Optional

from ...core.errors import StorageError
from ...response.models import (ApprovalRequest, EmergencyStop, EvidenceRecord, ExecutionBudget,
                                Incident, IncidentTimelineEntry, LoopFinding, ResponseExecution,
                                ResponseStep)
from ...response.store import ResponseStore

#: Maps a budget dimension to its usage-counter column. Closed vocabulary.
_USED_COL = {"actions": "actions_used", "retries": "retries_used", "requests": "requests_used",
              "concurrency": "concurrency_used", "tokens": "tokens_used", "cost": "cost_used"}


def _json(value) -> str:
    return json.dumps(value if value is not None else {}, separators=(",", ":"), default=str)


def _finding(r) -> LoopFinding:
    return LoopFinding(
        finding_id=r["finding_id"], org_id=r["org_id"], agent_id=r["agent_id"],
        ts=float(r["ts"]), pattern=r["pattern"], classification=r["classification"],
        subject=r["subject"], observed_count=int(r["observed_count"]),
        threshold=int(r["threshold"]), window_s=int(r["window_s"]), severity=r["severity"],
        evidence=tuple(r["evidence"] or ()), detail=r["detail"], task_id=r["task_id"])


def _budget(r) -> ExecutionBudget:
    return ExecutionBudget(
        budget_id=r["budget_id"], org_id=r["org_id"], scope=r["scope"], agent_id=r["agent_id"],
        task_id=r["task_id"], max_actions=r["max_actions"], max_retries=r["max_retries"],
        max_requests=r["max_requests"], max_concurrency=r["max_concurrency"],
        max_tokens=(int(r["max_tokens"]) if r["max_tokens"] is not None else None),
        max_cost=(float(r["max_cost"]) if r["max_cost"] is not None else None),
        deadline_s=r["deadline_s"], started_at=float(r["started_at"]),
        updated_at=float(r["updated_at"]), actions_used=int(r["actions_used"]),
        retries_used=int(r["retries_used"]), requests_used=int(r["requests_used"]),
        concurrency_used=int(r["concurrency_used"]), tokens_used=int(r["tokens_used"]),
        cost_used=float(r["cost_used"]), enabled=bool(r["enabled"]))


def _stop(r) -> EmergencyStop:
    return EmergencyStop(
        stop_id=r["stop_id"], org_id=r["org_id"], agent_id=r["agent_id"], task_id=r["task_id"],
        requested_by=r["requested_by"], reason=r["reason"], ts=float(r["ts"]),
        active=bool(r["active"]), released_by=r["released_by"],
        released_at=(float(r["released_at"]) if r["released_at"] is not None else None),
        release_reason=r["release_reason"])


def _approval(r) -> ApprovalRequest:
    return ApprovalRequest(
        approval_id=r["approval_id"], org_id=r["org_id"], agent_id=r["agent_id"],
        action=r["action"], resource=r["resource"], fingerprint=r["fingerprint"],
        status=r["status"], requested_at=float(r["requested_at"]),
        expires_at=float(r["expires_at"]), requested_by=r["requested_by"], reason=r["reason"],
        risk_score=(float(r["risk_score"]) if r["risk_score"] is not None else None),
        risk_band=r["risk_band"], risk_evidence=tuple(r["risk_evidence"] or ()),
        policy_id=r["policy_id"], policy_version=r["policy_version"],
        incident_id=r["incident_id"],
        decided_at=(float(r["decided_at"]) if r["decided_at"] is not None else None),
        decided_by=r["decided_by"], decision_reason=r["decision_reason"],
        delegated_to=r["delegated_to"], params=dict(r["params"] or {}))


def _incident(r) -> Incident:
    timeline = []
    for t in (r["timeline"] or []):
        timeline.append(IncidentTimelineEntry(ts=float(t.get("ts", 0.0)), kind=t.get("kind", ""),
                                              detail=t.get("detail", ""), actor=t.get("actor"),
                                              ref=t.get("ref")))
    return Incident(
        incident_id=r["incident_id"], org_id=r["org_id"], title=r["title"],
        severity=r["severity"], status=r["status"], opened_at=float(r["opened_at"]),
        updated_at=float(r["updated_at"]),
        closed_at=(float(r["closed_at"]) if r["closed_at"] is not None else None),
        owner=r["owner"], agent_ids=tuple(r["agent_ids"] or ()),
        resources=tuple(r["resources"] or ()), alert_ids=tuple(r["alert_ids"] or ()),
        finding_ids=tuple(r["finding_ids"] or ()), evidence_ids=tuple(r["evidence_ids"] or ()),
        response_ids=tuple(r["response_ids"] or ()), timeline=timeline,
        detection_source=r["detection_source"],
        risk_score=(float(r["risk_score"]) if r["risk_score"] is not None else None),
        risk_band=r["risk_band"], resolution=r["resolution"], post_review=r["post_review"],
        correlation_key=r["correlation_key"])


def _response(r) -> ResponseExecution:
    steps = [ResponseStep(action=s.get("action", ""), status=s.get("status", ""),
                          mechanism=s.get("mechanism", ""), detail=s.get("detail", ""),
                          attempts=int(s.get("attempts", 1)),
                          reversible=bool(s.get("reversible", False)), result=s.get("result"))
             for s in (r["steps"] or [])]
    rollback = [ResponseStep(action=s.get("action", ""), status=s.get("status", ""),
                             mechanism=s.get("mechanism", ""), detail=s.get("detail", ""),
                             attempts=int(s.get("attempts", 1)),
                             reversible=bool(s.get("reversible", False)), result=s.get("result"))
                for s in (r["rollback_steps"] or [])]
    return ResponseExecution(
        response_id=r["response_id"], org_id=r["org_id"],
        idempotency_key=r["idempotency_key"], incident_id=r["incident_id"],
        agent_id=r["agent_id"], task_id=r["task_id"], state=r["state"], trigger=r["trigger"],
        requested_by=r["requested_by"], approved_by=r["approved_by"],
        approval_id=r["approval_id"], created_at=float(r["created_at"]),
        updated_at=float(r["updated_at"]), steps=steps, rollback_steps=rollback,
        partial_failures=tuple(r["partial_failures"] or ()),
        evidence_ids=tuple(r["evidence_ids"] or ()), note=r["note"])


def _evidence(r) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=r["evidence_id"], org_id=r["org_id"], kind=r["kind"], ts=float(r["ts"]),
        summary=r["summary"], ref=r["ref"], digest=r["digest"], incident_id=r["incident_id"],
        agent_id=r["agent_id"], source=r["source"],
        retention_until=(float(r["retention_until"]) if r["retention_until"] is not None
                         else None), sealed=bool(r["sealed"]))


class PgResponseStore(ResponseStore):
    """Authoritative response-plane store. Requires migration 0009."""

    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------ loop findings
    def put_loop_finding(self, f: LoopFinding) -> None:
        self.db.run("p6_put_finding", lambda c: c.execute(
            "INSERT INTO response_loop_findings (finding_id, org_id, agent_id, task_id, ts, pattern,"
            " classification, subject, observed_count, threshold, window_s, severity, evidence, detail)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (finding_id) DO NOTHING",
            (f.finding_id, f.org_id, f.agent_id, f.task_id, f.ts, f.pattern, f.classification,
             f.subject, f.observed_count, f.threshold, f.window_s, f.severity, list(f.evidence),
             f.detail)))

    def list_loop_findings(self, *, org_id: str, agent_id: Optional[str] = None,
                           pattern: Optional[str] = None, since: Optional[float] = None,
                           limit: int = 100) -> List[LoopFinding]:
        limit = max(1, min(int(limit), 1000))
        clauses, params = ["org_id=%s"], [org_id]
        if agent_id is not None:
            clauses.append("agent_id=%s")
            params.append(agent_id)
        if pattern is not None:
            clauses.append("pattern=%s")
            params.append(pattern)
        if since is not None:
            clauses.append("ts >= %s")
            params.append(since)
        params.append(limit)
        sql = ("SELECT * FROM response_loop_findings WHERE " + " AND ".join(clauses)
               + " ORDER BY ts DESC, finding_id DESC LIMIT %s")
        rows = self.db.run("p6_list_findings", lambda c: c.execute(sql, tuple(params)).fetchall())
        return [_finding(r) for r in rows]

    # ------------------------------------------------------------------ budgets
    def put_budget(self, b: ExecutionBudget) -> None:
        self.db.run("p6_put_budget", lambda c: c.execute(
            "INSERT INTO response_budgets (budget_id, org_id, scope, agent_id, task_id, max_actions,"
            " max_retries, max_requests, max_concurrency, max_tokens, max_cost, deadline_s, started_at,"
            " updated_at, actions_used, retries_used, requests_used, concurrency_used, tokens_used,"
            " cost_used, enabled) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (budget_id) DO UPDATE SET scope=EXCLUDED.scope, agent_id=EXCLUDED.agent_id,"
            " task_id=EXCLUDED.task_id, max_actions=EXCLUDED.max_actions,"
            " max_retries=EXCLUDED.max_retries, max_requests=EXCLUDED.max_requests,"
            " max_concurrency=EXCLUDED.max_concurrency, max_tokens=EXCLUDED.max_tokens,"
            " max_cost=EXCLUDED.max_cost, deadline_s=EXCLUDED.deadline_s,"
            " updated_at=EXCLUDED.updated_at, actions_used=EXCLUDED.actions_used,"
            " retries_used=EXCLUDED.retries_used, requests_used=EXCLUDED.requests_used,"
            " concurrency_used=EXCLUDED.concurrency_used, tokens_used=EXCLUDED.tokens_used,"
            " cost_used=EXCLUDED.cost_used, enabled=EXCLUDED.enabled",
            (b.budget_id, b.org_id, b.scope, b.agent_id, b.task_id, b.max_actions, b.max_retries,
             b.max_requests, b.max_concurrency, b.max_tokens, b.max_cost, b.deadline_s,
             b.started_at, b.updated_at, b.actions_used, b.retries_used, b.requests_used,
             b.concurrency_used, b.tokens_used, b.cost_used, b.enabled)))

    def get_budget(self, budget_id: str, *, org_id: str) -> Optional[ExecutionBudget]:
        r = self.db.run("p6_get_budget", lambda c: c.execute(
            "SELECT * FROM response_budgets WHERE budget_id=%s AND org_id=%s",
            (budget_id, org_id)).fetchone())
        return _budget(r) if r else None

    def find_budget(self, *, org_id: str, agent_id: Optional[str] = None,
                    task_id: Optional[str] = None) -> Optional[ExecutionBudget]:
        if task_id is not None:
            r = self.db.run("p6_find_budget_task", lambda c: c.execute(
                "SELECT * FROM response_budgets WHERE org_id=%s AND task_id=%s AND enabled"
                " ORDER BY updated_at DESC LIMIT 1", (org_id, task_id)).fetchone())
            if r:
                return _budget(r)
        if agent_id is not None:
            r = self.db.run("p6_find_budget_agent", lambda c: c.execute(
                "SELECT * FROM response_budgets WHERE org_id=%s AND agent_id=%s AND task_id IS NULL"
                " AND enabled ORDER BY updated_at DESC LIMIT 1", (org_id, agent_id)).fetchone())
            if r:
                return _budget(r)
        return None

    def list_budgets(self, *, org_id: str, limit: int = 200) -> List[ExecutionBudget]:
        limit = max(1, min(int(limit), 1000))
        rows = self.db.run("p6_list_budgets", lambda c: c.execute(
            "SELECT * FROM response_budgets WHERE org_id=%s ORDER BY updated_at DESC LIMIT %s",
            (org_id, limit)).fetchall())
        return [_budget(r) for r in rows]

    def delete_budget(self, budget_id: str, *, org_id: str) -> None:
        self.db.run("p6_delete_budget", lambda c: c.execute(
            "DELETE FROM response_budgets WHERE budget_id=%s AND org_id=%s",
            (budget_id, org_id)))

    def consume_budget(self, budget_id: str, *, org_id: str, dimension: str, amount: float,
                       now: float, limit: Optional[float] = None) -> Optional[ExecutionBudget]:
        col = _USED_COL.get(dimension)
        if col is None:
            raise StorageError(f"unknown budget dimension: {dimension}")
        # The increment happens IN SQL, in one statement, so concurrent callers serialize on the row.
        # When a limit is supplied the increment is CONDITIONAL (WHERE clause); the statement returns
        # no row when it would exceed, so a refused operation never advances the counter.
        if limit is None:
            sql = (f"UPDATE response_budgets SET {col} = GREATEST(0, {col} + %s), updated_at = %s"
                   " WHERE budget_id=%s AND org_id=%s RETURNING *")
            params = (amount, now, budget_id, org_id)
        else:
            sql = (f"UPDATE response_budgets SET {col} = {col} + %s, updated_at = %s"
                   f" WHERE budget_id=%s AND org_id=%s AND ({col} IS NULL OR {col} + %s <= %s)"
                   " RETURNING *")
            params = (amount, now, budget_id, org_id, amount, limit)
        r = self.db.run("p6_consume_budget", lambda c: c.execute(sql, params).fetchone())
        return _budget(r) if r else None

    # ------------------------------------------------------------------ emergency stops
    def put_stop(self, s: EmergencyStop) -> None:
        self.db.run("p6_put_stop", lambda c: c.execute(
            "INSERT INTO response_emergency_stops (stop_id, org_id, agent_id, task_id, requested_by,"
            " reason, ts, active, released_by, released_at, release_reason)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (stop_id) DO UPDATE SET"
            " active=EXCLUDED.active, released_by=EXCLUDED.released_by,"
            " released_at=EXCLUDED.released_at, release_reason=EXCLUDED.release_reason",
            (s.stop_id, s.org_id, s.agent_id, s.task_id, s.requested_by, s.reason, s.ts, s.active,
             s.released_by, s.released_at, s.release_reason)))

    def get_stop(self, stop_id: str, *, org_id: str) -> Optional[EmergencyStop]:
        r = self.db.run("p6_get_stop", lambda c: c.execute(
            "SELECT * FROM response_emergency_stops WHERE stop_id=%s AND org_id=%s",
            (stop_id, org_id)).fetchone())
        return _stop(r) if r else None

    def find_active_stop(self, *, org_id: str, agent_id: Optional[str] = None,
                         task_id: Optional[str] = None) -> Optional[EmergencyStop]:
        clauses, params = ["org_id=%s", "active"], [org_id]
        scope = []
        if task_id is not None:
            scope.append("task_id=%s")
            params.append(task_id)
        if agent_id is not None:
            scope.append("agent_id=%s")
            params.append(agent_id)
        if not scope:
            return None
        sql = ("SELECT * FROM response_emergency_stops WHERE " + " AND ".join(clauses)
               + " AND (" + " OR ".join(scope) + ") ORDER BY ts DESC LIMIT 1")
        r = self.db.run("p6_find_active_stop", lambda c: c.execute(sql, tuple(params)).fetchone())
        return _stop(r) if r else None

    def list_stops(self, *, org_id: str, active_only: bool = False,
                   limit: int = 200) -> List[EmergencyStop]:
        limit = max(1, min(int(limit), 1000))
        sql = "SELECT * FROM response_emergency_stops WHERE org_id=%s"
        if active_only:
            sql += " AND active"
        sql += " ORDER BY ts DESC LIMIT %s"
        rows = self.db.run("p6_list_stops", lambda c: c.execute(sql, (org_id, limit)).fetchall())
        return [_stop(r) for r in rows]

    # ------------------------------------------------------------------ approvals
    def put_approval(self, a: ApprovalRequest) -> None:
        self.db.run("p6_put_approval", lambda c: c.execute(
            "INSERT INTO response_approvals (approval_id, org_id, agent_id, action, resource,"
            " fingerprint, status, requested_at, expires_at, requested_by, reason, risk_score,"
            " risk_band, risk_evidence, policy_id, policy_version, incident_id, decided_at,"
            " decided_by, decision_reason, delegated_to, params)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (approval_id) DO UPDATE SET status=EXCLUDED.status,"
            " decided_at=EXCLUDED.decided_at, decided_by=EXCLUDED.decided_by,"
            " decision_reason=EXCLUDED.decision_reason, delegated_to=EXCLUDED.delegated_to,"
            " risk_score=EXCLUDED.risk_score, risk_band=EXCLUDED.risk_band,"
            " risk_evidence=EXCLUDED.risk_evidence, incident_id=EXCLUDED.incident_id",
            (a.approval_id, a.org_id, a.agent_id, a.action, a.resource, a.fingerprint, a.status,
             a.requested_at, a.expires_at, a.requested_by, a.reason, a.risk_score, a.risk_band,
             list(a.risk_evidence), a.policy_id, a.policy_version, a.incident_id, a.decided_at,
             a.decided_by, a.decision_reason, a.delegated_to, _json(a.params))))

    def get_approval(self, approval_id: str, *, org_id: str) -> Optional[ApprovalRequest]:
        r = self.db.run("p6_get_approval", lambda c: c.execute(
            "SELECT * FROM response_approvals WHERE approval_id=%s AND org_id=%s",
            (approval_id, org_id)).fetchone())
        return _approval(r) if r else None

    def find_approval_by_fingerprint(self, *, org_id: str, fingerprint: str
                                     ) -> Optional[ApprovalRequest]:
        r = self.db.run("p6_find_approval_fp", lambda c: c.execute(
            "SELECT * FROM response_approvals WHERE org_id=%s AND fingerprint=%s"
            " ORDER BY requested_at DESC LIMIT 1", (org_id, fingerprint)).fetchone())
        return _approval(r) if r else None

    def list_approvals(self, *, org_id: str, status: Optional[str] = None,
                       agent_id: Optional[str] = None, limit: int = 100) -> List[ApprovalRequest]:
        limit = max(1, min(int(limit), 1000))
        clauses, params = ["org_id=%s"], [org_id]
        if status is not None:
            clauses.append("status=%s")
            params.append(status)
        if agent_id is not None:
            clauses.append("agent_id=%s")
            params.append(agent_id)
        params.append(limit)
        sql = ("SELECT * FROM response_approvals WHERE " + " AND ".join(clauses)
               + " ORDER BY requested_at DESC LIMIT %s")
        rows = self.db.run("p6_list_approvals", lambda c: c.execute(sql, tuple(params)).fetchall())
        return [_approval(r) for r in rows]

    def count_pending_approvals(self, *, org_id: str, agent_id: str) -> int:
        r = self.db.run("p6_count_pending", lambda c: c.execute(
            "SELECT count(*) AS n FROM response_approvals WHERE org_id=%s AND agent_id=%s"
            " AND status='pending'", (org_id, agent_id)).fetchone())
        return int(r["n"]) if r else 0

    # ------------------------------------------------------------------ incidents
    def put_incident(self, i: Incident) -> None:
        timeline = [t.to_dict() for t in i.timeline]
        self.db.run("p6_put_incident", lambda c: c.execute(
            "INSERT INTO response_incidents (incident_id, org_id, title, severity, status, opened_at,"
            " updated_at, closed_at, owner, agent_ids, resources, alert_ids, finding_ids,"
            " evidence_ids, response_ids, timeline, detection_source, risk_score, risk_band,"
            " resolution, post_review, correlation_key)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (incident_id) DO UPDATE SET title=EXCLUDED.title,"
            " severity=EXCLUDED.severity, status=EXCLUDED.status, updated_at=EXCLUDED.updated_at,"
            " closed_at=EXCLUDED.closed_at, owner=EXCLUDED.owner, agent_ids=EXCLUDED.agent_ids,"
            " resources=EXCLUDED.resources, alert_ids=EXCLUDED.alert_ids,"
            " finding_ids=EXCLUDED.finding_ids, evidence_ids=EXCLUDED.evidence_ids,"
            " response_ids=EXCLUDED.response_ids, timeline=EXCLUDED.timeline,"
            " risk_score=EXCLUDED.risk_score, risk_band=EXCLUDED.risk_band,"
            " resolution=EXCLUDED.resolution, post_review=EXCLUDED.post_review",
            (i.incident_id, i.org_id, i.title, i.severity, i.status, i.opened_at, i.updated_at,
             i.closed_at, i.owner, list(i.agent_ids), list(i.resources), list(i.alert_ids),
             list(i.finding_ids), list(i.evidence_ids), list(i.response_ids), _json(timeline),
             i.detection_source, i.risk_score, i.risk_band, i.resolution, i.post_review,
             i.correlation_key)))

    def get_incident(self, incident_id: str, *, org_id: str) -> Optional[Incident]:
        r = self.db.run("p6_get_incident", lambda c: c.execute(
            "SELECT * FROM response_incidents WHERE incident_id=%s AND org_id=%s",
            (incident_id, org_id)).fetchone())
        return _incident(r) if r else None

    def list_incidents(self, *, org_id: str, status: Optional[str] = None,
                       agent_id: Optional[str] = None, since: Optional[float] = None,
                       limit: int = 100) -> List[Incident]:
        limit = max(1, min(int(limit), 1000))
        clauses, params = ["org_id=%s"], [org_id]
        if status is not None:
            clauses.append("status=%s")
            params.append(status)
        if agent_id is not None:
            clauses.append("agent_id = ANY(%s)")
            params.append([agent_id])
        if since is not None:
            clauses.append("opened_at >= %s")
            params.append(since)
        params.append(limit)
        sql = ("SELECT * FROM response_incidents WHERE " + " AND ".join(clauses)
               + " ORDER BY opened_at DESC LIMIT %s")
        rows = self.db.run("p6_list_incidents", lambda c: c.execute(sql, tuple(params)).fetchall())
        return [_incident(r) for r in rows]

    def find_open_incident(self, *, org_id: str, correlation_key: str) -> Optional[Incident]:
        if not correlation_key:
            return None
        r = self.db.run("p6_find_open_incident", lambda c: c.execute(
            "SELECT * FROM response_incidents WHERE org_id=%s AND correlation_key=%s"
            " AND status NOT IN ('closed','post_review') ORDER BY opened_at DESC LIMIT 1",
            (org_id, correlation_key)).fetchone())
        return _incident(r) if r else None

    def count_open_incidents(self, *, org_id: str) -> int:
        r = self.db.run("p6_count_open_incidents", lambda c: c.execute(
            "SELECT count(*) AS n FROM response_incidents WHERE org_id=%s"
            " AND status NOT IN ('closed','post_review')", (org_id,)).fetchone())
        return int(r["n"]) if r else 0

    # ------------------------------------------------------------------ responses
    def put_response(self, r: ResponseExecution) -> None:
        steps = [s.to_dict() for s in r.steps]
        rollback = [s.to_dict() for s in r.rollback_steps]
        self.db.run("p6_put_response", lambda c: c.execute(
            "INSERT INTO response_executions (response_id, org_id, idempotency_key, incident_id,"
            " agent_id, task_id, state, trigger, requested_by, approved_by, approval_id, created_at,"
            " updated_at, steps, rollback_steps, partial_failures, evidence_ids, note)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (response_id) DO UPDATE SET state=EXCLUDED.state,"
            " updated_at=EXCLUDED.updated_at, steps=EXCLUDED.steps,"
            " rollback_steps=EXCLUDED.rollback_steps, partial_failures=EXCLUDED.partial_failures,"
            " evidence_ids=EXCLUDED.evidence_ids, note=EXCLUDED.note,"
            " approved_by=EXCLUDED.approved_by, approval_id=EXCLUDED.approval_id,"
            " incident_id=EXCLUDED.incident_id",
            (r.response_id, r.org_id, r.idempotency_key, r.incident_id, r.agent_id, r.task_id,
             r.state, r.trigger, r.requested_by, r.approved_by, r.approval_id, r.created_at,
             r.updated_at, _json(steps), _json(rollback), list(r.partial_failures),
             list(r.evidence_ids), r.note)))

    def get_response(self, response_id: str, *, org_id: str) -> Optional[ResponseExecution]:
        r = self.db.run("p6_get_response", lambda c: c.execute(
            "SELECT * FROM response_executions WHERE response_id=%s AND org_id=%s",
            (response_id, org_id)).fetchone())
        return _response(r) if r else None

    def get_response_by_key(self, *, org_id: str, idempotency_key: str
                            ) -> Optional[ResponseExecution]:
        r = self.db.run("p6_get_response_key", lambda c: c.execute(
            "SELECT * FROM response_executions WHERE org_id=%s AND idempotency_key=%s",
            (org_id, idempotency_key)).fetchone())
        return _response(r) if r else None

    def list_responses(self, *, org_id: str, incident_id: Optional[str] = None,
                       agent_id: Optional[str] = None, limit: int = 100
                       ) -> List[ResponseExecution]:
        limit = max(1, min(int(limit), 1000))
        clauses, params = ["org_id=%s"], [org_id]
        if incident_id is not None:
            clauses.append("incident_id=%s")
            params.append(incident_id)
        if agent_id is not None:
            clauses.append("agent_id=%s")
            params.append(agent_id)
        params.append(limit)
        sql = ("SELECT * FROM response_executions WHERE " + " AND ".join(clauses)
               + " ORDER BY created_at DESC LIMIT %s")
        rows = self.db.run("p6_list_responses", lambda c: c.execute(sql, tuple(params)).fetchall())
        return [_response(r) for r in rows]

    # ------------------------------------------------------------------ evidence
    def put_evidence(self, e: EvidenceRecord) -> None:
        self.db.run("p6_put_evidence", lambda c: c.execute(
            "INSERT INTO response_evidence (evidence_id, org_id, kind, ts, summary, ref, digest,"
            " incident_id, agent_id, source, retention_until, sealed)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (evidence_id) DO UPDATE SET sealed=EXCLUDED.sealed,"
            " retention_until=EXCLUDED.retention_until, incident_id=EXCLUDED.incident_id",
            (e.evidence_id, e.org_id, e.kind, e.ts, e.summary, e.ref, e.digest, e.incident_id,
             e.agent_id, e.source, e.retention_until, e.sealed)))

    def get_evidence(self, evidence_id: str, *, org_id: str) -> Optional[EvidenceRecord]:
        r = self.db.run("p6_get_evidence", lambda c: c.execute(
            "SELECT * FROM response_evidence WHERE evidence_id=%s AND org_id=%s",
            (evidence_id, org_id)).fetchone())
        return _evidence(r) if r else None

    def list_evidence(self, *, org_id: str, incident_id: Optional[str] = None,
                      limit: int = 200) -> List[EvidenceRecord]:
        limit = max(1, min(int(limit), 1000))
        clauses, params = ["org_id=%s"], [org_id]
        if incident_id is not None:
            clauses.append("incident_id=%s")
            params.append(incident_id)
        params.append(limit)
        sql = ("SELECT * FROM response_evidence WHERE " + " AND ".join(clauses)
               + " ORDER BY ts DESC LIMIT %s")
        rows = self.db.run("p6_list_evidence", lambda c: c.execute(sql, tuple(params)).fetchall())
        return [_evidence(r) for r in rows]

    def purge_evidence_before(self, cutoff_ts: float, *, org_id: Optional[str] = None) -> int:
        if org_id is None:
            r = self.db.run("p6_purge_evidence_all", lambda c: c.execute(
                "DELETE FROM response_evidence WHERE ts < %s AND NOT sealed RETURNING evidence_id",
                (cutoff_ts,)).fetchall())
        else:
            r = self.db.run("p6_purge_evidence_org", lambda c: c.execute(
                "DELETE FROM response_evidence WHERE ts < %s AND NOT sealed AND org_id=%s"
                " RETURNING evidence_id", (cutoff_ts, org_id)).fetchall())
        return len(r or [])

    # ------------------------------------------------------------------ audit
    def append_audit(self, event: dict) -> None:
        self.db.run("p6_append_audit", lambda c: c.execute(
            "INSERT INTO response_audit (event_id, ts, event, org_id, agent_id, outcome, reason,"
            " incident_id, approval_id, response_id, evidence_id, actor_user_id, action,"
            " correlation_id, prev_hash, hash)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (event_id) DO NOTHING",
            (event.get("event_id"), event.get("ts"), event.get("event"), event.get("org_id"),
             event.get("agent_id"), event.get("outcome", "ok"), event.get("reason"),
             event.get("incident_id"), event.get("approval_id"), event.get("response_id"),
             event.get("evidence_id"), event.get("actor_user_id"), event.get("action"),
             event.get("correlation_id"), event.get("prev_hash"), event.get("hash"))))

    def list_audit(self, *, org_id: Optional[str] = None, limit: int = 100) -> List[dict]:
        """Records in INSERTION order (oldest first) -- the order the hash chain was built in, so
        ``verify_chain`` can detect reordering and removal. Callers that want newest-first for display
        reverse the list themselves."""
        limit = max(1, min(int(limit), 10_000))
        if org_id is None:
            rows = self.db.run("p6_list_audit_all", lambda c: c.execute(
                "SELECT * FROM response_audit ORDER BY seq ASC LIMIT %s",
                (limit,)).fetchall())
        else:
            rows = self.db.run("p6_list_audit_org", lambda c: c.execute(
                "SELECT * FROM response_audit WHERE org_id=%s OR org_id IS NULL"
                " ORDER BY seq ASC LIMIT %s", (org_id, limit)).fetchall())
        return [dict(r) for r in rows]

    def audit_chain_head(self, *, org_id: Optional[str] = None) -> Optional[dict]:
        if org_id is None:
            r = self.db.run("p6_audit_head_all", lambda c: c.execute(
                "SELECT * FROM response_audit WHERE hash IS NOT NULL"
                " ORDER BY seq DESC LIMIT 1").fetchone())
        else:
            r = self.db.run("p6_audit_head_org", lambda c: c.execute(
                "SELECT * FROM response_audit WHERE hash IS NOT NULL AND (org_id=%s OR org_id IS NULL)"
                " ORDER BY seq DESC LIMIT 1", (org_id,)).fetchone())
        return dict(r) if r else None
