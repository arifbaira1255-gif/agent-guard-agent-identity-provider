"""PostgreSQL implementation of ``AssuranceStore`` (authoritative).

All SQL is constant strings; every value is a bound parameter. Every tenant-scoped table additionally
runs under RLS (migration 0010), so a forgotten filter still cannot leak across tenants.

Atomicity / integrity notes:

* ``assurance_audit`` rejects UPDATE via a trigger (append-only). The hash chain is built in INSERTION
  order and read back with ``ORDER BY seq ASC`` -- ``seq`` is the monotonic insertion counter, so
  reordering and removal are detectable by ``verify_chain``.
* ``put_proposal`` is an upsert keyed by ``proposal_id``; the lifecycle service is the only writer and
  it re-reads before every transition, so a lost update surfaces as a conflict rather than a silent
  overwrite.
* ``assurance_compliance_mappings`` is platform-wide (not tenant-scoped) and has a UNIQUE index on
  ``(framework, control_id)`` so the seed catalogue is idempotent.
"""
from __future__ import annotations

import json
from typing import List, Optional

from ...assurance.models import (AuditChainRecord, AuditCheckpoint, ComplianceControlMapping,
                                 CorrelationFinding, PolicyProposal, PolicyRecommendation,
                                 SecurityEvidence, SiemDelivery, SiemEvent)
from ...assurance.store import AssuranceStore


def _json(value) -> str:
    return json.dumps(value if value is not None else {}, separators=(",", ":"), default=str)


def _json_or_none(value):
    return None if value is None else _json(value)


def _evidence(r) -> SecurityEvidence:
    return SecurityEvidence(
        evidence_id=r["evidence_id"], org_id=r["org_id"], kind=r["kind"], ts=float(r["ts"]),
        summary=r["summary"], source=r["source"], agent_id=r["agent_id"], ref=r["ref"],
        digest=r["digest"], severity=r["severity"], count=int(r["count"]),
        correlation_id=r["correlation_id"], provenance=r["provenance"], detail=r["detail"])


def _recommendation(r) -> PolicyRecommendation:
    return PolicyRecommendation(
        recommendation_id=r["recommendation_id"], org_id=r["org_id"], created_at=float(r["created_at"]),
        kind=r["kind"], title=r["title"], target_policy_id=r["target_policy_id"],
        target_rule=r["target_rule"], proposed_change=r["proposed_change"] or {},
        observed_facts=tuple(r["observed_facts"] or ()),
        heuristic_conclusions=tuple(r["heuristic_conclusions"] or ()),
        evidence_ids=tuple(r["evidence_ids"] or ()), expected_benefit=r["expected_benefit"],
        operational_impact=r["operational_impact"], confidence=float(r["confidence"]),
        uncertainty=r["uncertainty"], impact_level=r["impact_level"],
        requires_approval=bool(r["requires_approval"]),
        test_requirements=tuple(r["test_requirements"] or ()), rollback_plan=r["rollback_plan"],
        status=r["status"], provenance=r["provenance"])


def _proposal(r) -> PolicyProposal:
    return PolicyProposal(
        proposal_id=r["proposal_id"], org_id=r["org_id"], recommendation_id=r["recommendation_id"],
        policy_id=r["policy_id"], base_version=r["base_version"], proposed_rego=r["proposed_rego"],
        checksum=r["checksum"], status=r["status"], impact_level=r["impact_level"],
        created_at=float(r["created_at"]), created_by=r["created_by"], updated_at=float(r["updated_at"]),
        title=r["title"], rationale=r["rationale"],
        validated_at=(float(r["validated_at"]) if r["validated_at"] is not None else None),
        validation_summary=r["validation_summary"], simulation_summary=r["simulation_summary"],
        approvals=tuple(r["approvals"] or ()), canary=r["canary"],
        activated_at=(float(r["activated_at"]) if r["activated_at"] is not None else None),
        activated_by=r["activated_by"], activated_version=r["activated_version"],
        rolled_back_at=(float(r["rolled_back_at"]) if r["rolled_back_at"] is not None else None),
        rolled_back_to=r["rolled_back_to"],
        expires_at=(float(r["expires_at"]) if r["expires_at"] is not None else None),
        emergency=bool(r["emergency"]), provenance=tuple(r["provenance"] or ()))


def _mapping(r) -> ComplianceControlMapping:
    return ComplianceControlMapping(
        mapping_id=r["mapping_id"], framework=r["framework"], control_id=r["control_id"],
        control_title=r["control_title"], description=r["description"], scope=r["scope"],
        evidence_source=r["evidence_source"], owner_component=r["owner_component"],
        verification_status=r["verification_status"],
        evidence_ts=(float(r["evidence_ts"]) if r["evidence_ts"] is not None else None),
        provenance=r["provenance"], known_gaps=tuple(r["known_gaps"] or ()),
        last_review=(float(r["last_review"]) if r["last_review"] is not None else None),
        next_review=(float(r["next_review"]) if r["next_review"] is not None else None),
        evidence_refs=tuple(r["evidence_refs"] or ()))


def _siem_event(r) -> SiemEvent:
    return SiemEvent(
        event_id=r["event_id"], ts=float(r["ts"]), org_id=r["org_id"], severity=r["severity"],
        category=r["category"], action=r["action"], outcome=r["outcome"], source=r["source"],
        dedup_key=r["dedup_key"], correlation_id=r["correlation_id"], agent_id=r["agent_id"],
        classification=r["classification"], provenance=r["provenance"], incident_id=r["incident_id"],
        policy_id=r["policy_id"], policy_version=r["policy_version"], fields=r["fields"])


def _delivery(r) -> SiemDelivery:
    return SiemDelivery(
        delivery_id=r["delivery_id"], destination_id=r["destination_id"], event_id=r["event_id"],
        org_id=r["org_id"], status=r["status"], attempts=int(r["attempts"]), ts=float(r["ts"]),
        last_error=r["last_error"],
        next_attempt_at=(float(r["next_attempt_at"]) if r["next_attempt_at"] is not None else None))


def _correlation(r) -> CorrelationFinding:
    return CorrelationFinding(
        finding_id=r["finding_id"], org_id=r["org_id"], correlation_id=r["correlation_id"],
        ts=float(r["ts"]), severity=r["severity"], summary=r["summary"],
        event_ids=tuple(r["event_ids"] or ()), dedup_key=r["dedup_key"],
        related_incident_id=r["related_incident_id"], policy_id=r["policy_id"],
        agent_id=r["agent_id"], provenance=r["provenance"], detail=r["detail"])


def _audit(r) -> AuditChainRecord:
    return AuditChainRecord(
        seq=int(r["seq"]), record_id=r["record_id"], org_id=r["org_id"], ts=float(r["ts"]),
        event=r["event"], actor_user_id=r["actor_user_id"], outcome=r["outcome"], reason=r["reason"],
        payload_digest=r["payload_digest"], prev_hash=r["prev_hash"], hash=r["hash"],
        signature=r["signature"], key_id=r["key_id"], key_version=r["key_version"],
        correlation_id=r["correlation_id"], detail=r["detail"])


def _checkpoint(r) -> AuditCheckpoint:
    return AuditCheckpoint(
        checkpoint_id=r["checkpoint_id"], org_id=r["org_id"], seq=int(r["seq"]),
        head_hash=r["head_hash"], record_count=int(r["record_count"]), ts=float(r["ts"]),
        signature=r["signature"], key_id=r["key_id"], key_version=r["key_version"])


class PostgresAssuranceStore(AssuranceStore):
    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------ evidence
    def put_evidence(self, e: SecurityEvidence) -> None:
        self.db.run("p7_put_evidence", lambda c: c.execute(
            "INSERT INTO assurance_evidence (evidence_id, org_id, kind, ts, summary, source,"
            " agent_id, ref, digest, severity, count, correlation_id, provenance, detail)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (evidence_id) DO NOTHING",
            (e.evidence_id, e.org_id, e.kind, e.ts, e.summary, e.source, e.agent_id, e.ref, e.digest,
             e.severity, e.count, e.correlation_id, e.provenance, _json(e.detail))))

    def get_evidence(self, evidence_id: str, *, org_id: str) -> Optional[SecurityEvidence]:
        r = self.db.run("p7_get_evidence", lambda c: c.execute(
            "SELECT * FROM assurance_evidence WHERE evidence_id=%s AND org_id=%s",
            (evidence_id, org_id)).fetchone())
        return _evidence(r) if r else None

    def list_evidence(self, *, org_id: str, kind: Optional[str] = None,
                      since: Optional[float] = None, limit: int = 500) -> List[SecurityEvidence]:
        limit = max(1, min(int(limit), 5_000))
        clauses, params = ["org_id=%s"], [org_id]
        if kind is not None:
            clauses.append("kind=%s")
            params.append(kind)
        if since is not None:
            clauses.append("ts >= %s")
            params.append(since)
        params.append(limit)
        sql = ("SELECT * FROM assurance_evidence WHERE " + " AND ".join(clauses)
               + " ORDER BY ts DESC, evidence_id DESC LIMIT %s")
        rows = self.db.run("p7_list_evidence", lambda c: c.execute(sql, tuple(params)).fetchall())
        return [_evidence(r) for r in rows]

    # ------------------------------------------------------------------ recommendations
    def put_recommendation(self, r: PolicyRecommendation) -> None:
        self.db.run("p7_put_recommendation", lambda c: c.execute(
            "INSERT INTO assurance_recommendations (recommendation_id, org_id, created_at, kind,"
            " title, target_policy_id, target_rule, proposed_change, observed_facts,"
            " heuristic_conclusions, evidence_ids, expected_benefit, operational_impact, confidence,"
            " uncertainty, impact_level, requires_approval, test_requirements, rollback_plan, status,"
            " provenance) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (recommendation_id) DO UPDATE SET status=EXCLUDED.status",
            (r.recommendation_id, r.org_id, r.created_at, r.kind, r.title, r.target_policy_id,
             r.target_rule, _json(r.proposed_change), list(r.observed_facts),
             list(r.heuristic_conclusions), list(r.evidence_ids), r.expected_benefit,
             r.operational_impact, r.confidence, r.uncertainty, r.impact_level, r.requires_approval,
             list(r.test_requirements), r.rollback_plan, r.status, r.provenance)))

    def get_recommendation(self, recommendation_id: str, *,
                           org_id: str) -> Optional[PolicyRecommendation]:
        r = self.db.run("p7_get_recommendation", lambda c: c.execute(
            "SELECT * FROM assurance_recommendations WHERE recommendation_id=%s AND org_id=%s",
            (recommendation_id, org_id)).fetchone())
        return _recommendation(r) if r else None

    def list_recommendations(self, *, org_id: str, status: Optional[str] = None,
                             limit: int = 100) -> List[PolicyRecommendation]:
        limit = max(1, min(int(limit), 1_000))
        clauses, params = ["org_id=%s"], [org_id]
        if status is not None:
            clauses.append("status=%s")
            params.append(status)
        params.append(limit)
        sql = ("SELECT * FROM assurance_recommendations WHERE " + " AND ".join(clauses)
               + " ORDER BY created_at DESC LIMIT %s")
        rows = self.db.run("p7_list_recommendations",
                           lambda c: c.execute(sql, tuple(params)).fetchall())
        return [_recommendation(r) for r in rows]

    # ------------------------------------------------------------------ proposals
    def put_proposal(self, p: PolicyProposal) -> None:
        self.db.run("p7_put_proposal", lambda c: c.execute(
            "INSERT INTO assurance_proposals (proposal_id, org_id, recommendation_id, policy_id,"
            " base_version, proposed_rego, checksum, status, impact_level, created_at, created_by,"
            " updated_at, title, rationale, validated_at, validation_summary, simulation_summary,"
            " approvals, canary, activated_at, activated_by, activated_version, rolled_back_at,"
            " rolled_back_to, expires_at, emergency, provenance)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (proposal_id) DO UPDATE SET status=EXCLUDED.status,"
            " policy_id=EXCLUDED.policy_id, updated_at=EXCLUDED.updated_at,"
            " validated_at=EXCLUDED.validated_at, validation_summary=EXCLUDED.validation_summary,"
            " simulation_summary=EXCLUDED.simulation_summary, approvals=EXCLUDED.approvals,"
            " canary=EXCLUDED.canary, activated_at=EXCLUDED.activated_at,"
            " activated_by=EXCLUDED.activated_by, activated_version=EXCLUDED.activated_version,"
            " rolled_back_at=EXCLUDED.rolled_back_at, rolled_back_to=EXCLUDED.rolled_back_to,"
            " provenance=EXCLUDED.provenance",
            (p.proposal_id, p.org_id, p.recommendation_id, p.policy_id, p.base_version,
             p.proposed_rego, p.checksum, p.status, p.impact_level, p.created_at, p.created_by,
             p.updated_at, p.title, p.rationale, p.validated_at, _json_or_none(p.validation_summary),
             _json_or_none(p.simulation_summary), _json(list(p.approvals)), _json_or_none(p.canary),
             p.activated_at, p.activated_by, p.activated_version, p.rolled_back_at, p.rolled_back_to,
             p.expires_at, p.emergency, _json(list(p.provenance)))))

    def get_proposal(self, proposal_id: str, *, org_id: str) -> Optional[PolicyProposal]:
        r = self.db.run("p7_get_proposal", lambda c: c.execute(
            "SELECT * FROM assurance_proposals WHERE proposal_id=%s AND org_id=%s",
            (proposal_id, org_id)).fetchone())
        return _proposal(r) if r else None

    def list_proposals(self, *, org_id: str, status: Optional[str] = None,
                       limit: int = 100) -> List[PolicyProposal]:
        limit = max(1, min(int(limit), 1_000))
        clauses, params = ["org_id=%s"], [org_id]
        if status is not None:
            clauses.append("status=%s")
            params.append(status)
        params.append(limit)
        sql = ("SELECT * FROM assurance_proposals WHERE " + " AND ".join(clauses)
               + " ORDER BY created_at DESC LIMIT %s")
        rows = self.db.run("p7_list_proposals", lambda c: c.execute(sql, tuple(params)).fetchall())
        return [_proposal(r) for r in rows]

    def count_pending_proposals(self, *, org_id: str) -> int:
        r = self.db.run("p7_count_pending_proposals", lambda c: c.execute(
            "SELECT count(*) AS n FROM assurance_proposals WHERE org_id=%s"
            " AND status IN ('pending_approval','approved','canary')", (org_id,)).fetchone())
        return int(r["n"]) if r else 0

    # ------------------------------------------------------------------ compliance
    def put_mapping(self, m: ComplianceControlMapping) -> None:
        self.db.run("p7_put_mapping", lambda c: c.execute(
            "INSERT INTO assurance_compliance_mappings (mapping_id, framework, control_id,"
            " control_title, description, scope, evidence_source, owner_component,"
            " verification_status, evidence_ts, provenance, known_gaps, last_review, next_review,"
            " evidence_refs) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (mapping_id) DO UPDATE SET control_title=EXCLUDED.control_title,"
            " description=EXCLUDED.description, scope=EXCLUDED.scope,"
            " evidence_source=EXCLUDED.evidence_source, owner_component=EXCLUDED.owner_component,"
            " verification_status=EXCLUDED.verification_status, evidence_ts=EXCLUDED.evidence_ts,"
            " known_gaps=EXCLUDED.known_gaps, last_review=EXCLUDED.last_review,"
            " next_review=EXCLUDED.next_review, evidence_refs=EXCLUDED.evidence_refs",
            (m.mapping_id, m.framework, m.control_id, m.control_title, m.description, m.scope,
             m.evidence_source, m.owner_component, m.verification_status, m.evidence_ts, m.provenance,
             list(m.known_gaps), m.last_review, m.next_review, list(m.evidence_refs))))

    def get_mapping(self, mapping_id: str) -> Optional[ComplianceControlMapping]:
        r = self.db.run("p7_get_mapping", lambda c: c.execute(
            "SELECT * FROM assurance_compliance_mappings WHERE mapping_id=%s",
            (mapping_id,)).fetchone())
        return _mapping(r) if r else None

    def list_mappings(self, *, framework: Optional[str] = None,
                      limit: int = 1_000) -> List[ComplianceControlMapping]:
        limit = max(1, min(int(limit), 10_000))
        if framework is None:
            rows = self.db.run("p7_list_mappings_all", lambda c: c.execute(
                "SELECT * FROM assurance_compliance_mappings ORDER BY framework, control_id LIMIT %s",
                (limit,)).fetchall())
        else:
            rows = self.db.run("p7_list_mappings_fw", lambda c: c.execute(
                "SELECT * FROM assurance_compliance_mappings WHERE framework=%s"
                " ORDER BY control_id LIMIT %s", (framework, limit)).fetchall())
        return [_mapping(r) for r in rows]

    # ------------------------------------------------------------------ SIEM events + deliveries
    def put_siem_event(self, e: SiemEvent) -> None:
        self.db.run("p7_put_siem_event", lambda c: c.execute(
            "INSERT INTO assurance_siem_events (event_id, ts, org_id, severity, category, action,"
            " outcome, source, dedup_key, correlation_id, agent_id, classification, provenance,"
            " incident_id, policy_id, policy_version, fields)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (event_id) DO NOTHING",
            (e.event_id, e.ts, e.org_id, e.severity, e.category, e.action, e.outcome, e.source,
             e.dedup_key, e.correlation_id, e.agent_id, e.classification, e.provenance, e.incident_id,
             e.policy_id, e.policy_version, _json(e.fields))))

    def get_siem_event(self, event_id: str, *, org_id: Optional[str] = None) -> Optional[SiemEvent]:
        if org_id is None:
            r = self.db.run("p7_get_siem_event", lambda c: c.execute(
                "SELECT * FROM assurance_siem_events WHERE event_id=%s", (event_id,)).fetchone())
        else:
            r = self.db.run("p7_get_siem_event_org", lambda c: c.execute(
                "SELECT * FROM assurance_siem_events WHERE event_id=%s AND org_id=%s",
                (event_id, org_id)).fetchone())
        return _siem_event(r) if r else None

    def list_siem_events(self, *, org_id: Optional[str] = None, since: Optional[float] = None,
                         limit: int = 500) -> List[SiemEvent]:
        limit = max(1, min(int(limit), 5_000))
        clauses, params = [], []
        if org_id is not None:
            clauses.append("org_id=%s")
            params.append(org_id)
        if since is not None:
            clauses.append("ts >= %s")
            params.append(since)
        params.append(limit)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = ("SELECT * FROM assurance_siem_events" + where
               + " ORDER BY ts DESC, event_id DESC LIMIT %s")
        rows = self.db.run("p7_list_siem_events", lambda c: c.execute(sql, tuple(params)).fetchall())
        return [_siem_event(r) for r in rows]

    def put_delivery(self, d: SiemDelivery) -> None:
        self.db.run("p7_put_delivery", lambda c: c.execute(
            "INSERT INTO assurance_siem_deliveries (delivery_id, destination_id, event_id, org_id,"
            " status, attempts, ts, last_error, next_attempt_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (delivery_id) DO UPDATE SET status=EXCLUDED.status,"
            " attempts=EXCLUDED.attempts, ts=EXCLUDED.ts, last_error=EXCLUDED.last_error,"
            " next_attempt_at=EXCLUDED.next_attempt_at",
            (d.delivery_id, d.destination_id, d.event_id, d.org_id, d.status, d.attempts, d.ts,
             d.last_error, d.next_attempt_at)))

    def get_delivery(self, delivery_id: str) -> Optional[SiemDelivery]:
        r = self.db.run("p7_get_delivery", lambda c: c.execute(
            "SELECT * FROM assurance_siem_deliveries WHERE delivery_id=%s",
            (delivery_id,)).fetchone())
        return _delivery(r) if r else None

    def list_deliveries(self, *, destination_id: Optional[str] = None, status: Optional[str] = None,
                        limit: int = 500) -> List[SiemDelivery]:
        limit = max(1, min(int(limit), 5_000))
        clauses, params = [], []
        if destination_id is not None:
            clauses.append("destination_id=%s")
            params.append(destination_id)
        if status is not None:
            clauses.append("status=%s")
            params.append(status)
        params.append(limit)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = ("SELECT * FROM assurance_siem_deliveries" + where
               + " ORDER BY ts DESC, delivery_id DESC LIMIT %s")
        rows = self.db.run("p7_list_deliveries", lambda c: c.execute(sql, tuple(params)).fetchall())
        return [_delivery(r) for r in rows]

    # ------------------------------------------------------------------ correlation
    def put_correlation(self, f: CorrelationFinding) -> None:
        self.db.run("p7_put_correlation", lambda c: c.execute(
            "INSERT INTO assurance_correlations (finding_id, org_id, correlation_id, ts, severity,"
            " summary, event_ids, dedup_key, related_incident_id, policy_id, agent_id, provenance,"
            " detail) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (finding_id) DO NOTHING",
            (f.finding_id, f.org_id, f.correlation_id, f.ts, f.severity, f.summary,
             list(f.event_ids), f.dedup_key, f.related_incident_id, f.policy_id, f.agent_id,
             f.provenance, _json(f.detail))))

    def list_correlations(self, *, org_id: str, since: Optional[float] = None,
                          limit: int = 200) -> List[CorrelationFinding]:
        limit = max(1, min(int(limit), 2_000))
        clauses, params = ["org_id=%s"], [org_id]
        if since is not None:
            clauses.append("ts >= %s")
            params.append(since)
        params.append(limit)
        sql = ("SELECT * FROM assurance_correlations WHERE " + " AND ".join(clauses)
               + " ORDER BY ts DESC LIMIT %s")
        rows = self.db.run("p7_list_correlations", lambda c: c.execute(sql, tuple(params)).fetchall())
        return [_correlation(r) for r in rows]

    # ------------------------------------------------------------------ tamper-evident audit
    def append_audit(self, record: AuditChainRecord) -> None:
        self.db.run("p7_append_audit", lambda c: c.execute(
            "INSERT INTO assurance_audit (seq, record_id, org_id, ts, event, actor_user_id, outcome,"
            " reason, payload_digest, prev_hash, hash, signature, key_id, key_version,"
            " correlation_id, detail) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (record_id) DO NOTHING",
            (record.seq, record.record_id, record.org_id, record.ts, record.event,
             record.actor_user_id, record.outcome, record.reason, record.payload_digest,
             record.prev_hash, record.hash, record.signature, record.key_id, record.key_version,
             record.correlation_id, _json_or_none(record.detail))))

    def list_audit(self, *, org_id: Optional[str] = None, limit: int = 1_000
                   ) -> List[AuditChainRecord]:
        """INSERTION order (oldest first) -- the order the hash chain was built in."""
        limit = max(1, min(int(limit), 100_000))
        if org_id is None:
            rows = self.db.run("p7_list_audit_all", lambda c: c.execute(
                "SELECT * FROM assurance_audit ORDER BY insert_order ASC LIMIT %s",
                (limit,)).fetchall())
        else:
            rows = self.db.run("p7_list_audit_org", lambda c: c.execute(
                "SELECT * FROM assurance_audit WHERE org_id=%s OR org_id IS NULL"
                " ORDER BY insert_order ASC LIMIT %s", (org_id, limit)).fetchall())
        return [_audit(r) for r in rows]

    def audit_chain_head(self, *, org_id: Optional[str] = None) -> Optional[AuditChainRecord]:
        if org_id is None:
            r = self.db.run("p7_audit_head_all", lambda c: c.execute(
                "SELECT * FROM assurance_audit ORDER BY insert_order DESC LIMIT 1").fetchone())
        else:
            r = self.db.run("p7_audit_head_org", lambda c: c.execute(
                "SELECT * FROM assurance_audit WHERE org_id=%s OR org_id IS NULL"
                " ORDER BY insert_order DESC LIMIT 1", (org_id,)).fetchone())
        return _audit(r) if r else None

    def audit_count(self, *, org_id: Optional[str] = None) -> int:
        if org_id is None:
            r = self.db.run("p7_audit_count_all", lambda c: c.execute(
                "SELECT count(*) AS n FROM assurance_audit").fetchone())
        else:
            r = self.db.run("p7_audit_count_org", lambda c: c.execute(
                "SELECT count(*) AS n FROM assurance_audit WHERE org_id=%s OR org_id IS NULL",
                (org_id,)).fetchone())
        return int(r["n"]) if r else 0

    def put_checkpoint(self, c: AuditCheckpoint) -> None:
        self.db.run("p7_put_checkpoint", lambda c_: c_.execute(
            "INSERT INTO assurance_checkpoints (checkpoint_id, org_id, seq, head_hash, record_count,"
            " ts, signature, key_id, key_version) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (checkpoint_id) DO NOTHING",
            (c.checkpoint_id, c.org_id, c.seq, c.head_hash, c.record_count, c.ts, c.signature,
             c.key_id, c.key_version)))

    def get_checkpoint(self, checkpoint_id: str) -> Optional[AuditCheckpoint]:
        r = self.db.run("p7_get_checkpoint", lambda c: c.execute(
            "SELECT * FROM assurance_checkpoints WHERE checkpoint_id=%s",
            (checkpoint_id,)).fetchone())
        return _checkpoint(r) if r else None

    def latest_checkpoint(self, *, org_id: Optional[str] = None) -> Optional[AuditCheckpoint]:
        if org_id is None:
            r = self.db.run("p7_latest_checkpoint_all", lambda c: c.execute(
                "SELECT * FROM assurance_checkpoints WHERE org_id IS NULL"
                " ORDER BY seq DESC, ts DESC LIMIT 1").fetchone())
        else:
            r = self.db.run("p7_latest_checkpoint_org", lambda c: c.execute(
                "SELECT * FROM assurance_checkpoints WHERE org_id=%s"
                " ORDER BY seq DESC, ts DESC LIMIT 1", (org_id,)).fetchone())
        return _checkpoint(r) if r else None

    def list_checkpoints(self, *, org_id: Optional[str] = None,
                         limit: int = 100) -> List[AuditCheckpoint]:
        limit = max(1, min(int(limit), 1_000))
        if org_id is None:
            rows = self.db.run("p7_list_checkpoints_all", lambda c: c.execute(
                "SELECT * FROM assurance_checkpoints WHERE org_id IS NULL"
                " ORDER BY seq DESC LIMIT %s", (limit,)).fetchall())
        else:
            rows = self.db.run("p7_list_checkpoints_org", lambda c: c.execute(
                "SELECT * FROM assurance_checkpoints WHERE org_id=%s ORDER BY seq DESC LIMIT %s",
                (org_id, limit)).fetchall())
        return [_checkpoint(r) for r in rows]
