"""PostgreSQL implementation of ``EgressStore`` (authoritative).

All SQL is constant strings; every value is a bound parameter. Tenant-scoped tables additionally run
under RLS (migration 0007), so a forgotten filter still cannot leak across tenants.

The gateway reads egress policy authoritatively from this store on EVERY decision (no cross-request
cache), which is what makes "no stale allow survives a policy change" true by construction.
"""
from typing import List, Optional

from ...core.errors import StorageError
from ...egress.models import (EgressOutcome, EgressPolicyRecord, Protocol, RateLimitSpec)
from ...egress.store import EgressStore


def _policy(r) -> EgressPolicyRecord:
    rl = None
    if r["rate_per_second"] is not None:
        rl = RateLimitSpec(per_second=float(r["rate_per_second"]),
                           burst=int(r["rate_burst"] or 1))
    return EgressPolicyRecord(
        policy_id=r["policy_id"], org_id=r["org_id"], name=r["name"],
        host_patterns=tuple(r["host_patterns"] or ()),
        protocols=frozenset(Protocol(p) for p in (r["protocols"] or ())),
        ports=frozenset(int(p) for p in (r["ports"] or ())),
        action=EgressOutcome(r["action"]), priority=int(r["priority"]), rate_limit=rl,
        max_request_bytes=r["max_request_bytes"], max_response_bytes=r["max_response_bytes"],
        timeout_ms=r["timeout_ms"], allow_redirects=r["allow_redirects"],
        dlp_enabled=r["dlp_enabled"], description=r["description"], enabled=r["enabled"],
        created_at=r["created_at"], updated_at=r["updated_at"], created_by=r["created_by"])


class PgEgressStore(EgressStore):
    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------ policies
    def put_policy(self, p: EgressPolicyRecord) -> None:
        rl = p.rate_limit
        self.db.run("p4_put_egress_policy", lambda c: c.execute(
            "INSERT INTO egress_policies (policy_id, org_id, name, host_patterns, protocols, ports,"
            " action, priority, rate_per_second, rate_burst, max_request_bytes, max_response_bytes,"
            " timeout_ms, allow_redirects, dlp_enabled, description, enabled, created_at, updated_at,"
            " created_by)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (policy_id) DO UPDATE SET name=EXCLUDED.name,"
            " host_patterns=EXCLUDED.host_patterns, protocols=EXCLUDED.protocols,"
            " ports=EXCLUDED.ports, action=EXCLUDED.action, priority=EXCLUDED.priority,"
            " rate_per_second=EXCLUDED.rate_per_second, rate_burst=EXCLUDED.rate_burst,"
            " max_request_bytes=EXCLUDED.max_request_bytes,"
            " max_response_bytes=EXCLUDED.max_response_bytes, timeout_ms=EXCLUDED.timeout_ms,"
            " allow_redirects=EXCLUDED.allow_redirects, dlp_enabled=EXCLUDED.dlp_enabled,"
            " description=EXCLUDED.description, enabled=EXCLUDED.enabled,"
            " updated_at=EXCLUDED.updated_at"
            " WHERE egress_policies.org_id = EXCLUDED.org_id",   # a policy can never change tenant
            (p.policy_id, p.org_id, p.name, list(p.host_patterns),
             sorted(proto.value for proto in p.protocols), sorted(int(x) for x in p.ports),
             p.action.value, int(p.priority),
             (rl.per_second if rl else None), (rl.burst if rl else None),
             p.max_request_bytes, p.max_response_bytes, p.timeout_ms, p.allow_redirects,
             p.dlp_enabled, p.description, p.enabled, p.created_at, p.updated_at, p.created_by)))

    def get_policy(self, policy_id: str) -> Optional[EgressPolicyRecord]:
        r = self.db.run("p4_get_egress_policy", lambda c: c.execute(
            "SELECT * FROM egress_policies WHERE policy_id=%s", (policy_id,)).fetchone())
        return _policy(r) if r else None

    def list_policies(self, *, org_id: Optional[str] = None) -> List[EgressPolicyRecord]:
        if org_id is None:
            rows = self.db.run("p4_list_egress_policies_all", lambda c: c.execute(
                "SELECT * FROM egress_policies ORDER BY org_id, priority DESC, policy_id").fetchall())
        else:
            rows = self.db.run("p4_list_egress_policies_org", lambda c: c.execute(
                "SELECT * FROM egress_policies WHERE org_id=%s ORDER BY priority DESC, policy_id",
                (org_id,)).fetchall())
        return [_policy(r) for r in rows]

    def delete_policy(self, policy_id: str) -> None:
        self.db.run("p4_del_egress_policy", lambda c: c.execute(
            "DELETE FROM egress_policies WHERE policy_id=%s", (policy_id,)))

    # ------------------------------------------------------------------ audit
    def append_audit(self, event: dict) -> None:
        self.db.run("p4_append_egress_audit", lambda c: c.execute(
            "INSERT INTO egress_audit (event_id, ts, event, org_id, agent_id, instance_id,"
            " destination, host, port, protocol, resource_id, operation, decision, reason, outcome,"
            " policy_id, policy_version, dlp_rule_ids, dlp_severity, resolved_ips, address_class,"
            " actor_user_id, correlation_id, latency_ms)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (event["event_id"], event["ts"], event["event"], event.get("org_id"),
             event.get("agent_id"), event.get("instance_id"), event.get("destination"),
             event.get("host"), event.get("port"), event.get("protocol"),
             event.get("resource_id"), event.get("operation"), event.get("decision"),
             event.get("reason"), event.get("outcome", "ok"), event.get("policy_id"),
             event.get("policy_version"), list(event.get("dlp_rule_ids") or ()),
             event.get("dlp_severity"), list(event.get("resolved_ips") or ()),
             event.get("address_class"), event.get("actor_user_id"), event.get("correlation_id"),
             event.get("latency_ms"))))

    def list_audit(self, *, org_id: Optional[str] = None, destination: Optional[str] = None,
                   limit: int = 100) -> List[dict]:
        clauses, params = [], []
        if org_id is not None:
            clauses.append("org_id=%s")
            params.append(org_id)
        if destination is not None:
            clauses.append("destination=%s")
            params.append(destination)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(int(limit))
        rows = self.db.run("p4_list_egress_audit", lambda c: c.execute(
            "SELECT * FROM egress_audit" + where + " ORDER BY ts DESC, event_id DESC LIMIT %s",
            tuple(params)).fetchall())
        return [dict(r) for r in rows]


def create_egress_store(db) -> PgEgressStore:
    if db is None:
        raise StorageError("a PostgreSQL database is required for the egress store")
    return PgEgressStore(db)
