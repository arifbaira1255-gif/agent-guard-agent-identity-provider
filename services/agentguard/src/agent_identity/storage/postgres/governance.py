"""PostgreSQL implementation of ``GovernanceStore`` (authoritative).

All SQL is constant strings; every value is a bound parameter. Tenant-scoped tables additionally run
under RLS (migration 0006), so a forgotten filter still cannot leak across tenants.
"""
from typing import List, Optional

from ...core.errors import StorageError
from ...governance.models import (Operation, ResourceRecord, ResourceType, RiskClass, Sensitivity,
                                  ToolRecord)
from ...governance.store import GovernanceStore


def _jsonb(v):
    from psycopg.types.json import Jsonb
    return Jsonb(v)


def _res(r) -> ResourceRecord:
    return ResourceRecord(
        resource_id=r["resource_id"], org_id=r["org_id"],
        resource_type=ResourceType(r["resource_type"]), name=r["name"], owner=r["owner"],
        sensitivity=Sensitivity(r["sensitivity"]),
        permitted_operations=frozenset(Operation(o) for o in (r["permitted_operations"] or ())),
        policy_refs=tuple(r["policy_refs"] or ()), enabled=r["enabled"], description=r["description"],
        metadata=(dict(r["metadata"]) if r["metadata"] else None), created_at=r["created_at"],
        updated_at=r["updated_at"], created_by=r["created_by"])


def _tool(r) -> ToolRecord:
    return ToolRecord(
        tool_id=r["tool_id"], org_id=r["org_id"], name=r["name"], version=r["tool_version"],
        owner=r["owner"], risk=RiskClass(r["risk"]),
        requested_capabilities=tuple(r["requested_capabilities"] or ()),
        approved_capabilities=tuple(r["approved_capabilities"] or ()), resource_id=r["resource_id"],
        policy_refs=tuple(r["policy_refs"] or ()), enabled=r["enabled"], approved=r["approved"],
        description=r["description"], manifest_checksum=r["manifest_checksum"],
        created_at=r["created_at"], updated_at=r["updated_at"], created_by=r["created_by"],
        approved_by=r["approved_by"])


def _ops(ops) -> list:
    return sorted(o.value for o in (ops or ()))


class PgGovernanceStore(GovernanceStore):
    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------ resources
    def put_resource(self, r: ResourceRecord) -> None:
        self.db.run("s11_put_resource", lambda c: c.execute(
            "INSERT INTO resources (resource_id, org_id, resource_type, name, owner, sensitivity,"
            " permitted_operations, policy_refs, enabled, description, metadata, created_at,"
            " updated_at, created_by)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (resource_id) DO UPDATE SET resource_type=EXCLUDED.resource_type,"
            " name=EXCLUDED.name, owner=EXCLUDED.owner, sensitivity=EXCLUDED.sensitivity,"
            " permitted_operations=EXCLUDED.permitted_operations, policy_refs=EXCLUDED.policy_refs,"
            " enabled=EXCLUDED.enabled, description=EXCLUDED.description, metadata=EXCLUDED.metadata,"
            " updated_at=EXCLUDED.updated_at"
            " WHERE resources.org_id = EXCLUDED.org_id",     # a resource can never change tenant
            (r.resource_id, r.org_id, r.resource_type.value, r.name, r.owner, r.sensitivity.value,
             _ops(r.permitted_operations), list(r.policy_refs), r.enabled, r.description,
             _jsonb(r.metadata) if r.metadata else None, r.created_at, r.updated_at, r.created_by)))

    def get_resource(self, resource_id: str) -> Optional[ResourceRecord]:
        r = self.db.run("s11_get_resource", lambda c: c.execute(
            "SELECT * FROM resources WHERE resource_id=%s", (resource_id,)).fetchone())
        return _res(r) if r else None

    def list_resources(self, *, org_id: Optional[str] = None) -> List[ResourceRecord]:
        if org_id is None:
            rows = self.db.run("s11_list_resources_all", lambda c: c.execute(
                "SELECT * FROM resources ORDER BY org_id, resource_id").fetchall())
        else:
            rows = self.db.run("s11_list_resources_org", lambda c: c.execute(
                "SELECT * FROM resources WHERE org_id=%s ORDER BY resource_id", (org_id,)).fetchall())
        return [_res(r) for r in rows]

    def delete_resource(self, resource_id: str) -> None:
        self.db.run("s11_del_resource", lambda c: c.execute(
            "DELETE FROM resources WHERE resource_id=%s", (resource_id,)))

    # ------------------------------------------------------------------ tools
    def put_tool(self, t: ToolRecord) -> None:
        self.db.run("s11_put_tool", lambda c: c.execute(
            "INSERT INTO tools (tool_id, org_id, name, tool_version, owner, risk, requested_capabilities,"
            " approved_capabilities, resource_id, policy_refs, enabled, approved, description,"
            " manifest_checksum, created_at, updated_at, created_by, approved_by)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (tool_id) DO UPDATE SET tool_version=EXCLUDED.tool_version,"
            " owner=EXCLUDED.owner, risk=EXCLUDED.risk,"
            " requested_capabilities=EXCLUDED.requested_capabilities,"
            " approved_capabilities=EXCLUDED.approved_capabilities, resource_id=EXCLUDED.resource_id,"
            " policy_refs=EXCLUDED.policy_refs, enabled=EXCLUDED.enabled, approved=EXCLUDED.approved,"
            " description=EXCLUDED.description, manifest_checksum=EXCLUDED.manifest_checksum,"
            " updated_at=EXCLUDED.updated_at, approved_by=EXCLUDED.approved_by"
            " WHERE tools.org_id = EXCLUDED.org_id",        # a tool can never change tenant
            (t.tool_id, t.org_id, t.name, t.version, t.owner, t.risk.value,
             list(t.requested_capabilities), list(t.approved_capabilities), t.resource_id,
             list(t.policy_refs), t.enabled, t.approved, t.description, t.manifest_checksum,
             t.created_at, t.updated_at, t.created_by, t.approved_by)))

    def get_tool(self, tool_id: str) -> Optional[ToolRecord]:
        r = self.db.run("s11_get_tool", lambda c: c.execute(
            "SELECT * FROM tools WHERE tool_id=%s", (tool_id,)).fetchone())
        return _tool(r) if r else None

    def list_tools(self, *, org_id: Optional[str] = None) -> List[ToolRecord]:
        if org_id is None:
            rows = self.db.run("s11_list_tools_all", lambda c: c.execute(
                "SELECT * FROM tools ORDER BY org_id, name, version, tool_id").fetchall())
        else:
            rows = self.db.run("s11_list_tools_org", lambda c: c.execute(
                "SELECT * FROM tools WHERE org_id=%s ORDER BY name, version, tool_id",
                (org_id,)).fetchall())
        return [_tool(r) for r in rows]

    def delete_tool(self, tool_id: str) -> None:
        self.db.run("s11_del_tool", lambda c: c.execute(
            "DELETE FROM tools WHERE tool_id=%s", (tool_id,)))

    # ------------------------------------------------------------------ audit
    def append_audit(self, event: dict) -> None:
        self.db.run("s11_append_audit", lambda c: c.execute(
            "INSERT INTO governance_audit (event_id, ts, event, org_id, agent_id, instance_id,"
            " resource_id, resource_type, operation, tool_id, decision, reason, outcome, policy_id,"
            " policy_version, actor_user_id, correlation_id)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (event["event_id"], event["ts"], event["event"], event.get("org_id"),
             event.get("agent_id"), event.get("instance_id"), event.get("resource_id"),
             event.get("resource_type"), event.get("operation"), event.get("tool_id"),
             event.get("decision"), event.get("reason"), event.get("outcome", "ok"),
             event.get("policy_id"), event.get("policy_version"), event.get("actor_user_id"),
             event.get("correlation_id"))))

    def list_audit(self, *, org_id: Optional[str] = None, resource_id: Optional[str] = None,
                   limit: int = 100) -> List[dict]:
        clauses, params = [], []
        if org_id is not None:
            clauses.append("org_id=%s")
            params.append(org_id)
        if resource_id is not None:
            clauses.append("resource_id=%s")
            params.append(resource_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(int(limit))
        rows = self.db.run("s11_list_audit", lambda c: c.execute(
            "SELECT * FROM governance_audit" + where + " ORDER BY ts DESC, event_id DESC LIMIT %s",
            tuple(params)).fetchall())
        return [dict(r) for r in rows]


def create_governance_store(db) -> PgGovernanceStore:
    if db is None:
        raise StorageError("a PostgreSQL database is required for the governance store")
    return PgGovernanceStore(db)
