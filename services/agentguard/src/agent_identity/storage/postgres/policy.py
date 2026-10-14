"""PostgreSQL implementation of ``PolicyStore`` (authoritative). All SQL is constant strings; every
value is a bound parameter. Tenant-scoped tables additionally run under RLS (migration 0005).
"""
from typing import List, Optional

from ...core.errors import ConflictError, StorageError
from ...policy.models import (ApprovalRequest, ApprovalStatus, GrantStatus, JitGrant, PolicyRecord,
                              PolicyStatus, PolicyVersion, VersionStatus)
from ...policy.store import PolicyStore


def _jsonb(v):
    from psycopg.types.json import Jsonb
    return Jsonb(v)


def _p(r) -> PolicyRecord:
    return PolicyRecord(r["policy_id"], r["org_id"], r["name"], r["description"], r["owner_user_id"],
                        PolicyStatus(r["status"]), r["active_version"], r["created_at"],
                        r["updated_at"], r["created_by"])


def _v(r) -> PolicyVersion:
    return PolicyVersion(r["policy_id"], r["version"], r["org_id"], r["rego_source"], r["checksum"],
                         VersionStatus(r["status"]), r["created_at"], r["created_by"],
                         r["activated_at"], dict(r["test_summary"]) if r["test_summary"] else None)


def _g(r) -> JitGrant:
    return JitGrant(r["grant_id"], r["org_id"], r["agent_id"], r["instance_id"], r["action"],
                    r["resource"], r["issued_at"], r["expires_at"], r["policy_version"],
                    GrantStatus(r["status"]), r["issued_by"], r["reason"],
                    dict(r["context"]) if r["context"] else None, r["revoked_at"], r["revoked_reason"])


def _a(r) -> ApprovalRequest:
    return ApprovalRequest(r["approval_id"], r["org_id"], r["agent_id"], r["action"], r["resource"],
                           ApprovalStatus(r["status"]), r["requested_at"], r["expires_at"],
                           r["requested_by"], r["decided_at"], r["decided_by"], r["reason"],
                           dict(r["context"]) if r["context"] else None)


class PgPolicyStore(PolicyStore):
    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------ policies
    def put_policy(self, p: PolicyRecord) -> None:
        self.db.run("s10_put_policy", lambda c: c.execute(
            "INSERT INTO policies (policy_id, org_id, name, description, owner_user_id, status,"
            " active_version, created_at, updated_at, created_by)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (policy_id) DO UPDATE SET name=EXCLUDED.name,"
            " description=EXCLUDED.description, owner_user_id=EXCLUDED.owner_user_id,"
            " status=EXCLUDED.status, active_version=EXCLUDED.active_version,"
            " updated_at=EXCLUDED.updated_at"
            " WHERE policies.org_id IS NOT DISTINCT FROM EXCLUDED.org_id"
            " AND policies.created_at = EXCLUDED.created_at",          # org/creation are immutable
            (p.policy_id, p.org_id, p.name, p.description, p.owner_user_id, p.status.value,
             p.active_version, p.created_at, p.updated_at, p.created_by)))

    def get_policy(self, policy_id: str) -> Optional[PolicyRecord]:
        r = self.db.run("s10_get_policy", lambda c: c.execute(
            "SELECT * FROM policies WHERE policy_id=%s", (policy_id,)).fetchone())
        return _p(r) if r else None

    def list_policies(self, *, org_id: Optional[str] = None,
                      include_platform: bool = True) -> List[PolicyRecord]:
        if org_id is None:
            rows = self.db.run("s10_list_policies_all", lambda c: c.execute(
                "SELECT * FROM policies ORDER BY org_id NULLS FIRST, policy_id").fetchall())
        elif include_platform:
            rows = self.db.run("s10_list_policies_org", lambda c: c.execute(
                "SELECT * FROM policies WHERE org_id=%s OR org_id IS NULL"
                " ORDER BY org_id NULLS FIRST, policy_id", (org_id,)).fetchall())
        else:
            rows = self.db.run("s10_list_policies_org_only", lambda c: c.execute(
                "SELECT * FROM policies WHERE org_id=%s ORDER BY policy_id", (org_id,)).fetchall())
        return [_p(r) for r in rows]

    def delete_policy(self, policy_id: str) -> None:
        self.db.run("s10_del_policy", lambda c: c.execute(
            "DELETE FROM policies WHERE policy_id=%s", (policy_id,)))

    # ------------------------------------------------------------------ versions
    def put_version(self, v: PolicyVersion) -> None:
        def go(c):
            cur = c.execute(
                "INSERT INTO policy_versions (policy_id, version, org_id, rego_source, checksum,"
                " status, created_at, created_by, activated_at, test_summary)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (policy_id, version) DO UPDATE SET status=EXCLUDED.status,"
                " activated_at=EXCLUDED.activated_at, test_summary=EXCLUDED.test_summary"
                " WHERE policy_versions.checksum = EXCLUDED.checksum",   # source is immutable
                (v.policy_id, v.version, v.org_id, v.rego_source, v.checksum, v.status.value,
                 v.created_at, v.created_by, v.activated_at,
                 _jsonb(v.test_summary) if v.test_summary else None))
            if cur.rowcount != 1:
                raise ConflictError("policy version is immutable")
        self.db.run("s10_put_version", go)

    def get_version(self, policy_id: str, version: int) -> Optional[PolicyVersion]:
        r = self.db.run("s10_get_version", lambda c: c.execute(
            "SELECT * FROM policy_versions WHERE policy_id=%s AND version=%s",
            (policy_id, version)).fetchone())
        return _v(r) if r else None

    def list_versions(self, policy_id: str) -> List[PolicyVersion]:
        rows = self.db.run("s10_list_versions", lambda c: c.execute(
            "SELECT * FROM policy_versions WHERE policy_id=%s ORDER BY version", (policy_id,)).fetchall())
        return [_v(r) for r in rows]

    def next_version_number(self, policy_id: str) -> int:
        r = self.db.run("s10_next_version", lambda c: c.execute(
            "SELECT COALESCE(MAX(version), 0) AS v FROM policy_versions WHERE policy_id=%s",
            (policy_id,)).fetchone())
        return int(r["v"]) + 1

    # ------------------------------------------------------------------ JIT grants
    def put_grant(self, g: JitGrant) -> None:
        self.db.run("s10_put_grant", lambda c: c.execute(
            "INSERT INTO jit_grants (grant_id, org_id, agent_id, instance_id, action, resource,"
            " issued_at, expires_at, policy_version, status, issued_by, reason, context,"
            " revoked_at, revoked_reason) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (grant_id) DO UPDATE SET status=EXCLUDED.status,"
            " revoked_at=EXCLUDED.revoked_at, revoked_reason=EXCLUDED.revoked_reason",
            (g.grant_id, g.org_id, g.agent_id, g.instance_id, g.action, g.resource, g.issued_at,
             g.expires_at, g.policy_version, g.status.value, g.issued_by, g.reason,
             _jsonb(g.context) if g.context else None, g.revoked_at, g.revoked_reason)))

    def get_grant(self, grant_id: str) -> Optional[JitGrant]:
        r = self.db.run("s10_get_grant", lambda c: c.execute(
            "SELECT * FROM jit_grants WHERE grant_id=%s", (grant_id,)).fetchone())
        return _g(r) if r else None

    def list_grants(self, *, org_id: str, agent_id: Optional[str] = None,
                    active_only: bool = False, now: Optional[float] = None) -> List[JitGrant]:
        clauses, params = ["org_id=%s"], [org_id]
        if agent_id is not None:
            clauses.append("agent_id=%s"); params.append(agent_id)
        if active_only:
            clauses.append("status='active'")
            if now is not None:
                clauses.append("expires_at > %s"); params.append(now)
        rows = self.db.run("s10_list_grants", lambda c: c.execute(
            "SELECT * FROM jit_grants WHERE " + " AND ".join(clauses)
            + " ORDER BY issued_at, grant_id", tuple(params)).fetchall())
        return [_g(r) for r in rows]

    def revoke_grant(self, grant_id: str, reason: str, now: float) -> Optional[JitGrant]:
        cur = self.db.run("s10_revoke_grant", lambda c: c.execute(
            "UPDATE jit_grants SET status='revoked', revoked_at=%s, revoked_reason=%s"
            " WHERE grant_id=%s AND status='active'", (now, reason, grant_id)))
        if cur.rowcount != 1:
            return None
        return self.get_grant(grant_id)

    # ------------------------------------------------------------------ approvals
    def put_approval(self, a: ApprovalRequest) -> None:
        self.db.run("s10_put_approval", lambda c: c.execute(
            "INSERT INTO approvals (approval_id, org_id, agent_id, action, resource, status,"
            " requested_at, expires_at, requested_by, decided_at, decided_by, reason, context)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (approval_id) DO UPDATE SET status=EXCLUDED.status,"
            " decided_at=EXCLUDED.decided_at, decided_by=EXCLUDED.decided_by, reason=EXCLUDED.reason",
            (a.approval_id, a.org_id, a.agent_id, a.action, a.resource, a.status.value,
             a.requested_at, a.expires_at, a.requested_by, a.decided_at, a.decided_by, a.reason,
             _jsonb(a.context) if a.context else None)))

    def get_approval(self, approval_id: str) -> Optional[ApprovalRequest]:
        r = self.db.run("s10_get_approval", lambda c: c.execute(
            "SELECT * FROM approvals WHERE approval_id=%s", (approval_id,)).fetchone())
        return _a(r) if r else None

    def find_approval(self, *, org_id: str, agent_id: str, action: str, resource: str,
                      now: float) -> Optional[ApprovalRequest]:
        r = self.db.run("s10_find_approval", lambda c: c.execute(
            "SELECT * FROM approvals WHERE org_id=%s AND agent_id=%s AND action=%s AND resource=%s"
            " AND status='approved' AND expires_at > %s ORDER BY decided_at DESC LIMIT 1",
            (org_id, agent_id, action, resource, now)).fetchone())
        return _a(r) if r else None

    # ------------------------------------------------------------------ audit
    def append_audit(self, event: dict) -> None:
        self.db.run("s10_append_audit", lambda c: c.execute(
            "INSERT INTO policy_audit (event_id, ts, event, actor_user_id, org_id, policy_id,"
            " policy_version, grant_id, outcome, reason, correlation_id)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (event["event_id"], event["ts"], event["event"], event.get("actor_user_id"),
             event.get("org_id"), event.get("policy_id"), event.get("policy_version"),
             event.get("grant_id"), event.get("outcome", "ok"), event.get("reason"),
             event.get("correlation_id"))))

    def list_audit(self, *, org_id: Optional[str] = None, policy_id: Optional[str] = None,
                   limit: int = 100) -> List[dict]:
        clauses, params = [], []
        if org_id is not None:
            clauses.append("org_id=%s"); params.append(org_id)
        if policy_id is not None:
            clauses.append("policy_id=%s"); params.append(policy_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(int(limit))
        rows = self.db.run("s10_list_audit", lambda c: c.execute(
            "SELECT * FROM policy_audit" + where + " ORDER BY ts DESC, event_id DESC LIMIT %s",
            tuple(params)).fetchall())
        return [dict(r) for r in rows]


def create_policy_store(db) -> PgPolicyStore:
    if db is None:
        raise StorageError("a PostgreSQL database is required for the policy store")
    return PgPolicyStore(db)
