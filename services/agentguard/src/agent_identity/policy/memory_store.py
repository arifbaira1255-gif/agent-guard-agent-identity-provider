"""In-memory ``PolicyStore`` for unit tests and single-process development.

Semantics mirror the PostgreSQL backend closely enough for the security contract to hold:
  * policy versions are immutable (a re-put of the same (policy_id, version) with different content
    is rejected),
  * grants/approvals are tenant-scoped and filtered explicitly,
  * policy audit is append-only.

It is NOT a production store: no durability, no cross-process sharing. Production uses PostgreSQL.
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional

from ..core.errors import ConflictError
from .models import ApprovalRequest, ApprovalStatus, GrantStatus, JitGrant, PolicyRecord, PolicyVersion
from .store import PolicyStore


class MemoryPolicyStore(PolicyStore):
    def __init__(self):
        self._lock = threading.RLock()
        self._policies: Dict[str, PolicyRecord] = {}
        self._versions: Dict[tuple, PolicyVersion] = {}
        self._grants: Dict[str, JitGrant] = {}
        self._approvals: Dict[str, ApprovalRequest] = {}
        self._audit: List[dict] = []

    # ------------------------------------------------------------------ policies
    def put_policy(self, p: PolicyRecord) -> None:
        with self._lock:
            self._policies[p.policy_id] = p

    def get_policy(self, policy_id: str) -> Optional[PolicyRecord]:
        return self._policies.get(policy_id)

    def list_policies(self, *, org_id: Optional[str] = None,
                      include_platform: bool = True) -> List[PolicyRecord]:
        out = []
        for p in self._policies.values():
            if p.org_id is None:
                if include_platform:
                    out.append(p)
            elif org_id is None or p.org_id == org_id:
                out.append(p)
        return sorted(out, key=lambda p: (p.org_id or "", p.policy_id))

    def delete_policy(self, policy_id: str) -> None:
        with self._lock:
            self._policies.pop(policy_id, None)
            for k in [k for k in self._versions if k[0] == policy_id]:
                self._versions.pop(k, None)

    # ------------------------------------------------------------------ versions
    def put_version(self, v: PolicyVersion) -> None:
        with self._lock:
            key = (v.policy_id, v.version)
            existing = self._versions.get(key)
            if existing is not None and existing.checksum != v.checksum:
                raise ConflictError("policy version is immutable")
            self._versions[key] = v

    def get_version(self, policy_id: str, version: int) -> Optional[PolicyVersion]:
        return self._versions.get((policy_id, version))

    def list_versions(self, policy_id: str) -> List[PolicyVersion]:
        return sorted([v for (pid, _), v in self._versions.items() if pid == policy_id],
                      key=lambda v: v.version)

    def next_version_number(self, policy_id: str) -> int:
        versions = [ver for (pid, ver) in self._versions.keys() if pid == policy_id]
        return (max(versions) + 1) if versions else 1

    # ------------------------------------------------------------------ JIT grants
    def put_grant(self, g: JitGrant) -> None:
        with self._lock:
            self._grants[g.grant_id] = g

    def get_grant(self, grant_id: str) -> Optional[JitGrant]:
        return self._grants.get(grant_id)

    def list_grants(self, *, org_id: str, agent_id: Optional[str] = None,
                    active_only: bool = False, now: Optional[float] = None) -> List[JitGrant]:
        out = []
        for g in self._grants.values():
            if g.org_id != org_id:
                continue
            if agent_id is not None and g.agent_id != agent_id:
                continue
            if active_only:
                if now is None or not g.is_live(now):
                    continue
            out.append(g)
        return sorted(out, key=lambda g: (g.issued_at, g.grant_id))

    def revoke_grant(self, grant_id: str, reason: str, now: float) -> Optional[JitGrant]:
        import dataclasses
        with self._lock:
            g = self._grants.get(grant_id)
            if g is None or g.status is not GrantStatus.ACTIVE:
                return None
            g2 = dataclasses.replace(g, status=GrantStatus.REVOKED, revoked_at=now,
                                     revoked_reason=reason)
            self._grants[grant_id] = g2
            return g2

    # ------------------------------------------------------------------ approvals
    def put_approval(self, a: ApprovalRequest) -> None:
        with self._lock:
            self._approvals[a.approval_id] = a

    def get_approval(self, approval_id: str) -> Optional[ApprovalRequest]:
        return self._approvals.get(approval_id)

    def find_approval(self, *, org_id: str, agent_id: str, action: str, resource: str,
                      now: float) -> Optional[ApprovalRequest]:
        best = None
        for a in self._approvals.values():
            if (a.org_id, a.agent_id, a.action, a.resource) != (org_id, agent_id, action, resource):
                continue
            if a.status is not ApprovalStatus.APPROVED or now >= a.expires_at:
                continue
            if best is None or a.decided_at > best.decided_at:
                best = a
        return best

    # ------------------------------------------------------------------ audit
    def append_audit(self, event: dict) -> None:
        with self._lock:
            self._audit.append(dict(event))          # append-only; no mutation/delete API exists

    def list_audit(self, *, org_id: Optional[str] = None, policy_id: Optional[str] = None,
                   limit: int = 100) -> List[dict]:
        items = self._audit
        if org_id is not None:
            items = [e for e in items if e.get("org_id") == org_id]
        if policy_id is not None:
            items = [e for e in items if e.get("policy_id") == policy_id]
        return sorted(items, key=lambda e: (e.get("ts", 0), e.get("event_id", "")), reverse=True)[:limit]
