"""Step 10 storage boundary for the policy plane.

One interface, two backends (mirroring ``security/store.py``):
  * ``storage.postgres.policy.PgPolicyStore`` — authoritative in production (migration 0005, RLS).
  * ``policy.memory_store.MemoryPolicyStore`` — unit tests + single-node dev only.

Every tenant-scoped read/write takes an explicit ``org_id``; the PostgreSQL backend also runs under
Row-Level Security, so a forgotten filter still cannot leak across tenants. Platform-wide policies
(``org_id IS NULL``) are readable by all tenants but writable only by a platform administrator.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from .models import ApprovalRequest, JitGrant, PolicyRecord, PolicyVersion


class PolicyStore(ABC):
    # ------------------------------------------------------------------ policies
    @abstractmethod
    def put_policy(self, p: PolicyRecord) -> None: ...
    @abstractmethod
    def get_policy(self, policy_id: str) -> Optional[PolicyRecord]: ...
    @abstractmethod
    def list_policies(self, *, org_id: Optional[str] = None,
                      include_platform: bool = True) -> List[PolicyRecord]: ...
    @abstractmethod
    def delete_policy(self, policy_id: str) -> None: ...

    # ------------------------------------------------------------------ versions
    @abstractmethod
    def put_version(self, v: PolicyVersion) -> None: ...
    @abstractmethod
    def get_version(self, policy_id: str, version: int) -> Optional[PolicyVersion]: ...
    @abstractmethod
    def list_versions(self, policy_id: str) -> List[PolicyVersion]: ...
    @abstractmethod
    def next_version_number(self, policy_id: str) -> int: ...

    # ------------------------------------------------------------------ JIT grants
    @abstractmethod
    def put_grant(self, g: JitGrant) -> None: ...
    @abstractmethod
    def get_grant(self, grant_id: str) -> Optional[JitGrant]: ...
    @abstractmethod
    def list_grants(self, *, org_id: str, agent_id: Optional[str] = None,
                    active_only: bool = False, now: Optional[float] = None) -> List[JitGrant]: ...
    @abstractmethod
    def revoke_grant(self, grant_id: str, reason: str, now: float) -> Optional[JitGrant]: ...

    # ------------------------------------------------------------------ approvals
    @abstractmethod
    def put_approval(self, a: ApprovalRequest) -> None: ...
    @abstractmethod
    def get_approval(self, approval_id: str) -> Optional[ApprovalRequest]: ...
    @abstractmethod
    def find_approval(self, *, org_id: str, agent_id: str, action: str, resource: str,
                      now: float) -> Optional[ApprovalRequest]: ...

    # ------------------------------------------------------------------ audit
    @abstractmethod
    def append_audit(self, event: dict) -> None: ...
    @abstractmethod
    def list_audit(self, *, org_id: Optional[str] = None, policy_id: Optional[str] = None,
                   limit: int = 100) -> List[dict]: ...
