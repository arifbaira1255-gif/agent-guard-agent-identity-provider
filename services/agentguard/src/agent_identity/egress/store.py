"""Phase 4 storage boundary for the egress/DLP plane.

One interface, two backends (the same pattern as ``governance/store.py`` and ``policy/store.py``):

  * ``storage.postgres.egress.PgEgressStore`` -- authoritative in production (migration 0007, same
    RLS GUC contract ``app.current_org`` / ``app.platform_admin``).
  * ``egress.memory_store.MemoryEgressStore`` -- unit tests + single-process dev only.

Every tenant-scoped read/write takes an explicit ``org_id``; the PostgreSQL backend also runs under
Row-Level Security, so a forgotten filter still cannot leak across tenants.

Egress policy records are read **authoritatively** on every decision (no cross-request cache), which
is what makes "no stale allow survives a policy change" true by construction.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from .models import EgressPolicyRecord


class EgressStore(ABC):
    # ------------------------------------------------------------------ egress policies
    @abstractmethod
    def put_policy(self, p: EgressPolicyRecord) -> None: ...

    @abstractmethod
    def get_policy(self, policy_id: str) -> Optional[EgressPolicyRecord]: ...

    @abstractmethod
    def list_policies(self, *, org_id: Optional[str] = None) -> List[EgressPolicyRecord]: ...

    @abstractmethod
    def delete_policy(self, policy_id: str) -> None: ...

    # ------------------------------------------------------------------ audit
    @abstractmethod
    def append_audit(self, event: dict) -> None: ...

    @abstractmethod
    def list_audit(self, *, org_id: Optional[str] = None, destination: Optional[str] = None,
                   limit: int = 100) -> List[dict]: ...
