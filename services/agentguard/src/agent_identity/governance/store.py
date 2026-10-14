"""Step 11 storage boundary for the governance plane.

One interface, two backends (the same pattern as ``policy/store.py`` and ``security/store.py``):

  * ``storage.postgres.governance.PgGovernanceStore`` — authoritative in production
    (migration 0006, same RLS GUC contract ``app.current_org`` / ``app.platform_admin``).
  * ``governance.memory_store.MemoryGovernanceStore`` — unit tests + single-process dev only.

Every tenant-scoped read/write takes an explicit ``org_id``; the PostgreSQL backend also runs under
Row-Level Security, so a forgotten filter still cannot leak across tenants.

Registry records are read **authoritatively** on every decision (no cross-request cache), which is
what makes "no stale allow survives a registry or policy change" true by construction.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from .models import ResourceRecord, ToolRecord


class GovernanceStore(ABC):
    # ------------------------------------------------------------------ resources
    @abstractmethod
    def put_resource(self, r: ResourceRecord) -> None: ...

    @abstractmethod
    def get_resource(self, resource_id: str) -> Optional[ResourceRecord]: ...

    @abstractmethod
    def list_resources(self, *, org_id: Optional[str] = None) -> List[ResourceRecord]: ...

    @abstractmethod
    def delete_resource(self, resource_id: str) -> None: ...

    # ------------------------------------------------------------------ tools
    @abstractmethod
    def put_tool(self, t: ToolRecord) -> None: ...

    @abstractmethod
    def get_tool(self, tool_id: str) -> Optional[ToolRecord]: ...

    @abstractmethod
    def list_tools(self, *, org_id: Optional[str] = None) -> List[ToolRecord]: ...

    @abstractmethod
    def delete_tool(self, tool_id: str) -> None: ...

    # ------------------------------------------------------------------ audit
    @abstractmethod
    def append_audit(self, event: dict) -> None: ...

    @abstractmethod
    def list_audit(self, *, org_id: Optional[str] = None, resource_id: Optional[str] = None,
                   limit: int = 100) -> List[dict]: ...
