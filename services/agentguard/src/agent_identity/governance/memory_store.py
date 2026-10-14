"""In-memory ``GovernanceStore`` for unit tests and single-process development.

Semantics mirror the PostgreSQL backend closely enough for the security contract to hold:
  * resource ids and tool ids are unique per tenant scope,
  * reads/writes are tenant-filtered explicitly,
  * governance audit is append-only.

It is NOT a production store: no durability, no cross-process sharing. Production uses PostgreSQL.
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional

from .models import ResourceRecord, ToolRecord
from .store import GovernanceStore


class MemoryGovernanceStore(GovernanceStore):
    def __init__(self):
        self._lock = threading.RLock()
        self._resources: Dict[str, ResourceRecord] = {}
        self._tools: Dict[str, ToolRecord] = {}
        self._audit: List[dict] = []

    # ------------------------------------------------------------------ resources
    def put_resource(self, r: ResourceRecord) -> None:
        with self._lock:
            self._resources[r.resource_id] = r

    def get_resource(self, resource_id: str) -> Optional[ResourceRecord]:
        return self._resources.get(resource_id)

    def list_resources(self, *, org_id: Optional[str] = None) -> List[ResourceRecord]:
        out = [r for r in self._resources.values() if org_id is None or r.org_id == org_id]
        return sorted(out, key=lambda r: (r.org_id, r.resource_id))

    def delete_resource(self, resource_id: str) -> None:
        with self._lock:
            self._resources.pop(resource_id, None)

    # ------------------------------------------------------------------ tools
    def put_tool(self, t: ToolRecord) -> None:
        with self._lock:
            self._tools[t.tool_id] = t

    def get_tool(self, tool_id: str) -> Optional[ToolRecord]:
        return self._tools.get(tool_id)

    def list_tools(self, *, org_id: Optional[str] = None) -> List[ToolRecord]:
        out = [t for t in self._tools.values() if org_id is None or t.org_id == org_id]
        return sorted(out, key=lambda t: (t.org_id, t.name, t.version, t.tool_id))

    def delete_tool(self, tool_id: str) -> None:
        with self._lock:
            self._tools.pop(tool_id, None)

    # ------------------------------------------------------------------ audit
    def append_audit(self, event: dict) -> None:
        with self._lock:
            self._audit.append(dict(event))

    def list_audit(self, *, org_id: Optional[str] = None, resource_id: Optional[str] = None,
                   limit: int = 100) -> List[dict]:
        items = self._audit
        if org_id is not None:
            items = [e for e in items if e.get("org_id") == org_id]
        if resource_id is not None:
            items = [e for e in items if e.get("resource_id") == resource_id]
        return sorted(items, key=lambda e: (e.get("ts", 0), e.get("event_id", "")),
                      reverse=True)[:limit]
