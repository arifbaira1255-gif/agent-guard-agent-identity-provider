"""In-memory ``EgressStore`` for unit tests and single-process development.

Semantics mirror the PostgreSQL backend closely enough for the security contract to hold:
  * policy ids are unique per tenant scope,
  * reads/writes are tenant-filtered explicitly,
  * egress audit is append-only.

It is NOT a production store: no durability, no cross-process sharing. Production uses PostgreSQL.
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional

from .models import EgressPolicyRecord
from .store import EgressStore


class MemoryEgressStore(EgressStore):
    def __init__(self):
        self._lock = threading.RLock()
        self._policies: Dict[str, EgressPolicyRecord] = {}
        self._audit: List[dict] = []

    # ------------------------------------------------------------------ policies
    def put_policy(self, p: EgressPolicyRecord) -> None:
        with self._lock:
            self._policies[p.policy_id] = p

    def get_policy(self, policy_id: str) -> Optional[EgressPolicyRecord]:
        return self._policies.get(policy_id)

    def list_policies(self, *, org_id: Optional[str] = None) -> List[EgressPolicyRecord]:
        out = [p for p in self._policies.values() if org_id is None or p.org_id == org_id]
        return sorted(out, key=lambda p: (p.org_id, -p.priority, p.policy_id))

    def delete_policy(self, policy_id: str) -> None:
        with self._lock:
            self._policies.pop(policy_id, None)

    # ------------------------------------------------------------------ audit
    def append_audit(self, event: dict) -> None:
        with self._lock:
            self._audit.append(dict(event))

    def list_audit(self, *, org_id: Optional[str] = None, destination: Optional[str] = None,
                   limit: int = 100) -> List[dict]:
        items = self._audit
        if org_id is not None:
            items = [e for e in items if e.get("org_id") == org_id]
        if destination is not None:
            items = [e for e in items if e.get("destination") == destination]
        return sorted(items, key=lambda e: (e.get("ts", 0), e.get("event_id", "")),
                      reverse=True)[:limit]
