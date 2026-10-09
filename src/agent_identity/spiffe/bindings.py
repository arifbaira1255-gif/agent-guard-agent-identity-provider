"""Deterministic, immutable binding between SPIFFE IDs and AgentGuard agents/instances.

A SPIFFE ID can be bound exactly once and never re-pointed at another agent (prevents identity
confusion / re-binding hijack). Verification denies any SPIFFE ID that is not bound."""
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from typing import Dict, Optional

from ..core.errors import ConflictError


@dataclass(frozen=True)
class Binding:
    spiffe_id: str
    org_id: str
    agent_id: str
    instance_id: Optional[str]
    created_at: float
    delegated_by_agent: Optional[str] = None      # set only by an authorized sub-agent spawn
    delegated_by_instance: Optional[str] = None
    status: str = "active"                        # active | revoked


class BindingRegistry(ABC):
    @abstractmethod
    def put(self, b: Binding) -> Binding: ...
    @abstractmethod
    def get(self, spiffe_id: str) -> Optional[Binding]: ...
    @abstractmethod
    def find(self, agent_id: str, instance_id: Optional[str]) -> Optional[Binding]: ...
    @abstractmethod
    def revoke(self, spiffe_id: str) -> None: ...


class MemoryBindingRegistry(BindingRegistry):
    def __init__(self):
        self._by_id: Dict[str, Binding] = {}
        self._l = threading.Lock()

    def put(self, b: Binding) -> Binding:
        with self._l:
            cur = self._by_id.get(b.spiffe_id)
            if cur is not None:
                same = (cur.org_id, cur.agent_id, cur.instance_id) == (b.org_id, b.agent_id, b.instance_id)
                if not same:
                    raise ConflictError("SPIFFE ID already bound to a different identity")
                return cur                                  # idempotent
            self._by_id[b.spiffe_id] = b
            return b

    def get(self, spiffe_id):
        with self._l:
            return self._by_id.get(spiffe_id)

    def find(self, agent_id, instance_id):
        with self._l:
            for b in self._by_id.values():
                if b.agent_id == agent_id and b.instance_id == instance_id:
                    return b
        return None

    def revoke(self, spiffe_id):
        with self._l:
            b = self._by_id.get(spiffe_id)
            if b:
                self._by_id[spiffe_id] = replace(b, status="revoked")
