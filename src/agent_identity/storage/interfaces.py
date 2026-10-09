"""Storage abstractions. Implement these for PostgreSQL / Redis / KMS / HSM / SPIRE.

Contract notes for implementers:
  * KeyStore must NEVER return private key bytes; it only signs.
  * ReplayCache.check_and_store must be atomic (e.g. Redis SET NX EX).
  * RevocationRegistry.add must keep the EARLIEST effective_at for a target.
"""
from abc import ABC, abstractmethod
from typing import List, Optional

from ..core.models import (AgentRecord, CredentialRecord, InstanceRecord,
                           IssuerCertificate, Organization, RevocationRecord,
                           SpawnRecord, Status, TargetType)


class KeyStore(ABC):
    @abstractmethod
    def generate_key(self, key_id: str) -> bytes:
        """Create a keypair; return RAW PUBLIC key bytes only."""

    @abstractmethod
    def public_key(self, key_id: str) -> bytes: ...

    @abstractmethod
    def sign(self, key_id: str, domain: bytes, data: bytes) -> bytes: ...

    @abstractmethod
    def has_key(self, key_id: str) -> bool: ...

    @abstractmethod
    def delete_key(self, key_id: str) -> None: ...


class AgentRegistry(ABC):
    @abstractmethod
    def put_org(self, org: Organization) -> None: ...
    @abstractmethod
    def get_org(self, org_id: str) -> Optional[Organization]: ...
    @abstractmethod
    def put_agent(self, agent: AgentRecord) -> None: ...
    @abstractmethod
    def get_agent(self, agent_id: str) -> Optional[AgentRecord]: ...
    @abstractmethod
    def put_instance(self, inst: InstanceRecord) -> None: ...
    @abstractmethod
    def get_instance(self, instance_id: str) -> Optional[InstanceRecord]: ...
    @abstractmethod
    def list_instances(self, agent_id: str) -> List[InstanceRecord]: ...
    @abstractmethod
    def put_spawn(self, spawn: SpawnRecord) -> None: ...
    @abstractmethod
    def get_spawn(self, child_agent_id: str) -> Optional[SpawnRecord]: ...
    @abstractmethod
    def list_children(self, parent_agent_id: str) -> List[SpawnRecord]: ...


class CredentialRegistry(ABC):
    @abstractmethod
    def put(self, rec: CredentialRecord) -> None: ...
    @abstractmethod
    def get(self, credential_id: str) -> Optional[CredentialRecord]: ...
    @abstractmethod
    def list_all(self) -> List[CredentialRecord]: ...


class RevocationRegistry(ABC):
    @abstractmethod
    def add(self, rec: RevocationRecord) -> RevocationRecord: ...
    @abstractmethod
    def get(self, target_type: TargetType, target_id: str) -> Optional[RevocationRecord]: ...

    def is_revoked(self, target_type: TargetType, target_id: str, now: float) -> bool:
        r = self.get(target_type, target_id)
        return r is not None and r.effective_at <= now


class TrustStore(ABC):
    @abstractmethod
    def add_root(self, root_key_id: str, public_key_b64: str) -> None: ...
    @abstractmethod
    def get_root(self, root_key_id: str) -> Optional[str]: ...
    @abstractmethod
    def put_issuer_cert(self, cert: IssuerCertificate) -> None: ...
    @abstractmethod
    def get_issuer_cert(self, issuer_key_id: str) -> Optional[IssuerCertificate]: ...


class ReplayCache(ABC):
    @abstractmethod
    def check_and_store(self, key: str, ttl_seconds: float, now: float) -> bool:
        """Atomically record key. Return True if new, False if already seen.
        Must raise if capacity is exhausted (fail closed)."""
