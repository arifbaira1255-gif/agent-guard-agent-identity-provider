"""Thread-safe in-memory reference implementations (local development / tests)."""
import threading
from dataclasses import replace
from typing import Dict, List, Optional

from cryptography.fernet import Fernet

from ..core.errors import StorageError
from ..core.models import (AgentRecord, CredentialRecord, InstanceRecord,
                           IssuerCertificate, Organization, RevocationRecord,
                           SpawnRecord, TargetType)
from ..crypto import keys
from .interfaces import (AgentRegistry, CredentialRegistry, KeyStore,
                         ReplayCache, RevocationRegistry, TrustStore)


class EncryptedMemoryKeyStore(KeyStore):
    """Private keys are Fernet-encrypted at rest in memory and decrypted only
    transiently inside sign(). No method exposes private key bytes.

    The master key comes from the caller (e.g. env/KMS). If omitted an ephemeral
    one is generated: keys are then lost on restart (development only).
    """

    def __init__(self, master_key: Optional[bytes] = None):
        self._fernet = Fernet(master_key or Fernet.generate_key())
        self._keys: Dict[str, bytes] = {}
        self._pub: Dict[str, bytes] = {}
        self._lock = threading.RLock()

    def generate_key(self, key_id: str) -> bytes:
        priv = keys.generate_private_key()
        pub = keys.public_bytes(priv)
        with self._lock:
            if key_id in self._keys:
                raise StorageError("key id collision")
            self._keys[key_id] = self._fernet.encrypt(keys.private_raw(priv))
            self._pub[key_id] = pub
        return pub

    def public_key(self, key_id: str) -> bytes:
        with self._lock:
            if key_id not in self._pub:
                raise StorageError("unknown key")
            return self._pub[key_id]

    def sign(self, key_id: str, domain: bytes, data: bytes) -> bytes:
        with self._lock:
            blob = self._keys.get(key_id)
        if blob is None:
            raise StorageError("unknown key")
        priv = keys.private_from_raw(self._fernet.decrypt(blob))
        return keys.sign(priv, domain, data)

    def has_key(self, key_id: str) -> bool:
        with self._lock:
            return key_id in self._keys

    def delete_key(self, key_id: str) -> None:
        with self._lock:
            self._keys.pop(key_id, None)

    def __repr__(self) -> str:
        return f"EncryptedMemoryKeyStore(keys={len(self._keys)})"


class MemoryAgentRegistry(AgentRegistry):
    def __init__(self):
        self._lock = threading.RLock()
        self._orgs: Dict[str, Organization] = {}
        self._agents: Dict[str, AgentRecord] = {}
        self._instances: Dict[str, InstanceRecord] = {}
        self._spawns: Dict[str, SpawnRecord] = {}

    def put_org(self, org):
        with self._lock:
            self._orgs[org.org_id] = org

    def get_org(self, org_id):
        return self._orgs.get(org_id)

    def put_agent(self, agent):
        with self._lock:
            self._agents[agent.agent_id] = agent

    def get_agent(self, agent_id):
        return self._agents.get(agent_id)

    def put_instance(self, inst):
        with self._lock:
            self._instances[inst.instance_id] = inst

    def get_instance(self, instance_id):
        return self._instances.get(instance_id)

    def list_instances(self, agent_id) -> List[InstanceRecord]:
        with self._lock:
            return [i for i in self._instances.values() if i.agent_id == agent_id]

    def put_spawn(self, spawn):
        with self._lock:
            self._spawns[spawn.child_agent_id] = spawn

    def get_spawn(self, child_agent_id):
        return self._spawns.get(child_agent_id)

    def list_children(self, parent_agent_id) -> List[SpawnRecord]:
        with self._lock:
            return [s for s in self._spawns.values() if s.parent_agent_id == parent_agent_id]


class MemoryCredentialRegistry(CredentialRegistry):
    def __init__(self):
        self._lock = threading.RLock()
        self._creds: Dict[str, CredentialRecord] = {}

    def put(self, rec):
        with self._lock:
            self._creds[rec.credential_id] = rec

    def get(self, credential_id):
        return self._creds.get(credential_id)

    def list_all(self):
        with self._lock:
            return list(self._creds.values())


class MemoryRevocationRegistry(RevocationRegistry):
    def __init__(self):
        self._lock = threading.RLock()
        self._recs: Dict[tuple, RevocationRecord] = {}

    def add(self, rec):
        k = (rec.target_type, rec.target_id)
        with self._lock:
            cur = self._recs.get(k)
            if cur is None or rec.effective_at < cur.effective_at:
                self._recs[k] = rec
                return rec
            return cur

    def get(self, target_type, target_id):
        return self._recs.get((target_type, target_id))


class MemoryTrustStore(TrustStore):
    def __init__(self):
        self._lock = threading.RLock()
        self._roots: Dict[str, str] = {}
        self._certs: Dict[str, IssuerCertificate] = {}

    def add_root(self, root_key_id, public_key_b64):
        with self._lock:
            self._roots[root_key_id] = public_key_b64

    def get_root(self, root_key_id):
        return self._roots.get(root_key_id)

    def put_issuer_cert(self, cert):
        with self._lock:
            self._certs[cert.issuer_key_id] = cert

    def get_issuer_cert(self, issuer_key_id):
        return self._certs.get(issuer_key_id)


class MemoryReplayCache(ReplayCache):
    def __init__(self, max_entries: int = 500_000):
        self._lock = threading.Lock()
        self._seen: Dict[str, float] = {}
        self._max = max_entries

    def check_and_store(self, key, ttl_seconds, now):
        with self._lock:
            exp = self._seen.get(key)
            if exp is not None and exp > now:
                return False
            if len(self._seen) >= self._max:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
                if len(self._seen) >= self._max:
                    raise StorageError("replay cache full")  # fail closed
            self._seen[key] = now + ttl_seconds
            return True
