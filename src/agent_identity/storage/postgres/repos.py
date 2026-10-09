"""PostgreSQL implementations of the EXISTING storage interfaces (same contracts as storage/memory.py).
All SQL is a constant string; every value is passed as a bound parameter (no string building)."""
from typing import List, Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from ...core.errors import ConflictError, StorageError
from ...core.models import (AgentRecord, CredentialRecord, InstanceRecord, IssuerCertificate,
                            Organization, RevocationReason, RevocationRecord, SpawnRecord, Status,
                            TargetType)
from ...crypto import keys
from ...spiffe.bindings import Binding, BindingRegistry
from ..interfaces import (AgentRegistry, CredentialRegistry, KeyStore, RevocationRegistry, TrustStore)


def _jsonb(v):
    from psycopg.types.json import Jsonb
    return Jsonb(v)


# ----------------------------------------------------------------------------- row mappers
def _org(r) -> Organization:
    caps = tuple(r["allowed_capabilities"]) if r["allowed_capabilities"] is not None else None
    return Organization(r["org_id"], r["name"], r["created_at"], Status(r["status"]),
                        r["active_issuer_key_id"], caps)


def _agent(r) -> AgentRecord:
    return AgentRecord(r["agent_id"], r["org_id"], r["agent_name"], r["agent_type"], r["owner"],
                       r["description"], tuple(r["capabilities"]), r["environment"], dict(r["metadata"]),
                       r["parent_agent_id"], tuple(r["lineage"]), r["created_at"], Status(r["status"]),
                       r["key_id"], r["public_key"], r["fingerprint"],
                       tuple((k, float(na)) for k, na in r["retired_keys"]), r["created_by"])


def _inst(r) -> InstanceRecord:
    return InstanceRecord(r["instance_id"], r["agent_id"], r["org_id"], r["session_id"], r["created_at"],
                          Status(r["status"]), r["agent_key_id"], r["agent_public_key"],
                          r["binding_signature"])


def _spawn(r) -> SpawnRecord:
    return SpawnRecord(r["parent_agent_id"], r["child_agent_id"], r["spawned_by_instance_id"],
                       r["created_at"], r["issuer"], Status(r["status"]))


def _cred(r) -> CredentialRecord:
    return CredentialRecord(r["credential_id"], r["agent_id"], r["instance_id"], r["org_id"],
                            r["issuer_key_id"], r["issued_at"], r["expires_at"], r["key_id"],
                            r["key_fingerprint"], r["payload_digest"])


class _Repo:
    def __init__(self, db):
        self.db = db


# ----------------------------------------------------------------------------- agents
class PgAgentRegistry(_Repo, AgentRegistry):
    def put_org(self, org):
        def go(c):
            c.execute(
                "INSERT INTO organizations (org_id, name, created_at, status, active_issuer_key_id,"
                " allowed_capabilities) VALUES (%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (org_id) DO UPDATE SET name=EXCLUDED.name, status=EXCLUDED.status,"
                " active_issuer_key_id=EXCLUDED.active_issuer_key_id,"
                " allowed_capabilities=EXCLUDED.allowed_capabilities",
                (org.org_id, org.name, org.created_at, org.status.value, org.active_issuer_key_id,
                 list(org.allowed_capabilities) if org.allowed_capabilities is not None else None))
        self.db.run("put_org", go)

    def get_org(self, org_id):
        r = self.db.run("get_org", lambda c: c.execute(
            "SELECT * FROM organizations WHERE org_id=%s", (org_id,)).fetchone())
        return _org(r) if r else None

    def put_agent(self, a):
        def go(c):
            cur = c.execute(
                "INSERT INTO agents (agent_id, org_id, agent_name, agent_type, owner, description,"
                " capabilities, environment, metadata, parent_agent_id, lineage, created_at, status,"
                " key_id, public_key, fingerprint, retired_keys, created_by)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (agent_id) DO UPDATE SET agent_name=EXCLUDED.agent_name,"
                " agent_type=EXCLUDED.agent_type, owner=EXCLUDED.owner, description=EXCLUDED.description,"
                " capabilities=EXCLUDED.capabilities, environment=EXCLUDED.environment,"
                " metadata=EXCLUDED.metadata, status=EXCLUDED.status, key_id=EXCLUDED.key_id,"
                " public_key=EXCLUDED.public_key, fingerprint=EXCLUDED.fingerprint,"
                " retired_keys=EXCLUDED.retired_keys"
                " WHERE agents.org_id = EXCLUDED.org_id",
                (a.agent_id, a.org_id, a.agent_name, a.agent_type, a.owner, a.description,
                 list(a.capabilities), a.environment, _jsonb(dict(a.metadata)), a.parent_agent_id,
                 list(a.lineage), a.created_at, a.status.value, a.key_id, a.public_key, a.fingerprint,
                 _jsonb([list(k) for k in a.retired_keys]), a.created_by))
            if cur.rowcount != 1:
                raise ConflictError("agent belongs to a different organization")
        self.db.run("put_agent", go)

    def get_agent(self, agent_id):
        r = self.db.run("get_agent", lambda c: c.execute(
            "SELECT * FROM agents WHERE agent_id=%s", (agent_id,)).fetchone())
        return _agent(r) if r else None

    def put_instance(self, i):
        def go(c):
            cur = c.execute(
                "INSERT INTO agent_instances (instance_id, agent_id, org_id, session_id, created_at,"
                " status, agent_key_id, agent_public_key, binding_signature)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (instance_id) DO UPDATE SET status=EXCLUDED.status"
                " WHERE agent_instances.agent_id = EXCLUDED.agent_id"
                " AND agent_instances.org_id = EXCLUDED.org_id",
                (i.instance_id, i.agent_id, i.org_id, i.session_id, i.created_at, i.status.value,
                 i.agent_key_id, i.agent_public_key, i.binding_signature))
            if cur.rowcount != 1:
                raise ConflictError("instance belongs to a different agent")
        self.db.run("put_instance", go)

    def get_instance(self, instance_id):
        r = self.db.run("get_instance", lambda c: c.execute(
            "SELECT * FROM agent_instances WHERE instance_id=%s", (instance_id,)).fetchone())
        return _inst(r) if r else None

    def list_instances(self, agent_id) -> List[InstanceRecord]:
        rows = self.db.run("list_instances", lambda c: c.execute(
            "SELECT * FROM agent_instances WHERE agent_id=%s ORDER BY created_at, instance_id",
            (agent_id,)).fetchall())
        return [_inst(r) for r in rows]

    def put_spawn(self, s):
        def go(c):
            cur = c.execute(
                "INSERT INTO agent_spawns (child_agent_id, parent_agent_id, spawned_by_instance_id,"
                " created_at, issuer, status) VALUES (%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (child_agent_id) DO UPDATE SET status=EXCLUDED.status"
                " WHERE agent_spawns.parent_agent_id = EXCLUDED.parent_agent_id"
                " AND agent_spawns.spawned_by_instance_id = EXCLUDED.spawned_by_instance_id",
                (s.child_agent_id, s.parent_agent_id, s.spawned_by_instance_id, s.created_at,
                 s.issuer, s.status.value))
            if cur.rowcount != 1:
                raise ConflictError("child agent already has a different parent")
        self.db.run("put_spawn", go)

    def get_spawn(self, child_agent_id):
        r = self.db.run("get_spawn", lambda c: c.execute(
            "SELECT * FROM agent_spawns WHERE child_agent_id=%s", (child_agent_id,)).fetchone())
        return _spawn(r) if r else None

    def list_children(self, parent_agent_id) -> List[SpawnRecord]:
        rows = self.db.run("list_children", lambda c: c.execute(
            "SELECT * FROM agent_spawns WHERE parent_agent_id=%s ORDER BY created_at, child_agent_id",
            (parent_agent_id,)).fetchall())
        return [_spawn(r) for r in rows]


# ----------------------------------------------------------------------------- credentials
class PgCredentialRegistry(_Repo, CredentialRegistry):
    def put(self, r):
        def go(c):
            cur = c.execute(
                "INSERT INTO credentials (credential_id, agent_id, instance_id, org_id, issuer_key_id,"
                " issued_at, expires_at, key_id, key_fingerprint, payload_digest)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (credential_id) DO NOTHING",       # credential metadata is immutable
                (r.credential_id, r.agent_id, r.instance_id, r.org_id, r.issuer_key_id, r.issued_at,
                 r.expires_at, r.key_id, r.key_fingerprint, r.payload_digest))
            if cur.rowcount == 0:
                row = c.execute("SELECT * FROM credentials WHERE credential_id=%s",
                                (r.credential_id,)).fetchone()
                if row is None or _cred(row) != r:
                    raise ConflictError("credential id already exists with different content")
        self.db.run("put_credential", go)

    def get(self, credential_id):
        r = self.db.run("get_credential", lambda c: c.execute(
            "SELECT * FROM credentials WHERE credential_id=%s", (credential_id,)).fetchone())
        return _cred(r) if r else None

    def list_all(self):
        rows = self.db.run("list_credentials", lambda c: c.execute(
            "SELECT * FROM credentials ORDER BY issued_at, credential_id").fetchall())
        return [_cred(r) for r in rows]


# ----------------------------------------------------------------------------- revocations
class PgRevocationRegistry(_Repo, RevocationRegistry):
    def add(self, rec):
        def go(c):
            c.execute(
                "INSERT INTO revocations (target_type, target_id, reason, revoked_at, revoked_by,"
                " effective_at, detail) VALUES (%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (target_type, target_id) DO UPDATE SET reason=EXCLUDED.reason,"
                " revoked_at=EXCLUDED.revoked_at, revoked_by=EXCLUDED.revoked_by,"
                " effective_at=EXCLUDED.effective_at, detail=EXCLUDED.detail"
                " WHERE EXCLUDED.effective_at < revocations.effective_at",   # earliest effective_at wins
                (rec.target_type.value, rec.target_id, rec.reason.value, rec.revoked_at, rec.revoked_by,
                 rec.effective_at, rec.detail))
            return c.execute("SELECT * FROM revocations WHERE target_type=%s AND target_id=%s",
                             (rec.target_type.value, rec.target_id)).fetchone()
        row = self.db.run("add_revocation", go)
        if row is None:
            raise StorageError("revocation not persisted")
        return self._rec(row)

    @staticmethod
    def _rec(r):
        return RevocationRecord(TargetType(r["target_type"]), r["target_id"], RevocationReason(r["reason"]),
                                r["revoked_at"], r["revoked_by"], r["effective_at"], r["detail"])

    def get(self, target_type, target_id):
        r = self.db.run("get_revocation", lambda c: c.execute(
            "SELECT * FROM revocations WHERE target_type=%s AND target_id=%s",
            (target_type.value, target_id)).fetchone())
        return self._rec(r) if r else None


# ----------------------------------------------------------------------------- trust
class PgTrustStore(_Repo, TrustStore):
    def add_root(self, root_key_id, public_key_b64):
        def go(c):
            cur = c.execute("INSERT INTO trust_roots (root_key_id, public_key) VALUES (%s,%s)"
                            " ON CONFLICT (root_key_id) DO NOTHING", (root_key_id, public_key_b64))
            if cur.rowcount == 0:
                row = c.execute("SELECT public_key FROM trust_roots WHERE root_key_id=%s",
                                (root_key_id,)).fetchone()
                if row is None or row["public_key"] != public_key_b64:
                    raise ConflictError("trust root id already registered with a different key")
        self.db.run("add_root", go)

    def get_root(self, root_key_id):
        r = self.db.run("get_root", lambda c: c.execute(
            "SELECT public_key FROM trust_roots WHERE root_key_id=%s", (root_key_id,)).fetchone())
        return r["public_key"] if r else None

    def put_issuer_cert(self, cert):
        def go(c):
            cur = c.execute(
                "INSERT INTO issuer_certificates (issuer_key_id, org_id, public_key, fingerprint,"
                " root_key_id, issued_at, signature, status, not_after) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (issuer_key_id) DO UPDATE SET status=EXCLUDED.status,"
                " not_after=EXCLUDED.not_after"
                " WHERE issuer_certificates.org_id = EXCLUDED.org_id"
                " AND issuer_certificates.public_key = EXCLUDED.public_key"
                " AND issuer_certificates.status <> 'revoked'",       # revoked issuer keys stay revoked
                (cert.issuer_key_id, cert.org_id, cert.public_key, cert.fingerprint, cert.root_key_id,
                 cert.issued_at, cert.signature, cert.status, cert.not_after))
            if cur.rowcount != 1:
                row = c.execute("SELECT status FROM issuer_certificates WHERE issuer_key_id=%s",
                                (cert.issuer_key_id,)).fetchone()
                if row is None or not (row["status"] == "revoked" and cert.status == "revoked"):
                    raise ConflictError("issuer certificate update rejected")
        self.db.run("put_issuer_cert", go)

    def get_issuer_cert(self, issuer_key_id):
        r = self.db.run("get_issuer_cert", lambda c: c.execute(
            "SELECT * FROM issuer_certificates WHERE issuer_key_id=%s", (issuer_key_id,)).fetchone())
        if not r:
            return None
        return IssuerCertificate(r["issuer_key_id"], r["org_id"], r["public_key"], r["fingerprint"],
                                 r["root_key_id"], r["issued_at"], r["signature"], r["status"], r["not_after"])


# ----------------------------------------------------------------------------- SPIFFE bindings
class PgBindingRegistry(_Repo, BindingRegistry):
    @staticmethod
    def _b(r):
        return Binding(r["spiffe_id"], r["org_id"], r["agent_id"], r["instance_id"], r["created_at"],
                       r["delegated_by_agent"], r["delegated_by_instance"], r["status"])

    def put(self, b):
        def go(c):
            c.execute(
                "INSERT INTO spiffe_bindings (spiffe_id, org_id, agent_id, instance_id, created_at,"
                " delegated_by_agent, delegated_by_instance, status) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (spiffe_id) DO NOTHING",
                (b.spiffe_id, b.org_id, b.agent_id, b.instance_id, b.created_at, b.delegated_by_agent,
                 b.delegated_by_instance, b.status))
            return c.execute("SELECT * FROM spiffe_bindings WHERE spiffe_id=%s", (b.spiffe_id,)).fetchone()
        row = self.db.run("put_binding", go)
        cur = self._b(row)
        if (cur.org_id, cur.agent_id, cur.instance_id) != (b.org_id, b.agent_id, b.instance_id):
            raise ConflictError("SPIFFE ID already bound to a different identity")
        return cur

    def get(self, spiffe_id):
        r = self.db.run("get_binding", lambda c: c.execute(
            "SELECT * FROM spiffe_bindings WHERE spiffe_id=%s", (spiffe_id,)).fetchone())
        return self._b(r) if r else None

    def find(self, agent_id, instance_id):
        r = self.db.run("find_binding", lambda c: c.execute(
            "SELECT * FROM spiffe_bindings WHERE agent_id=%s AND instance_id IS NOT DISTINCT FROM %s",
            (agent_id, instance_id)).fetchone())
        return self._b(r) if r else None

    def revoke(self, spiffe_id):
        self.db.run("revoke_binding", lambda c: c.execute(
            "UPDATE spiffe_bindings SET status='revoked' WHERE spiffe_id=%s", (spiffe_id,)))


# ----------------------------------------------------------------------------- key store
class PgKeyStore(KeyStore):
    """Private keys are Fernet-encrypted BEFORE they reach the DB; the master key(s) come from the caller
    (env / secret manager / KMS-unwrapped) and are never stored. First key encrypts; the rest only
    decrypt (master-key rotation). No method returns private key bytes."""

    def __init__(self, db, master_keys):
        if isinstance(master_keys, (bytes, str)):
            master_keys = [master_keys]
        if not master_keys:
            raise StorageError("a master key is required for the PostgreSQL key store")
        try:
            self._f = MultiFernet([Fernet(k) for k in master_keys])
        except Exception:
            raise StorageError("invalid master key")
        self.db = db

    def generate_key(self, key_id):
        priv = keys.generate_private_key()
        pub = keys.public_bytes(priv)
        blob = self._f.encrypt(keys.private_raw(priv))

        def go(c):
            cur = c.execute("INSERT INTO keystore_keys (key_id, public_key, encrypted_private)"
                            " VALUES (%s,%s,%s) ON CONFLICT (key_id) DO NOTHING", (key_id, pub, blob))
            if cur.rowcount != 1:
                raise StorageError("key id collision")
        self.db.run("generate_key", go)
        return pub

    def public_key(self, key_id):
        r = self.db.run("public_key", lambda c: c.execute(
            "SELECT public_key FROM keystore_keys WHERE key_id=%s", (key_id,)).fetchone())
        if r is None:
            raise StorageError("unknown key")
        return bytes(r["public_key"])

    def sign(self, key_id, domain, data):
        r = self.db.run("load_key", lambda c: c.execute(
            "SELECT encrypted_private FROM keystore_keys WHERE key_id=%s", (key_id,)).fetchone())
        if r is None:
            raise StorageError("unknown key")
        try:
            raw = self._f.decrypt(bytes(r["encrypted_private"]))
        except InvalidToken:
            raise StorageError("key cannot be decrypted (wrong master key?)")
        return keys.sign(keys.private_from_raw(raw), domain, data)

    def has_key(self, key_id):
        r = self.db.run("has_key", lambda c: c.execute(
            "SELECT 1 AS x FROM keystore_keys WHERE key_id=%s", (key_id,)).fetchone())
        return r is not None

    def delete_key(self, key_id):
        self.db.run("delete_key", lambda c: c.execute("DELETE FROM keystore_keys WHERE key_id=%s", (key_id,)))

    def __repr__(self):
        return "PgKeyStore(<redacted>)"
