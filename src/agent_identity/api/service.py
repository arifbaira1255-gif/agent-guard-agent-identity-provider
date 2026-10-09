"""IdentityService: the transport-agnostic core engine / public interface.

Admin-style operations (register, create instance, issue, rotate, revoke) are
control-plane operations: the *transport* must authenticate and authorise callers
and pass a trustworthy `actor`. See docs/INTEGRATION_CONTRACT.md.
"""
import os
from dataclasses import dataclass, replace
from typing import Iterable, Optional

from ..core.clock import Clock
from ..core.config import IdentityConfig
from ..core.errors import (ConflictError, NotFoundError, UnauthorizedError,
                           ValidationError)
from ..core.ids import (new_agent_id, new_correlation_id, new_credential_id,
                        new_instance_id, new_key_id)
from ..core.models import (AgentRecord, CredentialRecord, InstanceRecord,
                           IssuedCredential, IssuerCertificate, Organization,
                           Reason, RevocationReason, RevocationRecord, SpawnRecord,
                           Status, TargetType, VerificationResult, iso)
from ..core import validation as V
from ..credentials.passport import (build_payload, encode_token, issuer_uri,
                                    parse_token, payload_digest, spiffe_id)
from ..crypto import keys
from ..crypto.encoding import b64u_decode, b64u_encode
from ..observability.logging import SecurityLogger
from ..storage.interfaces import (AgentRegistry, CredentialRegistry, KeyStore,
                                  ReplayCache, RevocationRegistry, TrustStore)
from ..storage.memory import (EncryptedMemoryKeyStore, MemoryAgentRegistry,
                              MemoryCredentialRegistry, MemoryReplayCache,
                              MemoryRevocationRegistry, MemoryTrustStore)
from ..verification.verifier import Verifier

SPAWN_AUDIENCE = "agent-identity:spawn"
SPAWN_CAPABILITY = "agent:spawn"


@dataclass(frozen=True)
class SpawnResult:
    agent: dict
    instance: dict
    spawn: dict
    credential: Optional[IssuedCredential]


class IdentityService:
    def __init__(self, config: Optional[IdentityConfig] = None, *,
                 keystore: Optional[KeyStore] = None, agents: Optional[AgentRegistry] = None,
                 credentials: Optional[CredentialRegistry] = None,
                 revocations: Optional[RevocationRegistry] = None,
                 trust: Optional[TrustStore] = None, replay: Optional[ReplayCache] = None,
                 clock: Optional[Clock] = None, logger: Optional[SecurityLogger] = None,
                 root_key_id: Optional[str] = None):
        self.cfg = (config or IdentityConfig()).validate()
        self.clock = clock or Clock()
        self.log = logger or SecurityLogger(self.cfg.log_to_python_logging)
        master = os.environ.get("AGENT_IDENTITY_MASTER_KEY")
        self.keystore = keystore or EncryptedMemoryKeyStore(master.encode() if master else None)
        self.agents = agents or MemoryAgentRegistry()
        self.credentials = credentials or MemoryCredentialRegistry()
        self.revocations = revocations or MemoryRevocationRegistry()
        self.trust = trust or MemoryTrustStore()
        self.replay = replay or MemoryReplayCache(self.cfg.replay_cache_max_entries)
        from ..storage.postgres.factory import require_durable_or_raise
        require_durable_or_raise(agents=self.agents, credentials=self.credentials,
                                 revocations=self.revocations, trust=self.trust)
        if root_key_id is None:
            root_key_id = "root_" + new_key_id()[4:]
            self.keystore.generate_key(root_key_id)
        self.root_key_id = root_key_id
        self.trust.add_root(root_key_id, b64u_encode(self.keystore.public_key(root_key_id)))
        self.verifier = Verifier(self.cfg, self.trust, self.agents, self.credentials,
                                 self.revocations, self.replay, self.clock, self.log)

    # ------------------------------------------------------------- helpers
    def _actor(self, actor: str) -> str:
        return V.check_pattern("actor", actor, V.ACTOR)

    def _org(self, org_id: str) -> Organization:
        org = self.agents.get_org(org_id) if isinstance(org_id, str) else None
        if org is None:
            raise NotFoundError("unknown organization")
        return org

    def _agent(self, agent_id: str) -> AgentRecord:
        a = self.agents.get_agent(agent_id) if isinstance(agent_id, str) else None
        if a is None:
            raise NotFoundError("unknown agent")
        return a

    def _issue_issuer_key(self, org_id: str) -> IssuerCertificate:
        kid = "iss_" + new_key_id()[4:]
        pub = b64u_encode(self.keystore.generate_key(kid))
        now = self.clock.now()
        body = keys.cert_body(kid, org_id, pub, self.root_key_id, now)
        sig = self.keystore.sign(self.root_key_id, keys.DOMAIN_ISSUER_CERT, body)
        cert = IssuerCertificate(kid, org_id, pub, keys.fingerprint_b64(pub),
                                 self.root_key_id, int(now), b64u_encode(sig))
        self.trust.put_issuer_cert(cert)
        return cert

    # -------------------------------------------------------- organizations
    def register_organization(self, org_id: str, name: str, *,
                              allowed_capabilities: Optional[Iterable[str]] = None,
                              actor: str = "system") -> dict:
        V.check_pattern("org_id", org_id, V.ORG_ID)
        V.safe_text("name", name, 128)
        if not name.strip():
            raise ValidationError("invalid name")
        actor = self._actor(actor)
        if self.agents.get_org(org_id):
            raise ConflictError("organization exists")
        allowed = (V.validate_capabilities(allowed_capabilities)
                   if allowed_capabilities is not None else None)
        cert = self._issue_issuer_key(org_id)
        org = Organization(org_id, name, self.clock.now(), Status.ACTIVE,
                           cert.issuer_key_id, allowed)
        self.agents.put_org(org)
        self.log.emit("organization.register", org_id=org_id, actor=actor,
                      issuer_key_id=cert.issuer_key_id, result="ok")
        return org.public_dict()

    def rotate_issuer_key(self, org_id: str, *, grace_seconds: Optional[int] = None,
                          actor: str = "system") -> dict:
        """old key -> new key -> overlap -> old key retired (stops verifying)."""
        actor = self._actor(actor)
        org = self._org(org_id)
        grace = self.cfg.issuer_rotation_overlap_seconds if grace_seconds is None \
            else int(grace_seconds)
        if grace < 0:
            raise ValidationError("invalid grace")
        old = self.trust.get_issuer_cert(org.active_issuer_key_id)
        new = self._issue_issuer_key(org_id)
        now = self.clock.now()
        self.trust.put_issuer_cert(replace(old, status="retiring", not_after=now + grace))
        self.agents.put_org(replace(org, active_issuer_key_id=new.issuer_key_id))
        self.log.emit("issuer.rotate", org_id=org_id, actor=actor, result="ok",
                      issuer_key_id=new.issuer_key_id, target_id=old.issuer_key_id)
        return {"old": self.trust.get_issuer_cert(old.issuer_key_id).public_dict(),
                "new": new.public_dict()}

    def revoke_issuer_key(self, issuer_key_id: str, reason: RevocationReason,
                          revoked_by: str, detail: Optional[str] = None) -> dict:
        revoked_by = self._actor(revoked_by)
        cert = self.trust.get_issuer_cert(issuer_key_id)
        if cert is None:
            raise NotFoundError("unknown issuer key")
        self.trust.put_issuer_cert(replace(cert, status="revoked"))
        rec = self._add_revocation(TargetType.ISSUER_KEY, issuer_key_id, reason, revoked_by,
                                   detail, None)
        return rec.public_dict()

    # --------------------------------------------------------------- agents
    def register_agent(self, org_id: str, agent_name: str, agent_type: str, owner: str,
                       description: str = "", capabilities: Optional[Iterable[str]] = None,
                       environment: str = "development", metadata: Optional[dict] = None,
                       parent_agent_id: Optional[str] = None, actor: str = "system") -> dict:
        if parent_agent_id is not None:
            raise UnauthorizedError("sub-agents can only be created via spawn_sub_agent")
        rec = self._create_agent(org_id, agent_name, agent_type, owner, description,
                                 capabilities, environment, metadata, None, (), actor)
        return rec.public_dict()

    def _create_agent(self, org_id, agent_name, agent_type, owner, description, capabilities,
                      environment, metadata, parent_id, lineage, actor) -> AgentRecord:
        actor = self._actor(actor)
        org = self._org(org_id)
        if org.status != Status.ACTIVE:
            raise UnauthorizedError("organization not active")
        V.check_pattern("agent_name", agent_name, V.AGENT_NAME)
        V.check_pattern("agent_type", agent_type, V.AGENT_TYPE)
        V.check_pattern("owner", owner, V.OWNER)
        V.check_pattern("environment", environment, V.ENVIRONMENT)
        V.safe_text("description", description, 1024)
        caps = V.validate_capabilities(capabilities)
        meta = V.validate_metadata(metadata)
        if org.allowed_capabilities is not None and not set(caps) <= set(org.allowed_capabilities):
            raise UnauthorizedError("capability not permitted for organization")
        key_id = new_key_id()
        pub = b64u_encode(self.keystore.generate_key(key_id))
        rec = AgentRecord(new_agent_id(), org_id, agent_name, agent_type, owner, description,
                          caps, environment, meta, parent_id, tuple(lineage),
                          self.clock.now(), Status.ACTIVE, key_id, pub,
                          keys.fingerprint_b64(pub), (), actor)
        self.agents.put_agent(rec)
        self.log.emit("agent.register", agent_id=rec.agent_id, org_id=org_id, actor=actor,
                      parent_agent_id=parent_id, fingerprint=rec.fingerprint, result="ok")
        return rec

    def get_agent_identity(self, agent_id: str) -> dict:
        a = self._agent(agent_id)
        d = a.public_dict()
        d["instances"] = [i.instance_id for i in self.agents.list_instances(agent_id)]
        d["children"] = [s.child_agent_id for s in self.agents.list_children(agent_id)]
        return d

    def rotate_agent_key(self, agent_id: str, *, grace_seconds: Optional[int] = None,
                         actor: str = "system") -> dict:
        actor = self._actor(actor)
        a = self._agent(agent_id)
        grace = self.cfg.issuer_rotation_overlap_seconds if grace_seconds is None \
            else int(grace_seconds)
        if grace < 0:
            raise ValidationError("invalid grace")
        key_id = new_key_id()
        pub = b64u_encode(self.keystore.generate_key(key_id))
        now = self.clock.now()
        retired = a.retired_keys + ((a.key_id, now + grace),)
        new = replace(a, key_id=key_id, public_key=pub, fingerprint=keys.fingerprint_b64(pub),
                      retired_keys=retired)
        self.agents.put_agent(new)
        self.log.emit("agent.key_rotate", agent_id=agent_id, actor=actor, key_id=key_id,
                      fingerprint=new.fingerprint, result="ok")
        return new.public_dict()

    # ------------------------------------------------------------ instances
    def create_agent_instance(self, agent_id: str, *, session_id: Optional[str] = None,
                              actor: str = "system") -> dict:
        actor = self._actor(actor)
        a = self._agent(agent_id)
        if a.status != Status.ACTIVE:
            raise UnauthorizedError("agent not active")
        sess = session_id if session_id is not None else "ses_" + new_key_id()[4:]
        V.check_pattern("session_id", sess, V.ACTOR)
        inst_id = new_instance_id(a.agent_name)
        now = self.clock.now()
        sig = self.keystore.sign(a.key_id, keys.DOMAIN_INSTANCE_BINDING,
                                 keys.binding_bytes(a.agent_id, inst_id, a.org_id, a.key_id, now))
        inst = InstanceRecord(inst_id, a.agent_id, a.org_id, sess, now, Status.ACTIVE,
                              a.key_id, a.public_key, b64u_encode(sig))
        self.agents.put_instance(inst)
        self.log.emit("instance.create", agent_id=agent_id, instance_id=inst_id, actor=actor,
                      result="ok")
        return inst.public_dict()

    # ---------------------------------------------------------- credentials
    def issue_credential(self, agent_id: str, instance_id: str, *,
                         ttl_seconds: Optional[int] = None, public_key: Optional[str] = None,
                         pop_signature: Optional[str] = None, actor: str = "system",
                         correlation_id: Optional[str] = None) -> IssuedCredential:
        """Mode A (dev): service generates + holds the credential key.
        Mode B (recommended): caller supplies public_key + pop_signature (agent-held key)."""
        actor = self._actor(actor)
        a = self._agent(agent_id)
        inst = self.agents.get_instance(instance_id) if isinstance(instance_id, str) else None
        if inst is None or inst.agent_id != a.agent_id:
            raise NotFoundError("unknown instance for agent")
        org = self._org(a.org_id)
        now = self.clock.now()
        if a.status != Status.ACTIVE or inst.status != Status.ACTIVE or org.status != Status.ACTIVE:
            raise UnauthorizedError("agent, instance and organization must be active")
        if self.revocations.is_revoked(TargetType.INSTANCE, instance_id, now) or \
                self.revocations.is_revoked(TargetType.AGENT, agent_id, now):
            raise UnauthorizedError("identity revoked")
        for anc in a.lineage:
            ar = self.agents.get_agent(anc)
            if ar is None or ar.status != Status.ACTIVE:
                raise UnauthorizedError("ancestor not active")
        if not a.key_valid(inst.agent_key_id, now):
            raise UnauthorizedError("instance bound to retired agent key; create a new instance")
        # verify the instance binding really was made by the agent's identity key
        bind = keys.binding_bytes(a.agent_id, inst.instance_id, a.org_id, inst.agent_key_id,
                                  inst.created_at)
        if not keys.verify(inst.agent_public_key, keys.DOMAIN_INSTANCE_BINDING, bind,
                           b64u_decode(inst.binding_signature)):
            raise UnauthorizedError("instance binding invalid")

        ttl = self.cfg.credential_ttl_seconds if ttl_seconds is None else ttl_seconds
        if (not isinstance(ttl, int) or isinstance(ttl, bool) or
                not self.cfg.min_credential_ttl_seconds <= ttl <= self.cfg.max_credential_ttl_seconds):
            raise ValidationError("ttl outside allowed range")

        cert = self.trust.get_issuer_cert(org.active_issuer_key_id)
        if cert is None or cert.status != "active":
            raise UnauthorizedError("issuer key not active")

        cred_id = new_credential_id()
        if public_key is not None:
            try:
                raw = keys.validate_public_key_b64(public_key)
                ok = pop_signature is not None and keys.verify(
                    public_key, keys.DOMAIN_CSR,
                    keys.csr_bytes(a.agent_id, inst.instance_id, public_key),
                    b64u_decode(pop_signature))
            except ValueError:
                raise ValidationError("invalid public key or proof of possession")
            if not ok:
                raise ValidationError("invalid public key or proof of possession")
            pub, key_id = public_key, None
        else:
            key_id = new_key_id()
            pub = b64u_encode(self.keystore.generate_key(key_id))
        fp = keys.fingerprint_b64(pub)

        iat = int(now)
        payload = build_payload(
            v=1, credential_id=cred_id, agent_id=a.agent_id, instance_id=inst.instance_id,
            org_id=a.org_id, issuer=issuer_uri(self.cfg.trust_domain, a.org_id, cert.issuer_key_id),
            issuer_key_id=cert.issuer_key_id, iat=iat, nbf=iat, exp=iat + ttl,
            agent_name=a.agent_name, agent_type=a.agent_type, owner=a.owner,
            environment=a.environment, capabilities=list(a.capabilities),
            parent_agent_id=a.parent_agent_id, is_sub_agent=a.parent_agent_id is not None,
            lineage=list(a.lineage), public_key=pub, key_fingerprint=fp,
            spiffe_id=spiffe_id(self.cfg.trust_domain, a.org_id, a.agent_id, inst.instance_id))
        sig = self.keystore.sign(cert.issuer_key_id, keys.DOMAIN_PASSPORT, payload)
        token = encode_token(payload, sig)
        self.credentials.put(CredentialRecord(cred_id, a.agent_id, inst.instance_id, a.org_id,
                                              cert.issuer_key_id, iat, iat + ttl, key_id, fp,
                                              payload_digest(payload)))
        self.log.emit("credential.issue", agent_id=a.agent_id, instance_id=inst.instance_id,
                      credential_id=cred_id, issuer_key_id=cert.issuer_key_id, actor=actor,
                      expires_at=iso(iat + ttl), correlation_id=correlation_id, result="ok")
        import json as _j
        return IssuedCredential(cred_id, token, _j.loads(payload), iso(iat), iso(iat + ttl))

    def verify_credential(self, token: str, **kw) -> VerificationResult:
        return self.verifier.verify_credential(token, **kw)

    def create_proof(self, token: str, audience: str, *, request_id: Optional[str] = None) -> dict:
        """DEV HELPER (service-held keys only): sign a possession proof for a credential."""
        import time
        from ..core.ids import new_nonce
        p = parse_token(token, self.cfg.max_token_bytes).payload
        rec = self.credentials.get(p["credential_id"])
        if rec is None or rec.key_id is None:
            raise NotFoundError("no service-held key for credential")
        proof = {"credential_id": rec.credential_id, "nonce": new_nonce(),
                 "timestamp": int(self.clock.now()), "request_id": request_id or new_nonce(),
                 "audience": audience}
        proof["signature"] = b64u_encode(self.keystore.sign(rec.key_id, keys.DOMAIN_PROOF,
                                                            keys.proof_bytes(proof)))
        return proof

    def rotate_credential(self, credential_id: str, *, grace_seconds: Optional[int] = None,
                          ttl_seconds: Optional[int] = None, public_key: Optional[str] = None,
                          pop_signature: Optional[str] = None,
                          actor: str = "system") -> IssuedCredential:
        """Issue a replacement (new keypair), then revoke the old one after a short grace."""
        actor = self._actor(actor)
        old = self.credentials.get(credential_id) if isinstance(credential_id, str) else None
        if old is None:
            raise NotFoundError("unknown credential")
        now = self.clock.now()
        if now >= old.expires_at or self.revocations.is_revoked(TargetType.CREDENTIAL,
                                                                credential_id, now):
            raise UnauthorizedError("credential expired or revoked; issue a new one")
        grace = self.cfg.rotation_grace_seconds if grace_seconds is None else int(grace_seconds)
        if grace < 0:
            raise ValidationError("invalid grace")
        new = self.issue_credential(old.agent_id, old.instance_id, ttl_seconds=ttl_seconds,
                                    public_key=public_key, pop_signature=pop_signature,
                                    actor=actor)
        self._add_revocation(TargetType.CREDENTIAL, credential_id,
                             RevocationReason.CREDENTIAL_ROTATED, actor,
                             f"rotated_to={new.credential_id}", now + min(grace, old.expires_at - now))
        self.log.emit("credential.rotate", credential_id=credential_id, agent_id=old.agent_id,
                      instance_id=old.instance_id, actor=actor, result="ok",
                      target_id=new.credential_id)
        return new

    # ----------------------------------------------------------- revocation
    def _add_revocation(self, ttype, tid, reason, by, detail, effective_at) -> RevocationRecord:
        if not isinstance(reason, RevocationReason):
            try:
                reason = RevocationReason(reason)
            except ValueError:
                raise ValidationError("invalid revocation reason")
        if detail is not None:
            V.safe_text("detail", detail, 256)
        now = self.clock.now()
        eff = now if effective_at is None else float(effective_at)
        rec = self.revocations.add(RevocationRecord(ttype, tid, reason, now, by, eff, detail))
        self.log.emit("revocation.add", target_type=ttype.value, target_id=tid, actor=by,
                      revocation_reason=reason.value, result="ok")
        return rec

    def revoke_credential(self, credential_id: str, reason, revoked_by: str,
                          detail: Optional[str] = None) -> dict:
        by = self._actor(revoked_by)
        c = self.credentials.get(credential_id) if isinstance(credential_id, str) else None
        if c is None:
            raise NotFoundError("unknown credential")
        rec = self._add_revocation(TargetType.CREDENTIAL, credential_id, reason, by, detail, None)
        if c.key_id:
            self.keystore.delete_key(c.key_id)   # drop service-held key immediately
        return rec.public_dict()

    def revoke_instance(self, instance_id: str, reason, revoked_by: str,
                        detail: Optional[str] = None) -> dict:
        by = self._actor(revoked_by)
        inst = self.agents.get_instance(instance_id) if isinstance(instance_id, str) else None
        if inst is None:
            raise NotFoundError("unknown instance")
        self.agents.put_instance(replace(inst, status=Status.TERMINATED))
        return self._add_revocation(TargetType.INSTANCE, instance_id, reason, by, detail,
                                    None).public_dict()

    def revoke_agent(self, agent_id: str, reason, revoked_by: str,
                     detail: Optional[str] = None) -> dict:
        """Terminates the agent; all instances, credentials and descendants stop verifying."""
        by = self._actor(revoked_by)
        a = self._agent(agent_id)
        self.agents.put_agent(replace(a, status=Status.TERMINATED))
        return self._add_revocation(TargetType.AGENT, agent_id, reason, by, detail,
                                    None).public_dict()

    def get_credential_status(self, credential_id: str) -> dict:
        c = self.credentials.get(credential_id) if isinstance(credential_id, str) else None
        if c is None:
            return {"credential_id": None, "status": "unknown"}
        now = self.clock.now()
        rev = self.revocations.get(TargetType.CREDENTIAL, credential_id)
        if rev and rev.effective_at <= now:
            status = "revoked"
        elif now >= c.expires_at:
            status = "expired"
        elif rev:
            status = "pending_revocation"
        else:
            status = "active"
        return {"credential_id": c.credential_id, "status": status, "agent_id": c.agent_id,
                "instance_id": c.instance_id, "issued_at": iso(c.issued_at),
                "expires_at": iso(c.expires_at),
                "revocation": rev.public_dict() if rev else None}

    def purge_expired_material(self) -> int:
        """Delete service-held ephemeral keys of expired/revoked credentials."""
        now, n = self.clock.now(), 0
        for c in self.credentials.list_all():
            if c.key_id and self.keystore.has_key(c.key_id) and (
                    now >= c.expires_at or self.revocations.is_revoked(
                        TargetType.CREDENTIAL, c.credential_id, now)):
                self.keystore.delete_key(c.key_id)
                n += 1
        return n

    # ------------------------------------------------------------ sub-agents
    def spawn_sub_agent(self, parent_token: str, parent_proof: dict, *, agent_name: str,
                        agent_type: str, description: str = "",
                        capabilities: Optional[Iterable[str]] = None,
                        metadata: Optional[dict] = None, issue_credential: bool = True,
                        ttl_seconds: Optional[int] = None, public_key: Optional[str] = None,
                        pop_signature: Optional[str] = None,
                        correlation_id: Optional[str] = None) -> SpawnResult:
        """The parent must authenticate with a valid credential + fresh proof bound to the
        spawn audience. Child capabilities must be a subset of the parent's (no escalation)."""
        res = self.verifier.verify_credential(parent_token, proof=parent_proof,
                                              audience=SPAWN_AUDIENCE, require_proof=True,
                                              correlation_id=correlation_id)
        if not res.valid:
            self.log.emit("agent.spawn", result="denied", reason=res.reason,
                          correlation_id=res.correlation_id)
            raise UnauthorizedError(f"parent credential rejected: {res.reason}")
        return self._spawn_authorized(
            res.agent_id, res.instance_id, agent_name=agent_name, agent_type=agent_type,
            description=description, capabilities=capabilities, metadata=metadata,
            issue_credential=issue_credential, ttl_seconds=ttl_seconds, public_key=public_key,
            pop_signature=pop_signature)

    def spawn_sub_agent_authorized(self, parent_agent_id: str, parent_instance_id: str, **kw) -> SpawnResult:
        """Spawn a sub-agent for a parent that the CALLER has already authenticated (e.g. via a
        verified SPIFFE JWT-SVID). Registry state, spawn capability, capability subsetting and
        depth limits are still enforced here. Never expose this directly to untrusted callers."""
        return self._spawn_authorized(parent_agent_id, parent_instance_id, **kw)

    def _spawn_authorized(self, parent_agent_id, parent_instance_id, *, agent_name, agent_type,
                          description="", capabilities=None, metadata=None, issue_credential=True,
                          ttl_seconds=None, public_key=None, pop_signature=None) -> SpawnResult:
        parent = self._agent(parent_agent_id)
        if parent.status != Status.ACTIVE:
            raise UnauthorizedError("parent agent not active")
        pinst = self.agents.get_instance(parent_instance_id)
        if pinst is None or pinst.agent_id != parent.agent_id or pinst.status != Status.ACTIVE:
            raise UnauthorizedError("parent instance invalid")
        if self.cfg.require_spawn_capability and SPAWN_CAPABILITY not in parent.capabilities:
            self.log.emit("agent.spawn", agent_id=parent.agent_id, result="denied",
                          reason="missing_spawn_capability")
            raise UnauthorizedError("parent lacks agent:spawn capability")
        caps = V.validate_capabilities(capabilities)
        if not set(caps) <= set(parent.capabilities):
            self.log.emit("agent.spawn", agent_id=parent.agent_id, result="denied",
                          reason="capability_escalation")
            raise UnauthorizedError("child capabilities exceed parent capabilities")
        if len(parent.lineage) + 1 >= self.cfg.max_sub_agent_depth:
            raise UnauthorizedError("maximum sub-agent depth reached")
        child = self._create_agent(parent.org_id, agent_name, agent_type, parent.owner,
                                   description, caps, parent.environment, metadata,
                                   parent.agent_id, parent.lineage + (parent.agent_id,),
                                   f"spawn:{parent.agent_id}")
        org = self._org(parent.org_id)
        spawn = SpawnRecord(parent.agent_id, child.agent_id, parent_instance_id, self.clock.now(),
                            issuer_uri(self.cfg.trust_domain, org.org_id, org.active_issuer_key_id))
        self.agents.put_spawn(spawn)
        inst = self.create_agent_instance(child.agent_id, actor=f"spawn:{parent.agent_id}")
        cred = None
        if issue_credential:
            cred = self.issue_credential(child.agent_id, inst["instance_id"],
                                         ttl_seconds=ttl_seconds, public_key=public_key,
                                         pop_signature=pop_signature,
                                         actor=f"spawn:{parent.agent_id}")
        self.log.emit("agent.spawn", agent_id=parent.agent_id, child_agent_id=child.agent_id,
                      instance_id=parent_instance_id, result="ok")
        return SpawnResult(child.public_dict(), inst, spawn.public_dict(), cred)
