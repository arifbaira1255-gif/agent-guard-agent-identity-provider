"""Immutable domain models. None of these hold private key material."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Status(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


class RevocationReason(str, enum.Enum):
    COMPROMISE = "compromise"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    AGENT_TERMINATED = "agent_terminated"
    CREDENTIAL_ROTATED = "credential_rotated"
    ADMINISTRATIVE_ACTION = "administrative_action"
    SECURITY_INCIDENT = "security_incident"


class TargetType(str, enum.Enum):
    CREDENTIAL = "credential"
    INSTANCE = "instance"
    AGENT = "agent"
    ISSUER_KEY = "issuer_key"


class Reason:
    """Machine-readable verification failure reasons (safe to expose)."""
    MALFORMED_TOKEN = "malformed_token"
    UNKNOWN_ISSUER = "unknown_issuer"
    UNTRUSTED_ISSUER_CHAIN = "untrusted_issuer_chain"
    ISSUER_REVOKED = "issuer_revoked"
    ISSUER_KEY_RETIRED = "issuer_key_retired"
    ISSUER_MISMATCH = "issuer_mismatch"
    INVALID_SIGNATURE = "invalid_signature"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    TTL_EXCEEDS_POLICY = "ttl_exceeds_policy"
    UNKNOWN_AGENT = "unknown_agent"
    UNKNOWN_INSTANCE = "unknown_instance"
    UNKNOWN_CREDENTIAL = "unknown_credential"
    CREDENTIAL_MISMATCH = "credential_mismatch"
    REGISTRY_MISMATCH = "registry_mismatch"
    AGENT_MISMATCH = "agent_mismatch"
    INSTANCE_MISMATCH = "instance_mismatch"
    AGENT_NOT_ACTIVE = "agent_not_active"
    INSTANCE_NOT_ACTIVE = "instance_not_active"
    ORG_NOT_ACTIVE = "org_not_active"
    ANCESTOR_NOT_ACTIVE = "ancestor_not_active"
    AGENT_KEY_RETIRED = "agent_key_retired"
    REVOKED = "revoked"
    PROOF_REQUIRED = "proof_required"
    INVALID_PROOF = "invalid_proof"
    PROOF_STALE = "proof_stale"
    AUDIENCE_MISMATCH = "audience_mismatch"
    REPLAY_DETECTED = "replay_detected"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True)
class Organization:
    org_id: str
    name: str
    created_at: float
    status: Status
    active_issuer_key_id: str
    allowed_capabilities: Optional[tuple] = None

    def public_dict(self) -> dict:
        return {"org_id": self.org_id, "name": self.name, "status": self.status.value,
                "created_at": iso(self.created_at),
                "active_issuer_key_id": self.active_issuer_key_id,
                "allowed_capabilities": list(self.allowed_capabilities)
                if self.allowed_capabilities is not None else None}


@dataclass(frozen=True)
class IssuerCertificate:
    """Binds an organization's issuer public key to a trusted root (signed by root)."""
    issuer_key_id: str
    org_id: str
    public_key: str          # base64url raw Ed25519
    fingerprint: str
    root_key_id: str
    issued_at: float
    signature: str           # root signature over cert body
    status: str = "active"   # active | retiring | revoked
    not_after: Optional[float] = None   # set when retiring

    def public_dict(self) -> dict:
        return {"issuer_key_id": self.issuer_key_id, "org_id": self.org_id,
                "fingerprint": self.fingerprint, "status": self.status,
                "issued_at": iso(self.issued_at), "not_after": iso(self.not_after),
                "root_key_id": self.root_key_id}


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    org_id: str
    agent_name: str
    agent_type: str
    owner: str
    description: str
    capabilities: tuple
    environment: str
    metadata: dict
    parent_agent_id: Optional[str]
    lineage: tuple                      # ancestor agent_ids, root-most first
    created_at: float
    status: Status
    key_id: str                         # agent identity key (held in KeyStore)
    public_key: str
    fingerprint: str
    retired_keys: tuple = ()            # ((key_id, not_after), ...)
    created_by: str = "system"

    def key_valid(self, key_id: str, now: float) -> bool:
        if key_id == self.key_id:
            return True
        return any(k == key_id and now < na for k, na in self.retired_keys)

    def public_dict(self) -> dict:
        return {"agent_id": self.agent_id, "org_id": self.org_id,
                "agent_name": self.agent_name, "agent_type": self.agent_type,
                "owner": self.owner, "description": self.description,
                "capabilities": list(self.capabilities), "environment": self.environment,
                "metadata": dict(self.metadata), "parent_agent_id": self.parent_agent_id,
                "is_sub_agent": self.parent_agent_id is not None,
                "lineage": list(self.lineage), "created_at": iso(self.created_at),
                "status": self.status.value, "public_key": self.public_key,
                "key_fingerprint": self.fingerprint, "key_id": self.key_id}


@dataclass(frozen=True)
class InstanceRecord:
    instance_id: str
    agent_id: str
    org_id: str
    session_id: str
    created_at: float
    status: Status
    agent_key_id: str
    agent_public_key: str
    binding_signature: str   # signed by the agent identity key at creation

    def public_dict(self) -> dict:
        return {"instance_id": self.instance_id, "agent_id": self.agent_id,
                "org_id": self.org_id, "session_id": self.session_id,
                "created_at": iso(self.created_at), "status": self.status.value}


@dataclass(frozen=True)
class CredentialRecord:
    credential_id: str
    agent_id: str
    instance_id: str
    org_id: str
    issuer_key_id: str
    issued_at: float
    expires_at: float
    key_id: Optional[str]        # ephemeral key in KeyStore (None if agent-held)
    key_fingerprint: str
    payload_digest: str          # sha256 of exact signed payload bytes


@dataclass(frozen=True)
class RevocationRecord:
    target_type: TargetType
    target_id: str
    reason: RevocationReason
    revoked_at: float
    revoked_by: str
    effective_at: float
    detail: Optional[str] = None

    def public_dict(self) -> dict:
        return {"target_type": self.target_type.value, "target_id": self.target_id,
                "reason": self.reason.value, "revoked_at": iso(self.revoked_at),
                "revoked_by": self.revoked_by, "effective_at": iso(self.effective_at),
                "detail": self.detail}


@dataclass(frozen=True)
class SpawnRecord:
    parent_agent_id: str
    child_agent_id: str
    spawned_by_instance_id: str
    created_at: float
    issuer: str
    status: Status = Status.ACTIVE

    def public_dict(self) -> dict:
        return {"parent_agent_id": self.parent_agent_id,
                "child_agent_id": self.child_agent_id,
                "spawned_by_instance_id": self.spawned_by_instance_id,
                "created_at": iso(self.created_at), "issuer": self.issuer,
                "status": self.status.value}


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: Optional[str] = None
    agent_id: Optional[str] = None
    instance_id: Optional[str] = None
    credential_id: Optional[str] = None
    issuer: Optional[str] = None
    expires_at: Optional[str] = None
    org_id: Optional[str] = None
    capabilities: tuple = ()
    parent_agent_id: Optional[str] = None
    is_sub_agent: bool = False
    key_fingerprint: Optional[str] = None
    correlation_id: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"valid": self.valid, "agent_id": self.agent_id,
             "instance_id": self.instance_id, "credential_id": self.credential_id,
             "issuer": self.issuer, "expires_at": self.expires_at, "reason": self.reason,
             "correlation_id": self.correlation_id}
        if self.valid:
            d.update({"org_id": self.org_id, "capabilities": list(self.capabilities),
                      "parent_agent_id": self.parent_agent_id,
                      "is_sub_agent": self.is_sub_agent,
                      "key_fingerprint": self.key_fingerprint})
        return d


@dataclass(frozen=True)
class IssuedCredential:
    credential_id: str
    token: str = field(repr=False)       # bearer material: never repr/logged
    passport: dict = field(repr=False)
    issued_at: str = ""
    expires_at: str = ""

    def __repr__(self) -> str:
        return (f"IssuedCredential(credential_id={self.credential_id!r}, "
                f"expires_at={self.expires_at!r}, token=<redacted>)")

    def to_dict(self, include_token: bool = True) -> dict:
        d = {"credential_id": self.credential_id, "issued_at": self.issued_at,
             "expires_at": self.expires_at, "passport": self.passport}
        if include_token:
            d["token"] = self.token
        return d
