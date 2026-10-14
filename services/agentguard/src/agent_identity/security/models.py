"""Step 8 enterprise security domain models.

These are ADDITIVE, immutable domain models for human/dashboard/auth plane security:
enterprise *users* (distinct from cryptographic *agents*), their global roles, per-tenant
memberships, browser sessions, rotating refresh tokens, durable audit events, and the OIDC
federation boundary (idp configs + login transactions).

None of these hold secrets: passwords are stored only as a PHC `scrypt` hash string, refresh
tokens only as a SHA-256 digest, OIDC configs only client *ids* (never client secrets).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional

from ..core.models import iso  # reuse the existing ISO-8601 formatter


class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"          # admin lockout: cannot authenticate; sessions revoked
    DISABLED = "disabled"            # deprovisioned (terminal): cannot authenticate, no sessions


class MembershipStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"          # tenant-scoped suspension: loses tenant access only


# Role ids are stable strings (persisted). The permission matrix lives in rbac.py.
ROLE_PLATFORM_ADMIN = "platform_administrator"
ROLE_TENANT_ADMIN = "tenant_administrator"
ROLE_SECURITY_ANALYST = "security_analyst"
ROLE_SECURITY_OPERATOR = "security_operator"
ROLE_DEVELOPER = "developer"
ROLE_READONLY_AUDITOR = "read_only_auditor"

ALL_ROLES = (ROLE_PLATFORM_ADMIN, ROLE_TENANT_ADMIN, ROLE_SECURITY_ANALYST,
             ROLE_SECURITY_OPERATOR, ROLE_DEVELOPER, ROLE_READONLY_AUDITOR)

# Roles that grant authority over a single organization/tenant only.
TENANT_ROLES = (ROLE_TENANT_ADMIN, ROLE_SECURITY_ANALYST, ROLE_SECURITY_OPERATOR,
                ROLE_DEVELOPER, ROLE_READONLY_AUDITOR)
# Roles that may only be held platform-wide (never granted via a tenant membership).
PLATFORM_ONLY_ROLES = (ROLE_PLATFORM_ADMIN,)


class IdpType(str, enum.Enum):
    OIDC = "oidc"


@dataclass(frozen=True)
class EnterpriseUser:
    """A human principal (dashboard operator / admin / auditor). Distinct from AgentRecord."""

    user_id: str
    email: str                                 # lowercased, unique (citext-like semantics)
    display_name: str
    status: UserStatus
    is_platform_admin: bool                    # derived flag, kept in sync with global roles
    global_roles: tuple                        # e.g. ("platform_administrator", "security_analyst")
    password_hash: Optional[str]               # PHC scrypt string; None for SSO-only / unprovisioned
    password_changed_at: Optional[float]
    must_change_password: bool
    failed_login_count: int
    locked_until: Optional[float]              # local-auth lockout window
    last_login_at: Optional[float]
    created_at: float
    created_by: str
    updated_at: float
    mfa_enrolled: bool = False                 # reserved for a later step (documented limitation)

    def public_dict(self) -> dict:
        return {"user_id": self.user_id, "email": self.email, "display_name": self.display_name,
                "status": self.status.value, "is_platform_admin": self.is_platform_admin,
                "global_roles": list(self.global_roles), "mfa_enrolled": self.mfa_enrolled,
                "last_login_at": iso(self.last_login_at), "created_at": iso(self.created_at),
                "must_change_password": self.must_change_password,
                "has_password": self.password_hash is not None}


@dataclass(frozen=True)
class TenantMembership:
    """Binds a user to an organization (tenant) with a set of tenant-scoped roles."""

    org_id: str
    user_id: str
    roles: tuple                               # subset of TENANT_ROLES
    status: MembershipStatus
    created_at: float
    created_by: str
    updated_at: float

    def public_dict(self) -> dict:
        return {"org_id": self.org_id, "user_id": self.user_id, "roles": list(self.roles),
                "status": self.status.value, "created_at": iso(self.created_at),
                "updated_at": iso(self.updated_at)}


@dataclass(frozen=True)
class SessionRecord:
    """A server-side browser/API session. The opaque session id is the primary key."""

    session_id: str
    user_id: str
    org_id: Optional[str]                      # active tenant context (None for platform-only)
    auth_method: str                           # "password" | "oidc"
    idp_id: Optional[str]
    amr: tuple = ()                            # auth methods: ("pwd",), ("pwd","mfa"), ("oidc",)
    created_at: float = 0.0
    last_seen_at: float = 0.0
    absolute_expires_at: float = 0.0
    idle_expires_at: float = 0.0
    status: str = "active"                     # active | revoked | expired
    revoked_at: Optional[float] = None
    revoked_reason: Optional[str] = None
    csrf_secret: str = ""                      # random per-session CSRF token seed (never logged)
    refresh_version: int = 0                   # bumped on refresh rotation (for detection)
    rotated_at: Optional[float] = None
    user_agent: Optional[str] = None
    ip: Optional[str] = None

    def is_active(self, now: float) -> bool:
        return (self.status == "active" and now < self.absolute_expires_at
                and now < self.idle_expires_at)

    def public_dict(self) -> dict:
        return {"session_id": self.session_id, "user_id": self.user_id, "org_id": self.org_id,
                "auth_method": self.auth_method, "idp_id": self.idp_id, "amr": list(self.amr),
                "created_at": iso(self.created_at), "last_seen_at": iso(self.last_seen_at),
                "absolute_expires_at": iso(self.absolute_expires_at),
                "idle_expires_at": iso(self.idle_expires_at), "status": self.status,
                "revoked_at": iso(self.revoked_at), "revoked_reason": self.revoked_reason}


@dataclass(frozen=True)
class RefreshTokenRecord:
    """A rotating refresh token. Only the SHA-256 digest is stored; the raw token is never kept."""

    token_hash: str                            # sha256(raw token), hex
    session_id: str
    user_id: str
    org_id: Optional[str]
    issued_at: float
    expires_at: float
    rotated_at: Optional[float] = None
    status: str = "active"                     # active | rotated | revoked
    parent_hash: Optional[str] = None
    child_hash: Optional[str] = None


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    ts: float
    event: str
    actor_user_id: Optional[str]
    actor_type: str                            # "user" | "system" | "agent"
    org_id: Optional[str]
    target_type: Optional[str]                 # user | session | membership | role | idp | agent | credential ...
    target_id: Optional[str]
    outcome: str                               # "ok" | "denied" | "error"
    reason: Optional[str]
    correlation_id: Optional[str]
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    idp_id: Optional[str] = None

    def public_dict(self) -> dict:
        return {"event_id": self.event_id, "ts": iso(self.ts), "event": self.event,
                "actor_user_id": self.actor_user_id, "actor_type": self.actor_type,
                "org_id": self.org_id, "target_type": self.target_type, "target_id": self.target_id,
                "outcome": self.outcome, "reason": self.reason,
                "correlation_id": self.correlation_id, "ip": self.ip, "user_agent": self.user_agent,
                "idp_id": self.idp_id}


@dataclass(frozen=True)
class IdpConfig:
    """An OIDC identity provider (federation). ``client_secret`` is stored ONLY as a reference name
    resolved from the environment/secret manager, never the value itself."""

    idp_id: str
    org_id: Optional[str]                      # None = platform-wide provider
    idp_type: IdpType
    issuer: str
    client_id: str
    client_secret_ref: str                     # env var / secret name; the *value* is never stored
    scopes: tuple                              # ("openid","profile","email")
    redirect_uri: str
    jwks_uri: str                              # may be "" -> discovered from issuer well-known
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    allowed_email_domains: tuple = ()          # optional: restrict which domains may sign in
    allowed_organizations: tuple = ()          # optional (Entra/Okta org claim)
    require_verified_email: bool = True
    enabled: bool = True
    created_at: float = 0.0
    created_by: str = "system"
    updated_at: float = 0.0

    def public_dict(self) -> dict:
        return {"idp_id": self.idp_id, "org_id": self.org_id, "idp_type": self.idp_type.value,
                "issuer": self.issuer, "client_id": self.client_id,
                "has_client_secret": bool(self.client_secret_ref), "scopes": list(self.scopes),
                "redirect_uri": self.redirect_uri, "jwks_uri": self.jwks_uri,
                "allowed_email_domains": list(self.allowed_email_domains),
                "require_verified_email": self.require_verified_email, "enabled": self.enabled}


@dataclass(frozen=True)
class LoginTransaction:
    """A single-use OIDC authorization-code login attempt: binds state + PKCE verifier + nonce.

    Stored server-side (Redis, tenant-aware namespace). Consuming it is atomic, so a replayed or
    forged callback cannot be exchanged. Never holds tokens or the client secret.
    """

    txn_id: str                                # = the OIDC `state` value (opaque, high entropy)
    idp_id: str
    org_id: Optional[str]
    code_verifier: str                         # PKCE (S256) verifier
    nonce: str                                 # binds the id_token
    redirect_uri: str
    return_to: Optional[str]                   # validated post-login redirect (allow-listed paths)
    created_at: float
    expires_at: float
    ip: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class AuthContext:
    """Result of authenticating a request: a verified principal + tenant scope + permissions.

    ``permissions`` is the resolved, sorted effective permission set (PostgreSQL authoritative,
    optionally Redis-cached). ``org_id`` is the tenant scope the request is bound to; it comes from
    the VERIFIED session, never from the request body/query.
    """

    user_id: str
    email: str
    org_id: Optional[str]
    roles: tuple                               # effective roles in this tenant + global
    permissions: frozenset
    is_platform_admin: bool
    session_id: str
    amr: tuple = ()
    correlation_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {"user_id": self.user_id, "org_id": self.org_id, "roles": list(self.roles),
                "is_platform_admin": self.is_platform_admin, "session_id": self.session_id,
                "amr": list(self.amr)}


@dataclass(frozen=True)
class LoginResult:
    user: dict
    session: dict
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    expires_in: int = 0

    def __repr__(self) -> str:                 # never leak bearer material via repr
        return (f"LoginResult(user={self.user.get('user_id')!r}, "
                f"session={self.session.get('session_id')!r}, tokens=<redacted>)")
