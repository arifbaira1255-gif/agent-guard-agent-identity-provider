"""Step 8: enterprise authentication, RBAC and multi-tenancy.

Public surface (additive to Steps 1-7; nothing here mutates the agent-identity plane):

  * ``EnterpriseAuthConfig``            — fail-closed configuration (env-driven secrets).
  * ``EnterpriseAuthService``           — local + OIDC login, sessions, authorization checks.
  * ``AdminOps``                        — audited administrative operations with escalation guards.
  * ``RBAC`` / ``Authorizer``           — the six role permission matrix + decision point.
  * ``TokenSigner`` / ``SessionManager`` — short-lived access tokens, rotating refresh tokens.
  * ``EnterpriseStore`` (+ Pg / Memory) — users, memberships, sessions, refresh tokens, idps, audit.
  * ``PermissionCache`` / ``SecurityKeys`` — tenant-namespaced Redis cache; PostgreSQL authoritative.
  * ``AuditLog``                        — durable, allow-listed, secret-free audit events.
"""
from .admin_ops import AdminOps
from .audit import AuditLog
from .auth_service import EnterpriseAuthService
from .config import EnterpriseAuthConfig
from .memory_store import MemoryEnterpriseStore
from .models import (ALL_ROLES, ROLE_DEVELOPER, ROLE_PLATFORM_ADMIN, ROLE_READONLY_AUDITOR,
                     ROLE_SECURITY_ANALYST, ROLE_SECURITY_OPERATOR, ROLE_TENANT_ADMIN, TENANT_ROLES,
                     AuthContext, EnterpriseUser, IdpConfig, IdpType, LoginResult, SessionRecord,
                     TenantMembership, UserStatus)
from .oidc import OidcClient, OidcError, validate_id_token
from .passwords import (hash_password, needs_rehash, password_policy_error, verify_password)
from .permission_cache import PermissionCache
from .rbac import (PERMISSIONS, Authorizer, EffectiveAccess, ROLE_PERMISSIONS, effective_access,
                   permission_matrix, sanitize_global_roles, sanitize_tenant_roles)
from .redis_keys import SecurityKeys
from .session_manager import SessionManager, csrf_token_for
from .store import EnterpriseStore
from .tokens import AccessClaims, TokenSigner, digest, random_token, redact

__all__ = [
    "AdminOps", "AuditLog", "EnterpriseAuthService", "EnterpriseAuthConfig",
    "MemoryEnterpriseStore", "EnterpriseStore", "PermissionCache", "SecurityKeys",
    "SessionManager", "csrf_token_for", "TokenSigner", "AccessClaims", "digest", "random_token",
    "redact", "OidcClient", "OidcError", "validate_id_token",
    "hash_password", "verify_password", "needs_rehash", "password_policy_error",
    "Authorizer", "EffectiveAccess", "effective_access", "permission_matrix", "PERMISSIONS",
    "ROLE_PERMISSIONS", "sanitize_tenant_roles", "sanitize_global_roles",
    "EnterpriseUser", "TenantMembership", "SessionRecord", "IdpConfig", "IdpType", "AuthContext",
    "LoginResult", "UserStatus", "ALL_ROLES", "TENANT_ROLES",
    "ROLE_PLATFORM_ADMIN", "ROLE_TENANT_ADMIN", "ROLE_SECURITY_ANALYST", "ROLE_SECURITY_OPERATOR",
    "ROLE_DEVELOPER", "ROLE_READONLY_AUDITOR",
]
