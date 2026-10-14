"""Administrative security operations (Step 8), each with explicit authorization, guards and audit.

Every method:
  1. authorizes the ACTOR through the single :class:`Authorizer` decision point (no client-supplied
     authority is ever trusted),
  2. applies a domain guard that protects a security invariant (e.g. "never remove the last platform
     administrator"), 
  3. mutates the authoritative PostgreSQL store,
  4. invalidates the affected user's *permission cache* entries in Redis, and
  5. writes a durable + structured audit event.

Guards central to Step 8
------------------------
* **No tenant → platform escalation.** ``sanitize_tenant_roles`` rejects platform roles on any
  membership (enforced again by a SQL CHECK constraint), and only a platform administrator may grant
  a *global* role.
* **Never lock everyone out.** The last *active* platform administrator cannot be stripped of the
  platform role, suspended, or disabled; the last *active* tenant administrator of a tenant cannot
  be removed or demoted.
* **Least privilege / explicit deny** are inherited from the RBAC matrix — an operation simply fails
  the permission check if the actor's effective set does not contain the required permission.
"""
from __future__ import annotations

import dataclasses
from typing import List, Optional, Sequence

from ..core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from .audit import (AuditLog, E_ADMIN_SESSIONS_REVOKED, E_IDP_CREATED, E_IDP_DELETED, E_IDP_UPDATED,
                    E_MEMBERSHIP_ADDED, E_MEMBERSHIP_REMOVED, E_MEMBERSHIP_SUSPENDED,
                    E_MEMBERSHIP_REACTIVATED, E_ROLE_GRANTED, E_ROLE_REVOKED, E_USER_CREATED,
                    E_USER_DISABLED, E_USER_EMAIL_UPDATED, E_USER_PASSWORD_CHANGED,
                    E_USER_REACTIVATED, E_USER_SUSPENDED)
from .config import EnterpriseAuthConfig
from .ids import new_id
from .models import (EnterpriseUser, IdpConfig, IdpType, MembershipStatus, TenantMembership,
                     UserStatus, ROLE_PLATFORM_ADMIN, ROLE_TENANT_ADMIN)
from .passwords import hash_password, password_policy_error
from .permission_cache import PermissionCache
from .rbac import (P_AGENT_READ, P_AUDIT_READ, P_IDP_READ, P_IDP_WRITE, P_MEMBERSHIP_WRITE,
                   P_PLATFORM_ADMIN, P_RBAC_READ, P_ROLE_ASSIGN, P_SESSION_READ, P_SESSION_REVOKE,
                   P_TENANT_CREATE, P_USER_DELETE, P_USER_READ, P_USER_WRITE, Authorizer,
                   EffectiveAccess, PLATFORM_ONLY_ROLES, sanitize_global_roles, sanitize_tenant_roles)
from .store import EnterpriseStore


class AdminOps:
    def __init__(self, store: EnterpriseStore, audit: AuditLog, config: EnterpriseAuthConfig,
                 *, permission_cache: Optional[PermissionCache] = None, sessions=None, clock=None):
        self.store = store
        self.audit = audit
        self.config = config
        self.permission_cache = permission_cache
        self.sessions = sessions
        self._clock = clock

    def _now(self) -> float:
        import time
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ shared helpers
    def _require(self, actor: EffectiveAccess, perm: str, *, org_id: Optional[str] = None) -> None:
        try:
            Authorizer.require(actor, perm, org_id=org_id)
        except ForbiddenError:
            self.audit.deny(actor_user_id=actor.user_id, org_id=actor.org_id, target_type="permission",
                            target_id=perm, reason="permission_denied")
            raise

    def _invalidate(self, user_id: str) -> None:
        if self.permission_cache is None:
            return
        memberships = self.store.list_memberships(user_id=user_id)
        self.permission_cache.invalidate_user_everywhere(memberships, user_id)

    def _invalidate_scope(self, org_id: Optional[str], user_id: str) -> None:
        if self.permission_cache is not None:
            self.permission_cache.invalidate(org_id, user_id)

    # ================================================================== user lifecycle
    def create_user(self, actor: EffectiveAccess, *, email: str, display_name: str,
                    global_roles: Sequence[str] = (), password: Optional[str] = None,
                    org_id: Optional[str] = None, tenant_roles: Sequence[str] = (),
                    must_change_password: Optional[bool] = None,
                    correlation_id: Optional[str] = None) -> EnterpriseUser:
        """Create a user. Global platform roles require ``platform:admin``; tenant roles require
        ``membership:write`` + ``role:assign`` inside the tenant."""
        email = (email or "").strip()
        if "@" not in email or len(email) > 320:
            raise ValidationError("a valid email is required")
        if not display_name or len(display_name) > 200:
            raise ValidationError("a display name is required")
        # Organization-scoped creation needs the tenant permissions; without an org we require
        # the platform user-management permission.
        self._require(actor, P_USER_WRITE, org_id=org_id)
        g_roles = sanitize_global_roles(global_roles, actor_is_platform_admin=actor.is_platform_admin)
        t_roles = sanitize_tenant_roles(tenant_roles) if org_id is not None else ()
        if org_id is not None and (t_roles or tenant_roles):
            self._require(actor, P_ROLE_ASSIGN, org_id=org_id)
        if any(r in PLATFORM_ONLY_ROLES for r in g_roles):
            self._require(actor, P_PLATFORM_ADMIN)

        password_hash = None
        if password is not None:
            err = password_policy_error(password)
            if err:
                raise ValidationError(err)
            password_hash = hash_password(password)
        if self.store.get_user_by_email(email) is not None:
            raise ConflictError("email already in use")

        now = self._now()
        user = EnterpriseUser(
            user_id=new_id("usr"), email=email, display_name=display_name, status=UserStatus.ACTIVE,
            is_platform_admin=(ROLE_PLATFORM_ADMIN in g_roles), global_roles=tuple(g_roles),
            password_hash=password_hash, password_changed_at=(now if password_hash else None),
            must_change_password=bool(must_change_password) if must_change_password is not None
            else (password is None), failed_login_count=0, locked_until=None, last_login_at=None,
            created_at=now, created_by=actor.user_id, updated_at=now)
        self.store.put_user(user)
        self.audit.record(E_USER_CREATED, actor_user_id=actor.user_id, org_id=org_id,
                          target_type="user", target_id=user.user_id, outcome="ok",
                          correlation_id=correlation_id,
                          extra={"role": ",".join(g_roles) if g_roles else "none"})
        if org_id is not None:
            self.add_membership(actor, org_id=org_id, user_id=user.user_id, roles=t_roles,
                                correlation_id=correlation_id)
        return user

    def set_global_roles(self, actor: EffectiveAccess, user_id: str, roles: Sequence[str], *,
                         correlation_id: Optional[str] = None) -> EnterpriseUser:
        """Grant/revoke GLOBAL roles. Platform-administrator only."""
        self._require(actor, P_PLATFORM_ADMIN)
        target = self._get_user(user_id)
        new_roles = sanitize_global_roles(roles, actor_is_platform_admin=True)
        padmin_now = ROLE_PLATFORM_ADMIN in new_roles
        if target.is_platform_admin and not padmin_now:
            self._ensure_not_last_platform_admin(target, action="remove platform role")
            self._require(actor, P_PLATFORM_ADMIN)          # cannot self-demote either, if last
        user = dataclasses.replace(target, global_roles=tuple(new_roles), is_platform_admin=padmin_now,
                                   updated_at=self._now())
        self.store.put_user(user)
        self._invalidate(user_id)
        added = set(new_roles) - set(target.global_roles)
        removed = set(target.global_roles) - set(new_roles)
        self.audit.record(E_ROLE_GRANTED if added else E_ROLE_REVOKED, actor_user_id=actor.user_id,
                          org_id=None, target_type="user", target_id=user_id, outcome="ok",
                          correlation_id=correlation_id,
                          extra={"role": ",".join(sorted(added or removed)) or "none"})
        return user

    def suspend_user(self, actor: EffectiveAccess, user_id: str, reason: str, *,
                     correlation_id: Optional[str] = None) -> EnterpriseUser:
        self._require_manage_user(actor, user_id, perm=P_USER_WRITE)
        target = self._get_user(user_id)
        if target.is_platform_admin:
            self._ensure_not_last_platform_admin(target, action="suspend")
        user = dataclasses.replace(target, status=UserStatus.SUSPENDED, updated_at=self._now())
        self.store.put_user(user)
        if self.sessions is not None:
            self.sessions.revoke_user(user_id, "account_suspended", actor_user_id=actor.user_id,
                                      org_id=actor.org_id, correlation_id=correlation_id)
        self._invalidate(user_id)
        self.audit.record(E_USER_SUSPENDED, actor_user_id=actor.user_id, org_id=actor.org_id,
                          target_type="user", target_id=user_id, outcome="ok", reason=reason,
                          correlation_id=correlation_id)
        return user

    def reactivate_user(self, actor: EffectiveAccess, user_id: str, *,
                        correlation_id: Optional[str] = None) -> EnterpriseUser:
        self._require_manage_user(actor, user_id, perm=P_USER_WRITE)
        target = self._get_user(user_id)
        user = dataclasses.replace(target, status=UserStatus.ACTIVE, failed_login_count=0,
                                   locked_until=None, updated_at=self._now())
        self.store.put_user(user)
        self._invalidate(user_id)
        self.audit.record(E_USER_REACTIVATED, actor_user_id=actor.user_id, org_id=actor.org_id,
                          target_type="user", target_id=user_id, outcome="ok",
                          correlation_id=correlation_id)
        return user

    def disable_user(self, actor: EffectiveAccess, user_id: str, *,
                     correlation_id: Optional[str] = None) -> EnterpriseUser:
        """Terminal deprovisioning. Platform-administrator only (``user:delete``)."""
        self._require(actor, P_USER_DELETE)
        target = self._get_user(user_id)
        if target.is_platform_admin:
            self._ensure_not_last_platform_admin(target, action="disable")
        user = dataclasses.replace(target, status=UserStatus.DISABLED, updated_at=self._now())
        self.store.put_user(user)
        # deprovisioning also removes memberships so no residual tenant authority remains
        for m in self.store.list_memberships(user_id=user_id):
            self.store.delete_membership(m.org_id, user_id)
        if self.sessions is not None:
            self.sessions.revoke_user(user_id, "account_disabled", actor_user_id=actor.user_id,
                                      org_id=actor.org_id, correlation_id=correlation_id)
        self._invalidate(user_id)
        self.audit.record(E_USER_DISABLED, actor_user_id=actor.user_id, org_id=actor.org_id,
                          target_type="user", target_id=user_id, outcome="ok",
                          correlation_id=correlation_id)
        return user

    def admin_set_password(self, actor: EffectiveAccess, user_id: str, new_password: str, *,
                           correlation_id: Optional[str] = None) -> EnterpriseUser:
        """Administrative password reset. Forces a change at next login and revokes all sessions."""
        self._require_manage_user(actor, user_id, perm=P_USER_WRITE)
        err = password_policy_error(new_password)
        if err:
            raise ValidationError(err)
        target = self._get_user(user_id)
        user = dataclasses.replace(target, password_hash=hash_password(new_password),
                                   password_changed_at=self._now(), must_change_password=True,
                                   failed_login_count=0, locked_until=None, updated_at=self._now())
        self.store.put_user(user)
        if self.sessions is not None:
            self.sessions.revoke_user(user_id, "password_reset", actor_user_id=actor.user_id,
                                      org_id=actor.org_id, correlation_id=correlation_id)
        self._invalidate(user_id)
        self.audit.record(E_USER_PASSWORD_CHANGED, actor_user_id=actor.user_id, org_id=actor.org_id,
                          target_type="user", target_id=user_id, outcome="ok", reason="admin_reset",
                          correlation_id=correlation_id)
        return user

    # ================================================================== memberships
    def add_membership(self, actor: EffectiveAccess, *, org_id: str, user_id: str,
                       roles: Sequence[str], correlation_id: Optional[str] = None) -> TenantMembership:
        self._require(actor, P_MEMBERSHIP_WRITE, org_id=org_id)
        t_roles = sanitize_tenant_roles(roles)
        if t_roles:
            self._require(actor, P_ROLE_ASSIGN, org_id=org_id)
        self._get_user(user_id)
        now = self._now()
        m = TenantMembership(org_id, user_id, t_roles, MembershipStatus.ACTIVE, now, actor.user_id, now)
        self.store.put_membership(m)
        self._invalidate_scope(org_id, user_id)
        self.audit.record(E_MEMBERSHIP_ADDED, actor_user_id=actor.user_id, org_id=org_id,
                          target_type="membership", target_id=user_id, outcome="ok",
                          correlation_id=correlation_id,
                          extra={"role": ",".join(t_roles) or "none"})
        return m

    def set_membership_roles(self, actor: EffectiveAccess, *, org_id: str, user_id: str,
                             roles: Sequence[str], correlation_id: Optional[str] = None
                             ) -> TenantMembership:
        self._require(actor, P_ROLE_ASSIGN, org_id=org_id)
        m = self.store.get_membership(org_id, user_id)
        if m is None:
            raise NotFoundError("membership not found")
        t_roles = sanitize_tenant_roles(roles)
        if (ROLE_TENANT_ADMIN in m.roles) and (ROLE_TENANT_ADMIN not in t_roles):
            # demoting a tenant admin: refuse if they are the last one
            if self.store.count_org_admins(org_id) <= 1:
                raise ConflictError("cannot remove the last tenant administrator of this tenant")
        updated = dataclasses.replace(m, roles=t_roles, updated_at=self._now())
        self.store.put_membership(updated)
        self._invalidate_scope(org_id, user_id)
        added = set(t_roles) - set(m.roles)
        self.audit.record(E_ROLE_GRANTED if added else E_ROLE_REVOKED, actor_user_id=actor.user_id,
                          org_id=org_id, target_type="membership", target_id=user_id, outcome="ok",
                          correlation_id=correlation_id,
                          extra={"role": ",".join(sorted(added or (set(m.roles) - set(t_roles)))) or "none"})
        return updated

    def suspend_membership(self, actor: EffectiveAccess, *, org_id: str, user_id: str, reason: str,
                           correlation_id: Optional[str] = None) -> TenantMembership:
        self._require(actor, P_MEMBERSHIP_WRITE, org_id=org_id)
        m = self.store.get_membership(org_id, user_id)
        if m is None:
            raise NotFoundError("membership not found")
        if ROLE_TENANT_ADMIN in m.roles and self.store.count_org_admins(org_id) <= 1:
            raise ConflictError("cannot suspend the last tenant administrator of this tenant")
        updated = dataclasses.replace(m, status=MembershipStatus.SUSPENDED, updated_at=self._now())
        self.store.put_membership(updated)
        self._invalidate_scope(org_id, user_id)
        self.audit.record(E_MEMBERSHIP_SUSPENDED, actor_user_id=actor.user_id, org_id=org_id,
                          target_type="membership", target_id=user_id, outcome="ok", reason=reason,
                          correlation_id=correlation_id)
        return updated

    def reactivate_membership(self, actor: EffectiveAccess, *, org_id: str, user_id: str,
                              correlation_id: Optional[str] = None) -> TenantMembership:
        self._require(actor, P_MEMBERSHIP_WRITE, org_id=org_id)
        m = self.store.get_membership(org_id, user_id)
        if m is None:
            raise NotFoundError("membership not found")
        updated = dataclasses.replace(m, status=MembershipStatus.ACTIVE, updated_at=self._now())
        self.store.put_membership(updated)
        self._invalidate_scope(org_id, user_id)
        self.audit.record(E_MEMBERSHIP_REACTIVATED, actor_user_id=actor.user_id, org_id=org_id,
                          target_type="membership", target_id=user_id, outcome="ok",
                          correlation_id=correlation_id)
        return updated

    def remove_membership(self, actor: EffectiveAccess, *, org_id: str, user_id: str,
                          correlation_id: Optional[str] = None) -> None:
        self._require(actor, P_MEMBERSHIP_WRITE, org_id=org_id)
        m = self.store.get_membership(org_id, user_id)
        if m is None:
            raise NotFoundError("membership not found")
        if ROLE_TENANT_ADMIN in m.roles and self.store.count_org_admins(org_id) <= 1:
            raise ConflictError("cannot remove the last tenant administrator of this tenant")
        self.store.delete_membership(org_id, user_id)
        self._invalidate_scope(org_id, user_id)
        self.audit.record(E_MEMBERSHIP_REMOVED, actor_user_id=actor.user_id, org_id=org_id,
                          target_type="membership", target_id=user_id, outcome="ok",
                          correlation_id=correlation_id)

    # ================================================================== sessions
    def revoke_user_sessions(self, actor: EffectiveAccess, user_id: str, *,
                             except_session_id: Optional[str] = None,
                             correlation_id: Optional[str] = None) -> int:
        if actor.user_id != user_id:
            self._require_manage_user(actor, user_id, perm=P_SESSION_REVOKE)
        n = 0
        if self.sessions is not None:
            n = self.sessions.revoke_user(user_id, "admin_revoked", except_session_id=except_session_id,
                                          actor_user_id=actor.user_id, org_id=actor.org_id,
                                          correlation_id=correlation_id)
        self.audit.record(E_ADMIN_SESSIONS_REVOKED, actor_user_id=actor.user_id, org_id=actor.org_id,
                          target_type="user", target_id=user_id, outcome="ok",
                          correlation_id=correlation_id, extra={"session_id": f"count:{n}"})
        return n

    def list_user_sessions(self, actor: EffectiveAccess, user_id: str, *,
                           correlation_id: Optional[str] = None) -> List:
        if actor.user_id != user_id:
            self._require_manage_user(actor, user_id, perm=P_SESSION_READ)
        return self.store.list_sessions(user_id=user_id)

    def revoke_session(self, actor: EffectiveAccess, session_id: str, *,
                       correlation_id: Optional[str] = None) -> bool:
        s = self.store.get_session(session_id)
        if s is None:
            raise NotFoundError("session not found")
        if actor.user_id != s.user_id:
            self._require_manage_user(actor, s.user_id, perm=P_SESSION_REVOKE)
        ok = False
        if self.sessions is not None:
            ok = self.sessions.revoke(session_id, "admin_revoked", actor_user_id=actor.user_id,
                                      org_id=actor.org_id, correlation_id=correlation_id)
        return ok

    # ================================================================== identity providers
    def create_idp(self, actor: EffectiveAccess, *, issuer: str, client_id: str,
                   client_secret_ref: str, redirect_uri: str, scopes: Sequence[str] = ("openid",
                   "profile", "email"), org_id: Optional[str] = None, jwks_uri: str = "",
                   authorization_endpoint: str = "", token_endpoint: str = "",
                   allowed_email_domains: Sequence[str] = (), require_verified_email: bool = True,
                   correlation_id: Optional[str] = None) -> IdpConfig:
        self._require(actor, P_IDP_WRITE, org_id=org_id)
        if org_id is None:
            self._require(actor, P_PLATFORM_ADMIN)          # platform-wide provider
        for name, val in (("issuer", issuer), ("client_id", client_id),
                          ("redirect_uri", redirect_uri)):
            if not val or not isinstance(val, str):
                raise ValidationError(f"{name} is required")
        if not client_secret_ref:
            raise ValidationError("client_secret_ref (the env var name holding the secret) is required")
        now = self._now()
        cfg = IdpConfig(idp_id=new_id("idp"), org_id=org_id, idp_type=IdpType.OIDC, issuer=issuer,
                        client_id=client_id, client_secret_ref=client_secret_ref,
                        scopes=tuple(scopes), redirect_uri=redirect_uri, jwks_uri=jwks_uri,
                        authorization_endpoint=authorization_endpoint, token_endpoint=token_endpoint,
                        allowed_email_domains=tuple(d.lower() for d in allowed_email_domains),
                        require_verified_email=require_verified_email, enabled=True,
                        created_at=now, created_by=actor.user_id, updated_at=now)
        self.store.put_idp(cfg)
        self.audit.record(E_IDP_CREATED, actor_user_id=actor.user_id, org_id=org_id,
                          target_type="idp", target_id=cfg.idp_id, outcome="ok",
                          correlation_id=correlation_id, idp_id=cfg.idp_id)
        return cfg

    def update_idp(self, actor: EffectiveAccess, idp_id: str, *, correlation_id: Optional[str] = None,
                   **fields) -> IdpConfig:
        cfg = self.store.get_idp(idp_id)
        if cfg is None:
            raise NotFoundError("identity provider not found")
        self._require(actor, P_IDP_WRITE, org_id=cfg.org_id)
        if cfg.org_id is None:
            self._require(actor, P_PLATFORM_ADMIN)
        allowed = {"issuer", "client_id", "client_secret_ref", "redirect_uri", "scopes", "jwks_uri",
                   "authorization_endpoint", "token_endpoint", "allowed_email_domains",
                   "require_verified_email", "enabled"}
        clean = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if "scopes" in clean:
            clean["scopes"] = tuple(clean["scopes"])
        if "allowed_email_domains" in clean:
            clean["allowed_email_domains"] = tuple(d.lower() for d in clean["allowed_email_domains"])
        updated = dataclasses.replace(cfg, updated_at=self._now(), **clean)
        self.store.put_idp(updated)
        self.audit.record(E_IDP_UPDATED, actor_user_id=actor.user_id, org_id=cfg.org_id,
                          target_type="idp", target_id=idp_id, outcome="ok",
                          correlation_id=correlation_id, idp_id=idp_id)
        return updated

    def delete_idp(self, actor: EffectiveAccess, idp_id: str, *,
                   correlation_id: Optional[str] = None) -> None:
        cfg = self.store.get_idp(idp_id)
        if cfg is None:
            raise NotFoundError("identity provider not found")
        self._require(actor, P_IDP_WRITE, org_id=cfg.org_id)
        if cfg.org_id is None:
            self._require(actor, P_PLATFORM_ADMIN)
        self.store.delete_idp(idp_id)
        self.audit.record(E_IDP_DELETED, actor_user_id=actor.user_id, org_id=cfg.org_id,
                          target_type="idp", target_id=idp_id, outcome="ok",
                          correlation_id=correlation_id, idp_id=idp_id)

    # ================================================================== reads (audited-free)
    def list_users(self, actor: EffectiveAccess, *, org_id: Optional[str] = None,
                   limit: int = 50, offset: int = 0) -> List[EnterpriseUser]:
        limit = max(1, min(int(limit), 200))
        offset = max(0, int(offset))
        if org_id is not None:
            self._require(actor, P_USER_READ, org_id=org_id)
            return self.store.list_users_in_org(org_id)[offset:offset + limit]
        self._require(actor, P_USER_READ)
        if not actor.is_platform_admin:
            raise ForbiddenError("only platform administrators may list users across tenants")
        return self.store.list_users_page(limit=limit, offset=offset)

    def list_audit(self, actor: EffectiveAccess, *, org_id: Optional[str] = None, limit: int = 100,
                   actor_user_id: Optional[str] = None, event: Optional[str] = None):
        self._require(actor, P_AUDIT_READ, org_id=org_id)
        limit = max(1, min(int(limit), 500))
        return self.store.list_audit(org_id=org_id, limit=limit, actor_user_id=actor_user_id,
                                     event=event)

    def list_idps(self, actor: EffectiveAccess, *, org_id: Optional[str] = None) -> List[IdpConfig]:
        self._require(actor, P_IDP_READ, org_id=org_id)
        return self.store.list_idp(org_id=org_id)

    def role_matrix(self, actor: EffectiveAccess):
        self._require(actor, P_RBAC_READ)
        from .rbac import permission_matrix
        return permission_matrix()

    # ================================================================== guards + lookups
    def _get_user(self, user_id: str) -> EnterpriseUser:
        u = self.store.get_user(user_id)
        if u is None:
            raise NotFoundError("user not found")
        return u

    def _require_manage_user(self, actor: EffectiveAccess, user_id: str, *, perm: str) -> None:
        """A platform admin manages anyone; otherwise the target must share the actor's tenant."""
        if actor.is_platform_admin:
            self._require(actor, perm)
            return
        target = self.store.get_user(user_id)
        if target is None:
            raise NotFoundError("user not found")
        if target.is_platform_admin:
            # a tenant admin can never act on a platform administrator
            self.audit.deny(actor_user_id=actor.user_id, org_id=actor.org_id, target_type="user",
                            target_id=user_id, reason="cannot_manage_platform_admin")
            raise ForbiddenError("not permitted to manage a platform administrator")
        if actor.org_id is None or self.store.get_membership(actor.org_id, user_id) is None:
            self.audit.deny(actor_user_id=actor.user_id, org_id=actor.org_id, target_type="user",
                            target_id=user_id, reason="target_outside_tenant")
            raise ForbiddenError("target user is outside your tenant")
        self._require(actor, perm, org_id=actor.org_id)

    def _ensure_not_last_platform_admin(self, target: EnterpriseUser, *, action: str) -> None:
        if not target.is_platform_admin:
            return
        if self.store.count_platform_admins() <= 1:
            raise ConflictError(f"refusing to {action}: it would remove the last platform administrator")


# --------------------------------------------------------------------- secure bootstrap
def bootstrap_platform_admin(store: EnterpriseStore, audit: AuditLog, *, email: str, password: str,
                             display_name: str = "Platform Administrator") -> EnterpriseUser:
    """One-time, explicit provisioning of the FIRST platform administrator.

    Rules (no hard-coded default password anywhere):
      * refuses if any platform administrator already exists;
      * refuses an empty/weak password (full password policy applies);
      * the password is read by the caller from ``AGENTGUARD_BOOTSTRAP_ADMIN_PASSWORD`` (or an
        interactive prompt); it is never stored in config, code, or logs;
      * emits a ``user.created`` audit event with ``actor_type=system``.
    """
    if store.count_platform_admins() > 0:
        raise ConflictError("a platform administrator already exists; bootstrap is one-time")
    email = (email or "").strip()
    if "@" not in email:
        raise ValidationError("a valid bootstrap admin email is required")
    err = password_policy_error(password)
    if err:
        raise ValidationError(f"bootstrap admin password rejected: {err}")
    import time
    now = time.time()
    user = EnterpriseUser(user_id=new_id("usr"), email=email,
                          display_name=display_name or "Platform Administrator",
                          status=UserStatus.ACTIVE, is_platform_admin=True,
                          global_roles=(ROLE_PLATFORM_ADMIN,), password_hash=hash_password(password),
                          password_changed_at=now, must_change_password=True, failed_login_count=0,
                          locked_until=None, last_login_at=None, created_at=now,
                          created_by="bootstrap", updated_at=now)
    store.put_user(user)
    audit.record(E_USER_CREATED, actor_user_id=None, actor_type="system", target_type="user",
                 target_id=user.user_id, outcome="ok", reason="bootstrap",
                 extra={"role": ROLE_PLATFORM_ADMIN})
    return user
