"""``EnterpriseAuthService`` — the single entry point for enterprise authentication and
authorization (Step 8).

Responsibilities
----------------
* **Local login** (email + password): rate-limited, account-lockout aware, constant-time password
  verification, uniform error messages (no user enumeration), full audit.
* **OIDC / SSO login**: state + PKCE + nonce bound single-use login transactions, strict id_token
  validation, secure callback handling, login-CSRF protection, token-substitution protection.
* **Session lifecycle**: short-lived access tokens, rotating refresh tokens, logout/revocation,
  replay + reuse detection (delegated to ``SessionManager``).
* **Authorization**: resolve the caller's *effective* access (global roles + tenant roles for the
  session's verified tenant) — PostgreSQL authoritative, Redis-cached — and enforce it through the
  single ``Authorizer`` decision point. Tenant scope always comes from the verified session.
* **Tenant switch**: an audited, membership-checked re-bind that issues fresh tokens for a tenant.

This service NEVER trusts client-supplied roles/permissions/tenant ids; they are always derived from
verified server-side state.
"""
from __future__ import annotations

import dataclasses
import time
from typing import List, Optional, Tuple

from ..core.errors import AuthenticationError, ForbiddenError, RateLimitedError, ValidationError
from .audit import (AuditLog, E_LOGIN_FAIL, E_LOGIN_LOCKED, E_LOGIN_OK, E_LOGIN_RATE_LIMITED,
                    E_LOGIN_STARTED, E_LOGOUT, E_OIDC_CALLBACK_FAILED, E_USER_PROVISIONED_JIT)
from .config import EnterpriseAuthConfig
from .ids import new_id
from .models import (AuthContext, EnterpriseUser, MembershipStatus, TenantMembership, UserStatus)
from .oidc import LoginTxnStore, OidcClient, OidcError, make_pkce_pair
from .passwords import hash_password, needs_rehash, password_policy_error, verify_password
from .permission_cache import PermissionCache
from .rbac import Authorizer, EffectiveAccess, PLATFORM_ONLY_ROLES, effective_access, sanitize_tenant_roles
from .redis_keys import SecurityKeys
from .session_manager import SessionManager, csrf_token_for
from .store import EnterpriseStore
from .tokens import TokenSigner, redact

_LOGIN_FAIL_MSG = "invalid credentials"          # uniform: never reveal whether the account exists


class EnterpriseAuthService:
    def __init__(self, store: EnterpriseStore, config: EnterpriseAuthConfig, *, backend=None,
                 signer: Optional[TokenSigner] = None, oidc: Optional[OidcClient] = None,
                 logger=None, clock=None):
        self.store = store
        self.config = config
        self._clock = clock
        self.backend = backend
        self.keys = SecurityKeys(config.environment)
        self.signer = signer or TokenSigner(config.session_secret, environment=config.environment)
        self.logger = logger
        self.audit = AuditLog(store, logger, clock=clock) if logger is not None else None
        self.sessions = SessionManager(store, self.signer, config, clock=clock, audit=self.audit)
        self.permission_cache = (PermissionCache(backend, self.keys, ttl_ms=config.permission_cache_ttl_ms,
                                                 enabled=config.permission_cache_enabled and backend is not None)
                                 if backend is not None else None)
        if oidc is not None:
            self.oidc = oidc
        elif backend is not None:
            self.oidc = OidcClient(clock=clock, metadata_cache=backend, jwks_cache=backend,
                                   environment=config.environment)
        else:
            self.oidc = OidcClient(clock=clock, environment=config.environment)
        self.login_txns = LoginTxnStore(backend, self.keys) if backend is not None else None

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ===================================================================== local authentication
    def login(self, email: str, password: str, *, org_id: Optional[str] = None, ip: Optional[str] = None,
              user_agent: Optional[str] = None, correlation_id: Optional[str] = None):
        now = self._now()
        email = (email or "").strip()
        if not email or not isinstance(password, str) or not password:
            self._audit(E_LOGIN_FAIL, outcome="denied", reason="missing_credentials",
                        correlation_id=correlation_id, ip=ip, user_agent=user_agent)
            raise AuthenticationError(_LOGIN_FAIL_MSG)

        self._rate_limit("login", self._ident(email, ip), ip=ip, user_agent=user_agent,
                         correlation_id=correlation_id)

        user = self.store.get_user_by_email(email)
        # constant-time-ish: always run a KDF to avoid a timing oracle for account existence
        stored = user.password_hash if (user and user.password_hash) else _DUMMY_HASH
        ok = verify_password(password, stored)
        if user is None or not user.password_hash or not ok:
            self._on_failed_login(user, ip=ip, user_agent=user_agent, correlation_id=correlation_id)
            raise AuthenticationError(_LOGIN_FAIL_MSG)

        if user.status == UserStatus.SUSPENDED:
            self._audit(E_LOGIN_FAIL, actor_user_id=user.user_id, outcome="denied",
                        reason="account_suspended", correlation_id=correlation_id, ip=ip,
                        user_agent=user_agent)
            raise AuthenticationError("account is suspended")
        if user.status == UserStatus.DISABLED:
            self._audit(E_LOGIN_FAIL, actor_user_id=user.user_id, outcome="denied",
                        reason="account_disabled", correlation_id=correlation_id, ip=ip,
                        user_agent=user_agent)
            raise AuthenticationError(_LOGIN_FAIL_MSG)
        if user.locked_until and now < user.locked_until:
            self._audit(E_LOGIN_LOCKED, actor_user_id=user.user_id, outcome="denied",
                        reason="locked", correlation_id=correlation_id, ip=ip, user_agent=user_agent)
            raise AuthenticationError("account temporarily locked")

        # success: reset counters, record last login, opportunistically upgrade the hash
        new_hash = user.password_hash
        if needs_rehash(user.password_hash):
            new_hash = hash_password(password)
        user = dataclasses.replace(user, failed_login_count=0, locked_until=None, last_login_at=now,
                                   password_hash=new_hash, updated_at=now)
        self.store.put_user(user)

        target_org = self._resolve_login_tenant(user, org_id, idp_org=None)
        session, access, refresh, csrf = self.sessions.create(
            user, org_id=target_org, auth_method="password", amr=("pwd",), ip=ip, user_agent=user_agent,
            correlation_id=correlation_id)
        self._audit(E_LOGIN_OK, actor_user_id=user.user_id, org_id=target_org, outcome="ok",
                    correlation_id=correlation_id, ip=ip, user_agent=user_agent,
                    extra={"session_id": session.session_id, "auth_method": "password"})
        return user, session, access, refresh, csrf

    def _on_failed_login(self, user: Optional[EnterpriseUser], *, ip, user_agent, correlation_id) -> None:
        now = self._now()
        reason = "bad_credentials"
        if user is not None:
            count = user.failed_login_count + 1
            locked_until = None
            if count >= self.config.max_failed_logins:
                locked_until = now + self.config.lockout_s
                reason = "bad_credentials_locked"
            self.store.put_user(dataclasses.replace(user, failed_login_count=count,
                                                    locked_until=locked_until, updated_at=now))
        self._audit(E_LOGIN_FAIL, actor_user_id=(user.user_id if user else None), outcome="denied",
                    reason=reason, correlation_id=correlation_id, ip=ip, user_agent=user_agent)

    # ===================================================================== OIDC / SSO
    def start_oidc_login(self, idp_id: str, *, return_to: Optional[str] = None, ip: Optional[str] = None,
                         user_agent: Optional[str] = None, correlation_id: Optional[str] = None):
        idp = self.store.get_idp(idp_id)
        if idp is None or not idp.enabled:
            raise ValidationError("unknown or disabled identity provider")
        verifier, challenge = make_pkce_pair()
        nonce = new_id("nonce")
        txn = self.login_txns.create(idp, code_verifier=verifier, nonce=nonce,
                                     redirect_uri=idp.redirect_uri, return_to=_safe_return_to(return_to),
                                     ip=ip, user_agent=user_agent, now=self._now(),
                                     ttl_s=self.config.login_txn_ttl_s)
        url = self.oidc.authorization_url(idp, state=txn.txn_id, nonce=nonce, code_challenge=challenge)
        self._audit(E_LOGIN_STARTED, org_id=idp.org_id, target_type="idp", target_id=idp.idp_id,
                    outcome="ok", correlation_id=correlation_id, ip=ip, user_agent=user_agent,
                    idp_id=idp.idp_id)
        return url, txn.txn_id

    def complete_oidc_login(self, idp_id: str, state: str, code: str, *, org_hint: Optional[str] = None,
                            ip: Optional[str] = None, user_agent: Optional[str] = None,
                            correlation_id: Optional[str] = None):
        txn = None
        try:
            idp = self.store.get_idp(idp_id)
            if idp is None or not idp.enabled:
                raise OidcError("unknown or disabled identity provider")
            # single-use, tenant-namespaced transaction (login-CSRF + code-substitution protection)
            org_scope = org_hint if org_hint is not None else idp.org_id
            txn = self.login_txns.consume_for(org_scope, state, now=self._now())
            if txn.idp_id != idp_id:
                raise OidcError("login state does not belong to this provider")
            tokens = self.oidc.exchange_code(idp, code=code, code_verifier=txn.code_verifier)
            claims = self.oidc.verify(idp, tokens["id_token"], nonce=txn.nonce)
            user, org_id, provisioned = self._map_oidc_user(claims, idp, ip=ip, user_agent=user_agent,
                                                            correlation_id=correlation_id)
        except (OidcError, AuthenticationError, ValidationError) as exc:
            self._audit(E_OIDC_CALLBACK_FAILED, org_id=(org_hint or (idp.org_id if 'idp' in dir() else None)),
                        target_type="idp", target_id=idp_id, outcome="denied", reason=str(exc),
                        correlation_id=correlation_id, ip=ip, user_agent=user_agent, idp_id=idp_id)
            raise AuthenticationError("single sign-on failed")
        session, access, refresh, csrf = self.sessions.create(
            user, org_id=org_id, auth_method="oidc", idp_id=idp.idp_id, amr=("oidc",), ip=ip,
            user_agent=user_agent, correlation_id=correlation_id)
        self._audit(E_LOGIN_OK, actor_user_id=user.user_id, org_id=org_id, outcome="ok",
                    correlation_id=correlation_id, ip=ip, user_agent=user_agent, idp_id=idp_id,
                    extra={"session_id": session.session_id, "auth_method": "oidc",
                           "provisioned": provisioned})
        return user, session, access, refresh, csrf, (txn.return_to if txn else None)

    def _map_oidc_user(self, claims: dict, idp, *, ip, user_agent, correlation_id):
        email = claims["_email"]
        user = self.store.get_user_by_email(email)
        provisioned = False
        if user is None:
            if not self.config.allow_jit_provisioning:
                raise AuthenticationError("no local account for this identity (provisioning required)")
            now = self._now()
            user = EnterpriseUser(
                user_id=new_id("usr"), email=email, display_name=(claims.get("name") or email)[:200],
                status=UserStatus.ACTIVE, is_platform_admin=False, global_roles=(), password_hash=None,
                password_changed_at=None, must_change_password=False, failed_login_count=0,
                locked_until=None, last_login_at=now, created_at=now, created_by=f"oidc:{idp.idp_id}",
                updated_at=now)
            self.store.put_user(user)
            provisioned = True
            self._audit(E_USER_PROVISIONED_JIT, actor_user_id=user.user_id, org_id=idp.org_id,
                        target_type="user", target_id=user.user_id, outcome="ok",
                        correlation_id=correlation_id, ip=ip, user_agent=user_agent, idp_id=idp.idp_id)
        if user.status != UserStatus.ACTIVE:
            raise AuthenticationError("account is not active")
        user = dataclasses.replace(user, last_login_at=self._now(), updated_at=self._now())
        self.store.put_user(user)
        org_id = self._resolve_login_tenant(user, None, idp_org=idp.org_id, jit=provisioned)
        return user, org_id, provisioned

    # ===================================================================== tenant resolution
    def _resolve_login_tenant(self, user: EnterpriseUser, requested_org: Optional[str],
                              *, idp_org: Optional[str], jit: bool = False) -> Optional[str]:
        memberships = self.store.list_memberships(user_id=user.user_id)
        active = [m for m in memberships if m.status == MembershipStatus.ACTIVE]

        if idp_org is not None:
            if jit and not any(m.org_id == idp_org for m in active):
                # create a membership with NO roles: identity provisioning is not authorization
                now = self._now()
                self.store.put_membership(TenantMembership(idp_org, user.user_id, (), 
                                                           MembershipStatus.ACTIVE, now, "system", now))
                return idp_org
            if any(m.org_id == idp_org for m in active):
                return idp_org
            raise AuthenticationError("no active membership for this tenant")

        if requested_org is not None:
            if not any(m.org_id == requested_org for m in active):
                raise AuthenticationError("no active membership for this tenant")
            return requested_org

        if len(active) == 1:
            return active[0].org_id
        if not active:
            if user.is_platform_admin:
                return None                      # platform-only session (no tenant scope)
            raise AuthenticationError("account has no active tenant membership")
        # multiple tenants: require an explicit selection (prevent silent cross-tenant context)
        raise AuthenticationError("multiple tenants available; specify org_id")

    def switch_tenant(self, access_token: str, org_id: str, *, ip=None, user_agent=None,
                      correlation_id: Optional[str] = None):
        """Re-bind the caller to another tenant they are a member of, issuing fresh tokens."""
        if not self.config.allow_self_service_tenant_switch:
            raise ForbiddenError("tenant switching is disabled")
        session, user = self.sessions.resolve(access_token)
        m = self.store.get_membership(org_id, user.user_id)
        if m is None or m.status != MembershipStatus.ACTIVE:
            self._audit_deny(user.user_id, org_id=session.org_id, target_type="tenant",
                             target_id=org_id, reason="no_membership", correlation_id=correlation_id)
            raise ForbiddenError("not a member of this tenant")
        self.sessions.revoke(session.session_id, "tenant_switch", actor_user_id=user.user_id,
                             org_id=session.org_id, ip=ip, user_agent=user_agent,
                             correlation_id=correlation_id)
        new_session, access, refresh, csrf = self.sessions.create(
            user, org_id=org_id, auth_method=session.auth_method, idp_id=session.idp_id,
            amr=session.amr, ip=ip, user_agent=user_agent, correlation_id=correlation_id)
        return user, new_session, access, refresh, csrf

    # ===================================================================== logout / refresh
    def refresh(self, refresh_token: str, *, ip=None, user_agent=None, correlation_id=None):
        return self.sessions.rotate_refresh(refresh_token, ip=ip, user_agent=user_agent,
                                            correlation_id=correlation_id)

    def logout(self, access_token: str, *, ip=None, user_agent=None, correlation_id=None) -> bool:
        try:
            session, user = self.sessions.resolve(access_token)
        except AuthenticationError:
            return False
        ok = self.sessions.revoke(session.session_id, "logout", actor_user_id=user.user_id,
                                  org_id=session.org_id, ip=ip, user_agent=user_agent,
                                  correlation_id=correlation_id)
        if ok:
            self._audit(E_LOGOUT, actor_user_id=user.user_id, org_id=session.org_id, outcome="ok",
                        correlation_id=correlation_id, ip=ip, user_agent=user_agent,
                        extra={"session_id": session.session_id})
        return ok

    # ===================================================================== authorization
    def access_for(self, user: EnterpriseUser, org_id: Optional[str]) -> EffectiveAccess:
        """Effective permission set = global roles + tenant roles for THIS tenant (active only)."""
        def loader() -> EffectiveAccess:
            tenant_roles = ()
            if org_id is not None:
                m = self.store.get_membership(org_id, user.user_id)
                if m is not None and m.status == MembershipStatus.ACTIVE:
                    tenant_roles = m.roles
            return effective_access(user.user_id, org_id, global_roles=user.global_roles,
                                    tenant_roles=tenant_roles)
        if self.permission_cache is not None:
            return self.permission_cache.get_or_load(org_id, user.user_id, loader)
        return loader()

    def authorize(self, access_token: str, *, permission: Optional[str] = None,
                  org_id: Optional[str] = None, agent_owner: Optional[str] = None,
                  ip=None, user_agent=None, correlation_id=None) -> AuthContext:
        """Resolve + authorize. Returns a verified ``AuthContext`` or raises (audited)."""
        session, user = self.sessions.resolve(access_token)
        eff_org = session.org_id
        access = self.access_for(user, eff_org)
        try:
            if permission is not None:
                if agent_owner is not None and eff_org is not None:
                    Authorizer.require_agent_manage(access, agent_owner=agent_owner,
                                                    agent_org=eff_org, perm=permission)
                else:
                    Authorizer.require(access, permission, org_id=(org_id or None))
        except ForbiddenError:
            self._audit_deny(user.user_id, org_id=eff_org, target_type="permission",
                             target_id=permission, reason="permission_denied",
                             correlation_id=correlation_id, ip=ip, user_agent=user_agent)
            raise
        return AuthContext(user_id=user.user_id, email=user.email, org_id=eff_org, roles=access.roles,
                           permissions=access.permissions, is_platform_admin=access.is_platform_admin,
                           session_id=session.session_id, amr=session.amr, correlation_id=correlation_id)

    def resolve_context(self, access_token: str) -> AuthContext:
        return self.authorize(access_token, permission=None)

    def check_csrf(self, access_token: str, provided_token: Optional[str]) -> bool:
        """Verify the double-submit CSRF token against the server-side session binding."""
        try:
            session, _ = self.sessions.resolve(access_token)
        except AuthenticationError:
            return False
        if not provided_token:
            return False
        import hmac as _h
        return _h.compare_digest(provided_token, csrf_token_for(session.session_id, session.csrf_secret))

    def csrf_token(self, access_token: str) -> Optional[str]:
        try:
            session, _ = self.sessions.resolve(access_token)
        except AuthenticationError:
            return None
        return csrf_token_for(session.session_id, session.csrf_secret)

    # ===================================================================== helpers
    def _rate_limit(self, scope: str, ident: str, *, ip, user_agent, correlation_id) -> None:
        if self.backend is None:
            return
        allowed, _remaining, retry_after = self.backend.token_bucket(
            self.keys.rate(None, scope, ident),
            rate_per_sec=self.config.login_rate_per_min / 60.0, burst=self.config.login_burst)
        if not allowed:
            self._audit(E_LOGIN_RATE_LIMITED, outcome="denied", reason="rate_limited",
                        correlation_id=correlation_id, ip=ip, user_agent=user_agent)
            raise RateLimitedError(f"too many attempts; retry in {int(retry_after/1000)}s")

    @staticmethod
    def _ident(email: str, ip: Optional[str]) -> str:
        return f"{email.lower()}|{ip or 'unknown'}"

    def _audit(self, event: str, **kwargs) -> None:
        if self.audit is not None:
            kwargs.setdefault("actor_type", "user")
            self.audit.record(event, **kwargs)

    def _audit_deny(self, user_id: Optional[str], *, org_id, target_type, target_id, reason,
                    correlation_id, ip=None, user_agent=None) -> None:
        if self.audit is not None:
            self.audit.deny(actor_user_id=user_id, org_id=org_id, target_type=target_type,
                            target_id=target_id, reason=reason, correlation_id=correlation_id,
                            ip=ip, user_agent=user_agent)


# A fixed dummy hash so a login for an unknown account still performs a KDF (timing-oracle defence).
_DUMMY_HASH = hash_password("dummy-password-for-timing-000", n=2 ** 12)


def _safe_return_to(return_to: Optional[str]) -> Optional[str]:
    """Only allow same-site absolute PATHS (never a full URL) as a post-login return target."""
    if not return_to or not isinstance(return_to, str):
        return None
    if len(return_to) > 512:
        return None
    if "://" in return_to or return_to.startswith("//") or "\\" in return_to:
        return None
    if not return_to.startswith("/"):
        return None
    return return_to


def membership_roles_or_empty(store: EnterpriseStore, org_id: str, user_id: str) -> Tuple[str, ...]:
    m = store.get_membership(org_id, user_id)
    if m is None or m.status != MembershipStatus.ACTIVE:
        return ()
    return tuple(m.roles)


def validate_new_password(password: str) -> None:
    err = password_policy_error(password)
    if err:
        raise ValidationError(err)
