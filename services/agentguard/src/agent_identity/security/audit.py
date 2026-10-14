"""Durable security audit log for Step 8 (enterprise authentication / RBAC / multi-tenancy).

One ``record`` call fans out to two sinks so a single code path satisfies both requirements:
  * the PostgreSQL ``audit_events`` table — append-only, survives restarts, queryable per
    tenant / actor / event / outcome (see migration 0004), and
  * the EXISTING :class:`SecurityLogger` structured stream — allow-listed and secret-redacted, so
    Step 8 events travel through the same correlation architecture as Steps 1-7.

Nothing secret is ever recorded: only ids, roles/permissions, decisions, reason codes, timestamps
and correlation ids. The correlation id is taken from the caller or from the ambient context
(``observability.logging.current_correlation_id``).
"""
from __future__ import annotations

import time
from typing import Optional

from ..observability.logging import SecurityLogger, current_correlation_id
from .ids import new_id
from .models import AuditEvent
from .store import EnterpriseStore

# --- event names (stable, greppable) -----------------------------------------------------------
E_LOGIN_OK = "auth.login.succeeded"
E_LOGIN_FAIL = "auth.login.failed"
E_LOGIN_LOCKED = "auth.login.locked"
E_LOGIN_RATE_LIMITED = "auth.login.rate_limited"
E_LOGIN_STARTED = "auth.login.started"
E_LOGOUT = "auth.logout"

E_SESSION_CREATED = "session.created"
E_SESSION_REFRESHED = "session.refreshed"
E_SESSION_REVOKED = "session.revoked"
E_SESSION_REUSE = "session.refresh_reuse_detected"
E_SESSION_EXPIRED = "session.expired"

E_AUTHZ_DENIED = "authz.denied"

E_ROLE_GRANTED = "rbac.role.granted"
E_ROLE_REVOKED = "rbac.role.revoked"

E_MEMBERSHIP_ADDED = "tenant.membership.added"
E_MEMBERSHIP_REMOVED = "tenant.membership.removed"
E_MEMBERSHIP_SUSPENDED = "tenant.membership.suspended"
E_MEMBERSHIP_REACTIVATED = "tenant.membership.reactivated"

E_USER_CREATED = "user.created"
E_USER_SUSPENDED = "user.suspended"
E_USER_REACTIVATED = "user.reactivated"
E_USER_DISABLED = "user.disabled"
E_USER_PASSWORD_CHANGED = "user.password.changed"
E_USER_PROVISIONED_JIT = "user.provisioned.jit"
E_USER_EMAIL_UPDATED = "user.email.updated"

E_ADMIN_SESSIONS_REVOKED = "admin.sessions.revoked"

E_IDP_CREATED = "idp.config.created"
E_IDP_UPDATED = "idp.config.updated"
E_IDP_DELETED = "idp.config.deleted"

E_OIDC_CALLBACK_FAILED = "oidc.callback.failed"


class AuditLog:
    """Thin, dependency-light recorder. Tenant context is an explicit argument, never inferred."""

    def __init__(self, store: EnterpriseStore, logger: SecurityLogger, clock=None):
        self.store = store
        self.logger = logger
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def record(self, event: str, *, actor_user_id: Optional[str] = None, actor_type: str = "user",
               org_id: Optional[str] = None, target_type: Optional[str] = None,
               target_id: Optional[str] = None, outcome: str = "ok", reason: Optional[str] = None,
               correlation_id: Optional[str] = None, ip: Optional[str] = None,
               user_agent: Optional[str] = None, idp_id: Optional[str] = None,
               extra: Optional[dict] = None) -> AuditEvent:
        cid = correlation_id or current_correlation_id()
        ev = AuditEvent(
            event_id=new_id("aud"), ts=self._now(), event=event, actor_user_id=actor_user_id,
            actor_type=actor_type, org_id=org_id, target_type=target_type, target_id=target_id,
            outcome=outcome, reason=reason, correlation_id=cid, ip=ip, user_agent=user_agent,
            idp_id=idp_id)
        # durable sink (authoritative)
        self.store.append_audit(ev)
        # structured sink (correlation + redaction); only allow-listed, non-secret fields survive
        fields = {"event_id": ev.event_id, "outcome": outcome, "reason": reason, "actor": actor_user_id,
                  "org_id": org_id, "target_type": target_type, "target_id": target_id,
                  "correlation_id": cid, "idp_id": idp_id, "ip": ip, "user_agent": user_agent}
        if extra:
            for k, v in extra.items():
                fields.setdefault(k, v)
        self.logger.emit(event, **fields)
        return ev

    # convenience wrappers keep call sites short and events consistent ------------------------
    def deny(self, *, actor_user_id=None, org_id=None, target_type=None, target_id=None,
             reason=None, permission=None, correlation_id=None, ip=None, user_agent=None) -> AuditEvent:
        return self.record(E_AUTHZ_DENIED, actor_user_id=actor_user_id, org_id=org_id,
                           target_type=target_type, target_id=target_id, outcome="denied",
                           reason=reason, correlation_id=correlation_id, ip=ip, user_agent=user_agent,
                           extra={"permission": permission} if permission else None)
