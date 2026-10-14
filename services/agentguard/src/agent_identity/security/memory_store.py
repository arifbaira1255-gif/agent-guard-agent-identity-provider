"""In-memory ``EnterpriseStore`` for unit tests and single-process development.

Semantics mirror the PostgreSQL backend closely enough for the security contract to hold:
  * case-insensitive unique email,
  * platform roles are rejected from memberships (the SQL CHECK constraint's equivalent),
  * audit events are append-only (no update/delete),
  * tenant filtering is explicit in *both* the query helpers and the callers.

It is NOT a production store: no durability, no cross-process sharing. Production uses PostgreSQL.
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional

from ..core.errors import ConflictError
from .models import (AuditEvent, EnterpriseUser, IdpConfig, MembershipStatus, RefreshTokenRecord,
                     SessionRecord, TenantMembership)
from .rbac import PLATFORM_ONLY_ROLES
from .store import EnterpriseStore


class MemoryEnterpriseStore(EnterpriseStore):
    def __init__(self):
        self._lock = threading.RLock()
        self._users: Dict[str, EnterpriseUser] = {}
        self._memberships: Dict[tuple, TenantMembership] = {}
        self._sessions: Dict[str, SessionRecord] = {}
        self._refresh: Dict[str, RefreshTokenRecord] = {}
        self._idps: Dict[str, IdpConfig] = {}
        self._audit: List[AuditEvent] = []

    # ------------------------------------------------------------------ users
    def put_user(self, u: EnterpriseUser) -> None:
        with self._lock:
            for other in self._users.values():
                if other.user_id != u.user_id and other.email.lower() == u.email.lower():
                    raise ConflictError("email already in use")
            self._users[u.user_id] = u

    def get_user(self, user_id: str) -> Optional[EnterpriseUser]:
        return self._users.get(user_id)

    def get_user_by_email(self, email: str) -> Optional[EnterpriseUser]:
        e = email.lower()
        for u in self._users.values():
            if u.email.lower() == e:
                return u
        return None

    def list_users_page(self, *, limit: int, offset: int) -> List[EnterpriseUser]:
        users = sorted(self._users.values(), key=lambda u: (u.created_at, u.user_id))
        return users[offset:offset + limit]

    def list_users_in_org(self, org_id: str) -> List[EnterpriseUser]:
        ids = {m.user_id for m in self._memberships.values() if m.org_id == org_id}
        return [self._users[i] for i in sorted(ids) if i in self._users]

    def count_platform_admins(self) -> int:
        return sum(1 for u in self._users.values() if u.is_platform_admin and u.status.value == "active")

    # ------------------------------------------------------------------ memberships
    def put_membership(self, m: TenantMembership) -> None:
        for r in m.roles:
            if r in PLATFORM_ONLY_ROLES:
                raise ConflictError("platform roles cannot be stored on a tenant membership")
        with self._lock:
            self._memberships[(m.org_id, m.user_id)] = m

    def get_membership(self, org_id: str, user_id: str) -> Optional[TenantMembership]:
        return self._memberships.get((org_id, user_id))

    def list_memberships(self, *, user_id=None, org_id=None) -> List[TenantMembership]:
        out = []
        for (o, u), m in self._memberships.items():
            if user_id is not None and u != user_id:
                continue
            if org_id is not None and o != org_id:
                continue
            out.append(m)
        return sorted(out, key=lambda m: (m.org_id, m.user_id))

    def delete_membership(self, org_id: str, user_id: str) -> None:
        with self._lock:
            self._memberships.pop((org_id, user_id), None)

    def count_org_members(self, org_id: str) -> int:
        return sum(1 for m in self._memberships.values()
                   if m.org_id == org_id and m.status == MembershipStatus.ACTIVE)

    def count_org_admins(self, org_id: str) -> int:
        return sum(1 for m in self._memberships.values()
                   if m.org_id == org_id and m.status == MembershipStatus.ACTIVE
                   and "tenant_administrator" in m.roles)

    # ------------------------------------------------------------------ sessions
    def put_session(self, s: SessionRecord) -> None:
        with self._lock:
            self._sessions[s.session_id] = s

    def get_session(self, session_id: str) -> Optional[SessionRecord]:
        return self._sessions.get(session_id)

    def update_session(self, s: SessionRecord) -> None:
        with self._lock:
            self._sessions[s.session_id] = s

    def list_sessions(self, *, user_id: str) -> List[SessionRecord]:
        return sorted([s for s in self._sessions.values() if s.user_id == user_id],
                      key=lambda s: s.created_at, reverse=True)

    def revoke_session(self, session_id: str, reason: str, now: float) -> Optional[SessionRecord]:
        with self._lock:
            s = self._sessions.get(session_id)
            if not s or s.status != "active":
                return None
            import dataclasses
            s2 = dataclasses.replace(s, status="revoked", revoked_at=now, revoked_reason=reason)
            self._sessions[session_id] = s2
            return s2

    def revoke_user_sessions(self, user_id: str, reason: str, now: float, *,
                             except_session_id: Optional[str] = None) -> int:
        import dataclasses
        n = 0
        with self._lock:
            for sid, s in list(self._sessions.items()):
                if s.user_id != user_id or s.status != "active":
                    continue
                if except_session_id and sid == except_session_id:
                    continue
                self._sessions[sid] = dataclasses.replace(
                    s, status="revoked", revoked_at=now, revoked_reason=reason)
                n += 1
        return n

    # ------------------------------------------------------------------ refresh tokens
    def put_refresh(self, r: RefreshTokenRecord) -> None:
        with self._lock:
            self._refresh[r.token_hash] = r

    def get_refresh(self, token_hash: str) -> Optional[RefreshTokenRecord]:
        return self._refresh.get(token_hash)

    def update_refresh(self, r: RefreshTokenRecord) -> None:
        with self._lock:
            self._refresh[r.token_hash] = r

    def revoke_session_refresh(self, session_id: str, now: float) -> int:
        import dataclasses
        n = 0
        with self._lock:
            for h, r in list(self._refresh.items()):
                if r.session_id == session_id and r.status == "active":
                    self._refresh[h] = dataclasses.replace(r, status="revoked")
                    n += 1
        return n

    # ------------------------------------------------------------------ identity providers
    def put_idp(self, c: IdpConfig) -> None:
        with self._lock:
            self._idps[c.idp_id] = c

    def get_idp(self, idp_id: str) -> Optional[IdpConfig]:
        return self._idps.get(idp_id)

    def list_idp(self, *, org_id=None) -> List[IdpConfig]:
        out = [c for c in self._idps.values() if org_id is None or c.org_id == org_id]
        return sorted(out, key=lambda c: c.idp_id)

    def delete_idp(self, idp_id: str) -> None:
        with self._lock:
            self._idps.pop(idp_id, None)

    # ------------------------------------------------------------------ audit
    def append_audit(self, e: AuditEvent) -> None:
        with self._lock:
            self._audit.append(e)                     # append-only; no mutation/delete API exists

    def list_audit(self, *, org_id=None, limit: int = 100, before_ts=None, actor_user_id=None,
                   event=None) -> List[AuditEvent]:
        items = self._audit
        if org_id is not None:
            items = [e for e in items if e.org_id == org_id]
        if before_ts is not None:
            items = [e for e in items if e.ts < before_ts]
        if actor_user_id is not None:
            items = [e for e in items if e.actor_user_id == actor_user_id]
        if event is not None:
            items = [e for e in items if e.event == event]
        return sorted(items, key=lambda e: (e.ts, e.event_id), reverse=True)[:limit]
