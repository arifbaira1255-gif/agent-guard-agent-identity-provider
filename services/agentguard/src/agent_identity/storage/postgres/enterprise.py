"""PostgreSQL implementation of ``EnterpriseStore`` (authoritative). All SQL is constant strings;
every value is a bound parameter. Tenant-scoped tables additionally run under RLS (migration 0004).
"""
from typing import List, Optional

from ...core.errors import StorageError
from ...security.models import (AuditEvent, EnterpriseUser, IdpConfig, IdpType, MembershipStatus,
                                RefreshTokenRecord, SessionRecord, TenantMembership, UserStatus)
from ...security.store import EnterpriseStore


def _u(r) -> EnterpriseUser:
    return EnterpriseUser(
        r["user_id"], r["email"], r["display_name"], UserStatus(r["status"]),
        bool(r["is_platform_admin"]), tuple(r["global_roles"] or ()), r["password_hash"],
        r["password_changed_at"], bool(r["must_change_password"]), int(r["failed_login_count"]),
        r["locked_until"], r["last_login_at"], r["created_at"], r["created_by"], r["updated_at"],
        bool(r["mfa_enrolled"]))


def _m(r) -> TenantMembership:
    return TenantMembership(r["org_id"], r["user_id"], tuple(r["roles"] or ()),
                            MembershipStatus(r["status"]), r["created_at"], r["created_by"],
                            r["updated_at"])


def _s(r) -> SessionRecord:
    return SessionRecord(
        r["session_id"], r["user_id"], r["org_id"], r["auth_method"], r["idp_id"],
        tuple(r["amr"] or ()), r["created_at"], r["last_seen_at"], r["absolute_expires_at"],
        r["idle_expires_at"], r["status"], r["revoked_at"], r["revoked_reason"], r["csrf_secret"],
        int(r["refresh_version"]), r["rotated_at"], r["user_agent"], r["ip"])


def _rt(r) -> RefreshTokenRecord:
    return RefreshTokenRecord(r["token_hash"], r["session_id"], r["user_id"], r["org_id"],
                              r["issued_at"], r["expires_at"], r["rotated_at"], r["status"],
                              r["parent_hash"], r["child_hash"])


def _idp(r) -> IdpConfig:
    return IdpConfig(
        r["idp_id"], r["org_id"], IdpType(r["idp_type"]), r["issuer"], r["client_id"],
        r["client_secret_ref"], tuple(r["scopes"] or ()), r["redirect_uri"], r["jwks_uri"],
        r["authorization_endpoint"], r["token_endpoint"],
        tuple(r["allowed_email_domains"] or ()), tuple(r["allowed_organizations"] or ()),
        bool(r["require_verified_email"]), bool(r["enabled"]), r["created_at"], r["created_by"],
        r["updated_at"])


def _a(r) -> AuditEvent:
    return AuditEvent(r["event_id"], r["ts"], r["event"], r["actor_user_id"], r["actor_type"],
                      r["org_id"], r["target_type"], r["target_id"], r["outcome"], r["reason"],
                      r["correlation_id"], r["ip"], r["user_agent"], r["idp_id"])


class PgEnterpriseStore(EnterpriseStore):
    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------ users
    def put_user(self, u: EnterpriseUser) -> None:
        self.db.run("s8_put_user", lambda c: c.execute(
            "INSERT INTO users (user_id, email, display_name, status, is_platform_admin, global_roles,"
            " password_hash, password_changed_at, must_change_password, failed_login_count,"
            " locked_until, last_login_at, mfa_enrolled, created_at, created_by, updated_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (user_id) DO UPDATE SET email=EXCLUDED.email,"
            " display_name=EXCLUDED.display_name, status=EXCLUDED.status,"
            " is_platform_admin=EXCLUDED.is_platform_admin, global_roles=EXCLUDED.global_roles,"
            " password_hash=EXCLUDED.password_hash, password_changed_at=EXCLUDED.password_changed_at,"
            " must_change_password=EXCLUDED.must_change_password,"
            " failed_login_count=EXCLUDED.failed_login_count, locked_until=EXCLUDED.locked_until,"
            " last_login_at=EXCLUDED.last_login_at, mfa_enrolled=EXCLUDED.mfa_enrolled,"
            " updated_at=EXCLUDED.updated_at",
            (u.user_id, u.email, u.display_name, u.status.value, u.is_platform_admin,
             list(u.global_roles), u.password_hash, u.password_changed_at, u.must_change_password,
             u.failed_login_count, u.locked_until, u.last_login_at, u.mfa_enrolled, u.created_at,
             u.created_by, u.updated_at)))

    def get_user(self, user_id: str) -> Optional[EnterpriseUser]:
        r = self.db.run("s8_get_user", lambda c: c.execute(
            "SELECT * FROM users WHERE user_id=%s", (user_id,)).fetchone())
        return _u(r) if r else None

    def get_user_by_email(self, email: str) -> Optional[EnterpriseUser]:
        r = self.db.run("s8_get_user_by_email", lambda c: c.execute(
            "SELECT * FROM users WHERE lower(email)=lower(%s)", (email,)).fetchone())
        return _u(r) if r else None

    def list_users_page(self, *, limit: int, offset: int) -> List[EnterpriseUser]:
        rows = self.db.run("s8_list_users", lambda c: c.execute(
            "SELECT * FROM users ORDER BY created_at, user_id LIMIT %s OFFSET %s",
            (limit, offset)).fetchall())
        return [_u(r) for r in rows]

    def list_users_in_org(self, org_id: str) -> List[EnterpriseUser]:
        rows = self.db.run("s8_users_in_org", lambda c: c.execute(
            "SELECT u.* FROM users u JOIN tenant_memberships m ON m.user_id=u.user_id"
            " WHERE m.org_id=%s ORDER BY u.user_id", (org_id,)).fetchall())
        return [_u(r) for r in rows]

    def count_platform_admins(self) -> int:
        return int(self.db.run("s8_count_padmins", lambda c: c.execute(
            "SELECT count(*) AS n FROM users WHERE is_platform_admin AND status='active'"
        ).fetchone()["n"]))

    # ------------------------------------------------------------------ memberships
    def put_membership(self, m: TenantMembership) -> None:
        self.db.run("s8_put_membership", lambda c: c.execute(
            "INSERT INTO tenant_memberships (org_id, user_id, roles, status, created_at, created_by,"
            " updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (org_id, user_id) DO UPDATE SET roles=EXCLUDED.roles,"
            " status=EXCLUDED.status, updated_at=EXCLUDED.updated_at",
            (m.org_id, m.user_id, list(m.roles), m.status.value, m.created_at, m.created_by,
             m.updated_at)))

    def get_membership(self, org_id: str, user_id: str) -> Optional[TenantMembership]:
        r = self.db.run("s8_get_membership", lambda c: c.execute(
            "SELECT * FROM tenant_memberships WHERE org_id=%s AND user_id=%s",
            (org_id, user_id)).fetchone())
        return _m(r) if r else None

    def list_memberships(self, *, user_id: Optional[str] = None,
                         org_id: Optional[str] = None) -> List[TenantMembership]:
        clauses, params = [], []
        if user_id is not None:
            clauses.append("user_id=%s"); params.append(user_id)
        if org_id is not None:
            clauses.append("org_id=%s"); params.append(org_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.db.run("s8_list_memberships", lambda c: c.execute(
            "SELECT * FROM tenant_memberships" + where + " ORDER BY org_id, user_id",
            tuple(params)).fetchall())
        return [_m(r) for r in rows]

    def delete_membership(self, org_id: str, user_id: str) -> None:
        self.db.run("s8_del_membership", lambda c: c.execute(
            "DELETE FROM tenant_memberships WHERE org_id=%s AND user_id=%s", (org_id, user_id)))

    def count_org_members(self, org_id: str) -> int:
        return int(self.db.run("s8_count_members", lambda c: c.execute(
            "SELECT count(*) AS n FROM tenant_memberships WHERE org_id=%s AND status='active'",
            (org_id,)).fetchone()["n"]))

    def count_org_admins(self, org_id: str) -> int:
        return int(self.db.run("s8_count_org_admins", lambda c: c.execute(
            "SELECT count(*) AS n FROM tenant_memberships WHERE org_id=%s AND status='active'"
            " AND 'tenant_administrator' = ANY(roles)", (org_id,)).fetchone()["n"]))

    # ------------------------------------------------------------------ sessions
    def put_session(self, s: SessionRecord) -> None:
        self.db.run("s8_put_session", lambda c: c.execute(
            "INSERT INTO sessions (session_id, user_id, org_id, auth_method, idp_id, amr, created_at,"
            " last_seen_at, absolute_expires_at, idle_expires_at, status, revoked_at, revoked_reason,"
            " csrf_secret, refresh_version, rotated_at, user_agent, ip)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (s.session_id, s.user_id, s.org_id, s.auth_method, s.idp_id, list(s.amr), s.created_at,
             s.last_seen_at, s.absolute_expires_at, s.idle_expires_at, s.status, s.revoked_at,
             s.revoked_reason, s.csrf_secret, s.refresh_version, s.rotated_at, s.user_agent, s.ip)))

    def get_session(self, session_id: str) -> Optional[SessionRecord]:
        r = self.db.run("s8_get_session", lambda c: c.execute(
            "SELECT * FROM sessions WHERE session_id=%s", (session_id,)).fetchone())
        return _s(r) if r else None

    def update_session(self, s: SessionRecord) -> None:
        self.db.run("s8_update_session", lambda c: c.execute(
            "UPDATE sessions SET last_seen_at=%s, idle_expires_at=%s, status=%s, revoked_at=%s,"
            " revoked_reason=%s, refresh_version=%s, rotated_at=%s WHERE session_id=%s",
            (s.last_seen_at, s.idle_expires_at, s.status, s.revoked_at, s.revoked_reason,
             s.refresh_version, s.rotated_at, s.session_id)))

    def list_sessions(self, *, user_id: str) -> List[SessionRecord]:
        rows = self.db.run("s8_list_sessions", lambda c: c.execute(
            "SELECT * FROM sessions WHERE user_id=%s ORDER BY created_at DESC", (user_id,)).fetchall())
        return [_s(r) for r in rows]

    def revoke_session(self, session_id: str, reason: str, now: float) -> Optional[SessionRecord]:
        cur = self.db.run("s8_revoke_session", lambda c: c.execute(
            "UPDATE sessions SET status='revoked', revoked_at=%s, revoked_reason=%s"
            " WHERE session_id=%s AND status='active'", (now, reason, session_id)))
        if cur.rowcount != 1:
            return None
        return self.get_session(session_id)

    def revoke_user_sessions(self, user_id: str, reason: str, now: float, *,
                             except_session_id: Optional[str] = None) -> int:
        def go(c):
            if except_session_id:
                return c.execute(
                    "UPDATE sessions SET status='revoked', revoked_at=%s, revoked_reason=%s"
                    " WHERE user_id=%s AND status='active' AND session_id<>%s",
                    (now, reason, user_id, except_session_id))
            return c.execute(
                "UPDATE sessions SET status='revoked', revoked_at=%s, revoked_reason=%s"
                " WHERE user_id=%s AND status='active'", (now, reason, user_id))
        return int(self.db.run("s8_revoke_user_sessions", go).rowcount)

    # ------------------------------------------------------------------ refresh tokens
    def put_refresh(self, r: RefreshTokenRecord) -> None:
        self.db.run("s8_put_refresh", lambda c: c.execute(
            "INSERT INTO refresh_tokens (token_hash, session_id, user_id, org_id, issued_at,"
            " expires_at, rotated_at, status, parent_hash, child_hash)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (r.token_hash, r.session_id, r.user_id, r.org_id, r.issued_at, r.expires_at,
             r.rotated_at, r.status, r.parent_hash, r.child_hash)))

    def get_refresh(self, token_hash: str) -> Optional[RefreshTokenRecord]:
        r = self.db.run("s8_get_refresh", lambda c: c.execute(
            "SELECT * FROM refresh_tokens WHERE token_hash=%s", (token_hash,)).fetchone())
        return _rt(r) if r else None

    def update_refresh(self, r: RefreshTokenRecord) -> None:
        self.db.run("s8_update_refresh", lambda c: c.execute(
            "UPDATE refresh_tokens SET rotated_at=%s, status=%s, child_hash=%s WHERE token_hash=%s",
            (r.rotated_at, r.status, r.child_hash, r.token_hash)))

    def revoke_session_refresh(self, session_id: str, now: float) -> int:
        return int(self.db.run("s8_revoke_refresh", lambda c: c.execute(
            "UPDATE refresh_tokens SET status='revoked' WHERE session_id=%s AND status='active'",
            (session_id,)).rowcount))

    # ------------------------------------------------------------------ identity providers
    def put_idp(self, i: IdpConfig) -> None:
        self.db.run("s8_put_idp", lambda c: c.execute(
            "INSERT INTO idp_configs (idp_id, org_id, idp_type, issuer, client_id, client_secret_ref,"
            " scopes, redirect_uri, jwks_uri, authorization_endpoint, token_endpoint,"
            " allowed_email_domains, allowed_organizations, require_verified_email, enabled,"
            " created_at, created_by, updated_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (idp_id) DO UPDATE SET issuer=EXCLUDED.issuer, client_id=EXCLUDED.client_id,"
            " client_secret_ref=EXCLUDED.client_secret_ref, scopes=EXCLUDED.scopes,"
            " redirect_uri=EXCLUDED.redirect_uri, jwks_uri=EXCLUDED.jwks_uri,"
            " authorization_endpoint=EXCLUDED.authorization_endpoint,"
            " token_endpoint=EXCLUDED.token_endpoint,"
            " allowed_email_domains=EXCLUDED.allowed_email_domains,"
            " allowed_organizations=EXCLUDED.allowed_organizations,"
            " require_verified_email=EXCLUDED.require_verified_email, enabled=EXCLUDED.enabled,"
            " updated_at=EXCLUDED.updated_at",
            (i.idp_id, i.org_id, i.idp_type.value, i.issuer, i.client_id, i.client_secret_ref,
             list(i.scopes), i.redirect_uri, i.jwks_uri, i.authorization_endpoint, i.token_endpoint,
             list(i.allowed_email_domains) if i.allowed_email_domains else None,
             list(i.allowed_organizations) if i.allowed_organizations else None,
             i.require_verified_email, i.enabled, i.created_at, i.created_by, i.updated_at)))

    def get_idp(self, idp_id: str) -> Optional[IdpConfig]:
        r = self.db.run("s8_get_idp", lambda c: c.execute(
            "SELECT * FROM idp_configs WHERE idp_id=%s", (idp_id,)).fetchone())
        return _idp(r) if r else None

    def list_idp(self, *, org_id: Optional[str] = None) -> List[IdpConfig]:
        if org_id is None:
            rows = self.db.run("s8_list_idp", lambda c: c.execute(
                "SELECT * FROM idp_configs ORDER BY idp_id").fetchall())
        else:
            rows = self.db.run("s8_list_idp_org", lambda c: c.execute(
                "SELECT * FROM idp_configs WHERE org_id=%s ORDER BY idp_id", (org_id,)).fetchall())
        return [_idp(r) for r in rows]

    def delete_idp(self, idp_id: str) -> None:
        self.db.run("s8_del_idp", lambda c: c.execute(
            "DELETE FROM idp_configs WHERE idp_id=%s", (idp_id,)))

    # ------------------------------------------------------------------ audit
    def append_audit(self, e: AuditEvent) -> None:
        self.db.run("s8_append_audit", lambda c: c.execute(
            "INSERT INTO audit_events (event_id, ts, event, actor_user_id, actor_type, org_id,"
            " target_type, target_id, outcome, reason, correlation_id, ip, user_agent, idp_id)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (e.event_id, e.ts, e.event, e.actor_user_id, e.actor_type, e.org_id, e.target_type,
             e.target_id, e.outcome, e.reason, e.correlation_id, e.ip, e.user_agent, e.idp_id)))

    def list_audit(self, *, org_id: Optional[str] = None, limit: int = 100,
                   before_ts: Optional[float] = None, actor_user_id: Optional[str] = None,
                   event: Optional[str] = None) -> List[AuditEvent]:
        clauses, params = [], []
        if org_id is not None:
            clauses.append("org_id=%s"); params.append(org_id)
        if before_ts is not None:
            clauses.append("ts < %s"); params.append(before_ts)
        if actor_user_id is not None:
            clauses.append("actor_user_id=%s"); params.append(actor_user_id)
        if event is not None:
            clauses.append("event=%s"); params.append(event)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(int(limit))
        rows = self.db.run("s8_list_audit", lambda c: c.execute(
            "SELECT * FROM audit_events" + where + " ORDER BY ts DESC, event_id DESC LIMIT %s",
            tuple(params)).fetchall())
        return [_a(r) for r in rows]


def create_enterprise_store(db) -> PgEnterpriseStore:
    if db is None:
        raise StorageError("a PostgreSQL database is required for the enterprise store")
    return PgEnterpriseStore(db)
