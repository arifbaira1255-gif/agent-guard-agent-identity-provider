"""Session and refresh-token lifecycle for Step 8.

Guarantees implemented here
---------------------------
* **Short-lived access tokens** (HMAC-signed, see ``tokens.TokenSigner``) that are additionally
  bound to a server-side session; :meth:`SessionManager.resolve` re-checks the session on every API
  call, so a logout / revocation / suspension takes effect immediately (not at token expiry).
* **Rotating refresh tokens**: every refresh consumes the presented token and issues a new one. A
  *reused* (already-rotated) token is treated as theft — the entire session family is revoked and
  an audit event is emitted. Replay is therefore detectable and contained.
* **Absolute + idle expiry**: sessions end at ``absolute_expires_at`` regardless of activity and
  after ``session_idle_ttl_s`` of inactivity.
* **CSRF binding**: a per-session secret never leaves the server; the value handed to the client is
  ``HMAC(csrf_secret, session_id)`` and is verified on every state-changing request (double-submit
  cookie + header, compared against the server-side session).
* **No secrets at rest**: only the SHA-256 digest of each refresh token is stored.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import time
from typing import Optional, Tuple

from ..core.errors import AuthenticationError
from .audit import (AuditLog, E_SESSION_CREATED, E_SESSION_EXPIRED, E_SESSION_REFRESHED,
                    E_SESSION_REVOKED, E_SESSION_REUSE)
from .config import EnterpriseAuthConfig
from .ids import new_id
from .models import (EnterpriseUser, RefreshTokenRecord, SessionRecord, UserStatus)
from .store import EnterpriseStore
from .tokens import AccessClaims, TokenSigner, digest, random_token


def csrf_token_for(session_id: str, csrf_secret: str) -> str:
    """Deterministic, session-bound CSRF token = HMAC-SHA256(csrf_secret, session_id)."""
    return hmac.new(csrf_secret.encode("utf-8"), session_id.encode("utf-8"),
                    hashlib.sha256).hexdigest()


class SessionManager:
    def __init__(self, store: EnterpriseStore, signer: TokenSigner, config: EnterpriseAuthConfig,
                 clock=None, audit: Optional[AuditLog] = None):
        self.store = store
        self.signer = signer
        self.config = config
        self._clock = clock
        self.audit = audit

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ create
    def create(self, user: EnterpriseUser, *, org_id: Optional[str], auth_method: str,
               idp_id: Optional[str] = None, amr: tuple = (), ip: Optional[str] = None,
               user_agent: Optional[str] = None, correlation_id: Optional[str] = None
               ) -> Tuple[SessionRecord, str, str, str]:
        now = self._now()
        session = SessionRecord(
            session_id=new_id("sess"), user_id=user.user_id, org_id=org_id,
            auth_method=auth_method, idp_id=idp_id, amr=tuple(amr), created_at=now,
            last_seen_at=now, absolute_expires_at=now + self.config.session_absolute_ttl_s,
            idle_expires_at=now + self.config.session_idle_ttl_s, status="active",
            csrf_secret=random_token(32), refresh_version=0, user_agent=user_agent, ip=ip)
        self.store.put_session(session)
        access, refresh, csrf = self._issue(session, user, now)
        if self.audit:
            self.audit.record(E_SESSION_CREATED, actor_user_id=user.user_id, org_id=org_id,
                              target_type="session", target_id=session.session_id, outcome="ok",
                              correlation_id=correlation_id, ip=ip, user_agent=user_agent,
                              idp_id=idp_id, extra={"auth_method": auth_method})
        return session, access, refresh, csrf

    def _issue(self, session: SessionRecord, user: EnterpriseUser, now: float) -> Tuple[str, str, str]:
        access = self.signer.issue(
            user_id=user.user_id, session_id=session.session_id, org_id=session.org_id,
            roles=self._claim_roles(user), is_platform_admin=user.is_platform_admin,
            ttl_seconds=self.config.access_ttl_s, now=now, amr=session.amr)
        raw_refresh = random_token(32)
        rec = RefreshTokenRecord(digest(raw_refresh), session.session_id, user.user_id,
                                 session.org_id, now, now + self.config.refresh_ttl_s, None, "active")
        self.store.put_refresh(rec)
        return access, raw_refresh, csrf_token_for(session.session_id, session.csrf_secret)

    @staticmethod
    def _claim_roles(user: EnterpriseUser) -> tuple:
        # The access token carries the GLOBAL roles only; tenant roles are resolved server-side from
        # the authoritative store on every request (so a token can't smuggle tenant authority).
        return tuple(user.global_roles)

    # ------------------------------------------------------------------ verify
    def verify_access(self, access_token: str) -> AccessClaims:
        claims = self.signer.verify(access_token, now=self._now())
        return AccessClaims.from_claims(claims)

    def resolve(self, access_token: str) -> Tuple[SessionRecord, EnterpriseUser]:
        """Verify the token AND re-check the live session + user. Raises on any failure."""
        claims = self.verify_access(access_token)
        session = self.store.get_session(claims.session_id)
        if session is None:
            raise AuthenticationError("session not found")
        if session.user_id != claims.user_id:
            raise AuthenticationError("session/user mismatch")     # token substitution guard
        now = self._now()
        if session.status != "active":
            raise AuthenticationError("session revoked")
        if now >= session.absolute_expires_at:
            self.store.revoke_session(session.session_id, "absolute_expiry", now)
            if self.audit:
                self.audit.record(E_SESSION_EXPIRED, actor_user_id=session.user_id,
                                  org_id=session.org_id, target_type="session",
                                  target_id=session.session_id, outcome="denied",
                                  reason="absolute_expiry")
            raise AuthenticationError("session expired")
        if now >= session.idle_expires_at:
            self.store.revoke_session(session.session_id, "idle_timeout", now)
            raise AuthenticationError("session idle timeout")
        user = self.store.get_user(session.user_id)
        if user is None or user.status != UserStatus.ACTIVE:
            self.store.revoke_session(session.session_id, "user_not_active", now)
            raise AuthenticationError("user not active")
        # sliding idle window (bounded by the absolute expiry)
        session = dataclasses.replace(
            session, last_seen_at=now,
            idle_expires_at=min(now + self.config.session_idle_ttl_s, session.absolute_expires_at))
        self.store.update_session(session)
        return session, user

    # ------------------------------------------------------------------ refresh (rotation + replay detection)
    def rotate_refresh(self, refresh_token: str, *, ip: Optional[str] = None,
                       user_agent: Optional[str] = None,
                       correlation_id: Optional[str] = None
                       ) -> Tuple[SessionRecord, EnterpriseUser, str, str, str]:
        if not refresh_token or not isinstance(refresh_token, str):
            raise AuthenticationError("missing refresh token")
        h = digest(refresh_token)
        rec = self.store.get_refresh(h)
        now = self._now()
        if rec is None:
            raise AuthenticationError("invalid refresh token")
        if rec.status == "revoked":
            raise AuthenticationError("refresh token revoked")
        if now >= rec.expires_at:
            self.store.update_refresh(dataclasses.replace(rec, status="revoked"))
            raise AuthenticationError("refresh token expired")
        if rec.status == "rotated":
            # Reuse of an already-rotated token => treat the whole family as compromised.
            self._compromise(rec.session_id, ip=ip, user_agent=user_agent,
                             correlation_id=correlation_id)
            raise AuthenticationError("refresh token replay detected")
        session = self.store.get_session(rec.session_id)
        if session is None or session.status != "active" or now >= session.absolute_expires_at:
            self.store.update_refresh(dataclasses.replace(rec, status="revoked"))
            raise AuthenticationError("session not active")
        user = self.store.get_user(session.user_id)
        if user is None or user.status != UserStatus.ACTIVE:
            self.store.update_refresh(dataclasses.replace(rec, status="revoked"))
            self.store.revoke_session(session.session_id, "user_not_active", now)
            raise AuthenticationError("user not active")
        # rotate: mark old rotated + insert child (new raw token)
        raw_new = random_token(32)
        child_hash = digest(raw_new)
        self.store.update_refresh(dataclasses.replace(rec, status="rotated", rotated_at=now,
                                                      child_hash=child_hash))
        self.store.put_refresh(RefreshTokenRecord(child_hash, session.session_id, session.user_id,
                                                  session.org_id, now,
                                                  now + self.config.refresh_ttl_s, None, "active",
                                                  parent_hash=h))
        session = dataclasses.replace(session, last_seen_at=now, refresh_version=session.refresh_version + 1,
                                      rotated_at=now,
                                      idle_expires_at=min(now + self.config.session_idle_ttl_s,
                                                          session.absolute_expires_at))
        self.store.update_session(session)
        access = self.signer.issue(
            user_id=user.user_id, session_id=session.session_id, org_id=session.org_id,
            roles=self._claim_roles(user), is_platform_admin=user.is_platform_admin,
            ttl_seconds=self.config.access_ttl_s, now=now, amr=session.amr)
        csrf = csrf_token_for(session.session_id, session.csrf_secret)
        if self.audit:
            self.audit.record(E_SESSION_REFRESHED, actor_user_id=user.user_id, org_id=session.org_id,
                              target_type="session", target_id=session.session_id, outcome="ok",
                              correlation_id=correlation_id, ip=ip, user_agent=user_agent)
        return session, user, access, raw_new, csrf

    def _compromise(self, session_id: str, *, ip=None, user_agent=None, correlation_id=None) -> None:
        now = self._now()
        self.store.revoke_session(session_id, "refresh_replay", now)
        self.store.revoke_session_refresh(session_id, now)
        s = self.store.get_session(session_id)
        if self.audit:
            self.audit.record(E_SESSION_REUSE, actor_user_id=(s.user_id if s else None),
                              org_id=(s.org_id if s else None), target_type="session",
                              target_id=session_id, outcome="denied", reason="refresh_replay",
                              correlation_id=correlation_id, ip=ip, user_agent=user_agent)

    # ------------------------------------------------------------------ logout / revocation
    def revoke(self, session_id: str, reason: str, *, actor_user_id: Optional[str] = None,
               org_id: Optional[str] = None, ip=None, user_agent=None,
               correlation_id: Optional[str] = None) -> bool:
        now = self._now()
        rec = self.store.revoke_session(session_id, reason, now)
        self.store.revoke_session_refresh(session_id, now)
        if rec is None:
            return False
        if self.audit:
            self.audit.record(E_SESSION_REVOKED, actor_user_id=actor_user_id or rec.user_id,
                              org_id=org_id if org_id is not None else rec.org_id,
                              target_type="session", target_id=session_id, outcome="ok",
                              reason=reason, correlation_id=correlation_id, ip=ip,
                              user_agent=user_agent)
        return True

    def revoke_user(self, user_id: str, reason: str, *, except_session_id: Optional[str] = None,
                    actor_user_id: Optional[str] = None, org_id: Optional[str] = None,
                    correlation_id: Optional[str] = None) -> int:
        now = self._now()
        n = self.store.revoke_user_sessions(user_id, reason, now, except_session_id=except_session_id)
        for s in self.store.list_sessions(user_id=user_id):
            if s.status == "revoked":
                self.store.revoke_session_refresh(s.session_id, now)
        if n and self.audit:
            self.audit.record(E_SESSION_REVOKED, actor_user_id=actor_user_id or user_id,
                              org_id=org_id, target_type="user", target_id=user_id, outcome="ok",
                              reason=reason, correlation_id=correlation_id,
                              extra={"session_id": f"bulk:{n}"})
        return n
