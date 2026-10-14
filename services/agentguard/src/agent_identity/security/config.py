"""Step 8 configuration (enterprise authentication, RBAC, multi-tenancy).

Fail-closed defaults: secure cookies, short-lived access tokens, mandatory session secret outside
development. Secrets are read from the ENVIRONMENT only (never from code, never logged):
  * ``AGENTGUARD_SESSION_SECRET``   — >= 32 bytes, signs access tokens.
  * ``AGENTGUARD_BOOTSTRAP_ADMIN_EMAIL`` / ``AGENTGUARD_BOOTSTRAP_ADMIN_PASSWORD`` — one-time,
    explicit initial platform-administrator provisioning (no hard-coded default password).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Optional

from ..core.errors import ValidationError


@dataclass(frozen=True)
class EnterpriseAuthConfig:
    environment: str = "development"
    session_secret: Optional[bytes] = None

    # token / session lifetimes
    access_ttl_s: int = 900                    # 15 minutes
    refresh_ttl_s: int = 30 * 86400            # 30 days (rotation means each hop is short-lived)
    session_idle_ttl_s: int = 1800             # 30 minutes of inactivity ends the browser session
    session_absolute_ttl_s: int = 12 * 3600    # hard ceiling regardless of activity
    login_txn_ttl_s: int = 600                 # OIDC authorization-code flow window (10 min)
    clock_skew_s: int = 60

    # cookie / CSRF
    cookie_name: str = "ag_session"
    cookie_secure: bool = True
    cookie_httponly: bool = True
    cookie_samesite: str = "Lax"               # "Lax" allows top-level OIDC redirects back
    cookie_path: str = "/"
    cookie_domain: Optional[str] = None
    csrf_header: str = "X-CSRF-Token"
    csrf_cookie_name: str = "ag_csrf"

    # local-auth hardening
    max_failed_logins: int = 5
    lockout_s: int = 900
    login_rate_per_min: int = 10
    login_burst: int = 5

    # provisioning / SSO
    allow_jit_provisioning: bool = False       # OIDC just-in-time user creation is OFF by default
    allow_self_service_tenant_switch: bool = True

    # permission cache
    permission_cache_enabled: bool = True
    permission_cache_ttl_ms: int = 30_000

    # one-time bootstrap (values come from the environment; never persisted in this object)
    bootstrap_admin_email: Optional[str] = None
    bootstrap_admin_password: Optional[str] = field(default=None, repr=False)

    def __post_init__(self):
        if self.environment not in ("development", "staging", "production"):
            raise ValidationError("environment must be development|staging|production")
        if self.access_ttl_s <= 0 or self.access_ttl_s > 3600:
            raise ValidationError("access token TTL must be 1..3600 seconds")
        if self.session_idle_ttl_s <= self.access_ttl_s:
            raise ValidationError("idle TTL must exceed access token TTL")
        if self.session_absolute_ttl_s < self.session_idle_ttl_s:
            raise ValidationError("absolute session TTL must be >= idle TTL")
        if self.environment == "production":
            if not self.cookie_secure:
                raise ValidationError("secure cookies are mandatory in production")
            if self.cookie_samesite not in ("Lax", "Strict"):
                raise ValidationError("SameSite must be Lax or Strict in production")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def with_overrides(self, **kwargs) -> "EnterpriseAuthConfig":
        return replace(self, **kwargs)

    @classmethod
    def from_env(cls, **overrides) -> "EnterpriseAuthConfig":
        env_name = os.environ.get("AGENTGUARD_ENV", "development").strip().lower() or "development"
        secret_raw = os.environ.get("AGENTGUARD_SESSION_SECRET", "")
        base = cls(
            environment=env_name,
            session_secret=secret_raw.encode("utf-8") if secret_raw else None,
            bootstrap_admin_email=os.environ.get("AGENTGUARD_BOOTSTRAP_ADMIN_EMAIL") or None,
            bootstrap_admin_password=os.environ.get("AGENTGUARD_BOOTSTRAP_ADMIN_PASSWORD") or None,
            cookie_secure=(env_name == "production"),
            cookie_samesite=("Strict" if env_name == "production"
                             else os.environ.get("AGENTGUARD_COOKIE_SAMESITE", "Lax")),
            allow_jit_provisioning=(os.environ.get("AGENTGUARD_ALLOW_JIT_PROVISIONING", "false").lower()
                                    in ("1", "true", "yes")),
        )
        return base.with_overrides(**overrides) if overrides else base
