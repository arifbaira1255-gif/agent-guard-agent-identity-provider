"""Redis-backed, tenant-scoped permission cache. PostgreSQL remains AUTHORITATIVE.

The cache only ever accelerates the *resolution* of a user's effective permission set; it is never
consulted for authority on its own:
  * every entry is keyed per (tenant, user) through :class:`SecurityKeys`, so one tenant can never
    read another tenant's cached authority;
  * the loader ALWAYS recomputes from PostgreSQL on a miss, and the cached value carries a short
    TTL (bounded staleness is acceptable because access is still gated by the authoritative DB;
    role changes additionally evict the entry immediately — see ``invalidate``);
  * invalidation is explicit and happens synchronously after every role/membership/user change.

If the cache backend is unavailable the cache degrades to "always miss" (fail open on availability,
never on authority: the DB loader still runs). It is constructed with the SAME ``StateBackend``
used by Steps 1-7, so tests run this against the real Redis and the in-memory backend identically.
"""
from __future__ import annotations

import json
import logging
from typing import Callable, Optional

from .models import AuthContext
from .rbac import EffectiveAccess
from .redis_keys import SecurityKeys

_log = logging.getLogger("agentguard.identity.security")
DEFAULT_TTL_MS = 30_000          # 30s ceiling on staleness; explicit eviction on any change


class PermissionCache:
    def __init__(self, backend, keys: SecurityKeys, *, ttl_ms: int = DEFAULT_TTL_MS, enabled: bool = True):
        self.backend = backend
        self.keys = keys
        self.ttl_ms = ttl_ms
        self.enabled = enabled

    def _read(self, org_id, user_id: str) -> Optional[dict]:
        if not self.enabled:
            return None
        try:
            raw = self.backend.get(self.keys.permission(org_id, user_id))
        except Exception:                                   # backend down => behave as a miss
            _log.warning("permission cache read failed; falling back to authoritative store")
            return None
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def _write(self, org_id, user_id: str, payload: dict) -> None:
        if not self.enabled:
            return
        try:
            self.backend.set(self.keys.permission(org_id, user_id),
                             json.dumps(payload, separators=(",", ":")).encode("utf-8"), self.ttl_ms)
        except Exception:
            _log.warning("permission cache write failed (ignored; DB remains authoritative)")

    def get_or_load(self, org_id, user_id: str,
                    loader: Callable[[], "EffectiveAccess"]) -> "EffectiveAccess":
        """Return the effective access for (tenant, user), using the cache when available.

        The loader is the authoritative PostgreSQL resolution and is ALWAYS used on a miss. The
        cached payload is re-validated (roles/permissions shapes) before being trusted.
        """
        cached = self._read(org_id, user_id)
        if cached is not None:
            roles = cached.get("roles")
            perms = cached.get("permissions")
            if isinstance(roles, list) and isinstance(perms, list):
                return EffectiveAccess(user_id, org_id, bool(cached.get("is_platform_admin")),
                                       tuple(roles), frozenset(perms))
        access = loader()
        self._write(org_id, user_id, {"roles": list(access.roles),
                                      "permissions": sorted(access.permissions),
                                      "is_platform_admin": access.is_platform_admin})
        return access

    def invalidate(self, org_id, user_id: str) -> None:
        """Evict the cached authority for a user in a tenant. Called after ANY role/membership/
        status change so a demoted user cannot keep old permissions from the cache."""
        if not self.enabled:
            return
        try:
            self.backend.delete(self.keys.permission(org_id, user_id))
        except Exception:
            _log.warning("permission cache invalidate failed; entry will expire by TTL")

    def invalidate_user_everywhere(self, memberships: list, user_id: str, *,
                                   include_system: bool = True) -> None:
        """Evict every cached scope a user could hold authority in (all their tenants + platform)."""
        for m in memberships:
            self.invalidate(getattr(m, "org_id", m), user_id)
        if include_system:
            self.invalidate(None, user_id)


def auth_context_from(access: EffectiveAccess, *, ctx: "AuthContext") -> "AuthContext":
    """Convenience: rebuild an AuthContext from freshly resolved access."""
    ctx.roles = access.roles
    ctx.permissions = access.permissions
    ctx.is_platform_admin = access.is_platform_admin
    return ctx
