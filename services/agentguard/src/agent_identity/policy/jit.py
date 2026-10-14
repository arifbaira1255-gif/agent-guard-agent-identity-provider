"""Step 10 Just-in-Time (JIT) authorization.

A JIT grant is a narrowly scoped, short-lived, revocable permission that lets an eligible agent
perform ONE action on ONE resource for a bounded window. It is the mechanism by which an agent that
is *not* permanently entitled can still be authorized for a specific, time-boxed operation.

Guarantees enforced here
------------------------
* **Explicit expiration.** Every grant has ``expires_at``; the TTL is bounded by
  ``PolicyConfig.jit_max_ttl_s`` (default 1h, hard cap 24h). There is no way to mint a permanent
  grant through this API.
* **Least privilege.** A grant names exactly one ``(org_id, agent_id, action, resource)`` tuple.
  Matching is exact — no wildcards, no prefixes, no cross-tenant match.
* **Revocable.** :meth:`JitGrantService.revoke` flips the grant to ``revoked`` immediately; a
  revoked grant can never be re-activated.
* **Tenant-scoped.** Every read/write carries the verified ``org_id``; the store (and RLS) enforce
  the boundary.
* **Audited.** Issuance and revocation are recorded in the policy audit log.
"""
from __future__ import annotations

import time
from typing import List, Optional

from ..core.errors import ForbiddenError, ValidationError
from ..security.ids import new_id
from .config import PolicyConfig
from .errors import JitGrantError
from .models import GrantStatus, JitGrant
from .store import PolicyStore

#: Actions that may never be granted through JIT (they are administrative / self-escalating).
_FORBIDDEN_JIT_ACTIONS = frozenset({
    "policy:create", "policy:activate", "policy:rollback", "policy:delete",
    "role:assign", "platform:admin", "tenant:create", "user:delete",
    "jit:grant", "approval:decide",
})


class JitGrantService:
    def __init__(self, store: PolicyStore, config: PolicyConfig, *, audit=None, clock=None):
        self.store = store
        self.cfg = config
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ issuance
    def issue(self, *, org_id: str, agent_id: str, action: str, resource: str,
              ttl_seconds: Optional[int] = None, instance_id: Optional[str] = None,
              policy_version: Optional[str] = None, issued_by: str = "system",
              reason: str = "", context: Optional[dict] = None,
              correlation_id: Optional[str] = None) -> JitGrant:
        """Mint a narrowly scoped, short-lived grant. Raises on any unsafe request."""
        if not self.cfg.jit_enabled:
            raise JitGrantError("just-in-time authorization is disabled")
        for name, val in (("org_id", org_id), ("agent_id", agent_id), ("action", action),
                          ("resource", resource)):
            if not isinstance(val, str) or not val.strip():
                raise ValidationError(f"{name} is required")
        if action in _FORBIDDEN_JIT_ACTIONS:
            raise ForbiddenError("this action can never be granted through JIT")
        if "*" in action or "*" in resource:
            raise ValidationError("JIT grants must be exact; wildcards are not permitted")
        ttl = self.cfg.jit_default_ttl_s if ttl_seconds is None else int(ttl_seconds)
        if ttl <= 0:
            raise ValidationError("ttl_seconds must be positive")
        if ttl > self.cfg.jit_max_ttl_s:
            raise ValidationError(f"ttl_seconds exceeds the maximum ({self.cfg.jit_max_ttl_s}s)")
        now = self._now()
        grant = JitGrant(
            grant_id=new_id("jit"), org_id=org_id, agent_id=agent_id, instance_id=instance_id,
            action=action, resource=resource, issued_at=now, expires_at=now + ttl,
            policy_version=policy_version, status=GrantStatus.ACTIVE, issued_by=issued_by,
            reason=reason, context=context)
        self.store.put_grant(grant)
        self._audit("jit.grant.issued", org_id=org_id, grant_id=grant.grant_id,
                    outcome="ok", reason=reason, correlation_id=correlation_id,
                    actor_user_id=issued_by)
        return grant

    # ------------------------------------------------------------------ validation
    def find_live_grant(self, *, org_id: str, agent_id: str, action: str, resource: str,
                        instance_id: Optional[str] = None) -> Optional[JitGrant]:
        """Return a live grant matching the exact scope, or None. Never returns an expired/revoked
        grant, and never matches across tenants."""
        now = self._now()
        for g in self.store.list_grants(org_id=org_id, agent_id=agent_id, active_only=True, now=now):
            if g.matches(org_id=org_id, agent_id=agent_id, action=action, resource=resource,
                         instance_id=instance_id):
                return g
        return None

    def live_grants_for(self, *, org_id: str, agent_id: str) -> List[JitGrant]:
        return self.store.list_grants(org_id=org_id, agent_id=agent_id, active_only=True,
                                      now=self._now())

    # ------------------------------------------------------------------ revocation
    def revoke(self, grant_id: str, *, reason: str = "revoked", revoked_by: str = "system",
               correlation_id: Optional[str] = None) -> Optional[JitGrant]:
        now = self._now()
        g = self.store.revoke_grant(grant_id, reason, now)
        if g is not None:
            self._audit("jit.grant.revoked", org_id=g.org_id, grant_id=grant_id, outcome="ok",
                        reason=reason, correlation_id=correlation_id, actor_user_id=revoked_by)
        return g

    def revoke_all_for_agent(self, *, org_id: str, agent_id: str, reason: str = "agent_revoked",
                             revoked_by: str = "system",
                             correlation_id: Optional[str] = None) -> int:
        """Revoke every live grant for an agent (e.g. on agent termination). Returns the count."""
        n = 0
        for g in self.store.list_grants(org_id=org_id, agent_id=agent_id, active_only=True,
                                        now=self._now()):
            if self.store.revoke_grant(g.grant_id, reason, self._now()) is not None:
                n += 1
        if n:
            self._audit("jit.grant.revoked_all", org_id=org_id, outcome="ok", reason=reason,
                        correlation_id=correlation_id, actor_user_id=revoked_by)
        return n

    # ------------------------------------------------------------------ helpers
    def _audit(self, event: str, *, org_id, grant_id=None, outcome="ok", reason=None,
               correlation_id=None, actor_user_id=None) -> None:
        if self.audit is None:
            return
        self.audit.record(event, org_id=org_id, grant_id=grant_id, outcome=outcome, reason=reason,
                          correlation_id=correlation_id, actor_user_id=actor_user_id)
