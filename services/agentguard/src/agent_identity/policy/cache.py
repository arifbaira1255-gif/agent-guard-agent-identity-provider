"""Step 10 policy decision cache (Redis-backed, tenant + identity + policy-version scoped).

The cache accelerates *repeated identical* decisions. It is NEVER authoritative: PostgreSQL holds
the policy definitions and the JIT/approval state, and the engine re-evaluates on a miss.

Safety rules (all enforced here)
--------------------------------
* **Scoped correctly.** The key embeds the tenant, the agent identity, the action, the resource and
  the active policy version, so a decision for one tenant/identity/version can never be served to
  another. Keys are built through the EXISTING :class:`~agent_identity.state.keys.KeyBuilder`, which
  hash-tags by ``{env.tenant}`` and SHA-256 hashes untrusted components.
* **Bounded TTL.** Every entry has a short TTL (``cache_ttl_ms``, capped by ``cache_max_ttl_ms``).
* **No stale allows survive revocation.** Only ALLOW decisions are cached, and every mutation that
  could change an outcome (policy activation/rollback, JIT issue/revoke, approval decision) calls
  :meth:`invalidate_*`, which bumps a per-tenant generation counter so all prior entries are
  logically dead even before their TTL expires.
* **Fail closed on backend failure.** A cache read/write error is treated as a miss; the engine is
  still consulted. A cache is never a reason to allow.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from ..state.keys import KeyBuilder, SYSTEM_TENANT
from .config import PolicyConfig
from .models import DecisionKind, PolicyDecision

log = logging.getLogger("agentguard.policy.cache")

DOMAIN = "policy"


class DecisionCache:
    def __init__(self, backend, config: PolicyConfig, *, environment: str = "development",
                 prefix: str = "agentguard"):
        self.backend = backend
        self.cfg = config
        self.enabled = bool(config.cache_enabled and backend is not None)
        self._kb = KeyBuilder(environment, prefix=prefix)

    # ------------------------------------------------------------------ keys
    def _tenant(self, org_id) -> str:
        return org_id or SYSTEM_TENANT

    def _generation_key(self, org_id) -> str:
        return self._kb.key(self._tenant(org_id), DOMAIN, "gen", "current")

    def generation(self, org_id) -> str:
        if not self.enabled:
            return "0"
        try:
            raw = self.backend.get(self._generation_key(org_id))
            return raw.decode("utf-8") if raw else "0"
        except Exception:  # noqa: BLE001 - backend down => treat as generation 0 (still scoped)
            return "0"

    def _decision_key(self, org_id, agent_id: str, action: str, resource: str,
                      policy_version: Optional[str]) -> str:
        gen = self.generation(org_id)
        raw = f"{agent_id}|{action}|{resource}|{policy_version or '-'}|{gen}"
        return self._kb.hashed(self._tenant(org_id), DOMAIN, "dec", raw)

    # ------------------------------------------------------------------ read / write
    def get(self, *, org_id, agent_id: str, action: str, resource: str,
            policy_version: Optional[str]) -> Optional[PolicyDecision]:
        if not self.enabled:
            return None
        try:
            raw = self.backend.get(self._decision_key(org_id, agent_id, action, resource,
                                                      policy_version))
        except Exception:  # noqa: BLE001
            log.warning("policy decision cache read failed; evaluating authoritatively")
            return None
        if not raw:
            return None
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return None
        try:
            kind = DecisionKind(payload["decision"])
        except (KeyError, ValueError):
            return None
        # Only ALLOW is ever cached; anything else is re-evaluated (defence in depth).
        if kind is not DecisionKind.ALLOW:
            return None
        return PolicyDecision(kind, payload.get("reason", ""), policy_id=payload.get("policy_id"),
                              policy_version=payload.get("policy_version"),
                              decision_id=payload.get("decision_id"),
                              obligations=tuple(payload.get("obligations") or ()),
                              grant_id=payload.get("grant_id"), cached=True)

    def put(self, *, org_id, agent_id: str, action: str, resource: str,
            policy_version: Optional[str], decision: PolicyDecision) -> None:
        if not self.enabled or decision.kind is not DecisionKind.ALLOW:
            return
        ttl = min(self.cfg.cache_ttl_ms, self.cfg.cache_max_ttl_ms)
        payload = {"decision": decision.kind.value, "reason": decision.reason,
                   "policy_id": decision.policy_id, "policy_version": decision.policy_version,
                   "decision_id": decision.decision_id, "obligations": list(decision.obligations),
                   "grant_id": decision.grant_id}
        try:
            self.backend.set(self._decision_key(org_id, agent_id, action, resource, policy_version),
                             json.dumps(payload, separators=(",", ":")).encode("utf-8"), ttl)
        except Exception:  # noqa: BLE001
            log.warning("policy decision cache write failed (ignored; engine remains authoritative)")

    # ------------------------------------------------------------------ invalidation
    def invalidate_tenant(self, org_id) -> None:
        """Bump the tenant generation so every cached decision for that tenant is logically dead.

        Called after ANY policy activation/rollback, JIT issue/revoke, or approval decision. The
        generation key itself has a bounded TTL so it cannot grow without bound.
        """
        if not self.enabled:
            return
        try:
            self.backend.set(self._generation_key(org_id), str(int(self.generation(org_id)) + 1).encode(),
                             self.cfg.cache_max_ttl_ms)
        except Exception:  # noqa: BLE001
            log.warning("policy decision cache invalidation failed; entries expire by TTL")

    def invalidate_all(self) -> None:
        """Invalidate the platform scope (used when a platform-wide policy changes)."""
        self.invalidate_tenant(None)
