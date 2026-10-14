"""Tenant-aware Redis key namespacing for Step 8.

Every Step 8 key is built through the EXISTING :class:`state.keys.KeyBuilder`, which already:
  * embeds the environment + tenant inside a Redis-Cluster hash tag ``{<env>.<tenant>}`` so one
    tenant's keys share a single slot (and another tenant's keys live in a different slot),
  * validates each component against a closed character set (so an id can never forge another
    tenant/domain by smuggling a ``:``), and
  * SHA-256 hashes any untrusted/sensitive value used as an id (state values, session tokens).

Consequence: a cache entry, login transaction, or rate-limit bucket for tenant A can never be
addressed with tenant B's identity — cross-tenant cache access is structurally impossible.
"""
from __future__ import annotations

from ..state.keys import KeyBuilder, SYSTEM_TENANT

DOMAIN = "security"       # all Step 8 keys live under this domain


class SecurityKeys:
    def __init__(self, environment: str, prefix: str = "agentguard", version: str = "v1"):
        self.kb = KeyBuilder(environment, prefix=prefix, version=version)

    @staticmethod
    def _tenant(org_id) -> str:
        return org_id or SYSTEM_TENANT

    def for_tenant(self, org_id):
        return self.kb.scoped(self._tenant(org_id))

    # ---- permission cache (per user, per tenant scope) --------------------------------------
    def permission(self, org_id, user_id: str) -> str:
        return self.kb.hashed(self._tenant(org_id), DOMAIN, "perm", f"{user_id}|{self._tenant(org_id)}")

    # ---- OIDC login transaction (single-use state) ------------------------------------------
    def login_txn(self, org_id, state: str) -> str:
        return self.kb.hashed(self._tenant(org_id), DOMAIN, "oidcstate", state)

    # ---- rate limiting (per scope + identity, hashed identity) --------------------------------
    def rate(self, org_id, scope: str, ident: str) -> str:
        return self.kb.hashed(self._tenant(org_id), DOMAIN, f"rate_{scope}", ident)

    # ---- OIDC JWKS cache (issuer-scoped; platform-level, tenant "_system") --------------------
    def jwks(self, issuer: str) -> str:
        return self.kb.hashed(SYSTEM_TENANT, DOMAIN, "jwks", issuer)

    # ---- OIDC discovery cache -----------------------------------------------------------------
    def discovery(self, issuer: str) -> str:
        return self.kb.hashed(SYSTEM_TENANT, DOMAIN, "oidcmeta", issuer)
