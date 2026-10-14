"""Strict key namespace:   agentguard:v1:{<env>.<tenant>}:<domain>:<resource>:<id>
- `{env.tenant}` is the Redis Cluster hash tag: one tenant's keys share a slot (Lua scripts / multi-key ops OK).
- every component is validated against a closed character set (no ':', '{', '}', '*', whitespace, NUL) so ids
  cannot forge another tenant/domain; untrusted or sensitive values (nonces, tokens, IPs) are SHA-256 hashed."""
import hashlib
import re
from typing import Optional

from .errors import StateConfigError

ENVIRONMENTS = ("development", "staging", "production")
SYSTEM_TENANT = "_system"
_ID = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")
_TAG = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


class KeyBuilder:
    def __init__(self, environment: str, prefix: str = "agentguard", version: str = "v1"):
        if environment not in ENVIRONMENTS:
            raise StateConfigError("invalid environment")
        for part in (prefix, version):
            if not _TAG.match(part):
                raise StateConfigError("invalid key prefix/version")
        self.environment, self.prefix, self.version = environment, prefix, version

    @staticmethod
    def valid_tenant(tenant: str) -> str:
        if not isinstance(tenant, str) or not (tenant == SYSTEM_TENANT or _ID.match(tenant)):
            raise StateConfigError("invalid tenant id")
        return tenant

    def key(self, tenant: str, domain: str, resource: str, ident: str) -> str:
        self.valid_tenant(tenant)
        if not _TAG.match(domain or "") or not _TAG.match(resource or ""):
            raise StateConfigError("invalid key domain/resource")
        if not isinstance(ident, str) or not _ID.match(ident):
            raise StateConfigError("invalid key id")
        return f"{self.prefix}:{self.version}:{{{self.environment}.{tenant}}}:{domain}:{resource}:{ident}"

    def hashed(self, tenant: str, domain: str, resource: str, raw: str) -> str:
        return self.key(tenant, domain, resource, digest(raw))

    def scoped(self, tenant: str) -> "TenantKeys":
        return TenantKeys(self, self.valid_tenant(tenant))


class TenantKeys:
    """Key factory FIXED to one tenant: code holding it cannot address another tenant's keys."""
    def __init__(self, kb: KeyBuilder, tenant: str):
        self._kb, self.tenant = kb, tenant

    def key(self, domain, resource, ident):
        return self._kb.key(self.tenant, domain, resource, ident)

    def hashed(self, domain, resource, raw):
        return self._kb.hashed(self.tenant, domain, resource, raw)
