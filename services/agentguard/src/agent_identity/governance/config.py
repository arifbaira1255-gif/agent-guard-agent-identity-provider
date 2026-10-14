"""Step 11 governance configuration.

Fail-closed defaults. Nothing here is a secret; credentials for connectors are supplied by the
connector, never stored in governance config.

The two ``unknown_*`` policies are the ONLY knobs that shape how the guard treats a resource it
cannot classify. They are constrained to ``deny`` and ``require_approval`` — there is deliberately
no ``allow`` option, so misconfiguration cannot open a hole.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, replace

from ..core.errors import ValidationError

ENV_VAR = "AGENTGUARD_ENV"


@dataclass(frozen=True)
class GovernanceConfig:
    environment: str = "development"

    # ---- unclassified / unknown handling (never 'allow') ------------------------------------
    unknown_resource_policy: str = "deny"        # deny | require_approval
    unclassified_type_policy: str = "deny"       # deny | require_approval

    # ---- escalation -------------------------------------------------------------------------
    #: Escalate an otherwise-permitted destructive operation to REQUIRE_APPROVAL when the resolved
    #: resource is classified strictly above this level. ``restricted`` means "never escalate
    #: automatically" for the built-in classifier (a policy may still demand approval).
    escalate_at_or_above: str = "confidential"   # public | internal | confidential | restricted
    #: Also require approval for destructive ops at/above this level (same ladder).
    approval_for_destructive_ops: bool = True

    # ---- tool registry ----------------------------------------------------------------------
    #: A tool must be explicitly approved by an administrator before it can be invoked.
    require_tool_approval: bool = True
    #: A tool's own manifest may never be the source of an approval.
    trust_manifest_capabilities: bool = False    # must stay False; retained for documentation

    # ---- decision seal (anti-forgery) -------------------------------------------------------
    seal_ttl_s: int = 30                          # a sealed decision is single-use and short-lived
    seal_max_entries: int = 65536                 # bounded ledger; oldest entries evicted first

    # ---- limits -----------------------------------------------------------------------------
    max_permitted_operations: int = 32
    audit_enabled: bool = True

    def __post_init__(self):
        if self.environment not in ("development", "staging", "production"):
            raise ValidationError("environment must be development|staging|production")
        for name, val in (("unknown_resource_policy", self.unknown_resource_policy),
                          ("unclassified_type_policy", self.unclassified_type_policy)):
            if val not in ("deny", "require_approval"):
                raise ValidationError(f"{name} must be 'deny' or 'require_approval' "
                                      "(there is no 'allow' option)")
        if self.escalate_at_or_above not in ("public", "internal", "confidential", "restricted"):
            raise ValidationError("escalate_at_or_above is invalid")
        if self.trust_manifest_capabilities:
            raise ValidationError("manifest capabilities may never be trusted as grants")
        if not (1 <= self.seal_ttl_s <= 3600):
            raise ValidationError("seal_ttl_s must be 1..3600")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def with_overrides(self, **kwargs) -> "GovernanceConfig":
        return replace(self, **kwargs)

    @classmethod
    def from_env(cls, **overrides) -> "GovernanceConfig":
        e = os.environ

        def boolean(key, default):
            raw = e.get(key)
            if raw is None:
                return default
            return raw.strip().lower() in ("1", "true", "yes", "on")

        def num(key, default):
            raw = e.get(key)
            if raw in (None, ""):
                return default
            try:
                return int(raw)
            except ValueError:
                raise ValidationError(f"{key} must be a number")

        base = cls(
            environment=(e.get(ENV_VAR, "development").strip().lower() or "development"),
            unknown_resource_policy=(e.get("AGENTGUARD_GOV_UNKNOWN_POLICY", "deny").strip().lower()
                                     or "deny"),
            unclassified_type_policy=(e.get("AGENTGUARD_GOV_UNCLASSIFIED_POLICY", "deny").strip().lower()
                                      or "deny"),
            escalate_at_or_above=(e.get("AGENTGUARD_GOV_ESCALATE_AT", "confidential").strip().lower()
                                  or "confidential"),
            approval_for_destructive_ops=boolean("AGENTGUARD_GOV_APPROVE_DESTRUCTIVE", True),
            require_tool_approval=boolean("AGENTGUARD_GOV_REQUIRE_TOOL_APPROVAL", True),
            seal_ttl_s=num("AGENTGUARD_GOV_SEAL_TTL_S", 30),
            audit_enabled=boolean("AGENTGUARD_GOV_AUDIT_ENABLED", True),
        )
        return base.with_overrides(**overrides) if overrides else base
