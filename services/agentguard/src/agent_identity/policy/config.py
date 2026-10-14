"""Step 10 policy-engine configuration.

Fail-closed defaults. Secrets are read from the ENVIRONMENT only and never logged. The engine is
disabled by default: when no policy engine is configured the authorization surface keeps its
existing deny-by-default capability behaviour (Step 9), so nothing silently becomes more permissive.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Optional

from ..core.errors import ValidationError

ENV_VAR = "AGENTGUARD_ENV"


@dataclass(frozen=True)
class PolicyConfig:
    environment: str = "development"

    # ---- engine selection -------------------------------------------------------------------
    # "opa"  -> evaluate Rego through a real OPA instance (sidecar/CLI/HTTP).
    # "none" -> no policy engine; the authorization surface keeps the Step 9 capability default.
    engine: str = "none"
    opa_mode: str = "cli"                 # "cli" (opa eval subprocess) | "http" (opa run --server)
    opa_binary: str = "opa"               # path to the OPA binary (cli mode)
    opa_url: str = "http://127.0.0.1:8181"  # OPA server base URL (http mode)
    opa_decision_path: str = "agentguard/authz/decision"  # package path for the decision rule
    opa_bundle_dir: Optional[str] = None  # directory of .rego files loaded in cli mode

    # ---- bounded resource limits (never unbounded) ------------------------------------------
    eval_timeout_ms: int = 250            # hard wall-clock ceiling per evaluation
    max_input_bytes: int = 64 * 1024      # reject oversized inputs before they reach the engine
    max_policy_bytes: int = 256 * 1024    # reject oversized policy source
    max_concurrent_evals: int = 32        # bounded worker pool; excess waits then fails closed

    # ---- decision cache ---------------------------------------------------------------------
    cache_enabled: bool = True
    cache_ttl_ms: int = 5_000             # short ceiling; explicit invalidation on any change
    cache_max_ttl_ms: int = 30_000        # absolute cap regardless of configuration

    # ---- JIT grants -------------------------------------------------------------------------
    jit_enabled: bool = True
    jit_default_ttl_s: int = 300          # 5 minutes
    jit_max_ttl_s: int = 3600             # hard ceiling: no permanent access via JIT

    # ---- approvals --------------------------------------------------------------------------
    approval_ttl_s: int = 900             # an approval is itself short-lived

    # ---- policy administration --------------------------------------------------------------
    #: When True, only a platform administrator may create/activate platform-wide policies.
    require_platform_admin_for_global_policy: bool = True

    def __post_init__(self):
        if self.environment not in ("development", "staging", "production"):
            raise ValidationError("environment must be development|staging|production")
        if self.engine not in ("opa", "none"):
            raise ValidationError("engine must be 'opa' or 'none'")
        if self.opa_mode not in ("cli", "http"):
            raise ValidationError("opa_mode must be 'cli' or 'http'")
        if not (10 <= self.eval_timeout_ms <= 10_000):
            raise ValidationError("eval_timeout_ms must be 10..10000")
        if not (1 <= self.max_concurrent_evals <= 1024):
            raise ValidationError("max_concurrent_evals must be 1..1024")
        if self.cache_ttl_ms <= 0 or self.cache_ttl_ms > self.cache_max_ttl_ms:
            raise ValidationError("cache_ttl_ms must be positive and <= cache_max_ttl_ms")
        if not (1 <= self.jit_default_ttl_s <= self.jit_max_ttl_s):
            raise ValidationError("jit_default_ttl_s must be 1..jit_max_ttl_s")
        if self.jit_max_ttl_s > 24 * 3600:
            raise ValidationError("jit_max_ttl_s must not exceed 24h (no long-lived JIT access)")
        if self.environment == "production" and self.engine == "opa" and self.opa_mode == "http":
            if not self.opa_url.startswith("https://") and "127.0.0.1" not in self.opa_url \
                    and "localhost" not in self.opa_url:
                raise ValidationError("OPA over HTTP must be loopback or https in production")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def with_overrides(self, **kwargs) -> "PolicyConfig":
        return replace(self, **kwargs)

    @classmethod
    def from_env(cls, **overrides) -> "PolicyConfig":
        e = os.environ
        env_name = (e.get(ENV_VAR, "development").strip().lower() or "development")

        def num(key, default, cast=int):
            raw = e.get(key)
            if raw is None or raw == "":
                return default
            try:
                return cast(raw)
            except ValueError:
                raise ValidationError(f"{key} must be a number")

        def boolean(key, default):
            raw = e.get(key)
            if raw is None:
                return default
            return raw.strip().lower() in ("1", "true", "yes", "on")

        base = cls(
            environment=env_name,
            engine=e.get("AGENTGUARD_POLICY_ENGINE", "none").strip().lower() or "none",
            opa_mode=e.get("AGENTGUARD_OPA_MODE", "cli").strip().lower() or "cli",
            opa_binary=e.get("AGENTGUARD_OPA_BINARY", "opa"),
            opa_url=e.get("AGENTGUARD_OPA_URL", "http://127.0.0.1:8181"),
            opa_decision_path=e.get("AGENTGUARD_OPA_DECISION_PATH", "agentguard/authz/decision"),
            opa_bundle_dir=e.get("AGENTGUARD_OPA_BUNDLE_DIR") or None,
            eval_timeout_ms=num("AGENTGUARD_POLICY_EVAL_TIMEOUT_MS", 250),
            max_concurrent_evals=num("AGENTGUARD_POLICY_MAX_CONCURRENCY", 32),
            cache_enabled=boolean("AGENTGUARD_POLICY_CACHE_ENABLED", True),
            cache_ttl_ms=num("AGENTGUARD_POLICY_CACHE_TTL_MS", 5_000),
            jit_enabled=boolean("AGENTGUARD_JIT_ENABLED", True),
            jit_default_ttl_s=num("AGENTGUARD_JIT_DEFAULT_TTL_S", 300),
            jit_max_ttl_s=num("AGENTGUARD_JIT_MAX_TTL_S", 3600),
            approval_ttl_s=num("AGENTGUARD_APPROVAL_TTL_S", 900),
        )
        return base.with_overrides(**overrides) if overrides else base
