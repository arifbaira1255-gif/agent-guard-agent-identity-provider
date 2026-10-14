"""Configuration and feature flags for the agent platform.

SAFE BY DEFAULT.  The platform is a separate layer: with ``AGENT_PLATFORM_ENABLED`` unset the
platform's own entry points refuse to build a live run rather than silently running unbounded, and
nothing about AgentGuard or Happy LANG changes.  Each capability has its own flag so an operator can
adopt the platform one piece at a time without destabilising an existing deployment.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Optional

from .errors import ConfigError

_TRUTHY = ("1", "true", "yes", "on")
_FALSY = ("0", "false", "no", "off")

#: Authorization enforcement modes, mirroring the integration contract's vocabulary.
MODES = ("enforce", "audit", "off")

#: Environments.  ``production`` turns on the fail-closed checks in :meth:`PlatformConfig.validate`.
ENVIRONMENTS = ("development", "staging", "production")


# -- env helpers -------------------------------------------------------------------------------
def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUTHY:
        return True
    if value in _FALSY:
        return False
    return default


def env_str(name: str, default: Optional[str] = None) -> Optional[str]:
    raw = os.environ.get(name)
    if raw is None:
        return default
    raw = raw.strip()
    return raw or default


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def env_list(name: str) -> tuple:
    raw = os.environ.get(name)
    if not raw:
        return ()
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class PlatformConfig:
    """Resolved platform configuration."""

    # --- master switch ---------------------------------------------------------------------
    enabled: bool = False
    environment: str = "development"

    # --- identity --------------------------------------------------------------------------
    agent_id: str = "platform-agent"
    instance_id: Optional[str] = None
    org_id: Optional[str] = None

    # --- model router ----------------------------------------------------------------------
    provider: str = "openai_compatible"
    model: str = "gpt-4o-mini"
    base_url: Optional[str] = None
    api_key: Optional[str] = field(default=None, repr=False)
    temperature: float = 0.0
    max_tokens_per_call: int = 1024
    request_timeout_s: float = 60.0
    max_retries: int = 2
    fallback_models: tuple = ()
    #: Hard ceiling on a single model response body (protects against a hostile/garbled server).
    max_response_bytes: int = 2_000_000
    #: Prices in USD per 1M tokens: (input, output).  Used for cost accounting and cost budgets.
    price_per_million: dict = field(default_factory=dict)

    # --- run budgets -----------------------------------------------------------------------
    max_steps: int = 12
    wall_clock_s: float = 120.0
    max_tool_calls: int = 24
    max_tokens: Optional[int] = 200_000
    max_cost_usd: Optional[float] = 2.0

    # --- tools / authorization -------------------------------------------------------------
    mode: str = "enforce"
    require_authorization: bool = True
    tool_allowlist: tuple = ()
    #: AgentGuard endpoint for the authoritative decision (reuses the integration contract's route).
    agentguard_base_url: str = "http://127.0.0.1:8443"
    authorize_path: str = "/v1/authorize"
    events_path: str = "/v1/security/events"
    verify_tls: bool = True
    ca_bundle: Optional[str] = None
    allow_insecure_http: bool = False
    auth_timeout_s: float = 5.0

    # --- memory ----------------------------------------------------------------------------
    memory_enabled: bool = True
    memory_capacity: int = 500
    memory_top_k: int = 5
    memory_ttl_s: Optional[float] = None
    working_memory_max_messages: int = 40

    # --- tracing / observability -----------------------------------------------------------
    tracing_enabled: bool = True
    emit_events: bool = True
    max_events_buffer: int = 100
    log_prompts: bool = False

    # --- sandbox bridge --------------------------------------------------------------------
    sandbox_enabled: bool = False
    require_isolation: bool = False
    isolation_mode: str = "auto"
    isolation_backend: str = "auto"

    # -- validation --------------------------------------------------------------------------
    def validate(self) -> None:
        """Collect every problem and raise once.  ``production`` is checked strictly."""
        problems = []
        if self.environment not in ENVIRONMENTS:
            problems.append(f"environment must be one of {list(ENVIRONMENTS)}")
        if self.mode not in MODES:
            problems.append(f"mode must be one of {list(MODES)}")
        if not (0.0 <= float(self.temperature) <= 2.0):
            problems.append("temperature must be in [0, 2]")
        if not (1 <= int(self.max_tokens_per_call) <= 128_000):
            problems.append("max_tokens_per_call must be in [1, 128000]")
        if not (0 < float(self.request_timeout_s) <= 600):
            problems.append("request_timeout_s must be in (0, 600]")
        if not (0 <= int(self.max_retries) <= 5):
            problems.append("max_retries must be in [0, 5]")
        if not (1 <= int(self.max_steps) <= 100):
            problems.append("max_steps must be in [1, 100]")
        if not (0 < float(self.wall_clock_s) <= 3600):
            problems.append("wall_clock_s must be in (0, 3600]")
        if not (0 <= int(self.max_tool_calls) <= 1000):
            problems.append("max_tool_calls must be in [0, 1000]")
        if self.max_tokens is not None and not (1 <= int(self.max_tokens) <= 10_000_000):
            problems.append("max_tokens must be in [1, 10000000]")
        if self.max_cost_usd is not None and not (0 < float(self.max_cost_usd) <= 1000):
            problems.append("max_cost_usd must be in (0, 1000]")
        if not (1 <= int(self.memory_capacity) <= 1_000_000):
            problems.append("memory_capacity must be in [1, 1000000]")
        if not (0 <= int(self.memory_top_k) <= 100):
            problems.append("memory_top_k must be in [0, 100]")
        if not (0.0 < float(self.auth_timeout_s) <= 60):
            problems.append("auth_timeout_s must be in (0, 60]")
        if self.isolation_mode not in ("required", "auto", "off"):
            problems.append("isolation_mode must be one of ['required', 'auto', 'off']")
        if self.isolation_backend not in ("auto", "docker", "podman", "bwrap", "namespaces"):
            problems.append("isolation_backend must be one of ['auto', 'docker', 'podman', 'bwrap', "
                            "'namespaces']")
        if self.base_url is not None and not (
                str(self.base_url).startswith("http://")
                or str(self.base_url).startswith("https://")):
            problems.append("base_url must be an absolute http(s) URL")
        if problems:
            raise ConfigError("invalid platform configuration", errors=problems)
        # -- production-only, fail-closed rules ---------------------------------------------
        if self.environment == "production":
            if self.base_url and str(self.base_url).startswith("http://") \
                    and not self.allow_insecure_http:
                raise ConfigError(
                    "plaintext http:// model endpoint is not permitted in production "
                    "(set allow_insecure_http=True only behind a trusted TLS-terminating sidecar)",
                    field="base_url")
            if not self.verify_tls:
                raise ConfigError("verify_tls=False is not permitted in production",
                                  field="verify_tls")
            if self.mode == "off" and self.enabled:
                raise ConfigError(
                    "authorization mode 'off' is not permitted in production: every protected "
                    "operation must be authorized", field="mode")

    def __post_init__(self) -> None:
        self.validate()

    # -- derived ----------------------------------------------------------------------------
    @property
    def is_enabled(self) -> bool:
        return bool(self.enabled)

    @property
    def enforcing(self) -> bool:
        return bool(self.enabled) and self.mode == "enforce"

    def authorize_url(self) -> str:
        return self.agentguard_base_url.rstrip("/") + self.authorize_path

    def events_url(self) -> str:
        return self.agentguard_base_url.rstrip("/") + self.events_path

    def with_overrides(self, **kwargs) -> "PlatformConfig":
        return replace(self, **kwargs)

    # -- environment -------------------------------------------------------------------------
    @classmethod
    def from_env(cls, **overrides) -> "PlatformConfig":
        """Build from ``AGENT_PLATFORM_*`` environment variables."""
        base = cls(
            enabled=env_flag("AGENT_PLATFORM_ENABLED", False),
            environment=env_str("AGENT_PLATFORM_ENV", "development"),
            agent_id=env_str("AGENT_PLATFORM_AGENT_ID", "platform-agent"),
            instance_id=env_str("AGENT_PLATFORM_INSTANCE_ID"),
            org_id=env_str("AGENT_PLATFORM_ORG_ID"),
            provider=env_str("AGENT_PLATFORM_PROVIDER", "openai_compatible"),
            model=env_str("AGENT_PLATFORM_MODEL", "gpt-4o-mini"),
            base_url=env_str("AGENT_PLATFORM_BASE_URL"),
            api_key=env_str("AGENT_PLATFORM_API_KEY"),
            temperature=env_float("AGENT_PLATFORM_TEMPERATURE", 0.0),
            max_tokens_per_call=env_int("AGENT_PLATFORM_MAX_TOKENS_PER_CALL", 1024),
            request_timeout_s=env_float("AGENT_PLATFORM_REQUEST_TIMEOUT_S", 60.0),
            max_retries=env_int("AGENT_PLATFORM_MAX_RETRIES", 2),
            fallback_models=env_list("AGENT_PLATFORM_FALLBACK_MODELS"),
            max_steps=env_int("AGENT_PLATFORM_MAX_STEPS", 12),
            wall_clock_s=env_float("AGENT_PLATFORM_WALL_CLOCK_S", 120.0),
            max_tool_calls=env_int("AGENT_PLATFORM_MAX_TOOL_CALLS", 24),
            mode=env_str("AGENT_PLATFORM_MODE", "enforce"),
            require_authorization=env_flag("AGENT_PLATFORM_REQUIRE_AUTHORIZATION", True),
            tool_allowlist=env_list("AGENT_PLATFORM_TOOL_ALLOWLIST"),
            agentguard_base_url=env_str("AGENT_PLATFORM_AGENTGUARD_URL", "http://127.0.0.1:8443"),
            verify_tls=env_flag("AGENT_PLATFORM_VERIFY_TLS", True),
            ca_bundle=env_str("AGENT_PLATFORM_CA_BUNDLE"),
            allow_insecure_http=env_flag("AGENT_PLATFORM_ALLOW_INSECURE_HTTP", False),
            memory_enabled=env_flag("AGENT_PLATFORM_MEMORY_ENABLED", True),
            memory_capacity=env_int("AGENT_PLATFORM_MEMORY_CAPACITY", 500),
            memory_top_k=env_int("AGENT_PLATFORM_MEMORY_TOP_K", 5),
            tracing_enabled=env_flag("AGENT_PLATFORM_TRACING_ENABLED", True),
            emit_events=env_flag("AGENT_PLATFORM_EMIT_EVENTS", True),
            log_prompts=env_flag("AGENT_PLATFORM_LOG_PROMPTS", False),
            sandbox_enabled=env_flag("AGENT_PLATFORM_SANDBOX_ENABLED", False),
            require_isolation=env_flag("AGENT_PLATFORM_REQUIRE_ISOLATION", False),
            isolation_mode=env_str("AGENT_PLATFORM_ISOLATION_MODE", "auto"),
            isolation_backend=env_str("AGENT_PLATFORM_ISOLATION_BACKEND", "auto"),
        )
        return base.with_overrides(**overrides) if overrides else base


__all__ = ["PlatformConfig", "MODES", "ENVIRONMENTS", "env_flag", "env_str", "env_int",
           "env_float", "env_list"]
