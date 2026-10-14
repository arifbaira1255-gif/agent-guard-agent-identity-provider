"""Centralised, typed application settings loaded from the environment."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All runtime configuration for the AQL-1 backend."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # App
    app_name: str = "AQL-1"
    app_env: str = "development"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: str = "http://localhost:3000"

    # LLM providers — OpenAI-compatible gateways only (no direct OpenAI /
    # Anthropic accounts). UnoRouter is primary, ExperimentLab is the fallback.
    unorouter_api_key: str = ""
    unorouter_base_url: str = "https://api.unorouter.com/v1"
    unorouter_model: str = "claude-opus-4.6"
    experimentlab_api_key: str = ""
    experimentlab_base_url: str = "https://api.experimentlab.ai/v1"
    # Empty → reuse ``unorouter_model``. Set to a model id ExperimentLab serves.
    experimentlab_model: str = ""

    # Vector DB
    pinecone_api_key: str = ""
    pinecone_index_name: str = "llama-text-embed-v2-index"
    pinecone_environment: str = "us-east-1"

    # Long-term memory
    pinecone_namespace: str = "default"
    memory_top_k: int = 5
    memory_audit_table: str = "memory_audit"

    # Supabase
    supabase_url: str = ""
    supabase_anon_key: str = ""
    supabase_service_role_key: str = ""

    # Payoneer (manual payment workflow — no payment link / webhook).
    # Users pay to ``payoneer_email`` (or by bank transfer), then submit the
    # transaction reference + screenshot; an admin approves it to activate them.
    payoneer_merchant_id: str = ""
    payoneer_api_key: str = ""
    payoneer_email: str = ""
    payoneer_payment_url: str = ""
    bank_transfer_details: str = ""
    # Shared secret for the admin approval endpoints (``X-Admin-Token``).
    admin_token: str = ""

    # Billing
    billing_enabled: bool = True
    subscriptions_table: str = "subscriptions"
    usage_table: str = "usage"
    payment_verifications_table: str = "payment_verifications"
    payment_screenshot_bucket: str = "payment-screenshots"
    payment_screenshot_max_bytes: int = 5 * 1024 * 1024
    # Days of access granted when a payment is approved.
    payment_period_days: int = 30

    # ── Tool security (AgentGuard gate + isolated code execution) ─────────────
    # tool_gate_mode: agentguard | local | deny_all | allow_all (never in production)
    tool_gate_mode: str = "local"
    # ``local`` mode: only these tools may run; ``tool_denylist`` always wins.
    tool_allowlist: str = "echo,now,web_search,file_generator"
    tool_denylist: str = ""
    # ``agentguard`` mode: POST {agentguard_url}/v1/authorize before every tool call.
    agentguard_url: str = ""
    agentguard_token: str = ""
    # "package.module:function" returning an AgentGuard SDK AuthorizationClient (credential +
    # proof-of-possession). Required for ``agentguard`` mode - see docs/HOSTING.md.
    agentguard_client_factory: str = ""
    agentguard_agent_id: str = "aql-1"
    agentguard_timeout_seconds: float = 3.0
    agentguard_verify_tls: bool = True
    # Plaintext http:// to AgentGuard is refused in production unless this is set
    # (only for a private docker network; terminate TLS at the public edge).
    agentguard_allow_insecure_http: bool = False
    # python_exec_mode: disabled | isolated | unsafe_dev (unsafe_dev refused in production)
    python_exec_mode: str = "disabled"

    # Agent runtime
    agent_max_steps: int = 12
    agent_timeout_seconds: int = 120

    # Multi-agent orchestrator
    orchestrator_max_iterations: int = 3
    orchestrator_max_steps: int = 6
    orchestrator_output_dir: str = "orchestrator_output"

    # Safety guardrails / human-in-the-loop approval
    guardrails_enabled: bool = True
    guardrails_approval_table: str = "pending_approvals"
    guardrails_auto_approve: bool = False

    # REST API authentication (hashed API keys + per-key rate limiting)
    # When ``auth_enabled`` is False the middleware is a no-op, which is handy
    # for local development. Keys are ALWAYS stored hashed (SHA-256).
    auth_enabled: bool = True
    api_keys_table: str = "api_keys"
    api_key_prefix: str = "aql1_"
    # Requests allowed per key inside each rate-limit window.
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    # Routes that never require a key (health, docs, OpenAPI schema).
    # the whole ``/v1/billing/`` prefix is public at the middleware level; each
    # billing route authenticates itself (Supabase JWT or X-Admin-Token).
    auth_public_paths: str = (
        "/health,/docs,/redoc,/openapi.json,/docs/oauth2-redirect,"
        "/v1/billing/,/"
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def auth_public_path_list(self) -> list[str]:
        """Public (unauthenticated) route prefixes, parsed from the env var."""
        return [p.strip() for p in self.auth_public_paths.split(",") if p.strip()]

    @property
    def payoneer_configured(self) -> bool:
        """True when a Payoneer payee email is configured."""
        return bool(self.payoneer_email)


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
