"""SDK configuration. Fail-closed defaults: TLS verification ON, bounded timeouts, bounded retries.

No credential, token or private key is ever part of the configuration object. The only secret the
SDK holds is the agent's own ephemeral private key, which lives inside an ``AgentSideKey`` and is
never serialised, logged or sent to the server (only its public key + a proof of possession are).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Optional

from .errors import ConfigurationError

SDK_VERSION = "0.2.0"


@dataclass(frozen=True)
class SdkConfig:
    base_url: str
    environment: str = "development"

    # --- transport ---
    timeout_seconds: float = 10.0
    max_retries: int = 3
    retry_base_seconds: float = 0.1
    retry_max_seconds: float = 2.0
    max_response_bytes: int = 1_048_576
    user_agent: str = f"agentguard-python-sdk/{SDK_VERSION}"

    # --- TLS / server identity ---
    verify_tls: bool = True
    ca_bundle: Optional[str] = None
    client_cert: Optional[str] = None               # mTLS (PEM cert chain)
    client_key: Optional[str] = None                # mTLS (PEM private key)

    # --- protocol ---
    default_audience: str = "agentguard-control-plane"
    tool_audience: str = "agentguard:tool"
    credential_renewal_skew_seconds: int = 60
    default_credential_ttl_seconds: Optional[int] = None

    # --- provisioning ---
    #: Bearer token used ONLY for control-plane bootstrap calls (register agent, create instance,
    #: issue credential). It is a provisioning credential, never the agent's own identity, and is
    #: read from the environment (``AGENTGUARD_CONTROL_PLANE_TOKEN``) \u2014 never hard-coded.
    control_plane_token: Optional[str] = field(default=None, repr=False)

    def __post_init__(self):
        if not isinstance(self.base_url, str) or not self.base_url:
            raise ConfigurationError("base_url is required")
        if not (self.base_url.startswith("http://") or self.base_url.startswith("https://")):
            raise ConfigurationError("base_url must be an absolute http(s) URL")
        if self.environment not in ("development", "staging", "production"):
            raise ConfigurationError("environment must be development|staging|production")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 300:
            raise ConfigurationError("timeout_seconds must be in (0, 300]")
        if self.max_retries < 0 or self.max_retries > 10:
            raise ConfigurationError("max_retries must be in [0, 10]")
        if self.retry_base_seconds <= 0 or self.retry_max_seconds < self.retry_base_seconds:
            raise ConfigurationError("invalid retry backoff bounds")
        if self.credential_renewal_skew_seconds < 0:
            raise ConfigurationError("credential_renewal_skew_seconds must be >= 0")
        # Fail closed: disabling TLS verification is a development-only escape hatch.
        if not self.verify_tls and self.environment != "development":
            raise ConfigurationError("verify_tls=False is only permitted in development")
        if self.environment == "production" and self.base_url.startswith("http://"):
            raise ConfigurationError("plaintext http:// is not permitted in production")
        if (self.client_cert is None) != (self.client_key is None):
            raise ConfigurationError("client_cert and client_key must be provided together")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def with_overrides(self, **kwargs) -> "SdkConfig":
        return replace(self, **kwargs)

    @classmethod
    def from_env(cls, **overrides) -> "SdkConfig":
        env = os.environ.get("AGENTGUARD_ENV", "development").strip().lower() or "development"
        base = cls(
            base_url=os.environ.get("AGENTGUARD_BASE_URL", "http://127.0.0.1:8443"),
            environment=env,
            verify_tls=(os.environ.get("AGENTGUARD_VERIFY_TLS", "true").lower()
                        not in ("0", "false", "no")),
            ca_bundle=os.environ.get("AGENTGUARD_CA_BUNDLE") or None,
            client_cert=os.environ.get("AGENTGUARD_CLIENT_CERT") or None,
            client_key=os.environ.get("AGENTGUARD_CLIENT_KEY") or None,
            control_plane_token=os.environ.get("AGENTGUARD_CONTROL_PLANE_TOKEN") or None,
        )
        return base.with_overrides(**overrides) if overrides else base
