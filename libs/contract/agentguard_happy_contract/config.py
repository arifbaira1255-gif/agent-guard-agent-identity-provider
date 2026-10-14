"""Feature flags and configuration for the AgentGuard x Happy LANG integration.

DEFAULT IS OFF.  With ``HAPPY_AGENTGUARD_ENABLED`` unset (or false) the integration is completely
inert: Happy LANG runs exactly as it did before this package was installed, and AgentGuard is never
contacted.  That is what makes the integration safe to ship into an existing AgentGuard deployment
-- it cannot destabilise anything until an operator opts in.

When the integration IS enabled, every failure mode fails CLOSED: an unreachable or misconfigured
AgentGuard denies, it never allows.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Optional

from .errors import ValidationError

#: Accepted spellings for a boolean environment flag.
_TRUTHY = ("1", "true", "yes", "on")
_FALSY = ("0", "false", "no", "off")

#: Authorization enforcement modes.
#:   enforce -> a non-ALLOW decision raises (the default, and the only safe setting in production)
#:   audit   -> the decision is recorded and reported, but execution continues (migration only)
#:   off     -> remote authorization is skipped entirely (local checks still apply)
MODES = ("enforce", "audit", "off")

_ENVIRONMENTS = ("development", "staging", "production")


def env_flag(name: str, default: bool = False) -> bool:
    """Read a boolean environment flag (unknown values fall back to ``default``)."""
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


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class IntegrationConfig:
    """Resolved configuration for the integration."""

    # --- master switch ---------------------------------------------------------------------
    enabled: bool = False

    # --- AgentGuard endpoint ---------------------------------------------------------------
    base_url: str = "http://127.0.0.1:8443"
    environment: str = "development"
    authorize_path: str = "/v1/authorize"
    events_path: str = "/v1/security/events"
    egress_path: str = "/v1/egress/request"
    audience: str = "agentguard:tool"

    # --- identity (populated from the verified credential when a token is available) --------
    agent_id: Optional[str] = None
    instance_id: Optional[str] = None
    org_id: Optional[str] = None
    agent_scope: Optional[str] = None

    # --- transport / bounds ----------------------------------------------------------------
    timeout_seconds: float = 5.0
    verify_tls: bool = True
    ca_bundle: Optional[str] = None
    max_response_bytes: int = 65536
    allow_insecure_http: bool = False
    control_plane_token: Optional[str] = field(default=None, repr=False)

    # --- behaviour -------------------------------------------------------------------------
    mode: str = "enforce"
    route_egress: bool = False
    require_isolation: bool = False
    emit_events: bool = True
    max_events_buffer: int = 100
    default_resource: str = "unspecified"

    # --- secure execution runtime (M2) ------------------------------------------------------
    #: Install a deny-by-default checker into every ``happy.std`` module while the integration is
    #: active.  This closes the ``_CHECKER is None`` bypass; leave it on unless you have a reason.
    install_std_guard: bool = True
    #: Isolation mode for the jailed runtime: ``required`` (fail closed), ``auto``, or ``off``.
    isolation_mode: str = "auto"
    #: Isolation backend: ``auto``, ``docker``, ``podman``, ``bwrap`` or ``namespaces``.
    isolation_backend: str = "auto"
    #: Execution workers and the bounded queue that feeds them (backpressure, not unbounded growth).
    max_concurrency: int = 2
    queue_capacity: int = 8

    def __post_init__(self) -> None:
        errors = []
        if not isinstance(self.base_url, str) or not (
                self.base_url.startswith("http://") or self.base_url.startswith("https://")):
            errors.append("base_url must be an absolute http(s) URL")
        if self.environment not in _ENVIRONMENTS:
            errors.append(f"environment must be one of {list(_ENVIRONMENTS)}")
        if self.mode not in MODES:
            errors.append(f"mode must be one of {list(MODES)}")
        if not (0 < float(self.timeout_seconds) <= 60):
            errors.append("timeout_seconds must be in (0, 60]")
        if int(self.max_response_bytes) <= 0 or int(self.max_response_bytes) > 8 * 1024 * 1024:
            errors.append("max_response_bytes must be in (0, 8388608]")
        if self.isolation_mode not in ("required", "auto", "off"):
            errors.append("isolation_mode must be one of ['required', 'auto', 'off']")
        if self.isolation_backend not in ("auto", "docker", "podman", "bwrap", "namespaces"):
            errors.append("isolation_backend must be one of ['auto', 'docker', 'podman', 'bwrap', "
                          "'namespaces']")
        if not (1 <= int(self.max_concurrency) <= 64):
            errors.append("max_concurrency must be in [1, 64]")
        if not (0 <= int(self.queue_capacity) <= 1024):
            errors.append("queue_capacity must be in [0, 1024]")
        if errors:
            raise ValidationError("invalid integration configuration", errors=errors)
        # Fail closed on transport security, mirroring the AgentGuard SDK's own rule.
        if self.environment == "production" and self.base_url.startswith("http://") \
                and not self.allow_insecure_http:
            raise ValidationError(
                "plaintext http:// is not permitted in production "
                "(set allow_insecure_http=True only for a TLS-terminating sidecar)",
                field="base_url")
        if self.environment == "production" and not self.verify_tls:
            raise ValidationError("verify_tls=False is not permitted in production",
                                  field="verify_tls")

    # -- derived ----------------------------------------------------------------------------
    @property
    def is_enabled(self) -> bool:
        return bool(self.enabled)

    @property
    def enforcing(self) -> bool:
        return self.enabled and self.mode == "enforce"

    def authorize_url(self) -> str:
        return self.base_url.rstrip("/") + self.authorize_path

    def events_url(self) -> str:
        return self.base_url.rstrip("/") + self.events_path

    def egress_url(self) -> str:
        return self.base_url.rstrip("/") + self.egress_path

    def with_overrides(self, **kwargs) -> "IntegrationConfig":
        return replace(self, **kwargs)

    # -- environment --------------------------------------------------------------------------
    @classmethod
    def from_env(cls, **overrides) -> "IntegrationConfig":
        """Build the configuration from ``HAPPY_AGENTGUARD_*`` environment variables.

        The integration is OFF unless ``HAPPY_AGENTGUARD_ENABLED`` is truthy.
        """
        base = cls(
            enabled=env_flag("HAPPY_AGENTGUARD_ENABLED", False),
            base_url=env_str("HAPPY_AGENTGUARD_BASE_URL", "http://127.0.0.1:8443"),
            environment=env_str("HAPPY_AGENTGUARD_ENV", "development"),
            authorize_path=env_str("HAPPY_AGENTGUARD_AUTHORIZE_PATH", "/v1/authorize"),
            events_path=env_str("HAPPY_AGENTGUARD_EVENTS_PATH", "/v1/security/events"),
            egress_path=env_str("HAPPY_AGENTGUARD_EGRESS_PATH", "/v1/egress/request"),
            audience=env_str("HAPPY_AGENTGUARD_AUDIENCE", "agentguard:tool"),
            agent_id=env_str("HAPPY_AGENTGUARD_AGENT_ID"),
            instance_id=env_str("HAPPY_AGENTGUARD_INSTANCE_ID"),
            org_id=env_str("HAPPY_AGENTGUARD_ORG_ID"),
            agent_scope=env_str("HAPPY_AGENTGUARD_SCOPE"),
            timeout_seconds=env_float("HAPPY_AGENTGUARD_TIMEOUT_SECONDS", 5.0),
            verify_tls=env_flag("HAPPY_AGENTGUARD_VERIFY_TLS", True),
            ca_bundle=env_str("HAPPY_AGENTGUARD_CA_BUNDLE"),
            max_response_bytes=env_int("HAPPY_AGENTGUARD_MAX_RESPONSE_BYTES", 65536),
            allow_insecure_http=env_flag("HAPPY_AGENTGUARD_ALLOW_INSECURE_HTTP", False),
            control_plane_token=env_str("AGENTGUARD_CONTROL_PLANE_TOKEN"),
            mode=env_str("HAPPY_AGENTGUARD_MODE", "enforce"),
            route_egress=env_flag("HAPPY_AGENTGUARD_ROUTE_EGRESS", False),
            require_isolation=env_flag("HAPPY_AGENTGUARD_REQUIRE_ISOLATION", False),
            emit_events=env_flag("HAPPY_AGENTGUARD_EMIT_EVENTS", True),
            max_events_buffer=env_int("HAPPY_AGENTGUARD_MAX_EVENTS_BUFFER", 100),
            default_resource=env_str("HAPPY_AGENTGUARD_DEFAULT_RESOURCE", "unspecified"),
            install_std_guard=env_flag("HAPPY_AGENTGUARD_INSTALL_STD_GUARD", True),
            isolation_mode=env_str("HAPPY_AGENTGUARD_ISOLATION_MODE", "auto"),
            isolation_backend=env_str("HAPPY_AGENTGUARD_ISOLATION_BACKEND", "auto"),
            max_concurrency=env_int("HAPPY_AGENTGUARD_MAX_CONCURRENCY", 2),
            queue_capacity=env_int("HAPPY_AGENTGUARD_QUEUE_CAPACITY", 8),
        )
        return base.with_overrides(**overrides) if overrides else base


__all__ = ["IntegrationConfig", "MODES", "env_flag", "env_str", "env_float", "env_int"]
