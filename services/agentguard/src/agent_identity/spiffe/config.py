"""SPIFFE/SPIRE configuration with fail-closed validation and environment separation."""
import enum
import json
import os
from dataclasses import dataclass, field, fields
from typing import Tuple

from .errors import ConfigError
from .ids import parse_spiffe_id

ENV_VAR = "AGENTGUARD_ENV"
_PLACEHOLDER_TDS = {"agentguard.local", "example.org", "example.com", "localhost", "test", "dev"}
_ALLOWED_JWT_ALGS = ("ES256", "ES384", "ES512", "RS256", "RS384", "RS512",
                     "PS256", "PS384", "PS512")


class Environment(str, enum.Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class SpireConfig:
    environment: Environment = Environment.PRODUCTION     # safe default: strictest rules
    provider: str = "spire"                               # "spire" | "dev"
    trust_domain: str = ""                                # REQUIRED, no default
    socket_path: str = "unix:///run/spire/sockets/agent.sock"
    federated_trust_domains: Tuple[str, ...] = ()         # explicit allow-list only
    # --- timeouts / retries
    connect_timeout_seconds: float = 5.0
    rpc_timeout_seconds: float = 10.0
    retry_max_attempts: int = 3
    retry_initial_backoff_seconds: float = 0.2
    retry_max_backoff_seconds: float = 5.0
    # --- rotation
    rotation_threshold_fraction: float = 0.5      # refresh when <= this fraction of lifetime left
    rotation_min_remaining_seconds: int = 60      # ...or when this little time remains
    refresh_interval_seconds: float = 30.0        # background poll (also picks up bundle changes)
    # --- verification
    clock_skew_seconds: int = 30
    bundle_max_age_seconds: int = 3600            # stale bundle => deny
    jwt_allowed_algorithms: Tuple[str, ...] = ("ES256", "ES384", "RS256", "PS256")
    jwt_max_ttl_seconds: int = 3600
    jwt_expected_issuer: str = ""                 # optional: if set, 'iss' must equal it
    jwt_single_use: bool = False                  # default replay posture for verify()
    max_token_bytes: int = 8192
    require_instance_identity: bool = True        # agent-level SVID alone is not enough
    max_x509_chain_depth: int = 5
    # --- TLS for AgentGuard peer connections (mTLS built from the SVID; see tlsutil.py)
    tls_min_version: str = "TLSv1.3"              # TLSv1.2 | TLSv1.3
    # --- workload selection
    workload_selectors: Tuple[str, ...] = ()      # documentation/registration aid, e.g. unix:uid:1001

    def validate(self) -> "SpireConfig":
        if isinstance(self.environment, str):
            self.environment = Environment(self.environment)
        env = self.environment
        for name in ("federated_trust_domains", "jwt_allowed_algorithms", "workload_selectors"):
            v = getattr(self, name)
            if isinstance(v, list):
                setattr(self, name, tuple(v))
        if self.tls_min_version not in ("TLSv1.2", "TLSv1.3"):
            raise ConfigError("tls_min_version must be TLSv1.2 or TLSv1.3")
        if self.provider not in ("spire", "dev"):
            raise ConfigError("provider must be 'spire' or 'dev'")
        td = self.trust_domain
        if not td:
            raise ConfigError("trust_domain is required")
        parse_spiffe_id(f"spiffe://{td}")
        for f in self.federated_trust_domains:
            parse_spiffe_id(f"spiffe://{f}")
        if td in self.federated_trust_domains:
            raise ConfigError("own trust domain must not be listed as federated")
        if not set(self.jwt_allowed_algorithms) or not set(self.jwt_allowed_algorithms) <= set(_ALLOWED_JWT_ALGS):
            raise ConfigError("jwt_allowed_algorithms must be a non-empty subset of asymmetric SPIFFE algs")
        if not (0.05 <= self.rotation_threshold_fraction < 1.0):
            raise ConfigError("rotation_threshold_fraction must be in [0.05, 1.0)")
        if min(self.connect_timeout_seconds, self.rpc_timeout_seconds) <= 0:
            raise ConfigError("timeouts must be > 0")
        if self.retry_max_attempts < 1 or self.retry_initial_backoff_seconds < 0:
            raise ConfigError("invalid retry policy")
        if self.clock_skew_seconds < 0 or self.clock_skew_seconds > 300:
            raise ConfigError("clock_skew_seconds must be within 0..300")
        if self.bundle_max_age_seconds <= 0 or self.jwt_max_ttl_seconds <= 0:
            raise ConfigError("bundle_max_age_seconds / jwt_max_ttl_seconds must be > 0")
        # environment separation: the process environment can only make things stricter
        proc = os.environ.get(ENV_VAR, "").strip().lower()
        if proc:
            try:
                penv = Environment(proc)
            except ValueError:
                raise ConfigError(f"{ENV_VAR} must be development|staging|production")
            order = [Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION]
            if order.index(env) < order.index(penv):
                raise ConfigError(f"config environment '{env.value}' is weaker than {ENV_VAR}={proc}")
        if self.provider == "dev" and env != Environment.DEVELOPMENT:
            raise ConfigError("dev provider is only allowed in the development environment")
        if env != Environment.DEVELOPMENT:
            if td.lower() in _PLACEHOLDER_TDS:
                raise ConfigError("placeholder trust domain not allowed outside development")
            if not self.socket_path.startswith("unix:///"):
                raise ConfigError("Workload API must be a local unix socket (unix:///abs/path)")
            if self.clock_skew_seconds > 60:
                raise ConfigError("clock_skew_seconds > 60 not allowed outside development")
            if not self.require_instance_identity:
                raise ConfigError("require_instance_identity must be true outside development")
        return self

    @classmethod
    def from_dict(cls, d: dict) -> "SpireConfig":
        known = {f.name for f in fields(cls)}
        unknown = set(d) - known
        if unknown:
            raise ConfigError(f"unknown config keys: {sorted(unknown)}")
        return cls(**d).validate()

    @classmethod
    def from_file(cls, path: str) -> "SpireConfig":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    @classmethod
    def from_env(cls) -> "SpireConfig":
        """Production-style: everything from env; nothing secret is needed (SPIRE uses peer
        credentials on the unix socket, so there is no password/key to configure)."""
        d = {"environment": os.environ.get(ENV_VAR, "production").lower(),
             "trust_domain": os.environ.get("AGENTGUARD_SPIFFE_TRUST_DOMAIN", ""),
             "socket_path": os.environ.get("SPIFFE_ENDPOINT_SOCKET",
                                           "unix:///run/spire/sockets/agent.sock")}
        fed = os.environ.get("AGENTGUARD_SPIFFE_FEDERATED_DOMAINS", "")
        if fed:
            d["federated_trust_domains"] = tuple(x for x in fed.split(",") if x)
        return cls.from_dict(d)
