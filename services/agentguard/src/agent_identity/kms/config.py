"""KMS configuration: environment-driven, provider selection, strict production guards.

Mirrors the conventions already used by ``PgConfig``/``RedisConfig``: secrets by reference (env or
``_FILE``), TLS/endpoint settings, bounded timeouts and retries, and a process-environment guard so
a development provider can never be selected silently in production.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from typing import Optional, Tuple

from ..spiffe.config import ENV_VAR, Environment
from .errors import KmsConfigError

_ORDER = [Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION]
PROVIDERS = ("local-dev", "aws-kms", "pkcs11")
#: providers that are only acceptable in the development environment
DEV_ONLY_PROVIDERS = ("local-dev",)


def _coerce_env(v) -> Environment:
    if isinstance(v, Environment):
        return v
    try:
        return Environment(str(v).lower())
    except ValueError:
        raise KmsConfigError(f"{ENV_VAR} must be development|staging|production")


@dataclass
class KmsConfig:
    environment: Environment = Environment.PRODUCTION     # strictest by default
    provider: str = "local-dev"                            # local-dev | aws-kms | pkcs11
    # --- AWS KMS
    region: str = ""
    endpoint_url: str = ""                                # e.g. a VPC endpoint; empty => AWS default
    aws_profile: str = ""                                 # optional named profile / role
    # --- PKCS#11 / HSM
    module_path: str = ""                                 # path to the PKCS#11 .so
    token_label: str = ""
    slot: Optional[int] = None
    pin_file: str = ""                                    # preferred: mounted secret file
    # --- rotation / lifecycle
    rotation_interval_seconds: int = 30 * 24 * 3600       # default: rotate issuer keys every 30 days
    retire_overlap_seconds: int = 7200                    # how long a retiring key still verifies
    pending_deletion_days: int = 7                         # AWS KMS minimum window
    # --- timeouts / retries
    connect_timeout_seconds: float = 5.0
    command_timeout_seconds: float = 5.0
    retry_max_attempts: int = 3
    retry_initial_backoff_seconds: float = 0.05
    retry_max_backoff_seconds: float = 1.0
    # --- policy
    require_health_check: bool = True                      # refuse a provider that fails its probe
    allow_export_in_dev: bool = True                       # only honoured for local-dev
    require_tls: bool = True                               # endpoint must be TLS outside development

    def validate(self) -> "KmsConfig":
        self.environment = _coerce_env(self.environment)
        if self.provider not in PROVIDERS:
            raise KmsConfigError(f"provider must be one of {PROVIDERS}")
        if min(self.connect_timeout_seconds, self.command_timeout_seconds) <= 0:
            raise KmsConfigError("timeouts must be > 0")
        if self.retry_max_attempts < 1 or self.retry_initial_backoff_seconds < 0:
            raise KmsConfigError("invalid retry policy")
        if self.retire_overlap_seconds < 0 or self.rotation_interval_seconds < 0:
            raise KmsConfigError("invalid rotation policy")
        if not (7 <= self.pending_deletion_days <= 365):
            raise KmsConfigError("pending_deletion_days must be within 7..365 (AWS KMS minimum is 7)")
        if self.provider == "pkcs11":
            if not self.module_path:
                raise KmsConfigError("pkcs11 requires module_path")
            if self.slot is None and not self.token_label:
                # tolerated (falls back to the default token) but flagged
                pass
        # the process environment can only make things STRICTER (same rule as PgConfig/RedisConfig)
        proc_raw = os.environ.get(ENV_VAR, "").strip().lower()
        if proc_raw:
            proc = _coerce_env(proc_raw)
            if _ORDER.index(self.environment) < _ORDER.index(proc):
                raise KmsConfigError(f"config environment is weaker than {ENV_VAR}={proc_raw}")
        # dev-only provider / export are forbidden outside development
        if self.environment != Environment.DEVELOPMENT:
            if self.provider in DEV_ONLY_PROVIDERS:
                raise KmsConfigError(
                    "local-dev key provider is only allowed in the development environment; "
                    "select 'aws-kms' or 'pkcs11' for staging/production")
            if self.allow_export_in_dev:
                self.allow_export_in_dev = False           # export is meaningless for real providers
            if self.endpoint_url and self.require_tls and not self.endpoint_url.startswith("https://"):
                raise KmsConfigError("KMS endpoint must use TLS outside development")
            if self.provider == "aws-kms" and not self.region:
                raise KmsConfigError("aws-kms requires a region outside development")
        return self

    def safe_dict(self) -> dict:
        """Never returns secrets; ``pin_file`` is reduced to a presence flag."""
        d = {k: v for k, v in self.__dict__.items() if k != "pin_file"}
        d["environment"] = self.environment.value
        d["pin_file"] = "<set>" if self.pin_file else ""
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "KmsConfig":
        known = {f.name for f in fields(cls)}
        unknown = set(d) - known
        if unknown:
            raise KmsConfigError(f"unknown config keys: {sorted(unknown)}")
        return cls(**d).validate()

    @classmethod
    def from_env(cls, env=None) -> "KmsConfig":
        e = os.environ if env is None else env

        def g(k, d=""):
            return e.get("AGENTGUARD_KMS_" + k, d)

        def num(k, d, t=float):
            raw = g(k, "")
            if raw == "":
                return t(d)
            try:
                return t(raw)
            except ValueError:
                raise KmsConfigError(f"AGENTGUARD_KMS_{k} must be a number")

        slot = g("PKCS11_SLOT", "")
        return cls(
            environment=(e.get(ENV_VAR) or "production").lower(),
            provider=g("PROVIDER", "aws-kms"),
            region=g("REGION"), endpoint_url=g("ENDPOINT_URL"), aws_profile=g("AWS_PROFILE"),
            module_path=g("PKCS11_MODULE"), token_label=g("PKCS11_TOKEN_LABEL"),
            slot=(int(slot) if slot != "" else None), pin_file=g("PKCS11_PIN_FILE"),
            rotation_interval_seconds=num("ROTATION_INTERVAL_SECONDS", 30 * 24 * 3600, int),
            retire_overlap_seconds=num("RETIRE_OVERLAP_SECONDS", 7200, int),
            pending_deletion_days=num("PENDING_DELETION_DAYS", 7, int),
            connect_timeout_seconds=num("CONNECT_TIMEOUT_S", 5.0, float),
            command_timeout_seconds=num("COMMAND_TIMEOUT_S", 5.0, float),
            retry_max_attempts=num("RETRY_MAX_ATTEMPTS", 3, int),
            retry_initial_backoff_seconds=num("RETRY_INITIAL_BACKOFF_S", 0.05, float),
            retry_max_backoff_seconds=num("RETRY_MAX_BACKOFF_S", 1.0, float),
            require_health_check=(g("REQUIRE_HEALTH_CHECK", "1") == "1"),
            require_tls=(g("REQUIRE_TLS", "1") == "1"),
        ).validate()
