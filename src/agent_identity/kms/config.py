"""KMS/HSM configuration: environment-based, secrets by reference, dev-vs-prod enforced.

Mirrors the existing config style (PgConfig / SpireConfig): the process environment can
only TIGHTEN the effective environment, and production silently falling back to the
development software provider is treated as a configuration error, not a warning.
"""
import os
from dataclasses import dataclass, field
from typing import Optional

from ..spiffe.config import ENV_VAR, Environment
from .errors import KmsConfigError

PROVIDERS = ("local", "vault", "pkcs11")


@dataclass
class KmsConfig:
    environment: Environment = Environment.PRODUCTION      # strictest by default
    provider: str = "local"                                # local | vault | pkcs11

    # -- policy switches (each is an explicit, auditable opt-out) --
    allow_local_in_production: bool = False    # permits the dev provider outside development
    allow_exportable_keys: bool = False        # permits non-exportable custody to be relaxed

    key_id_prefix: str = "agentguard"          # provider-side name prefix (vault/pkcs11)

    # -- HashiCorp Vault Transit --
    vault_addr: str = ""
    vault_token: str = field(default="", repr=False)
    vault_token_file: str = ""                 # e.g. a mounted Kubernetes secret
    vault_namespace: str = ""
    vault_mount: str = "transit"
    vault_tls_verify: bool = True
    vault_ca_cert: str = ""

    # -- PKCS#11 HSM --
    pkcs11_library: str = ""                   # path to the PKCS#11 module (.so)
    pkcs11_token_label: str = ""
    pkcs11_slot: Optional[int] = None
    pkcs11_pin: str = field(default="", repr=False)
    pkcs11_pin_file: str = ""

    # -- transport policy --
    timeout_seconds: float = 5.0
    retry_max_attempts: int = 3
    retry_initial_backoff_seconds: float = 0.05
    retry_max_backoff_seconds: float = 0.5

    # -- rotation defaults --
    rotate_grace_seconds: int = 7200           # overlap during which both keys verify

    def validate(self) -> "KmsConfig":
        if isinstance(self.environment, str):
            self.environment = Environment(self.environment)
        if self.provider not in PROVIDERS:
            raise KmsConfigError(f"provider must be one of {PROVIDERS}")
        if not (0 < self.timeout_seconds <= 120):
            raise KmsConfigError("timeout_seconds must be in (0, 120]")
        if self.retry_max_attempts < 1 or self.retry_initial_backoff_seconds < 0:
            raise KmsConfigError("invalid retry policy")
        if self.rotate_grace_seconds < 0:
            raise KmsConfigError("rotate_grace_seconds must be >= 0")

        # The process environment can only tighten.
        proc = os.environ.get(ENV_VAR, "").strip().lower()
        if proc:
            try:
                penv = Environment(proc)
            except ValueError:
                raise KmsConfigError(f"{ENV_VAR} must be development|staging|production")
            order = [Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION]
            if order.index(self.environment) < order.index(penv):
                raise KmsConfigError(f"config environment is weaker than {ENV_VAR}={proc}")

        if self.environment != Environment.DEVELOPMENT:
            if self.provider == "local" and not self.allow_local_in_production:
                raise KmsConfigError(
                    "the local software key provider is development/test only; outside "
                    "development configure provider='vault' or 'pkcs11' "
                    "(or set allow_local_in_production=True to accept the risk explicitly)")
            if self.allow_exportable_keys:
                raise KmsConfigError("exportable keys are not allowed outside development")

        if self.provider == "vault":
            if not self.vault_addr:
                raise KmsConfigError("vault provider requires vault_addr")
            if not (self.vault_token or self.vault_token_file):
                raise KmsConfigError("vault provider requires vault_token or vault_token_file")
            if self.environment != Environment.DEVELOPMENT:
                if not self.vault_addr.lower().startswith("https://"):
                    raise KmsConfigError("vault_addr must use https outside development")
                if not self.vault_tls_verify:
                    raise KmsConfigError("vault_tls_verify cannot be disabled outside development")

        if self.provider == "pkcs11":
            if not self.pkcs11_library:
                raise KmsConfigError("pkcs11 provider requires pkcs11_library")
            if not self.pkcs11_token_label and self.pkcs11_slot is None:
                raise KmsConfigError("pkcs11 provider requires pkcs11_token_label or pkcs11_slot")
            if not (self.pkcs11_pin or self.pkcs11_pin_file):
                raise KmsConfigError("pkcs11 provider requires pkcs11_pin or pkcs11_pin_file")
        return self

    # ------------------------------------------------------------------ resolution
    def resolve_vault_token(self) -> str:
        if self.vault_token_file:
            with open(self.vault_token_file, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        return self.vault_token

    def resolve_pkcs11_pin(self) -> str:
        if self.pkcs11_pin_file:
            with open(self.pkcs11_pin_file, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        return self.pkcs11_pin

    def safe_dict(self) -> dict:
        """Config with every secret replaced by a marker — safe to log or return over HTTP."""
        d = {k: v for k, v in self.__dict__.items()
             if k not in ("vault_token", "pkcs11_pin")}
        d["environment"] = getattr(self.environment, "value", self.environment)
        d["vault_token"] = "<set>" if self.vault_token else ""
        d["vault_token_file"] = "<set>" if self.vault_token_file else ""
        d["pkcs11_pin"] = "<set>" if self.pkcs11_pin else ""
        d["pkcs11_pin_file"] = "<set>" if self.pkcs11_pin_file else ""
        return d

    @classmethod
    def from_env(cls, env=None) -> "KmsConfig":
        e = os.environ if env is None else env

        def g(k, d=""):
            return e.get("AGENTGUARD_KMS_" + k, d)

        def gi(k, d):
            try:
                return int(g(k, str(d)))
            except ValueError:
                raise KmsConfigError(f"AGENTGUARD_KMS_{k} must be an integer")

        def gt(k):
            return g(k, "").lower() in ("1", "true", "yes")

        slot = e.get("AGENTGUARD_KMS_PKCS11_SLOT")
        return cls(
            environment=(e.get(ENV_VAR) or "production").lower(),
            provider=g("PROVIDER", "local"),
            allow_local_in_production=gt("ALLOW_LOCAL_IN_PRODUCTION"),
            allow_exportable_keys=gt("ALLOW_EXPORTABLE_KEYS"),
            key_id_prefix=g("KEY_ID_PREFIX", "agentguard"),
            vault_addr=g("VAULT_ADDR"),
            vault_token=g("VAULT_TOKEN"),
            vault_token_file=g("VAULT_TOKEN_FILE"),
            vault_namespace=g("VAULT_NAMESPACE"),
            vault_mount=g("VAULT_MOUNT", "transit"),
            vault_tls_verify=not gt("VAULT_TLS_SKIP_VERIFY"),
            vault_ca_cert=g("VAULT_CA_CERT"),
            pkcs11_library=g("PKCS11_LIBRARY"),
            pkcs11_token_label=g("PKCS11_TOKEN_LABEL"),
            pkcs11_slot=int(slot) if slot else None,
            pkcs11_pin=g("PKCS11_PIN"),
            pkcs11_pin_file=g("PKCS11_PIN_FILE"),
            timeout_seconds=float(g("TIMEOUT_SECONDS", "5")),
            retry_max_attempts=gi("RETRY_MAX_ATTEMPTS", 3),
            rotate_grace_seconds=gi("ROTATE_GRACE_SECONDS", 7200),
        ).validate()
