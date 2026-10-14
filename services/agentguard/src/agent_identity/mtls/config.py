"""mTLS configuration with fail-closed validation and explicit environment separation.

Reuses spiffe.config.Environment / ENV_VAR so there is ONE environment model. The process
environment (AGENTGUARD_ENV) can only make validation stricter, never weaker.
"""
import json
import os
from dataclasses import dataclass, fields
from typing import Tuple

from ..spiffe.config import ENV_VAR, Environment
from ..spiffe.errors import SpiffeIdError
from ..spiffe.ids import parse_spiffe_id
from .errors import MtlsConfigError

# TLS<=1.2 suites: ECDHE (forward secrecy) + AEAD only. No CBC, RC4, 3DES, static RSA/DH, SHA-1.
SAFE_TLS12_CIPHERS = ("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
                      "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
                      "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256")
_ORDER = [Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION]


def _tup(v):
    if isinstance(v, list):
        return tuple(v)
    return v


@dataclass
class MtlsConfig:
    environment: Environment = Environment.PRODUCTION
    # --- own workload identity (the SPIFFE ID of THIS service's SVID, issued by real SPIRE)
    workload_spiffe_id: str = ""
    # --- TLS
    min_tls_version: str = "TLSv1.3"               # TLSv1.2 | TLSv1.3
    tls12_ciphers: Tuple[str, ...] = SAFE_TLS12_CIPHERS
    # --- listener
    listen_host: str = "127.0.0.1"
    listen_port: int = 8443
    handshake_timeout_seconds: float = 5.0
    connect_timeout_seconds: float = 5.0
    max_concurrent_connections: int = 256
    shutdown_grace_seconds: float = 10.0
    # --- credential lifecycle
    expiry_warning_seconds: int = 900              # emit expiry warnings / readiness degraded
    min_ready_remaining_seconds: int = 30          # readiness fails if own SVID has less than this
    bundle_refresh_interval_seconds: float = 30.0  # poll SPIRE for trust-bundle changes
    # --- policy / validation
    require_eku: bool = True                       # leaf must carry serverAuth/clientAuth as needed
    policy_max_age_seconds: int = 0                # 0 = signed policy never auto-expires by age
    # --- development-only escapes (rejected outside development)
    allow_plaintext: bool = False

    def validate(self) -> "MtlsConfig":
        if isinstance(self.environment, str):
            try:
                self.environment = Environment(self.environment)
            except ValueError:
                raise MtlsConfigError("environment must be development|staging|production") from None
        self.tls12_ciphers = _tup(self.tls12_ciphers)
        env = self.environment
        if self.min_tls_version not in ("TLSv1.2", "TLSv1.3"):
            raise MtlsConfigError("min_tls_version must be TLSv1.2 or TLSv1.3")
        if not self.tls12_ciphers or any(c not in SAFE_TLS12_CIPHERS for c in self.tls12_ciphers):
            raise MtlsConfigError("tls12_ciphers must be a non-empty subset of the AEAD+ECDHE allow-list")
        try:
            sid = parse_spiffe_id(self.workload_spiffe_id)
            if not sid.path:
                raise SpiffeIdError("trust-domain id")
        except SpiffeIdError:
            raise MtlsConfigError("workload_spiffe_id must be a valid workload SPIFFE ID") from None
        if not (0 < self.listen_port < 65536):
            raise MtlsConfigError("listen_port out of range")
        if min(self.handshake_timeout_seconds, self.connect_timeout_seconds) <= 0 \
                or self.handshake_timeout_seconds > 30:
            raise MtlsConfigError("timeouts must be >0 (handshake <=30s)")
        if self.max_concurrent_connections < 1 or self.shutdown_grace_seconds < 0:
            raise MtlsConfigError("invalid connection limits")
        if self.bundle_refresh_interval_seconds <= 0:
            raise MtlsConfigError("bundle_refresh_interval_seconds must be > 0")
        if self.expiry_warning_seconds < 0 or self.min_ready_remaining_seconds < 0:
            raise MtlsConfigError("invalid expiry thresholds")
        proc = os.environ.get(ENV_VAR, "").strip().lower()
        if proc:
            try:
                penv = Environment(proc)
            except ValueError:
                raise MtlsConfigError(f"{ENV_VAR} must be development|staging|production") from None
            if _ORDER.index(env) < _ORDER.index(penv):
                raise MtlsConfigError(f"config environment '{env.value}' is weaker than {ENV_VAR}={proc}")
        if env is not Environment.DEVELOPMENT:
            if self.allow_plaintext:
                raise MtlsConfigError("allow_plaintext is development-only")
            if not self.require_eku:
                raise MtlsConfigError("require_eku must be true outside development")
            if self.min_ready_remaining_seconds < 5:
                raise MtlsConfigError("min_ready_remaining_seconds must be >= 5 outside development")
        return self

    @property
    def own_trust_domain(self) -> str:
        return parse_spiffe_id(self.workload_spiffe_id).trust_domain

    @classmethod
    def from_dict(cls, d: dict) -> "MtlsConfig":
        known = {f.name for f in fields(cls)}
        unknown = set(d) - known
        if unknown:
            raise MtlsConfigError(f"unknown config keys: {sorted(unknown)}")
        return cls(**d).validate()

    @classmethod
    def from_file(cls, path: str) -> "MtlsConfig":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    @classmethod
    def from_env(cls) -> "MtlsConfig":
        """No secret is needed: key material comes from SPIRE over the local Workload API."""
        e = os.environ
        d = {"environment": e.get(ENV_VAR, "production").lower(),
             "workload_spiffe_id": e.get("AGENTGUARD_MTLS_SPIFFE_ID", "")}
        for env_name, key, cast in (("AGENTGUARD_MTLS_MIN_TLS", "min_tls_version", str),
                                    ("AGENTGUARD_MTLS_LISTEN_HOST", "listen_host", str),
                                    ("AGENTGUARD_MTLS_LISTEN_PORT", "listen_port", int),
                                    ("AGENTGUARD_MTLS_MAX_CONNECTIONS", "max_concurrent_connections", int)):
            if env_name in e:
                d[key] = cast(e[env_name])
        return cls.from_dict(d)
