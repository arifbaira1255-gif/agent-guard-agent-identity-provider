import json
from dataclasses import dataclass, fields


@dataclass
class IdentityConfig:
    trust_domain: str = "agentguard.local"
    credential_ttl_seconds: int = 900          # default short-lived credential: 15 min
    min_credential_ttl_seconds: int = 30
    max_credential_ttl_seconds: int = 3600     # hard ceiling: no permanent credentials
    clock_skew_seconds: int = 30
    proof_max_age_seconds: int = 60            # freshness window for possession proofs
    require_proof: bool = True                 # require nonce-bound proof of possession
    replay_cache_max_entries: int = 500_000
    max_token_bytes: int = 8192
    max_sub_agent_depth: int = 5
    require_spawn_capability: bool = True      # parent must hold "agent:spawn"
    rotation_grace_seconds: int = 60           # old credential overlap on rotation
    issuer_rotation_overlap_seconds: int = 7200
    log_to_python_logging: bool = True

    def validate(self) -> "IdentityConfig":
        if not (0 < self.min_credential_ttl_seconds <= self.credential_ttl_seconds
                <= self.max_credential_ttl_seconds):
            raise ValueError("require 0 < min_ttl <= default_ttl <= max_ttl")
        if self.max_credential_ttl_seconds > 86400:
            raise ValueError("max_credential_ttl_seconds must be <= 86400")
        if self.clock_skew_seconds < 0 or self.proof_max_age_seconds <= 0:
            raise ValueError("invalid skew/proof window")
        if self.max_sub_agent_depth < 1:
            raise ValueError("max_sub_agent_depth must be >= 1")
        return self

    @classmethod
    def from_dict(cls, d: dict) -> "IdentityConfig":
        known = {f.name for f in fields(cls)}
        unknown = set(d) - known
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        return cls(**d).validate()

    @classmethod
    def from_file(cls, path: str) -> "IdentityConfig":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))
