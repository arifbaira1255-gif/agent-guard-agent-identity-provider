"""Contract version constants and the additive-only evolution rule.

The integration contract is consumed by two independently-released projects.  It is therefore
versioned explicitly, and both sides refuse to proceed when the version is not mutually
supported -- a version mismatch must be a loud, fail-closed error, never a silent guess.
"""
from __future__ import annotations

from typing import Optional, Tuple

from .errors import UnsupportedContractVersion

#: Machine name of this contract (used in envelopes and log/audit records).
CONTRACT_NAME = "agentguard-happy-contract"

#: Current contract version.  Bump ONLY for a breaking change (see EVOLUTION_RULE).
CONTRACT_VERSION = "1.0.0"

#: Schema identifier for the v1 payload family.
SCHEMA_ID = "agentguard-happy-contract/v1"

#: Every version this build can speak.  Additive changes do NOT add entries.
SUPPORTED_CONTRACT_VERSIONS: Tuple[str, ...] = ("1.0.0",)

#: The rule both projects agree to.  Documented here because it is part of the contract, not an
#: implementation detail of either side.
EVOLUTION_RULE = (
    "The contract evolves ADDITIVELY ONLY: new fields MUST be optional, unknown fields MUST be "
    "ignored by both sides, and no existing field may change type or meaning. Any change that "
    "violates this requires a new CONTRACT_VERSION plus a corresponding entry in "
    "SUPPORTED_CONTRACT_VERSIONS. The 'happy' block is a namespaced extension of AgentGuard's "
    "existing POST /v1/authorize body; AgentGuard treats every field of it as UNTRUSTED input and "
    "never lets it grant anything on its own."
)


def parse_version(value: str) -> Tuple[int, int, int]:
    """Parse a strict ``MAJOR.MINOR.PATCH`` string."""
    parts = str(value).strip().split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise UnsupportedContractVersion(f"malformed contract version {value!r}",
                                        field="contract_version")
    return int(parts[0]), int(parts[1]), int(parts[2])


def is_supported(value: Optional[str]) -> bool:
    """True when ``value`` is a contract version this build can speak."""
    return bool(value) and str(value).strip() in SUPPORTED_CONTRACT_VERSIONS


def require_supported(value: Optional[str], *, where: str = "request") -> str:
    """Return the version, or raise :class:`UnsupportedContractVersion` (fail closed)."""
    if not is_supported(value):
        raise UnsupportedContractVersion(
            f"{where}: unsupported contract version {value!r}; "
            f"this build supports {list(SUPPORTED_CONTRACT_VERSIONS)}",
            field="contract_version",
        )
    return str(value).strip()


def contract_header() -> dict:
    """The version header attached to every contract payload."""
    return {"name": CONTRACT_NAME, "version": CONTRACT_VERSION, "schema": SCHEMA_ID}


__all__ = [
    "CONTRACT_NAME",
    "CONTRACT_VERSION",
    "SCHEMA_ID",
    "SUPPORTED_CONTRACT_VERSIONS",
    "EVOLUTION_RULE",
    "parse_version",
    "is_supported",
    "require_supported",
    "contract_header",
]
