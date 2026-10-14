"""Version and capability constants for the agent platform.

The platform is an independent, additive layer that sits ON TOP of the existing
AgentGuard <-> Happy LANG integration contract.  It never modifies the contract, AgentGuard or
Happy LANG; it consumes their public interfaces only.
"""
from __future__ import annotations

from typing import Tuple

#: Machine name of this platform.
PLATFORM_NAME = "agentguard-agent-platform"

#: Platform version.  Bump the MINOR for additive capability, the MAJOR for a breaking API change.
PLATFORM_VERSION = "0.1.0"

#: The integration contract version this platform was built and tested against.  Declared explicitly
#: so a version skew between the two layers is a loud, fail-closed error rather than a silent guess.
REQUIRED_CONTRACT_VERSION = "1.0.0"

#: Feature flags the platform understands (all default OFF or safe).
FEATURES: Tuple[str, ...] = (
    "router",
    "tools",
    "authorization",
    "memory",
    "planning",
    "tracing",
    "evaluation",
    "sandbox",
    "event_forwarding",
)


def platform_header() -> dict:
    """The version header attached to platform envelopes and audit records."""
    return {
        "name": PLATFORM_NAME,
        "version": PLATFORM_VERSION,
        "contract_version": REQUIRED_CONTRACT_VERSION,
    }


__all__ = [
    "PLATFORM_NAME",
    "PLATFORM_VERSION",
    "REQUIRED_CONTRACT_VERSION",
    "FEATURES",
    "platform_header",
]
