"""SPIFFE/SPIRE compatibility layer.

The engine already emits SPIFFE-shaped IDs (`spiffe://<trust-domain>/org/<org>/agent/<id>/instance/<id>`)
in every passport (`spiffe_id`). This module defines the adapter *contracts* so a real
SPIRE deployment can be plugged in later without changing the engine or its callers.

STATUS: contracts + parsing helpers + a local provider. The real SPIFFE/SPIRE adapter lives in
`agent_identity.spiffe` (`SpireWorkloadApiProvider` resolves to it).
"""
import re
from abc import ABC, abstractmethod
from typing import Optional, Protocol

_SPIFFE = re.compile(
    r"^spiffe://(?P<td>[a-z0-9.\-]+)/org/(?P<org>[a-z0-9_\-]+)/agent/(?P<agent>[A-Za-z0-9_\-]+)"
    r"/instance/(?P<instance>[A-Za-z0-9_\-]+)$")


def parse_spiffe_id(value: str) -> Optional[dict]:
    m = _SPIFFE.fullmatch(value) if isinstance(value, str) else None
    return m.groupdict() if m else None


class Attestor(Protocol):
    """Workload attestation hook (SPIRE-style). Called before an instance is created/issued.
    Return True only if `evidence` proves the runtime really is this agent
    (k8s service-account token, cloud instance identity doc, TPM quote, ...)."""

    def attest(self, agent_id: str, evidence: dict) -> bool: ...


class IdentityProvider(ABC):
    """Pluggable issuer of agent credentials."""

    @abstractmethod
    def issue(self, agent_id: str, instance_id: str, **kw): ...

    @abstractmethod
    def verify(self, token: str, **kw): ...


class LocalIdentityProvider(IdentityProvider):
    """Default provider: delegates to the built-in IdentityService."""

    def __init__(self, service):
        self._svc = service

    def issue(self, agent_id, instance_id, **kw):
        return self._svc.issue_credential(agent_id, instance_id, **kw)

    def verify(self, token, **kw):
        return self._svc.verify_credential(token, **kw)


def __getattr__(name):
    """`SpireWorkloadApiProvider` is now the real adapter (agent_identity.spiffe.provider).
    Lazy to avoid an import cycle; the former NotImplementedError stub no longer exists."""
    if name == "SpireWorkloadApiProvider":
        from ..spiffe.provider import SpiffeIdentityProvider
        return SpiffeIdentityProvider
    raise AttributeError(name)
