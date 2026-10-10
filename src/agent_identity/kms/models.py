"""Provider-independent key-management value objects.

NONE of these hold private key material — only the public key and non-secret metadata.
This is deliberate and matches the pre-existing invariant (storage/interfaces.py:
"KeyStore must NEVER return private key bytes").
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional

from ..core.models import iso


class KeyAlgorithm(str, enum.Enum):
    """Signature algorithms a managed key may be created for.

    Only what AgentGuard actually consumes is allowed: the passport/issuer-cert/binding/
    proof/proof-CSR signatures are all Ed25519. Adding a new algorithm is a security
    decision (it changes the token format's implicit algorithm), so this list is closed.
    """
    ED25519 = "ed25519"


class KeyStatus(str, enum.Enum):
    """Key lifecycle. The allowed operations per state are the whole point:

        PENDING   - created but not yet usable to sign/verify (staged activation)
        ACTIVE    - signs and verifies
        ROTATING  - successor issued; STILL SIGNS during the rotation overlap window
        RETIRING  - verify-only; no new signatures, usable until `not_after`
        RETIRED   - no signing; kept only because live credentials may still need it
        REVOKED   - compromised; never usable again, terminal

    A key is never deleted while a valid credential may still depend on it: retirement
    is explicit (`retire_key`) and only RETIRED/REVOKED keys may be destroyed.
    """
    PENDING = "pending"
    ACTIVE = "active"
    ROTATING = "rotating"
    RETIRING = "retiring"
    RETIRED = "retired"
    REVOKED = "revoked"


_SIGNING_STATES = frozenset({KeyStatus.ACTIVE, KeyStatus.ROTATING})
_VERIFY_STATES = frozenset({KeyStatus.ACTIVE, KeyStatus.ROTATING, KeyStatus.RETIRING,
                            KeyStatus.RETIRED})
_TERMINAL_STATES = frozenset({KeyStatus.RETIRED, KeyStatus.REVOKED})
_DESTRUCTIBLE_STATES = frozenset({KeyStatus.RETIRED, KeyStatus.REVOKED})


def may_sign(status: KeyStatus) -> bool:
    return status in _SIGNING_STATES


def may_verify(status: KeyStatus, now: float, not_after: Optional[float]) -> bool:
    """Which keys a verifier may still honour.

    ACTIVE / ROTATING always verify. RETIRING and RETIRED verify ONLY until their
    `not_after` deadline: past it the key no longer validates anything, which is what makes
    a retired key eventually safe to destroy. Operators keep a key verifiable for as long as
    live credentials may reference it by retiring it with a deadline past their validity.
    PENDING never verifies; REVOKED never verifies.
    """
    if status in _SIGNING_STATES:
        return True
    if status in (KeyStatus.RETIRING, KeyStatus.RETIRED):
        return not_after is not None and now < not_after
    return False


def may_destroy(status: KeyStatus) -> bool:
    return status in _DESTRUCTIBLE_STATES


def is_terminal(status: KeyStatus) -> bool:
    return status in _TERMINAL_STATES


@dataclass(frozen=True)
class KeyMetadata:
    """Everything a caller may know about a key. Never contains private key bytes."""
    key_id: str
    provider: str
    algorithm: KeyAlgorithm
    status: KeyStatus
    created_at: float
    public_key_b64: str
    fingerprint: str
    version: int = 1
    external_ref: Optional[str] = None      # provider-side handle (Vault key name / CKA_ID / path)
    not_after: Optional[float] = None       # set when retiring (overlap deadline)
    rotates_to: Optional[str] = None        # successor key id
    rotated_from: Optional[str] = None      # predecessor key id
    revoked_reason: Optional[str] = None
    revoke_effective_at: Optional[float] = None
    exportable: bool = False
    created_by: str = "system"
    tenant_id: Optional[str] = None
    labels: tuple = ()

    def public_dict(self) -> dict:
        return {"key_id": self.key_id, "provider": self.provider,
                "algorithm": self.algorithm.value, "status": self.status.value,
                "created_at": iso(self.created_at), "public_key": self.public_key_b64,
                "fingerprint": self.fingerprint, "version": self.version,
                "not_after": iso(self.not_after), "rotates_to": self.rotates_to,
                "rotated_from": self.rotated_from, "revoked_reason": self.revoked_reason,
                "revoke_effective_at": iso(self.revoke_effective_at),
                "exportable": self.exportable, "created_by": self.created_by,
                "tenant_id": self.tenant_id, "labels": list(self.labels)}


@dataclass(frozen=True)
class ProviderHealth:
    healthy: bool
    provider: str
    checked_at: float = 0.0
    latency_ms: Optional[float] = None
    detail: str = ""

    def public_dict(self) -> dict:
        return {"healthy": self.healthy, "provider": self.provider,
                "checked_at": iso(self.checked_at), "latency_ms": self.latency_ms,
                "detail": self.detail}
