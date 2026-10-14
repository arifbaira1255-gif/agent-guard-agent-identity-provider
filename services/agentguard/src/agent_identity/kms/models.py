"""Immutable KMS domain models.

IMPORTANT: none of these types hold private key material. A ``KeyVersion`` records *where* a key
lives (a provider-native handle) and its lifecycle state; the private material never leaves the
provider. ``public_key_b64`` is the base64url raw public key (safe to store/log/transmit).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, replace
from typing import Iterable, Optional, Tuple

from .errors import KmsKeyStateError, KmsProviderError


class KmsAlgorithm(str, enum.Enum):
    """Signature algorithms the identity layer may request.

    AgentGuard agent identity is deliberately Ed25519-only (fixed algorithm, no ``alg`` header, so
    no algorithm-confusion surface). The enum stays extensible so a provider can host material for
    other purposes without conflating it with passport signing keys."""
    ED25519 = "ed25519"


class KmsKeyType(str, enum.Enum):
    ASYMMETRIC_SIGNATURE = "asymmetric_signature"
    SYMMETRIC = "symmetric"


class KmsKeyUsage(str, enum.Enum):
    """What a key is allowed to be used for. Enforced by this layer, never trusted from a caller."""
    ISSUER_CERT_SIGNING = "issuer_cert_signing"   # root key signs issuer certificates
    PASSPORT_SIGNING = "passport_signing"         # org issuer key signs agent passports
    IDENTITY_SIGNING = "identity_signing"         # agent identity key signs instance bindings
    PROOF_SIGNING = "proof_signing"               # service-held credential key signs proofs
    DATA_KEY = "data_key"                         # non-signing (envelope encryption) key


SIGNING_USAGES = frozenset((KmsKeyUsage.ISSUER_CERT_SIGNING, KmsKeyUsage.PASSPORT_SIGNING,
                            KmsKeyUsage.IDENTITY_SIGNING, KmsKeyUsage.PROOF_SIGNING))


class KmsKeyState(str, enum.Enum):
    """Lifecycle: PENDING -> ENABLED -> (DISABLED) -> RETIRING -> RETIRED -> REVOKED.

    Only ENABLED keys sign. RETIRING keys still verify (this is what makes rotation overlap safe:
    credentials signed by the previous version remain verifiable while the new version signs).
    RETIRED/REVOKED/DESTROYED are terminal for signing and verification."""
    PENDING = "pending"
    ENABLED = "enabled"
    DISABLED = "disabled"
    RETIRING = "retiring"
    RETIRED = "retired"
    REVOKED = "revoked"
    DESTROYED = "destroyed"


SIGNING_STATES = frozenset((KmsKeyState.ENABLED,))
VERIFYING_STATES = frozenset((KmsKeyState.ENABLED, KmsKeyState.RETIRING))
TERMINAL_STATES = frozenset((KmsKeyState.RETIRED, KmsKeyState.REVOKED, KmsKeyState.DESTROYED))

#: legal state transitions. Retirement is one-way; a revoked key can never return to service.
_ALLOWED_TRANSITIONS = {
    KmsKeyState.PENDING: frozenset((KmsKeyState.ENABLED, KmsKeyState.REVOKED)),
    KmsKeyState.ENABLED: frozenset((KmsKeyState.DISABLED, KmsKeyState.RETIRING, KmsKeyState.REVOKED)),
    KmsKeyState.DISABLED: frozenset((KmsKeyState.ENABLED, KmsKeyState.RETIRING, KmsKeyState.REVOKED)),
    KmsKeyState.RETIRING: frozenset((KmsKeyState.RETIRED, KmsKeyState.REVOKED)),
    KmsKeyState.RETIRED: frozenset((KmsKeyState.REVOKED,)),
    KmsKeyState.REVOKED: frozenset(),
    KmsKeyState.DESTROYED: frozenset(),
}


def can_transition(src: "KmsKeyState", dst: "KmsKeyState") -> bool:
    try:
        return KmsKeyState(dst) in _ALLOWED_TRANSITIONS.get(KmsKeyState(src), frozenset())
    except ValueError:
        return False


def check_transition(src: "KmsKeyState", dst: "KmsKeyState") -> KmsKeyState:
    if not can_transition(src, dst):
        raise KmsKeyStateError(f"illegal key state transition {KmsKeyState(src).value} -> "
                               f"{KmsKeyState(dst).value}")
    return KmsKeyState(dst)


def coerce_algorithm(value) -> KmsAlgorithm:
    if isinstance(value, KmsAlgorithm):
        return value
    try:
        return KmsAlgorithm(value)
    except ValueError:
        raise KmsProviderError("unsupported key algorithm")


def coerce_usages(usages: Optional[Iterable]) -> Tuple[KmsKeyUsage, ...]:
    """Accept enums or plain strings (the storage ``KeyStore.generate_key`` API passes strings),
    de-duplicate and return a stable order. Unknown usages are rejected."""
    out = set()
    for u in usages or ():
        try:
            out.add(u if isinstance(u, KmsKeyUsage) else KmsKeyUsage(u))
        except ValueError:
            raise KmsProviderError("unknown key usage")
    return tuple(sorted(out, key=lambda x: x.value))


def coerce_state(value) -> KmsKeyState:
    try:
        return value if isinstance(value, KmsKeyState) else KmsKeyState(value)
    except ValueError:
        raise KmsProviderError("unknown key state")


@dataclass(frozen=True)
class KeyVersion:
    """One immutable revision of a logical key. Private material lives inside the provider and is
    NEVER represented here. ``provider_key_id`` is the provider-native handle (ARN / PKCS#11 object
    label / dev handle) and is not secret."""
    key_id: str
    version: int
    provider: str
    provider_key_id: str
    algorithm: KmsAlgorithm
    key_type: KmsKeyType
    usages: Tuple[KmsKeyUsage, ...]
    state: KmsKeyState
    public_key_b64: Optional[str]
    fingerprint: str
    created_at: float
    enabled_at: Optional[float] = None
    retire_at: Optional[float] = None       # deadline of the retirement overlap window
    retired_at: Optional[float] = None
    revoked_at: Optional[float] = None
    revoke_reason: Optional[str] = None
    exportable: bool = False                # True only for development providers
    org_id: Optional[str] = None
    purpose: str = ""

    def __post_init__(self):
        if not isinstance(self.key_id, str) or not self.key_id:
            raise KmsProviderError("key version requires a key id")
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise KmsProviderError("key version must be a positive integer")

    # ---- capability queries (single source of truth, used by providers and the manager) ----
    def can_sign(self, usage: Optional[KmsKeyUsage] = None) -> bool:
        if self.state not in SIGNING_STATES:
            return False
        if usage is None:
            return True
        try:
            return KmsKeyUsage(usage) in self.usages
        except ValueError:
            return False

    def can_verify(self) -> bool:
        return self.state in VERIFYING_STATES

    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def retired_in_use(self) -> bool:
        """True if a retire deadline has passed but the state has not yet been advanced."""
        return (self.state == KmsKeyState.RETIRING and self.retire_at is not None)

    def public_dict(self) -> dict:
        """Safe to expose: contains public key material and lifecycle metadata, never secrets."""
        return {"key_id": self.key_id, "version": self.version, "provider": self.provider,
                "algorithm": self.algorithm.value, "key_type": self.key_type.value,
                "usages": [u.value for u in self.usages], "state": self.state.value,
                "fingerprint": self.fingerprint, "public_key_b64": self.public_key_b64,
                "created_at": self.created_at, "enabled_at": self.enabled_at,
                "retire_at": self.retire_at, "retired_at": self.retired_at,
                "revoked_at": self.revoked_at, "org_id": self.org_id, "purpose": self.purpose,
                "exportable": self.exportable}

    def __repr__(self) -> str:
        return (f"KeyVersion(key_id={self.key_id!r}, version={self.version}, "
                f"state={self.state.value}, provider={self.provider!r}, "
                f"fingerprint={self.fingerprint!r})")


@dataclass(frozen=True)
class KeyMetadata:
    """Logical key = an ordered set of versions sharing one ``key_id``."""
    key_id: str
    provider: str
    algorithm: KmsAlgorithm
    key_type: KmsKeyType
    usages: Tuple[KmsKeyUsage, ...]
    org_id: Optional[str]
    purpose: str
    created_at: float
    created_by: str
    versions: Tuple[KeyVersion, ...] = ()

    def version(self, n: int) -> Optional[KeyVersion]:
        for v in self.versions:
            if v.version == n:
                return v
        return None

    def active(self) -> Optional[KeyVersion]:
        """The single version new signatures must use (highest ENABLED version)."""
        best = None
        for v in self.versions:
            if v.state == KmsKeyState.ENABLED and (best is None or v.version > best.version):
                best = v
        return best

    def latest(self) -> Optional[KeyVersion]:
        return max(self.versions, key=lambda v: v.version) if self.versions else None

    def verifying_versions(self) -> Tuple[KeyVersion, ...]:
        return tuple(v for v in self.versions if v.can_verify())

    def with_version(self, ver: KeyVersion) -> "KeyMetadata":
        """Return a copy with ``ver`` inserted/replaced (keeping versions ordered)."""
        vs = tuple(sorted(tuple(v for v in self.versions if v.version != ver.version) + (ver,),
                          key=lambda v: v.version))
        return replace(self, versions=vs)

    def public_dict(self) -> dict:
        return {"key_id": self.key_id, "provider": self.provider,
                "algorithm": self.algorithm.value, "key_type": self.key_type.value,
                "usages": [u.value for u in self.usages], "org_id": self.org_id,
                "purpose": self.purpose, "created_at": self.created_at,
                "created_by": self.created_by,
                "active_version": (self.active().version if self.active() else None),
                "versions": [v.public_dict() for v in self.versions]}

    def __repr__(self) -> str:
        return (f"KeyMetadata(key_id={self.key_id!r}, provider={self.provider!r}, "
                f"versions={len(self.versions)})")