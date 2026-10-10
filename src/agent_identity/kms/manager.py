"""DefaultKeyManager: the provider-independent key manager.

It is BOTH
  * the new rich KeyManager API (create/identify/version/sign/verify-support/rotate/
    status/revoke/health/retire), and
  * a drop-in `KeyStore`, because KeyManager extends the pre-existing KeyStore ABC.

That second property is why the identity system needs no redesign: `IdentityService`,
`Verifier`, `PgStorage.service_kwargs()` and the SPIFFE provider all keep working
unchanged when you hand them a DefaultKeyManager instead of the legacy key store.

Failure policy: provider failures are retried a bounded number of times and then raised.
They are NEVER swallowed into a "valid" verdict — a credential whose issuer key cannot be
reached fails verification (fail closed).
"""
import threading
import time
from typing import Callable, List, Optional, Sequence, Tuple

from ..core.clock import Clock
from ..core.errors import StorageError
from ..crypto import keys as _keys
from ..crypto.encoding import b64u_encode
from ..observability.logging import SecurityLogger
from .errors import (KeyCollisionError, KeyNotFoundError, KmsError, KeyStateError,
                     ProviderError, ProviderPermissionError, UnsupportedAlgorithmError)
from .interfaces import CryptoBackend, KeyManager
from .metadata import (KeyAuditSink, KeyMetadataStore, MemoryKeyMetadataStore,
                       NullKeyAuditSink)
from .models import (KeyAlgorithm, KeyMetadata, KeyStatus, ProviderHealth, is_terminal,
                     may_destroy, may_sign, may_verify)

_RETRYABLE = (ProviderError,)


class DefaultKeyManager(KeyManager):
    def __init__(self, backend: CryptoBackend, *, metadata: Optional[KeyMetadataStore] = None,
                 audit: Optional[KeyAuditSink] = None, logger: Optional[SecurityLogger] = None,
                 clock: Optional[Clock] = None, retry_max_attempts: int = 3,
                 retry_initial_backoff_seconds: float = 0.05,
                 retry_max_backoff_seconds: float = 0.5,
                 sleep: Callable[[float], None] = time.sleep):
        if retry_max_attempts < 1:
            raise KeyStateError("retry_max_attempts must be >= 1")
        self.backend = backend
        self.metadata = metadata or MemoryKeyMetadataStore()
        self.audit = audit or NullKeyAuditSink()
        self.log = logger or SecurityLogger(use_python_logging=False)
        self.clock = clock or Clock()
        self._retry_max = retry_max_attempts
        self._retry_initial = retry_initial_backoff_seconds
        self._retry_max_backoff = retry_max_backoff_seconds
        self._sleep = sleep
        # serialises rotation of the same key inside one process; across processes the
        # metadata store's compare-and-swap is the authority.
        self._rot_lock = threading.RLock()
        self._locks = {}

    # =====================================================  KeyManager: creation
    def create_key(self, key_id: str, algorithm: KeyAlgorithm = KeyAlgorithm.ED25519, *,
                   status: KeyStatus = KeyStatus.ACTIVE, labels: Tuple[str, ...] = (),
                   tenant_id: Optional[str] = None, external_ref: Optional[str] = None,
                   actor: str = "system") -> KeyMetadata:
        if not isinstance(key_id, str) or not key_id.strip():
            raise KeyStateError("key_id is required")
        if not self.backend.supports(algorithm):
            raise UnsupportedAlgorithmError(f"{self.backend.name} does not support {algorithm.value}")
        existing = self.metadata.get(key_id)
        if existing is not None and not is_terminal(existing.status):
            raise KeyCollisionError("key id already exists and is not retired/revoked")
        pub, refs = self._retry(lambda: self.backend.generate(key_id, algorithm),
                                op="generate", key_id=key_id)
        meta = KeyMetadata(
            key_id=key_id, provider=self.backend.name, algorithm=algorithm, status=status,
            created_at=self.clock.now(), public_key_b64=b64u_encode(pub),
            fingerprint=_keys.fingerprint(pub), version=1,
            external_ref=external_ref or refs.get("ref"),
            exportable=bool(getattr(self.backend, "exportable", False)),
            created_by=actor, tenant_id=tenant_id, labels=tuple(labels))
        try:
            self.metadata.put(meta)
        except KmsError:
            # metadata could not be recorded => the key must not be left dangling
            self._best_effort_destroy(key_id, meta.external_ref)
            raise
        self._audit("kms.key.create", key_id=key_id, actor=actor, result="ok")
        return meta

    # =========================================================  KeyManager: read
    def get_key_status(self, key_id: str) -> KeyMetadata:
        meta = self._require(key_id)
        return self._settle(meta)

    def get_public_key(self, key_id: str) -> str:
        meta = self._settle(self._require(key_id))
        if meta.public_key_b64:
            return meta.public_key_b64
        pub = self._retry(lambda: self.backend.public(key_id, meta.external_ref,
                                                      meta.algorithm),
                          op="public", key_id=key_id)
        return b64u_encode(pub)

    def list_keys(self, *, status: Optional[KeyStatus] = None) -> List[KeyMetadata]:
        items = self.metadata.list(status)
        return [self._settle(m) for m in items]

    # ====================================================  KeyManager: lifecycle
    def rotate_key(self, key_id: str, new_key_id: str, *, grace_seconds: float,
                   actor: str = "system") -> Tuple[KeyMetadata, KeyMetadata]:
        if float(grace_seconds) < 0:
            raise KeyStateError("grace_seconds must be >= 0")
        with self._key_lock(key_id):
            old = self._settle(self._require(key_id))
            if is_terminal(old.status):
                raise KeyStateError(f"cannot rotate a {old.status.value} key")
            if self.metadata.get(new_key_id) is not None:
                raise KeyCollisionError("successor key id already exists")
            # 1) create the successor FIRST: a crash here leaves the old key fully usable
            #    and simply creates an unused key — never a broken signing path.
            new = self.create_key(new_key_id, old.algorithm, status=KeyStatus.ACTIVE,
                                  labels=old.labels, tenant_id=old.tenant_id, actor=actor)
            not_after = self.clock.now() + float(grace_seconds)
            try:
                # 2) CAS the old key into ROTATING (still signs during the overlap). The source
                #    set is ACTIVE only: a key already mid-rotation must not silently gain a
                #    second successor, which is what makes concurrent rotations safe.
                old = self.metadata.transition(key_id, (KeyStatus.ACTIVE,),
                                               KeyStatus.ROTATING, rotates_to=new_key_id,
                                               not_after=not_after)
                new = self.metadata.update(new_key_id, rotated_from=key_id)
            except KmsError:
                # CAS lost (someone rotated concurrently): remove the successor entirely —
                # both its provider key and its metadata row — so no orphan is left behind.
                self._best_effort_destroy(new_key_id, new.external_ref)
                self.metadata.delete(new_key_id)
                raise
        self._audit("kms.key.rotate", key_id=key_id, actor=actor, result="ok",
                    detail=f"->{new_key_id}")
        return old, new

    def retire_key(self, key_id: str, *, not_after: float, actor: str = "system") -> KeyMetadata:
        with self._key_lock(key_id):
            cur = self._require(key_id)
            if is_terminal(cur.status):
                raise KeyStateError(f"key is already {cur.status.value}")
            meta = self.metadata.transition(
                key_id, (KeyStatus.ACTIVE, KeyStatus.ROTATING), KeyStatus.RETIRING,
                not_after=float(not_after))
        self._audit("kms.key.retire", key_id=key_id, actor=actor, result="ok",
                    detail=f"verify_until_unset_or_{not_after}")
        return meta

    def revoke_key(self, key_id: str, *, reason: str, actor: str = "system") -> KeyMetadata:
        with self._key_lock(key_id):
            cur = self._require(key_id)
            if cur.status is KeyStatus.REVOKED:
                return cur                      # idempotent: revocation is terminal
            meta = self.metadata.transition(
                key_id, (KeyStatus.PENDING, KeyStatus.ACTIVE, KeyStatus.ROTATING,
                         KeyStatus.RETIRING, KeyStatus.RETIRED),
                KeyStatus.REVOKED, revoked_reason=str(reason)[:256],
                revoke_effective_at=self.clock.now())
        self._audit("kms.key.revoke", key_id=key_id, actor=actor, result="ok", reason=reason)
        return meta

    def destroy_key(self, key_id: str, *, actor: str = "system") -> None:
        with self._key_lock(key_id):
            meta = self._settle(self._require(key_id))
            if not may_destroy(meta.status):
                # Retiring/active keys may still be needed to verify live credentials.
                raise KeyStateError(
                    f"refusing to destroy a {meta.status.value} key: live credentials may "
                    "still depend on it (retire it first and wait out the overlap)")
            self._retry(lambda: self.backend.destroy(key_id, meta.external_ref),
                        op="destroy", key_id=key_id)
            self.metadata.update(key_id, external_ref=None, not_after=self.clock.now())
        self._audit("kms.key.destroy", key_id=key_id, actor=actor, result="ok")

    # =======================================================  KeyManager: health
    def health_check(self) -> ProviderHealth:
        try:
            return self.backend.health()
        except Exception as e:  # noqa: BLE001 - health must never raise
            return ProviderHealth(healthy=False, provider=self.backend.name,
                                  checked_at=self.clock.now(), detail=type(e).__name__)

    # ==========================================  legacy KeyStore (unchanged contract)
    def generate_key(self, key_id: str) -> bytes:
        """Legacy path used by IdentityService for agent/issuer/credential keys."""
        meta = self.create_key(key_id)
        return _keys.b64u_decode(meta.public_key_b64)

    def public_key(self, key_id: str) -> bytes:
        meta = self._require(key_id)
        pub = self._retry(lambda: self.backend.public(key_id, meta.external_ref, meta.algorithm),
                          op="public", key_id=key_id)
        raw = bytes(pub)
        if _keys.fingerprint(raw) != meta.fingerprint:
            raise ProviderError("provider public key does not match recorded fingerprint")
        return raw

    def sign(self, key_id: str, domain: bytes, data: bytes) -> bytes:
        meta = self._settle(self._require(key_id))
        if not may_sign(meta.status):
            self._audit("kms.sign.denied", key_id=key_id, result="denied",
                        reason=f"key_{meta.status.value}")
            raise KeyStateError(f"key is {meta.status.value}; not permitted to sign")
        try:
            sig = self._retry(
                lambda: self.backend.sign(key_id, meta.external_ref, meta.algorithm,
                                          bytes(domain) + bytes(data)),
                op="sign", key_id=key_id)
        except KmsError as e:
            self._audit("kms.sign.error", key_id=key_id, result="error", reason=e.code)
            raise
        self._audit("kms.sign", key_id=key_id, result="ok")
        return bytes(sig)

    def has_key(self, key_id: str) -> bool:
        """True while the key can still do something for us (sign or verify)."""
        meta = self.metadata.get(key_id)
        if meta is None or meta.status is KeyStatus.REVOKED:
            return False
        meta = self._settle(meta)
        now = self.clock.now()
        return may_sign(meta.status) or may_verify(meta.status, now, meta.not_after)

    def delete_key(self, key_id: str) -> None:
        """Legacy destructive path, used only for ephemeral credential keys (never for
        issuer/agent identity keys). Use `destroy_key()` where the lifecycle guard matters."""
        meta = self.metadata.get(key_id)
        self._best_effort_destroy(key_id, meta.external_ref if meta else None)
        self.metadata.delete(key_id)

    # ==================================================  Verification-key policy
    def verification_material(self, key_id: str) -> Optional[str]:
        """Public key b64u if the key may currently VERIFY, else None (fail closed).

        Called by the trust bridge before any credential is accepted, so a revoked /
        retired-past-overlap / missing key can never silently validate an identity.
        """
        meta = self.metadata.get(key_id)
        if meta is None:
            return None
        try:
            meta = self._settle(meta)
        except KmsError:
            return None
        if not may_verify(meta.status, self.clock.now(), meta.not_after):
            return None
        return meta.public_key_b64

    # =================================================================== internals
    def _require(self, key_id: str) -> KeyMetadata:
        meta = self.metadata.get(key_id)
        if meta is None:
            raise KeyNotFoundError("unknown key id")
        return meta

    def _settle(self, meta: KeyMetadata) -> KeyMetadata:
        """Advance time-based transitions once an overlap window closes:
        ROTATING -> RETIRING -> RETIRED. ACTIVE/REVOKED/PENDING keys are never moved.

        RETIRED keeps verifying (old credentials may still be live); it only means the key
        no longer signs and may now be destroyed by an administrator.
        """
        # Loop, because one call may need to cross BOTH boundaries at once (a rotation
        # whose whole overlap already elapsed settles straight from ROTATING to RETIRED).
        for _ in range(3):
            now = self.clock.now()
            if meta.not_after is None or now < meta.not_after:
                return meta
            if meta.status is KeyStatus.ROTATING:
                target, frm = KeyStatus.RETIRING, (KeyStatus.ROTATING,)
            elif meta.status is KeyStatus.RETIRING:
                target, frm = KeyStatus.RETIRED, (KeyStatus.RETIRING,)
            else:
                return meta
            try:
                meta = self.metadata.transition(meta.key_id, frm, target)
            except KmsError:
                return self.metadata.get(meta.key_id) or meta
        return meta

    def _key_lock(self, key_id: str):
        with self._rot_lock:
            lock = self._locks.get(key_id)
            if lock is None:
                lock = self._locks[key_id] = threading.RLock()
            return lock

    def _retry(self, fn, *, op: str, key_id: str):
        attempt, delay = 1, self._retry_initial
        while True:
            try:
                return fn()
            except _RETRYABLE as e:
                # Only *transient* provider failures are retried. A permission denial is a
                # policy answer, not a hiccup: retrying it would hammer the provider and
                # cannot change the outcome, so it propagates on the first attempt.
                if attempt >= self._retry_max or isinstance(e, ProviderPermissionError):
                    self._audit("kms.provider.failed", key_id=key_id, result="error",
                                reason=e.code, detail=op)
                    raise
                self.log.emit("kms.provider.retry", key_id=key_id, result="retry",
                              reason=e.code, operation=op)
                self._sleep(delay)
                attempt += 1
                delay = min(delay * 2, self._retry_max_backoff)

    def _best_effort_destroy(self, key_id: str, external_ref: Optional[str]) -> None:
        try:
            self.backend.destroy(key_id, external_ref)
        except Exception:  # noqa: BLE001 - cleanup must never mask the original failure
            self.log.emit("kms.cleanup.failed", key_id=key_id, result="error")

    def _audit(self, event: str, *, key_id: str, result: str, reason: Optional[str] = None,
               actor: str = "system", detail: Optional[str] = None) -> None:
        provider = getattr(self.backend, "name", "unknown")
        try:
            self.audit.record(event, key_id=key_id, provider=provider, result=result,
                              reason=reason, actor=actor, detail=detail)
        except Exception:  # noqa: BLE001 - auditing must not break the operation
            self.log.emit("kms.audit.failed", key_id=key_id, result="error")
        self.log.emit(event, key_id=key_id, result=result, reason=reason, actor=actor,
                      provider=provider)

    def __repr__(self) -> str:
        return f"DefaultKeyManager(provider={getattr(self.backend, 'name', '?')}, <redacted>)"
