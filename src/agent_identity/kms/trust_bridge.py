"""Bridge between the KMS lifecycle and the EXISTING TrustStore interface.

Why this exists
---------------
`IdentityService`/`Verifier` trust the `TrustStore` for issuer certificates (the trust
chain). The KMS owns key *lifecycle* (active/retiring/retired/revoked). This composition
makes the trust decision consult the KMS, so:

  * every issuer key id is registered in the KMS (provider-backed, non-exportable);
  * a key that is missing, revoked, or retired past its overlap can NEVER verify
    (get_issuer_cert returns None => verification fails closed);
  * during rotation the outgoing key still verifies until its overlap closes.

Wiring (the standard, backward-compatible seam):

    manager = build_key_manager(cfg, db=storage.db)
    kwargs = storage.service_kwargs()
    kwargs["keystore"] = manager                      # signs through the KMS
    kwargs["trust"] = TrustStoreComposition(storage.trust, manager)
    IdentityService(config, **kwargs)

Because `DefaultKeyManager` implements the legacy `KeyStore` ABC, nothing else in the
identity system changes.
"""
from typing import Optional

from ..core.clock import Clock
from ..core.errors import ConflictError
from ..core.models import IssuerCertificate
from ..observability.logging import SecurityLogger
from ..storage.interfaces import TrustStore
from .errors import KeyNotFoundError, KmsError
from .models import KeyStatus, may_verify


class TrustStoreComposition(TrustStore):
    def __init__(self, base: TrustStore, manager, *, logger: Optional[SecurityLogger] = None,
                 clock: Optional[Clock] = None):
        self._base = base
        self._manager = manager
        self._log = logger or SecurityLogger(use_python_logging=False)
        self._clock = clock or Clock()

    # ------------------------------------------------------------------ pass-through
    def add_root(self, root_key_id: str, public_key_b64: str) -> None:
        return self._base.add_root(root_key_id, public_key_b64)

    def get_root(self, root_key_id: str) -> Optional[str]:
        return self._base.get_root(root_key_id)

    # ------------------------------------------------------------------ bridged
    def put_issuer_cert(self, cert: IssuerCertificate) -> None:
        """Persist the certificate, then reconcile the KMS key with its status.

        The key itself is created by IdentityService through the (KMS-backed) key store, so
        here we only validate consistency and mirror revoke/retire transitions.
        """
        self._base.put_issuer_cert(cert)
        if self._manager is None:
            return
        try:
            meta = self._manager.get_key_status(cert.issuer_key_id)
        except KeyNotFoundError:
            # A certificate without a KMS key cannot be honoured: fail closed by logging and
            # letting get_issuer_cert return None rather than inventing a key that would not
            # match the signer.
            self._log.emit("kms.issuer_cert.unmanaged", issuer_key_id=cert.issuer_key_id,
                           result="error", reason="no_matching_kms_key")
            return
        if meta.public_key_b64 != cert.public_key:
            raise ConflictError("issuer certificate public key does not match the KMS key")
        try:
            if cert.status == "revoked" and meta.status is not KeyStatus.REVOKED:
                self._manager.revoke_key(cert.issuer_key_id, reason="issuer_revoked",
                                         actor="trust-bridge")
            elif cert.status == "retiring" and meta.status in (KeyStatus.ACTIVE,
                                                               KeyStatus.ROTATING):
                self._manager.retire_key(
                    cert.issuer_key_id,
                    not_after=(cert.not_after if cert.not_after is not None
                               else self._clock.now() + 7200),
                    actor="trust-bridge")
        except KmsError as e:
            # Lifecycle sync must not corrupt the certificate store; log and continue.
            self._log.emit("kms.issuer_cert.sync_failed", issuer_key_id=cert.issuer_key_id,
                           result="error", reason=e.code)

    def get_issuer_cert(self, issuer_key_id: str) -> Optional[IssuerCertificate]:
        cert = self._base.get_issuer_cert(issuer_key_id)
        if cert is None or self._manager is None:
            return cert
        try:
            meta = self._manager.get_key_status(issuer_key_id)
        except KeyNotFoundError:
            return None                                   # unmanaged => untrusted
        except KmsError:
            return None                                   # provider trouble => fail closed
        if not may_verify(meta.status, self._clock.now(), meta.not_after):
            return None
        if meta.public_key_b64 != cert.public_key:
            return None
        return cert


def managed_storage_kwargs(storage, manager, *, logger=None, clock=None) -> dict:
    """Return IdentityService(**kwargs) wiring the KMS behind the existing storage."""
    kwargs = dict(storage.service_kwargs())
    kwargs["keystore"] = manager
    kwargs["trust"] = TrustStoreComposition(storage.trust, manager, logger=logger, clock=clock)
    return kwargs
