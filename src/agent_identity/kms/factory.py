"""Provider selection. There is NO silent fallback: an unconfigured/unknown provider
raises, and production refuses the development software provider (see KmsConfig.validate).
"""
import os
from typing import Optional

from ..core.clock import Clock
from ..observability.logging import SecurityLogger
from .config import KmsConfig
from .errors import KmsConfigError
from .interfaces import CryptoBackend
from .manager import DefaultKeyManager
from .metadata import KeyAuditSink, KeyMetadataStore, PgKeyMetadataStore, PgKeyAuditSink

MASTER_KEY_ENV = "AGENT_IDENTITY_MASTER_KEY"      # same name the existing key store uses


def backend_from_config(cfg: KmsConfig, *, transport=None, session_factory=None) -> CryptoBackend:
    cfg.validate()
    if cfg.provider == "local":
        from .providers.local_provider import LocalKeyBackend
        master = os.environ.get(MASTER_KEY_ENV)
        if not master:
            # Development convenience only: an ephemeral master key. Keys are then lost on
            # restart. Outside development KmsConfig.validate() already refuses this provider.
            from cryptography.fernet import Fernet
            master = Fernet.generate_key().decode()
        return LocalKeyBackend(master)
    if cfg.provider == "vault":
        from .providers.vault_provider import VaultTransitBackend
        return VaultTransitBackend(
            addr=cfg.vault_addr, token=cfg.resolve_vault_token(), mount=cfg.vault_mount,
            prefix=cfg.key_id_prefix, namespace=cfg.vault_namespace,
            tls_verify=cfg.vault_tls_verify, ca_cert=cfg.vault_ca_cert,
            timeout=cfg.timeout_seconds, exportable=cfg.allow_exportable_keys,
            transport=transport)
    if cfg.provider == "pkcs11":
        from .providers.pkcs11_provider import Pkcs11Backend
        return Pkcs11Backend(
            library=cfg.pkcs11_library, token_label=cfg.pkcs11_token_label,
            pin=cfg.resolve_pkcs11_pin(), key_label_prefix=cfg.key_id_prefix,
            slot=cfg.pkcs11_slot, session_factory=session_factory)
    raise KmsConfigError(f"unknown KMS provider {cfg.provider!r}")


def build_key_manager(cfg: KmsConfig, *, metadata: Optional[KeyMetadataStore] = None,
                      audit: Optional[KeyAuditSink] = None, logger=None, clock=None,
                      transport=None, session_factory=None,
                      db=None) -> DefaultKeyManager:
    """Build the manager for `cfg`. Passing `db` attaches the durable metadata + audit
    stores (PostgreSQL); without it the in-memory reference stores are used."""
    cfg.validate()
    if db is not None and metadata is None:
        metadata = PgKeyMetadataStore(db)
    if db is not None and audit is None:
        audit = PgKeyAuditSink(db)
    backend = backend_from_config(cfg, transport=transport, session_factory=session_factory)
    return DefaultKeyManager(
        backend, metadata=metadata, audit=audit,
        logger=logger or SecurityLogger(use_python_logging=False),
        clock=clock or Clock(), retry_max_attempts=cfg.retry_max_attempts,
        retry_initial_backoff_seconds=cfg.retry_initial_backoff_seconds,
        retry_max_backoff_seconds=cfg.retry_max_backoff_seconds)


def build_managed_service(storage, identity_config, cfg=None, *, logger=None, clock=None,
                          **manager_kw):
    """Fully wire an IdentityService to the KMS: signing goes through the managed keys and
    the trust chain is gated on key lifecycle state.

    Returns (IdentityService, DefaultKeyManager). `storage` is the existing PgStorage (or
    any object exposing `.service_kwargs()` + `.trust` + `.db`).
    """
    from ..api.service import IdentityService
    from ..observability.logging import SecurityLogger
    from .trust_bridge import managed_storage_kwargs
    cfg = cfg or KmsConfig.from_env()
    logger = logger or SecurityLogger(use_python_logging=False)
    manager = build_key_manager(cfg, db=getattr(storage, "db", None), logger=logger,
                                clock=clock, **manager_kw)
    kwargs = managed_storage_kwargs(storage, manager, logger=logger, clock=clock)
    return IdentityService(identity_config, logger=logger, clock=clock, **kwargs), manager
