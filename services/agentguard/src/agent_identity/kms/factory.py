"""KMS provider selection + wiring, with the same fail-closed posture as the PG/Redis factories.

Production rules enforced here (defence in depth on top of ``KmsConfig.validate``):
  * a development provider can never be selected outside development;
  * a durable environment requires a durable metadata ledger (never the in-memory one);
  * an optional health check must pass before the runtime is handed out.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..spiffe.config import Environment
from .config import DEV_ONLY_PROVIDERS, KmsConfig
from .errors import KmsConfigError, KmsUnavailableError
from .interfaces import KeyManagementProvider, KeyMetadataStore
from .keystore import KmsKeyStore
from .stores import InMemoryKeyMetadataStore, KeyManagementManager

DURABLE_ENVS = (Environment.STAGING, Environment.PRODUCTION)


@dataclass
class KmsRuntime:
    cfg: KmsConfig
    provider: KeyManagementProvider
    store: KeyMetadataStore
    manager: KeyManagementManager
    keystore: KmsKeyStore

    def service_kwargs(self) -> dict:
        """Pass to ``IdentityService(config, **runtime.service_kwargs())``."""
        return {"keystore": self.keystore}

    def health(self) -> dict:
        out = self.manager.health()
        out["environment"] = self.cfg.environment.value
        return out


def build_key_metadata_store(cfg: KmsConfig, *, pg_db=None,
                             store: Optional[KeyMetadataStore] = None) -> KeyMetadataStore:
    if store is not None:
        return store
    if cfg.environment in DURABLE_ENVS:
        if pg_db is None:
            raise KmsConfigError(
                "a durable key-metadata store (PostgreSQL) is required outside development")
        from ..storage.postgres.kms_repos import PgKeyMetadataStore
        return PgKeyMetadataStore(pg_db)
    return InMemoryKeyMetadataStore()


def build_kms(cfg: KmsConfig, *, metadata_store=None, store: Optional[KeyMetadataStore] = None,
              client=None, module=None, entity_store=None, pg_db=None, logger=None, clock=None,
              metrics=None, strict_health: Optional[bool] = None) -> KmsRuntime:
    """Construct the provider, metadata ledger, manager and drop-in key store."""
    cfg.validate()
    meta_store = store or build_key_metadata_store(cfg, pg_db=pg_db, store=metadata_store)

    if cfg.provider == "local-dev":
        if cfg.environment in DURABLE_ENVS:
            raise KmsConfigError("local-dev provider is not allowed outside development")
        from .local_dev import LocalDevProvider
        provider = LocalDevProvider(entity_store=entity_store,
                                    allow_export=cfg.allow_export_in_dev)
    elif cfg.provider == "aws-kms":
        from .aws_kms import AwsKmsProvider
        provider = AwsKmsProvider(cfg, client=client)
    elif cfg.provider == "pkcs11":
        from .pkcs11_provider import Pkcs11Provider
        provider = Pkcs11Provider(cfg, module=module, metadata_store=meta_store)
    else:                                                            # pragma: no cover
        raise KmsConfigError(f"unknown provider {cfg.provider!r}")

    manager = KeyManagementManager(provider, meta_store, cfg, logger=logger, clock=clock,
                                   metrics=metrics)
    keystore = KmsKeyStore(provider, manager, meta_store, logger=logger)

    check = cfg.require_health_check if strict_health is None else strict_health
    if check and not provider.health_check():
        raise KmsUnavailableError(f"{provider.name} provider failed its health check")
    return KmsRuntime(cfg, provider, meta_store, manager, keystore)
