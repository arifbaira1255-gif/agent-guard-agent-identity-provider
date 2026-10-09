"""Storage selection. Production REQUIRES PostgreSQL; there is no silent fallback to memory."""
import os
from dataclasses import dataclass
from typing import Optional

from ...core.errors import StorageError
from ...spiffe.config import ENV_VAR
from . import migrate
from .config import PgConfig
from .db import Database
from .repos import (PgAgentRegistry, PgBindingRegistry, PgCredentialRegistry, PgKeyStore,
                    PgRevocationRegistry, PgTrustStore)

DURABLE_ENVS = ("staging", "production")


@dataclass
class PgStorage:
    db: Database
    agents: PgAgentRegistry
    credentials: PgCredentialRegistry
    revocations: PgRevocationRegistry
    trust: PgTrustStore
    bindings: PgBindingRegistry
    keystore: PgKeyStore

    def service_kwargs(self) -> dict:
        """IdentityService(config, **storage.service_kwargs())"""
        return dict(keystore=self.keystore, agents=self.agents, credentials=self.credentials,
                    revocations=self.revocations, trust=self.trust)

    def close(self):
        self.db.close()


def build_postgres_storage(cfg: PgConfig, master_keys, *, db: Optional[Database] = None,
                           ensure_schema: bool = True) -> PgStorage:
    """Opens the pool, (optionally) auto-migrates in development/staging, then VERIFIES the schema:
    a database that is missing, behind, ahead or tampered raises SchemaMismatchError (fail closed)."""
    cfg.validate()
    db = db or Database(cfg)
    try:
        if cfg.auto_migrate:
            migrate.migrate(db)
        if ensure_schema:
            migrate.verify_schema(db)
        return PgStorage(db, PgAgentRegistry(db), PgCredentialRegistry(db), PgRevocationRegistry(db),
                         PgTrustStore(db), PgBindingRegistry(db), PgKeyStore(db, master_keys))
    except Exception:
        db.close()
        raise


def process_env() -> str:
    return os.environ.get(ENV_VAR, "").strip().lower()


def require_durable_or_raise(**stores) -> None:
    """Called by IdentityService / SpiffeIdentityProvider: in staging/production an in-memory
    authoritative store aborts startup instead of silently losing/forking security state."""
    if process_env() not in DURABLE_ENVS:
        return
    for name, store in stores.items():
        if type(store).__module__.endswith("storage.memory") or type(store).__name__.startswith("Memory"):
            raise StorageError(f"in-memory {name} is not allowed when {ENV_VAR}={process_env()}; "
                               "configure PostgreSQL storage")
