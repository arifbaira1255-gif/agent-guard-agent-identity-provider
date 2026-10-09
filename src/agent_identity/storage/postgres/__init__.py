"""PostgreSQL persistence (authoritative durable state). psycopg is imported lazily."""
from .config import PgConfig
from .errors import (MigrationError, PgConfigError, SchemaMismatchError, StorageUnavailableError)
from .factory import PgStorage, build_postgres_storage, require_durable_or_raise

__all__ = ["PgConfig", "PgStorage", "build_postgres_storage", "require_durable_or_raise",
           "MigrationError", "PgConfigError", "SchemaMismatchError", "StorageUnavailableError"]
