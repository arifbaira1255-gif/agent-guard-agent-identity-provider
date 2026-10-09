"""Structured, secret-free database errors. Messages NEVER include driver text (it can echo DSNs/values)."""
from ...core.errors import ConflictError, StorageError


class StorageUnavailableError(StorageError):
    """DB unreachable / pool exhausted / timeout / deadlock after retries. Callers MUST deny (fail closed)."""
    code = "storage_unavailable"


class MigrationError(StorageError):
    code = "migration_error"


class SchemaMismatchError(StorageError):
    """Schema missing, behind, ahead or tampered: refuse to serve security decisions."""
    code = "schema_mismatch"


class PgConfigError(ValueError):
    pass


_CONFLICT = {"23505": "record already exists", "23503": "referenced record missing or tenant mismatch",
             "23514": "invalid state transition or immutable field", "23502": "missing required value",
             "22P02": "invalid value", "22001": "value too long"}
_TRANSIENT = {"40001", "40P01", "57014", "55P03", "53300", "57P01", "57P02", "57P03", "53200", "53100"}


def sqlstate_of(exc) -> str:
    return getattr(exc, "sqlstate", None) or getattr(getattr(exc, "diag", None), "sqlstate", None) or ""


def is_transient(exc) -> bool:
    st = sqlstate_of(exc)
    if st:
        return st in _TRANSIENT or st.startswith("08")
    names = {c.__name__ for c in type(exc).__mro__}
    return bool(names & {"OperationalError", "PoolTimeout", "PoolClosed", "ConnectionError",
                         "TimeoutError", "InterfaceError"})


def map_error(exc) -> Exception:
    """psycopg error -> AgentGuard error (no driver message is propagated)."""
    if isinstance(exc, (StorageError, ConflictError)):
        return exc
    st = sqlstate_of(exc)
    if st in _CONFLICT:
        return ConflictError(_CONFLICT[st])
    if is_transient(exc):
        return StorageUnavailableError("database temporarily unavailable")
    return StorageError("database error")
