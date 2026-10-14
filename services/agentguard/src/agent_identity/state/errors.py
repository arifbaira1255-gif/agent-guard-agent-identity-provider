"""Redis/state errors. Messages never contain driver text (can echo URLs/credentials)."""
from ..core.errors import ConflictError, StorageError


class StateUnavailableError(StorageError):
    """Redis unreachable / timeout / auth failure / pool exhausted. Security callers MUST deny or bypass the
    cache (never assume 'not seen' / 'not revoked' / 'allowed')."""
    code = "state_unavailable"


class StateCorruptError(StorageError):
    code = "state_corrupt"


class StateConflictError(ConflictError):
    code = "state_conflict"


class StateConfigError(ValueError):
    pass


class LockNotAcquired(StorageError):
    code = "lock_not_acquired"
