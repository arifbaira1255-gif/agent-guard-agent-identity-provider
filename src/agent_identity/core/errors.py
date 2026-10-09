"""Exception hierarchy. Messages never contain secrets or key material."""


class IdentityError(Exception):
    code = "identity_error"


class ValidationError(IdentityError):
    code = "validation_error"


class NotFoundError(IdentityError):
    code = "not_found"


class ConflictError(IdentityError):
    code = "conflict"


class UnauthorizedError(IdentityError):
    code = "unauthorized"


class StorageError(IdentityError):
    code = "storage_error"


class TokenFormatError(IdentityError):
    code = "malformed_token"
