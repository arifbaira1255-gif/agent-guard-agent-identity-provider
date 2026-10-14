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


# ---------------------------------------------------------------- Step 8 (enterprise authN/authZ)
class AuthenticationError(IdentityError):
    """Authentication failed (bad credentials, expired/revoked session, failed OIDC exchange)."""

    code = "authentication_failed"


class ForbiddenError(IdentityError):
    """Authenticated but not authorized (RBAC deny / tenant isolation deny)."""

    code = "forbidden"


class CsrfError(IdentityError):
    code = "csrf_failed"


class RateLimitedError(IdentityError):
    code = "rate_limited"
