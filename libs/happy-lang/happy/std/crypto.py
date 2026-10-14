"""``std.crypto`` — hashing, encoding and token helpers for Happy.

Cryptographic operations are treated as sensitive: functions that touch key
material accept an optional active checker and require the ``secrets``
capability.  Pure digest / encoding helpers do not.

The module deliberately exposes only well-understood primitives (SHA-256,
HMAC, random tokens, base64/hex) built on the Python standard library, so
generated programs stay dependency-free.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import os
import secrets as _secrets
from typing import Any, Optional

from ..runtime.errors import HappyRuntimeError
from ..runtime.secrets import Secret

__all__ = [
    "sha256",
    "sha256_bytes",
    "hmac_sha256",
    "random_token",
    "random_bytes",
    "base64_encode",
    "base64_decode",
    "hex_encode",
    "hex_decode",
    "constant_time_equal",
    "PUBLIC",
]

PUBLIC = [
    "sha256",
    "hmac_sha256",
    "random_token",
    "base64_encode",
    "base64_decode",
    "hex_encode",
    "hex_decode",
    "constant_time_equal",
]

_CHECKER: Any = None


def use_checker(checker: Any) -> None:
    """Point ``std.crypto`` at the active capability checker."""
    global _CHECKER
    _CHECKER = checker


def _authorize(action: str) -> None:
    """Authorise an action (e.g. ``secrets``) via the active checker."""
    if _CHECKER is None:
        return
    require = getattr(_CHECKER, "require_action", None)
    if callable(require):
        require(action)
    else:
        _CHECKER.check_operation(action)


def _raw(value: Any) -> bytes:
    """Coerce a value to bytes without leaking a Secret into memory."""
    if isinstance(value, Secret):
        value = value.reveal(reason="crypto")
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return str(value).encode("utf-8")


def sha256(data: Any, __ctx__: Any = None) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(_raw(data)).hexdigest()


def sha256_bytes(data: Any, __ctx__: Any = None) -> bytes:
    """Return the raw SHA-256 digest of ``data``."""
    return hashlib.sha256(_raw(data)).digest()


def hmac_sha256(key: Any, message: Any, __ctx__: Any = None) -> str:
    """Return the hex HMAC-SHA256 of ``message`` under ``key`` (needs secrets)."""
    _authorize("secrets")
    return _hmac.new(_raw(key), _raw(message), hashlib.sha256).hexdigest()


def random_token(length: int = 32, __ctx__: Any = None) -> str:
    """Return a URL-safe random token of ``length`` bytes of entropy."""
    _authorize("secrets")
    return _secrets.token_urlsafe(length)


def random_bytes(length: int = 16, __ctx__: Any = None) -> bytes:
    """Return ``length`` cryptographically secure random bytes."""
    _authorize("secrets")
    return os.urandom(length)


def base64_encode(data: Any, __ctx__: Any = None) -> str:
    """Base64-encode ``data`` to a string."""
    return base64.b64encode(_raw(data)).decode("ascii")


def base64_decode(text: Any, __ctx__: Any = None) -> bytes:
    """Decode a base64 string to bytes."""
    try:
        return base64.b64decode(_raw(text))
    except Exception as exc:  # noqa: BLE001
        raise HappyRuntimeError(
            message=f"base64_decode failed: {exc}", code="R4501", cause=exc
        ) from exc


def hex_encode(data: Any, __ctx__: Any = None) -> str:
    """Hex-encode ``data`` to a string."""
    return _raw(data).hex()


def hex_decode(text: Any, __ctx__: Any = None) -> bytes:
    """Decode a hex string to bytes."""
    try:
        return bytes.fromhex(_raw(text).decode("ascii"))
    except Exception as exc:  # noqa: BLE001
        raise HappyRuntimeError(
            message=f"hex_decode failed: {exc}", code="R4502", cause=exc
        ) from exc


def constant_time_equal(a: Any, b: Any, __ctx__: Any = None) -> bool:
    """Compare two values in constant time (for secrets / MACs)."""
    return _hmac.compare_digest(_raw(a), _raw(b))
