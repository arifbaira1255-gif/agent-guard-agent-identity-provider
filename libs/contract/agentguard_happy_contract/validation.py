"""Strict, dependency-free validation, canonicalisation and redaction helpers.

Every helper appends a human-readable problem to a caller-supplied list instead of raising, so a
caller can report ALL problems with one payload (and so a malformed request is never half-applied).
:func:`raise_if` converts the collected list into a single :class:`ValidationError`.

This is the input-validation layer required at the trust boundary: the Happy LANG process is
semi-trusted, so every string that reaches AgentGuard is length-capped, charset-checked and
type-checked before it is used.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Mapping, Optional, Pattern, Sequence

from .errors import ValidationError

#: Identifier / action charset.  Deliberately excludes whitespace and control characters so a value
#: can never smuggle a delimiter into a downstream header, log line or policy input document.
SAFE_TOKEN_RE: Pattern[str] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@=+~-]*$")

#: Resource-target charset: the safe-token set plus the punctuation a path/URL-shaped target needs.
#: Note the leading character may be ``/``, ``.`` or ``~`` (absolute paths, relative paths, home),
#: so there is deliberately no first-character class here -- but whitespace and control characters
#: are still excluded so a value can never smuggle a delimiter downstream.
SAFE_RESOURCE_RE: Pattern[str] = re.compile(r"^[A-Za-z0-9._:/@=+~,()\[\]{}\- ]+$")

# --- hard bounds -----------------------------------------------------------------------------
MAX_ID_LEN = 128
MAX_ACTION_LEN = 256
MAX_RESOURCE_LEN = 1024
MAX_REASON_LEN = 512
MAX_EVENT_TYPE_LEN = 128
MAX_METADATA_KEYS = 32
MAX_METADATA_VALUE_LEN = 512
MAX_CAPABILITIES = 64
MAX_RESOURCES = 64
MAX_CONTRACTS = 32

HARD_MAX_TIMEOUT_S = 300.0
HARD_MAX_MEMORY_MB = 4096.0
HARD_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
HARD_MAX_OPERATIONS = 1_000_000

_HEX64_RE: Pattern[str] = re.compile(r"^[0-9a-f]{64}$")

_REDACT_MARKERS = (
    "bearer ", "agp1.", "-----begin", "private key", "password", "passwd",
    "secret", "token", "api_key", "apikey", "credential",
)


def add_error(errors: List[str], field_name: str, message: str) -> None:
    errors.append(f"{field_name}: {message}")


def check_str(errors: List[str], field_name: str, value: Any, *, max_len: int = MAX_ID_LEN,
              required: bool = True, allow_empty: bool = False,
              pattern: Optional[Pattern[str]] = None) -> Optional[str]:
    if value is None:
        if required:
            add_error(errors, field_name, "is required")
        return None
    if not isinstance(value, str):
        add_error(errors, field_name, f"must be a string, got {type(value).__name__}")
        return None
    if not allow_empty and not value.strip():
        add_error(errors, field_name, "must not be empty")
        return None
    if len(value) > max_len:
        add_error(errors, field_name, f"exceeds maximum length {max_len}")
        return None
    if pattern is not None and not pattern.match(value):
        add_error(errors, field_name, "contains disallowed characters")
        return None
    return value


def check_bool(errors: List[str], field_name: str, value: Any, *, required: bool = True) -> Optional[bool]:
    if value is None:
        if required:
            add_error(errors, field_name, "is required")
        return None
    if not isinstance(value, bool):
        add_error(errors, field_name, f"must be a boolean, got {type(value).__name__}")
        return None
    return value


def check_int(errors: List[str], field_name: str, value: Any, *, minimum: Optional[int] = None,
              maximum: Optional[int] = None, required: bool = True) -> Optional[int]:
    if value is None:
        if required:
            add_error(errors, field_name, "is required")
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        add_error(errors, field_name, f"must be an integer, got {type(value).__name__}")
        return None
    if minimum is not None and value < minimum:
        add_error(errors, field_name, f"must be >= {minimum}")
        return None
    if maximum is not None and value > maximum:
        add_error(errors, field_name, f"must be <= {maximum}")
        return None
    return value


def check_float(errors: List[str], field_name: str, value: Any, *, minimum: Optional[float] = None,
                maximum: Optional[float] = None, required: bool = True) -> Optional[float]:
    if value is None:
        if required:
            add_error(errors, field_name, "is required")
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        add_error(errors, field_name, f"must be a number, got {type(value).__name__}")
        return None
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        add_error(errors, field_name, "must be a finite number")
        return None
    if minimum is not None and number < minimum:
        add_error(errors, field_name, f"must be >= {minimum}")
        return None
    if maximum is not None and number > maximum:
        add_error(errors, field_name, f"must be <= {maximum}")
        return None
    return number


def check_enum(errors: List[str], field_name: str, value: Any, enum_cls, *, required: bool = True):
    if value is None:
        if required:
            add_error(errors, field_name, "is required")
        return None
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(value)
    except Exception:
        allowed = ", ".join(sorted(str(m.value) for m in enum_cls))
        add_error(errors, field_name, f"must be one of [{allowed}], got {value!r}")
        return None


def check_mapping(errors: List[str], field_name: str, value: Any,
                  *, required: bool = False) -> Optional[Dict[str, Any]]:
    if value is None:
        if required:
            add_error(errors, field_name, "is required")
        return None
    if not isinstance(value, Mapping):
        add_error(errors, field_name, f"must be an object, got {type(value).__name__}")
        return None
    return dict(value)


def check_sequence_of_str(errors: List[str], field_name: str, value: Any, *,
                          max_items: int = MAX_CAPABILITIES, required: bool = False,
                          allow_empty: bool = True) -> Optional[tuple]:
    if value is None:
        if required:
            add_error(errors, field_name, "is required")
        return None
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        add_error(errors, field_name, f"must be a list, got {type(value).__name__}")
        return None
    if len(value) > max_items:
        add_error(errors, field_name, f"exceeds maximum of {max_items} items")
        return None
    out: List[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            add_error(errors, field_name, f"[{i}] must be a non-empty string")
            continue
        if len(item) > MAX_ACTION_LEN:
            add_error(errors, field_name, f"[{i}] exceeds maximum length {MAX_ACTION_LEN}")
            continue
        out.append(item)
    if not out and not allow_empty:
        add_error(errors, field_name, "must not be empty")
    return tuple(out)


def check_sha256(errors: List[str], field_name: str, value: Any,
                 *, required: bool = False) -> Optional[str]:
    if value is None:
        if required:
            add_error(errors, field_name, "is required")
        return None
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        add_error(errors, field_name, "must be a 64-character lowercase hex sha256 digest")
        return None
    return value


def raise_if(errors: Sequence[str], *, where: str = "request",
             field_name: Optional[str] = None) -> None:
    """Turn a collected error list into a single :class:`ValidationError`."""
    if errors:
        raise ValidationError(f"invalid {where}", errors=list(errors), field=field_name)


def canonical_json(value: Any) -> str:
    """Deterministic JSON (sorted keys, no incidental whitespace) for hashing/dedup/audit."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(value: Any) -> str:
    """Canonical sha256 digest of ``value`` (accepts str/bytes/anything JSON-serialisable)."""
    if isinstance(value, str):
        if len(value) == 64 and _HEX64_RE.match(value):
            return value
        data = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray)):
        data = bytes(value)
    else:
        data = canonical_json(value).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def redact(value: Any) -> Any:
    """Best-effort redaction for metadata that leaves the process (never emit bearer material)."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = value if isinstance(value, str) else str(value)
    lowered = text.lower()
    for marker in _REDACT_MARKERS:
        if marker in lowered:
            return "<redacted>"
    return text[:MAX_METADATA_VALUE_LEN]


def clean_metadata(metadata: Optional[Mapping[str, Any]],
                   *, max_keys: int = MAX_METADATA_KEYS) -> Dict[str, Any]:
    """Bound and redact an arbitrary metadata mapping."""
    if not metadata:
        return {}
    out: Dict[str, Any] = {}
    for key, value in list(metadata.items())[:max_keys]:
        if not isinstance(key, str) or not key.strip() or len(key) > MAX_ID_LEN:
            continue
        out[key] = redact(value)
    return out


__all__ = [
    "SAFE_TOKEN_RE", "SAFE_RESOURCE_RE",
    "MAX_ID_LEN", "MAX_ACTION_LEN", "MAX_RESOURCE_LEN", "MAX_REASON_LEN",
    "MAX_EVENT_TYPE_LEN", "MAX_METADATA_KEYS", "MAX_METADATA_VALUE_LEN",
    "MAX_CAPABILITIES", "MAX_RESOURCES", "MAX_CONTRACTS",
    "HARD_MAX_TIMEOUT_S", "HARD_MAX_MEMORY_MB", "HARD_MAX_OUTPUT_BYTES", "HARD_MAX_OPERATIONS",
    "add_error", "check_str", "check_bool", "check_int", "check_float", "check_enum",
    "check_mapping", "check_sequence_of_str", "check_sha256", "raise_if",
    "canonical_json", "sha256_hex", "redact", "clean_metadata",
]
