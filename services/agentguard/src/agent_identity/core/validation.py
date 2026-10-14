"""Strict input validation: allow-list patterns, size limits, no control/bidi chars."""
import json
import math
import re
from typing import Any, Iterable, Optional

from .errors import ValidationError

_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069\u200b-\u200f]")
ORG_ID = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,47}$")
AGENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}$")
AGENT_TYPE = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,47}$")
OWNER = re.compile(r"^[A-Za-z0-9@._+\- ]{1,128}$")
ENVIRONMENT = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,31}$")
CAPABILITY = re.compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
META_KEY = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
ACTOR = re.compile(r"^[A-Za-z0-9@._:/+\- ]{1,128}$")
MAX_CAPS, MAX_META_KEYS, MAX_META_BYTES = 64, 32, 4096


def check_pattern(field: str, value: Any, pattern: re.Pattern) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValidationError(f"invalid {field}")
    return value


def safe_text(field: str, value: Any, max_len: int) -> str:
    if not isinstance(value, str) or len(value) > max_len or _BAD_CHARS.search(value):
        raise ValidationError(f"invalid {field}")
    return value


def validate_capabilities(caps: Optional[Iterable[str]]) -> tuple:
    if caps is None:
        return ()
    if isinstance(caps, (str, bytes)):
        raise ValidationError("invalid capabilities")
    out = []
    for c in caps:
        check_pattern("capability", c, CAPABILITY)
        out.append(c)
    if len(out) > MAX_CAPS:
        raise ValidationError("too many capabilities")
    return tuple(sorted(set(out)))


def _check_meta_value(v: Any, depth: int) -> Any:
    if v is None or isinstance(v, (bool, int)):
        return v
    if isinstance(v, float):
        if not math.isfinite(v):
            raise ValidationError("invalid metadata value")
        return v
    if isinstance(v, str):
        return safe_text("metadata value", v, 256)
    if isinstance(v, list) and depth < 2 and len(v) <= 16:
        return [_check_meta_value(i, depth + 1) for i in v]
    raise ValidationError("invalid metadata value")


def validate_metadata(meta: Optional[dict]) -> dict:
    if meta is None:
        return {}
    if not isinstance(meta, dict) or len(meta) > MAX_META_KEYS:
        raise ValidationError("invalid metadata")
    out = {}
    for k, v in meta.items():
        if not isinstance(k, str) or not META_KEY.fullmatch(k) or k.startswith("__"):
            raise ValidationError("invalid metadata key")
        out[k] = _check_meta_value(v, 0)
    if len(json.dumps(out, separators=(",", ":"))) > MAX_META_BYTES:
        raise ValidationError("metadata too large")
    return out
