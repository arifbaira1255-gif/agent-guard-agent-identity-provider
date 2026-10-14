"""Small, dependency-free validation and sanitisation helpers.

The platform must validate untrusted input (model output, tool arguments, webhook payloads) without
pulling in a schema library, and must be able to render any value safely into a log or an audit
event.  Both jobs live here.

A deliberately *small* JSON-Schema subset is implemented -- the parts a tool schema actually needs --
with one rule that matters: an unknown keyword is IGNORED but an unknown *type* is an ERROR, so a
typo in a tool schema fails loudly at registration rather than silently accepting anything.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Mapping

__all__ = [
    "canonical_json", "sha256_hex", "redact", "truncate", "scrub_secrets",
    "SchemaError", "validate_against_schema", "check_schema",
    "MAX_STRING", "MAX_DEPTH", "SECRET_KEY_RE",
]

#: Largest string retained in a sanitised record.  Longer values are truncated with a marker.
MAX_STRING = 4096
#: Largest nesting depth walked when sanitising.  Deeper structures are replaced by a marker.
MAX_DEPTH = 8

#: Keys whose VALUES are never emitted, whatever they hold.  Defence in depth: the platform also
#: never puts a secret into a record, but a caller-supplied metadata dict might.
SECRET_KEY_RE = re.compile(
    r"(pass(word|phrase)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|"
    r"authorization|cookie|session|bearer|signature|salt|otp|pin|ssn|credit|card|cvv)",
    re.IGNORECASE)

_REDACTED = "<redacted>"

#: Credential-shaped tokens that must never survive into a derived record, whatever field they sit in.
#: Deliberately narrow and high-precision: a false positive corrupts real content, so only the forms
#: that are unambiguously credentials are matched.
_SECRET_TOKEN_RE = re.compile(
    r"\b(sk-[A-Za-z0-9_\-]{8,}"
    r"|pk-[A-Za-z0-9_\-]{8,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9\-]{10,})\b")

#: ``key = value`` / ``key: value`` pairs where the KEY names a credential and the VALUE is a secret.
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(pass(?:word|phrase)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"credential|authorization|auth|bearer)\b(\s*[:=]\s*)([\"']?)([^\s\"',;\]}]{6,})")


def scrub_secrets(text: str) -> str:
    """Replace credential-shaped substrings inside free text.

    :func:`redact` removes values that sit under a secret-looking KEY, but a secret pasted into a
    sentence (a goal, a log line, a model answer) has no key at all.  This is the complementary pass,
    and it is what stops a user's ``api_key=...`` from being re-read out of memory or a trace later.
    """
    if not text:
        return text
    cleaned = _SECRET_TOKEN_RE.sub(_REDACTED, text)
    return _SECRET_ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{_REDACTED}",
                                 cleaned)


def canonical_json(value: Any) -> str:
    """Deterministic JSON (sorted keys, no spaces) -- the form a digest is taken over."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(text: Any) -> str:
    """SHA-256 of the UTF-8 encoding of ``text`` (a str is hashed as-is, anything else canonically)."""
    data = text if isinstance(text, str) else canonical_json(text)
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


def truncate(text: Any, limit: int = MAX_STRING) -> str:
    """Render ``text`` as a bounded string, with credentials scrubbed and cut content marked.

    Scrubbing here (not only in :func:`redact`) is deliberate: ``truncate`` is the single funnel every
    rendered record passes through -- a model answer, a tool result shown back to the model, a span
    attribute -- so a secret pasted into free text cannot survive into any of them.
    """
    rendered = text if isinstance(text, str) else str(text)
    rendered = scrub_secrets(rendered)
    if len(rendered) <= limit:
        return rendered
    return rendered[:limit] + f"...<+{len(rendered) - limit} chars>"


def redact(value: Any, *, _depth: int = 0, _key: str = "") -> Any:
    """Recursively replace secret-bearing values and bound the result.

    Used before anything is logged, traced or forwarded to the audit chain.  A key that *looks*
    secret has its value replaced even if it does not; a string that is not under a secret key is
    only truncated.
    """
    if _depth > MAX_DEPTH:
        return "<depth-limit>"
    if _key and SECRET_KEY_RE.search(str(_key)):
        return _REDACTED
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return truncate(value)
    if isinstance(value, Mapping):
        return {str(k)[:128]: redact(v, _depth=_depth + 1, _key=str(k))
                for k, v in list(value.items())[:64]}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact(v, _depth=_depth + 1, _key=_key) for v in list(value)[:256]]
    if isinstance(value, BaseException):
        return {"error": type(value).__name__, "message": truncate(str(value), 512)}
    return truncate(repr(value), 512)


# =============================================================================================
# Minimal JSON-Schema validation
# =============================================================================================
class SchemaError(Exception):
    """A schema itself is malformed (a programming error, not a data error)."""


#: The JSON-Schema subset the platform understands.  Anything else is ignored, except an unknown
#: ``type`` which is rejected -- silence there would make a tool accept arbitrary input.
_KNOWN_TYPES = ("object", "array", "string", "number", "integer", "boolean", "null")
_KNOWN_KEYWORDS = frozenset({
    "type", "properties", "required", "items", "enum", "minimum", "maximum",
    "minLength", "maxLength", "additionalProperties", "description", "title", "default",
    "oneOf", "anyOf", "minItems", "maxItems",
})


def check_schema(schema: Mapping[str, Any], *, where: str = "schema") -> None:
    """Reject a malformed schema up front (called at tool-registration time)."""
    if not isinstance(schema, Mapping):
        raise SchemaError(f"{where}: schema must be an object")
    unknown = set(schema) - _KNOWN_KEYWORDS
    if unknown:
        raise SchemaError(f"{where}: unsupported schema keyword(s): {sorted(unknown)}")
    declared = schema.get("type")
    if declared is not None:
        names = [declared] if isinstance(declared, str) else list(declared)
        for name in names:
            if name not in _KNOWN_TYPES:
                raise SchemaError(f"{where}: unknown type {name!r}; allowed: {list(_KNOWN_TYPES)}")
    for name, child in (schema.get("properties") or {}).items():
        check_schema(child, where=f"{where}.properties.{name}")
    if isinstance(schema.get("items"), Mapping):
        check_schema(schema["items"], where=f"{where}.items")
    for keyword in ("oneOf", "anyOf"):
        for i, child in enumerate(schema.get(keyword) or ()):
            check_schema(child, where=f"{where}.{keyword}[{i}]")


def _type_of(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, (list, tuple)):
        return "array"
    return type(value).__name__


def _matches_type(value: Any, declared: Any) -> bool:
    """``integer`` accepts a whole ``float``; ``number`` accepts an ``int``.  Both are deliberate."""
    names = [declared] if isinstance(declared, str) else list(declared or ())
    if not names:
        return True
    actual = _type_of(value)
    if actual in names:
        return True
    if actual == "integer" and "number" in names:
        return True
    if actual == "number" and "integer" in names and float(value).is_integer():
        return True
    return False


def validate_against_schema(value: Any, schema: Mapping[str, Any],
                           *, path: str = "$", _depth: int = 0) -> List[str]:
    """Validate ``value`` against the subset.  Returns a list of human-readable problems."""
    problems: List[str] = []
    if not isinstance(schema, Mapping):
        return [f"{path}: schema is not an object"]
    if _depth > 32:
        return [f"{path}: nesting too deep"]

    declared = schema.get("type")
    if declared is not None and not _matches_type(value, declared):
        return [f"{path}: expected {declared}, got {_type_of(value)}"]

    if "enum" in schema:
        allowed = list(schema["enum"] or [])
        if value not in allowed:
            problems.append(f"{path}: must be one of {allowed!r}")

    if "oneOf" in schema:
        matches = sum(1 for sub in schema["oneOf"]
                      if not validate_against_schema(value, sub, path=path))
        if matches != 1:
            problems.append(f"{path}: must match exactly one of the oneOf alternatives "
                            f"(matched {matches})")
    if "anyOf" in schema:
        if all(validate_against_schema(value, sub, path=path) for sub in schema["anyOf"]):
            problems.append(f"{path}: must match at least one of the anyOf alternatives")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            problems.append(f"{path}: shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            problems.append(f"{path}: longer than maxLength {schema['maxLength']}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and float(value) < float(schema["minimum"]):
            problems.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and float(value) > float(schema["maximum"]):
            problems.append(f"{path}: above maximum {schema['maximum']}")

    if isinstance(value, Mapping):
        properties = schema.get("properties") or {}
        for name in schema.get("required") or ():
            if name not in value:
                problems.append(f"{path}.{name}: required property is missing")
        for name, child in properties.items():
            if name in value:
                problems.extend(validate_against_schema(value[name], child,
                                                        path=f"{path}.{name}", _depth=_depth + 1))
        if schema.get("additionalProperties") is False:
            extra = sorted(set(value) - set(properties))
            if extra:
                problems.append(f"{path}: unexpected propert(ies) {extra}")

    if isinstance(value, (list, tuple)):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            problems.append(f"{path}: fewer than minItems {schema['minItems']}")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            problems.append(f"{path}: more than maxItems {schema['maxItems']}")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for i, item in enumerate(value):
                problems.extend(validate_against_schema(item, item_schema, path=f"{path}[{i}]",
                                                        _depth=_depth + 1))
    return problems
