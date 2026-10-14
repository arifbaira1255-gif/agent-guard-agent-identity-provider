"""Governance input validation.

Untrusted metadata (ids, operations, capability names, manifests) is validated HERE before it ever
reaches a registry, a policy decision, or a connector. The rules are deliberately strict:

* identifiers are bounded length and drawn from a closed character set — no whitespace, no ``*``
  wildcards, no ``..`` traversal, no braces/quotes/control characters. A single ``:`` is permitted
  as the resource-CLASS separator (``tool:lookup``, ``api:billing``); the authoritative tenant/type
  always comes from the registry, never from the identifier text;
* operations and capability names are from closed sets where possible;
* manifests are size-bounded and structurally checked — a manifest can never *grant* a capability,
  it can only *request* one.
"""
from __future__ import annotations

import re

from .errors import RegistryValidationError
from .models import ID_MAX, Operation

#: A safe governed identifier: lowercase/uppercase, digits, dot, dash, underscore, ``:`` (resource
#: CLASS namespacing, e.g. ``tool:lookup``/``api:billing``), and ``/`` for hierarchical ids. No
#: wildcard, no whitespace, no brace/quote/control characters, no ``..`` traversal.
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,199}$")
_CAP_RE = re.compile(r"^[a-z][a-z0-9:_\-]{0,127}$")
_WS_RE = re.compile(r"\s")

MAX_CAPABILITIES = 64
MAX_OPERATIONS = 32
MAX_POLICY_REFS = 32


def validate_id(value, *, field: str = "id", required: bool = True) -> str:
    if value is None or value == "":
        if required:
            raise RegistryValidationError(f"{field} is required")
        return ""
    if not isinstance(value, str):
        raise RegistryValidationError(f"{field} must be a string")
    v = value.strip()
    if len(v) > ID_MAX:
        raise RegistryValidationError(f"{field} is too long")
    if not _ID_RE.match(v):
        raise RegistryValidationError(f"{field} contains invalid characters")
    if ".." in v or "*" in v:
        raise RegistryValidationError(f"{field} must be an exact, non-wildcard identifier")
    return v


def validate_operation(value) -> Operation:
    op = Operation.coerce(value)
    if op is None:
        raise RegistryValidationError("unknown operation")
    return op


def validate_operations(values) -> frozenset:
    """Validate a collection of operations. An empty collection is permitted (denies everything),
    but wildcards and over-long lists are rejected."""
    if values is None:
        return frozenset()
    if isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
        raise RegistryValidationError("operations must be a list")
    values = list(values)
    if len(values) > MAX_OPERATIONS:
        raise RegistryValidationError("too many operations")
    out = set()
    for v in values:
        out.add(validate_operation(v))
    return frozenset(out)


def validate_capabilities(values, *, field: str = "capabilities") -> tuple:
    """Validate a capability list. Capabilities are NAMES ONLY — they never carry a grant."""
    if values is None:
        return ()
    if isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
        raise RegistryValidationError(f"{field} must be a list")
    values = list(values)
    if len(values) > MAX_CAPABILITIES:
        raise RegistryValidationError(f"too many {field}")
    out = []
    for v in values:
        if not isinstance(v, str):
            raise RegistryValidationError(f"{field} entries must be strings")
        c = v.strip()
        if not _CAP_RE.match(c):
            raise RegistryValidationError(f"invalid capability name in {field}")
        out.append(c)
    return tuple(sorted(set(out)))


def validate_policy_refs(values) -> tuple:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
        raise RegistryValidationError("policy_refs must be a list")
    values = list(values)
    if len(values) > MAX_POLICY_REFS:
        raise RegistryValidationError("too many policy_refs")
    return tuple(validate_id(v, field="policy_ref") for v in values)


def validate_free_text(value, *, field: str = "text", max_len: int = 1024) -> str:
    """A bounded, control-character-free description/short text field."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RegistryValidationError(f"{field} must be a string")
    v = _WS_RE.sub(" ", value.replace("\n", " ").replace("\r", " ")).strip()
    if len(v) > max_len:
        raise RegistryValidationError(f"{field} is too long")
    return v


def validate_metadata(value) -> dict:
    """Registry metadata is a flat, primitive-only mapping of bounded size.

    Nested structures are rejected: a registry record must never become a smuggling channel for
    credentials, payloads or executable content.
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RegistryValidationError("metadata must be an object")
    if len(value) > 32:
        raise RegistryValidationError("metadata has too many keys")
    out = {}
    for k, v in value.items():
        if not isinstance(k, str) or len(k) > 64:
            raise RegistryValidationError("metadata keys must be short strings")
        if isinstance(v, (dict, list, tuple, set)):
            raise RegistryValidationError("metadata values must be primitives")
        if v is not None and not isinstance(v, (str, int, float, bool)):
            raise RegistryValidationError("metadata values must be primitives")
        if isinstance(v, str) and len(v) > 256:
            raise RegistryValidationError("metadata string values are too long")
        out[k] = v
    return out


def validate_manifest(value) -> dict:
    """Validate a (untrusted) tool manifest.

    A manifest may declare a name, version, capabilities it *requests*, and descriptive metadata.
    Anything else is ignored. Crucially: validation never turns a requested capability into an
    approved one, and no manifest field can bypass the registry approval step.
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RegistryValidationError("manifest must be an object")
    if len(value) > 64:
        raise RegistryValidationError("manifest is too large")
    allowed = {"name", "version", "capabilities", "description", "risk", "resource_id", "metadata"}
    extra = set(value) - allowed
    if extra:
        raise RegistryValidationError(f"manifest contains unsupported fields: {sorted(extra)[:4]}")
    out = {}
    if "name" in value:
        out["name"] = validate_id(value["name"], field="manifest name")
    if "version" in value:
        out["version"] = validate_free_text(value["version"], field="manifest version", max_len=64)
    if "capabilities" in value:
        out["capabilities"] = validate_capabilities(value["capabilities"],
                                                    field="manifest capabilities")
    if "description" in value:
        out["description"] = validate_free_text(value["description"], field="description")
    if "risk" in value:
        out["risk"] = validate_free_text(value["risk"], field="risk", max_len=16)
    if "resource_id" in value:
        out["resource_id"] = validate_id(value["resource_id"], field="resource_id")
    if "metadata" in value:
        out["metadata"] = validate_metadata(value["metadata"])
    return out
