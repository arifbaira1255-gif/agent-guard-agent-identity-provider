"""JSON Schemas for the integration contract.

Both projects need to validate the same payloads, one of them without any third-party dependency, so
the schemas are expressed as plain Python data structures and a small validator is included.  The
schemas are the authoritative description of the wire format; :func:`assert_conforms` is the
executable form of that description and is used by the contract tests.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional

from .errors import ValidationError
from .version import CONTRACT_VERSION, SCHEMA_ID

#: Severity ordering for the supported JSON Schema subset.
_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
}

AUTHORIZATION_REQUEST_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "agentguard-happy-contract/v1/authorization-request",
    "title": "Happy LANG -> AgentGuard authorization request",
    "type": "object",
    "additionalProperties": True,          # additive-only evolution: unknown keys MUST be ignored
    "required": ["contract_version", "request_id", "correlation_id", "action", "resource",
                 "agent_id"],
    "properties": {
        "contract_version": {"type": "string"},
        "schema_version": {"type": "integer"},
        "request_id": {"type": "string", "maxLength": 128},
        "correlation_id": {"type": "string", "maxLength": 128},
        "action": {"type": "string", "maxLength": 256},
        "resource": {"type": "string", "maxLength": 1024},
        "agent_id": {"type": "string", "maxLength": 128},
        "instance_id": {"type": "string", "maxLength": 128},
        "org_id": {"type": "string", "maxLength": 128},
        "operation": {"type": "string", "maxLength": 256},
        "agent_scope": {"type": "string", "maxLength": 128},
        "requested_capabilities": {"type": "array", "items": {"type": "string"}, "maxItems": 64},
        "declared_resources": {"type": "array", "items": {"type": "string"}, "maxItems": 64},
        "effects": {"type": "array", "items": {"type": "string"}, "maxItems": 64},
        "contracts": {"type": "array", "items": {"type": "string"}, "maxItems": 32},
        "source_loc": {"type": ["object", "null"]},
        "artifact": {"type": ["object", "null"]},
        "context": {"type": ["object", "null"]},
        "token": {"type": "string"},
        "proof": {"type": ["object", "null"]},
        "audience": {"type": "string"},
    },
}

AUTHORIZATION_DECISION_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "agentguard-happy-contract/v1/authorization-decision",
    "title": "AgentGuard -> Happy LANG authorization decision",
    "type": "object",
    "additionalProperties": True,
    "required": ["allowed", "decision"],
    "properties": {
        "contract_version": {"type": "string"},
        "allowed": {"type": "boolean"},
        "decision": {"type": "string",
                     "enum": ["ALLOW", "DENY", "REQUIRE_APPROVAL", "INDETERMINATE"]},
        "reason": {"type": "string", "maxLength": 512},
        "decision_id": {"type": ["string", "null"]},
        "policy": {"type": ["string", "null"]},
        "policy_version": {"type": ["string", "null"]},
        "obligations": {"type": "array", "maxItems": 64},
        "correlation_id": {"type": ["string", "null"]},
        "request_id": {"type": ["string", "null"]},
        "latency_ms": {"type": ["integer", "null"]},
        "indeterminate": {"type": "boolean"},
    },
}

SECURITY_EVENT_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "agentguard-happy-contract/v1/security-event",
    "title": "Happy LANG -> AgentGuard security event",
    "type": "object",
    "additionalProperties": True,
    "required": ["event_type", "outcome"],
    "properties": {
        "event_type": {"type": "string", "maxLength": 128},
        "outcome": {"type": "string", "enum": ["ok", "denied", "error"]},
        "correlation_id": {"type": ["string", "null"]},
        "agent_id": {"type": ["string", "null"]},
        "instance_id": {"type": ["string", "null"]},
        "org_id": {"type": ["string", "null"]},
        "action": {"type": ["string", "null"], "maxLength": 256},
        "resource": {"type": ["string", "null"], "maxLength": 1024},
        "reason": {"type": ["string", "null"], "maxLength": 512},
        "metadata": {"type": ["object", "null"]},
    },
}

SECURITY_EVENT_BATCH_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "agentguard-happy-contract/v1/security-event-batch",
    "title": "Happy LANG -> AgentGuard security event batch",
    "type": "object",
    "additionalProperties": True,
    "required": ["events"],
    "properties": {"events": {"type": "array", "maxItems": 200}},
}

EXECUTION_REQUEST_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "agentguard-happy-contract/v1/execution-request",
    "title": "Structured integrated execution request",
    "type": "object",
    "additionalProperties": True,
    "required": ["contract_version", "request_id", "correlation_id", "agent_id", "artifact",
                 "requested_capabilities", "declared_resources", "policy_version", "limits"],
    "properties": {
        "contract_version": {"type": "string"},
        "schema_version": {"type": "integer"},
        "request_id": {"type": "string", "maxLength": 128},
        "correlation_id": {"type": "string", "maxLength": 128},
        "agent_id": {"type": "string", "maxLength": 128},
        "instance_id": {"type": ["string", "null"]},
        "org_id": {"type": ["string", "null"]},
        "artifact": {"type": "object"},
        "entry": {"type": "string", "maxLength": 128},
        "requested_capabilities": {"type": "array", "items": {"type": "string"},
                                   "minItems": 1, "maxItems": 64},
        "declared_resources": {"type": "array", "minItems": 1, "maxItems": 64},
        "policy_id": {"type": ["string", "null"]},
        "policy_version": {"type": "string"},
        "limits": {"type": "object"},
        "context": {"type": ["object", "null"]},
    },
}

EXECUTION_RESULT_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "agentguard-happy-contract/v1/execution-result",
    "title": "Structured integrated execution result",
    "type": "object",
    "additionalProperties": True,
    "required": ["contract_version", "result", "ok", "request_id", "correlation_id"],
    "properties": {
        "contract_version": {"type": "string"},
        "result": {"type": "string",
                   "enum": ["ok", "authorization_denied", "policy_violation", "require_approval",
                            "compile_error", "validation_error", "runtime_error", "resource_limit",
                            "cancelled", "timeout", "isolation_unavailable", "integration_error",
                            "internal_error"]},
        "ok": {"type": "boolean"},
        "request_id": {"type": "string"},
        "correlation_id": {"type": "string"},
        "output": {"type": "string"},
        "error": {"type": ["string", "null"]},
        "error_code": {"type": ["string", "null"]},
        "decision": {"type": ["object", "null"]},
        "source_loc": {"type": ["object", "null"]},
        "diagnostics": {"type": "array"},
        "duration_ms": {"type": "number"},
        "operations": {"type": "integer"},
        "metadata": {"type": ["object", "null"]},
    },
}

SCHEMAS: Dict[str, Dict[str, Any]] = {
    "authorization_request": AUTHORIZATION_REQUEST_SCHEMA,
    "authorization_decision": AUTHORIZATION_DECISION_SCHEMA,
    "security_event": SECURITY_EVENT_SCHEMA,
    "security_event_batch": SECURITY_EVENT_BATCH_SCHEMA,
    "execution_request": EXECUTION_REQUEST_SCHEMA,
    "execution_result": EXECUTION_RESULT_SCHEMA,
}


def schema_names() -> Iterable[str]:
    return tuple(SCHEMAS.keys())


def _validate(schema: Mapping[str, Any], value: Any, path: str, errors: List[str]) -> None:
    expected = schema.get("type")
    if expected is not None:
        candidates = expected if isinstance(expected, list) else [expected]
        ok = False
        for candidate in candidates:
            python_type = _TYPES.get(candidate)
            if python_type is None:
                continue
            if candidate in ("integer", "number") and isinstance(value, bool):
                continue
            if isinstance(value, python_type) and not (candidate == "integer" and isinstance(
                    value, bool)):
                ok = True
                break
        if not ok:
            errors.append(f"{path}: expected type {expected}, got {type(value).__name__}")
            return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: must be one of {schema['enum']}, got {value!r}")
    if isinstance(value, str) and "maxLength" in schema and len(value) > schema["maxLength"]:
        errors.append(f"{path}: exceeds maxLength {schema['maxLength']}")
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: exceeds maxItems {schema['maxItems']}")
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: fewer than minItems {schema['minItems']}")
    if isinstance(value, Mapping):
        for key in schema.get("required", ()):
            if key not in value:
                errors.append(f"{path}.{key}: is required")
        properties = schema.get("properties") or {}
        for key, subschema in properties.items():
            if key in value and value[key] is not None:
                _validate(subschema, value[key], f"{path}.{key}", errors)


def validate_payload(name: str, value: Any) -> List[str]:
    """Return the list of schema violations for ``name`` (empty when it conforms)."""
    schema = SCHEMAS.get(name)
    if schema is None:
        raise ValidationError(f"unknown schema {name!r}", field="schema")
    errors: List[str] = []
    _validate(schema, value, name, errors)
    return errors


def assert_conforms(name: str, value: Any) -> None:
    """Raise :class:`ValidationError` when ``value`` violates schema ``name``."""
    errors = validate_payload(name, value)
    if errors:
        raise ValidationError(f"payload does not conform to {name}", errors=errors)


__all__ = [
    "SCHEMAS", "schema_names", "validate_payload", "assert_conforms",
    "AUTHORIZATION_REQUEST_SCHEMA", "AUTHORIZATION_DECISION_SCHEMA", "SECURITY_EVENT_SCHEMA",
    "SECURITY_EVENT_BATCH_SCHEMA", "EXECUTION_REQUEST_SCHEMA", "EXECUTION_RESULT_SCHEMA",
    "SCHEMA_ID", "CONTRACT_VERSION",
]
