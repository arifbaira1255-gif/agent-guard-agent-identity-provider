"""Typed, versioned data models for the AgentGuard x Happy LANG integration contract.

These models are the ONLY sanctioned way for the two projects to exchange an authorization
request, its decision, a security event, and a structured execution request/result.  They are
plain ``dataclasses`` with explicit ``to_dict`` / ``from_dict`` and an independent ``validate`` so
that:

* a payload is checked **before** it is used (never after),
* serialisation only ever emits JSON-safe primitives,
* unknown fields from a newer peer are ignored (additive-only evolution), and
* no field can carry credential material off the process (``to_dict`` is secret-safe by design).

Mapping to the EXISTING AgentGuard surface (no change to AgentGuard required):
  * :meth:`AuthorizationRequest.to_authorize_body` produces a superset of the body that
    ``POST /v1/authorize`` already accepts (``action``, ``resource``, ``context``, ``token``,
    ``proof``, ``audience``, ``correlation_id``).  The Happy LANG additions live under the
    namespaced ``context['happy']`` block, which AgentGuard treats as untrusted input.
  * :meth:`AuthorizationDecision.from_agentguard_dict` parses the decision that
    ``/v1/authorize`` already returns (``allowed``, ``reason``, ``decision_id``, ``policy``,
    ``obligations``, ``correlation_id``).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .errors import UnsupportedContractVersion, ValidationError
from .validation import (
    HARD_MAX_MEMORY_MB,
    HARD_MAX_OPERATIONS,
    HARD_MAX_OUTPUT_BYTES,
    HARD_MAX_TIMEOUT_S,
    MAX_ACTION_LEN,
    MAX_CAPABILITIES,
    MAX_CONTRACTS,
    MAX_EVENT_TYPE_LEN,
    MAX_ID_LEN,
    MAX_REASON_LEN,
    MAX_RESOURCES,
    MAX_RESOURCE_LEN,
    SAFE_RESOURCE_RE,
    SAFE_TOKEN_RE,
    canonical_json,
    check_bool,
    check_enum,
    check_float,
    check_int,
    check_mapping,
    check_sequence_of_str,
    check_sha256,
    check_str,
    clean_metadata,
    raise_if,
    sha256_hex,
)
from .version import CONTRACT_VERSION, SCHEMA_ID, is_supported


def new_id(prefix: str) -> str:
    """Mint a new correlation/request identifier (contract-scoped, opaque)."""
    return f"{prefix}_{uuid.uuid4().hex}"


def _json_safe(value: Any, *, _depth: int = 0) -> Any:
    """Coerce a value into something ``json.dumps`` can always emit.

    Prevents a caller from smuggling a non-serialisable (or pathologically deep) object across the
    trust boundary -- such an object is replaced by its bounded ``repr`` rather than raising deep
    inside the transport.
    """
    if _depth > 8:
        return "<truncated>"
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(k)[:MAX_ID_LEN]: _json_safe(v, _depth=_depth + 1)
                for k, v in list(value.items())[:64]}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v, _depth=_depth + 1) for v in list(value)[:256]]
    return str(value)[:512]


# =============================================================================================
# Decision enum
# =============================================================================================
class Decision(str, Enum):
    """Authorization outcome.  ``INDETERMINATE`` is the fail-closed outcome for any uncertainty."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    INDETERMINATE = "INDETERMINATE"


class ResultKind(str, Enum):
    """The structured outcome of an integrated execution."""

    OK = "ok"                                  # successful validation + authorized + completed
    AUTHORIZATION_DENIED = "authorization_denied"
    POLICY_VIOLATION = "policy_violation"
    REQUIRE_APPROVAL = "require_approval"
    COMPILE_ERROR = "compile_error"
    VALIDATION_ERROR = "validation_error"
    RUNTIME_ERROR = "runtime_error"
    RESOURCE_LIMIT = "resource_limit"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    ISOLATION_UNAVAILABLE = "isolation_unavailable"
    INTEGRATION_ERROR = "integration_error"
    INTERNAL_ERROR = "internal_error"


class SecurityEventOutcome(str, Enum):
    OK = "ok"
    DENIED = "denied"
    ERROR = "error"


# =============================================================================================
# Authorization request
# =============================================================================================
@dataclass(frozen=True)
class SourceLocation:
    """Where in the ``.hpy`` source the protected operation appears."""

    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.file is not None:
            out["file"] = self.file
        if self.line is not None:
            out["line"] = self.line
        if self.column is not None:
            out["column"] = self.column
        return out

    @classmethod
    def from_dict(cls, d: Optional[Mapping[str, Any]]) -> "SourceLocation":
        if not isinstance(d, Mapping):
            return cls()
        return cls(file=d.get("file"), line=d.get("line"), column=d.get("column"))

    def validate(self) -> None:
        errors: List[str] = []
        if self.file is not None:
            check_str(errors, "source_loc.file", self.file, max_len=MAX_RESOURCE_LEN,
                      required=False, allow_empty=True)
        if self.line is not None:
            check_int(errors, "source_loc.line", self.line, minimum=0, required=False)
        if self.column is not None:
            check_int(errors, "source_loc.column", self.column, minimum=0, required=False)
        raise_if(errors, where="source location")

    def render(self) -> str:
        parts = []
        if self.file:
            parts.append(str(self.file))
        if self.line is not None:
            parts.append(str(self.line))
            if self.column is not None:
                parts.append(str(self.column))
        return ":".join(parts) if parts else "<unknown>"


@dataclass(frozen=True)
class ArtifactRef:
    """A reference to the compiled/executable artifact the request is about.

    Carries a digest rather than the program text, so the authorization request stays small and the
    policy input document never becomes an exfiltration channel.
    """

    digest: Optional[str] = None
    entry: str = "main"
    filename: Optional[str] = None
    bytes_size: Optional[int] = None
    language_version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"entry": self.entry}
        for key in ("digest", "filename", "bytes_size", "language_version"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        return out

    @classmethod
    def from_dict(cls, d: Optional[Mapping[str, Any]]) -> "ArtifactRef":
        if not isinstance(d, Mapping):
            return cls()
        return cls(digest=d.get("digest"), entry=d.get("entry") or "main",
                   filename=d.get("filename"), bytes_size=d.get("bytes_size"),
                   language_version=d.get("language_version"))

    def validate(self) -> None:
        errors: List[str] = []
        check_sha256(errors, "artifact.digest", self.digest, required=False)
        check_str(errors, "artifact.entry", self.entry, max_len=MAX_ID_LEN, required=False,
                  allow_empty=False) if self.entry else None
        if self.filename is not None:
            check_str(errors, "artifact.filename", self.filename, max_len=MAX_RESOURCE_LEN,
                      required=False, allow_empty=True)
        if self.bytes_size is not None:
            check_int(errors, "artifact.bytes_size", self.bytes_size, minimum=0, required=False)
        raise_if(errors, where="artifact reference")


@dataclass(frozen=True)
class AuthorizationRequest:
    """A typed request asking AgentGuard whether a Happy LANG operation is permitted.

    AgentGuard is authoritative: it re-derives the identity from the verified credential, treats
    ``requested_capabilities`` / ``declared_resources`` as *claims* (never as grants), and fails
    closed on any uncertainty.
    """

    action: str
    resource: str
    agent_id: str
    request_id: str = field(default_factory=lambda: new_id("req"))
    correlation_id: str = field(default_factory=lambda: new_id("corr"))
    instance_id: Optional[str] = None
    org_id: Optional[str] = None
    requested_capabilities: Tuple[str, ...] = ()
    declared_resources: Tuple[str, ...] = ()
    operation: Optional[str] = None
    source_loc: SourceLocation = field(default_factory=SourceLocation)
    agent_scope: Optional[str] = None
    effects: Tuple[str, ...] = ()
    contracts: Tuple[str, ...] = ()
    artifact: ArtifactRef = field(default_factory=ArtifactRef)
    context: Dict[str, Any] = field(default_factory=dict)
    contract_version: str = CONTRACT_VERSION
    schema_version: int = 1

    # -- validation --------------------------------------------------------------------------
    def validate(self) -> None:
        errors: List[str] = []
        check_str(errors, "action", self.action, max_len=MAX_ACTION_LEN, pattern=SAFE_TOKEN_RE)
        check_str(errors, "resource", self.resource, max_len=MAX_RESOURCE_LEN,
                  pattern=SAFE_RESOURCE_RE)
        check_str(errors, "agent_id", self.agent_id, max_len=MAX_ID_LEN, pattern=SAFE_TOKEN_RE)
        check_str(errors, "request_id", self.request_id, max_len=MAX_ID_LEN, pattern=SAFE_TOKEN_RE)
        check_str(errors, "correlation_id", self.correlation_id, max_len=MAX_ID_LEN,
                  pattern=SAFE_TOKEN_RE)
        if self.instance_id is not None:
            check_str(errors, "instance_id", self.instance_id, max_len=MAX_ID_LEN,
                      pattern=SAFE_TOKEN_RE)
        if self.org_id is not None:
            check_str(errors, "org_id", self.org_id, max_len=MAX_ID_LEN, pattern=SAFE_TOKEN_RE)
        if self.operation is not None:
            check_str(errors, "operation", self.operation, max_len=MAX_ACTION_LEN,
                      pattern=SAFE_TOKEN_RE)
        if self.agent_scope is not None:
            check_str(errors, "agent_scope", self.agent_scope, max_len=MAX_ID_LEN,
                      pattern=SAFE_TOKEN_RE)
        check_sequence_of_str(errors, "requested_capabilities", list(self.requested_capabilities),
                              max_items=MAX_CAPABILITIES)
        check_sequence_of_str(errors, "declared_resources", list(self.declared_resources),
                              max_items=MAX_RESOURCES)
        check_sequence_of_str(errors, "effects", list(self.effects), max_items=MAX_CAPABILITIES)
        check_sequence_of_str(errors, "contracts", list(self.contracts), max_items=MAX_CONTRACTS)
        check_mapping(errors, "context", self.context)
        if not is_supported(self.contract_version):
            raise UnsupportedContractVersion(
                f"authorization request: unsupported contract_version "
                f"{self.contract_version!r}", field="contract_version")
        self.source_loc.validate()
        self.artifact.validate()
        raise_if(errors, where="authorization request")

    # -- (de)serialisation -------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe payload (NO credential material -- the credential is added by the client)."""
        out: Dict[str, Any] = {
            "contract_version": self.contract_version,
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "action": self.action,
            "resource": self.resource,
            "agent_id": self.agent_id,
            "requested_capabilities": list(self.requested_capabilities),
            "declared_resources": list(self.declared_resources),
            "effects": list(self.effects),
            "contracts": list(self.contracts),
            "source_loc": self.source_loc.to_dict(),
            "artifact": self.artifact.to_dict(),
            "context": _json_safe(self.context),
        }
        for key in ("instance_id", "org_id", "operation", "agent_scope"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        return out

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "AuthorizationRequest":
        if not isinstance(d, Mapping):
            raise ValidationError("authorization request must be an object",
                                  field="authorization_request")
        request = cls(
            action=d.get("action", ""),
            resource=d.get("resource", ""),
            agent_id=d.get("agent_id", ""),
            request_id=d.get("request_id") or new_id("req"),
            correlation_id=d.get("correlation_id") or new_id("corr"),
            instance_id=d.get("instance_id"),
            org_id=d.get("org_id"),
            requested_capabilities=tuple(d.get("requested_capabilities") or ()),
            declared_resources=tuple(d.get("declared_resources") or ()),
            operation=d.get("operation"),
            source_loc=SourceLocation.from_dict(d.get("source_loc")),
            agent_scope=d.get("agent_scope"),
            effects=tuple(d.get("effects") or ()),
            contracts=tuple(d.get("contracts") or ()),
            artifact=ArtifactRef.from_dict(d.get("artifact")),
            context=dict(d.get("context") or {}),
            contract_version=d.get("contract_version") or "",
            schema_version=d.get("schema_version", 1),
        )
        request.validate()
        return request

    # -- AgentGuard mapping ------------------------------------------------------------------
    def happy_context(self) -> Dict[str, Any]:
        """The namespaced, additive-only ``context['happy']`` extension AgentGuard must ignore."""
        return {
            "contract_version": self.contract_version,
            "schema_id": SCHEMA_ID,
            "request_id": self.request_id,
            "operation": self.operation,
            "requested_capabilities": list(self.requested_capabilities),
            "declared_resources": list(self.declared_resources),
            "source_loc": self.source_loc.to_dict(),
            "agent_scope": self.agent_scope,
            "effects": list(self.effects),
            "contracts": list(self.contracts),
            "artifact": self.artifact.to_dict(),
            "context": _json_safe(self.context),
        }

    def to_authorize_body(self, *, token: str = "", proof: Optional[dict] = None,
                          audience: Optional[str] = None) -> Dict[str, Any]:
        """Build the ``POST /v1/authorize`` body (superset of what AgentGuard already accepts).

        ``token``/``proof`` are the credential and possession proof; they are the ONLY secret
        material and are never included by :meth:`to_dict`.
        """
        body: Dict[str, Any] = {
            "contract_version": self.contract_version,
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "action": self.action,
            "resource": self.resource,
            "agent_id": self.agent_id,
            "requested_capabilities": list(self.requested_capabilities),
            "declared_resources": list(self.declared_resources),
            "context": {"happy": self.happy_context()},
        }
        if self.instance_id:
            body["instance_id"] = self.instance_id
        if self.org_id:
            body["org_id"] = self.org_id
        if self.operation:
            body["operation"] = self.operation
        if token:
            body["token"] = token
        if proof is not None:
            body["proof"] = proof
        if audience:
            body["audience"] = audience
        return body


# =============================================================================================
# Authorization decision
# =============================================================================================
@dataclass(frozen=True)
class AuthorizationDecision:
    """AgentGuard's authoritative answer.  Anything other than ALLOW means "do not execute"."""

    decision: Decision
    allowed: bool = False
    reason: str = ""
    decision_id: Optional[str] = None
    policy: Optional[str] = None
    policy_version: Optional[str] = None
    obligations: Tuple[Dict[str, Any], ...] = ()
    correlation_id: Optional[str] = None
    request_id: Optional[str] = None
    latency_ms: Optional[int] = None
    indeterminate: bool = False
    contract_version: str = CONTRACT_VERSION

    # -- constructors ------------------------------------------------------------------------
    @classmethod
    def allow(cls, reason: str = "allowed", **kw) -> "AuthorizationDecision":
        return cls(Decision.ALLOW, True, reason, **kw)

    @classmethod
    def deny(cls, reason: str = "denied", **kw) -> "AuthorizationDecision":
        return cls(Decision.DENY, False, reason, **kw)

    @classmethod
    def make_indeterminate(cls, reason: str = "indeterminate", **kw) -> "AuthorizationDecision":
        """The fail-closed outcome: unreachable PDP, timeout, malformed/garbled answer.

        Note the name: this cannot be called ``indeterminate`` because the dataclass already has a
        field of that name, and a same-named classmethod would become that field's default.
        """
        kw.setdefault("indeterminate", True)
        return cls(Decision.INDETERMINATE, False, reason, **kw)

    @classmethod
    def from_agentguard_dict(cls, d: Optional[Mapping[str, Any]], *,
                             correlation_id: Optional[str] = None,
                             request_id: Optional[str] = None,
                             latency_ms: Optional[int] = None) -> "AuthorizationDecision":
        """Parse the EXISTING ``/v1/authorize`` response.

        A non-mapping or an answer that does not carry an explicit boolean ``allowed`` is treated as
        INDETERMINATE -- Happy LANG must never soften an unclear answer into an allow.
        """
        if not isinstance(d, Mapping) or not isinstance(d.get("allowed"), bool):
            return cls.make_indeterminate("malformed_decision", correlation_id=correlation_id,
                                     request_id=request_id, latency_ms=latency_ms)
        allowed = bool(d["allowed"])
        reason = str(d.get("reason") or "")
        obligations = tuple(
            o for o in (d.get("obligations") or ()) if isinstance(o, Mapping)
        )
        if allowed:
            decision = Decision.ALLOW
        elif "approval" in reason.lower() or obligations:
            decision = Decision.REQUIRE_APPROVAL
        else:
            decision = Decision.DENY
        return cls(decision, allowed, reason, decision_id=d.get("decision_id"),
                   policy=d.get("policy"), policy_version=(str(d["policy_version"])
                                                           if d.get("policy_version") else None),
                   obligations=obligations,
                   correlation_id=d.get("correlation_id") or correlation_id,
                   request_id=request_id, latency_ms=latency_ms,
                   contract_version=str(d.get("contract_version") or CONTRACT_VERSION))

    # -- validation --------------------------------------------------------------------------
    def validate(self) -> None:
        errors: List[str] = []
        check_enum(errors, "decision", self.decision, Decision)
        check_bool(errors, "allowed", self.allowed)
        check_str(errors, "reason", self.reason, max_len=MAX_REASON_LEN, required=False,
                  allow_empty=True)
        if self.decision_id is not None:
            check_str(errors, "decision_id", self.decision_id, max_len=MAX_ID_LEN, required=False)
        raise_if(errors, where="authorization decision")
        # Internal consistency: INDETERMINATE and DENY can never be "allowed".
        if self.decision is not Decision.ALLOW and self.allowed:
            raise ValidationError(
                f"inconsistent decision: {self.decision.value} cannot be allowed",
                field="allowed")

    @property
    def is_final_deny(self) -> bool:
        """True when the caller MUST NOT execute (deny or approval-required or indeterminate)."""
        return not self.allowed

    # -- (de)serialisation -------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "contract_version": self.contract_version,
            "decision": self.decision.value,
            "allowed": self.allowed,
            "reason": self.reason,
            "obligations": [_json_safe(o) for o in self.obligations],
            "indeterminate": self.indeterminate,
        }
        for key in ("decision_id", "policy", "policy_version", "correlation_id", "request_id",
                    "latency_ms"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        return out

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "AuthorizationDecision":
        if not isinstance(d, Mapping):
            raise ValidationError("authorization decision must be an object", field="decision")
        errors: List[str] = []
        decision = check_enum(errors, "decision", d.get("decision"), Decision)
        allowed = check_bool(errors, "allowed", d.get("allowed"), required=False)
        raise_if(errors, where="authorization decision")
        result = cls(
            decision=decision,
            allowed=bool(allowed) if allowed is not None else False,
            reason=str(d.get("reason") or "")[:MAX_REASON_LEN],
            decision_id=d.get("decision_id"), policy=d.get("policy"),
            policy_version=d.get("policy_version"),
            obligations=tuple(o for o in (d.get("obligations") or ()) if isinstance(o, Mapping)),
            correlation_id=d.get("correlation_id"), request_id=d.get("request_id"),
            latency_ms=d.get("latency_ms"),
            indeterminate=bool(d.get("indeterminate") or decision is Decision.INDETERMINATE),
            contract_version=str(d.get("contract_version") or CONTRACT_VERSION),
        )
        result.validate()
        return result

    def to_agentguard_decision_dict(self) -> Dict[str, Any]:
        """Render into the EXISTING AgentGuard ``Decision`` shape (for SDK interop)."""
        out: Dict[str, Any] = {"allowed": self.allowed, "reason": self.reason}
        if self.decision_id is not None:
            out["decision_id"] = self.decision_id
        if self.policy is not None:
            out["policy"] = self.policy
        if self.obligations:
            out["obligations"] = [_json_safe(o) for o in self.obligations]
        if self.correlation_id is not None:
            out["correlation_id"] = self.correlation_id
        return out


# =============================================================================================
# Security event
# =============================================================================================
class EventType:
    """Stable event-type constants emitted across the seam (namespaced ``happy.``)."""

    AUTHORIZED = "happy.authorization.allowed"
    DENIED = "happy.authorization.denied"
    INDETERMINATE = "happy.authorization.indeterminate"
    CAPABILITY_DENIED = "happy.capability.denied"
    PERMISSION_DENIED = "happy.permission.denied"
    CONTRACT_VIOLATION = "happy.contract.violation"
    SECRET_LEAK_BLOCKED = "happy.secret.blocked"
    VALIDATION_FAILED = "happy.request.invalid"
    COMPILE_FAILED = "happy.compile.failed"
    RUNTIME_FAILED = "happy.runtime.failed"
    RESOURCE_LIMIT = "happy.execution.resource_limit"
    CANCELLED = "happy.execution.cancelled"
    TIMEOUT = "happy.execution.timeout"
    ISOLATION_UNAVAILABLE = "happy.execution.isolation_unavailable"
    OPERATION_ROUTED = "happy.operation.routed"


@dataclass(frozen=True)
class SecurityEvent:
    """A security-relevant fact emitted by Happy LANG and recorded by AgentGuard.

    ``metadata`` is bounded and redacted by :meth:`validate`/:func:`clean_metadata`, so an event can
    never carry a secret into the audit stream.
    """

    event_type: str
    outcome: str = SecurityEventOutcome.OK.value
    correlation_id: Optional[str] = None
    agent_id: Optional[str] = None
    instance_id: Optional[str] = None
    org_id: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    reason: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    contract_version: str = CONTRACT_VERSION

    def validate(self) -> None:
        errors: List[str] = []
        check_str(errors, "event_type", self.event_type, max_len=MAX_EVENT_TYPE_LEN,
                  pattern=SAFE_TOKEN_RE)
        check_enum(errors, "outcome", self.outcome, SecurityEventOutcome)
        for key in ("correlation_id", "agent_id", "instance_id", "org_id", "request_id"):
            value = getattr(self, key)
            if value is not None:
                check_str(errors, key, value, max_len=MAX_ID_LEN, pattern=SAFE_TOKEN_RE)
        if self.action is not None:
            check_str(errors, "action", self.action, max_len=MAX_ACTION_LEN,
                      pattern=SAFE_TOKEN_RE)
        if self.resource is not None:
            check_str(errors, "resource", self.resource, max_len=MAX_RESOURCE_LEN,
                      pattern=SAFE_RESOURCE_RE)
        if self.reason is not None:
            check_str(errors, "reason", self.reason, max_len=MAX_REASON_LEN, required=False,
                      allow_empty=True)
        check_mapping(errors, "metadata", self.metadata)
        raise_if(errors, where="security event")

    def to_dict(self) -> Dict[str, Any]:
        """The ``/v1/security/events`` item shape (secret-safe, bounded)."""
        out: Dict[str, Any] = {
            "event_type": self.event_type,
            "outcome": self.outcome,
            "metadata": self._clean_metadata(),
        }
        for key in ("correlation_id", "agent_id", "instance_id", "org_id", "action", "resource",
                    "reason"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        return out

    def _clean_metadata(self) -> Dict[str, Any]:
        base = dict(self.metadata or {})
        if self.request_id:
            base.setdefault("request_id", self.request_id)
        base.setdefault("happy_contract_version", self.contract_version)
        return clean_metadata(base)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "SecurityEvent":
        if not isinstance(d, Mapping):
            raise ValidationError("security event must be an object", field="security_event")
        event = cls(
            event_type=d.get("event_type", ""),
            outcome=d.get("outcome") or SecurityEventOutcome.OK.value,
            correlation_id=d.get("correlation_id"), agent_id=d.get("agent_id"),
            instance_id=d.get("instance_id"), org_id=d.get("org_id"),
            action=d.get("action"), resource=d.get("resource"), reason=d.get("reason"),
            request_id=d.get("request_id"),
            metadata=dict(d.get("metadata") or {}),
            timestamp=d.get("timestamp", time.time()),
            contract_version=str(d.get("contract_version") or CONTRACT_VERSION),
        )
        event.validate()
        return event


# =============================================================================================
# Structured execution request / result
# =============================================================================================
@dataclass(frozen=True)
class ExecutionResource:
    """One real external resource the execution declares it will touch."""

    kind: str
    target: str
    access: str = "read"
    required: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "target": self.target, "access": self.access,
                "required": self.required}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ExecutionResource":
        return cls(kind=str(d.get("kind") or ""), target=str(d.get("target") or ""),
                   access=str(d.get("access") or "read"), required=bool(d.get("required", True)))

    def validate(self) -> None:
        errors: List[str] = []
        check_str(errors, "resource.kind", self.kind, max_len=64, pattern=SAFE_TOKEN_RE)
        check_str(errors, "resource.target", self.target, max_len=MAX_RESOURCE_LEN,
                  pattern=SAFE_RESOURCE_RE)
        if self.access not in ("read", "write", "read_write", "execute"):
            errors.append(f"resource.access: must be read|write|read_write|execute, got "
                          f"{self.access!r}")
        check_bool(errors, "resource.required", self.required, required=False)
        raise_if(errors, where="execution resource")


@dataclass(frozen=True)
class ExecutionLimits:
    """Bounded resource budget for one execution (validated against hard ceilings)."""

    timeout_s: float = 10.0
    max_memory_mb: float = 256.0
    max_output_bytes: int = 1_048_576
    max_operations: int = 100_000

    def validate(self) -> None:
        errors: List[str] = []
        check_float(errors, "limits.timeout_s", self.timeout_s, minimum=0.001,
                    maximum=HARD_MAX_TIMEOUT_S)
        check_float(errors, "limits.max_memory_mb", self.max_memory_mb, minimum=1,
                    maximum=HARD_MAX_MEMORY_MB)
        check_int(errors, "limits.max_output_bytes", self.max_output_bytes, minimum=1,
                  maximum=HARD_MAX_OUTPUT_BYTES)
        check_int(errors, "limits.max_operations", self.max_operations, minimum=1,
                  maximum=HARD_MAX_OPERATIONS)
        raise_if(errors, where="execution limits")

    def to_dict(self) -> Dict[str, Any]:
        return {"timeout_s": self.timeout_s, "max_memory_mb": self.max_memory_mb,
                "max_output_bytes": self.max_output_bytes, "max_operations": self.max_operations}

    @classmethod
    def from_dict(cls, d: Optional[Mapping[str, Any]]) -> "ExecutionLimits":
        if not isinstance(d, Mapping):
            return cls()
        defaults = cls()
        return cls(
            timeout_s=float(d.get("timeout_s", defaults.timeout_s)),
            max_memory_mb=float(d.get("max_memory_mb", defaults.max_memory_mb)),
            max_output_bytes=int(d.get("max_output_bytes", defaults.max_output_bytes)),
            max_operations=int(d.get("max_operations", defaults.max_operations)),
        )


@dataclass(frozen=True)
class ExecutionRequest:
    """The structured request Happy LANG submits for one integrated execution.

    Everything the task requires is present and explicit: request identifier, agent identity,
    program/artifact reference, requested capabilities, declared resource requirements, the
    applicable security policy, execution limits and a correlation identifier.
    """

    request_id: str
    agent_id: str
    artifact: ArtifactRef
    requested_capabilities: Tuple[str, ...] = ()
    declared_resources: Tuple[ExecutionResource, ...] = ()
    policy_id: Optional[str] = None
    policy_version: str = "unset"
    limits: ExecutionLimits = field(default_factory=ExecutionLimits)
    correlation_id: str = field(default_factory=lambda: new_id("corr"))
    instance_id: Optional[str] = None
    org_id: Optional[str] = None
    entry: str = "main"
    context: Dict[str, Any] = field(default_factory=dict)
    contract_version: str = CONTRACT_VERSION
    schema_version: int = 1

    @classmethod
    def require_policy_version(cls, errors: List[str], value: Any) -> None:
        """A policy version must be a non-empty, well-formed token (no implicit 'latest')."""
        check_str(errors, "policy_version", value, max_len=MAX_ID_LEN, required=True,
                  allow_empty=False, pattern=SAFE_TOKEN_RE)

    def validate(self) -> None:
        errors: List[str] = []
        check_str(errors, "request_id", self.request_id, max_len=MAX_ID_LEN, pattern=SAFE_TOKEN_RE)
        check_str(errors, "agent_id", self.agent_id, max_len=MAX_ID_LEN, pattern=SAFE_TOKEN_RE)
        check_str(errors, "correlation_id", self.correlation_id, max_len=MAX_ID_LEN,
                  pattern=SAFE_TOKEN_RE)
        if self.instance_id is not None:
            check_str(errors, "instance_id", self.instance_id, max_len=MAX_ID_LEN,
                      pattern=SAFE_TOKEN_RE)
        if self.org_id is not None:
            check_str(errors, "org_id", self.org_id, max_len=MAX_ID_LEN, pattern=SAFE_TOKEN_RE)
        if self.policy_id is not None:
            check_str(errors, "policy_id", self.policy_id, max_len=MAX_ID_LEN,
                      pattern=SAFE_TOKEN_RE)
        self.require_policy_version(errors, self.policy_version)
        check_str(errors, "entry", self.entry, max_len=MAX_ID_LEN, required=True,
                  allow_empty=False, pattern=SAFE_TOKEN_RE)
        check_sequence_of_str(errors, "requested_capabilities",
                              list(self.requested_capabilities), max_items=MAX_CAPABILITIES,
                              required=True, allow_empty=False)
        check_mapping(errors, "context", self.context)
        raise_if(errors, where="execution request")
        if not self.artifact:
            raise ValidationError("artifact: is required", field="artifact")
        self.artifact.validate()
        self.limits.validate()
        if not self.declared_resources:
            errors2: List[str] = ["declared_resources: must declare at least one resource (use an "
                                 "empty-target 'none' resource for a pure program)"]
            raise_if(errors2, where="execution request")
        for i, resource in enumerate(self.declared_resources):
            if not isinstance(resource, ExecutionResource):
                raise ValidationError(f"declared_resources[{i}] must be an ExecutionResource",
                                      field=f"declared_resources[{i}]")
            resource.validate()
        if self.schema_version != 1:
            raise ValidationError(f"schema_version: must be 1, got {self.schema_version!r}",
                                  field="schema_version")
        from .version import is_supported
        if not is_supported(self.contract_version):
            from .errors import UnsupportedContractVersion
            raise UnsupportedContractVersion(
                f"unsupported contract_version {self.contract_version!r}",
                field="contract_version")

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "contract_version": self.contract_version,
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "agent_id": self.agent_id,
            "artifact": self.artifact.to_dict(),
            "entry": self.entry,
            "requested_capabilities": list(self.requested_capabilities),
            "declared_resources": [r.to_dict() for r in self.declared_resources],
            "policy_version": self.policy_version,
            "limits": self.limits.to_dict(),
            "context": _json_safe(self.context),
        }
        for key in ("instance_id", "org_id", "policy_id"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        return out

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ExecutionRequest":
        if not isinstance(d, Mapping):
            raise ValidationError("execution request must be an object", field="execution_request")
        raw_resources = d.get("declared_resources") or ()
        request = cls(
            request_id=d.get("request_id", ""), agent_id=d.get("agent_id", ""),
            artifact=ArtifactRef.from_dict(d.get("artifact")),
            requested_capabilities=tuple(d.get("requested_capabilities") or ()),
            declared_resources=tuple(
                ExecutionResource.from_dict(r) if isinstance(r, Mapping) else r
                for r in raw_resources),
            policy_id=d.get("policy_id"),
            # Deliberately NOT defaulted: an absent policy version must fail validation rather than
            # silently become a permissive placeholder.
            policy_version=str(d.get("policy_version") or ""),
            limits=ExecutionLimits.from_dict(d.get("limits")),
            correlation_id=d.get("correlation_id") or new_id("corr"),
            instance_id=d.get("instance_id"), org_id=d.get("org_id"),
            entry=d.get("entry") or "main", context=dict(d.get("context") or {}),
            contract_version=str(d.get("contract_version") or ""),
            schema_version=d.get("schema_version", 1),
        )
        request.validate()
        return request

    def artifact_digest(self) -> str:
        """Digest of the artifact (mints one from the ref when the caller did not supply one)."""
        return self.artifact.digest or sha256_hex(canonical_json(self.artifact.to_dict()))


@dataclass(frozen=True)
class ExecutionResult:
    """The structured outcome of one integrated execution (one discriminant per requirement)."""

    result: ResultKind
    request_id: str
    correlation_id: str
    ok: bool = False
    output: str = ""
    error: Optional[str] = None
    error_code: Optional[str] = None
    decision: Optional[AuthorizationDecision] = None
    source_loc: Optional[SourceLocation] = None
    diagnostics: Tuple[str, ...] = ()
    duration_ms: float = 0.0
    operations: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    contract_version: str = CONTRACT_VERSION
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "contract_version": self.contract_version,
            "result": self.result.value,
            "ok": self.ok,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "output": self.output,
            "diagnostics": list(self.diagnostics),
            "duration_ms": self.duration_ms,
            "operations": self.operations,
            "metadata": clean_metadata(self.metadata),
            "timestamp": self.timestamp,
        }
        if self.error is not None:
            out["error"] = self.error
        if self.error_code is not None:
            out["error_code"] = self.error_code
        if self.decision is not None:
            out["decision"] = self.decision.to_dict()
        if self.source_loc is not None:
            out["source_loc"] = self.source_loc.to_dict()
        return out

    @property
    def denied(self) -> bool:
        return self.result in (ResultKind.AUTHORIZATION_DENIED, ResultKind.REQUIRE_APPROVAL,
                               ResultKind.POLICY_VIOLATION)

    def to_security_event(self, *, agent_id: Optional[str] = None,
                          instance_id: Optional[str] = None,
                          org_id: Optional[str] = None) -> SecurityEvent:
        """Map the result onto a Happy LANG security event for AgentGuard's audit chain."""
        mapping = {
            ResultKind.OK: (EventType.AUTHORIZED, SecurityEventOutcome.OK),
            ResultKind.AUTHORIZATION_DENIED: (EventType.DENIED, SecurityEventOutcome.DENIED),
            ResultKind.REQUIRE_APPROVAL: (EventType.DENIED, SecurityEventOutcome.DENIED),
            ResultKind.POLICY_VIOLATION: (EventType.DENIED, SecurityEventOutcome.DENIED),
            ResultKind.COMPILE_ERROR: (EventType.COMPILE_FAILED, SecurityEventOutcome.ERROR),
            ResultKind.VALIDATION_ERROR: (EventType.VALIDATION_FAILED, SecurityEventOutcome.ERROR),
            ResultKind.RUNTIME_ERROR: (EventType.RUNTIME_FAILED, SecurityEventOutcome.ERROR),
            ResultKind.RESOURCE_LIMIT: (EventType.RESOURCE_LIMIT, SecurityEventOutcome.DENIED),
            ResultKind.CANCELLED: (EventType.CANCELLED, SecurityEventOutcome.DENIED),
            ResultKind.TIMEOUT: (EventType.TIMEOUT, SecurityEventOutcome.DENIED),
            ResultKind.ISOLATION_UNAVAILABLE: (EventType.ISOLATION_UNAVAILABLE,
                                               SecurityEventOutcome.ERROR),
            ResultKind.INTEGRATION_ERROR: (EventType.INDETERMINATE, SecurityEventOutcome.ERROR),
            ResultKind.INTERNAL_ERROR: (EventType.INDETERMINATE, SecurityEventOutcome.ERROR),
        }
        event_type, outcome = mapping.get(self.result, (EventType.INDETERMINATE,
                                                        SecurityEventOutcome.ERROR))
        return SecurityEvent(
            event_type=event_type, outcome=outcome.value,
            correlation_id=self.correlation_id, agent_id=agent_id, instance_id=instance_id,
            org_id=org_id, action=(self.decision.policy if self.decision else None),
            reason=self.error or (self.decision.reason if self.decision else None),
            request_id=self.request_id,
            metadata={"result": self.result.value, "ok": self.ok,
                      "duration_ms": self.duration_ms, "operations": self.operations},
        )


__all__ = [
    "Decision", "ResultKind", "SecurityEventOutcome", "EventType",
    "SourceLocation", "ArtifactRef",
    "AuthorizationRequest", "AuthorizationDecision",
    "SecurityEvent",
    "ExecutionResource", "ExecutionLimits", "ExecutionRequest", "ExecutionResult",
    "new_id", "SCHEMA_ID", "CONTRACT_VERSION",
]
