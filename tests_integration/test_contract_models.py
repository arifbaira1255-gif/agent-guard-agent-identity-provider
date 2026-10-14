"""Contract-package tests: typed models, versioning, bounds, redaction and fail-closed mapping."""
import json

import pytest

from agentguard_happy_contract import (
    CONTRACT_VERSION,
    SCHEMAS,
    ArtifactRef,
    AuthorizationDecision,
    AuthorizationRequest,
    Decision,
    EventType,
    ExecutionLimits,
    ExecutionRequest,
    ExecutionResource,
    ExecutionResult,
    ResultKind,
    SecurityEvent,
    SourceLocation,
    UnsupportedContractVersion,
    ValidationError,
    assert_conforms,
    canonical_json,
    clean_metadata,
    contract_header,
    describe,
    is_supported,
    redact,
    require_supported,
    sha256_hex,
)
from agentguard_happy_contract import schema as schema_mod


# ---------------------------------------------------------------- versioning
def test_contract_metadata_is_consistent():
    info = describe()
    assert info["version"] == CONTRACT_VERSION
    assert CONTRACT_VERSION in info["supported_versions"]
    assert set(info["schemas"]) == set(SCHEMAS)
    assert contract_header()["version"] == CONTRACT_VERSION


def test_every_expectation_data_schema_is_present():
    for name in ("authorization_request", "authorization_decision", "security_event",
                 "security_event_batch", "execution_request", "execution_result"):
        assert name in SCHEMAS, name


def test_unsupported_version_is_rejected_fail_closed():
    assert is_supported(CONTRACT_VERSION)
    assert not is_supported("99.0.0")
    with pytest.raises(UnsupportedContractVersion):
        require_supported("99.0.0")
    with pytest.raises(UnsupportedContractVersion):
        require_supported(None)


def test_additive_only_evolution_ignores_unknown_fields():
    """A newer peer's unknown keys must be ignored, not rejected (documented evolution rule)."""
    payload = AuthorizationRequest(action="tool:read_file", resource="/etc/hosts",
                                   agent_id="agt_1").to_dict()
    payload["future_field_from_a_newer_peer"] = {"whatever": True}
    parsed = AuthorizationRequest.from_dict(payload)
    assert parsed.action == "tool:read_file"
    assert "future_field_from_a_newer_peer" not in parsed.to_dict()


# ---------------------------------------------------------------- authorization request
def test_authorization_request_round_trip_and_schema():
    request = AuthorizationRequest(
        action="tool:write_file", resource="/data/out.json", agent_id="agt_1",
        instance_id="inst_1", org_id="acme", operation="write_file",
        requested_capabilities=("file_write",), declared_resources=("/data/out.json",),
        agent_scope="Teller", effects=("io",), contracts=("no_overdraft",),
        source_loc=SourceLocation(file="demo.hpy", line=14, column=9),
        artifact=ArtifactRef(digest=sha256_hex("x"), filename="demo.hpy"))
    request.validate()
    payload = request.to_dict()
    assert_conforms("authorization_request", payload)
    again = AuthorizationRequest.from_dict(payload)
    assert again.to_dict() == payload
    assert again.correlation_id == request.correlation_id


def test_authorization_request_never_carries_credentials():
    request = AuthorizationRequest(action="tool:http_get", resource="https://example.invalid",
                                   agent_id="agt_1")
    payload = json.dumps(request.to_dict())
    assert "token" not in request.to_dict()
    assert "proof" not in request.to_dict()
    assert "agp1." not in payload


def test_authorize_body_is_a_superset_of_the_existing_agentguard_contract():
    """The body must keep the fields AgentGuard's /v1/authorize already consumes."""
    request = AuthorizationRequest(action="tool:write_file", resource="/data/out.json",
                                   agent_id="agt_1", operation="write_file",
                                   requested_capabilities=("file_write",))
    body = request.to_authorize_body(token="agp1.fake", proof={"sig": "x"},
                                     audience="agentguard:tool")
    for key in ("action", "resource", "context", "token", "proof", "audience",
                "correlation_id", "agent_id"):
        assert key in body, key
    # Happy LANG's additions live under a single namespaced block.
    assert set(body["context"].keys()) == {"happy"}
    happy = body["context"]["happy"]
    assert happy["contract_version"] == CONTRACT_VERSION
    assert happy["operation"] == "write_file"
    assert happy["requested_capabilities"] == ["file_write"]


# ---------------------------------------------------------------- decision
def test_decision_mapping_fails_closed_on_garbage():
    assert AuthorizationDecision.from_agentguard_dict(
        {"allowed": False, "reason": "no_matching_capability"}).decision is Decision.DENY
    assert AuthorizationDecision.from_agentguard_dict(
        {"allowed": True, "reason": "capability_match"}).decision is Decision.ALLOW
    for garbage in ("nonsense", None, {}, {"allowed": "yes"}, 42, [1, 2]):
        decision = AuthorizationDecision.from_agentguard_dict(garbage)
        assert decision.decision is Decision.INDETERMINATE
        assert decision.allowed is False
        assert decision.is_final_deny


def test_indeterminate_and_deny_can_never_be_allowed():
    with pytest.raises(ValidationError):
        AuthorizationDecision(Decision.DENY, True, "contradiction").validate()
    with pytest.raises(ValidationError):
        AuthorizationDecision(Decision.INDETERMINATE, True, "contradiction").validate()


def test_decision_round_trip_schema():
    decision = AuthorizationDecision.deny("no_matching_capability", decision_id="dec_1",
                                          policy="capability-default", correlation_id="corr_1")
    decision.validate()
    payload = decision.to_dict()
    assert_conforms("authorization_decision", payload)
    assert AuthorizationDecision.from_dict(payload).to_dict() == payload


def test_decision_renders_into_the_existing_agentguard_shape():
    payload = AuthorizationDecision.allow("capability_match").to_agentguard_decision_dict()
    assert payload["allowed"] is True and payload["reason"] == "capability_match"


# ---------------------------------------------------------------- security event
def test_security_event_round_trip_and_schema():
    event = SecurityEvent(event_type=EventType.CAPABILITY_DENIED, outcome="denied",
                          correlation_id="corr_1", agent_id="agt_1", action="tool:write_file",
                          resource="/data/out.json", reason="no capability",
                          metadata={"operation": "write_file"})
    event.validate()
    payload = event.to_dict()
    assert_conforms("security_event", payload)
    assert_conforms("security_event_batch", {"events": [payload]})
    assert SecurityEvent.from_dict(payload).to_dict() == payload


def test_security_event_metadata_is_redacted_and_bounded():
    assert redact("Authorization: Bearer agp1.abc.def") == "<redacted>"
    assert redact("hello") == "hello"
    cleaned = clean_metadata({"token": "super-secret", "latency_ms": 3, "x" * 500: "v"})
    assert cleaned["token"] == "<redacted>"
    assert cleaned["latency_ms"] == 3
    event = SecurityEvent(event_type=EventType.DENIED, outcome="denied",
                          metadata={"authorization": "Bearer agp1.secret"}).to_dict()
    assert event["metadata"]["authorization"] == "<redacted>"
    assert "agp1." not in json.dumps(event)


# ---------------------------------------------------------------- execution request/result
def _execution_request(**kw):
    defaults = dict(
        request_id="req_1", agent_id="agt_1", artifact=ArtifactRef(digest=sha256_hex("src")),
        requested_capabilities=("file_write",),
        declared_resources=(ExecutionResource(kind="file", target="/data/out.json",
                                              access="write"),),
        policy_id="policy.banking", policy_version="3")
    defaults.update(kw)
    return ExecutionRequest(**defaults)


def test_execution_request_round_trip_and_schema():
    request = _execution_request()
    request.validate()
    payload = request.to_dict()
    assert_conforms("execution_request", payload)
    assert ExecutionRequest.from_dict(payload).to_dict() == payload


def test_execution_request_requires_every_mandated_field():
    for missing in ("request_id", "agent_id", "policy_version"):
        payload = _execution_request().to_dict()
        payload.pop(missing)
        if missing == "policy_version":
            with pytest.raises(ValidationError):
                ExecutionRequest.from_dict(payload)
        else:
            with pytest.raises(ValidationError):
                ExecutionRequest(request_id=payload.get("request_id", ""),
                                 agent_id=payload.get("agent_id", ""),
                                 artifact=ArtifactRef(digest=sha256_hex("s")),
                                 requested_capabilities=("file_write",),
                                 declared_resources=(ExecutionResource(kind="file",
                                                                       target="/x"),),
                                 policy_version=payload.get("policy_version", "")).validate()


def test_execution_request_rejects_undeclared_resources():
    with pytest.raises(ValidationError):
        _execution_request(declared_resources=()).validate()


def test_execution_limits_are_hard_bounded():
    assert ExecutionLimits().validate() is None
    with pytest.raises(ValidationError):
        ExecutionLimits(timeout_s=0).validate()
    with pytest.raises(ValidationError):
        ExecutionLimits(timeout_s=99999).validate()
    with pytest.raises(ValidationError):
        ExecutionLimits(max_memory_mb=0).validate()
    with pytest.raises(ValidationError):
        ExecutionLimits(max_output_bytes=0).validate()


def test_every_required_result_kind_is_representable():
    """The task mandates one structured result per outcome; all must exist and serialise."""
    required = {
        "ok", "authorization_denied", "policy_violation", "require_approval", "compile_error",
        "validation_error", "runtime_error", "resource_limit", "cancelled", "timeout",
        "isolation_unavailable", "integration_error", "internal_error",
    }
    assert {k.value for k in ResultKind} == required
    for kind in ResultKind:
        result = ExecutionResult(result=kind, request_id="req_1", correlation_id="corr_1")
        assert_conforms("execution_result", result.to_dict())


def test_execution_result_maps_onto_a_security_event():
    result = ExecutionResult(result=ResultKind.AUTHORIZATION_DENIED, request_id="req_1",
                             correlation_id="corr_1", error="denied")
    event = result.to_security_event(agent_id="agt_1")
    assert event.event_type == EventType.DENIED
    assert event.outcome == "denied"
    assert event.request_id == "req_1"


def test_canonical_json_and_digest_are_deterministic():
    a = {"b": 1, "a": [2, 3]}
    b = {"a": [2, 3], "b": 1}
    assert canonical_json(a) == canonical_json(b)
    assert sha256_hex(a) == sha256_hex(b)
    assert sha256_hex("x") != sha256_hex("y")


# ---------------------------------------------------------------- schema validator itself
def test_schema_validator_rejects_wrong_types_and_enum_values():
    errors = schema_mod.validate_payload("authorization_decision",
                                         {"allowed": "yes", "decision": "MAYBE"})
    assert any("expected type boolean" in e for e in errors)
    assert any("must be one of" in e for e in errors)
    with pytest.raises(ValidationError):
        assert_conforms("authorization_decision", {"allowed": "yes", "decision": "MAYBE"})
    with pytest.raises(ValidationError):
        schema_mod.validate_payload("no_such_schema", {})
