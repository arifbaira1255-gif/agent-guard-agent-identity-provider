"""Negative/input-validation tests at the trust boundary.

AgentGuard treats every Happy LANG request as untrusted input, so the validation layer must reject
malformed, incomplete, oversized, wrong-typed and control-character-bearing payloads -- and it must
report every problem at once, not one per attempt.
"""
import pytest

from agentguard_happy_contract import (
    ArtifactRef,
    AuthorizationRequest,
    AuthorizationDecision,
    Decision,
    ExecutionLimits,
    ExecutionRequest,
    ExecutionResource,
    SecurityEvent,
    SourceLocation,
    UnsupportedContractVersion,
    ValidationError,
    assert_conforms,
    sha256_hex,
)

DIGEST = sha256_hex("source")


def _valid_execution_request(**kw):
    base = dict(request_id="req_1", agent_id="agt_1", artifact=ArtifactRef(digest=DIGEST),
                requested_capabilities=("file_write",),
                declared_resources=(ExecutionResource(kind="file", target="/tmp/out.txt",
                                                      access="write"),),
                policy_version="3")
    base.update(kw)
    return ExecutionRequest(**base)


# ---------------------------------------------------------------- authorization request
@pytest.mark.parametrize("field,bad", [
    ("action", ""),                       # empty
    ("action", "has space"),               # charset
    ("action", "a" * 300),                 # over length
    ("resource", ""),                      # empty
    ("resource", "x" * 2000),              # over length
    ("agent_id", ""),                      # empty
    ("agent_id", "bad\nid"),               # control character injection
    ("request_id", "id;drop"),             # shell/policy metacharacter
])
def test_malformed_authorization_request_is_rejected(field, bad):
    kwargs = dict(action="tool:write_file", resource="/data/out.json", agent_id="agt_1")
    kwargs[field] = bad
    with pytest.raises(ValidationError) as exc:
        AuthorizationRequest(**kwargs).validate()
    assert any(field in e for e in exc.value.errors), exc.value.errors


def test_wrong_python_types_are_rejected_not_coerced():
    with pytest.raises(ValidationError) as exc:
        AuthorizationRequest(action=123, resource=["/x"], agent_id={"a": 1}).validate()
    joined = " ".join(exc.value.errors)
    assert "action: must be a string" in joined
    assert "resource: must be a string" in joined
    assert "agent_id: must be a string" in joined


def test_too_many_capabilities_are_rejected():
    with pytest.raises(ValidationError):
        AuthorizationRequest(action="tool:write_file", resource="/x", agent_id="agt_1",
                             requested_capabilities=tuple(f"cap{i}" for i in range(200))).validate()


def test_unsupported_contract_version_is_rejected():
    with pytest.raises(UnsupportedContractVersion):
        AuthorizationRequest(action="tool:write_file", resource="/x", agent_id="agt_1",
                             contract_version="0.0.9").validate()


def test_schema_rejects_a_missing_mandatory_field():
    payload = AuthorizationRequest(action="tool:write_file", resource="/x",
                                   agent_id="agt_1").to_dict()
    payload.pop("correlation_id")
    errors = []
    from agentguard_happy_contract import schema as schema_mod
    errors = schema_mod.validate_payload("authorization_request", payload)
    assert any("correlation_id: is required" in e for e in errors)


def test_source_location_bounds_and_types():
    with pytest.raises(ValidationError):
        SourceLocation(file="x", line=-1).validate()
    with pytest.raises(ValidationError):
        SourceLocation(file="x", line="fourteen").validate()
    SourceLocation(file="demo.hpy", line=14, column=9).validate()


# ---------------------------------------------------------------- execution request
def test_valid_execution_request_passes():
    _valid_execution_request().validate()


@pytest.mark.parametrize("kwargs", [
    {"request_id": ""},
    {"agent_id": ""},
    {"policy_version": ""},
    {"entry": "bad entry"},
    {"requested_capabilities": ()},
    {"declared_resources": ()},
    {"declared_resources": (ExecutionResource(kind="", target="/x"), )},
    {"declared_resources": (ExecutionResource(kind="file", target="/x", access="sudo"), )},
    {"limits": ExecutionLimits(timeout_s=0.0)},
    {"limits": ExecutionLimits(max_operations=0)},
])
def test_invalid_execution_request_is_rejected(kwargs):
    with pytest.raises(ValidationError):
        _valid_execution_request(**kwargs).validate()


def test_declared_resource_target_charset_is_enforced():
    with pytest.raises(ValidationError):
        ExecutionResource(kind="file", target="/tmp/x;rm -rf /", access="write").validate()
    # an absolute path, a relative path, a URL and a bare name are all valid targets
    for target in ("/var/log/app.log", "out.json", "https://api.example.com/v1", "ACCOUNTS"):
        ExecutionResource(kind="file", target=target, access="read").validate()


def test_from_dict_rejects_non_objects_and_missing_fields():
    with pytest.raises(ValidationError):
        ExecutionRequest.from_dict("not-an-object")
    with pytest.raises(ValidationError):
        ExecutionRequest.from_dict({"request_id": "r", "agent_id": "a"})
    with pytest.raises(ValidationError):
        AuthorizationRequest.from_dict(None)


def test_artifact_digest_must_be_a_sha256_hex():
    with pytest.raises(ValidationError):
        ArtifactRef(digest="not-a-digest").validate()
    with pytest.raises(ValidationError):
        ArtifactRef(digest="A" * 64).validate()          # uppercase is not canonical
    ArtifactRef(digest=DIGEST).validate()


# ---------------------------------------------------------------- decision + event
def test_inconsistent_decision_is_rejected():
    with pytest.raises(ValidationError):
        AuthorizationDecision(Decision.DENY, True, "contradiction").validate()
    with pytest.raises(ValidationError):
        AuthorizationDecision(Decision.REQUIRE_APPROVAL, True, "contradiction").validate()


def test_malformed_decision_dicts_are_rejected_or_fail_closed():
    with pytest.raises(ValidationError):
        AuthorizationDecision.from_dict({"allowed": "yes", "decision": "MAYBE"}).validate()
    with pytest.raises(ValidationError):
        AuthorizationDecision.from_dict({"allowed": True}).validate()


def test_security_event_rejects_unknown_outcome_and_bad_event_type():
    with pytest.raises(ValidationError):
        SecurityEvent(event_type="happy.x", outcome="maybe").validate()
    with pytest.raises(ValidationError):
        SecurityEvent(event_type="happy event with spaces").validate()
    with pytest.raises(ValidationError):
        SecurityEvent.from_dict("not-an-object")


def test_schema_validator_rejects_an_oversized_batch():
    payload = {"events": [{"event_type": "happy.x", "outcome": "ok"}] * 201}
    errors = []
    from agentguard_happy_contract import schema as schema_mod
    errors = schema_mod.validate_payload("security_event_batch", payload)
    assert any("maxItems" in e for e in errors)
