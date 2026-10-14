"""Compatibility tests: wire-level, version-negotiation, and non-invasiveness guarantees.

Three properties are verified here:

1. **Wire compatibility** -- the payload the contract produces is accepted by AgentGuard's EXISTING
   ``POST /v1/authorize`` route, whose happy-lang additions sit in a namespaced block the server
   ignores; and the decision AgentGuard returns parses back into the typed decision.
2. **Version negotiation** -- an unknown future version fails closed, while an additive change
   (unknown extra fields) is tolerated.
3. **Non-invasiveness** -- the integration reaches Happy LANG only through its documented
   ``use_checker`` extension points and AgentGuard only through its ``/v1/authorize`` route, so both
   keep working exactly as before when the integration is off.
"""
import json

import pytest

from agentguard_happy_contract import (
    AgentGuardAuthorizer,
    ArtifactRef,
    AuthorizationDecision,
    AuthorizationRequest,
    CallablePdp,
    Decision,
    ExecutionLimits,
    ExecutionRequest,
    ExecutionResource,
    IntegrationConfig,
    SecurityEvent,
    UnsupportedContractVersion,
    sha256_hex,
)
from agentguard_happy_contract import schema as schema_mod
from live_stack import restore_default_hook, start_live_agentguard


# ---------------------------------------------------------------- wire compatibility
def test_namespaced_extension_does_not_disturb_the_existing_body():
    """AgentGuard consumes action/resource/token/proof; Happy's data rides under context.happy."""
    request = AuthorizationRequest(action="tool:write_file", resource="/data/out.json",
                                   agent_id="agt_1", operation="write_file",
                                   requested_capabilities=("file_write",),
                                   effects=("io",),
                                   source_loc=__import__("agentguard_happy_contract",
                                                         fromlist=["SourceLocation"])
                                   .SourceLocation(file="demo.hpy", line=12))
    body = request.to_authorize_body(token="agp1.x", proof={"signature": "s"},
                                     audience="agentguard:tool")
    # The fields AgentGuard's handler reads directly.
    assert body["action"] == "tool:write_file"
    assert body["resource"] == "/data/out.json"
    assert body["token"] == "agp1.x"
    assert body["proof"] == {"signature": "s"}
    assert body["audience"] == "agentguard:tool"
    # Everything else is confined to the namespaced block.
    assert list(body["context"].keys()) == ["happy"]
    assert body["context"]["happy"]["source_loc"] == {"file": "demo.hpy", "line": 12}


def test_request_and_decision_survive_a_json_wire_round_trip():
    request = AuthorizationRequest(action="tool:read_file", resource="/etc/hosts",
                                   agent_id="agt_1", requested_capabilities=("file_read",))
    wire = json.loads(json.dumps(request.to_dict()))
    assert AuthorizationRequest.from_dict(wire).to_dict() == request.to_dict()

    decision = AuthorizationDecision.deny("no_matching_capability", policy="capability-default")
    wire = json.loads(json.dumps(decision.to_dict()))
    assert AuthorizationDecision.from_dict(wire).to_dict() == decision.to_dict()


def test_agentguard_decision_shape_parses_into_the_typed_decision():
    """The real /v1/authorize reply shape must map cleanly onto our typed decision."""
    reply = {"allowed": True, "reason": "capability_match", "policy": "capability-default",
             "obligations": [], "decision_id": None, "correlation_id": "cor_abc"}
    decision = AuthorizationDecision.from_agentguard_dict(reply)
    decision.validate()
    assert decision.decision is Decision.ALLOW
    assert decision.policy == "capability-default"
    assert decision.correlation_id == "cor_abc"


def test_decision_reply_from_the_default_hook_parses():
    """AgentGuard's deny-by-default hook emits exactly this minimal shape."""
    for reply, expected in (
            ({"allowed": False, "reason": "no_matching_capability", "policy": "capability-default"},
             Decision.DENY),
            ({"allowed": False, "reason": "missing_action", "policy": "capability-default"},
             Decision.DENY),
            ({"allowed": False, "reason": "invalid_credential"}, Decision.DENY),
            ({"allowed": True, "reason": "capability_match"}, Decision.ALLOW)):
        assert AuthorizationDecision.from_agentguard_dict(reply).decision is expected


# ---------------------------------------------------------------- version negotiation
def test_future_major_version_fails_closed():
    payload = AuthorizationRequest(action="tool:read_file", resource="/etc/hosts",
                                   agent_id="agt_1").to_dict()
    payload["contract_version"] = "2.0.0"
    with pytest.raises(UnsupportedContractVersion):
        AuthorizationRequest.from_dict(payload)


def test_unknown_additive_fields_are_tolerated():
    """Additive-only evolution: a newer peer's extra fields must not break an older peer."""
    payload = AuthorizationRequest(action="tool:read_file", resource="/etc/hosts",
                                   agent_id="agt_1").to_dict()
    payload["x_future"] = 1
    payload["context"] = {"future": {"nested": True}}
    request = AuthorizationRequest.from_dict(payload)
    assert request.action == "tool:read_file"


def test_schema_declares_additional_properties_for_forward_compatibility():
    for name, schema in schema_mod.SCHEMAS.items():
        assert schema.get("additionalProperties") is not False, name


def test_execution_request_schema_round_trips():
    request = ExecutionRequest(request_id="req_1", agent_id="agt_1",
                               artifact=ArtifactRef(digest=sha256_hex("s")),
                               requested_capabilities=("file_write",),
                               declared_resources=(ExecutionResource(kind="file", target="/x",
                                                                     access="write"),),
                               policy_version="2")
    payload = json.loads(json.dumps(request.to_dict()))
    assert ExecutionRequest.from_dict(payload).to_dict() == request.to_dict()


# ---------------------------------------------------------------- non-invasiveness
def test_happy_extension_points_are_reused_not_replaced():
    """The integration installs via Happy's own use_checker/pattern, without editing its source."""
    import inspect

    from happy.runtime import RuntimeContext
    from happy.std import fs, net

    assert hasattr(fs, "use_checker") and hasattr(net, "use_checker")
    source = inspect.getsource(RuntimeContext.bind_std or RuntimeContext.__init__) \
        if hasattr(RuntimeContext, "bind_std") else inspect.getsource(RuntimeContext)
    assert "use_checker" in source, "Happy binds stdlib checkers from the context's capabilities"


def test_disabled_integration_leaves_happy_untouched():
    """With the flag off the authorizer defers entirely to whatever Happy already had."""
    marker = {"value": "happy-default"}
    policy = {"default": marker["value"]}

    class PassThrough:
        def check_operation(self, operation, agent=None, loc=None, args=None):
            return policy["default"] == "happy-default"

    auth = AgentGuardAuthorizer(IntegrationConfig(enabled=False, mode="off"), checker=PassThrough())
    assert auth.enabled is False
    assert auth.check_operation("write_file", args={"path": "/tmp/x"}) is True
    assert auth.audit[-1].asked_remote is False


# ---------------------------------------------------------------- live server compatibility
@pytest.fixture(scope="module")
def live():
    server = start_live_agentguard(capabilities=("tool:read_file", "file_read"))
    try:
        yield server
    finally:
        restore_default_hook()
        server.close()


def test_contract_body_is_accepted_by_the_real_agentguard_route(live):
    """The exact body the contract builds (with its namespaced block) is decided correctly."""
    request = AuthorizationRequest(action="tool:read_file", resource="/etc/hosts",
                                   agent_id=live.agent_id, instance_id=live.instance_id,
                                   org_id=live.org_id, operation="read_file",
                                   requested_capabilities=("file_read",))
    body = request.to_authorize_body(token=live.token, proof=live.make_proof(),
                                     audience="agentguard:tool")
    assert "context" in body and "happy" in body["context"]
    status, reply = live.post("/v1/authorize", body)
    assert status == 200
    decision = AuthorizationDecision.from_agentguard_dict(reply)
    decision.validate()
    assert decision.allowed is True


def test_unknown_context_block_is_ignored_by_the_real_route(live):
    """A future peer sending extra context keys must not break AgentGuard."""
    request = AuthorizationRequest(action="tool:read_file", resource="/etc/hosts",
                                   agent_id=live.agent_id)
    body = request.to_authorize_body(token=live.token, proof=live.make_proof(),
                                     audience="agentguard:tool")
    body["context"]["some_future_namespace"] = {"anything": True}
    body["x_unknown_top_level"] = "ignored"
    status, reply = live.post("/v1/authorize", body)
    assert status == 200
    assert AuthorizationDecision.from_agentguard_dict(reply).allowed is True


def test_real_route_denies_when_the_credential_is_forged(live):
    request = AuthorizationRequest(action="tool:read_file", resource="/etc/hosts",
                                   agent_id=live.agent_id)
    body = request.to_authorize_body(token="agp1.forged.token.value", proof={"signature": "x"},
                                     audience="agentguard:tool")
    status, reply = live.post("/v1/authorize", body)
    assert status == 200
    decision = AuthorizationDecision.from_agentguard_dict(reply)
    assert decision.allowed is False
    assert decision.is_final_deny


def test_malformed_body_does_not_break_the_real_route(live):
    """A malformed request must be rejected without taking the security service down."""
    for body in ({}, {"action": ""}, {"action": "tool:read_file"},
                 {"token": 12345, "action": "tool:read_file"}):
        status, reply = live.post("/v1/authorize", body)
        assert status in (200, 400)
        assert isinstance(reply, dict)
    # The service is still healthy and still deciding correctly afterwards.
    status, reply = live.post("/v1/authorize",
                              AuthorizationRequest(action="tool:read_file", resource="/etc/hosts",
                                                   agent_id=live.agent_id)
                              .to_authorize_body(token=live.token, proof=live.make_proof(),
                                                 audience="agentguard:tool"))
    assert status == 200
    assert AuthorizationDecision.from_agentguard_dict(reply).allowed is True
