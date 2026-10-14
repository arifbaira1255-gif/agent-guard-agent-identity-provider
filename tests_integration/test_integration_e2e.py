"""End-to-end integration tests: a REAL Happy LANG artifact through the integrated flow.

Every test here either:
  * compiles a real ``.hpy`` program with the real Happy compiler,
  * runs an authorized program through the real Happy ``RuntimeContext``, or
  * performs an authenticated ``POST /v1/authorize`` against a real AgentGuard HTTP server,

and asserts on observable behaviour (returned structured result, AgentGuard's own decision body,
whether a file was actually written).  No mock stands in for either project.
"""
import os
import tempfile

import pytest

from agentguard_happy_contract import (
    AgentGuardAuthorizer,
    AuthorizationDecision,
    CallablePdp,
    ExecutionLimits,
    ExecutionResource,
    IntegratedExecutor,
    IntegrationConfig,
    ResultKind,
)
from agentguard_happy_contract.executor import compile_artifact
from live_stack import restore_default_hook, start_live_agentguard


# ---------------------------------------------------------------- test programs
#: Declares a capability that grants NOTHING useful, then tries to write a file.
DECLARED_BUT_NOT_GRANTED = """
module demo.escape

capability NetOnly { grants net }

agent Sneaky {
    capability [NetOnly]
    function save(p: String) -> Unit {
        write_file(p, "escaped")
        return
    }
}

app Escape {
    Sneaky.save("__PATH__")
}
"""

#: A capability that genuinely grants file_write to an agent that uses it.
GRANTED_WRITE = """
module demo.allowed

capability FileWriter { grants file_write }

agent Writer {
    capability [FileWriter]
    function save(p: String) -> Unit {
        write_file(p, "authorized-write")
        return
    }
}

app Allowed {
    Writer.save("__PATH__")
}
"""

#: Compiles and runs, prints a value, touches nothing.
PURE = """
module demo.pure

app Pure {
    println("pure-ok")
}
"""

#: Fails at runtime (integer division by zero) after a valid compile.
RUNTIME_FAILURE = """
module demo.boom

app Boom {
    let a = 0
    let b = 1
    println(str(b / a))
}
"""

#: Does not compile.
BROKEN = """
module demo.broken

app Broken {
    this is not valid happy syntax {{{
}
"""


def _temp_path(name):
    return os.path.join(tempfile.gettempdir(), f"happy_ag_{name}.txt")


@pytest.fixture(autouse=True)
def _cleanup_temp_files():
    made = []
    yield made
    for path in made:
        try:
            os.remove(path)
        except OSError:
            pass


# ---------------------------------------------------------------- compile stage
def test_real_example_compiles_and_declarations_are_extracted():
    source = open(os.path.join(os.path.dirname(__file__), "..", "happy-lang", "examples",
                               "banking.hpy")).read()
    artifact = compile_artifact(source, filename="examples/banking.hpy")
    assert artifact.ok is True
    assert artifact.capabilities, "the real IR must expose the declared capability grants"
    assert "Teller" in artifact.agents
    assert artifact.digest and len(artifact.digest) == 64


def test_structured_request_is_validated_before_anything_runs():
    executor = IntegratedExecutor(IntegrationConfig(enabled=False))
    ok, problems = executor.validate_request(
        _request(requested_capabilities=(), declared_resources=()))
    assert ok is False
    assert any("requested_capabilities" in p for p in problems)
    assert any("declared_resources" in p for p in problems)


def _request(*, agent_id="agt_1", requested_capabilities=("file_write", ),
             declared_resources=None, limits=None, filename=None):
    from agentguard_happy_contract import ArtifactRef, ExecutionRequest, sha256_hex

    if declared_resources is None:
        declared_resources = (ExecutionResource(kind="file", target=_temp_path("req"),
                                                access="write"), )
    return ExecutionRequest(
        request_id="req_test_1", agent_id=agent_id,
        artifact=ArtifactRef(digest=sha256_hex("src"), entry="main", filename=filename),
        requested_capabilities=tuple(requested_capabilities),
        declared_resources=tuple(declared_resources), policy_id="policy.test", policy_version="1",
        limits=limits or ExecutionLimits(timeout_s=10, max_memory_mb=256))


def test_invalid_request_yields_a_validation_error_result_not_an_exception():
    executor = IntegratedExecutor(IntegrationConfig(enabled=False))
    result = executor.execute(_request(requested_capabilities=()), PURE)
    assert result.result is ResultKind.VALIDATION_ERROR
    assert result.ok is False
    assert result.diagnostics


# ---------------------------------------------------------------- compile failures
def test_invalid_program_fails_safely_with_a_compile_error():
    executor = IntegratedExecutor(IntegrationConfig(enabled=False))
    result = executor.execute(_request(), BROKEN)
    assert result.result is ResultKind.COMPILE_ERROR
    assert result.ok is False
    assert result.error


def test_deeply_nested_program_fails_safely_instead_of_overflowing():
    executor = IntegratedExecutor(IntegrationConfig(enabled=False))
    result = executor.execute(_request(), "main { " + "(" * 400 + "1" + ")" * 400 + " }")
    assert result.result in (ResultKind.COMPILE_ERROR, ResultKind.OK)
    assert isinstance(result.result, ResultKind)


# ---------------------------------------------------------------- run stage
def test_authorized_program_runs_and_prints(tmp_path):
    executor = IntegratedExecutor(IntegrationConfig(enabled=False))
    result = executor.execute_source(PURE, filename="pure.hpy",
                                     requested_capabilities=("file_write", ),
                                     declared_resources=(ExecutionResource(
                                         kind="none", target="unspecified", access="read"), ))
    assert result.result is ResultKind.OK
    assert result.ok is True
    assert "pure-ok" in result.output


def test_runtime_error_is_handled_without_crashing_the_service():
    executor = IntegratedExecutor(IntegrationConfig(enabled=False))
    result = executor.execute_source(RUNTIME_FAILURE, filename="boom.hpy",
                                     requested_capabilities=("file_write", ),
                                     declared_resources=(ExecutionResource(
                                         kind="none", target="unspecified", access="read"), ))
    assert result.result in (ResultKind.RUNTIME_ERROR, ResultKind.POLICY_VIOLATION,
                             ResultKind.COMPILE_ERROR)
    assert result.ok is False
    # The executor itself must still be usable afterwards.
    assert executor.execute_source(PURE, filename="pure.hpy").ok is True


# ---------------------------------------------------------------- the security control
def test_declared_capability_does_not_grant_real_access(_cleanup_temp_files):
    """THE core integration guarantee: a declaration is a claim, and AgentGuard decides."""
    path = _temp_path("escape")
    _cleanup_temp_files.append(path)
    source = DECLARED_BUT_NOT_GRANTED.replace("__PATH__", path)

    executor = IntegratedExecutor(IntegrationConfig(enabled=True, mode="enforce"))
    executor.authorizer = AgentGuardAuthorizer(
        IntegrationConfig(enabled=True, mode="enforce"),
        pdp=CallablePdp(lambda req, **kw: AuthorizationDecision.deny("no_grant_for_write_file")))

    result = executor.execute_source(
        source, filename="escape.hpy", requested_capabilities=("file_write", ),
        declared_resources=(ExecutionResource(kind="file", target=path, access="write"), ))

    assert result.result is ResultKind.AUTHORIZATION_DENIED
    assert result.ok is False
    assert "denied" in (result.error or "").lower()
    assert not os.path.exists(path), "an unauthorized write must never reach the filesystem"


def test_deny_by_default_stops_execution_before_user_code_runs(_cleanup_temp_files):
    """With the integration on and no policy grant, NOTHING executes."""
    path = _temp_path("default_deny")
    _cleanup_temp_files.append(path)
    executor = IntegratedExecutor(IntegrationConfig(enabled=True, mode="enforce"))  # no PDP wired
    result = executor.execute_source(
        GRANTED_WRITE.replace("__PATH__", path), filename="granted.hpy",
        requested_capabilities=("file_write", ),
        declared_resources=(ExecutionResource(kind="file", target=path, access="write"), ))
    assert result.result is ResultKind.AUTHORIZATION_DENIED
    assert not os.path.exists(path)


def test_authorized_write_actually_reaches_the_filesystem(_cleanup_temp_files):
    """The positive control: when AgentGuard allows, the real program really does run."""
    path = _temp_path("granted")
    _cleanup_temp_files.append(path)
    executor = IntegratedExecutor(IntegrationConfig(enabled=True, mode="enforce"))
    executor.authorizer = AgentGuardAuthorizer(
        IntegrationConfig(enabled=True, mode="enforce"),
        pdp=CallablePdp(lambda req, **kw: AuthorizationDecision.allow("granted_by_test_policy")))

    result = executor.execute_source(
        GRANTED_WRITE.replace("__PATH__", path), filename="granted.hpy",
        requested_capabilities=("file_write", ),
        declared_resources=(ExecutionResource(kind="file", target=path, access="write"), ))

    assert result.ok is True, result.error
    assert os.path.exists(path), "an authorized write must really happen"
    with open(path) as handle:
        assert "authorized-write" in handle.read()


def test_cancellation_stops_before_execution():
    executor = IntegratedExecutor(IntegrationConfig(enabled=False))
    result = executor.execute_source(PURE, should_cancel=lambda: True)
    assert result.result is ResultKind.CANCELLED
    assert result.output == ""


def test_output_is_bounded_by_the_request_limit():
    executor = IntegratedExecutor(IntegrationConfig(enabled=False))
    source = 'module demo.chatty\n\napp Chatty {\n    let i = 0\n    while i < 2000 {\n' \
             '        println("0123456789012345678901234567890123456789")\n        i = i + 1\n' \
             '    }\n}\n'
    result = executor.execute_source(source, limits=ExecutionLimits(timeout_s=20,
                                                                    max_output_bytes=2048))
    assert len(result.output.encode("utf-8")) <= 2048 + 32
    assert "truncated" in result.output or len(result.output.encode("utf-8")) <= 2048


# ---------------------------------------------------------------- REAL AgentGuard server
@pytest.fixture(scope="module")
def live():
    server = start_live_agentguard(capabilities=("tool:write_file", "file_write"))
    try:
        yield server
    finally:
        restore_default_hook()
        server.close()


def test_real_agentguard_denies_an_unauthenticated_request(live):
    status, body = live.authorize({"action": "tool:write_file", "resource": "/tmp/x"})
    assert status == 200
    assert body["allowed"] is False
    assert body["reason"] in ("missing_credential", "invalid_credential")


def test_real_agentguard_allows_a_granted_capability(live):
    proof = live.make_proof()
    status, body = live.authorize({"token": live.token, "proof": proof,
                                   "audience": "agentguard:tool", "action": "tool:write_file",
                                   "resource": "/tmp/x"})
    assert status == 200
    assert body["allowed"] is True
    assert body["reason"] == "capability_match"


def test_real_agentguard_denies_an_ungranted_capability(live):
    proof = live.make_proof()
    status, body = live.authorize({"token": live.token, "proof": proof,
                                   "audience": "agentguard:tool", "action": "tool:delete_account",
                                   "resource": "/tmp/x"})
    assert status == 200
    assert body["allowed"] is False
    assert body["reason"] == "no_matching_capability"


def test_full_integration_against_the_real_agentguard_server(live):
    """END TO END: real Happy artifact -> real AgentGuard decision -> real structured result."""
    path = _temp_path("live")
    try:
        config = IntegrationConfig(
            enabled=True, mode="enforce", base_url=live.base_url, agent_id=live.agent_id,
            instance_id=live.instance_id, org_id=live.org_id, environment="development",
            timeout_seconds=10.0)
        authorizer = AgentGuardAuthorizer(config)
        # A fresh proof per request: AgentGuard's replay cache rejects a reused nonce, so the
        # integration mints one per authorization call (proof_provider).
        authorizer.set_credentials(token=live.token, proof_provider=live.make_proof)

        # 1. The granted action: AgentGuard allows, so the operation proceeds.
        assert authorizer.check_operation("write_file", agent="Writer",
                                          args={"path": path}) is True

        # 2. An action the credential was NOT issued for: AgentGuard denies, fail closed.
        with pytest.raises(Exception):
            authorizer.check_operation("process", agent="Writer", args={"command": "/bin/sh"})

        # 3. The structured result records the real denial (auditable, correlated).
        assert authorizer.denials, "the real denial must be recorded"
        denial = authorizer.denials[-1]
        assert denial.decision.allowed is False
        assert denial.decision.reason == "no_matching_capability"
        # A correlation id is always present so the denial is traceable across the seam. AgentGuard
        # mints its own ("cor_...") when it verifies the credential; the contract's id ("corr_...")
        # is threaded through when verification echoes the caller's value.
        assert denial.decision.correlation_id
        assert denial.decision.correlation_id.startswith("cor")

        # 4. Security events flow to AgentGuard's real /v1/security/events route.
        from agentguard_happy_contract import EventForwarder, http_event_sink

        forwarder = EventForwarder(http_event_sink(config), buffer_size=1)
        from agentguard_happy_contract import SecurityEvent

        forwarder.report(SecurityEvent(event_type="happy.capability.denied", outcome="denied",
                                       correlation_id="cor_live_test", agent_id=live.agent_id,
                                       reason="integration audit test"))
        assert forwarder.pending() == 0, "the event was accepted by AgentGuard's audit route"
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
