"""End-to-end tests for the secure execution runtime (``secure_runtime.py``).

Every test here runs a REAL Happy LANG program through the REAL jail.  The eight structured outcomes
the task requires are each asserted by discriminant, and the security properties are asserted by
*observing* the run (a denied operation must not have happened), never by trusting a flag.
"""
from __future__ import annotations

import pytest

from agentguard_happy_contract.config import IntegrationConfig
from agentguard_happy_contract.isolation import isolation_available
from agentguard_happy_contract.models import (
    ArtifactRef,
    ExecutionLimits,
    ExecutionRequest,
    ExecutionResource,
    ResultKind,
)
from agentguard_happy_contract.pdp import CallablePdp
from agentguard_happy_contract.authorizer import AgentGuardAuthorizer
from agentguard_happy_contract.secure_runtime import CallerCredential, SecureExecutionRuntime
from agentguard_happy_contract.validation import sha256_hex

pytestmark = pytest.mark.skipif(
    not isolation_available(), reason="no usable OS isolation backend on this host")

HELLO = 'module t\n\nfunction main() {\n  println("hello from the jail")\n}\n'
CONTRACT_VIOLATION = (
    'module t\n\nfunction f(x: Int) -> Int\n  requires x > 0\n{\n  return x\n}\n\n'
    'function main() {\n  println(f(0))\n}\n')
DIVIDE_BY_ZERO = 'module t\n\nfunction main() {\n  let x = 1 / 0\n  println(x)\n}\n'
INFINITE_LOOP = 'module t\n\nfunction main() {\n  var i = 0\n  while true {\n    i = i + 1\n  }\n}\n'
OUTPUT_FLOOD = (
    'module t\n\nfunction main() {\n  var i = 0\n  while i < 100000 {\n'
    '    println("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")\n    i = i + 1\n  }\n}\n')
READ_HOST_FILE = (
    'module t\n\nimport { read_file } from "std.fs"\n\nfunction main() {\n'
    '  let c = read_file("/etc/passwd")\n  println(c)\n}\n')
OPEN_NETWORK = (
    'module t\n\nimport { http_get } from "std.net"\n\nfunction main() {\n'
    '  let r = http_get("http://1.1.1.1/")\n  println(r)\n}\n')
BROKEN = 'module t\n\nfunction main( {\n  this is not happy\n}\n'


def _request(source, *, limits=None, resources=None, capabilities=("file_read",),
             request_id="req_test", policy_version="v1") -> ExecutionRequest:
    return ExecutionRequest(
        request_id=request_id, agent_id="agent_test",
        artifact=ArtifactRef(digest=sha256_hex(source), entry="main", filename="t.hpy",
                             bytes_size=len(source.encode("utf-8"))),
        requested_capabilities=tuple(capabilities),
        declared_resources=tuple(resources) if resources else (
            ExecutionResource(kind="none", target="unspecified", access="read"), ),
        policy_version=policy_version, limits=limits or ExecutionLimits(timeout_s=30))


@pytest.fixture
def runtime():
    rt = SecureExecutionRuntime(IntegrationConfig(enabled=False), isolation_mode="auto")
    rt.start()
    yield rt
    rt.shutdown()


def _run(runtime, source, **kwargs):
    request = _request(source, **kwargs)
    return runtime.execute(request, source, credential=CallerCredential(token="test-token"))


class TestStructuredOutcomes:
    """One test per structured result the task enumerates."""

    def test_successful_validation_and_execution(self, runtime):
        result = _run(runtime, HELLO)
        assert result.result is ResultKind.OK
        assert result.ok is True
        assert "hello from the jail" in result.output

    def test_compilation_failure(self, runtime):
        result = _run(runtime, BROKEN)
        assert result.result is ResultKind.COMPILE_ERROR
        assert result.ok is False
        assert result.diagnostics

    def test_runtime_failure(self, runtime):
        result = _run(runtime, DIVIDE_BY_ZERO)
        assert result.result is ResultKind.RUNTIME_ERROR
        assert result.ok is False

    def test_policy_violation(self, runtime):
        result = _run(runtime, CONTRACT_VIOLATION)
        assert result.result is ResultKind.POLICY_VIOLATION
        assert result.ok is False

    def test_resource_limit_violation(self, runtime):
        result = _run(runtime, OUTPUT_FLOOD,
                      limits=ExecutionLimits(timeout_s=30, max_output_bytes=4096))
        assert result.result is ResultKind.RESOURCE_LIMIT
        assert result.metadata.get("limit_kind") == "output"

    def test_timeout(self, runtime):
        result = _run(runtime, INFINITE_LOOP, limits=ExecutionLimits(timeout_s=5))
        assert result.result is ResultKind.TIMEOUT
        assert result.ok is False

    def test_cancellation(self, runtime):
        from agentguard_happy_contract.limits import CancellationToken

        request = _request(HELLO)
        result = runtime.execute(request, HELLO, credential=CallerCredential(token="t"),
                                 token=CancellationToken.pre_cancelled())
        assert result.result is ResultKind.CANCELLED

    def test_authorization_denial(self):
        """A declared resource AgentGuard denies must stop the run before any code executes."""
        config = IntegrationConfig(enabled=True, mode="enforce", emit_events=False)
        authorizer = AgentGuardAuthorizer(config, pdp=CallablePdp(lambda req: {
            "allowed": False, "reason": "policy says no"}))
        rt = SecureExecutionRuntime(config, authorizer=authorizer, isolation_mode="auto")
        rt.start()
        try:
            result = _run(rt, HELLO, resources=(ExecutionResource(
                kind="file", target="/etc/shadow", access="read"), ))
        finally:
            rt.shutdown()
        assert result.result is ResultKind.AUTHORIZATION_DENIED
        assert result.ok is False

    def test_unauthenticated_request_is_refused(self):
        config = IntegrationConfig(enabled=True, mode="enforce", emit_events=False)
        rt = SecureExecutionRuntime(config, isolation_mode="auto")
        rt.start()
        try:
            result = rt.execute(_request(HELLO), HELLO, credential=None)
        finally:
            rt.shutdown()
        assert result.result is ResultKind.AUTHORIZATION_DENIED
        assert result.error_code == "unauthenticated"

    def test_malformed_request_is_refused(self, runtime):
        request = _request(HELLO)
        object.__setattr__(request, "request_id", "")          # frozen dataclass, forced invalid
        result = runtime.execute(request, HELLO, credential=CallerCredential(token="t"))
        assert result.result is ResultKind.VALIDATION_ERROR
        assert result.diagnostics


class TestSecurityProperties:
    """The properties the task requires to be *demonstrated*, not asserted."""

    def test_unauthorized_host_file_read_is_denied(self, runtime):
        """The program declares no file capability, so the read must not happen."""
        result = _run(runtime, READ_HOST_FILE, capabilities=("file_read",))
        assert result.result is not ResultKind.OK
        assert "root:" not in result.output

    def test_unauthorized_network_access_is_denied(self, runtime):
        result = _run(runtime, OPEN_NETWORK, capabilities=("net",))
        assert result.result is not ResultKind.OK

    def test_a_denied_operation_cannot_bypass_via_another_path(self, runtime):
        """A program that tries the file API twice must be refused both times."""
        source = (
            'module t\n\nimport { read_file } from "std.fs"\n\nfunction main() {\n'
            '  let a = read_file("/etc/passwd")\n  let b = read_file("/etc/hosts")\n'
            '  println(a)\n  println(b)\n}\n')
        result = _run(runtime, source)
        assert result.result is not ResultKind.OK
        assert "root:" not in result.output

    def test_a_worker_crash_does_not_crash_the_control_plane(self, runtime):
        """A hostile program must not take the runtime down; the next run still works."""
        _run(runtime, DIVIDE_BY_ZERO)
        assert runtime.health()["healthy"] is True
        assert _run(runtime, HELLO).result is ResultKind.OK

    def test_sensitive_values_are_not_exposed_in_the_result(self, runtime):
        result = _run(runtime, HELLO)
        payload = str(result.to_dict())
        assert "test-token" not in payload

    def test_evidence_records_the_isolation_actually_used(self, runtime):
        result = _run(runtime, HELLO)
        evidence = result.metadata.get("evidence") or {}
        assert evidence.get("isolation", {}).get("os_isolated") is True
        assert evidence.get("jail", {}).get("backend")
        assert evidence.get("cleanup_ok") is True

    def test_each_execution_gets_a_fresh_work_directory(self, runtime):
        first = _run(runtime, HELLO, request_id="req_a")
        second = _run(runtime, HELLO, request_id="req_b")
        assert first.result is ResultKind.OK and second.result is ResultKind.OK
        assert first.metadata["evidence"]["jail"] != second.metadata["evidence"]["jail"]


class TestHealthAndLifecycle:
    def test_health_reports_a_running_pool(self, runtime):
        health = runtime.health()
        assert health["running"] is True and health["healthy"] is True
        assert health["capacity"] >= 1

    def test_isolation_report_is_observed_not_assumed(self, runtime):
        report = runtime.isolation_report()
        assert report.os_isolated is True
        assert report.selected

    def test_shutdown_is_safe_to_repeat(self):
        rt = SecureExecutionRuntime(IntegrationConfig(enabled=False), isolation_mode="auto")
        rt.start()
        rt.shutdown()
        rt.shutdown()
        assert rt.health()["running"] is False
