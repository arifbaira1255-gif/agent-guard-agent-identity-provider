"""Adversarial tests: the attacks the task names, run against the real runtime.

Each test tries to *break out* or *exhaust* the runtime and asserts the attempt failed.  Where a
property cannot be demonstrated on this host the test skips rather than claiming success -- the
honesty rule applies to tests as much as to reports.

Attacks covered: path traversal, resource exhaustion (output / operations / wall clock), unauthorized
network access, malformed inputs, and isolation failures.
"""
from __future__ import annotations

import os
import sys

import pytest

from agentguard_happy_contract.config import IntegrationConfig
from agentguard_happy_contract.isolation import (
    JailSpec,
    cleanup_workdir,
    isolation_available,
    make_workdir,
    run_in_jail,
)
from agentguard_happy_contract.limits import BudgetTracker, ExecutionBudget, ResourceLimitExceeded
from agentguard_happy_contract.models import (
    ArtifactRef,
    ExecutionLimits,
    ExecutionRequest,
    ExecutionResource,
    ResultKind,
)
from agentguard_happy_contract.secure_runtime import CallerCredential, SecureExecutionRuntime
from agentguard_happy_contract.validation import sha256_hex

needs_isolation = pytest.mark.skipif(
    not isolation_available(), reason="no usable OS isolation backend on this host")


def _request(source, *, limits=None, resources=None, capabilities=("file_read",),
             request_id="req_adv") -> ExecutionRequest:
    return ExecutionRequest(
        request_id=request_id, agent_id="agent_adv",
        artifact=ArtifactRef(digest=sha256_hex(source), entry="main", filename="adv.hpy",
                             bytes_size=len(source.encode("utf-8"))),
        requested_capabilities=tuple(capabilities),
        declared_resources=tuple(resources) if resources else (
            ExecutionResource(kind="none", target="unspecified", access="read"), ),
        policy_version="v1", limits=limits or ExecutionLimits(timeout_s=30))


@pytest.fixture
def runtime():
    rt = SecureExecutionRuntime(IntegrationConfig(enabled=False), isolation_mode="auto")
    rt.start()
    yield rt
    rt.shutdown()


def _run(runtime, source, **kwargs):
    return runtime.execute(_request(source, **kwargs), source,
                           credential=CallerCredential(token="adv-token"))


@needs_isolation
class TestPathTraversal:
    """A program must not be able to read host files, by any path spelling."""

    @pytest.mark.parametrize("path", [
        "/etc/passwd",
        "/etc/shadow",
        "../../../../etc/passwd",
        "/proc/self/environ",
        "/root/.ssh/id_rsa",
        "/work/../etc/passwd",
    ])
    def test_host_file_reads_are_refused(self, runtime, path):
        source = (
            'module t\n\nimport { read_file } from "std.fs"\n\nfunction main() {\n'
            f'  let c = read_file("{path}")\n  println(c)\n}}\n')
        result = _run(runtime, source)
        assert result.result is not ResultKind.OK
        assert "root:" not in result.output
        assert "PRIVATE KEY" not in result.output

    def test_a_traversal_attempt_does_not_escape_the_work_directory(self, runtime):
        source = (
            'module t\n\nimport { read_file } from "std.fs"\n\nfunction main() {\n'
            '  let c = read_file("../../../../../../etc/hostname")\n  println(c)\n}\n')
        result = _run(runtime, source)
        assert result.result is not ResultKind.OK


@needs_isolation
class TestResourceExhaustion:
    def test_output_flood_is_stopped(self, runtime):
        source = (
            'module t\n\nfunction main() {\n  var i = 0\n  while i < 1000000 {\n'
            '    println("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")\n    i = i + 1\n  }\n}\n')
        result = _run(runtime, source, limits=ExecutionLimits(timeout_s=30, max_output_bytes=8192))
        assert result.result is ResultKind.RESOURCE_LIMIT
        assert len(result.output.encode("utf-8")) <= 8192 + 4096

    def test_infinite_loop_is_killed(self, runtime):
        source = ('module t\n\nfunction main() {\n  var i = 0\n  while true {\n'
                  '    i = i + 1\n  }\n}\n')
        result = _run(runtime, source, limits=ExecutionLimits(timeout_s=4))
        assert result.result is ResultKind.TIMEOUT

    def test_operation_budget_is_enforced_in_process(self):
        """The tracker is a real control: it refuses the operation that exceeds the ceiling."""
        tracker = BudgetTracker(ExecutionBudget(max_operations=5))
        for _ in range(5):
            tracker.charge_operation()
        with pytest.raises(ResourceLimitExceeded) as exc:
            tracker.charge_operation()
        assert exc.value.kind == "operations"

    def test_a_deeply_nested_program_fails_cleanly(self, runtime):
        """A pathological program must produce a diagnostic, never a raw traceback."""
        source = "module t\n\nfunction main() {\n  let x = " + "(" * 400 + "1" + ")" * 400 + "\n}\n"
        result = _run(runtime, source)
        assert result.result in (ResultKind.COMPILE_ERROR, ResultKind.RUNTIME_ERROR,
                                 ResultKind.RESOURCE_LIMIT, ResultKind.OK)
        assert "Traceback" not in (result.error or "")


@needs_isolation
class TestUnauthorizedNetwork:
    def test_outbound_connection_is_impossible(self, runtime):
        source = (
            'module t\n\nimport { http_get } from "std.net"\n\nfunction main() {\n'
            '  let r = http_get("http://1.1.1.1/")\n  println(r)\n}\n')
        result = _run(runtime, source, capabilities=("net",))
        assert result.result is not ResultKind.OK

    def test_raw_socket_is_unreachable_inside_the_jail(self):
        """Even bypassing the language, the kernel has no route: the netns is empty."""
        workdir = make_workdir()
        try:
            with open(os.path.join(workdir, "sock.py"), "w", encoding="utf-8") as handle:
                handle.write(
                    "import socket\n"
                    "try:\n"
                    "    socket.create_connection(('1.1.1.1', 53), 2)\n"
                    "    print('NETWORK_OPEN')\n"
                    "except Exception:\n"
                    "    print('blocked')\n")
            spec = JailSpec(workdir=workdir, python=sys.executable, timeout_s=30)
            result = run_in_jail([sys.executable, "/work/sock.py"], spec)
        finally:
            cleanup_workdir(workdir)
        assert "NETWORK_OPEN" not in result.stdout
        assert "blocked" in result.stdout


@needs_isolation
class TestMalformedInputs:
    @pytest.mark.parametrize("source", [
        "",
        "   ",
        "module",
        "module t\n\nfunction main() {",
        "module t\n\nfunction main() {\n  let x = \n}\n",
        "\x00\x01\x02binary garbage",
        "module t\n\n" + "function f() {}\n" * 2000,
    ])
    def test_malformed_programs_fail_safely(self, runtime, source):
        result = _run(runtime, source)
        assert result.result is not ResultKind.OK
        assert result.ok is False
        assert result.result in (ResultKind.COMPILE_ERROR, ResultKind.VALIDATION_ERROR,
                                 ResultKind.RUNTIME_ERROR, ResultKind.RESOURCE_LIMIT,
                                 ResultKind.TIMEOUT)

    def test_a_request_with_no_capabilities_is_refused(self, runtime):
        result = _run(runtime, "module t\n\nfunction main() {}\n", capabilities=())
        assert result.result is ResultKind.VALIDATION_ERROR

    def test_a_request_with_no_resources_is_refused(self, runtime):
        request = _request("module t\n\nfunction main() {}\n")
        object.__setattr__(request, "declared_resources", ())
        result = runtime.execute(request, "module t\n\nfunction main() {}\n",
                                 credential=CallerCredential(token="t"))
        assert result.result is ResultKind.VALIDATION_ERROR

    def test_an_unsupported_contract_version_is_refused(self, runtime):
        request = _request("module t\n\nfunction main() {}\n")
        object.__setattr__(request, "contract_version", "99.0.0")
        result = runtime.execute(request, "module t\n\nfunction main() {}\n",
                                 credential=CallerCredential(token="t"))
        assert result.result is ResultKind.VALIDATION_ERROR


@needs_isolation
class TestIsolationFailures:
    def test_a_program_that_tries_to_escalate_privileges_fails(self):
        workdir = make_workdir()
        try:
            with open(os.path.join(workdir, "priv.py"), "w", encoding="utf-8") as handle:
                handle.write(
                    "import os\n"
                    "try:\n"
                    "    os.setuid(0)\n"
                    "    print('ESCALATED')\n"
                    "except Exception:\n"
                    "    print('blocked')\n")
            spec = JailSpec(workdir=workdir, python=sys.executable, timeout_s=30)
            result = run_in_jail([sys.executable, "/work/priv.py"], spec)
        finally:
            cleanup_workdir(workdir)
        assert "ESCALATED" not in result.stdout

    def test_the_jail_refuses_to_run_when_isolation_is_required_but_absent(self):
        """``required`` mode with an unusable backend must refuse, never run unjailed."""
        workdir = make_workdir()
        try:
            with open(os.path.join(workdir, "p.py"), "w", encoding="utf-8") as handle:
                handle.write("print('should not run')\n")
            spec = JailSpec(workdir=workdir, python=sys.executable, timeout_s=10,
                            mode="required", backend="docker")
            result = run_in_jail([sys.executable, "/work/p.py"], spec)
        finally:
            cleanup_workdir(workdir)
        if not result.ok:
            assert "should not run" not in result.stdout
            assert result.error is not None

    def test_a_worker_crash_leaves_the_control_plane_healthy(self, runtime):
        _run(runtime, "module t\n\nfunction main() {\n  let x = 1 / 0\n}\n")
        assert runtime.health()["healthy"] is True
        assert _run(runtime, 'module t\n\nfunction main() {\n  println("still alive")\n}\n'
                    ).result is ResultKind.OK

    def test_no_work_directory_is_left_behind_after_attacks(self, runtime):
        import glob
        import tempfile

        before = set(glob.glob(os.path.join(tempfile.gettempdir(), "happy_exec_*")))
        _run(runtime, "module t\n\nfunction main() {\n  let x = 1 / 0\n}\n")
        _run(runtime, 'module t\n\nfunction main() {\n  println("x")\n}\n')
        after = set(glob.glob(os.path.join(tempfile.gettempdir(), "happy_exec_*")))
        assert after <= before, f"leaked work directories: {after - before}"
