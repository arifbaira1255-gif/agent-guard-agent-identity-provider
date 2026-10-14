"""Tests for the OS-enforced isolation layer (``isolation.py``).

These tests assert only what the host actually provides: when no backend is usable they skip rather
than pretend.  The escape probes are the real ones Happy LANG ships, so a pass here is evidence of
an *observed* property, not a claim.
"""
from __future__ import annotations

import os
import sys

import pytest

from agentguard_happy_contract.isolation import (
    IsolationReport,
    JailSpec,
    cleanup_workdir,
    isolation_available,
    make_workdir,
    probe_isolation,
    run_in_jail,
)


@pytest.fixture(scope="module")
def report() -> IsolationReport:
    return probe_isolation()


class TestProbe:
    def test_report_is_machine_readable(self, report):
        payload = report.to_dict()
        assert set(payload) >= {"mode", "selected", "os_isolated", "achieved", "backends", "probes"}
        assert isinstance(payload["backends"], dict)

    def test_achieved_requires_observed_probes(self, report):
        """``achieved`` must never be true on an assumption -- only on passed probes."""
        if report.achieved:
            assert report.probes and not report.failures
        else:
            assert not report.probes or report.failures

    def test_available_matches_the_report(self, report):
        assert isolation_available() == report.os_isolated

    def test_required_mode_fails_closed_when_nothing_is_usable(self):
        """With an impossible backend, ``required`` must report no isolation (never a silent pass)."""
        forced = probe_isolation(mode="required", backend="docker", run_self_test=False)
        if not forced.os_isolated:
            assert forced.error is not None


class TestWorkdir:
    def test_workdir_is_private_and_removable(self):
        path = make_workdir()
        try:
            assert os.path.isdir(path)
            assert (os.stat(path).st_mode & 0o777) == 0o700
        finally:
            assert cleanup_workdir(path) is True
        assert not os.path.exists(path)

    def test_cleanup_of_a_missing_path_is_safe(self):
        """Cleanup must never raise, and must report the path is gone."""
        assert cleanup_workdir("/nonexistent/happy/path") is True
        assert cleanup_workdir("") is False

    def test_two_workdirs_never_collide(self):
        first, second = make_workdir(), make_workdir()
        try:
            assert first != second
        finally:
            cleanup_workdir(first)
            cleanup_workdir(second)


class TestJailSpec:
    def test_invalid_specs_are_rejected(self):
        from agentguard_happy_contract.errors import ValidationError

        with pytest.raises(ValidationError):
            JailSpec(workdir="/nonexistent", timeout_s=1).validate()
        with pytest.raises(ValidationError):
            JailSpec(workdir=make_workdir(), timeout_s=0).validate()


@pytest.mark.skipif(not isolation_available(), reason="no usable OS isolation backend on this host")
class TestJailExecution:
    """Real jailed runs.  Skipped (not faked) when the host cannot isolate."""

    def _run(self, script: str, **kwargs):
        workdir = make_workdir()
        try:
            with open(os.path.join(workdir, "prog.py"), "w", encoding="utf-8") as handle:
                handle.write(script)
            spec = JailSpec(workdir=workdir, python=sys.executable, timeout_s=kwargs.pop(
                "timeout_s", 30), **kwargs)
            return run_in_jail([sys.executable, "/work/prog.py"], spec)
        finally:
            cleanup_workdir(workdir)

    def test_a_benign_program_runs_and_its_output_is_captured(self):
        result = self._run("print('jailed-ok')")
        assert result.ok is True, result.stderr
        assert "jailed-ok" in result.stdout
        assert result.backend is not None

    def test_host_files_are_not_visible_inside_the_jail(self):
        """The read-only rootfs must not contain the host's ``/etc/passwd``."""
        result = self._run(
            "import os\n"
            "try:\n"
            "    open('/etc/passwd').read()\n"
            "    print('READ_HOST_FILE')\n"
            "except Exception:\n"
            "    print('blocked')\n")
        assert "READ_HOST_FILE" not in result.stdout
        assert "blocked" in result.stdout

    def test_network_is_unreachable_inside_the_jail(self):
        result = self._run(
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 53), 2)\n"
            "    print('NETWORK_OPEN')\n"
            "except Exception:\n"
            "    print('blocked')\n")
        assert "NETWORK_OPEN" not in result.stdout
        assert "blocked" in result.stdout

    def test_the_root_filesystem_is_read_only(self):
        result = self._run(
            "try:\n"
            "    open('/usr/happy_probe', 'w').write('x')\n"
            "    print('ROOTFS_WRITABLE')\n"
            "except Exception:\n"
            "    print('blocked')\n")
        assert "ROOTFS_WRITABLE" not in result.stdout

    def test_the_program_runs_unprivileged(self):
        result = self._run("import os; print('uid', os.getuid())")
        assert "uid 0" not in result.stdout

    def test_a_runaway_program_is_killed_at_the_timeout(self):
        result = self._run("while True:\n    pass\n", timeout_s=3)
        assert result.timed_out is True
        assert result.ok is False
        assert result.killed_group is True

    def test_a_crashing_program_does_not_break_the_jail(self):
        result = self._run("raise SystemExit(3)")
        assert result.ok is False and result.returncode == 3
        assert result.timed_out is False
