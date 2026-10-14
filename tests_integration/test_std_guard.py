"""Tests for the fail-closed ``std`` guard -- the residual-bypass fix.

These tests exercise the REAL ``happy.std`` modules.  Before the fix, ``_authorize`` returned
silently when ``_CHECKER`` was ``None``, so ``std.fs.list_dir`` performed the operation with no check
at all.  The guard makes that path refuse instead.
"""
from __future__ import annotations

import pytest

from agentguard_happy_contract.std_guard import (
    DenyByDefaultChecker,
    StaticAllowlistChecker,
    install_std_guard,
    std_guard_installed,
    uninstall_std_guard,
)


@pytest.fixture(autouse=True)
def _restore_guard():
    """Never leave a guard installed for another test module."""
    yield
    uninstall_std_guard()


def _std(name):
    from importlib import import_module

    return import_module(f"happy.std.{name}")


class TestDenyByDefaultChecker:
    def test_denies_everything_by_default(self):
        checker = DenyByDefaultChecker()
        with pytest.raises(Exception) as exc:
            checker.check_operation("file_read")
        assert getattr(exc.value, "code", None) == "R2001"
        assert checker.denials == 1

    def test_allows_only_what_was_granted(self):
        checker = DenyByDefaultChecker(["file_read"])
        checker.check_operation("file_read")
        with pytest.raises(Exception):
            checker.check_operation("net")
        assert checker.checks == 2 and checker.denials == 1

    def test_require_action_hook_is_also_fail_closed(self):
        checker = DenyByDefaultChecker()
        with pytest.raises(Exception):
            checker.require_action("secrets")

    def test_allow_widens_the_policy(self):
        checker = StaticAllowlistChecker()
        checker.allow("net")
        assert checker.require_action("net") is True


class TestInstallUninstall:
    def test_install_points_every_std_module_at_a_checker(self):
        install_std_guard()
        assert std_guard_installed() is True
        for name in ("io", "fs", "net", "process", "env", "crypto"):
            assert _std(name)._CHECKER is not None, f"happy.std.{name} still has no checker"

    def test_uninstall_restores_the_previous_state(self):
        before = {name: _std(name)._CHECKER for name in ("io", "fs", "net", "process", "env",
                                                         "crypto")}
        install_std_guard()
        uninstall_std_guard()
        assert std_guard_installed() is False
        for name, value in before.items():
            assert _std(name)._CHECKER is before[name]

    def test_install_is_idempotent(self):
        first = install_std_guard(["file_read"])
        second = install_std_guard(["net"])
        assert first is second
        assert first.allowed == {"file_read"}


class TestBypassIsClosed:
    """The regression tests for the exact bypass the Step 1 audit identified."""

    def test_fs_operation_is_refused_without_a_grant(self):
        install_std_guard()
        with pytest.raises(Exception) as exc:
            _std("fs").list_dir(".")
        assert getattr(exc.value, "code", None) == "R2001"

    def test_fs_operation_is_permitted_with_a_grant(self):
        install_std_guard(["file_read"])
        assert isinstance(_std("fs").list_dir("."), list)

    def test_net_operation_is_refused_without_a_grant(self):
        install_std_guard()
        with pytest.raises(Exception):
            _std("net").http_get("http://127.0.0.1:1/")

    def test_crypto_secret_operation_is_refused_without_a_grant(self):
        install_std_guard()
        with pytest.raises(Exception):
            _std("crypto").random_token(8)

    def test_env_is_fail_closed_even_without_the_guard(self):
        """``std.env`` was already fail-closed; the guard must not weaken it."""
        uninstall_std_guard()
        with pytest.raises(Exception):
            _std("env").get("PATH")
