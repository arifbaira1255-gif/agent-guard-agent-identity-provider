"""Tests for the tool gate and the isolated-or-refused code execution path.

These cover the SECURE DEFAULTS (the legacy suite opts in to permissive settings in conftest).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_ROOT = Path(__file__).resolve().parents[4]
for _p in (_ROOT / "libs" / "contract", _ROOT / "libs" / "happy-lang"):
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from core.secure_exec import run_happy, run_python  # noqa: E402
from core.secure_gate import (  # noqa: E402
    AgentGuardGate,
    AllowAllGate,
    DenyAllGate,
    LocalPolicyGate,
    ToolDenied,
    ToolGate,
    build_gate,
)
from tools.registry import ToolRegistry, ToolSpec, build_default_gate  # noqa: E402


def _contract_available() -> bool:
    try:
        import agentguard_happy_contract.models  # noqa: F401

        return True
    except Exception:
        return False


# ── gates ────────────────────────────────────────────────────────────────────
def test_deny_all_denies():
    d = DenyAllGate().authorize("echo", {"text": "x"})
    assert d.allowed is False and d.decision == "DENY"


def test_local_policy_allow_deny_and_default_deny():
    g = LocalPolicyGate(allow="echo,now,python_exec", deny="python_exec")
    assert g.authorize("echo").allowed
    assert not g.authorize("python_exec").allowed  # deny wins over allow
    assert not g.authorize("web_search").allowed  # not on allow-list
    assert g.denied_count == 2 and g.allowed_count == 1


def test_gate_that_raises_is_a_denial():
    class Broken(ToolGate):
        def _decide(self, tool, arguments, agent_id):
            raise RuntimeError("boom")

    d = Broken().authorize("echo")
    assert d.allowed is False and d.decision == "INDETERMINATE" and "gate_error" in d.reason


def test_allow_all_refused_in_production():
    try:
        build_gate("allow_all", app_env="production")
    except ValueError:
        pass
    else:
        raise AssertionError("allow_all must not build in production")
    assert isinstance(build_gate("allow_all", app_env="development"), AllowAllGate)


def test_unknown_mode_raises():
    try:
        build_gate("yolo")
    except ValueError:
        return
    raise AssertionError("unknown mode must raise")


def test_audit_history_never_stores_arguments():
    g = LocalPolicyGate(allow="echo")
    g.authorize("echo", {"text": "TOP-SECRET-VALUE"})
    assert "TOP-SECRET-VALUE" not in repr(g.recent())


class _FakePdp:
    def __init__(self, result=None, exc=None):
        self.result, self.exc, self.requests = result, exc, []

    def decide(self, request, *, token="", proof=None):
        self.requests.append((request, token))
        if self.exc:
            raise self.exc
        return self.result


def _res(allowed, indeterminate=False, reason="r"):
    return SimpleNamespace(allowed=allowed, indeterminate=indeterminate, reason=reason,
                           decision=None, correlation_id="c1")


def test_agentguard_gate_allow_and_request_shape():
    if not _contract_available():
        return
    pdp = _FakePdp(_res(True))
    g = AgentGuardGate("http://ag", token="tok", agent_id="aql-1", pdp=pdp)
    assert g.authorize("web_search", {"query": "x"}).allowed
    req, token = pdp.requests[0]
    assert req.action == "tool:web_search" and req.resource == "tool:web_search" and token == "tok"


def test_agentguard_remote_deny_is_authoritative():
    if not _contract_available():
        return
    g = AgentGuardGate("http://ag", pdp=_FakePdp(_res(False, reason="policy_denied")))
    assert not g.authorize("echo").allowed


def test_agentguard_indeterminate_and_errors_fail_closed():
    if not _contract_available():
        return
    assert not AgentGuardGate("http://ag", pdp=_FakePdp(_res(True, indeterminate=True))).authorize("echo").allowed
    d = AgentGuardGate("http://ag", pdp=_FakePdp(exc=TimeoutError("t"))).authorize("echo")
    assert not d.allowed and d.decision == "INDETERMINATE"


def test_agentguard_client_factory_is_used_and_fails_closed_when_broken():
    if not _contract_available():
        return
    import types as _t

    mod = _t.ModuleType("_fake_ag_factory")

    class _Client:
        def authorize(self, **kw):
            return {"allowed": kw["action"] == "tool:echo", "reason": "cap"}

    mod.make = lambda: _Client()
    sys.modules["_fake_ag_factory"] = mod
    g = AgentGuardGate("", client_factory="_fake_ag_factory:make")
    assert g.authorize("echo").allowed
    assert not g.authorize("python_exec").allowed
    bad = AgentGuardGate("", client_factory="no_such_module:make").authorize("echo")
    assert not bad.allowed


def test_agentguard_no_url_and_local_denylist():
    assert not AgentGuardGate("").authorize("echo").allowed
    if _contract_available():
        pdp = _FakePdp(_res(True))
        g = AgentGuardGate("http://ag", deny="python_exec", pdp=pdp)
        assert not g.authorize("python_exec").allowed
        assert pdp.requests == []  # local deny short-circuits, never reaches the server


# ── registry ─────────────────────────────────────────────────────────────────
def _registry(gate):
    r = ToolRegistry(gate=gate)
    r.register(ToolSpec("echo", "e", {"type": "object", "properties": {}}, lambda text="": text))
    return r


def test_registry_denies_without_calling_handler():
    called = []
    r = ToolRegistry(gate=DenyAllGate())
    r.register(ToolSpec("t", "t", {}, lambda: called.append(1)))
    try:
        r.call("t")
    except ToolDenied as exc:
        assert exc.decision.allowed is False
    else:
        raise AssertionError("expected ToolDenied")
    assert called == []


def test_registry_allows_when_gate_allows_and_unknown_tool_is_keyerror():
    r = _registry(LocalPolicyGate(allow="echo"))
    assert r.call("echo", text="hi") == "hi"
    try:
        r.call("nope")
    except KeyError:
        return
    raise AssertionError("unknown tool must raise KeyError")


def test_default_gate_is_deny_all_when_settings_unavailable():
    with mock.patch("tools.registry._security_settings", return_value=None):
        assert isinstance(build_default_gate(), DenyAllGate)


def test_default_gate_is_deny_all_on_misconfiguration():
    bad = SimpleNamespace(tool_gate_mode="allow_all", app_env="production")
    with mock.patch("tools.registry._security_settings", return_value=bad):
        assert isinstance(build_default_gate(), DenyAllGate)  # allow_all in prod -> closed


# ── code execution ───────────────────────────────────────────────────────────
def test_python_exec_disabled_by_default():
    r = run_python("print(1)")
    assert r["ok"] is False and r["mode"] == "disabled" and "disabled" in r["error"]


def test_python_exec_unknown_mode_refused():
    assert run_python("print(1)", mode="whatever")["ok"] is False


def test_unsafe_dev_refused_in_production():
    r = run_python("print(1)", mode="unsafe_dev", app_env="production")
    assert r["ok"] is False and "production" in r["error"]


def test_unsafe_dev_runs_and_scrubs_environment():
    os.environ["AQL_TEST_SECRET"] = "s3cret"
    try:
        ok = run_python("print(2 + 2)", mode="unsafe_dev", app_env="development")
        assert ok["ok"] and ok["stdout"] == "4" and ok["isolated"] is False
        leak = run_python("import os; print(os.environ.get('AQL_TEST_SECRET'))",
                          mode="unsafe_dev", app_env="development")
        assert leak["stdout"] == "None"
        err = run_python("raise ValueError('boom')", mode="unsafe_dev", app_env="development")
        assert err["ok"] is False and "boom" in err["error"]
    finally:
        os.environ.pop("AQL_TEST_SECRET", None)


def test_code_size_limit():
    assert run_python("x=1\n" * 40000, mode="unsafe_dev", app_env="development")["ok"] is False


def test_isolated_mode_never_falls_back_to_host():
    r = run_python("print('hi')", mode="isolated", app_env="production")
    if r["ok"]:
        assert r["isolated"] is True  # a real jail was available and was used
    else:
        assert r["isolated"] is False  # refused - and crucially did not run on the host


def test_happy_run_is_jailed_or_refused_never_host():
    r = run_happy("function main() { }")
    assert r["isolated"] is True or r["ok"] is False  # an ok result must have come from the jail


def test_happy_run_executes_real_program_in_jail():
    tour = _ROOT / "libs" / "happy-lang" / "examples" / "language_tour.hpy"
    if not (_isolation_up() and tour.is_file()):
        return
    r = run_happy(tour.read_text(encoding="utf-8"), timeout=20)
    assert r["ok"] and r["isolated"] is True and "rect area=12" in r["stdout"]


def test_happy_run_reports_compile_errors_as_data():
    if not _isolation_up():
        return
    r = run_happy("this is not happy")
    assert r["ok"] is False and r["isolated"] is True and r["error"]


def _isolation_up() -> bool:
    try:
        from agentguard_happy_contract.isolation import isolation_available

        return bool(isolation_available())
    except Exception:
        return False


def test_isolated_python_actually_isolates_when_backend_present():
    if not _isolation_up():
        return
    ok = run_python("print(2 + 2)", mode="isolated", app_env="production")
    assert ok["ok"] and ok["stdout"] == "4" and ok["isolated"] is True
    probe = (
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 80), timeout=1); print('NET-OPEN')\n"
        "except Exception: print('net-blocked')\n"
        "try:\n"
        "    open('/etc/passwd').read(); print('PASSWD-READ')\n"
        "except Exception: print('passwd-blocked')\n"
    )
    out = run_python(probe, mode="isolated", app_env="production")["stdout"]
    assert "NET-OPEN" not in out and "PASSWD-READ" not in out
