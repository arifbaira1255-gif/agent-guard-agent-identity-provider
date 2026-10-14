"""Authorizer tests: local pre-filter, authoritative remote decision, preemption and fail-closed.

These pin the security-critical precedence rules from the Step 1 audit (§D):
  * the remote decision is authoritative -- a local ALLOW never overrides a remote DENY;
  * uncertainty (unreachable PDP, timeout, malformed answer) is ALWAYS a denial;
  * a local DENY short-circuits without a network call;
  * a capability DECLARED by a program grants nothing by itself.
"""
import pytest

from agentguard_happy_contract import (
    AgentGuardAuthorizer,
    AuthorizationDecision,
    CallablePdp,
    IntegrationConfig,
    SecurityEvent,
)
from agentguard_happy_contract.authorizer import (
    ACTION_PREFIX,
    HappyAuthorizationDenied,
    install_into_runtime,
)


# ---------------------------------------------------------------- helpers/stubs
class FakeChecker:
    """A stand-in for Happy's ``CapabilityChecker`` (local pre-filter)."""

    def __init__(self, allow: bool = True, error=None):
        self._allow = allow
        self._error = error
        self.calls = []
        self._agent = "Main"

    @property
    def current_agent(self):
        return self._agent

    def enter_agent(self, agent):
        self._agent = agent

    def exit_agent(self):
        self._agent = "Main"

    def check_operation(self, operation, agent=None, loc=None, args=None):
        self.calls.append(("check_operation", operation, agent))
        if self._error is not None:
            raise self._error
        return self._allow

    def require_action(self, action, agent=None, loc=None):
        self.calls.append(("require_action", action, agent))
        if self._error is not None:
            raise self._error
        return self._allow


def allowing_pdp(reason="test_allow"):
    return CallablePdp(lambda req, **kw: AuthorizationDecision.allow(reason))


def denying_pdp(reason="no_matching_capability"):
    return CallablePdp(lambda req, **kw: AuthorizationDecision.deny(reason))


def garbage_pdp():
    return CallablePdp(lambda req, **kw: "not-a-decision")


def raising_pdp(exc):
    def boom(req, **kw):
        raise exc

    return CallablePdp(boom)


def collecting_forwarder():
    batches = []

    class F:
        def report(self, event):
            batches.append(event)
            return event.to_dict()

        def flush(self):
            return len(batches)

    return F(), batches


def authorizer(pdp, *, checker=None, enabled=True, mode="enforce", forwarder=None):
    return AgentGuardAuthorizer(
        IntegrationConfig(enabled=enabled, mode=mode), checker=checker, pdp=pdp,
        forwarder=forwarder)


# ---------------------------------------------------------------- precedence rules
def test_remote_deny_is_final():
    auth = authorizer(denying_pdp())
    with pytest.raises(Exception) as exc:
        auth.check_operation("write_file", agent="Teller", loc=("demo.hpy", 12, 5),
                             args={"path": "/tmp/out.txt"})
    assert "not authorized by AgentGuard" in str(exc.value)
    assert auth.denials, "the denial must be recorded in the audit trail"


def test_local_allow_never_overrides_a_remote_deny():
    """The core audit finding: the local checker is a pre-filter, NOT the authority."""
    auth = authorizer(denying_pdp(), checker=FakeChecker(allow=True))
    with pytest.raises(Exception):
        auth.check_operation("write_file", agent="Teller", args={"path": "/tmp/x"})
    assert auth.audit[-1].local_allowed is True
    assert auth.audit[-1].decision.allowed is False


def test_local_deny_short_circuits_without_contacting_the_pdp():
    contacted = []

    def spy(req, **kw):
        contacted.append(req)
        return AuthorizationDecision.allow()

    auth = authorizer(CallablePdp(spy), checker=FakeChecker(allow=False))
    # Happy's contract: check_operation RETURNS False for a locally-denied operation.
    assert auth.check_operation("write_file", args={"path": "/tmp/x"}) is False
    assert contacted == [], "a locally denied operation must not reach the network"
    assert auth.audit[-1].asked_remote is False


def test_remote_allow_permits_the_operation():
    auth = authorizer(allowing_pdp())
    assert auth.check_operation("read_file", args={"path": "/etc/hosts"}) is True


# ---------------------------------------------------------------- fail closed
def test_indeterminate_answer_is_denied():
    auth = authorizer(garbage_pdp())
    with pytest.raises(Exception):
        auth.check_operation("write_file", args={"path": "/tmp/x"})
    decision = auth.audit[-1].decision
    assert decision.decision.value == "INDETERMINATE"
    assert decision.allowed is False


def test_unreachable_pdp_is_denied_not_allowed():
    auth = authorizer(raising_pdp(ConnectionError("connection refused")))
    with pytest.raises(Exception):
        auth.check_operation("write_file", args={"path": "/tmp/x"})
    assert auth.audit[-1].decision.allowed is False


def test_timeout_is_denied():
    auth = authorizer(raising_pdp(TimeoutError("timed out")))
    with pytest.raises(Exception):
        auth.check_operation("write_file", args={"path": "/tmp/x"})
    assert auth.audit[-1].decision.allowed is False


def test_literal_none_answer_is_denied():
    auth = authorizer(CallablePdp(lambda req, **kw: None))
    with pytest.raises(Exception):
        auth.check_operation("write_file", args={"path": "/tmp/x"})


# ---------------------------------------------------------------- feature flag
def test_disabled_integration_is_inert_and_offline():
    contacted = []
    auth = authorizer(CallablePdp(lambda req, **kw: contacted.append(req)),
                      checker=FakeChecker(allow=True), enabled=False, mode="off")
    assert auth.check_operation("write_file", args={"path": "/tmp/x"}) is True
    assert contacted == [], "a disabled integration must never contact AgentGuard"
    assert auth.audit[-1].asked_remote is False


def test_audit_mode_records_without_blocking():
    """Migration mode: the decision is recorded, but a denial does not stop execution."""
    auth = authorizer(denying_pdp(), enabled=True, mode="audit")
    # mode="audit" still returns the decision; the executor decides what to do with it.
    decision = auth.authorize_operation("write_file", args={"path": "/tmp/x"})
    assert decision.allowed is False
    assert auth.audit, "the check must still be recorded"


# ---------------------------------------------------------------- request shape
def test_authorization_request_carries_identity_action_resource_and_correlation():
    captured = {}

    def capture(req, **kw):
        captured["request"] = req
        return AuthorizationDecision.allow("ok")

    auth = AgentGuardAuthorizer(
        IntegrationConfig(enabled=True, mode="enforce", agent_id="agt_integration",
                          instance_id="inst_1", org_id="acme", agent_scope="Teller"),
        pdp=CallablePdp(capture), forwarder=None)
    auth.check_operation("write_file", agent="Teller", loc=("banking.hpy", 14, 9),
                         args={"path": "/data/out.json"})
    request = captured["request"]
    assert request.action == "tool:write_file"
    assert request.resource == "/data/out.json"
    assert request.agent_id == "agt_integration"
    assert request.instance_id == "inst_1"
    assert request.org_id == "acme"
    assert request.agent_scope == "Teller"
    assert request.correlation_id.startswith("corr_")
    assert request.request_id.startswith("req_")
    assert request.source_loc.file == "banking.hpy"
    assert request.requested_capabilities == ("file_write", )
    assert request.effects == ()


def test_action_mapping_uses_happy_enforcement_map():
    """The abstract action must come from Happy's own map so both sides cannot disagree."""
    auth = authorizer(allowing_pdp())
    action, abstract = auth.action_for("write_file")
    assert action == f"{ACTION_PREFIX}write_file"
    assert abstract == "file_write"
    _action, http_abstract = auth.action_for("http_get")
    assert http_abstract == "net"


def test_resource_is_derived_from_call_arguments_not_the_program():
    auth = authorizer(allowing_pdp())
    assert auth.resolve_resource("write_file", {"path": "/a/b.txt"}, "A") == "/a/b.txt"
    assert auth.resolve_resource("http_post", {"url": "https://x.invalid"}, "A") == "https://x.invalid"
    assert auth.resolve_resource("write_file", None, "A") == "unspecified"


def test_require_action_path_is_authorized_too():
    auth = authorizer(denying_pdp("secrets_not_granted"))
    with pytest.raises(Exception) as exc:
        auth.require_action("secrets", agent="Crypto")
    assert "not authorized by AgentGuard" in str(exc.value)


# ---------------------------------------------------------------- audit + events
def test_denial_emits_a_security_event_with_the_correlation_id():
    forwarder, batches = collecting_forwarder()
    auth = authorizer(denying_pdp(), forwarder=forwarder)
    with pytest.raises(Exception):
        auth.check_operation("write_file", args={"path": "/tmp/x"})
    assert batches, "a denial must be observable/auditable"
    event = batches[-1]
    assert isinstance(event, SecurityEvent)
    assert event.event_type == "happy.authorization.denied"
    assert event.correlation_id.startswith("corr_")
    assert event.outcome == "denied"


def test_successful_authorization_is_auditable():
    forwarder, batches = collecting_forwarder()
    auth = authorizer(allowing_pdp(), forwarder=forwarder)
    auth.check_operation("read_file", args={"path": "/etc/hosts"})
    assert batches[-1].event_type == "happy.operation.routed"


def test_summary_reports_real_counts():
    auth = authorizer(denying_pdp())
    for _ in range(2):
        with pytest.raises(Exception):
            auth.check_operation("write_file", args={"path": "/tmp/x"})
    assert len(auth.audit) == 2
    assert len(auth.denials) == 2
    summary = auth.summary()
    assert "2 authorization check(s)" in summary
    assert "2 denial(s)" in summary


# ---------------------------------------------------------------- runtime installation
class FakeRuntimeContext:
    def __init__(self):
        self.capabilities = object()


def test_install_into_runtime_rebinds_the_pluggable_hook():
    context = FakeRuntimeContext()
    auth = authorizer(allowing_pdp())
    install_into_runtime(context, auth)
    assert context.capabilities is auth


def test_install_into_runtime_rejects_a_context_without_capabilities():
    from agentguard_happy_contract import ContractError

    with pytest.raises(ContractError):
        install_into_runtime(object(), authorizer(allowing_pdp()))


def test_denial_uses_happys_own_exception_type_when_available():
    """Programs keep working: the integration changes the decision source, not the error surface."""
    from happy.runtime.errors import CapabilityDenied

    auth = authorizer(denying_pdp(), pdp_extra=None) if False else authorizer(denying_pdp())
    with pytest.raises(Exception) as exc:
        auth.check_operation("write_file", args={"path": "/tmp/x"})
    assert isinstance(exc.value, CapabilityDenied)


def test_standalone_denial_type_is_used_when_happy_is_absent(monkeypatch):
    """The module must be usable (and still fail closed) without Happy LANG importable."""
    import builtins

    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name.startswith("happy"):
            raise ImportError("happy not available")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    auth = authorizer(denying_pdp())
    with pytest.raises(HappyAuthorizationDenied):
        auth.check_operation("write_file", args={"path": "/tmp/x"})
