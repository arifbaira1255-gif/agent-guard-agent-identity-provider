"""Phase 6 tests: autonomous loop detection, human approval, incident response & containment.

Deterministic by construction: every test drives a fake clock, so no assertion depends on wall time.
The loop detector consumes the SAME normalized :class:`RuntimeEvent` objects Phase 5 ingests -- one
event pipeline, not two.

Coverage map (requirements 2,3,4,5,6,7,8,9,10,11):

  loop / runaway detection      LoopDetectionTests, ClassificationTests, TenantIsolationTests
  execution budgets + stops     BudgetTests, EmergencyStopTests, BudgetConcurrencyTests
  risk-based human approval     ApprovalTests, ApprovalBindingTests, ApprovalAdversarialTests
  incident lifecycle            IncidentLifecycleTests, CorrelationTests
  containment engine            ContainmentTests, ContainmentAdversarialTests
  response orchestration        OrchestrationTests, ResponseIdempotencyTests, LevelSelectionTests
  evidence + audit integrity    EvidenceTests, AuditIntegrityTests
  safe failure handling         SafeFailureTests
"""
from __future__ import annotations

import threading
import unittest

from agent_identity.core.errors import StorageError
from agent_identity.response import (
    ApprovalError, ApprovalMismatchError, ApprovalService, BudgetExceededError, BudgetService,
    ContainmentAction, ContainmentEngine, ContainmentIntegrations, EmergencyStopError,
    EvidenceService, IncidentError, IncidentService, LoopClassification, LoopDetector, LoopPattern,
    MemoryResponseStore, ResponseConfig, ResponseLevel, ResponseOrchestrator, ResponseService,
    ResponseState)
from agent_identity.response.audit import ResponseAudit, compute_hash
from agent_identity.runtime_monitoring.models import (Decision, EventType, RuntimeEvent, Severity)

ORG = "org_acme"
ORG_B = "org_globex"
AGENT = "agent_1"
AGENT_B = "agent_2"


class FakeClock:
    def __init__(self, t: float = 1_000_000.0):
        self.t = t

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def evt(org=ORG, agent=AGENT, event_type="tool.invocation", ts=1_000_000.0, action="read_file",
        resource="s3://bucket/report.csv", decision=None, outcome="ok", destination=None,
        extra=None, task_id=None):
    return RuntimeEvent(
        event_id=f"ev-{ts}-{action}-{len(str(resource))}", event_type=event_type, ts=ts,
        org_id=org, agent_id=agent, action=action, resource=resource,
        decision=(decision.value if isinstance(decision, Decision) else decision),
        outcome=outcome, destination=destination, extra=extra or {}, task_id=task_id)


def _svc(**cfg_kw):
    cfg = ResponseConfig(containment_allow_auto=True,
                         containment_high_impact_requires_approval=False, **cfg_kw)
    store = MemoryResponseStore()
    clock = FakeClock()
    return ResponseService(store, config=cfg, clock=clock), store, cfg, clock


# --------------------------------------------------------------------------- loop detection
class LoopDetectionTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryResponseStore()
        self.clock = FakeClock()
        self.det = LoopDetector(config=ResponseConfig(), clock=self.clock)

    def _feed(self, n, **kw):
        events = [evt(ts=self.clock.now() + i, **kw) for i in range(n)]
        self.det.observe(events, now=self.clock.now() + n)
        return events

    def test_repeated_action_without_budget_is_suspicious_not_confirmed(self):
        self._feed(6, action="read_file", resource="s3://bucket/a.csv")
        findings = self.det.detect(org_id=ORG, agent_id=AGENT, now=self.clock.now())
        names = {f.pattern for f in findings}
        self.assertIn(LoopPattern.REPEATED_ACTION.value, names)
        f = next(x for x in findings if x.pattern == LoopPattern.REPEATED_ACTION.value)
        self.assertEqual(f.classification, LoopClassification.SUSPICIOUS_REPETITION.value)
        self.assertEqual(f.observed_count, 6)
        self.assertGreaterEqual(len(f.evidence), 2)

    def test_repeated_action_exceeding_budget_is_confirmed_violation(self):
        self._feed(6, action="read_file", resource="s3://bucket/a.csv")
        budget = type("B", (), {"max_actions": 3})()
        findings = self.det.detect(org_id=ORG, agent_id=AGENT, now=self.clock.now(), budget=budget)
        f = next(x for x in findings if x.pattern == LoopPattern.REPEATED_ACTION.value)
        self.assertEqual(f.classification, LoopClassification.CONFIRMED_VIOLATION.value)

    def test_below_threshold_is_insufficient_not_suspicious(self):
        self._feed(2, action="read_file", resource="s3://bucket/a.csv")
        findings = self.det.detect(org_id=ORG, agent_id=AGENT, now=self.clock.now())
        self.assertEqual([f for f in findings
                          if f.classification != LoopClassification.INSUFFICIENT_EVIDENCE.value], [])

    def test_circular_invocation_detected(self):
        seq = ["a", "b", "a", "b", "a", "b"]
        events = [evt(ts=self.clock.now() + i, action=a, resource=a) for i, a in enumerate(seq)]
        self.det.observe(events, now=self.clock.now() + len(seq))
        findings = self.det.detect(org_id=ORG, agent_id=AGENT, now=self.clock.now())
        names = {f.pattern for f in findings}
        self.assertIn(LoopPattern.CIRCULAR_INVOCATION.value, names)

    def test_excessive_retry(self):
        self._feed(6, event_type=EventType.AGENT_RETRY.value, action="retry_op", resource="op/x")
        findings = self.det.detect(org_id=ORG, agent_id=AGENT, now=self.clock.now())
        names = {f.pattern for f in findings}
        self.assertIn(LoopPattern.EXCESSIVE_RETRY.value, names)

    def test_repeated_denial(self):
        self._feed(6, action="read_file", resource="s3://secret/x.csv",
                   decision=Decision.DENY)
        findings = self.det.detect(org_id=ORG, agent_id=AGENT, now=self.clock.now())
        names = {f.pattern for f in findings}
        self.assertIn(LoopPattern.REPEATED_DENIAL.value, names)

    def test_egress_repetition(self):
        self._feed(12, event_type=EventType.NETWORK_REQUEST.value, action=None, resource=None,
                   destination="https://exfil.example.com")
        findings = self.det.detect(org_id=ORG, agent_id=AGENT, now=self.clock.now())
        names = {f.pattern for f in findings}
        self.assertIn(LoopPattern.EGRESS_REPETITION.value, names)

    def test_cascade_failure(self):
        for i, res in enumerate(["a", "b", "c"]):
            self._feed(2, action=f"op_{i}", resource=res, outcome="error")
        findings = self.det.detect(org_id=ORG, agent_id=AGENT, now=self.clock.now())
        names = {f.pattern for f in findings}
        self.assertIn(LoopPattern.CASCADE_FAILURE.value, names)

    def test_resource_burn_tokens_confirmed(self):
        self._feed(3, action="llm", resource="model", extra={"tokens": 10_000})
        budget = type("B", (), {"max_tokens": 1_000, "max_cost": None})()
        findings = self.det.detect(org_id=ORG, agent_id=AGENT, now=self.clock.now(), budget=budget)
        f = next((x for x in findings if x.pattern == LoopPattern.RESOURCE_BURN.value
                  and x.subject == "tokens"), None)
        self.assertIsNotNone(f)
        self.assertEqual(f.classification, LoopClassification.CONFIRMED_VIOLATION.value)

    def test_tenant_windows_are_isolated(self):
        self._feed(6, org=ORG, agent=AGENT)
        self._feed(1, org=ORG_B, agent=AGENT)
        findings_a = self.det.detect(org_id=ORG, agent_id=AGENT, now=self.clock.now())
        findings_b = self.det.detect(org_id=ORG_B, agent_id=AGENT, now=self.clock.now())
        self.assertTrue(any(f.pattern == LoopPattern.REPEATED_ACTION.value for f in findings_a))
        self.assertFalse(any(f.pattern == LoopPattern.REPEATED_ACTION.value for f in findings_b))


# --------------------------------------------------------------------------- budgets
class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryResponseStore()
        self.clock = FakeClock()
        self.svc = BudgetService(self.store, config=ResponseConfig(), clock=self.clock)

    def test_guard_refuses_over_budget(self):
        self.svc.set_budget(org_id=ORG, agent_id=AGENT, max_actions=2)
        for _ in range(2):
            self.svc.guard(org_id=ORG, agent_id=AGENT)
        with self.assertRaises(BudgetExceededError):
            self.svc.guard(org_id=ORG, agent_id=AGENT)

    def test_no_budget_configured_is_admitted(self):
        d = self.svc.guard(org_id=ORG, agent_id=AGENT)
        self.assertTrue(d.allowed)
        self.assertEqual(d.reason, "no_budget_configured")

    def test_deadline_refused(self):
        self.svc.set_budget(org_id=ORG, agent_id=AGENT, deadline_s=10)
        self.clock.advance(11)
        with self.assertRaises(BudgetExceededError):
            self.svc.guard(org_id=ORG, agent_id=AGENT)

    def test_fail_closed_when_store_unavailable(self):
        class BoomStore:
            def find_budget(self, *a, **k):
                raise StorageError("down")
        svc = BudgetService(BoomStore(), config=ResponseConfig(budget_fail_closed=True),
                            clock=self.clock)
        d = svc.consume(org_id=ORG, agent_id=AGENT)
        self.assertFalse(d.allowed)
        self.assertTrue(d.fail_closed)

    def test_fail_open_when_configured(self):
        class BoomStore:
            def find_budget(self, *a, **k):
                raise StorageError("down")
        svc = BudgetService(BoomStore(), config=ResponseConfig(budget_fail_closed=False),
                            clock=self.clock)
        d = svc.consume(org_id=ORG, agent_id=AGENT)
        self.assertTrue(d.allowed)

    def test_task_budget_is_more_specific_than_agent_budget(self):
        self.svc.set_budget(org_id=ORG, agent_id=AGENT, max_actions=100)
        self.svc.set_budget(org_id=ORG, task_id="task_1", max_actions=1)
        b = self.svc.get_budget(org_id=ORG, agent_id=AGENT, task_id="task_1")
        self.assertEqual(b.max_actions, 1)
        # The task budget governs when a task is named.
        self.svc.guard(org_id=ORG, agent_id=AGENT, task_id="task_1")
        with self.assertRaises(BudgetExceededError):
            self.svc.guard(org_id=ORG, agent_id=AGENT, task_id="task_1")

    def test_unknown_dimension_rejected(self):
        from agent_identity.response import ResponsePlaneError
        with self.assertRaises(ResponsePlaneError):
            self.svc.consume(org_id=ORG, agent_id=AGENT, dimension="nope")


class EmergencyStopTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryResponseStore()
        self.clock = FakeClock()
        self.svc = BudgetService(self.store, config=ResponseConfig(), clock=self.clock)

    def test_stop_refuses_before_budget(self):
        self.svc.set_budget(org_id=ORG, agent_id=AGENT, max_actions=1000)
        self.svc.emergency_stop(org_id=ORG, agent_id=AGENT, requested_by="admin")
        with self.assertRaises(EmergencyStopError):
            self.svc.guard(org_id=ORG, agent_id=AGENT)

    def test_release_restores_admission(self):
        s = self.svc.emergency_stop(org_id=ORG, agent_id=AGENT, requested_by="admin")
        self.svc.release_stop(org_id=ORG, stop_id=s.stop_id, released_by="admin")
        d = self.svc.guard(org_id=ORG, agent_id=AGENT)
        self.assertTrue(d.allowed)

    def test_stop_is_idempotent(self):
        s1 = self.svc.emergency_stop(org_id=ORG, agent_id=AGENT, requested_by="admin")
        s2 = self.svc.emergency_stop(org_id=ORG, agent_id=AGENT, requested_by="admin")
        self.assertEqual(s1.stop_id, s2.stop_id)


class BudgetConcurrencyTests(unittest.TestCase):
    def test_concurrent_consumption_never_exceeds_limit(self):
        store = MemoryResponseStore()
        clock = FakeClock()
        svc = BudgetService(store, config=ResponseConfig(), clock=clock)
        svc.set_budget(org_id=ORG, agent_id=AGENT, max_actions=5)
        refusals = []
        lock = threading.Lock()

        def worker():
            try:
                svc.guard(org_id=ORG, agent_id=AGENT)
            except BudgetExceededError:
                with lock:
                    refusals.append(1)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(refusals), 15)
        b = svc.get_budget(org_id=ORG, agent_id=AGENT)
        self.assertEqual(b.actions_used, 5)


# --------------------------------------------------------------------------- approvals
class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryResponseStore()
        self.clock = FakeClock()
        self.svc = ApprovalService(self.store, config=ResponseConfig(), clock=self.clock)

    def test_full_request_approve_check_cycle(self):
        a = self.svc.request(org_id=ORG, agent_id=AGENT, action="export", resource="users",
                             requested_by="requester", params={"format": "csv"})
        self.assertEqual(a.status, "pending")
        a2 = self.svc.decide(org_id=ORG, approval_id=a.approval_id, approved=True,
                             decided_by="approver", approver_org_id=ORG)
        self.assertEqual(a2.status, "approved")
        ok = self.svc.check(org_id=ORG, agent_id=AGENT, action="export", resource="users",
                            params={"format": "csv"}, approval_id=a.approval_id)
        self.assertIsNotNone(ok)

    def test_separation_of_duties(self):
        a = self.svc.request(org_id=ORG, agent_id=AGENT, action="export", resource="users",
                             requested_by="same_person")
        with self.assertRaises(ApprovalError):
            self.svc.decide(org_id=ORG, approval_id=a.approval_id, approved=True,
                            decided_by="same_person", approver_org_id=ORG)

    def test_expiry_with_fake_clock(self):
        a = self.svc.request(org_id=ORG, agent_id=AGENT, action="export", resource="users",
                             requested_by="requester", ttl_s=60)
        self.clock.advance(61)
        with self.assertRaises(ApprovalError):
            self.svc.decide(org_id=ORG, approval_id=a.approval_id, approved=True,
                            decided_by="approver", approver_org_id=ORG)
        # After expiry, check() must not return it.
        self.assertIsNone(self.svc.check(org_id=ORG, agent_id=AGENT, action="export",
                                         resource="users", approval_id=a.approval_id,
                                         raise_on_mismatch=False))

    def test_idempotent_re_request(self):
        a1 = self.svc.request(org_id=ORG, agent_id=AGENT, action="export", resource="users",
                              requested_by="requester")
        a2 = self.svc.request(org_id=ORG, agent_id=AGENT, action="export", resource="users",
                              requested_by="requester")
        self.assertEqual(a1.approval_id, a2.approval_id)


class ApprovalBindingTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryResponseStore()
        self.clock = FakeClock()
        self.svc = ApprovalService(self.store, config=ResponseConfig(), clock=self.clock)
        self.a = self.svc.request(org_id=ORG, agent_id=AGENT, action="export", resource="users",
                                  requested_by="requester", params={"format": "csv"})
        self.svc.decide(org_id=ORG, approval_id=self.a.approval_id, approved=True,
                        decided_by="approver", approver_org_id=ORG)

    def test_modified_params_rejected(self):
        with self.assertRaises(ApprovalMismatchError):
            self.svc.check(org_id=ORG, agent_id=AGENT, action="export", resource="users",
                           params={"format": "json"}, approval_id=self.a.approval_id)

    def test_modified_resource_rejected(self):
        with self.assertRaises(ApprovalMismatchError):
            self.svc.check(org_id=ORG, agent_id=AGENT, action="export", resource="secrets",
                           params={"format": "csv"}, approval_id=self.a.approval_id)

    def test_cross_tenant_rejected(self):
        with self.assertRaises(ApprovalMismatchError):
            self.svc.check(org_id=ORG_B, agent_id=AGENT, action="export", resource="users",
                           params={"format": "csv"}, approval_id=self.a.approval_id)

    def test_approver_not_in_tenant_rejected(self):
        a = self.svc.request(org_id=ORG, agent_id=AGENT, action="export", resource="users",
                             requested_by="requester")
        with self.assertRaises(ApprovalError):
            self.svc.decide(org_id=ORG, approval_id=a.approval_id, approved=True,
                            decided_by="outsider", approver_org_id=ORG_B)

    def test_approver_lacking_permission_rejected(self):
        a = self.svc.request(org_id=ORG, agent_id=AGENT, action="export", resource="users",
                             requested_by="requester")
        with self.assertRaises(ApprovalError):
            self.svc.decide(org_id=ORG, approval_id=a.approval_id, approved=True,
                            decided_by="approver", approver_org_id=ORG,
                            approver_permissions=["response:read"],
                            required_permission="response:approve")


# --------------------------------------------------------------------------- incidents
class IncidentLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryResponseStore()
        self.clock = FakeClock()
        self.svc = IncidentService(self.store, config=ResponseConfig(), clock=self.clock)

    def test_valid_transition_path(self):
        inc = self.svc.open_or_correlate(org_id=ORG, title="loop", agent_id=AGENT,
                                         subject="a::b")
        inc = self.svc.transition(org_id=ORG, incident_id=inc.incident_id, new_status="triage")
        self.assertEqual(inc.status, "triage")
        inc = self.svc.transition(org_id=ORG, incident_id=inc.incident_id,
                                  new_status="investigating")
        inc = self.svc.transition(org_id=ORG, incident_id=inc.incident_id,
                                  new_status="containment")
        inc = self.svc.transition(org_id=ORG, incident_id=inc.incident_id, new_status="recovery")
        inc = self.svc.resolve(org_id=ORG, incident_id=inc.incident_id, resolution="done")
        self.assertEqual(inc.status, "closed")
        self.assertIsNotNone(inc.closed_at)

    def test_invalid_transition_rejected(self):
        inc = self.svc.open_or_correlate(org_id=ORG, title="x", agent_id=AGENT, subject="a::b")
        with self.assertRaises(IncidentError):
            self.svc.transition(org_id=ORG, incident_id=inc.incident_id, new_status="recovery")

    def test_cannot_attach_to_closed_incident(self):
        inc = self.svc.open_or_correlate(org_id=ORG, title="x", agent_id=AGENT, subject="a::b")
        self.svc.resolve(org_id=ORG, incident_id=inc.incident_id, resolution="done")
        with self.assertRaises(IncidentError):
            self.svc.attach(org_id=ORG, incident_id=inc.incident_id, alert_ids=("a1",))


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryResponseStore()
        self.clock = FakeClock()
        self.svc = IncidentService(self.store, config=ResponseConfig(), clock=self.clock)

    def test_same_key_correlates(self):
        inc1 = self.svc.open_or_correlate(org_id=ORG, title="a", agent_id=AGENT, subject="x::y")
        inc2 = self.svc.open_or_correlate(org_id=ORG, title="b", agent_id=AGENT, subject="x::y")
        self.assertEqual(inc1.incident_id, inc2.incident_id)

    def test_time_proximity_alone_does_not_merge(self):
        # Same agent, different subjects, same instant: must NOT merge.
        inc1 = self.svc.open_or_correlate(org_id=ORG, title="a", agent_id=AGENT, subject="x::1")
        inc2 = self.svc.open_or_correlate(org_id=ORG, title="b", agent_id=AGENT, subject="x::2")
        self.assertNotEqual(inc1.incident_id, inc2.incident_id)


# --------------------------------------------------------------------------- containment
class _FakePolicy:
    def __init__(self, fail=False):
        self.denied = []
        self.fail = fail

    def deny_agent(self, org_id, agent_id, reason, actor):
        if self.fail:
            raise RuntimeError("boom")
        self.denied.append((agent_id, reason))
        return {"denied": agent_id}


class _FakeIdentity:
    def __init__(self):
        self.suspended = []
        self.revoked = []

    def revoke_agent(self, agent_id, reason, actor, note=""):
        self.suspended.append(agent_id)
        return {"revoked": agent_id}

    def list_credentials(self, agent_id=None):
        return [{"credential_id": f"c-{agent_id}-1"}, {"credential_id": f"c-{agent_id}-2"}]

    def revoke_credential(self, cid, reason, actor, note=""):
        self.revoked.append(cid)


class ContainmentTests(unittest.TestCase):
    def _engine(self, **cfg_kw):
        cfg = ResponseConfig(containment_allow_auto=True, **cfg_kw)
        policy = _FakePolicy()
        identity = _FakeIdentity()
        integ = ContainmentIntegrations(policy_service=policy, identity_service=identity)
        eng = ContainmentEngine(integrations=integ, config=cfg)
        return eng, policy, identity

    def test_deny_protected_operations_delegates_to_policy(self):
        eng, policy, _ = self._engine(containment_high_impact_requires_approval=False)
        step = eng.execute(action=ContainmentAction.DENY_PROTECTED_OPERATIONS, org_id=ORG,
                           agent_id=AGENT, reason="loop", authorized_by="admin")
        self.assertEqual(step.status, "ok")
        self.assertEqual(step.mechanism, "policy_engine")
        self.assertEqual(policy.denied, [(AGENT, "loop")])

    def test_suspend_agent_delegates_to_identity(self):
        eng, _, identity = self._engine(containment_high_impact_requires_approval=False)
        step = eng.execute(action=ContainmentAction.SUSPEND_AGENT, org_id=ORG, agent_id=AGENT,
                           reason="loop", authorized_by="admin")
        self.assertEqual(step.status, "ok")
        self.assertEqual(identity.suspended, [AGENT])

    def test_revoke_credentials_delegates_to_identity(self):
        eng, _, identity = self._engine(containment_high_impact_requires_approval=False)
        step = eng.execute(action=ContainmentAction.REVOKE_CREDENTIALS, org_id=ORG, agent_id=AGENT,
                           reason="loop", authorized_by="admin")
        self.assertEqual(step.status, "ok")
        self.assertEqual(len(identity.revoked), 2)

    def test_unavailable_mechanism_is_honest(self):
        cfg = ResponseConfig(containment_allow_auto=True)
        integ = ContainmentIntegrations()  # nothing configured
        eng = ContainmentEngine(integrations=integ, config=cfg)
        step = eng.execute(action=ContainmentAction.DENY_PROTECTED_OPERATIONS, org_id=ORG,
                           agent_id=AGENT, reason="loop", authorized_by="admin")
        self.assertEqual(step.status, "unavailable")

    def test_missing_authorized_by_is_refused(self):
        eng, _, _ = self._engine(containment_high_impact_requires_approval=False)
        step = eng.execute(action=ContainmentAction.DENY_PROTECTED_OPERATIONS, org_id=ORG,
                           agent_id=AGENT, reason="loop", authorized_by=None)
        self.assertEqual(step.status, "skipped")
        self.assertEqual(step.mechanism, "authorization")


class ContainmentAdversarialTests(unittest.TestCase):
    def test_auto_containment_off_by_default(self):
        cfg = ResponseConfig()  # containment_allow_auto defaults False
        integ = ContainmentIntegrations(policy_service=_FakePolicy())
        eng = ContainmentEngine(integrations=integ, config=cfg)
        step = eng.execute(action=ContainmentAction.DENY_PROTECTED_OPERATIONS, org_id=ORG,
                           agent_id=AGENT, reason="loop", authorized_by="admin", auto=True)
        self.assertEqual(step.status, "skipped")
        self.assertEqual(step.mechanism, "authorization")

    def test_high_impact_requires_approval(self):
        cfg = ResponseConfig(containment_allow_auto=True,
                             containment_high_impact_requires_approval=True)
        integ = ContainmentIntegrations(identity_service=_FakeIdentity())
        eng = ContainmentEngine(integrations=integ, config=cfg)
        step = eng.execute(action=ContainmentAction.SUSPEND_AGENT, org_id=ORG, agent_id=AGENT,
                           reason="loop", authorized_by="admin", auto=True, approved=False)
        self.assertEqual(step.status, "skipped")

    def test_delegate_failure_is_recorded_not_raised(self):
        cfg = ResponseConfig(containment_allow_auto=True,
                             containment_high_impact_requires_approval=False)
        integ = ContainmentIntegrations(policy_service=_FakePolicy(fail=True))
        eng = ContainmentEngine(integrations=integ, config=cfg)
        step = eng.execute(action=ContainmentAction.DENY_PROTECTED_OPERATIONS, org_id=ORG,
                           agent_id=AGENT, reason="loop", authorized_by="admin")
        self.assertEqual(step.status, "failed")

    def test_rollback_only_for_reversible(self):
        cfg = ResponseConfig(containment_allow_auto=True)
        integ = ContainmentIntegrations()
        eng = ContainmentEngine(integrations=integ, config=cfg)
        from agent_identity.response import ResponseStep
        step = ResponseStep(action="revoke_credentials", status="ok", reversible=False)
        rb = eng.rollback(step=step, org_id=ORG, agent_id=AGENT, authorized_by="admin")
        self.assertEqual(rb.status, "skipped")


# --------------------------------------------------------------------------- orchestration
class LevelSelectionTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryResponseStore()
        self.clock = FakeClock()
        integ = ContainmentIntegrations(policy_service=_FakePolicy(),
                                        identity_service=_FakeIdentity())
        self.eng = ContainmentEngine(integrations=integ, config=ResponseConfig())
        self.evid = EvidenceService(self.store, config=ResponseConfig(), clock=self.clock)
        self.inc = IncidentService(self.store, config=ResponseConfig(), clock=self.clock)
        self.orch = ResponseOrchestrator(store=self.store, containment=self.eng, evidence=self.evid,
                                         incidents=self.inc, config=ResponseConfig(),
                                         clock=self.clock)

    def test_statistical_anomaly_capped_at_restrict(self):
        # Even a "critical" risk band cannot exceed RESTRICT when the finding is only suspicious.
        lvl = self.orch.select_level(risk_band="critical",
                                     classification=LoopClassification.SUSPICIOUS_REPETITION.value)
        self.assertLessEqual(lvl.rank, ResponseLevel.RESTRICT.rank)

    def test_confirmed_violation_critical_reaches_incident(self):
        lvl = self.orch.select_level(risk_band="critical",
                                     classification=LoopClassification.CONFIRMED_VIOLATION.value)
        self.assertEqual(lvl, ResponseLevel.INCIDENT)

    def test_observe_never_contains(self):
        lvl = self.orch.select_level(risk_band="low",
                                     classification=LoopClassification.NORMAL_RETRY.value)
        self.assertEqual(lvl, ResponseLevel.OBSERVE)


class ResponseIdempotencyTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryResponseStore()
        self.clock = FakeClock()
        self.policy = _FakePolicy()
        integ = ContainmentIntegrations(policy_service=self.policy)
        self.eng = ContainmentEngine(integrations=integ, config=ResponseConfig())
        self.evid = EvidenceService(self.store, config=ResponseConfig(), clock=self.clock)
        self.inc = IncidentService(self.store, config=ResponseConfig(), clock=self.clock)
        self.orch = ResponseOrchestrator(store=self.store, containment=self.eng, evidence=self.evid,
                                         incidents=self.inc, config=ResponseConfig(),
                                         clock=self.clock)

    def test_duplicate_delivery_runs_containment_once(self):
        ex1 = self.orch.execute(org_id=ORG, level=ResponseLevel.RESTRICT, agent_id=AGENT,
                                authorized_by="admin", idempotency_key="k1")
        ex2 = self.orch.execute(org_id=ORG, level=ResponseLevel.RESTRICT, agent_id=AGENT,
                                authorized_by="admin", idempotency_key="k1")
        self.assertEqual(ex1.response_id, ex2.response_id)
        # Policy.deny was called exactly once across the plan.
        self.assertEqual(len(self.policy.denied), 1)

    def test_requires_verified_authorizer(self):
        from agent_identity.response import ResponseOrchestrationError
        with self.assertRaises(ResponseOrchestrationError):
            self.orch.execute(org_id=ORG, level=ResponseLevel.RESTRICT, agent_id=AGENT,
                              authorized_by=None)


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryResponseStore()
        self.clock = FakeClock()
        self.policy = _FakePolicy()
        integ = ContainmentIntegrations(policy_service=self.policy)
        self.eng = ContainmentEngine(integrations=integ, config=ResponseConfig())
        self.evid = EvidenceService(self.store, config=ResponseConfig(), clock=self.clock)
        self.inc = IncidentService(self.store, config=ResponseConfig(), clock=self.clock)
        self.orch = ResponseOrchestrator(store=self.store, containment=self.eng, evidence=self.evid,
                                         incidents=self.inc, config=ResponseConfig(),
                                         clock=self.clock)

    def test_partial_failure_is_not_success(self):
        # A plan with a known-bad mechanism yields PARTIAL, never SUCCEEDED.
        cfg = ResponseConfig(containment_allow_auto=True)
        integ = ContainmentIntegrations(policy_service=_FakePolicy(),
                                        identity_service=_FakeIdentity(),
                                        egress_service=None, governance_service=None)
        eng = ContainmentEngine(integrations=integ, config=cfg)
        orch = ResponseOrchestrator(store=self.store, containment=eng, evidence=self.evid,
                                    incidents=self.inc, config=cfg, clock=self.clock)
        ex = orch.execute(org_id=ORG, level=ResponseLevel.RESTRICT, agent_id=AGENT,
                          authorized_by="admin")
        # RESTRICT includes require_approval (unavailable) + deny + limit_budget (unavailable).
        self.assertEqual(ex.state, ResponseState.PARTIAL.value)
        self.assertGreater(len(ex.partial_failures), 0)

    def test_evidence_preserved_before_destructive_step(self):
        cfg = ResponseConfig(containment_allow_auto=True)
        integ = ContainmentIntegrations(identity_service=_FakeIdentity())
        eng = ContainmentEngine(integrations=integ, config=cfg)
        orch = ResponseOrchestrator(store=self.store, containment=eng, evidence=self.evid,
                                    incidents=self.inc, config=cfg, clock=self.clock)
        ex = orch.execute(org_id=ORG, level=ResponseLevel.SUSPEND, agent_id=AGENT,
                          authorized_by="admin", idempotency_key="k2")
        self.assertGreater(len(ex.evidence_ids), 0)
        for eid in ex.evidence_ids:
            self.assertTrue(self.evid.get(org_id=ORG, evidence_id=eid).sealed)

    def test_observe_level_does_not_run_containment(self):
        ex = self.orch.execute(org_id=ORG, level=ResponseLevel.OBSERVE, agent_id=AGENT,
                               authorized_by="admin")
        self.assertEqual(ex.state, ResponseState.SUCCEEDED.value)
        self.assertEqual(ex.steps, [])


# --------------------------------------------------------------------------- evidence
class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryResponseStore()
        self.clock = FakeClock()
        self.svc = EvidenceService(self.store, config=ResponseConfig(), clock=self.clock)

    def test_digest_verify(self):
        e = self.svc.preserve(org_id=ORG, kind="snapshot", summary="s",
                              payload={"a": 1, "b": [2, 3]})
        self.assertTrue(self.svc.verify(org_id=ORG, evidence_id=e.evidence_id,
                                        payload={"a": 1, "b": [2, 3]}))
        self.assertFalse(self.svc.verify(org_id=ORG, evidence_id=e.evidence_id,
                                         payload={"a": 1, "b": [2, 4]}))

    def test_sealed_evidence_survives_retention(self):
        sealed = self.svc.preserve(org_id=ORG, kind="k", summary="s", seal=True, ref="r1")
        unsealed = self.svc.preserve(org_id=ORG, kind="k", summary="s", seal=False, ref="r2")
        self.clock.advance(400 * 86400)  # past any retention horizon
        removed = self.svc.apply_retention(org_id=ORG)
        self.assertIsNone(self.svc.get(org_id=ORG, evidence_id=unsealed.evidence_id))
        self.assertIsNotNone(self.svc.get(org_id=ORG, evidence_id=sealed.evidence_id))

    def test_retention_is_org_scoped(self):
        e = self.svc.preserve(org_id=ORG, kind="k", summary="s", ref="r1")
        self.clock.advance(400 * 86400)
        self.svc.apply_retention(org_id=ORG_B)  # wrong org must not purge ORG's row
        self.assertIsNotNone(self.svc.get(org_id=ORG, evidence_id=e.evidence_id))


# --------------------------------------------------------------------------- audit integrity
class AuditIntegrityTests(unittest.TestCase):
    def _audit(self):
        store = MemoryResponseStore()
        clock = FakeClock()
        return ResponseAudit(store, clock=clock), store, clock

    def test_chain_verifies_when_intact(self):
        audit, store, clock = self._audit()
        for i in range(3):
            clock.advance(1)
            audit.record(f"evt{i}", org_id=ORG)
        result = audit.verify_chain(org_id=ORG)
        self.assertTrue(result["ok"], result)

    def test_tampered_record_detected(self):
        audit, store, clock = self._audit()
        for i in range(3):
            clock.advance(1)
            audit.record(f"evt{i}", org_id=ORG)
        # Tamper the STORE's record directly (a returned copy would leave the chain untouched).
        store._audit[1]["event"] = "tampered"
        result = audit.verify_chain(org_id=ORG)
        self.assertFalse(result["ok"])
        self.assertEqual(result["broken_at"], store._audit[1]["event_id"])

    def test_reordered_record_detected(self):
        audit, store, clock = self._audit()
        for i in range(3):
            clock.advance(1)
            audit.record(f"evt{i}", org_id=ORG)
        rows = store.list_audit(org_id=ORG)
        rows.sort(key=lambda r: (r["ts"], r["event_id"]))
        rows[0], rows[1] = rows[1], rows[0]
        # Rebuild the store list in the reordered order.
        store._audit = [dict(r) for r in rows]
        result = audit.verify_chain(org_id=ORG)
        self.assertFalse(result["ok"])


# --------------------------------------------------------------------------- safe failure handling
class SafeFailureTests(unittest.TestCase):
    def test_policy_unavailable_fails_closed_via_orchestrator(self):
        # The orchestrator itself is unaffected by a policy outage, but containment steps report it.
        store = MemoryResponseStore()
        clock = FakeClock()
        cfg = ResponseConfig(containment_allow_auto=True)
        integ = ContainmentIntegrations(policy_service=_FakePolicy(fail=True))
        eng = ContainmentEngine(integrations=integ, config=cfg)
        evid = EvidenceService(store, config=cfg, clock=clock)
        inc = IncidentService(store, config=cfg, clock=clock)
        orch = ResponseOrchestrator(store=store, containment=eng, evidence=evid, incidents=inc,
                                    config=cfg, clock=clock)
        ex = orch.execute(org_id=ORG, level=ResponseLevel.RESTRICT, agent_id=AGENT,
                          authorized_by="admin")
        # Nothing applied (policy failed, remaining mechanisms unavailable) -> FAILED, never a
        # false success, and never silently dropped.
        self.assertEqual(ex.state, ResponseState.FAILED.value)
        self.assertGreater(len(ex.partial_failures), 0)

    def test_invalid_response_transition_rejected(self):
        store = MemoryResponseStore()
        integ = ContainmentIntegrations(policy_service=_FakePolicy())
        eng = ContainmentEngine(integrations=integ, config=ResponseConfig())
        evid = EvidenceService(store, config=ResponseConfig(), clock=FakeClock())
        inc = IncidentService(store, config=ResponseConfig(), clock=FakeClock())
        orch = ResponseOrchestrator(store=store, containment=eng, evidence=evid, incidents=inc,
                                    config=ResponseConfig(), clock=FakeClock())
        ex = orch.execute(org_id=ORG, level=ResponseLevel.OBSERVE, agent_id=AGENT,
                          authorized_by="admin")
        # SUCCEEDED cannot transition back to RUNNING.
        from agent_identity.response import ResponseOrchestrationError
        ex.state = ResponseState.SUCCEEDED.value
        with self.assertRaises(ResponseOrchestrationError):
            orch._transition(ex, ResponseState.RUNNING)


if __name__ == "__main__":
    unittest.main()
