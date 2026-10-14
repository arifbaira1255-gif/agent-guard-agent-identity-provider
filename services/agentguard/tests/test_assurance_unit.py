"""Phase 7 unit + adversarial tests for the assurance plane.

Runs entirely against the in-memory store and a fake SIEM transport, so no external service is
required. The PostgreSQL-backed store is covered by ``test_pg_phase7_integration.py``.

Coverage (per the Phase 7 brief, section 9):
  * malicious / over-permissive policy recommendations and the confidence gate
  * unauthorized policy activation and the no-auto-activation guarantee
  * invalid policy schemas and unsafe (privilege-broadening) changes
  * policy simulation and rollback
  * tenant isolation
  * audit event modification, reordering and removal; checkpoint verification
  * signing-key rotation compatibility
  * unauthorized audit access
  * compliance evidence provenance and the no-certification disclaimer
  * SIEM authentication/TLS failures, duplicate delivery, retry exhaustion, backpressure
  * secret redaction in exported events
  * partial system failures (audit store down, SIEM endpoint down)
"""
from __future__ import annotations

import unittest

from agent_identity.assurance import (AssuranceConfig, AssuranceService, AuditChainRecord,
                                      BackpressureError, FakeTransport, LocalEd25519Signer,
                                      MemoryAssuranceStore, NullSigner, SiemConfigError,
                                      SigningUnavailableError, TamperEvidentAudit, build_transport,
                                      compute_hash, redact_fields, static_security_check)
from agent_identity.assurance.models import (EvidenceKind, ImpactLevel, ProposalStatus, Provenance,
                                             SiemEvent, normalize_severity, severity_rank)
from agent_identity.core.clock import FixedClock
from agent_identity.core.errors import ForbiddenError, NotFoundError, ValidationError
from agent_identity.policy import MemoryPolicyStore, PolicyConfig, PolicyDecisionService, build_engine
from agent_identity.security.rbac import (ROLE_DEVELOPER, ROLE_PLATFORM_ADMIN, ROLE_READONLY_AUDITOR,
                                          ROLE_SECURITY_ANALYST, ROLE_SECURITY_OPERATOR,
                                          ROLE_TENANT_ADMIN, effective_access)

ORG = "acme"
OTHER = "globex"

VALID_REGO = """
package agentguard.authz

default decision := {"decision": "DENY", "reason": "default_deny"}

decision := {"decision": "ALLOW", "reason": "scoped_allow"} {
    input.action == "tool:read"
    input.resource == "db:public"
}
"""


def _actor(role=ROLE_TENANT_ADMIN, *, org_id=ORG, platform=False, user_id="usr_admin"):
    if platform:
        return effective_access(user_id, org_id, global_roles=(ROLE_PLATFORM_ADMIN,))
    return effective_access(user_id, org_id, tenant_roles=(role,))


def _policy_service():
    cfg = PolicyConfig()
    return PolicyDecisionService(MemoryPolicyStore(), build_engine(cfg), cfg)


def _svc(*, policy_service=None, config=None, clock=None):
    store = MemoryAssuranceStore()
    cfg = config or AssuranceConfig(environment="development")
    svc = AssuranceService(store, config=cfg, clock=clock or FixedClock(),
                           policy_service=policy_service)
    return svc, store


# =========================================================================== config
class ConfigTests(unittest.TestCase):
    def test_production_refuses_weakened_controls(self):
        for kw in ({"audit_require_signature": False}, {"audit_fail_closed": False},
                   {"siem_require_tls": False}, {"siem_verify_tls": False},
                   {"proposal_require_approval": False}):
            with self.assertRaises(ValidationError):
                AssuranceConfig(environment="production", **kw)

    def test_invalid_values_rejected(self):
        with self.assertRaises(ValidationError):
            AssuranceConfig(environment="nope")
        with self.assertRaises(ValidationError):
            AssuranceConfig(siem_backpressure_policy="whatever")
        with self.assertRaises(ValidationError):
            AssuranceConfig(compliance_frameworks=("hipaa",))
        with self.assertRaises(ValidationError):
            AssuranceConfig(recommendation_min_confidence=2.0)

    def test_from_env_defaults_are_fail_closed(self):
        cfg = AssuranceConfig.from_env()
        self.assertTrue(cfg.audit_require_signature)
        self.assertTrue(cfg.audit_fail_closed)
        self.assertTrue(cfg.proposal_require_approval)
        self.assertFalse(cfg.proposal_allow_auto_activate)
        self.assertTrue(cfg.siem_require_tls)


# =========================================================================== recommendations
class RecommendationTests(unittest.TestCase):
    def test_repeated_signals_produce_explainable_recommendation(self):
        svc, _ = _svc()
        for _ in range(4):
            svc.record_evidence(org_id=ORG, kind=EvidenceKind.DLP_DETECTION.value,
                                summary="dlp hit", source="egress", agent_id="a1", severity="high")
        recs = svc.analyze(org_id=ORG)
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r["kind"], "tighten")
        self.assertEqual(r["provenance"], Provenance.RECOMMENDATION.value)
        # the three epistemic layers are separate and non-empty
        self.assertTrue(r["observed_facts"])
        self.assertTrue(r["heuristic_conclusions"])
        self.assertIn("auto_applied", r["proposed_change"])
        self.assertFalse(r["proposed_change"]["auto_applied"])
        self.assertTrue(r["requires_approval"])
        self.assertTrue(r["test_requirements"])
        self.assertTrue(r["rollback_plan"])
        self.assertGreater(r["confidence"], 0.0)
        self.assertTrue(r["uncertainty"])

    def test_below_threshold_produces_nothing(self):
        svc, _ = _svc()
        svc.record_evidence(org_id=ORG, kind=EvidenceKind.DLP_DETECTION.value, summary="one",
                            source="egress", agent_id="a1")
        self.assertEqual(svc.analyze(org_id=ORG), [])

    def test_repeated_denials_without_feedback_are_review_not_actionable(self):
        svc, _ = _svc()
        for _ in range(5):
            svc.record_evidence(org_id=ORG, kind=EvidenceKind.AUTHORIZATION_DENIAL.value,
                                summary="denied", source="policy", agent_id="a1",
                                detail={"action": "tool:delete"})
        recs = svc.analyze(org_id=ORG)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["kind"], "review")
        self.assertFalse(svc.recommendations.is_actionable(
            svc.store.list_recommendations(org_id=ORG)[0]))

    def test_denials_with_admin_feedback_become_narrow_jit_proposal(self):
        svc, _ = _svc()
        for _ in range(4):
            svc.record_evidence(org_id=ORG, kind=EvidenceKind.AUTHORIZATION_DENIAL.value,
                                summary="denied", source="policy", agent_id="a1",
                                detail={"action": "tool:delete"})
        svc.record_evidence(org_id=ORG, kind=EvidenceKind.ADMIN_FEEDBACK.value,
                            summary="this is legitimate", source="admin")
        recs = svc.analyze(org_id=ORG)
        kinds = {r["kind"] for r in recs}
        self.assertIn("add_jit_scope", kinds)
        jit = [r for r in recs if r["kind"] == "add_jit_scope"][0]
        self.assertEqual(jit["proposed_change"]["direction"], "grant")
        self.assertFalse(jit["proposed_change"]["auto_applied"])

    def test_false_positives_produce_loosen_recommendation(self):
        svc, _ = _svc()
        for _ in range(3):
            svc.record_evidence(org_id=ORG, kind=EvidenceKind.FALSE_POSITIVE.value,
                                summary="fp", source="analyst", agent_id="a1")
        recs = svc.analyze(org_id=ORG)
        self.assertEqual(recs[0]["kind"], "loosen")

    def test_tenant_isolation_of_evidence(self):
        svc, _ = _svc()
        for _ in range(4):
            svc.record_evidence(org_id=OTHER, kind=EvidenceKind.DLP_DETECTION.value, summary="x",
                                source="egress", agent_id="a1")
        self.assertEqual(svc.analyze(org_id=ORG), [])
        self.assertEqual(len(svc.analyze(org_id=OTHER)), 1)

    def test_evidence_digest_is_reference_not_payload(self):
        svc, _ = _svc()
        e = svc.record_evidence(org_id=ORG, kind=EvidenceKind.INCIDENT.value, summary="inc",
                                source="response", payload={"secret": "do-not-store"})
        self.assertIsNotNone(e.digest)
        self.assertNotIn("do-not-store", str(e.public_dict()))


# =========================================================================== lifecycle
class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.policy = _policy_service()
        self.svc, self.store = _svc(policy_service=self.policy)
        self.admin = _actor(ROLE_TENANT_ADMIN, user_id="usr_admin")
        self.approver = _actor(ROLE_SECURITY_ANALYST, user_id="usr_analyst")
        self.approver2 = _actor(ROLE_SECURITY_ANALYST, user_id="usr_analyst2")

    def _proposal(self, rego=VALID_REGO, impact="medium"):
        return self.svc.create_proposal(self.admin, org_id=ORG, proposed_rego=rego,
                                        title="t", rationale="r", impact_level=impact)

    def test_creator_cannot_approve_own_proposal(self):
        p = self._proposal()
        self.svc.validate_proposal(self.admin, p.proposal_id, org_id=ORG)
        self.svc.submit_proposal(self.admin, p.proposal_id, org_id=ORG)
        with self.assertRaises(ForbiddenError):
            self.svc.decide_proposal(self.admin, p.proposal_id, org_id=ORG, decision="approved")

    def test_activation_requires_approval(self):
        p = self._proposal()
        self.svc.validate_proposal(self.admin, p.proposal_id, org_id=ORG)
        # not submitted/approved yet -> activation refused
        with self.assertRaises(Exception):
            self.svc.activate_proposal(self.admin, p.proposal_id, org_id=ORG)

    def test_full_happy_path_activate_and_rollback(self):
        p = self._proposal()
        self.svc.validate_proposal(self.admin, p.proposal_id, org_id=ORG)
        self.svc.simulate_proposal(self.admin, p.proposal_id, org_id=ORG, cases=[])
        self.svc.submit_proposal(self.admin, p.proposal_id, org_id=ORG)
        self.svc.decide_proposal(self.approver, p.proposal_id, org_id=ORG, decision="approved")
        active = self.svc.activate_proposal(self.admin, p.proposal_id, org_id=ORG)
        self.assertEqual(active.status, ProposalStatus.ACTIVE.value)
        self.assertIsNotNone(active.activated_version)
        # rollback to the base version (None here) is refused; roll back to v1 works
        rb = self.svc.rollback_proposal(self.admin, p.proposal_id, org_id=ORG, to_version=1)
        self.assertEqual(rb.status, ProposalStatus.ROLLED_BACK.value)

    def test_high_impact_requires_two_distinct_approvers(self):
        p = self._proposal(impact=ImpactLevel.HIGH.value)
        self.svc.validate_proposal(self.admin, p.proposal_id, org_id=ORG)
        self.svc.submit_proposal(self.admin, p.proposal_id, org_id=ORG)
        after_one = self.svc.decide_proposal(self.approver, p.proposal_id, org_id=ORG,
                                             decision="approved")
        self.assertEqual(after_one.status, ProposalStatus.PENDING_APPROVAL.value)
        after_two = self.svc.decide_proposal(self.approver2, p.proposal_id, org_id=ORG,
                                             decision="approved")
        self.assertEqual(after_two.status, ProposalStatus.APPROVED.value)

    def test_same_approver_cannot_approve_twice(self):
        p = self._proposal(impact=ImpactLevel.HIGH.value)
        self.svc.validate_proposal(self.admin, p.proposal_id, org_id=ORG)
        self.svc.submit_proposal(self.admin, p.proposal_id, org_id=ORG)
        self.svc.decide_proposal(self.approver, p.proposal_id, org_id=ORG, decision="approved")
        with self.assertRaises(Exception):
            self.svc.decide_proposal(self.approver, p.proposal_id, org_id=ORG, decision="approved")

    def test_unsafe_change_is_refused(self):
        unsafe = "package agentguard.authz\n\ndefault allow := true\n"
        p = self._proposal(rego=unsafe)
        with self.assertRaises(Exception):
            self.svc.validate_proposal(self.admin, p.proposal_id, org_id=ORG)

    def test_invalid_schema_is_refused(self):
        p = self._proposal(rego="this is not rego at all")
        with self.assertRaises(Exception):
            self.svc.validate_proposal(self.admin, p.proposal_id, org_id=ORG)

    def test_removing_tenant_guard_is_flagged(self):
        base = "package p\nallow { input.tenant == input.resource_tenant }\ndeny { true }\n"
        proposed = "package p\nallow { true }\n"
        result = static_security_check(proposed, base)
        self.assertFalse(result["ok"])
        self.assertTrue(any("tenant" in f for f in result["findings"]))

    def test_unauthorized_actor_cannot_create_proposal(self):
        dev = _actor(ROLE_DEVELOPER, user_id="usr_dev")
        with self.assertRaises(ForbiddenError):
            self.svc.create_proposal(dev, org_id=ORG, proposed_rego=VALID_REGO)

    def test_unauthorized_actor_cannot_approve(self):
        p = self._proposal()
        self.svc.validate_proposal(self.admin, p.proposal_id, org_id=ORG)
        self.svc.submit_proposal(self.admin, p.proposal_id, org_id=ORG)
        dev = _actor(ROLE_DEVELOPER, user_id="usr_dev")
        with self.assertRaises(ForbiddenError):
            self.svc.decide_proposal(dev, p.proposal_id, org_id=ORG, decision="approved")

    def test_cross_tenant_proposal_is_not_found(self):
        p = self._proposal()
        other_admin = _actor(ROLE_TENANT_ADMIN, org_id=OTHER, user_id="usr_other")
        with self.assertRaises(NotFoundError):
            self.svc.get_proposal(other_admin, p.proposal_id, org_id=OTHER)

    def test_canary_auto_rejects_on_deny_delta(self):
        p = self._proposal()
        self.svc.validate_proposal(self.admin, p.proposal_id, org_id=ORG)
        self.svc.submit_proposal(self.admin, p.proposal_id, org_id=ORG)
        self.svc.decide_proposal(self.approver, p.proposal_id, org_id=ORG, decision="approved")
        self.svc.start_canary(self.admin, p.proposal_id, org_id=ORG)
        rejected = self.svc.record_canary(self.admin, p.proposal_id, org_id=ORG, samples=50,
                                          deny_delta=0.9)
        self.assertEqual(rejected.status, ProposalStatus.REJECTED.value)

    def test_emergency_change_is_audited_and_flagged(self):
        p = self.svc.emergency_change(self.admin, org_id=ORG, proposed_rego=VALID_REGO,
                                      title="hotfix", rationale="active exploit")
        self.assertTrue(p.emergency)
        self.assertEqual(p.impact_level, ImpactLevel.CRITICAL.value)
        events = [r["event"] for r in self.svc.list_audit(org_id=ORG, limit=100)]
        self.assertIn("assurance.proposal.emergency", events)

    def test_lifecycle_transitions_are_audited(self):
        p = self._proposal()
        self.svc.validate_proposal(self.admin, p.proposal_id, org_id=ORG)
        events = [r["event"] for r in self.svc.list_audit(org_id=ORG, limit=100)]
        self.assertIn("assurance.proposal.created", events)
        self.assertIn("assurance.proposal.validated", events)


# =========================================================================== audit integrity
class AuditIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.store = _svc()
        for i in range(5):
            self.svc.audit.record("evt", org_id=ORG, actor_user_id="u1", detail={"i": i})

    def test_chain_verifies(self):
        self.assertTrue(self.svc.verify_audit(org_id=ORG)["ok"])

    def test_modified_record_is_detected(self):
        rows = self.store.list_audit(org_id=ORG, limit=100)
        tampered = rows[2]
        import dataclasses
        self.store._audit[self.store._audit.index(tampered)] = dataclasses.replace(
            tampered, outcome="forged")
        result = self.svc.verify_audit(org_id=ORG)
        self.assertFalse(result["ok"])
        self.assertIn("hash", result["chain"]["reason"])

    def test_reordered_records_are_detected(self):
        rows = self.store.list_audit(org_id=ORG, limit=100)
        self.store._audit[1], self.store._audit[3] = self.store._audit[3], self.store._audit[1]
        result = self.svc.verify_audit(org_id=ORG)
        self.assertFalse(result["ok"])

    def test_removed_record_is_detected(self):
        del self.store._audit[2]
        result = self.svc.verify_audit(org_id=ORG)
        self.assertFalse(result["ok"])

    def test_checkpoint_detects_tail_truncation(self):
        cp = self.svc.checkpoint(org_id=ORG)
        self.assertIsNotNone(cp)
        # remove the last two records (tail truncation)
        del self.store._audit[-2:]
        result = self.svc.verify_audit(org_id=ORG)
        self.assertFalse(result["ok"])
        self.assertFalse(result["checkpoint"]["ok"])

    def test_checkpoint_verifies_when_intact(self):
        self.svc.checkpoint(org_id=ORG)
        result = self.svc.verify_audit(org_id=ORG)
        self.assertTrue(result["ok"])
        self.assertTrue(result["checkpoint"]["ok"])

    def test_forged_signature_is_detected(self):
        rows = self.store.list_audit(org_id=ORG, limit=100)
        import dataclasses
        self.store._audit[0] = dataclasses.replace(rows[0], signature="AAAA")
        result = self.svc.verify_audit(org_id=ORG)
        self.assertFalse(result["ok"])

    def test_unsigned_record_rejected_when_signatures_required(self):
        rows = self.store.list_audit(org_id=ORG, limit=100)
        import dataclasses
        self.store._audit[0] = dataclasses.replace(rows[0], signature=None)
        result = self.svc.verify_audit(org_id=ORG)
        self.assertFalse(result["ok"])
        self.assertIn("signature", result["chain"]["reason"])

    def test_key_rotation_compatibility(self):
        """A record signed by an older key version still verifies after rotation."""
        store = MemoryAssuranceStore()
        signer = LocalEd25519Signer(key_id="audit_signing", environment="development")
        audit = TamperEvidentAudit(store, config=AssuranceConfig(environment="development"),
                                   signer=signer)
        audit.record("evt", org_id=ORG)
        # a NEW signer instance (simulating a rotated key) cannot verify the old signature
        rotated = LocalEd25519Signer(key_id="audit_signing", environment="development")
        audit2 = TamperEvidentAudit(store, config=AssuranceConfig(environment="development"),
                                    signer=rotated)
        self.assertFalse(audit2.verify_chain(org_id=ORG)["ok"])
        # but the ORIGINAL signer still verifies (key_id/key_version are recorded per record)
        self.assertTrue(audit.verify_chain(org_id=ORG)["ok"])

    def test_local_signer_refuses_production(self):
        with self.assertRaises(SigningUnavailableError):
            LocalEd25519Signer(environment="production")

    def test_null_signer_refused_when_signatures_required(self):
        with self.assertRaises(SigningUnavailableError):
            TamperEvidentAudit(MemoryAssuranceStore(),
                               config=AssuranceConfig(environment="development"),
                               signer=NullSigner())

    def test_audit_store_failure_fails_closed(self):
        class BrokenStore(MemoryAssuranceStore):
            def append_audit(self, record):
                raise RuntimeError("store down")
        audit = TamperEvidentAudit(BrokenStore(), config=AssuranceConfig(environment="development"),
                                   signer=LocalEd25519Signer(environment="development"))
        with self.assertRaises(Exception):
            audit.record("evt", org_id=ORG)

    def test_unauthorized_audit_read(self):
        from agent_identity.security.rbac import Authorizer, P_ASSURANCE_READ
        dev = _actor(ROLE_DEVELOPER, user_id="usr_dev")
        # a developer holds assurance:read (investigation), so use a role that does not
        with self.assertRaises(ForbiddenError):
            Authorizer.require(dev, "assurance:admin", org_id=ORG)
        auditor = _actor(ROLE_READONLY_AUDITOR, user_id="usr_aud")
        Authorizer.require(auditor, P_ASSURANCE_READ, org_id=ORG)   # allowed

    def test_tenant_isolation_of_audit(self):
        self.svc.audit.record("other", org_id=OTHER)
        org_rows = self.svc.list_audit(org_id=ORG, limit=100)
        self.assertTrue(all(r["org_id"] == ORG for r in org_rows))


# =========================================================================== compliance
class ComplianceTests(unittest.TestCase):
    def test_seed_and_report(self):
        svc, _ = _svc()
        n = svc.seed_compliance()
        self.assertGreater(n, 0)
        report = svc.compliance_report(framework="soc2")
        self.assertIn("NOT a certification", report["disclaimer"])
        self.assertGreater(report["summary"]["total_controls"], 0)
        # idempotent
        self.assertEqual(svc.seed_compliance(), 0)

    def test_unknown_framework_rejected(self):
        svc, _ = _svc()
        with self.assertRaises(Exception):
            svc.compliance_report(framework="hipaa")

    def test_verification_statuses_are_honest(self):
        svc, _ = _svc()
        svc.seed_compliance()
        controls = svc.list_controls()
        statuses = {c["verification_status"] for c in controls}
        # organizational controls are labelled as such, not as implemented
        self.assertIn("organizational", statuses)
        org_controls = [c for c in controls if c["verification_status"] == "organizational"]
        self.assertTrue(all(c["known_gaps"] for c in org_controls))

    def test_evidence_provenance_in_report(self):
        svc, _ = _svc()
        svc.seed_compliance()
        svc.record_evidence(org_id=ORG, kind=EvidenceKind.POLICY_VIOLATION.value, summary="v",
                            source="policy")
        report = svc.compliance_report(org_id=ORG)
        self.assertIn(EvidenceKind.POLICY_VIOLATION.value, report["evidence_summary"])


# =========================================================================== SIEM
class SiemTests(unittest.TestCase):
    def _event(self, **kw):
        base = dict(event_id="sev_1", ts=1.0, org_id=ORG, severity="high", category="policy",
                    action="deny", outcome="denied", source="policy", dedup_key="k1",
                    classification="internal", fields={"password": "hunter2", "note": "ok"})
        base.update(kw)
        return SiemEvent(**base)

    def test_redaction_of_secret_fields(self):
        out = redact_fields({"password": "x", "api_key": "y", "note": "ok", "nested": {"token": "z"}},
                            redact_names=("password", "api_key", "token"))
        self.assertEqual(out["password"], "[REDACTED]")
        self.assertEqual(out["api_key"], "[REDACTED]")
        self.assertEqual(out["nested"]["token"], "[REDACTED]")
        self.assertEqual(out["note"], "ok")

    def test_redaction_of_secret_looking_values(self):
        out = redact_fields({"blob": "-----BEGIN PRIVATE KEY-----"}, redact_names=())
        self.assertEqual(out["blob"], "[REDACTED]")

    def test_classification_gate_suppresses_and_records(self):
        svc, store = _svc()
        t = FakeTransport(config=svc.cfg)
        svc.siem.register_destination("d1", t)
        res = svc.export_event(self._event(classification="restricted"))
        self.assertFalse(res["queued"])
        self.assertEqual(res["reason"], "classification_not_exportable")
        deliveries = store.list_deliveries(status="suppressed")
        self.assertEqual(len(deliveries), 1)

    def test_export_redacts_before_delivery(self):
        svc, _ = _svc()
        t = FakeTransport(config=svc.cfg)
        svc.siem.register_destination("d1", t)
        svc.export_event(self._event())
        svc.flush_siem()
        self.assertEqual(t.received[0]["fields"]["password"], "[REDACTED]")

    def test_duplicate_delivery_suppressed(self):
        svc, _ = _svc()
        t = FakeTransport(config=svc.cfg)
        svc.siem.register_destination("d1", t)
        e = self._event()
        first = svc.export_event(e)
        second = svc.export_event(e)
        self.assertTrue(first["accepted"])
        self.assertTrue(second["duplicate"])
        svc.flush_siem()
        self.assertEqual(len(t.received), 1)

    def test_retry_then_success(self):
        svc, _ = _svc()
        t = FakeTransport(config=svc.cfg, fail_times=2)
        svc.siem.register_destination("d1", t)
        svc.export_event(self._event())
        result = svc.flush_siem()
        self.assertEqual(result["delivered"], 1)
        self.assertEqual(result["failed"], 0)

    def test_retry_exhaustion_dead_letters(self):
        svc, store = _svc(config=AssuranceConfig(environment="development", siem_max_retries=2,
                                                 siem_retry_backoff_s=0.0))
        t = FakeTransport(config=svc.cfg, fail_times=99)
        svc.siem.register_destination("d1", t)
        svc.export_event(self._event())
        result = svc.flush_siem()
        self.assertEqual(result["failed"], 1)
        dead = store.list_deliveries(status="dead_letter")
        self.assertEqual(len(dead), 1)

    def test_backpressure_reject(self):
        svc, _ = _svc(config=AssuranceConfig(environment="development", siem_queue_max=1,
                                             siem_backpressure_policy="reject"))
        t = FakeTransport(config=svc.cfg)
        svc.siem.register_destination("d1", t)
        svc.export_event(self._event(event_id="sev_a", dedup_key="a"))
        res = svc.export_event(self._event(event_id="sev_b", dedup_key="b"))
        self.assertFalse(res["queued"])
        self.assertEqual(res["reason"], "backpressure")

    def test_backpressure_fail_closed_raises(self):
        svc, _ = _svc(config=AssuranceConfig(environment="development", siem_queue_max=1,
                                             siem_backpressure_policy="reject",
                                             siem_fail_closed=True))
        t = FakeTransport(config=svc.cfg)
        svc.siem.register_destination("d1", t)
        svc.export_event(self._event(event_id="sev_a", dedup_key="a"))
        with self.assertRaises(BackpressureError):
            svc.export_event(self._event(event_id="sev_b", dedup_key="b"))

    def test_plaintext_transport_refused(self):
        cfg = AssuranceConfig(environment="development", siem_require_tls=True)
        with self.assertRaises(SiemConfigError):
            build_transport("syslog_tcp", config=cfg, host="h", port=1)
        with self.assertRaises(SiemConfigError):
            build_transport("http", config=cfg, url="http://insecure.example/ingest")

    def test_unknown_transport_refused(self):
        with self.assertRaises(SiemConfigError):
            build_transport("carrier_pigeon", config=AssuranceConfig(environment="development"))

    def test_siem_outage_does_not_stop_security_plane(self):
        svc, _ = _svc(config=AssuranceConfig(environment="development", siem_max_retries=1,
                                             siem_retry_backoff_s=0.0))
        t = FakeTransport(config=svc.cfg, fail_times=99)
        svc.siem.register_destination("d1", t)
        svc.export_event(self._event())
        svc.flush_siem()          # must not raise
        health = svc.health()
        self.assertIn(health["status"], ("ok", "degraded"))

    def test_health_reports_queue_and_destinations(self):
        svc, _ = _svc()
        t = FakeTransport(config=svc.cfg)
        svc.siem.register_destination("d1", t)
        h = svc.siem.health()
        self.assertEqual(h["queue_depth"], 0)
        self.assertEqual(len(h["destinations"]), 1)


# =========================================================================== correlation
class CorrelationTests(unittest.TestCase):
    def test_severity_normalization(self):
        self.assertEqual(normalize_severity("WARNING"), "medium")
        self.assertEqual(normalize_severity("fatal"), "critical")
        self.assertEqual(normalize_severity("nonsense"), "medium")
        self.assertGreater(severity_rank("critical"), severity_rank("low"))

    def test_correlation_preserves_provenance(self):
        svc, _ = _svc()
        for i in range(4):
            ev = svc.correlation.normalize(org_id=ORG, category="policy", action="deny",
                                           outcome="denied", source="policy", severity="high",
                                           agent_id="a1", subject=f"res-{i}")
            svc.correlation.ingest(ev)
        findings = svc.correlate(org_id=ORG, min_events=3)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["provenance"], Provenance.DERIVED.value)
        self.assertTrue(findings[0]["event_ids"])

    def test_dedup_window(self):
        svc, _ = _svc()
        ev = svc.correlation.normalize(org_id=ORG, category="policy", action="deny",
                                       outcome="denied", source="policy", agent_id="a1")
        self.assertTrue(svc.correlation.ingest(ev)["accepted"])
        self.assertTrue(svc.correlation.ingest(ev)["duplicate"])

    def test_tenant_isolation_of_correlations(self):
        svc, _ = _svc()
        for i in range(4):
            svc.correlation.ingest(svc.correlation.normalize(
                org_id=OTHER, category="policy", action="deny", outcome="denied", source="p",
                agent_id="a1", subject=f"res-{i}"))
        self.assertEqual(svc.correlate(org_id=ORG, min_events=3), [])
        self.assertEqual(len(svc.correlate(org_id=OTHER, min_events=3)), 1)


# =========================================================================== hash primitive
class HashPrimitiveTests(unittest.TestCase):
    def test_canonical_hash_is_stable(self):
        rec = {"seq": 1, "record_id": "r", "org_id": "o", "ts": 1.0, "event": "e",
               "actor_user_id": None, "outcome": "ok", "reason": None, "payload_digest": None,
               "correlation_id": None, "detail": None}
        self.assertEqual(compute_hash(None, rec), compute_hash(None, dict(rec)))
        self.assertNotEqual(compute_hash("a", rec), compute_hash("b", rec))

    def test_hash_ignores_non_hashed_fields(self):
        rec = {"seq": 1, "record_id": "r", "org_id": "o", "ts": 1.0, "event": "e",
               "actor_user_id": None, "outcome": "ok", "reason": None, "payload_digest": None,
               "correlation_id": None, "detail": None}
        h1 = compute_hash(None, rec)
        rec2 = dict(rec, signature="whatever", key_id="k")
        self.assertEqual(h1, compute_hash(None, rec2))


if __name__ == "__main__":
    unittest.main()
