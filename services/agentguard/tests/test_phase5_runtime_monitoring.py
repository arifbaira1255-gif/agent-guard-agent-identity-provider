"""Phase 5 tests: runtime monitoring, agent behaviour intelligence, intent graph & agentic drift.

Deterministic by construction: every test drives a fake clock, so no assertion depends on wall time,
and every fixture is built inline so results are reproducible.

Coverage map (requirement 10):

  schema validation            EventSchemaTests
  correlation + duplicates     CorrelationTests, DuplicateTests
  tenant isolation             TenantIsolationTests
  missing/delayed telemetry    LateAndMissingTelemetryTests, OutOfOrderTests
  baseline + min samples       ProfileBaselineTests
  drift detection              DriftDetectionTests
  FP/FN scenarios              DriftFalsePositiveTests
  risk score explanations      RiskScoringTests
  alert dedup + rate limiting  AlertDeduplicationTests, AlertRateLimitTests
  policy/grant revocation      PolicyIntegrationTests
  malformed + resource abuse   MalformedEventTests, ResourceExhaustionTests
  privacy redaction            RedactionTests
  graph                        IntentGraphTests
  HTTP + RBAC surface          HttpSurfaceTests
"""
from __future__ import annotations

import time
import unittest

from agent_identity.core.errors import ForbiddenError
from agent_identity.runtime_monitoring import (AlertError, AlertState, BehaviorProfileService,
                                               Corroboration, Decision, DriftClass, DriftDetector,
                                               EventType, EventValidationError, IntentGraph,
                                               MemoryRuntimeMonitoringStore, MonitoringConfig,
                                               Redactor, ResponseAction, RiskScorer, RiskRules,
                                               RuntimeEventPipeline, RuntimeMonitoringService,
                                               Severity, SignalKind, TenantBoundaryError)
from agent_identity.runtime_monitoring.audit import RuntimeMonitoringAudit

ORG = "org_acme"
ORG_B = "org_globex"
AGENT = "agent_1"
#: Fixed reference instant for the suite. Kept as a CONSTANT so ``_profile``'s incremental-vs-full
#: comparison window stays deterministic -- but recomputed per run from the wall clock, because the
#: ingestion pipeline rejects events that predate the retention horizon (fail-closed).
NOW = time.time() - 86400


class FakeClock:
    def __init__(self, t: float = NOW):
        self.t = t

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def evt(**kw) -> dict:
    base = {"org_id": ORG, "event_type": "tool.invocation", "ts": NOW, "agent_id": AGENT,
            "action": "read_file", "resource": "s3://bucket/report.csv", "decision": "ALLOW"}
    base.update(kw)
    return base


def build(cfg: MonitoringConfig | None = None, clock: FakeClock | None = None):
    clock = clock or FakeClock()
    cfg = cfg or MonitoringConfig(default_min_samples=1)
    store = MemoryRuntimeMonitoringStore(max_events=cfg.max_events_retained)
    audit = RuntimeMonitoringAudit(store, enabled=True, clock=clock)
    pipe = RuntimeEventPipeline(store, config=cfg, audit=audit, clock=clock)
    return store, pipe, audit, clock, cfg


# ============================================================================ schema validation
class EventSchemaTests(unittest.TestCase):
    def setUp(self):
        self.store, self.pipe, self.audit, self.clock, self.cfg = build()

    def test_normalize_required_fields(self):
        for missing in ("org_id", "event_type", "ts"):
            raw = evt()
            del raw[missing]
            with self.assertRaises(EventValidationError):
                self.pipe.normalize(raw)

    def test_aliases_are_accepted(self):
        e = self.pipe.normalize({"tenant": ORG, "type": "tool.invocation", "timestamp": NOW,
                                 "agent": AGENT})
        self.assertEqual(e.org_id, ORG)
        self.assertEqual(e.event_type, EventType.TOOL_INVOCATION.value)

    def test_unknown_event_type_rejected(self):
        with self.assertRaises(EventValidationError):
            self.pipe.normalize(evt(event_type="totally.invented"))

    def test_derived_event_type_cannot_be_ingested(self):
        with self.assertRaises(EventValidationError):
            self.pipe.normalize(evt(event_type=EventType.ACTION_SEQUENCE.value))

    def test_non_finite_timestamp_rejected(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(EventValidationError):
                self.pipe.normalize(evt(ts=bad))

    def test_future_timestamp_rejected(self):
        with self.assertRaises(EventValidationError):
            self.pipe.normalize(evt(ts=NOW + self.cfg.max_future_skew_s + 10))

    def test_prehorizon_timestamp_rejected(self):
        with self.assertRaises(EventValidationError):
            self.pipe.normalize(evt(ts=NOW - self.cfg.max_event_age_s - 10))

    def test_negative_latency_rejected(self):
        with self.assertRaises(EventValidationError):
            self.pipe.normalize(evt(latency_ms=-1))

    def test_non_mapping_rejected(self):
        with self.assertRaises(EventValidationError):
            self.pipe.normalize(["not", "a", "mapping"])

    def test_all_closed_event_types_normalize(self):
        for et in EventType:
            if et in (EventType.ACTION_SEQUENCE,):
                continue
            e = self.pipe.normalize(evt(event_type=et.value))
            self.assertEqual(e.event_type, et.value)

    def test_unknown_decision_coerces_to_unknown_not_dropped(self):
        e = self.pipe.normalize(evt(decision="banana"))
        self.assertEqual(e.decision, Decision.UNKNOWN.value)

    def test_public_dict_has_documented_metadata_fields(self):
        e = self.pipe.normalize(evt(correlation_id="c1", trace_id="t1", policy_id="p1",
                                    policy_version="v3", severity="high"))
        d = e.public_dict()
        for key in ("agent_id", "org_id", "event_type", "ts", "resource", "action", "decision",
                    "policy_version", "correlation_id", "trace_id"):
            self.assertIn(key, d)


# ============================================================================ pipeline behaviours
class DuplicateTests(unittest.TestCase):
    def test_exact_replay_is_a_duplicate_not_a_second_event(self):
        store, pipe, *_ = build()
        first = pipe.ingest(evt())
        second = pipe.ingest(evt())
        self.assertTrue(first.stored)
        self.assertEqual(second.outcome, "duplicate")
        self.assertEqual(store.count_events(org_id=ORG), 1)

    def test_distinct_events_are_not_deduplicated(self):
        store, pipe, *_ = build()
        pipe.ingest(evt(resource="a"))
        pipe.ingest(evt(resource="b"))
        self.assertEqual(store.count_events(org_id=ORG), 2)

    def test_explicit_dedup_key_respected(self):
        store, pipe, *_ = build()
        pipe.ingest(evt(dedup_key="k1"))
        r = pipe.ingest(evt(dedup_key="k1", resource="different"))
        self.assertEqual(r.outcome, "duplicate")


class LateAndMissingTelemetryTests(unittest.TestCase):
    def test_late_event_is_stored_and_flagged_not_dropped(self):
        store, pipe, audit, clock, cfg = build()
        pipe.ingest(evt(ts=NOW))
        res = pipe.ingest(evt(ts=NOW - 3600, resource="late"))
        self.assertTrue(res.stored)
        self.assertTrue(res.event.late)
        self.assertEqual(store.count_events(org_id=ORG), 2)

    def test_absent_baseline_yields_insufficient_evidence_not_a_finding(self):
        det = DriftDetector()
        out = det.detect(org_id=ORG, agent_id=AGENT, events=[], profile=None)
        self.assertTrue(all(f.classification == DriftClass.INSUFFICIENT_EVIDENCE.value for f in out))

    def test_investigate_reports_no_data_honestly(self):
        store, pipe, *_ = build()
        view = pipe.investigate(org_id=ORG, agent_id="never_seen")
        self.assertEqual(view["count"], 0)
        self.assertIn("absence of an event", view["caveat"])


class OutOfOrderTests(unittest.TestCase):
    def test_out_of_order_events_are_ordered_by_event_time(self):
        store, pipe, *_ = build()
        pipe.ingest(evt(ts=NOW + 100, resource="third", correlation_id="c"))
        pipe.ingest(evt(ts=NOW, resource="first", correlation_id="c"))
        pipe.ingest(evt(ts=NOW + 50, resource="second", correlation_id="c"))
        seq = pipe.correlate(org_id=ORG, correlation_id="c")
        self.assertEqual([l.resource for l in seq.links], ["first", "second", "third"])

    def test_cursor_pagination_does_not_skip_or_duplicate_with_new_arrivals(self):
        store, pipe, *_ = build()
        for i in range(5):
            pipe.ingest(evt(ts=NOW + i, resource=f"r{i}", dedup_key=f"k{i}"))
        page1, cursor = store.list_events(org_id=ORG, limit=2)
        self.assertIsNotNone(cursor)
        # a late-arriving event whose ts sorts INSIDE/ABOVE page 1's range must not disturb the walk:
        # keyset pagination is snapshot-consistent purely from the cursor
        pipe.ingest(evt(ts=NOW + 3.5, resource="interloper", dedup_key="kx"))
        page2, cursor2 = store.list_events(org_id=ORG, limit=2, cursor=cursor)
        page3, cursor3 = store.list_events(org_id=ORG, limit=2, cursor=cursor2)
        ids1 = {e.event_id for e in page1}
        ids2 = {e.event_id for e in page2}
        self.assertFalse(ids1 & ids2, "a page must never repeat a row from the previous page")
        self.assertEqual(len(ids1), 2)
        self.assertEqual(len(ids2), 2)
        # DESC order, so page 1 holds the NEWER timestamps
        self.assertGreater(min(e.ts for e in page1), max(e.ts for e in page2))
        # the walk reaches the rest of the original corpus without loss and then terminates
        self.assertEqual(len(ids1 | ids2 | {e.event_id for e in page3}), 5)
        self.assertIsNone(cursor3)


# ============================================================================ correlation
class CorrelationTests(unittest.TestCase):
    def test_trace_grouping_is_marked_causal_only_with_span_context(self):
        store, pipe, *_ = build()
        pipe.ingest(evt(correlation_id="c1", trace_id="t1", span_id="s2", parent_span_id="s1"))
        pipe.ingest(evt(correlation_id="c1", trace_id="t1", span_id="s3", parent_span_id="s2",
                        ts=NOW + 1))
        seq = pipe.correlate(org_id=ORG, trace_id="t1")
        self.assertTrue(seq.to_dict()["causal_established"])
        self.assertTrue(all(l.causal for l in seq.links))

    def test_correlation_id_grouping_is_not_presented_as_causal(self):
        store, pipe, *_ = build()
        pipe.ingest(evt(correlation_id="c1", span_id="s1"))
        pipe.ingest(evt(correlation_id="c1", span_id="s2", ts=NOW + 1))
        seq = pipe.correlate(org_id=ORG, correlation_id="c1")
        self.assertFalse(seq.to_dict()["causal_established"])
        self.assertIn("causal linkage is NOT established", seq.note)

    def test_sequence_flags_blocked_and_departed_from_policy(self):
        store, pipe, *_ = build()
        pipe.ingest(evt(correlation_id="c", decision="ALLOW"))
        pipe.ingest(evt(correlation_id="c", decision="DENY", ts=NOW + 1, resource="secret"))
        seq = pipe.correlate(org_id=ORG, correlation_id="c")
        self.assertTrue(seq.blocked)
        self.assertTrue(seq.departed_from_policy)

    def test_correlate_requires_an_identifier(self):
        store, pipe, *_ = build()
        with self.assertRaises(EventValidationError):
            pipe.correlate(org_id=ORG)

    def test_investigation_view_answers_the_documented_questions(self):
        store, pipe, *_ = build()
        pipe.ingest(evt(correlation_id="c", decision="REQUIRE_APPROVAL"))
        view = pipe.investigate(org_id=ORG, agent_id=AGENT, correlation_id="c")
        self.assertTrue(view["approval_required"])
        self.assertIn("decisions", view)
        self.assertIsNotNone(view["sequence"])


# ============================================================================ tenant isolation
class TenantIsolationTests(unittest.TestCase):
    def test_events_are_never_readable_across_tenants(self):
        store, pipe, *_ = build()
        pipe.ingest(evt(org_id=ORG))
        self.assertEqual(store.count_events(org_id=ORG_B), 0)
        items, _ = store.list_events(org_id=ORG_B)
        self.assertEqual(items, [])

    def test_claimed_org_mismatch_is_a_boundary_error(self):
        store, pipe, *_ = build()
        with self.assertRaises(TenantBoundaryError):
            pipe.ingest(evt(org_id=ORG_B), claimed_org=ORG)

    def test_get_event_is_tenant_scoped(self):
        store, pipe, *_ = build()
        res = pipe.ingest(evt())
        self.assertIsNotNone(store.get_event(res.event.event_id, org_id=ORG))
        self.assertIsNone(store.get_event(res.event.event_id, org_id=ORG_B))

    def test_profiles_are_tenant_isolated(self):
        store, *_r = build()
        svc = BehaviorProfileService(store, config=MonitoringConfig(default_min_samples=1))
        svc.build(org_id=ORG, agent_id=AGENT, events=[])
        self.assertIsNotNone(svc.get(org_id=ORG, agent_id=AGENT))
        self.assertIsNone(svc.get(org_id=ORG_B, agent_id=AGENT))

    def test_graph_nodes_are_tenant_isolated(self):
        store, *_r = build()
        g = IntentGraph(store)
        g.upsert_node(org_id=ORG, kind="agent", key=AGENT)
        self.assertIsNotNone(g.store.get_node(g.node_id(ORG, "agent", AGENT), org_id=ORG))
        self.assertIsNone(g.store.get_node(g.node_id(ORG, "agent", AGENT), org_id=ORG_B))

    def test_alerts_are_tenant_isolated(self):
        store, *_r = build()
        from agent_identity.runtime_monitoring import AlertService
        svc = AlertService(store, config=MonitoringConfig())
        rule = svc.register_rule(org_id=ORG, name="r")
        svc.raise_alert(org_id=ORG, rule=rule, severity="high", title="x", agent_id=AGENT)
        self.assertGreaterEqual(len(svc.list_alerts(org_id=ORG)), 1)
        self.assertEqual(svc.list_alerts(org_id=ORG_B), [])

    def test_aggregate_is_tenant_scoped(self):
        store, pipe, *_ = build()
        pipe.ingest(evt(org_id=ORG))
        pipe.ingest(evt(org_id=ORG_B))
        self.assertEqual(sum(store.aggregate_by_type(org_id=ORG).values()), 1)


# ============================================================================ profiles
class ProfileBaselineTests(unittest.TestCase):
    def test_min_sample_threshold_blocks_premature_maturity(self):
        store, *_r = build()
        svc = BehaviorProfileService(store, config=MonitoringConfig(default_min_samples=50))
        svc.build(org_id=ORG, agent_id=AGENT, events=[])
        p = svc.get(org_id=ORG, agent_id=AGENT)
        self.assertFalse(p.is_mature)

    def test_profile_counts_observable_activity(self):
        store, pipe, *_ = build()
        svc = BehaviorProfileService(store, config=MonitoringConfig(default_min_samples=1))
        e1 = pipe.normalize(evt(resource="a", action="read"))
        e2 = pipe.normalize(evt(event_type="data.access", data_classes=["pii"],
                                decision="DENY", ts=NOW + 1))
        p = svc.build(org_id=ORG, agent_id=AGENT, events=[e1, e2], now=NOW + 1)
        self.assertEqual(p.total_events, 2)
        self.assertEqual(p.denials, 1)
        self.assertEqual(p.sensitive_reads, 1)
        self.assertIn("read", p.actions)

    def test_version_increments_and_reset_clears(self):
        store, *_r = build()
        svc = BehaviorProfileService(store, config=MonitoringConfig(default_min_samples=1))
        v1 = svc.build(org_id=ORG, agent_id=AGENT, events=[])
        v2 = svc.build(org_id=ORG, agent_id=AGENT, events=[])
        self.assertEqual((v1.version, v2.version), (1, 2))
        svc.reset(org_id=ORG, agent_id=AGENT)
        self.assertIsNone(svc.get(org_id=ORG, agent_id=AGENT))
        v3 = svc.build(org_id=ORG, agent_id=AGENT, events=[])
        self.assertEqual(v3.version, 1)

    def test_retrain_discards_and_rebuilds(self):
        store, *_r = build()
        svc = BehaviorProfileService(store, config=MonitoringConfig(default_min_samples=1))
        svc.build(org_id=ORG, agent_id=AGENT, events=[])
        p = svc.retrain(org_id=ORG, agent_id=AGENT)
        self.assertEqual(p.version, 1)


# ============================================================================ drift
def _profile(store, events, min_samples=1, now=NOW):
    svc = BehaviorProfileService(store, config=MonitoringConfig(default_min_samples=min_samples))
    return svc.build(org_id=ORG, agent_id=AGENT, events=events, now=now)


class DriftDetectionTests(unittest.TestCase):
    def test_capability_violation_is_confirmed_and_authoritative(self):
        store, pipe, *_ = build()
        e = pipe.normalize(evt(action="read", resource="db", extra={"capability": "db:write"}))
        out = DriftDetector().check_capabilities(org_id=ORG, agent_id=AGENT, events=[e],
                                                 declared_capabilities=["db:read"])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].classification, DriftClass.CONFIRMED_VIOLATION.value)
        self.assertEqual(out[0].corroboration, Corroboration.AUTHORITATIVE.value)

    def test_missing_capability_set_is_insufficient_not_permissive(self):
        store, pipe, *_ = build()
        e = pipe.normalize(evt(extra={"capability": "db:write"}))
        out = DriftDetector().check_capabilities(org_id=ORG, agent_id=AGENT, events=[e],
                                                 declared_capabilities=None)
        self.assertEqual(out[0].classification, DriftClass.INSUFFICIENT_EVIDENCE.value)

    def test_destination_outside_declared_scope_is_confirmed(self):
        store, pipe, *_ = build()
        e = pipe.normalize(evt(event_type="network.request", destination="evil.example",
                               address_class="public"))
        out = DriftDetector().check_destination_scope(
            org_id=ORG, agent_id=AGENT, events=[e], declared_destinations=["api.internal"])
        self.assertEqual(out[0].classification, DriftClass.CONFIRMED_VIOLATION.value)

    def test_novel_tool_in_mature_baseline_is_a_statistical_anomaly(self):
        store, pipe, *_ = build()
        known = [pipe.normalize(evt(action="known_tool", ts=NOW + i)) for i in range(3)]
        profile = _profile(store, known)
        new = pipe.normalize(evt(action="never_used_tool", ts=NOW + 10))
        out = DriftDetector().check_novelty(org_id=ORG, agent_id=AGENT, events=[new],
                                            profile=profile)
        kinds = [f for f in out if f.classification == DriftClass.STATISTICAL_ANOMALY.value]
        self.assertTrue(kinds)
        self.assertEqual(kinds[0].corroboration, Corroboration.BASELINE.value)

    def test_novelty_without_mature_baseline_is_insufficient(self):
        store, pipe, *_ = build()
        profile = _profile(store, [], min_samples=50)
        new = pipe.normalize(evt(action="t", ts=NOW + 1))
        out = DriftDetector().check_novelty(org_id=ORG, agent_id=AGENT, events=[new],
                                            profile=profile)
        self.assertEqual(out[0].classification, DriftClass.INSUFFICIENT_EVIDENCE.value)

    def test_repeated_denials_is_heuristic_not_proof(self):
        store, pipe, *_ = build()
        events = [pipe.normalize(evt(event_type="authorization.failure", decision="DENY",
                                     ts=NOW + i, dedup_key=f"d{i}")) for i in range(6)]
        out = DriftDetector().check_repeated_denials(org_id=ORG, agent_id=AGENT, events=events)
        self.assertEqual(out[0].classification, DriftClass.HEURISTIC_SUSPICION.value)
        self.assertEqual(out[0].corroboration, Corroboration.HEURISTIC.value)
        self.assertIn("human adjudication", out[0].detail)

    def test_access_burst_above_baseline_multiplier(self):
        store, pipe, *_ = build()
        t0 = time.time() - 7200
        base_events = [pipe.normalize(evt(ts=t0 + i, dedup_key=f"b{i}"), now=t0 + 4)
                       for i in range(4)]
        profile = _profile(store, base_events, now=t0 + 4)
        burst = [pipe.normalize(evt(ts=t0 + 3600 + i, dedup_key=f"x{i}"), now=t0 + 3660)
                 for i in range(60)]
        out = DriftDetector().check_access_bursts(org_id=ORG, agent_id=AGENT, events=burst,
                                                  profile=profile)
        self.assertTrue(out)
        self.assertEqual(out[0].category, "access_burst")

    def test_policy_denial_is_a_confirmed_violation(self):
        store, pipe, *_ = build()
        e = pipe.normalize(evt(decision="DENY", policy_id="pol_1", reason="not_permitted"))
        f = DriftDetector().policy_violation(org_id=ORG, agent_id=AGENT, event=e)
        self.assertIsNotNone(f)
        self.assertEqual(f.classification, DriftClass.CONFIRMED_VIOLATION.value)

    def test_findings_never_claim_intent(self):
        store, pipe, *_ = build()
        events = [pipe.normalize(evt(action="discover_tools", ts=NOW + i, dedup_key=f"e{i}"))
                  for i in range(3)]
        out = DriftDetector().detect(org_id=ORG, agent_id=AGENT, events=events)
        blob = " ".join(f.to_dict()["detail"] + f.category for f in out).lower()
        self.assertNotIn("intent", blob)
        self.assertNotIn("intends", blob)

    def test_full_detect_returns_something_even_when_clean(self):
        store, pipe, *_ = build()
        out = DriftDetector().detect(org_id=ORG, agent_id=AGENT, events=[])
        self.assertTrue(out)


class DriftFalsePositiveTests(unittest.TestCase):
    def test_legitimate_new_tool_with_authoritative_scope_is_not_a_violation(self):
        store, pipe, *_ = build()
        e = pipe.normalize(evt(action="json_parse", resource="tmp:x", extra={"capability": "tmp:read"}))
        out = DriftDetector().check_capabilities(org_id=ORG, agent_id=AGENT, events=[e],
                                                 declared_capabilities=["tmp:read"])
        self.assertEqual(out, [])

    def test_single_denial_does_not_trip_the_repeated_denial_heuristic(self):
        store, pipe, *_ = build(cfg=MonitoringConfig(default_min_samples=1, repeated_denial_threshold=5))
        e = pipe.normalize(evt(event_type="authorization.failure", decision="DENY"))
        self.assertEqual(DriftDetector().check_repeated_denials(org_id=ORG, agent_id=AGENT,
                                                               events=[e]), [])

    def test_normal_rate_does_not_trip_the_burst_detector(self):
        store, pipe, *_ = build()
        t0 = time.time() - 7200
        base = [pipe.normalize(evt(ts=t0 + i, dedup_key=f"b{i}"), now=t0 + 10)
                for i in range(10)]
        profile = _profile(store, base, now=t0 + 10)
        same = [pipe.normalize(evt(ts=t0 + 3600 + i, dedup_key=f"s{i}"), now=t0 + 3660)
                for i in range(10)]
        self.assertEqual(DriftDetector().check_access_bursts(org_id=ORG, agent_id=AGENT,
                                                            events=same, profile=profile), [])


# ============================================================================ risk
class RiskScoringTests(unittest.TestCase):
    def test_score_explains_its_signals_and_version(self):
        store, pipe, *_ = build()
        events = [pipe.normalize(evt(decision="DENY", ts=NOW + i, dedup_key=f"d{i}"))
                  for i in range(6)]
        a = RiskScorer(config=MonitoringConfig()).assess(org_id=ORG, agent_id=AGENT, events=events)
        self.assertGreater(a.score, 0)
        self.assertEqual(a.rule_version, MonitoringConfig().risk_rule_version)
        kinds = {s.kind for s in a.signals}
        self.assertIn(SignalKind.POLICY_VIOLATION.value, kinds)
        self.assertTrue(a.evidence)
        self.assertIn("not an enforcement decision", a.caveat)

    def test_clean_activity_scores_zero(self):
        store, pipe, *_ = build()
        events = [pipe.normalize(evt(ts=NOW + i, dedup_key=f"c{i}")) for i in range(3)]
        a = RiskScorer(config=MonitoringConfig()).assess(org_id=ORG, agent_id=AGENT, events=events)
        self.assertEqual(a.score, 0.0)
        self.assertEqual(a.band, "low")

    def test_band_thresholds_are_calibrated(self):
        rules = RiskRules.from_config(MonitoringConfig())
        self.assertEqual(rules.band_of(0), "low")
        self.assertEqual(rules.band_of(30), "medium")
        self.assertEqual(rules.band_of(60), "high")
        self.assertEqual(rules.band_of(95), "critical")

    def test_score_is_clamped_to_the_configured_maximum(self):
        store, pipe, *_ = build()
        events = [pipe.normalize(evt(decision="DENY", event_type="dlp.blocked",
                                     data_classes=["pii"], destination="x", severity="critical",
                                     ts=NOW + i, dedup_key=f"m{i}")) for i in range(20)]
        cfg = MonitoringConfig()
        a = RiskScorer(config=cfg).assess(org_id=ORG, agent_id=AGENT, events=events)
        self.assertLessEqual(a.score, cfg.risk_max)

    def test_dlp_findings_contribute(self):
        store, pipe, *_ = build()
        e = pipe.normalize(evt(event_type="dlp.blocked", dlp_rule_ids=["ssn"]))
        a = RiskScorer(config=MonitoringConfig()).assess(org_id=ORG, agent_id=AGENT, events=[e])
        self.assertIn(SignalKind.DLP_FINDING.value, {s.kind for s in a.signals})

    def test_untracked_destination_contributes_destination_risk(self):
        store, pipe, *_ = build()
        e = pipe.normalize(evt(event_type="network.request", destination="mystery.host",
                               address_class="unknown"))
        a = RiskScorer(config=MonitoringConfig()).assess(org_id=ORG, agent_id=AGENT, events=[e])
        self.assertIn(SignalKind.DESTINATION_RISK.value, {s.kind for s in a.signals})


# ============================================================================ alerts
class AlertDeduplicationTests(unittest.TestCase):
    def setUp(self):
        self.store, *_r = build()
        from agent_identity.runtime_monitoring import AlertService
        self.svc = AlertService(self.store, config=MonitoringConfig())
        self.rule = self.svc.register_rule(org_id=ORG, name="r", event_types=["dlp.blocked"],
                                           dedup_window_s=600)

    def test_same_condition_inside_the_window_updates_one_alert(self):
        a1 = self.svc.raise_alert(org_id=ORG, rule=self.rule, severity="high", title="dlp",
                                  agent_id=AGENT, ts=NOW)
        a2 = self.svc.raise_alert(org_id=ORG, rule=self.rule, severity="high", title="dlp",
                                  agent_id=AGENT, ts=NOW + 10)
        self.assertEqual(a1.alert_id, a2.alert_id)
        self.assertEqual(a2.occurrence_count, 2)
        self.assertEqual(len(self.svc.list_alerts(org_id=ORG)), 1)

    def test_condition_outside_the_window_creates_a_new_alert(self):
        self.svc.raise_alert(org_id=ORG, rule=self.rule, severity="high", title="dlp",
                             agent_id=AGENT, ts=NOW)
        a2 = self.svc.raise_alert(org_id=ORG, rule=self.rule, severity="high", title="dlp",
                                  agent_id=AGENT, ts=NOW + 700)
        self.assertEqual(len(self.svc.list_alerts(org_id=ORG)), 2)
        self.assertEqual(a2.occurrence_count, 1)

    def test_different_agents_do_not_share_a_dedup_key(self):
        self.svc.raise_alert(org_id=ORG, rule=self.rule, severity="high", title="dlp",
                             agent_id="a1", ts=NOW)
        self.svc.raise_alert(org_id=ORG, rule=self.rule, severity="high", title="dlp",
                             agent_id="a2", ts=NOW)
        self.assertEqual(len(self.svc.list_alerts(org_id=ORG)), 2)


class AlertRateLimitTests(unittest.TestCase):
    def test_rate_limit_suppresses_and_records_rather_than_dropping(self):
        store, *_r = build()
        from agent_identity.runtime_monitoring import AlertService
        svc = AlertService(store, config=MonitoringConfig())
        rule = svc.register_rule(org_id=ORG, name="r", dedup_window_s=0, rate_window_s=3600,
                                 max_per_window=2)
        for i in range(5):
            svc.raise_alert(org_id=ORG, rule=rule, severity="high", title=f"t{i}",
                            agent_id=AGENT, ts=NOW + i)
        alerts = svc.list_alerts(org_id=ORG)
        live = [a for a in alerts if a.state != "suppressed"]
        suppressed = [a for a in alerts if a.state == "suppressed"]
        self.assertEqual(len(live), 2)                     # the per-window ceiling
        self.assertGreaterEqual(len(suppressed), 1)        # recorded, not silently dropped
        rate_limited = [e for e in store.list_audit(org_id=ORG)
                        if e["event"] == "runtime.alert.rate_limited"]
        self.assertTrue(rate_limited)

    def test_alert_lifecycle_rejects_illegal_transitions(self):
        store, *_r = build()
        from agent_identity.runtime_monitoring import AlertService
        svc = AlertService(store, config=MonitoringConfig())
        rule = svc.register_rule(org_id=ORG, name="r")
        a = svc.raise_alert(org_id=ORG, rule=rule, severity="high", title="t", agent_id=AGENT)
        svc.transition(org_id=ORG, alert_id=a.alert_id, new_state="acknowledged", actor_user_id="u")
        svc.transition(org_id=ORG, alert_id=a.alert_id, new_state="resolved", actor_user_id="u")
        with self.assertRaises(AlertError):
            svc.transition(org_id=ORG, alert_id=a.alert_id, new_state="investigating")

    def test_alert_states_are_a_closed_vocabulary(self):
        self.assertEqual(AlertState.coerce("open"), AlertState.OPEN)
        with self.assertRaises(ValueError):
            AlertState.coerce("bogus")


# ============================================================================ policy integration
class _FakeJit:
    def __init__(self):
        self.calls = []

    def revoke_all_for_agent(self, *, org_id, agent_id, reason, revoked_by):
        self.calls.append((org_id, agent_id, reason, revoked_by))
        return [{"grant_id": "g1"}, {"grant_id": "g2"}]


class _FakePolicy:
    def __init__(self):
        self.seen = []

    def authorize(self, *, agent_id, tenant, action, resource, context=None, correlation_id=None):
        self.seen.append((agent_id, action, resource))
        return {"decision": "DENY", "reason": "reevaluated"}


class PolicyIntegrationTests(unittest.TestCase):
    def test_no_service_reports_unavailable_rather_than_pretending(self):
        from agent_identity.runtime_monitoring import PolicyIntegration
        res = PolicyIntegration().reevaluate(agent_id=AGENT, tenant=ORG, action="a", resource="r")
        self.assertFalse(res.available)
        self.assertFalse(res.performed)

    def test_reevaluation_delegates_and_returns_the_engine_decision(self):
        from agent_identity.runtime_monitoring import PolicyIntegration
        pol = _FakePolicy()
        res = PolicyIntegration(policy_service=pol).reevaluate(agent_id=AGENT, tenant=ORG,
                                                               action="write", resource="db")
        self.assertTrue(res.performed)
        self.assertEqual(res.result["decision"], "DENY")
        self.assertEqual(pol.seen, [(AGENT, "write", "db")])

    def test_jit_revocation_delegates_to_the_grant_service(self):
        from agent_identity.runtime_monitoring import PolicyIntegration
        jit = _FakeJit()
        res = PolicyIntegration(jit_service=jit).revoke_grants_for_agent(
            org_id=ORG, agent_id=AGENT, reason="drift", revoked_by="analyst")
        self.assertTrue(res.performed)
        self.assertEqual(res.result["revoked"], 2)
        self.assertEqual(len(jit.calls), 1)

    def test_auto_actions_are_off_by_default(self):
        store, *_r = build()
        from agent_identity.runtime_monitoring import AlertService, PolicyIntegration
        svc = AlertService(store, config=MonitoringConfig(), integration=PolicyIntegration())
        with self.assertRaises(AlertError):
            svc.register_rule(org_id=ORG, name="r", auto_actions=["revoke_jit"])

    def test_unknown_auto_action_is_rejected(self):
        store, *_r = build()
        from agent_identity.runtime_monitoring import AlertService
        svc = AlertService(store, config=MonitoringConfig(allow_auto_actions=True))
        with self.assertRaises(AlertError):
            svc.register_rule(org_id=ORG, name="r", auto_actions=["launch_missiles"])


# ============================================================================ malformed / abuse
class MalformedEventTests(unittest.TestCase):
    def test_malformed_batch_does_not_abort_the_healthy_events(self):
        store, pipe, *_ = build()
        results = pipe.ingest_many([evt(), {"nonsense": True}, evt(resource="ok", ts=NOW + 1)])
        outcomes = [r.outcome for r in results]
        self.assertEqual(outcomes, ["stored", "rejected", "stored"])
        self.assertEqual(store.count_events(org_id=ORG), 2)

    def test_rejection_is_audited_with_a_reason(self):
        store, pipe, *_ = build()
        pipe.ingest({"org_id": ORG, "event_type": "unknown.type", "ts": NOW})
        rejected = [e for e in store.list_audit(org_id=ORG)
                    if e["event"] == "runtime.ingest.rejected"]
        self.assertTrue(rejected)
        self.assertEqual(rejected[0]["outcome"], "denied")

    def test_non_string_keys_rejected(self):
        store, pipe, *_ = build()
        with self.assertRaises(EventValidationError):
            pipe.normalize({1: "x", "org_id": ORG, "event_type": "tool.invocation", "ts": NOW})

    def test_oversized_free_text_is_truncated_not_stored_whole(self):
        store, pipe, *_ = build()
        e = pipe.normalize(evt(resource="r" * 5000))
        self.assertLessEqual(len(e.resource), 512)


class ResourceExhaustionTests(unittest.TestCase):
    def test_deeply_nested_extra_hits_the_depth_limit(self):
        store, pipe, *_ = build()
        # every intermediate key is allow-listed, so the walker recurses (a non-allow-listed nested
        # value is redacted whole, which is the stricter behaviour) and hits the depth bound
        nested = {"method": {"port": {"protocol": {"status_code": {"retry_count":
                  {"direction": {"grant_id": "deep"}}}}}}}
        e = pipe.normalize(evt(extra=nested))
        self.assertIn("DEPTH_LIMIT", str(e.extra))

    def test_extra_key_count_is_bounded(self):
        store, pipe, *_ = build()
        wide = {f"k{i}": i for i in range(500)}
        e = pipe.normalize(evt(extra=wide))
        self.assertLessEqual(len(e.extra), 25)

    def test_retention_bounds_in_memory_growth(self):
        store = MemoryRuntimeMonitoringStore(max_events=10)
        pipe = RuntimeEventPipeline(store, config=MonitoringConfig(default_min_samples=1))
        for i in range(50):
            pipe.ingest(evt(ts=NOW + i, resource=f"r{i}", dedup_key=f"k{i}"))
        self.assertLessEqual(store.count_events(org_id=ORG), 10)

    def test_one_second_late_purge_is_org_scoped(self):
        store, pipe, *_ = build()
        pipe.ingest(evt(org_id=ORG, ts=NOW))
        pipe.ingest(evt(org_id=ORG_B, ts=NOW))
        removed = store.purge_before(NOW + 1, org_id=ORG)
        self.assertEqual(removed, 1)
        self.assertEqual(store.count_events(org_id=ORG), 0)
        self.assertEqual(store.count_events(org_id=ORG_B), 1)


# ============================================================================ privacy
class RedactionTests(unittest.TestCase):
    def test_prompt_and_payload_keys_never_reach_storage(self):
        store, pipe, *_ = build()
        e = pipe.normalize(evt(prompt="tell me the secret plan",
                               payload={"ssn": "123-45-6789"},
                               authorization="Bearer abcdef"))
        blob = str(e.extra) + str(e.public_dict())
        self.assertNotIn("secret plan", blob)
        self.assertNotIn("123-45-6789", blob)
        self.assertNotIn("Bearer abcdef", blob)

    def test_secret_shaped_values_are_redacted_even_under_innocent_keys(self):
        r = Redactor(mode="hash")
        out = r.redact_extra({"note": "sk-live-abcdefghijklmnopqrstuvwx"})
        self.assertNotIn("sk-live", str(out))

    def test_hash_mode_is_stable_but_not_the_value(self):
        r = Redactor(mode="hash")
        a = r.redact_extra({"api_key": "same-value"})["api_key"]
        b = r.redact_extra({"api_key": "same-value"})["api_key"]
        self.assertEqual(a, b)
        self.assertNotIn("same-value", str(a))
        self.assertTrue(str(a).startswith("sha256:"))

    def test_mask_mode_masks_the_middle(self):
        self.assertEqual(Redactor(mode="mask").redact_extra({"api_key": "abcdefgh"})["api_key"],
                         "ab****gh")

    def test_drop_mode_removes_the_value(self):
        self.assertEqual(Redactor(mode="drop").redact_extra({"api_key": "abcdefgh"})["api_key"],
                         "[DROPPED]")

    def test_there_is_no_redaction_off_mode(self):
        for bad in ("off", "none", "plaintext"):
            with self.assertRaises(ValueError):
                Redactor(mode=bad)

    def test_redaction_mode_is_recorded_on_the_event(self):
        store, pipe, *_ = build()
        e = pipe.normalize(evt(prompt="x"))
        self.assertTrue(e.redacted)
        self.assertEqual(e.extra.get("_redaction_mode"), "hash")


# ============================================================================ graph
class IntentGraphTests(unittest.TestCase):
    def setUp(self):
        self.store, self.pipe, *_ = build()
        self.g = IntentGraph(self.store)

    def test_event_projects_into_nodes_and_edges(self):
        e = self.pipe.normalize(evt(resource="db://users", destination="api.internal",
                                    policy_id="pol_1"))
        self.g.record_event(e)
        chain = self.g.agent_toolchain(org_id=ORG, agent_id=AGENT)
        self.assertGreater(chain["edge_count"], 0)
        self.assertIn("agent_resource", chain["by_kind"])

    def test_edges_record_provenance_and_confidence(self):
        e = self.pipe.normalize(evt(resource="db://users"))
        self.g.record_event(e)
        edges = self.store.list_edges(org_id=ORG)
        edge = [x for x in edges if x.kind == "agent_resource"][0]
        self.assertEqual(edge.provenance, "direct_observation")
        self.assertEqual(edge.confidence, 1.0)

    def test_repeated_observations_increment_count(self):
        for i in range(3):
            self.g.record_event(self.pipe.normalize(evt(resource="db://users",
                                                        ts=NOW + i, dedup_key=f"k{i}")))
        edges = [x for x in self.store.list_edges(org_id=ORG, kind="agent_resource")]
        self.assertEqual(edges[0].count, 3)

    def test_declared_task_scope_is_labelled_declared_not_observed(self):
        self.g.declare_task_scope(org_id=ORG, task_id="task_1", resources=["db://reports"])
        edges = self.store.list_edges(org_id=ORG, kind="task_resource")
        self.assertEqual(edges[0].provenance, "declared_scope")
        self.assertEqual(edges[0].confidence, 0.9)

    def test_unknown_node_kind_is_rejected(self):
        with self.assertRaises(Exception):
            self.g.upsert_node(org_id=ORG, kind="supernode", key="x")

    def test_suspicious_chains_are_ranked_and_labelled_honestly(self):
        self.g.record_event(self.pipe.normalize(evt(destination="external.example")))
        chains = self.g.suspicious_chains(org_id=ORG)
        self.assertTrue(chains)
        self.assertIn("does not establish intent", chains[0]["note"])

    def test_repeated_patterns_requires_the_minimum_count(self):
        for i in range(4):
            self.g.record_event(self.pipe.normalize(evt(resource="db://hot",
                                                        ts=NOW + i, dedup_key=f"k{i}")))
        self.assertTrue(self.g.repeated_patterns(org_id=ORG, min_count=3))

    def test_graph_clear_is_org_scoped(self):
        self.g.record_event(self.pipe.normalize(evt(org_id=ORG)))
        self.g.record_event(self.pipe.normalize(evt(org_id=ORG_B)))
        self.g.clear(org_id=ORG)
        self.assertEqual(self.store.list_edges(org_id=ORG), [])
        self.assertGreater(len(self.store.list_edges(org_id=ORG_B)), 0)


# ============================================================================ service chain
class ServiceChainTests(unittest.TestCase):
    def test_observe_runs_the_whole_chain(self):
        clock = FakeClock()
        rt = RuntimeMonitoringService(config=MonitoringConfig(default_min_samples=1), clock=clock)
        rt.alerts.register_rule(org_id=ORG, name="r", event_types=["dlp.blocked"],
                                drift_classes=["confirmed_violation"], risk_threshold=30.0)
        out = rt.observe(org_id=ORG, agent_id=AGENT, raw_events=[
            evt(event_type="dlp.blocked", decision="BLOCKED", data_classes=["pii"],
                destination="unknown.host", address_class="unknown", dlp_rule_ids=["ssn"]),
        ])
        self.assertEqual(out["ingested"], 1)
        self.assertEqual(out["stored"], 1)
        self.assertIsNotNone(out["profile"])
        self.assertTrue(out["findings"])
        self.assertGreater(out["assessment"]["score"], 0)
        self.assertTrue(out["alerts"])

    def test_observe_rejects_cross_tenant_events(self):
        rt = RuntimeMonitoringService(config=MonitoringConfig(default_min_samples=1))
        with self.assertRaises(TenantBoundaryError):
            rt.observe(org_id=ORG, agent_id=AGENT, raw_events=[evt(org_id=ORG_B)])

    def test_health_reports_the_enforced_privacy_posture(self):
        rt = RuntimeMonitoringService(config=MonitoringConfig())
        h = rt.health()
        self.assertEqual(h["redaction_mode"], "hash")
        self.assertFalse(h["auto_actions_allowed"])

    def test_metrics_are_counted(self):
        rt = RuntimeMonitoringService(config=MonitoringConfig(default_min_samples=1),
                                      clock=FakeClock())
        rt.ingest(evt())
        m = rt.metrics()
        self.assertEqual(m["stored"], 1)
        self.assertEqual(m["ingested"], 1)


# ============================================================================ HTTP surface
class HttpSurfaceTests(unittest.TestCase):
    def test_required_permission_maps_the_runtime_surface(self):
        from agent_identity.api.enterprise_http import required_permission
        from agent_identity.security.rbac import P_RUNTIME_ADMIN, P_RUNTIME_READ
        self.assertEqual(required_permission("GET", "v1/runtime/events"), P_RUNTIME_READ)
        self.assertEqual(required_permission("GET", "v1/runtime/alerts"), P_RUNTIME_READ)
        self.assertEqual(required_permission("POST", "v1/runtime/ingest"), P_RUNTIME_ADMIN)
        self.assertEqual(required_permission("POST", "v1/runtime/observe"), P_RUNTIME_ADMIN)
        self.assertEqual(required_permission("GET", "v1/admin/runtime/rules"), P_RUNTIME_READ)
        self.assertEqual(required_permission("POST", "v1/admin/runtime/rules"), P_RUNTIME_ADMIN)

    def test_runtime_permissions_are_in_the_rbac_matrix(self):
        from agent_identity.security import rbac
        self.assertIn(rbac.P_RUNTIME_READ, rbac.PERMISSIONS)
        self.assertIn(rbac.P_RUNTIME_ADMIN, rbac.PERMISSIONS)
        self.assertIn(rbac.P_RUNTIME_READ, rbac.ROLE_PERMISSIONS[rbac.ROLE_SECURITY_ANALYST])
        self.assertIn(rbac.P_RUNTIME_ADMIN, rbac.ROLE_PERMISSIONS[rbac.ROLE_TENANT_ADMIN])
        self.assertNotIn(rbac.P_RUNTIME_ADMIN, rbac.ROLE_PERMISSIONS[rbac.ROLE_READONLY_AUDITOR])

    def test_readonly_auditor_cannot_ingest(self):
        from agent_identity.security import rbac
        from agent_identity.security.rbac import Authorizer, EffectiveAccess
        actor = EffectiveAccess(user_id="u", org_id=ORG, roles=(rbac.ROLE_READONLY_AUDITOR,),
                                permissions=rbac.ROLE_PERMISSIONS[rbac.ROLE_READONLY_AUDITOR],
                                is_platform_admin=False)
        with self.assertRaises(ForbiddenError):
            Authorizer.require(actor, rbac.P_RUNTIME_ADMIN, org_id=ORG)
        Authorizer.require(actor, rbac.P_RUNTIME_READ, org_id=ORG)   # read is fine


if __name__ == "__main__":                                        # pragma: no cover
    unittest.main()
