"""Phase 5 runtime-monitoring composition root.

:class:`RuntimeMonitoringService` wires the store, the ingest pipeline, behaviour profiles, drift
detection, the intent graph, risk scoring, alerting and the policy integration into one object -- the
same shape as ``EgressService`` (Phase 4) and ``GovernanceService`` (Step 11).

It also exposes a small, uniform ``metrics()``/``health()`` surface for the observability stack, and a
single ``observe(...)`` convenience that runs the whole analysis chain for one batch of events:

    ingest → (rebuild profile) → drift detect → risk assess → graph project → evaluate alerts

Every step is optional and independently callable, and the chain never enforces anything: alerts may
request response actions, but those delegate to the existing policy/JIT mechanisms.
"""
from __future__ import annotations

import threading
from typing import Dict, Iterable, List, Optional, Sequence

from .alerts import AlertService
from .audit import RuntimeMonitoringAudit
from .config import MonitoringConfig
from .drift import DriftDetector
from .graph import IntentGraph
from .memory_store import MemoryRuntimeMonitoringStore
from .models import (Alert, DriftFinding, RiskAssessment, RuntimeEvent)
from .pipeline import IngestResult, RuntimeEventPipeline
from .policy_integration import PolicyIntegration
from .profiles import BehaviorProfileService
from .risk import RiskScorer, RiskRules, band_thresholds
from .store import RuntimeMonitoringStore


class RuntimeMonitoringService:
    """The Phase 5 composition root."""

    def __init__(self, store: Optional[RuntimeMonitoringStore] = None, *,
                 config: Optional[MonitoringConfig] = None, policy_service=None,
                 jit_service=None, approval_service=None, logger=None, clock=None,
                 auto_register_rule: bool = False):
        self.cfg = config or MonitoringConfig()
        self.store = store or MemoryRuntimeMonitoringStore(max_events=self.cfg.max_events_retained)
        self.audit = RuntimeMonitoringAudit(self.store, logger=logger,
                                            enabled=self.cfg.audit_enabled, clock=clock)
        self.integration = PolicyIntegration(policy_service=policy_service, jit_service=jit_service,
                                             approval_service=approval_service)
        self.pipeline = RuntimeEventPipeline(self.store, config=self.cfg, audit=self.audit,
                                             clock=clock)
        self.profiles = BehaviorProfileService(self.store, config=self.cfg, audit=self.audit,
                                               clock=clock)
        self.drift = DriftDetector(config=self.cfg, audit=self.audit, clock=clock)
        self.graph = IntentGraph(self.store, audit=self.audit, clock=clock)
        self.risk = RiskScorer(config=self.cfg, audit=self.audit, clock=clock)
        self.alerts = AlertService(self.store, config=self.cfg, audit=self.audit,
                                   integration=self.integration, clock=clock)
        self._metrics_lock = threading.Lock()
        self._metrics = {"ingested": 0, "stored": 0, "rejected": 0, "duplicates": 0,
                         "sampled_out": 0, "late": 0, "findings": 0, "assessments": 0,
                         "alerts_raised": 0, "alerts_deduped": 0, "responses_taken": 0,
                         "graph_edges": 0}
        self._auto_register_rule = auto_register_rule

    # ------------------------------------------------------------------ ingest
    def ingest(self, raw: dict, *, claimed_org: Optional[str] = None,
               now: Optional[float] = None) -> IngestResult:
        res = self.pipeline.ingest(raw, claimed_org=claimed_org, now=now)
        with self._metrics_lock:
            self._metrics["ingested"] += 1
            if res.outcome == "stored":
                self._metrics["stored"] += 1
            elif res.outcome == "rejected":
                self._metrics["rejected"] += 1
            elif res.outcome == "duplicate":
                self._metrics["duplicates"] += 1
            elif res.outcome == "sampled_out":
                self._metrics["sampled_out"] += 1
            if res.event is not None and res.event.late:
                self._metrics["late"] += 1
        return res

    def ingest_many(self, raws: Iterable[dict], *, claimed_org: Optional[str] = None,
                    now: Optional[float] = None) -> List[IngestResult]:
        return [self.ingest(r, claimed_org=claimed_org, now=now) for r in raws]

    # ------------------------------------------------------------------ full chain
    def observe(self, *, org_id: str, agent_id: str, raw_events: Sequence[dict],
                declared_capabilities: Optional[Iterable[str]] = None,
                declared_tools: Optional[Iterable[str]] = None,
                declared_destinations: Optional[Iterable[str]] = None,
                rebuild_profile: bool = True, now: Optional[float] = None) -> dict:
        """Ingest a batch and run the full analysis chain for one agent. Returns a summary dict."""
        results = self.ingest_many(raw_events, claimed_org=org_id, now=now)
        stored = [r.event for r in results if r.event is not None and r.event.outcome != "rejected"
                  and not r.event.sampled]

        if rebuild_profile:
            self.profiles.build(org_id=org_id, agent_id=agent_id, now=now)
        profile = self.profiles.get(org_id=org_id, agent_id=agent_id)

        findings = self.drift.detect(org_id=org_id, agent_id=agent_id, events=stored,
                                     profile=profile, declared_capabilities=declared_capabilities,
                                     declared_tools=declared_tools,
                                     declared_destinations=declared_destinations, now=now)
        for f in findings:
            self.store.put_finding(f)

        assessment = self.risk.assess(org_id=org_id, agent_id=agent_id, events=stored,
                                      findings=findings,
                                      baseline_peak_per_hour=(profile.max_events_per_hour
                                                              if profile else None), now=now)
        self.store.put_assessment(assessment)

        edges = 0
        for ev in stored:
            self.graph.record_event(ev)
            edges += 1

        raised: List[Alert] = []
        raised += self.alerts.evaluate_events(org_id=org_id, events=stored, agent_id=agent_id)
        raised += self.alerts.evaluate_findings(org_id=org_id, findings=findings)
        raised += self.alerts.evaluate_assessment(org_id=org_id, assessment=assessment)

        with self._metrics_lock:
            self._metrics["findings"] += len(findings)
            self._metrics["assessments"] += 1
            self._metrics["alerts_raised"] += len(raised)
            self._metrics["graph_edges"] += edges

        return {"ingested": len(results), "stored": len(stored),
                "rejected": [r.to_dict() for r in results if r.outcome == "rejected"],
                "duplicates": sum(1 for r in results if r.outcome == "duplicate"),
                "sampled_out": sum(1 for r in results if r.outcome == "sampled_out"),
                "profile": profile.public_dict() if profile else None,
                "findings": [f.to_dict() for f in findings],
                "assessment": assessment.to_dict(),
                "alerts": [a.to_dict() for a in raised]}

    # ------------------------------------------------------------------ reads
    def investigate(self, **kwargs) -> dict:
        return self.pipeline.investigate(**kwargs)

    def correlate(self, **kwargs):
        return self.pipeline.correlate(**kwargs)

    def list_events(self, **kwargs):
        return self.store.list_events(**kwargs)

    def aggregate_by_type(self, **kwargs) -> dict:
        return self.store.aggregate_by_type(**kwargs)

    # ------------------------------------------------------------------ retention
    def apply_retention(self, *, org_id: Optional[str] = None,
                        now: Optional[float] = None) -> int:
        """Purge telemetry older than the configured retention horizon (org-scoped when given)."""
        current = now if now is not None else None
        import time as _t
        cutoff = (current if current is not None else _t.time()) - self.cfg.retention_days * 86400
        removed = self.store.purge_before(cutoff, org_id=org_id)
        self.audit.record("runtime.retention.purged", org_id=org_id, outcome="ok",
                          extra={"removed": removed, "cutoff": round(cutoff, 3)})
        return removed

    # ------------------------------------------------------------------ ops
    def risk_rule_summary(self) -> dict:
        return band_thresholds(self.cfg)

    def register_default_rule(self, *, org_id: str, name: str = "default",
                              min_severity: str = "medium") -> Alert:
        return self.alerts.register_rule(org_id=org_id, name=name, min_severity=min_severity,
                                         event_types=("policy.enforcement.failure",
                                                      "authorization.failure", "dlp.blocked"),
                                         drift_classes=("confirmed_violation",),
                                         risk_threshold=self.cfg.risk_band_high)

    def metrics(self) -> dict:
        with self._metrics_lock:
            m = dict(self._metrics)
        m["policy_integration_available"] = self.integration.available
        m["auto_actions_allowed"] = self.cfg.allow_auto_actions
        return m

    def health(self) -> dict:
        return {"status": "ok", "component": "runtime_monitoring",
                "environment": self.cfg.environment, "redaction_mode": self.cfg.redaction_mode,
                "sampling_enabled": self.cfg.sampling_enabled,
                "retention_days": self.cfg.retention_days,
                "auto_actions_allowed": self.cfg.allow_auto_actions,
                "policy_integration_available": self.integration.available}