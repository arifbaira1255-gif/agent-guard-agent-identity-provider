"""Phase 6 composition root -- the autonomous-response plane.

Mirrors ``runtime_monitoring/service.py``: one object that owns the store, the audit recorder and the
sub-services, and exposes the operations the HTTP layer dispatches to. It is injected into the
enterprise HTTP app as an OPTIONAL constructor argument, so when it is absent the ``/v1/response*``
surface 404s and every existing route is byte-for-byte unchanged.

Integration with Phase 5 (requirement 9): :meth:`evaluate_agent` consumes the SAME normalized runtime
events Phase 5 ingests, and :meth:`respond_to_finding` turns a detection into a policy-defined
response. Detection, risk assessment and enforcement remain separate components with clear
interfaces -- this class only coordinates them.
"""
from __future__ import annotations

import time
from typing import Iterable, List, Optional, Sequence

from ..observability.logging import SecurityLogger
from .approvals import ApprovalService
from .audit import ResponseAudit
from .budgets import BudgetService
from .config import ResponseConfig
from .containment import ContainmentEngine, ContainmentIntegrations
from .errors import ResponsePlaneError
from .evidence import EvidenceService
from .incidents import IncidentService
from .loops import LoopDetector
from .models import (ContainmentAction, LoopClassification, ResponseExecution, ResponseLevel)
from .orchestrator import ResponseOrchestrator


class ResponseService:
    """The Phase 6 composition root."""

    def __init__(self, store, *, config: Optional[ResponseConfig] = None,
                 logger: Optional[SecurityLogger] = None, clock=None,
                 policy_service=None, jit_service=None, identity_service=None,
                 egress_service=None, governance_service=None, deployment_adapter=None,
                 risk_service=None):
        self.cfg = config or ResponseConfig()
        self.store = store
        self.clock = clock
        self.risk_service = risk_service
        self.audit = ResponseAudit(store, logger, enabled=self.cfg.audit_enabled, clock=clock)
        self.budgets = BudgetService(store, config=self.cfg, audit=self.audit, clock=clock)
        self.approvals = ApprovalService(store, config=self.cfg, audit=self.audit, clock=clock)
        self.incidents = IncidentService(store, config=self.cfg, audit=self.audit, clock=clock)
        self.evidence = EvidenceService(store, config=self.cfg, audit=self.audit, clock=clock)
        self.loops = LoopDetector(config=self.cfg, audit=self.audit, clock=clock)
        self.integrations = ContainmentIntegrations(
            policy_service=policy_service, jit_service=jit_service,
            identity_service=identity_service, egress_service=egress_service,
            governance_service=governance_service, deployment_adapter=deployment_adapter,
            budget_service=self.budgets)
        self.containment = ContainmentEngine(integrations=self.integrations, config=self.cfg,
                                             audit=self.audit, clock=clock)
        self.orchestrator = ResponseOrchestrator(
            store=store, containment=self.containment, evidence=self.evidence,
            incidents=self.incidents, audit=self.audit, config=self.cfg, clock=clock)

    def _now(self) -> float:
        return self.clock.now() if self.clock is not None else time.time()

    # ================================================================== detection
    def observe_events(self, events: Iterable, *, now: Optional[float] = None) -> int:
        """Feed normalized runtime events into the loop detector's bounded window."""
        return self.loops.observe(events, now=now)

    def evaluate_agent(self, *, org_id: str, agent_id: str, task_id: Optional[str] = None,
                       now: Optional[float] = None, persist: bool = True) -> List[dict]:
        """Detect repetitive/runaway activity for one agent and (optionally) persist the findings."""
        budget = self.budgets.get_budget(org_id=org_id, agent_id=agent_id, task_id=task_id)
        findings = self.loops.detect(org_id=org_id, agent_id=agent_id, now=now, budget=budget,
                                     task_id=task_id)
        if persist:
            for f in findings:
                self.store.put_loop_finding(f)
                self.audit.record("response.loop.finding", org_id=org_id, agent_id=agent_id,
                                  outcome=f.classification, reason=f.pattern,
                                  extra={"finding_id": f.finding_id, "pattern": f.pattern,
                                         "subject": f.subject[:200],
                                         "observed": f.observed_count,
                                         "threshold": f.threshold})
        return [f.to_dict() for f in findings]

    def list_findings(self, *, org_id: str, agent_id: Optional[str] = None,
                      pattern: Optional[str] = None, since: Optional[float] = None,
                      limit: int = 100) -> List[dict]:
        return [f.to_dict() for f in self.store.list_loop_findings(
            org_id=org_id, agent_id=agent_id, pattern=pattern, since=since, limit=limit)]

    # ================================================================== response
    def respond_to_finding(self, *, org_id: str, agent_id: str, finding: dict,
                           authorized_by: Optional[str] = None, auto: bool = False,
                           approved: bool = False, incident_id: Optional[str] = None,
                           destination: Optional[str] = None, tool_id: Optional[str] = None,
                           idempotency_key: Optional[str] = None) -> dict:
        """Turn a detection into a policy-defined response.

        The level is derived from the finding's classification and (when a risk service is wired) the
        Phase 5 risk band. A statistical anomaly is capped at RESTRICT by
        :meth:`ResponseOrchestrator.select_level`.
        """
        risk_band = None
        risk_score = None
        if self.risk_service is not None:
            try:
                assessment = self.risk_service.assess(org_id=org_id, agent_id=agent_id)
                risk_band = getattr(assessment, "band", None)
                risk_score = getattr(assessment, "score", None)
            except Exception:  # noqa: BLE001 - risk is advisory; never block the response path
                risk_band = None
        level = self.orchestrator.select_level(
            risk_band=risk_band, classification=finding.get("classification"),
            severity=finding.get("severity"))
        self.audit.record("response.level.selected", org_id=org_id, agent_id=agent_id,
                          outcome=level.value,
                          extra={"classification": finding.get("classification"),
                                 "risk_band": risk_band, "risk_score": risk_score})
        if level == ResponseLevel.OBSERVE:
            return {"level": level.value, "execution": None,
                    "note": "observe-only: no containment action taken"}
        if incident_id is None:
            inc = self.incidents.open_or_correlate(
                org_id=org_id, title=f"{finding.get('pattern', 'anomaly')} on {agent_id}",
                agent_id=agent_id, subject=finding.get("subject"),
                severity=finding.get("severity", "medium"),
                detection_source="loop_detector", finding_ids=(finding.get("finding_id"),),
                risk_score=risk_score, risk_band=risk_band)
            incident_id = inc.incident_id
        ex = self.orchestrator.execute(
            org_id=org_id, level=level, agent_id=agent_id, incident_id=incident_id,
            trigger=finding.get("pattern", "finding"), authorized_by=authorized_by,
            approved=approved, auto=auto, destination=destination, tool_id=tool_id,
            reason=finding.get("detail", ""), idempotency_key=idempotency_key)
        return {"level": level.value, "execution": ex.public_dict(), "incident_id": incident_id}

    def contain(self, *, org_id: str, level: str, agent_id: Optional[str] = None,
                incident_id: Optional[str] = None, authorized_by: Optional[str] = None,
                approved: bool = False, auto: bool = False, destination: Optional[str] = None,
                tool_id: Optional[str] = None, reason: str = "",
                idempotency_key: Optional[str] = None) -> ResponseExecution:
        """Execute a containment response at an explicitly requested level."""
        return self.orchestrator.execute(
            org_id=org_id, level=ResponseLevel.coerce(level), agent_id=agent_id,
            incident_id=incident_id, trigger="manual", authorized_by=authorized_by,
            approved=approved, auto=auto, destination=destination, tool_id=tool_id, reason=reason,
            idempotency_key=idempotency_key)

    def rollback(self, *, org_id: str, response_id: str, authorized_by: Optional[str] = None,
                 reason: str = "rollback") -> ResponseExecution:
        return self.orchestrator.rollback(org_id=org_id, response_id=response_id,
                                          authorized_by=authorized_by, reason=reason)

    def get_response(self, *, org_id: str, response_id: str) -> Optional[dict]:
        ex = self.orchestrator.get(org_id=org_id, response_id=response_id)
        return ex.public_dict() if ex else None

    def list_responses(self, *, org_id: str, incident_id: Optional[str] = None,
                       agent_id: Optional[str] = None, limit: int = 100) -> List[dict]:
        return [r.public_dict() for r in self.orchestrator.list(
            org_id=org_id, incident_id=incident_id, agent_id=agent_id, limit=limit)]

    # ================================================================== audit
    def verify_audit(self, *, org_id: Optional[str] = None, limit: int = 10_000) -> dict:
        return self.audit.verify_chain(org_id=org_id, limit=limit)

    def list_audit(self, *, org_id: Optional[str] = None, limit: int = 100) -> List[dict]:
        return self.audit.list(org_id=org_id, limit=limit)
