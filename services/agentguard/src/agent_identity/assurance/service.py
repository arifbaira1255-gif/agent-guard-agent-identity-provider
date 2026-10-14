"""Phase 7 composition root -- the assurance plane.

Mirrors ``response/service.py`` and ``runtime_monitoring/service.py``: one object that owns the store,
the tamper-evident audit chain and the sub-services, and exposes the operations the HTTP layer
dispatches to. It is injected into the enterprise HTTP app as an OPTIONAL constructor argument, so
when it is absent the ``/v1/assurance*`` surface 404s and every existing route is byte-for-byte
unchanged.

It introduces NO second database, NO second event pipeline and NO competing authorization path:
policy changes go through the EXISTING policy engine, and every lifecycle transition is recorded in
the tamper-evident audit chain.
"""
from __future__ import annotations

import time
from typing import List, Optional, Sequence

from ..observability.logging import SecurityLogger
from .audit import AuditSigner, LocalEd25519Signer, TamperEvidentAudit
from .compliance import ComplianceService
from .config import AssuranceConfig
from .correlation import CorrelationService
from .lifecycle import PolicyLifecycleService
from .models import SecurityEvidence, SiemEvent
from .recommendation_engine import RecommendationEngine
from .siem import SiemService
from .store import AssuranceStore


class AssuranceService:
    """The Phase 7 composition root."""

    def __init__(self, store: AssuranceStore, *, config: Optional[AssuranceConfig] = None,
                 logger: Optional[SecurityLogger] = None, clock=None, signer: Optional[AuditSigner] = None,
                 policy_service=None):
        self.cfg = config or AssuranceConfig()
        self.store = store
        self.clock = clock
        self.policy = policy_service
        if signer is None and self.cfg.audit_require_signature:
            # Development default: an in-process Ed25519 signer. Production MUST inject a KMS signer
            # (KmsAuditSigner) -- the local signer refuses to run in staging/production.
            signer = LocalEd25519Signer(environment=self.cfg.environment,
                                        key_id=self.cfg.audit_signing_key_id,
                                        domain=self.cfg.audit_signature_domain)
        self.audit = TamperEvidentAudit(store, config=self.cfg, signer=signer, logger=logger,
                                        clock=clock)
        self.recommendations = RecommendationEngine(config=self.cfg, clock=clock)
        self.lifecycle = PolicyLifecycleService(store, policy_service=policy_service, config=self.cfg,
                                                audit=self.audit, clock=clock)
        self.compliance = ComplianceService(store, config=self.cfg, audit=self.audit, clock=clock)
        self.siem = SiemService(store, config=self.cfg, logger=logger, clock=clock)
        self.correlation = CorrelationService(store, config=self.cfg, clock=clock)

    def _now(self) -> float:
        return self.clock.now() if self.clock is not None else time.time()

    # ================================================================== evidence
    def record_evidence(self, *, org_id: str, kind: str, summary: str, source: str = "",
                        agent_id: Optional[str] = None, ref: Optional[str] = None, payload=None,
                        severity: str = "medium", count: int = 1,
                        correlation_id: Optional[str] = None, detail: Optional[dict] = None
                        ) -> SecurityEvidence:
        """Record a trusted security signal (referenced + digested, never copied)."""
        import hashlib
        import json
        digest = None
        if payload is not None:
            blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
            digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        from ..security.ids import new_id
        e = SecurityEvidence(evidence_id=new_id("evd"), org_id=org_id, kind=kind, ts=self._now(),
                             summary=summary[:512], source=source[:512], agent_id=agent_id, ref=ref,
                             digest=digest, severity=severity, count=max(1, int(count)),
                             correlation_id=correlation_id, detail=detail)
        self.store.put_evidence(e)
        self.audit.record("assurance.evidence.recorded", org_id=org_id, actor_user_id=None,
                          detail={"evidence_id": e.evidence_id, "kind": kind})
        return e

    def list_evidence(self, *, org_id: str, kind: Optional[str] = None, limit: int = 500) -> List[dict]:
        return [e.public_dict() for e in self.store.list_evidence(org_id=org_id, kind=kind,
                                                                  limit=limit)]

    # ================================================================== recommendations
    def analyze(self, *, org_id: str, persist: bool = True) -> List[dict]:
        """Analyze trusted evidence and produce explainable recommendations."""
        evidence = self.store.list_evidence(org_id=org_id, limit=self.cfg.recommendation_max_evidence)
        recs = self.recommendations.analyze(org_id=org_id, evidence=evidence)
        if persist:
            for r in recs:
                self.store.put_recommendation(r)
            self.audit.record("assurance.recommendations.analyzed", org_id=org_id,
                              detail={"count": len(recs)})
        return [r.public_dict() for r in recs]

    def list_recommendations(self, *, org_id: str, status: Optional[str] = None,
                             limit: int = 100) -> List[dict]:
        return [r.public_dict() for r in self.store.list_recommendations(org_id=org_id, status=status,
                                                                         limit=limit)]

    def get_recommendation(self, *, org_id: str, recommendation_id: str) -> Optional[dict]:
        r = self.store.get_recommendation(recommendation_id, org_id=org_id)
        return r.public_dict() if r else None

    # ================================================================== lifecycle (delegated)
    def create_proposal(self, actor, **kw):
        return self.lifecycle.create_proposal(actor, **kw)

    def validate_proposal(self, actor, proposal_id, *, org_id):
        return self.lifecycle.validate(actor, proposal_id, org_id=org_id)

    def simulate_proposal(self, actor, proposal_id, *, org_id, cases):
        return self.lifecycle.simulate(actor, proposal_id, org_id=org_id, cases=cases)

    def submit_proposal(self, actor, proposal_id, *, org_id):
        return self.lifecycle.submit_for_approval(actor, proposal_id, org_id=org_id)

    def decide_proposal(self, actor, proposal_id, *, org_id, decision, reason=""):
        return self.lifecycle.decide(actor, proposal_id, org_id=org_id, decision=decision,
                                     reason=reason)

    def start_canary(self, actor, proposal_id, *, org_id):
        return self.lifecycle.start_canary(actor, proposal_id, org_id=org_id)

    def record_canary(self, actor, proposal_id, *, org_id, samples, deny_delta):
        return self.lifecycle.record_canary(actor, proposal_id, org_id=org_id, samples=samples,
                                            deny_delta=deny_delta)

    def activate_proposal(self, actor, proposal_id, *, org_id):
        return self.lifecycle.activate(actor, proposal_id, org_id=org_id)

    def rollback_proposal(self, actor, proposal_id, *, org_id, to_version=None):
        return self.lifecycle.rollback(actor, proposal_id, org_id=org_id, to_version=to_version)

    def emergency_change(self, actor, **kw):
        return self.lifecycle.emergency_change(actor, **kw)

    def get_proposal(self, actor, proposal_id, *, org_id):
        return self.lifecycle.get(actor, proposal_id, org_id=org_id)

    def list_proposals(self, actor, *, org_id, status=None):
        return self.lifecycle.list(actor, org_id=org_id, status=status)

    # ================================================================== audit
    def verify_audit(self, *, org_id: Optional[str] = None) -> dict:
        return self.audit.verify_all(org_id=org_id)

    def list_audit(self, *, org_id: Optional[str] = None, limit: int = 100) -> List[dict]:
        return self.audit.list(org_id=org_id, limit=limit)

    def checkpoint(self, *, org_id: Optional[str] = None) -> Optional[dict]:
        cp = self.audit.checkpoint(org_id=org_id)
        return cp.public_dict() if cp else None

    # ================================================================== compliance
    def seed_compliance(self, *, actor: str = "system") -> int:
        return self.compliance.seed_catalogue(actor=actor)

    def compliance_report(self, *, framework: Optional[str] = None,
                          org_id: Optional[str] = None) -> dict:
        return self.compliance.report(framework=framework, org_id=org_id)

    def list_controls(self, *, framework: Optional[str] = None) -> List[dict]:
        return [m.public_dict() for m in self.compliance.list_mappings(framework=framework)]

    # ================================================================== SIEM + correlation
    def export_event(self, event: SiemEvent) -> dict:
        """Normalize -> dedup -> enqueue for export. Returns the ingest + enqueue status."""
        ingest = self.correlation.ingest(event)
        if ingest.get("duplicate"):
            return {"accepted": False, "duplicate": True, "queued": False}
        queued = self.siem.enqueue(event)
        return {"accepted": True, "duplicate": False, **queued}

    def flush_siem(self, *, max_batches: int = 100) -> dict:
        return self.siem.flush(max_batches=max_batches)

    def correlate(self, *, org_id: str, window_s: Optional[int] = None,
                  min_events: int = 3) -> List[dict]:
        return [f.public_dict() for f in self.correlation.correlate(org_id=org_id, window_s=window_s,
                                                                    min_events=min_events)]

    def list_correlations(self, *, org_id: str, limit: int = 200) -> List[dict]:
        return self.correlation.list_findings(org_id=org_id, limit=limit)

    # ================================================================== health
    def health(self) -> dict:
        siem = self.siem.health()
        audit_ok = True
        try:
            audit_ok = bool(self.audit.verify_chain(org_id=None, limit=1_000).get("ok"))
        except Exception:                                            # noqa: BLE001
            audit_ok = False
        return {"status": "ok" if (siem.get("ready") and audit_ok) else "degraded",
                "plane": "assurance", "audit_chain_ok": audit_ok,
                "audit_require_signature": self.cfg.audit_require_signature,
                "siem": siem}
