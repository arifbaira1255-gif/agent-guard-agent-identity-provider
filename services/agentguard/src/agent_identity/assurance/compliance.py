"""Phase 7 compliance evidence and control mapping.

Maps IMPLEMENTED security controls and COLLECTED evidence to framework requirements. Mappings are
configurable DATA (a built-in seed catalogue plus operator-supplied mappings), not hard-coded claims.

Honesty rules (requirement 5)
-----------------------------
* ``verification_status`` distinguishes a technical control that exists and is evidenced
  (``implemented``) from one that requires an organizational process (``organizational``), one that
  is only partially evidenced (``evidence_collected`` / ``incomplete``) and one that is claimed but
  unverified (``unverified``).
* Generating a report is NOT a claim of certification or legal compliance. The report says so
  explicitly, and framework mappings must be reviewed for the organization's actual scope.
* Evidence carries its source, timestamp and provenance; a report is built from ACTUAL system
  records, never from a template of assertions.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Sequence

from ..security.ids import new_id
from .config import AssuranceConfig, KNOWN_FRAMEWORKS
from .errors import UnknownFrameworkError
from .models import ComplianceControlMapping, Provenance, VerificationStatus
from .store import AssuranceStore

#: Built-in seed catalogue. Each entry is a MAPPING TEMPLATE: the ``evidence_source`` names the
#: AgentGuard component that produces the evidence, and ``verification_status`` states honestly how
#: far the control is verified. Operators extend/override these for their own scope.
_SEED: Sequence[dict] = (
    # ---- SOC 2 (Trust Services Criteria) ------------------------------------------------------
    {"framework": "soc2", "control_id": "CC6.1", "control_title": "Logical access controls",
     "description": "Access to systems is restricted to authorized identities.",
     "scope": "platform", "evidence_source": "security.rbac + policy engine decisions",
     "owner_component": "security/rbac.py, policy/service.py",
     "verification_status": VerificationStatus.IMPLEMENTED.value},
    {"framework": "soc2", "control_id": "CC6.6", "control_title": "Boundary protection",
     "description": "Egress is governed and data loss is prevented at the boundary.",
     "scope": "platform", "evidence_source": "egress gateway + DLP detections",
     "owner_component": "egress/gateway.py, egress/dlp.py",
     "verification_status": VerificationStatus.IMPLEMENTED.value},
    {"framework": "soc2", "control_id": "CC7.2", "control_title": "Monitoring for anomalies",
     "description": "Security events are monitored and anomalies are detected.",
     "scope": "platform", "evidence_source": "runtime monitoring + drift detection + alerts",
     "owner_component": "runtime_monitoring/",
     "verification_status": VerificationStatus.IMPLEMENTED.value},
    {"framework": "soc2", "control_id": "CC7.3", "control_title": "Incident response",
     "description": "Detected incidents are evaluated, contained and reviewed.",
     "scope": "platform", "evidence_source": "response plane incidents + containment executions",
     "owner_component": "response/incidents.py, response/containment.py",
     "verification_status": VerificationStatus.IMPLEMENTED.value},
    {"framework": "soc2", "control_id": "CC7.4", "control_title": "Audit logging integrity",
     "description": "Security-relevant activity is logged with integrity protection.",
     "scope": "platform", "evidence_source": "tamper-evident audit chain + signed checkpoints",
     "owner_component": "assurance/audit.py",
     "verification_status": VerificationStatus.IMPLEMENTED.value,
     "known_gaps": ("Hash chaining does not prevent truncation without external anchoring of "
                    "checkpoints.",)},
    {"framework": "soc2", "control_id": "CC8.1", "control_title": "Change management",
     "description": "Changes to security controls are authorized, tested and reversible.",
     "scope": "platform", "evidence_source": "policy proposal lifecycle + approvals + rollback",
     "owner_component": "assurance/lifecycle.py",
     "verification_status": VerificationStatus.IMPLEMENTED.value},
    # ---- ISO/IEC 27001 ------------------------------------------------------------------------
    {"framework": "iso27001", "control_id": "A.5.15", "control_title": "Access control",
     "description": "Access to information is controlled by policy.",
     "scope": "platform", "evidence_source": "policy engine + JIT grants",
     "owner_component": "policy/",
     "verification_status": VerificationStatus.IMPLEMENTED.value},
    {"framework": "iso27001", "control_id": "A.8.15", "control_title": "Logging",
     "description": "Event logs are produced, stored and protected.",
     "scope": "platform", "evidence_source": "tamper-evident audit chain",
     "owner_component": "assurance/audit.py",
     "verification_status": VerificationStatus.IMPLEMENTED.value},
    {"framework": "iso27001", "control_id": "A.8.16", "control_title": "Monitoring activities",
     "description": "Networks, systems and applications are monitored for anomalous behaviour.",
     "scope": "platform", "evidence_source": "runtime monitoring + SIEM export",
     "owner_component": "runtime_monitoring/, assurance/siem.py",
     "verification_status": VerificationStatus.IMPLEMENTED.value},
    {"framework": "iso27001", "control_id": "A.5.24", "control_title": "Incident management",
     "description": "Information security incidents are managed through a defined process.",
     "scope": "organizational", "evidence_source": "incident lifecycle records",
     "owner_component": "response/incidents.py",
     "verification_status": VerificationStatus.ORGANIZATIONAL.value,
     "known_gaps": ("Requires an organizational incident-management process and named owners.",)},
    # ---- GDPR ---------------------------------------------------------------------------------
    {"framework": "gdpr", "control_id": "Art.5(1)(f)", "control_title": "Integrity and confidentiality",
     "description": "Personal data is processed with appropriate security.",
     "scope": "platform", "evidence_source": "DLP + egress governance + redaction",
     "owner_component": "egress/dlp.py, runtime_monitoring/redaction.py",
     "verification_status": VerificationStatus.IMPLEMENTED.value},
    {"framework": "gdpr", "control_id": "Art.30", "control_title": "Records of processing",
     "description": "Records of processing activities are maintained.",
     "scope": "organizational", "evidence_source": "audit chain + compliance evidence reports",
     "owner_component": "assurance/audit.py, assurance/compliance.py",
     "verification_status": VerificationStatus.ORGANIZATIONAL.value,
     "known_gaps": ("Requires an organizational record-of-processing register; the platform "
                    "provides the technical evidence only.",)},
    {"framework": "gdpr", "control_id": "Art.32", "control_title": "Security of processing",
     "description": "Technical and organizational measures ensure a level of security appropriate "
                    "to the risk.",
     "scope": "platform", "evidence_source": "identity, policy, egress, monitoring, audit",
     "owner_component": "agent_identity/",
     "verification_status": VerificationStatus.IMPLEMENTED.value},
    # ---- EU AI Act ----------------------------------------------------------------------------
    {"framework": "eu_ai_act", "control_id": "Art.12", "control_title": "Record-keeping",
     "description": "High-risk AI systems automatically record events over their lifetime.",
     "scope": "platform", "evidence_source": "runtime event pipeline + tamper-evident audit",
     "owner_component": "runtime_monitoring/pipeline.py, assurance/audit.py",
     "verification_status": VerificationStatus.IMPLEMENTED.value},
    {"framework": "eu_ai_act", "control_id": "Art.14", "control_title": "Human oversight",
     "description": "High-risk AI systems are designed for effective human oversight.",
     "scope": "platform", "evidence_source": "human approval workflow + emergency stops",
     "owner_component": "response/approvals.py, assurance/lifecycle.py",
     "verification_status": VerificationStatus.IMPLEMENTED.value},
    {"framework": "eu_ai_act", "control_id": "Art.15", "control_title": "Accuracy, robustness, cybersecurity",
     "description": "High-risk AI systems achieve appropriate accuracy, robustness and cybersecurity.",
     "scope": "organizational", "evidence_source": "security testing + limitations documentation",
     "owner_component": "tests/, docs/",
     "verification_status": VerificationStatus.INCOMPLETE.value,
     "known_gaps": ("Requires system-specific accuracy/robustness evaluation and a conformity "
                    "assessment; the platform provides security evidence only.",)},
)


class ComplianceService:
    """Control mapping + evidence reporting over ACTUAL system records."""

    def __init__(self, store: AssuranceStore, *, config: Optional[AssuranceConfig] = None,
                 audit=None, clock=None):
        self.store = store
        self.cfg = config or AssuranceConfig()
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ================================================================== seeding
    def seed_catalogue(self, *, actor: str = "system") -> int:
        """Install the built-in mapping catalogue (idempotent by (framework, control_id))."""
        existing = {(m.framework, m.control_id) for m in self.store.list_mappings(limit=10_000)}
        n = 0
        for tpl in _SEED:
            if (tpl["framework"], tpl["control_id"]) in existing:
                continue
            if tpl["framework"] not in self.cfg.compliance_frameworks:
                continue
            m = ComplianceControlMapping(
                mapping_id=new_id("cmp"), framework=tpl["framework"], control_id=tpl["control_id"],
                control_title=tpl["control_title"], description=tpl["description"],
                scope=tpl["scope"], evidence_source=tpl["evidence_source"],
                owner_component=tpl["owner_component"],
                verification_status=tpl["verification_status"],
                known_gaps=tuple(tpl.get("known_gaps", ())), last_review=self._now(),
                provenance=Provenance.OBSERVED_FACT.value)
            self.store.put_mapping(m)
            n += 1
        if self.audit is not None:
            self.audit.record("assurance.compliance.seeded", actor_user_id=actor,
                              detail={"installed": n})
        return n

    def upsert_mapping(self, *, framework: str, control_id: str, control_title: str,
                       description: str, scope: str, evidence_source: str, owner_component: str,
                       verification_status: str, known_gaps: Sequence[str] = (),
                       evidence_refs: Sequence[str] = (), actor: str = "system"
                       ) -> ComplianceControlMapping:
        if framework not in KNOWN_FRAMEWORKS:
            raise UnknownFrameworkError(f"unknown framework: {framework}")
        if verification_status not in {v.value for v in VerificationStatus}:
            raise UnknownFrameworkError(f"unknown verification status: {verification_status}")
        # replace any existing mapping for the same (framework, control_id)
        for m in self.store.list_mappings(framework=framework, limit=10_000):
            if m.control_id == control_id:
                self.store.put_mapping(ComplianceControlMapping(
                    mapping_id=m.mapping_id, framework=framework, control_id=control_id,
                    control_title=control_title, description=description, scope=scope,
                    evidence_source=evidence_source, owner_component=owner_component,
                    verification_status=verification_status, evidence_ts=self._now(),
                    known_gaps=tuple(known_gaps), last_review=self._now(),
                    evidence_refs=tuple(evidence_refs)))
                return self.store.get_mapping(m.mapping_id)
        m = ComplianceControlMapping(
            mapping_id=new_id("cmp"), framework=framework, control_id=control_id,
            control_title=control_title, description=description, scope=scope,
            evidence_source=evidence_source, owner_component=owner_component,
            verification_status=verification_status, evidence_ts=self._now(),
            known_gaps=tuple(known_gaps), last_review=self._now(),
            evidence_refs=tuple(evidence_refs))
        self.store.put_mapping(m)
        return m

    # ================================================================== reporting
    def report(self, *, framework: Optional[str] = None, org_id: Optional[str] = None) -> dict:
        """Build an evidence report from ACTUAL mappings + collected evidence.

        The report explicitly states that it is NOT a certification or a legal-compliance claim.
        """
        if framework is not None and framework not in KNOWN_FRAMEWORKS:
            raise UnknownFrameworkError(f"unknown framework: {framework}")
        mappings = self.store.list_mappings(framework=framework,
                                            limit=self.cfg.compliance_max_evidence)
        by_status: Dict[str, int] = {}
        controls = []
        stale_cutoff = self._now() - self.cfg.compliance_evidence_stale_days * 86400
        for m in mappings:
            by_status[m.verification_status] = by_status.get(m.verification_status, 0) + 1
            stale = m.evidence_ts is not None and m.evidence_ts < stale_cutoff
            controls.append({**m.public_dict(), "evidence_stale": stale})
        # attach real evidence counts where an org is given
        evidence_summary = {}
        if org_id is not None:
            ev = self.store.list_evidence(org_id=org_id, limit=self.cfg.compliance_max_evidence)
            for e in ev:
                evidence_summary[e.kind] = evidence_summary.get(e.kind, 0) + 1
        return {
            "generated_at": self._now(),
            "framework": framework or "all",
            "org_id": org_id,
            "disclaimer": ("This report maps implemented controls and collected evidence to framework "
                           "requirements. It is NOT a certification and does NOT by itself establish "
                           "legal compliance. Framework mappings must be reviewed for the "
                           "organization's actual scope and applicable obligations."),
            "summary": {"total_controls": len(controls), "by_verification_status": by_status},
            "evidence_summary": evidence_summary,
            "controls": controls,
        }

    def list_mappings(self, *, framework: Optional[str] = None) -> List[ComplianceControlMapping]:
        return self.store.list_mappings(framework=framework, limit=self.cfg.compliance_max_evidence)
