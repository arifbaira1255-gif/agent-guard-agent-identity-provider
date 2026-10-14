"""Phase 7 safe policy lifecycle.

Integrates recommendations with the EXISTING policy engine (``policy.service.PolicyDecisionService``)
without duplicating it. A proposal moves through:

    draft -> validated -> simulated -> pending_approval -> approved -> canary -> active
                                                                  \\-> rejected
    active -> rolled_back

Hard guarantees (requirement 3)
-------------------------------
* A newly generated policy NEVER becomes active solely because a model recommended it. Activation
  requires an explicit, authorized call AND (by default) at least one human approval bound to the
  proposal's checksum.
* A high-impact change requires TWO DISTINCT approvers (separation of duties).
* Static security checks refuse a change that would silently broaden privilege, weaken tenant
  isolation or disable a required security control.
* Every lifecycle transition is recorded in the tamper-evident audit chain with provenance.
* Rollback restores a previously validated version (delegated to the policy engine, which retains
  retired versions for exactly this purpose).
* Emergency changes follow a documented, auditable path: they are marked ``emergency``, still
  require an authorized actor, are still audited, and are flagged for mandatory post-hoc review.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import List, Optional, Sequence, Tuple

from ..core.errors import ForbiddenError, NotFoundError, ValidationError
from ..security.ids import new_id
from ..security.rbac import (P_ASSURANCE_APPROVE, P_POLICY_ACTIVATE, P_POLICY_READ, P_POLICY_WRITE,
                             Authorizer)
from .config import AssuranceConfig, IMPACT_LEVELS
from .errors import (ApprovalRequiredError, ProposalConflictError, ProposalValidationError,
                     UnsafeChangeError)
from .models import ImpactLevel, PolicyProposal, ProposalStatus, Provenance
from .store import AssuranceStore

#: Static patterns that indicate a change could weaken a control. These are HEURISTIC text checks,
#: not a proof of safety -- they are a guardrail, and the limitations doc says so.
_UNSAFE_PATTERNS = (
    (re.compile(r"default\s+allow\s*(:=|=)\s*true", re.I),
     "unconditional default allow"),
    (re.compile(r"allow\s*(:=|=)\s*true\s*$", re.M),
     "unconditional allow rule"),
    (re.compile(r"allow\s*\{\s*true\s*\}", re.I),
     "allow rule with an empty (always-true) body"),
    (re.compile(r"resource\s*(:=|=)\s*\"\*\"", re.I),
     "wildcard resource scope"),
    (re.compile(r"action\s*(:=|=)\s*\"\*\"", re.I),
     "wildcard action scope"),
)
#: Guards whose REMOVAL relative to the base version is treated as weakening tenant isolation.
_TENANT_GUARDS = ("tenant", "org_id", "resource_tenant", "current_org")


def _checksum(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def static_security_check(proposed: str, base: Optional[str]) -> dict:
    """Heuristic static checks. Returns ``{"ok", "findings": [...]}``.

    This is a guardrail, not a proof: it catches the common ways a policy change silently broadens
    privilege or disables a control, and it is honest about being heuristic.
    """
    findings: List[str] = []
    for pattern, label in _UNSAFE_PATTERNS:
        if pattern.search(proposed or ""):
            findings.append(label)
    if base:
        # Removing a tenant guard that the base version enforced weakens tenant isolation.
        for guard in _TENANT_GUARDS:
            if guard in base and guard not in proposed:
                findings.append(f"removes tenant-isolation guard '{guard}' present in the base version")
        # Removing a deny rule that the base version had weakens enforcement.
        base_denies = len(re.findall(r"\bdeny\b", base))
        prop_denies = len(re.findall(r"\bdeny\b", proposed or ""))
        if base_denies > 0 and prop_denies < base_denies:
            findings.append("removes one or more deny rules present in the base version")
    return {"ok": not findings, "findings": findings}


class PolicyLifecycleService:
    """Proposal lifecycle on top of the existing policy engine."""

    def __init__(self, store: AssuranceStore, *, policy_service=None,
                 config: Optional[AssuranceConfig] = None, audit=None, clock=None):
        self.store = store
        self.policy = policy_service
        self.cfg = config or AssuranceConfig()
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def _audit(self, event: str, *, org_id: Optional[str] = None, actor: Optional[str] = None,
               outcome: str = "ok", reason: Optional[str] = None, detail: Optional[dict] = None):
        if self.audit is not None:
            self.audit.record(event, org_id=org_id, actor_user_id=actor, outcome=outcome,
                              reason=reason, detail=detail)

    def _require(self, actor, perm: str, *, org_id: Optional[str] = None) -> None:
        try:
            Authorizer.require(actor, perm, org_id=org_id)
        except ForbiddenError:
            self._audit("assurance.proposal.authz.denied", org_id=org_id,
                        actor=getattr(actor, "user_id", None), outcome="denied",
                        reason="permission_denied")
            raise

    def _get(self, proposal_id: str, org_id: str) -> PolicyProposal:
        p = self.store.get_proposal(proposal_id, org_id=org_id)
        if p is None:
            raise NotFoundError("proposal not found")
        return p

    def _transition(self, p: PolicyProposal, status: str, *, actor: Optional[str],
                    note: str = "") -> PolicyProposal:
        import dataclasses
        entry = {"ts": self._now(), "from": p.status, "to": status, "actor": actor, "note": note}
        return dataclasses.replace(p, status=status, updated_at=self._now(),
                                   provenance=tuple(p.provenance) + (entry,))

    # ================================================================== create
    def create_proposal(self, actor, *, org_id: str, proposed_rego: str, title: str = "",
                        rationale: str = "", policy_id: Optional[str] = None,
                        base_version: Optional[int] = None, recommendation_id: Optional[str] = None,
                        impact_level: str = ImpactLevel.MEDIUM.value, emergency: bool = False
                        ) -> PolicyProposal:
        """Create a DRAFT proposal. Requires ``policy:write``. Never activates anything."""
        self._require(actor, P_POLICY_WRITE, org_id=org_id)
        if not isinstance(proposed_rego, str) or not proposed_rego.strip():
            raise ValidationError("proposed_rego is required")
        if impact_level not in IMPACT_LEVELS:
            raise ValidationError("invalid impact_level")
        if self.store.count_pending_proposals(org_id=org_id) >= self.cfg.proposal_max_pending:
            raise ProposalConflictError("too many pending proposals for this tenant")
        now = self._now()
        p = PolicyProposal(
            proposal_id=new_id("prp"), org_id=org_id, recommendation_id=recommendation_id,
            policy_id=policy_id, base_version=base_version, proposed_rego=proposed_rego,
            checksum=_checksum(proposed_rego), status=ProposalStatus.DRAFT.value,
            impact_level=impact_level, created_at=now, created_by=actor.user_id, updated_at=now,
            title=title or "policy change", rationale=rationale,
            expires_at=now + self.cfg.proposal_ttl_s, emergency=bool(emergency),
            provenance=({"ts": now, "from": None, "to": ProposalStatus.DRAFT.value,
                         "actor": actor.user_id, "note": "created"},))
        self.store.put_proposal(p)
        self._audit("assurance.proposal.created", org_id=org_id, actor=actor.user_id,
                    detail={"proposal_id": p.proposal_id, "impact": impact_level,
                            "emergency": bool(emergency), "recommendation_id": recommendation_id})
        return p

    # ================================================================== validate
    def validate(self, actor, proposal_id: str, *, org_id: str) -> PolicyProposal:
        """Schema + semantic validation and static security checks. Requires ``policy:read``."""
        self._require(actor, P_POLICY_READ, org_id=org_id)
        p = self._get(proposal_id, org_id)
        if p.status not in (ProposalStatus.DRAFT.value, ProposalStatus.VALIDATED.value):
            raise ProposalConflictError("proposal is not in a validatable state")
        # 1) schema/semantic validation through the EXISTING policy engine validator
        schema_ok, schema_reason = True, "valid"
        if self.policy is not None:
            try:
                from ..policy.engine import validate_rego
                validate_rego(p.proposed_rego, max_bytes=self.policy.cfg.max_policy_bytes)
            except Exception as e:                                   # noqa: BLE001
                schema_ok, schema_reason = False, getattr(e, "code", "invalid_rego")
        # 2) static security checks against the base version (if any)
        base = None
        if p.policy_id and p.base_version is not None and self.policy is not None:
            try:
                v = self.policy.store.get_version(p.policy_id, p.base_version)
                base = v.rego_source if v is not None else None
            except Exception:                                        # noqa: BLE001
                base = None
        static = static_security_check(p.proposed_rego, base)
        summary = {"schema_ok": schema_ok, "schema_reason": schema_reason,
                   "static_ok": static["ok"], "static_findings": static["findings"]}
        import dataclasses
        if not schema_ok:
            updated = dataclasses.replace(p, validation_summary=summary, updated_at=self._now())
            self.store.put_proposal(updated)
            self._audit("assurance.proposal.validated", org_id=org_id, actor=actor.user_id,
                        outcome="error", reason=schema_reason,
                        detail={"proposal_id": proposal_id})
            raise ProposalValidationError(schema_reason)
        if not static["ok"]:
            updated = dataclasses.replace(p, validation_summary=summary, updated_at=self._now())
            self.store.put_proposal(updated)
            self._audit("assurance.proposal.validated", org_id=org_id, actor=actor.user_id,
                        outcome="error", reason="unsafe_change",
                        detail={"proposal_id": proposal_id, "findings": static["findings"]})
            raise UnsafeChangeError("; ".join(static["findings"]))
        updated = self._transition(dataclasses.replace(p, validation_summary=summary),
                                   ProposalStatus.VALIDATED.value, actor=actor.user_id,
                                   note="validated")
        self.store.put_proposal(updated)
        self._audit("assurance.proposal.validated", org_id=org_id, actor=actor.user_id,
                    detail={"proposal_id": proposal_id})
        return updated

    # ================================================================== simulate
    def simulate(self, actor, proposal_id: str, *, org_id: str, cases: Sequence[dict]
                 ) -> PolicyProposal:
        """Run the proposal against representative events BEFORE activation (requirement 3)."""
        self._require(actor, P_POLICY_READ, org_id=org_id)
        p = self._get(proposal_id, org_id)
        if p.status not in (ProposalStatus.VALIDATED.value, ProposalStatus.SIMULATED.value):
            raise ProposalConflictError("proposal must be validated before simulation")
        results, passed, failed = [], 0, 0
        if self.policy is not None:
            for case in cases or []:
                input_doc = case.get("input") if isinstance(case, dict) else None
                if not isinstance(input_doc, dict):
                    results.append({"error": "invalid_case"})
                    failed += 1
                    continue
                decision = self.policy.engine.evaluate(
                    policy_source=p.proposed_rego, policy_id=p.policy_id or p.proposal_id,
                    version=p.base_version or 0, input_doc=input_doc)
                expect = case.get("expect")
                ok = (expect is None) or (decision.kind.value == str(expect).upper())
                passed += 1 if ok else 0
                failed += 0 if ok else 1
                results.append({"decision": decision.kind.value, "reason": decision.reason,
                                "expect": expect, "ok": ok})
        summary = {"total": len(results), "passed": passed, "failed": failed, "results": results}
        import dataclasses
        updated = self._transition(dataclasses.replace(p, simulation_summary=summary),
                                   ProposalStatus.SIMULATED.value, actor=actor.user_id,
                                   note=f"simulated passed={passed} failed={failed}")
        self.store.put_proposal(updated)
        self._audit("assurance.proposal.simulated", org_id=org_id, actor=actor.user_id,
                    outcome=("ok" if failed == 0 else "error"),
                    reason=f"passed={passed} failed={failed}", detail={"proposal_id": proposal_id})
        return updated

    # ================================================================== approval
    def submit_for_approval(self, actor, proposal_id: str, *, org_id: str) -> PolicyProposal:
        self._require(actor, P_POLICY_WRITE, org_id=org_id)
        p = self._get(proposal_id, org_id)
        if p.status not in (ProposalStatus.VALIDATED.value, ProposalStatus.SIMULATED.value):
            raise ProposalConflictError("proposal must be validated/simulated before approval")
        import dataclasses
        updated = self._transition(p, ProposalStatus.PENDING_APPROVAL.value, actor=actor.user_id,
                                   note="submitted for approval")
        self.store.put_proposal(updated)
        self._audit("assurance.proposal.submitted", org_id=org_id, actor=actor.user_id,
                    detail={"proposal_id": proposal_id})
        return updated

    def decide(self, actor, proposal_id: str, *, org_id: str, decision: str, reason: str = ""
               ) -> PolicyProposal:
        """Record an approval decision. Requires ``assurance:approve`` (a distinct authority from
        ``policy:write``, which authors the change, and ``policy:activate``, which activates it).

        The decision is bound to the proposal's CURRENT checksum, so a proposal modified after an
        approval cannot reuse it. A high-impact change requires two DISTINCT approvers.
        """
        self._require(actor, P_ASSURANCE_APPROVE, org_id=org_id)
        if decision not in ("approved", "rejected"):
            raise ValidationError("decision must be approved|rejected")
        p = self._get(proposal_id, org_id)
        if p.status not in (ProposalStatus.PENDING_APPROVAL.value, ProposalStatus.APPROVED.value):
            raise ProposalConflictError("proposal is not awaiting approval")
        if p.expires_at is not None and self._now() > p.expires_at:
            import dataclasses
            expired = self._transition(p, ProposalStatus.EXPIRED.value, actor=actor.user_id,
                                       note="expired")
            self.store.put_proposal(expired)
            raise ProposalConflictError("proposal has expired")
        # separation of duties: the creator may not approve their own proposal
        if actor.user_id == p.created_by:
            raise ForbiddenError("the proposal creator may not approve their own proposal")
        # a modified proposal invalidates prior approvals
        prior = [a for a in p.approvals if a.get("checksum") == p.checksum]
        if any(a.get("approver_user_id") == actor.user_id for a in prior):
            raise ProposalConflictError("this approver has already decided on this proposal")
        entry = {"approval_id": new_id("apr"), "proposal_id": proposal_id, "org_id": org_id,
                 "approver_user_id": actor.user_id, "decision": decision, "checksum": p.checksum,
                 "ts": self._now(), "reason": reason}
        import dataclasses
        approvals = tuple(prior) + (entry,)
        if decision == "rejected":
            updated = self._transition(dataclasses.replace(p, approvals=approvals),
                                       ProposalStatus.REJECTED.value, actor=actor.user_id,
                                       note="rejected")
            self.store.put_proposal(updated)
            self._audit("assurance.proposal.rejected", org_id=org_id, actor=actor.user_id,
                        reason=reason, detail={"proposal_id": proposal_id})
            return updated
        # approved: does it satisfy the approval requirement?
        high_impact = _impact_rank(p.impact_level) >= _impact_rank(self.cfg.proposal_high_impact_level)
        needed = 2 if (high_impact and self.cfg.proposal_high_impact_requires_two_approvers) else 1
        distinct = {a["approver_user_id"] for a in approvals if a.get("decision") == "approved"}
        status = (ProposalStatus.APPROVED.value if len(distinct) >= needed
                  else ProposalStatus.PENDING_APPROVAL.value)
        updated = self._transition(dataclasses.replace(p, approvals=approvals), status,
                                   actor=actor.user_id,
                                   note=f"approved by {len(distinct)}/{needed}")
        self.store.put_proposal(updated)
        self._audit("assurance.proposal.approved", org_id=org_id, actor=actor.user_id,
                    detail={"proposal_id": proposal_id, "approvers": len(distinct), "needed": needed})
        return updated

    # ================================================================== canary
    def start_canary(self, actor, proposal_id: str, *, org_id: str) -> PolicyProposal:
        self._require(actor, P_POLICY_ACTIVATE, org_id=org_id)
        p = self._get(proposal_id, org_id)
        if p.status != ProposalStatus.APPROVED.value:
            raise ApprovalRequiredError("proposal must be approved before a canary")
        import dataclasses
        canary = {"fraction": self.cfg.proposal_canary_fraction, "started_at": self._now(),
                  "samples": 0, "deny_delta": 0.0, "status": "running"}
        updated = self._transition(dataclasses.replace(p, canary=canary),
                                   ProposalStatus.CANARY.value, actor=actor.user_id,
                                   note="canary started")
        self.store.put_proposal(updated)
        self._audit("assurance.proposal.canary.started", org_id=org_id, actor=actor.user_id,
                    detail={"proposal_id": proposal_id})
        return updated

    def record_canary(self, actor, proposal_id: str, *, org_id: str, samples: int,
                      deny_delta: float) -> PolicyProposal:
        """Record canary observations. Auto-rejects when the deny-rate delta exceeds the threshold."""
        self._require(actor, P_POLICY_ACTIVATE, org_id=org_id)
        p = self._get(proposal_id, org_id)
        if p.status != ProposalStatus.CANARY.value:
            raise ProposalConflictError("proposal is not in canary")
        import dataclasses
        canary = dict(p.canary or {})
        canary.update({"samples": int(samples), "deny_delta": float(deny_delta)})
        if deny_delta > self.cfg.proposal_canary_max_deny_delta:
            canary["status"] = "rejected"
            updated = self._transition(dataclasses.replace(p, canary=canary),
                                       ProposalStatus.REJECTED.value, actor=actor.user_id,
                                       note="canary deny-rate delta exceeded threshold")
            self.store.put_proposal(updated)
            self._audit("assurance.proposal.canary.rejected", org_id=org_id, actor=actor.user_id,
                        reason="deny_delta_exceeded", detail={"proposal_id": proposal_id})
            return updated
        canary["status"] = "healthy"
        updated = dataclasses.replace(p, canary=canary, updated_at=self._now())
        self.store.put_proposal(updated)
        return updated

    # ================================================================== activate
    def activate(self, actor, proposal_id: str, *, org_id: str) -> PolicyProposal:
        """Activate an approved proposal through the EXISTING policy engine.

        Refuses unless the proposal is approved (or a healthy canary) AND the deployment permits
        activation. A model recommendation alone can never reach this state.
        """
        self._require(actor, P_POLICY_ACTIVATE, org_id=org_id)
        p = self._get(proposal_id, org_id)
        if p.status not in (ProposalStatus.APPROVED.value, ProposalStatus.CANARY.value):
            raise ApprovalRequiredError("proposal must be approved (or a healthy canary) to activate")
        if p.status == ProposalStatus.CANARY.value:
            canary = p.canary or {}
            if canary.get("status") != "healthy" or \
                    int(canary.get("samples", 0)) < self.cfg.proposal_canary_min_samples:
                raise ApprovalRequiredError("canary has not observed enough healthy samples")
        if self.policy is None:
            raise ProposalConflictError("the policy engine is not configured")
        # create the version and activate it through the existing service
        if p.policy_id is None:
            record = self.policy.create_policy(actor, name=p.title or "recommended policy",
                                               description=p.rationale, org_id=org_id,
                                               rego_source=p.proposed_rego)
            policy_id = record.policy_id
            # create_policy leaves the policy DRAFT; activate the version it just created
            versions = self.policy.store.list_versions(policy_id)
            version = versions[-1].version
        else:
            policy_id = p.policy_id
            v = self.policy.create_version(actor, policy_id, rego_source=p.proposed_rego)
            version = v.version
        self.policy.activate(actor, policy_id, version)
        import dataclasses
        updated = self._transition(
            dataclasses.replace(p, policy_id=policy_id, activated_at=self._now(),
                                activated_by=actor.user_id, activated_version=version),
            ProposalStatus.ACTIVE.value, actor=actor.user_id, note=f"activated v{version}")
        self.store.put_proposal(updated)
        self._audit("assurance.proposal.activated", org_id=org_id, actor=actor.user_id,
                    detail={"proposal_id": proposal_id, "policy_id": policy_id, "version": version,
                            "emergency": p.emergency})
        return updated

    # ================================================================== rollback
    def rollback(self, actor, proposal_id: str, *, org_id: str, to_version: Optional[int] = None
                 ) -> PolicyProposal:
        """Roll back an activated proposal to a previously validated version."""
        self._require(actor, P_POLICY_ACTIVATE, org_id=org_id)
        p = self._get(proposal_id, org_id)
        if p.status != ProposalStatus.ACTIVE.value or p.policy_id is None:
            raise ProposalConflictError("only an active proposal can be rolled back")
        if self.policy is None:
            raise ProposalConflictError("the policy engine is not configured")
        target = to_version if to_version is not None else p.base_version
        if target is None:
            raise ValidationError("no rollback target version is available")
        self.policy.rollback(actor, p.policy_id, to_version=target)
        import dataclasses
        updated = self._transition(
            dataclasses.replace(p, rolled_back_at=self._now(), rolled_back_to=target),
            ProposalStatus.ROLLED_BACK.value, actor=actor.user_id, note=f"rolled back to v{target}")
        self.store.put_proposal(updated)
        self._audit("assurance.proposal.rolled_back", org_id=org_id, actor=actor.user_id,
                    detail={"proposal_id": proposal_id, "to_version": target})
        return updated

    # ================================================================== emergency
    def emergency_change(self, actor, *, org_id: str, proposed_rego: str, title: str,
                         rationale: str, policy_id: Optional[str] = None,
                         base_version: Optional[int] = None) -> PolicyProposal:
        """Documented, auditable emergency path.

        An emergency change still requires an authorized actor, is still validated and audited, and
        is flagged for mandatory post-hoc review. It does NOT bypass the static security checks.
        """
        p = self.create_proposal(actor, org_id=org_id, proposed_rego=proposed_rego, title=title,
                                 rationale=f"EMERGENCY: {rationale}", policy_id=policy_id,
                                 base_version=base_version,
                                 impact_level=ImpactLevel.CRITICAL.value, emergency=True)
        p = self.validate(actor, p.proposal_id, org_id=org_id)
        self._audit("assurance.proposal.emergency", org_id=org_id, actor=actor.user_id,
                    detail={"proposal_id": p.proposal_id, "post_review_required": True})
        return p

    # ================================================================== queries
    def get(self, actor, proposal_id: str, *, org_id: str) -> PolicyProposal:
        self._require(actor, P_POLICY_READ, org_id=org_id)
        return self._get(proposal_id, org_id)

    def list(self, actor, *, org_id: str, status: Optional[str] = None) -> List[PolicyProposal]:
        self._require(actor, P_POLICY_READ, org_id=org_id)
        return self.store.list_proposals(org_id=org_id, status=status)


def _impact_rank(level: str) -> int:
    try:
        return IMPACT_LEVELS.index(level)
    except ValueError:
        return 1
