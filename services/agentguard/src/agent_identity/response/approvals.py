"""Phase 6 risk-based human approval.

A human-approval workflow for high-risk operations, built on the SAME store and audit discipline as
the rest of the plane. It is a *workflow*, not an enforcement path: it decides whether an approval
exists for an operation, and the caller (the policy engine or the response orchestrator) remains the
thing that acts on that answer.

Binding rule (the security core of this module)
-----------------------------------------------
Every request carries an :func:`~agent_identity.response.models.operation_fingerprint` over
``(org_id, agent_id, action, resource, params)``. :meth:`ApprovalService.check` recomputes the
fingerprint from the operation being attempted and refuses on any mismatch
(:class:`~agent_identity.response.errors.ApprovalMismatchError`). A modified request therefore cannot
reuse an approval granted for a different action, resource, tenant or parameter set.

Other guarantees:

* **Separation of duties** (default on): the requester may not approve their own request.
* **Expiry**: a PENDING approval past ``expires_at`` is transitioned to EXPIRED and never satisfies a
  check. Expiry is evaluated against the injected clock, so it is deterministic in tests.
* **Delegation**: an approval may be delegated to another approver, recorded in the audit trail.
* **Bounded pending set**: a per-agent cap prevents an agent from exhausting the approval queue.
* **Approver verification**: the caller supplies the approver's verified identity/permissions; this
  module records them and enforces the tenant match, and the HTTP layer enforces the RBAC permission.
"""
from __future__ import annotations

import dataclasses
import time
from typing import List, Optional, Sequence

from ..security.ids import new_id
from .config import ResponseConfig
from .errors import ApprovalError, ApprovalMismatchError, ResponsePlaneError
from .models import (APPROVAL_TERMINAL_STATES, ApprovalRequest, ApprovalStatus,
                     operation_fingerprint)


class ApprovalService:
    """Risk-based human approval, bound to the exact operation it authorizes."""

    def __init__(self, store, *, config: Optional[ResponseConfig] = None, audit=None, clock=None):
        self.store = store
        self.cfg = config or ResponseConfig()
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ request
    def request(self, *, org_id: str, agent_id: Optional[str], action: str, resource: str,
                requested_by: str, reason: str = "", params: Optional[dict] = None,
                risk_score: Optional[float] = None, risk_band: Optional[str] = None,
                risk_evidence: Sequence[str] = (), policy_id: Optional[str] = None,
                policy_version: Optional[str] = None, incident_id: Optional[str] = None,
                ttl_s: Optional[int] = None) -> ApprovalRequest:
        """Raise an approval request for one exact operation.

        Idempotent per fingerprint: re-requesting the SAME operation returns the existing PENDING
        request instead of creating a duplicate, so a retrying caller cannot flood the queue.
        """
        for name, val in (("org_id", org_id), ("action", action), ("resource", resource),
                          ("requested_by", requested_by)):
            if not isinstance(val, str) or not val.strip():
                raise ResponsePlaneError(f"{name} is required")
        fp = operation_fingerprint(org_id=org_id, agent_id=agent_id, action=action,
                                   resource=resource, params=params)
        existing = self.store.find_approval_by_fingerprint(org_id=org_id, fingerprint=fp)
        if existing is not None and existing.status == ApprovalStatus.PENDING.value:
            if not self._is_expired(existing):
                return existing
            self._expire(existing)
        if agent_id:
            pending = self.store.count_pending_approvals(org_id=org_id, agent_id=agent_id)
            if pending >= self.cfg.approval_max_pending_per_agent:
                raise ApprovalError("too many pending approvals for this agent")
        now = self._now()
        a = ApprovalRequest(
            approval_id=new_id("apr"), org_id=org_id, agent_id=agent_id, action=action,
            resource=resource, fingerprint=fp, status=ApprovalStatus.PENDING.value,
            requested_at=now, expires_at=now + (ttl_s if ttl_s is not None else self.cfg.approval_ttl_s),
            requested_by=requested_by, reason=reason[:512], risk_score=risk_score,
            risk_band=risk_band, risk_evidence=tuple(str(e)[:512] for e in risk_evidence),
            policy_id=policy_id, policy_version=policy_version, incident_id=incident_id,
            params=dict(params or {}))
        self.store.put_approval(a)
        self._audit("response.approval.requested", org_id=org_id, agent_id=agent_id,
                    actor_user_id=requested_by, extra={"approval_id": a.approval_id,
                                                       "action": action, "resource": resource,
                                                       "risk_band": risk_band})
        return a

    # ------------------------------------------------------------------ decide
    def decide(self, *, org_id: str, approval_id: str, approved: bool, decided_by: str,
               reason: str = "", approver_org_id: Optional[str] = None,
               approver_is_platform_admin: bool = False,
               approver_permissions: Optional[Sequence[str]] = None,
               required_permission: Optional[str] = None) -> ApprovalRequest:
        """Record a human decision, enforcing tenant membership and separation of duties."""
        a = self.store.get_approval(approval_id, org_id=org_id)
        if a is None:
            raise ApprovalError("unknown approval")
        if a.status != ApprovalStatus.PENDING.value:
            raise ApprovalError("approval has already been decided")
        if self._is_expired(a):
            self._expire(a)
            raise ApprovalError("approval has expired")
        # --- approver identity / tenant membership -------------------------------------------
        if not approver_is_platform_admin:
            if approver_org_id is None or approver_org_id != a.org_id:
                self._audit("response.approval.denied", org_id=org_id, agent_id=a.agent_id,
                            outcome="denied", reason="approver_not_in_tenant",
                            actor_user_id=decided_by, extra={"approval_id": approval_id})
                raise ApprovalError("approver is not a member of this tenant")
        if required_permission is not None:
            perms = set(approver_permissions or ())
            if required_permission not in perms:
                self._audit("response.approval.denied", org_id=org_id, agent_id=a.agent_id,
                            outcome="denied", reason="approver_lacks_permission",
                            actor_user_id=decided_by, extra={"approval_id": approval_id})
                raise ApprovalError("approver lacks the required permission")
        # --- separation of duties ------------------------------------------------------------
        if self.cfg.approval_require_separation_of_duties and approved \
                and decided_by == a.requested_by:
            self._audit("response.approval.denied", org_id=org_id, agent_id=a.agent_id,
                        outcome="denied", reason="separation_of_duties",
                        actor_user_id=decided_by, extra={"approval_id": approval_id})
            raise ApprovalError("the requester may not approve their own request")
        now = self._now()
        a2 = dataclasses.replace(
            a, status=(ApprovalStatus.APPROVED.value if approved
                       else ApprovalStatus.DENIED.value),
            decided_at=now, decided_by=decided_by, decision_reason=reason[:512])
        self.store.put_approval(a2)
        self._audit("response.approval.decided", org_id=org_id, agent_id=a.agent_id,
                    outcome="ok" if approved else "denied", reason=reason,
                    actor_user_id=decided_by, extra={"approval_id": approval_id,
                                                     "approved": bool(approved)})
        return a2

    def cancel(self, *, org_id: str, approval_id: str, cancelled_by: str,
               reason: str = "cancelled") -> ApprovalRequest:
        a = self.store.get_approval(approval_id, org_id=org_id)
        if a is None:
            raise ApprovalError("unknown approval")
        if a.status != ApprovalStatus.PENDING.value:
            raise ApprovalError("approval has already been decided")
        a2 = dataclasses.replace(a, status=ApprovalStatus.CANCELLED.value,
                                 decided_at=self._now(), decided_by=cancelled_by,
                                 decision_reason=reason[:512])
        self.store.put_approval(a2)
        self._audit("response.approval.cancelled", org_id=org_id, agent_id=a.agent_id,
                    actor_user_id=cancelled_by, extra={"approval_id": approval_id})
        return a2

    def delegate(self, *, org_id: str, approval_id: str, delegated_to: str,
                 delegated_by: str) -> ApprovalRequest:
        """Delegate a PENDING approval to another approver (recorded, not silent)."""
        a = self.store.get_approval(approval_id, org_id=org_id)
        if a is None:
            raise ApprovalError("unknown approval")
        if a.status != ApprovalStatus.PENDING.value:
            raise ApprovalError("only a pending approval can be delegated")
        if self._is_expired(a):
            self._expire(a)
            raise ApprovalError("approval has expired")
        a2 = dataclasses.replace(a, delegated_to=delegated_to)
        self.store.put_approval(a2)
        self._audit("response.approval.delegated", org_id=org_id, agent_id=a.agent_id,
                    actor_user_id=delegated_by, extra={"approval_id": approval_id,
                                                       "delegated_to": delegated_to})
        return a2

    # ------------------------------------------------------------------ check (the binding)
    def check(self, *, org_id: str, agent_id: Optional[str], action: str, resource: str,
              params: Optional[dict] = None, approval_id: Optional[str] = None,
              raise_on_mismatch: bool = True) -> Optional[ApprovalRequest]:
        """Return the APPROVED, unexpired approval for THIS EXACT operation, or ``None``.

        When ``approval_id`` is supplied the approval must exist, be APPROVED, be unexpired, and its
        fingerprint must match the operation being attempted. A mismatch raises
        :class:`ApprovalMismatchError` (or returns ``None`` when ``raise_on_mismatch=False``).
        """
        fp = operation_fingerprint(org_id=org_id, agent_id=agent_id, action=action,
                                   resource=resource, params=params)
        if approval_id is not None:
            a = self.store.get_approval(approval_id, org_id=org_id)
            if a is None:
                if raise_on_mismatch:
                    raise ApprovalMismatchError("unknown approval")
                return None
            if a.fingerprint != fp:
                self._audit("response.approval.mismatch", org_id=org_id, agent_id=agent_id,
                            outcome="denied", reason="fingerprint_mismatch",
                            extra={"approval_id": approval_id, "action": action,
                                   "resource": resource})
                if raise_on_mismatch:
                    raise ApprovalMismatchError(
                        "approval does not authorize this operation (fingerprint mismatch)")
                return None
            if a.status != ApprovalStatus.APPROVED.value:
                return None
            if self._is_expired(a):
                self._expire(a)
                return None
            return a
        a = self.store.find_approval_by_fingerprint(org_id=org_id, fingerprint=fp)
        if a is None or a.status != ApprovalStatus.APPROVED.value:
            return None
        if self._is_expired(a):
            self._expire(a)
            return None
        return a

    def require(self, *, org_id: str, agent_id: Optional[str], action: str, resource: str,
                params: Optional[dict] = None, approval_id: Optional[str] = None
                ) -> ApprovalRequest:
        """Like :meth:`check` but raises when no valid approval exists (fail closed)."""
        a = self.check(org_id=org_id, agent_id=agent_id, action=action, resource=resource,
                       params=params, approval_id=approval_id)
        if a is None:
            raise ApprovalError("no valid approval for this operation")
        return a

    # ------------------------------------------------------------------ reads
    def get(self, *, org_id: str, approval_id: str) -> Optional[ApprovalRequest]:
        a = self.store.get_approval(approval_id, org_id=org_id)
        if a is not None and self._is_expired(a):
            self._expire(a)
            return self.store.get_approval(approval_id, org_id=org_id)
        return a

    def list(self, *, org_id: str, status: Optional[str] = None, agent_id: Optional[str] = None,
             limit: int = 100) -> List[ApprovalRequest]:
        items = self.store.list_approvals(org_id=org_id, status=status, agent_id=agent_id,
                                          limit=limit)
        for a in items:
            if self._is_expired(a):
                self._expire(a)
        return self.store.list_approvals(org_id=org_id, status=status, agent_id=agent_id,
                                         limit=limit)

    def history(self, *, org_id: str, agent_id: Optional[str] = None,
                limit: int = 100) -> List[dict]:
        """The auditable decision history for an agent (or the tenant)."""
        return [a.public_dict() for a in self.store.list_approvals(
            org_id=org_id, agent_id=agent_id, limit=limit)]

    # ------------------------------------------------------------------ expiry
    def _is_expired(self, a: ApprovalRequest) -> bool:
        return (a.status == ApprovalStatus.PENDING.value and a.expires_at > 0
                and self._now() >= a.expires_at)

    def _expire(self, a: ApprovalRequest) -> None:
        a2 = dataclasses.replace(a, status=ApprovalStatus.EXPIRED.value,
                                 decided_at=self._now(), decision_reason="expired")
        self.store.put_approval(a2)
        self._audit("response.approval.expired", org_id=a.org_id, agent_id=a.agent_id,
                    extra={"approval_id": a.approval_id})

    # ------------------------------------------------------------------ audit helper
    def _audit(self, event: str, *, org_id: Optional[str] = None, agent_id: Optional[str] = None,
               outcome: str = "ok", reason: Optional[str] = None,
               actor_user_id: Optional[str] = None, extra: Optional[dict] = None) -> None:
        if self.audit is not None:
            self.audit.record(event, org_id=org_id, agent_id=agent_id, outcome=outcome,
                              reason=reason, actor_user_id=actor_user_id, extra=extra)
