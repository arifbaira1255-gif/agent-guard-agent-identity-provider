"""Step 10 risk-signal and human-approval integration interfaces.

These are deliberately MINIMAL. Step 10 must be able to (a) consume risk signals produced by other
components and (b) gate an action that policy marked ``REQUIRE_APPROVAL`` — but the full risk engine
and the full approval workflow belong to later steps (Step 11 tool/resource governance, Step 17
approvals). Only the interfaces and the minimum safe functionality live here.

* :class:`RiskSignalProvider` — a pluggable source of :class:`RiskSignal`. The default provider
  returns a neutral low-risk signal; a real provider (Step 11+) is injected.
* :class:`ApprovalProvider` — request/check/decide an approval. The default provider is a
  fail-closed in-memory implementation backed by the policy store; a real workflow (Step 17) is
  injected. An action requiring approval MUST NOT execute until a valid approval exists.
"""
from __future__ import annotations

import time
from typing import Optional, Protocol

from ..core.errors import ForbiddenError, ValidationError
from ..security.ids import new_id
from .config import PolicyConfig
from .models import ApprovalRequest, ApprovalStatus, RiskSignal
from .store import PolicyStore


# --------------------------------------------------------------------------- risk
class RiskSignalProvider(Protocol):
    def signal_for(self, *, org_id: str, agent_id: str, action: str, resource: str,
                   context: Optional[dict] = None) -> RiskSignal:  # pragma: no cover - protocol
        ...


class NeutralRiskProvider:
    """Default provider: no risk information available -> a neutral low signal.

    It never fabricates a *high* risk (which would deny legitimate traffic) and never fabricates a
    *low* risk that overrides a real signal — it simply reports that no signal is available.
    """

    def signal_for(self, *, org_id, agent_id, action, resource, context=None) -> RiskSignal:
        return RiskSignal(level="low", score=0.0, reasons=(), source="neutral")


class StaticRiskProvider:
    """Deterministic provider for tests: returns a fixed signal."""

    def __init__(self, signal: RiskSignal):
        self._signal = signal

    def signal_for(self, *, org_id, agent_id, action, resource, context=None) -> RiskSignal:
        return self._signal


# --------------------------------------------------------------------------- approvals
class ApprovalProvider(Protocol):
    def request(self, *, org_id: str, agent_id: str, action: str, resource: str,
                requested_by: str, reason: str = "", context: Optional[dict] = None,
                correlation_id: Optional[str] = None) -> ApprovalRequest:  # pragma: no cover
        ...

    def check(self, *, org_id: str, agent_id: str, action: str,
              resource: str) -> Optional[ApprovalRequest]:  # pragma: no cover
        ...


class StoreApprovalProvider:
    """Minimal, fail-closed approval provider backed by the policy store.

    * :meth:`request` creates a PENDING approval with an explicit, bounded expiry.
    * :meth:`decide` records a human decision (approve/deny). Only an APPROVED, unexpired approval
      satisfies a ``REQUIRE_APPROVAL`` decision.
    * :meth:`check` returns a valid approval or None. There is no "auto-approve" path.

    The full multi-step approval workflow (routing, quorum, notifications, escalation) is Step 17's
    responsibility; this is the minimum needed to gate execution safely.
    """

    def __init__(self, store: PolicyStore, config: PolicyConfig, *, audit=None, clock=None):
        self.store = store
        self.cfg = config
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def request(self, *, org_id: str, agent_id: str, action: str, resource: str,
                requested_by: str, reason: str = "", context: Optional[dict] = None,
                correlation_id: Optional[str] = None) -> ApprovalRequest:
        for name, val in (("org_id", org_id), ("agent_id", agent_id), ("action", action),
                          ("resource", resource)):
            if not isinstance(val, str) or not val.strip():
                raise ValidationError(f"{name} is required")
        now = self._now()
        a = ApprovalRequest(approval_id=new_id("apr"), org_id=org_id, agent_id=agent_id,
                            action=action, resource=resource, status=ApprovalStatus.PENDING,
                            requested_at=now, expires_at=now + self.cfg.approval_ttl_s,
                            requested_by=requested_by, reason=reason, context=context)
        self.store.put_approval(a)
        self._audit("approval.requested", org_id=org_id, outcome="ok", reason=reason,
                    correlation_id=correlation_id, actor_user_id=requested_by)
        return a

    def decide(self, approval_id: str, *, approved: bool, decided_by: str, reason: str = "",
               correlation_id: Optional[str] = None) -> ApprovalRequest:
        a = self.store.get_approval(approval_id)
        if a is None:
            raise ValidationError("unknown approval")
        if a.status is not ApprovalStatus.PENDING:
            raise ForbiddenError("approval has already been decided")
        now = self._now()
        if now >= a.expires_at:
            raise ForbiddenError("approval has expired")
        import dataclasses
        a2 = dataclasses.replace(a, status=(ApprovalStatus.APPROVED if approved
                                            else ApprovalStatus.DENIED),
                                 decided_at=now, decided_by=decided_by, reason=reason or a.reason)
        self.store.put_approval(a2)
        self._audit("approval.decided", org_id=a.org_id, outcome="ok" if approved else "denied",
                    reason=reason, correlation_id=correlation_id, actor_user_id=decided_by)
        return a2

    def check(self, *, org_id: str, agent_id: str, action: str,
              resource: str) -> Optional[ApprovalRequest]:
        return self.store.find_approval(org_id=org_id, agent_id=agent_id, action=action,
                                        resource=resource, now=self._now())

    def _audit(self, event: str, *, org_id, outcome="ok", reason=None, correlation_id=None,
               actor_user_id=None) -> None:
        if self.audit is None:
            return
        self.audit.record(event, org_id=org_id, outcome=outcome, reason=reason,
                          correlation_id=correlation_id, actor_user_id=actor_user_id)
