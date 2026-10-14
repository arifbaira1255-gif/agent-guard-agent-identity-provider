"""Step 10 policy audit log.

A thin recorder that fans out to two sinks, mirroring ``security/audit.py``:
  * the PostgreSQL ``policy_audit`` table (append-only, migration 0005), and
  * the EXISTING :class:`~agent_identity.observability.logging.SecurityLogger` structured stream
    (allow-listed + secret-redacted), so policy events travel through the same correlation
    architecture as Steps 1-9.

Nothing secret is ever recorded: only ids, decisions, reason codes, timestamps and correlation ids.
"""
from __future__ import annotations

import time
from typing import Optional

from ..observability.logging import SecurityLogger, current_correlation_id
from ..security.ids import new_id
from .store import PolicyStore

# --- event names (stable, greppable) -----------------------------------------------------------
E_POLICY_CREATED = "policy.created"
E_POLICY_VERSION_CREATED = "policy.version.created"
E_POLICY_VALIDATED = "policy.validated"
E_POLICY_TESTED = "policy.tested"
E_POLICY_ACTIVATED = "policy.activated"
E_POLICY_ROLLED_BACK = "policy.rolled_back"
E_POLICY_DISABLED = "policy.disabled"
E_POLICY_DELETED = "policy.deleted"

E_DECISION = "policy.decision"
E_DECISION_DENIED = "policy.decision.denied"
E_ENGINE_UNAVAILABLE = "policy.engine.unavailable"

E_JIT_ISSUED = "jit.grant.issued"
E_JIT_REVOKED = "jit.grant.revoked"
E_JIT_REVOKED_ALL = "jit.grant.revoked_all"

E_APPROVAL_REQUESTED = "approval.requested"
E_APPROVAL_DECIDED = "approval.decided"


class PolicyAudit:
    def __init__(self, store: PolicyStore, logger: Optional[SecurityLogger] = None, clock=None):
        self.store = store
        self.logger = logger
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def record(self, event: str, *, actor_user_id: Optional[str] = None, org_id: Optional[str] = None,
               policy_id: Optional[str] = None, policy_version: Optional[int] = None,
               grant_id: Optional[str] = None, outcome: str = "ok", reason: Optional[str] = None,
               correlation_id: Optional[str] = None) -> dict:
        cid = correlation_id or current_correlation_id()
        ev = {"event_id": new_id("pau"), "ts": self._now(), "event": event,
              "actor_user_id": actor_user_id, "org_id": org_id, "policy_id": policy_id,
              "policy_version": policy_version, "grant_id": grant_id, "outcome": outcome,
              "reason": reason, "correlation_id": cid}
        self.store.append_audit(ev)
        if self.logger is not None:
            self.logger.emit(event, outcome=outcome, reason=reason, actor=actor_user_id,
                             org_id=org_id, target_type="policy" if policy_id else "grant",
                             target_id=policy_id or grant_id, correlation_id=cid)
        return ev
