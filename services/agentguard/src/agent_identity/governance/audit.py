"""Step 11 governance audit log.

A thin recorder that fans out to two sinks, mirroring ``policy/audit.py`` and ``security/audit.py``:

  * the PostgreSQL ``governance_audit`` table (append-only, migration 0006), and
  * the EXISTING :class:`~agent_identity.observability.logging.SecurityLogger` structured stream
    (allow-listed + secret-redacted), so governance events travel through the same correlation
    architecture as Steps 1-10.

Nothing secret is ever recorded: only ids, the decision, reason codes, the operation, timestamps and
correlation ids. Request payloads, tool arguments and connection details are never passed here.
"""
from __future__ import annotations

import time
from typing import Optional

from ..observability.logging import SecurityLogger, current_correlation_id
from ..security.ids import new_id
from .store import GovernanceStore

# --- event names (stable, greppable) -----------------------------------------------------------
E_RESOURCE_REGISTERED = "governance.resource.registered"
E_RESOURCE_UPDATED = "governance.resource.updated"
E_RESOURCE_DELETED = "governance.resource.deleted"
E_RESOURCE_ENABLED = "governance.resource.enabled"
E_RESOURCE_DISABLED = "governance.resource.disabled"

E_TOOL_REGISTERED = "governance.tool.registered"
E_TOOL_APPROVED = "governance.tool.approved"
E_TOOL_DISABLED = "governance.tool.disabled"
E_TOOL_ENABLED = "governance.tool.enabled"
E_TOOL_DELETED = "governance.tool.deleted"
E_TOOL_MANIFEST_REJECTED = "governance.tool.manifest_rejected"

E_DECISION = "governance.decision"
E_DECISION_DENIED = "governance.decision.denied"
E_ENFORCED = "governance.enforced"
E_REGISTRY_ERROR = "governance.registry.error"


class GovernanceAudit:
    def __init__(self, store: GovernanceStore, logger: Optional[SecurityLogger] = None, *,
                 enabled: bool = True, clock=None):
        self.store = store
        self.logger = logger
        self.enabled = enabled
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def record(self, event: str, *, org_id: Optional[str] = None, agent_id: Optional[str] = None,
               instance_id: Optional[str] = None, resource_id: Optional[str] = None,
               resource_type: Optional[str] = None, operation: Optional[str] = None,
               tool_id: Optional[str] = None, decision: Optional[str] = None,
               reason: Optional[str] = None, outcome: str = "ok",
               policy_id: Optional[str] = None, policy_version: Optional[str] = None,
               actor_user_id: Optional[str] = None,
               correlation_id: Optional[str] = None,
               extra: Optional[dict] = None) -> Optional[dict]:
        if not self.enabled:
            return None
        cid = correlation_id or current_correlation_id()
        ev = {"event_id": new_id("gau"), "ts": self._now(), "event": event, "org_id": org_id,
              "agent_id": agent_id, "instance_id": instance_id, "resource_id": resource_id,
              "resource_type": resource_type, "operation": operation, "tool_id": tool_id,
              "decision": decision, "reason": reason, "outcome": outcome, "policy_id": policy_id,
              "policy_version": policy_version, "actor_user_id": actor_user_id,
              "correlation_id": cid}
        if extra:
            # bounded, primitive-only extra detail; never payloads or secrets
            for k, v in extra.items():
                if isinstance(v, (str, int, float, bool)) or v is None:
                    ev.setdefault(k, v)
        self.store.append_audit(ev)
        if self.logger is not None:
            self.logger.emit(event, outcome=outcome, reason=reason, org_id=org_id,
                             agent_id=agent_id, instance_id=instance_id,
                             resource_id=resource_id, resource_type=resource_type,
                             operation=operation, tool_id=tool_id, decision=decision,
                             actor=actor_user_id,
                             target_type=("resource" if resource_id else "tool"),
                             target_id=resource_id or tool_id, correlation_id=cid)
        return ev
