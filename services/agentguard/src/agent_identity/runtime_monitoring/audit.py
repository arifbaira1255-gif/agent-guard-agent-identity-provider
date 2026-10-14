"""Phase 5 runtime-monitoring audit log.

A thin recorder that fans out to two sinks, mirroring ``egress/audit.py``, ``governance/audit.py``
and ``policy/audit.py``:

  * the PostgreSQL ``runtime_monitoring_audit`` table (append-only, migration 0008), and
  * the EXISTING :class:`~agent_identity.observability.logging.SecurityLogger` structured stream
    (allow-listed + secret-redacted), so Phase 5 events travel through the same correlation
    architecture as Steps 1-11.

This is the audit of the *monitoring plane's own* actions (rule changes, alert lifecycle, response
actions, retention runs) -- distinct from the runtime telemetry it ingests. Nothing secret is ever
recorded: ids, decisions, reason codes and counts only.
"""
from __future__ import annotations

import time
from typing import Optional

from ..observability.logging import SecurityLogger, current_correlation_id
from ..security.ids import new_id
from .store import RuntimeMonitoringStore

# --- event names (stable, greppable) -----------------------------------------------------------
E_RULE_REGISTERED = "runtime.alert_rule.registered"
E_RULE_DELETED = "runtime.alert_rule.deleted"
E_ALERT_RAISED = "runtime.alert.raised"
E_ALERT_DEDUPED = "runtime.alert.deduped"
E_ALERT_RATE_LIMITED = "runtime.alert.rate_limited"
E_ALERT_STATE = "runtime.alert.state_changed"
E_FINDING_RECORDED = "runtime.drift.finding"
E_ASSESSMENT_RECORDED = "runtime.risk.assessment"
E_RESPONSE_ACTION = "runtime.response.action"
E_RESPONSE_DENIED = "runtime.response.denied"
E_PROFILE_BUILT = "runtime.profile.built"
E_PROFILE_RESET = "runtime.profile.reset"
E_GRAPH_UPDATED = "runtime.graph.updated"
E_RETENTION_PURGED = "runtime.retention.purged"
E_INGEST_REJECTED = "runtime.ingest.rejected"
E_INGEST_DUPLICATE = "runtime.ingest.duplicate"


class RuntimeMonitoringAudit:
    def __init__(self, store: RuntimeMonitoringStore, logger: Optional[SecurityLogger] = None, *,
                 enabled: bool = True, clock=None):
        self.store = store
        self.logger = logger
        self.enabled = enabled
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def record(self, event: str, *, org_id: Optional[str] = None, agent_id: Optional[str] = None,
               outcome: str = "ok", reason: Optional[str] = None, alert_id: Optional[str] = None,
               rule_id: Optional[str] = None, finding_id: Optional[str] = None,
               assessment_id: Optional[str] = None, event_id: Optional[str] = None,
               actor_user_id: Optional[str] = None, action: Optional[str] = None,
               correlation_id: Optional[str] = None,
               extra: Optional[dict] = None) -> Optional[dict]:
        if not self.enabled:
            return None
        cid = correlation_id or current_correlation_id()
        ev = {"event_id": new_id("rau"), "ts": self._now(), "event": event, "org_id": org_id,
              "agent_id": agent_id, "outcome": outcome, "reason": reason, "alert_id": alert_id,
              "rule_id": rule_id, "finding_id": finding_id, "assessment_id": assessment_id,
              "runtime_event_id": event_id, "actor_user_id": actor_user_id, "action": action,
              "correlation_id": cid}
        if extra:
            # bounded, primitive-only extra detail; never payloads or secrets
            for k, v in extra.items():
                if isinstance(v, (str, int, float, bool)) or v is None:
                    ev.setdefault(k, v)
        self.store.append_audit(ev)
        if self.logger is not None:
            self.logger.emit(event, outcome=outcome, reason=reason, org_id=org_id,
                             agent_id=agent_id, target_type="runtime",
                             target_id=alert_id or finding_id or rule_id or event_id,
                             actor=actor_user_id, correlation_id=cid)
        return ev
