"""Phase 4 egress/DLP audit log.

A thin recorder that fans out to two sinks, mirroring ``governance/audit.py`` and ``policy/audit.py``:

  * the PostgreSQL ``egress_audit`` table (append-only, migration 0007), and
  * the EXISTING :class:`~agent_identity.observability.logging.SecurityLogger` structured stream
    (allow-listed + secret-redacted), so egress/DLP events travel through the same correlation
    architecture as Steps 1-11.

Nothing secret is ever recorded: only ids, the decision, reason codes, the destination host, the
resolved address CLASS (never the payload), DLP rule ids and correlation ids. Request bodies, tool
arguments and connection details are never passed here.
"""
from __future__ import annotations

import time
from typing import Optional, Tuple

from ..observability.logging import SecurityLogger, current_correlation_id
from ..security.ids import new_id
from .store import EgressStore

# --- event names (stable, greppable) -----------------------------------------------------------
E_POLICY_REGISTERED = "egress.policy.registered"
E_POLICY_UPDATED = "egress.policy.updated"
E_POLICY_DELETED = "egress.policy.deleted"
E_POLICY_ENABLED = "egress.policy.enabled"
E_POLICY_DISABLED = "egress.policy.disabled"

E_REQUEST_ALLOWED = "egress.request.allowed"
E_REQUEST_DENIED = "egress.request.denied"
E_REQUEST_APPROVAL = "egress.request.approval_required"
E_REQUEST_INDETERMINATE = "egress.request.indeterminate"
E_SSRF_BLOCKED = "egress.ssrf.blocked"
E_REDIRECT_BLOCKED = "egress.redirect.blocked"
E_RATE_LIMITED = "egress.rate_limited"
E_GATEWAY_ERROR = "egress.gateway.error"

E_DLP_CLEAN = "egress.dlp.clean"
E_DLP_REDACTED = "egress.dlp.redacted"
E_DLP_BLOCKED = "egress.dlp.blocked"
E_DLP_APPROVAL = "egress.dlp.approval_required"
E_DLP_INDETERMINATE = "egress.dlp.indeterminate"


class EgressAudit:
    def __init__(self, store: EgressStore, logger: Optional[SecurityLogger] = None, *,
                 enabled: bool = True, clock=None):
        self.store = store
        self.logger = logger
        self.enabled = enabled
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def record(self, event: str, *, org_id: Optional[str] = None, agent_id: Optional[str] = None,
               instance_id: Optional[str] = None, destination: Optional[str] = None,
               host: Optional[str] = None, port: Optional[int] = None,
               protocol: Optional[str] = None, resource_id: Optional[str] = None,
               operation: Optional[str] = None, decision: Optional[str] = None,
               reason: Optional[str] = None, outcome: str = "ok",
               policy_id: Optional[str] = None, policy_version: Optional[str] = None,
               dlp_rule_ids: Tuple[str, ...] = (), dlp_severity: Optional[str] = None,
               resolved_ips: Tuple[str, ...] = (), address_class: Optional[str] = None,
               actor_user_id: Optional[str] = None, correlation_id: Optional[str] = None,
               latency_ms: Optional[int] = None, extra: Optional[dict] = None) -> Optional[dict]:
        if not self.enabled:
            return None
        cid = correlation_id or current_correlation_id()
        ev = {"event_id": new_id("eau"), "ts": self._now(), "event": event, "org_id": org_id,
              "agent_id": agent_id, "instance_id": instance_id, "destination": destination,
              "host": host, "port": port, "protocol": protocol, "resource_id": resource_id,
              "operation": operation, "decision": decision, "reason": reason, "outcome": outcome,
              "policy_id": policy_id, "policy_version": policy_version,
              "dlp_rule_ids": list(dlp_rule_ids or ()), "dlp_severity": dlp_severity,
              "resolved_ips": list(resolved_ips or ()), "address_class": address_class,
              "actor_user_id": actor_user_id, "correlation_id": cid, "latency_ms": latency_ms}
        if extra:
            # bounded, primitive-only extra detail; never payloads or secrets
            for k, v in extra.items():
                if isinstance(v, (str, int, float, bool)) or v is None:
                    ev.setdefault(k, v)
        self.store.append_audit(ev)
        if self.logger is not None:
            self.logger.emit(event, outcome=outcome, reason=reason, org_id=org_id,
                             agent_id=agent_id, instance_id=instance_id,
                             target_type="egress", target_id=destination or host,
                             correlation_id=cid)
        return ev
