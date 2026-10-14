"""Phase 6 response-plane audit log with a hash chain.

A thin recorder that fans out to two sinks, mirroring ``runtime_monitoring/audit.py``,
``egress/audit.py`` and ``governance/audit.py``:

  * the PostgreSQL ``response_audit`` table (append-only, migration 0009), and
  * the EXISTING :class:`~agent_identity.observability.logging.SecurityLogger` structured stream
    (allow-listed + secret-redacted), so Phase 6 events travel through the same correlation
    architecture as Steps 1-11 and Phases 4-5.

Tamper evidence -- stated precisely
-----------------------------------
Each record carries ``prev_hash`` (the previous record's ``hash`` for the same tenant) and ``hash``
= SHA-256 over ``prev_hash`` + the canonical record. :meth:`verify_chain` recomputes the chain and
reports the first divergence, so a modified, reordered or removed record is DETECTED.

This is a **hash chain, not a notarization**: an attacker with write access to the whole log could
recompute every subsequent hash and produce a self-consistent chain. Detecting that requires external
anchoring (publishing the head hash to an append-only external system), which is NOT implemented here
and is listed as a limitation. Do not describe this as cryptographically tamper-proof.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import List, Optional

from ..observability.logging import SecurityLogger, current_correlation_id
from ..security.ids import new_id
from .store import ResponseStore

# --- event names (stable, greppable) -----------------------------------------------------------
E_LOOP_FINDING = "response.loop.finding"
E_BUDGET_SET = "response.budget.set"
E_BUDGET_DELETED = "response.budget.deleted"
E_GUARD_REFUSED = "response.guard.refused"
E_STOP_RAISED = "response.emergency_stop.raised"
E_STOP_RELEASED = "response.emergency_stop.released"
E_APPROVAL_REQUESTED = "response.approval.requested"
E_APPROVAL_DECIDED = "response.approval.decided"
E_APPROVAL_DENIED = "response.approval.denied"
E_APPROVAL_CANCELLED = "response.approval.cancelled"
E_APPROVAL_DELEGATED = "response.approval.delegated"
E_APPROVAL_EXPIRED = "response.approval.expired"
E_APPROVAL_MISMATCH = "response.approval.mismatch"
E_INCIDENT_OPENED = "response.incident.opened"
E_INCIDENT_TRANSITION = "response.incident.transition"
E_CONTAINMENT_STEP = "response.containment.step"
E_CONTAINMENT_DENIED = "response.containment.denied"
E_RESPONSE_STATE = "response.execution.state"
E_RESPONSE_ROLLBACK = "response.execution.rollback"
E_EVIDENCE_PRESERVED = "response.evidence.preserved"
E_EVIDENCE_SEALED = "response.evidence.sealed"
E_EVIDENCE_RETENTION = "response.evidence.retention"
E_LEVEL_SELECTED = "response.level.selected"

#: Fields that participate in the hash. Everything else is carried alongside but not hashed.
_CHAIN_FIELDS = ("event_id", "ts", "event", "org_id", "agent_id", "outcome", "reason",
                 "actor_user_id", "action", "correlation_id")


def _canonical(record: dict) -> str:
    payload = {k: record.get(k) for k in _CHAIN_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(prev_hash: Optional[str], record: dict) -> str:
    """SHA-256 over ``prev_hash`` + the canonical record."""
    blob = f"{prev_hash or ''}|{_canonical(record)}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class ResponseAudit:
    """Hash-chained audit recorder for the response plane's own actions."""

    def __init__(self, store: ResponseStore, logger: Optional[SecurityLogger] = None, *,
                 enabled: bool = True, clock=None):
        self.store = store
        self.logger = logger
        self.enabled = enabled
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def record(self, event: str, *, org_id: Optional[str] = None, agent_id: Optional[str] = None,
               outcome: str = "ok", reason: Optional[str] = None,
               incident_id: Optional[str] = None, approval_id: Optional[str] = None,
               response_id: Optional[str] = None, evidence_id: Optional[str] = None,
               actor_user_id: Optional[str] = None, action: Optional[str] = None,
               correlation_id: Optional[str] = None,
               extra: Optional[dict] = None) -> Optional[dict]:
        if not self.enabled:
            return None
        cid = correlation_id or current_correlation_id()
        ev = {"event_id": new_id("rau"), "ts": self._now(), "event": event, "org_id": org_id,
              "agent_id": agent_id, "outcome": outcome, "reason": reason,
              "incident_id": incident_id, "approval_id": approval_id,
              "response_id": response_id, "evidence_id": evidence_id,
              "actor_user_id": actor_user_id, "action": action, "correlation_id": cid}
        if extra:
            # bounded, primitive-only extra detail; never payloads or secrets
            for k, v in extra.items():
                if isinstance(v, (str, int, float, bool)) or v is None:
                    ev.setdefault(k, v)
        head = self.store.audit_chain_head(org_id=org_id)
        prev_hash = head.get("hash") if head else None
        ev["prev_hash"] = prev_hash
        ev["hash"] = compute_hash(prev_hash, ev)
        self.store.append_audit(ev)
        if self.logger is not None:
            self.logger.emit(event, outcome=outcome, reason=reason, org_id=org_id,
                             agent_id=agent_id, target_type="response",
                             target_id=incident_id or approval_id or response_id or evidence_id,
                             actor=actor_user_id, correlation_id=cid)
        return ev

    # ------------------------------------------------------------------ integrity
    def verify_chain(self, *, org_id: Optional[str] = None, limit: int = 10_000) -> dict:
        """Recompute the chain and report the first divergence.

        Returns ``{"ok": bool, "checked": n, "broken_at": event_id|None, "reason": str}``.
        """
        rows = self.store.list_audit(org_id=org_id, limit=limit)
        rows = [r for r in rows if r.get("hash")]
        # ``list_audit`` returns records in INSERTION order (the order the chain was built in). We
        # must NOT re-sort here, or reordering/removal of records becomes undetectable.
        prev = None
        for i, r in enumerate(rows):
            if r.get("prev_hash") != prev:
                return {"ok": False, "checked": i, "broken_at": r.get("event_id"),
                        "reason": "prev_hash does not match the preceding record"}
            if compute_hash(prev, r) != r.get("hash"):
                return {"ok": False, "checked": i, "broken_at": r.get("event_id"),
                        "reason": "record hash does not match its content"}
            prev = r.get("hash")
        return {"ok": True, "checked": len(rows), "broken_at": None, "reason": "chain intact"}

    def chain_head(self, *, org_id: Optional[str] = None) -> Optional[dict]:
        return self.store.audit_chain_head(org_id=org_id)

    def list(self, *, org_id: Optional[str] = None, limit: int = 100) -> List[dict]:
        return self.store.list_audit(org_id=org_id, limit=limit)
