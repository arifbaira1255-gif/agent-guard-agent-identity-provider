"""Phase 6 cross-component response orchestration.

Wires the response plane together: it selects a response LEVEL from trusted evidence, plans the
containment actions that level authorizes, preserves evidence, executes the plan through the
containment engine, and records an auditable, idempotent :class:`ResponseExecution`.

Separation of concerns (requirement 9): detection (``loops``), risk assessment (Phase 5 risk engine),
and enforcement (policy engine / identity plane / egress / governance) stay separate components. This
module only *coordinates*; it never authorizes anything itself and never bypasses the policy engine.

Safety properties implemented here:

* **Idempotency** -- an execution is keyed by ``(org_id, idempotency_key)``; a duplicate delivery of
  the same trigger returns the existing execution instead of running containment twice.
* **Concurrency** -- a per-(org, agent) lock serializes overlapping containment for one agent, so two
  concurrent incidents cannot interleave destructive steps on the same target.
* **Validated transitions** -- the response state machine rejects an illegal transition.
* **Honest outcomes** -- any failed step yields ``PARTIAL`` (or ``FAILED`` when nothing succeeded);
  success is never reported for a plan that did not fully apply.
* **Evidence before destruction** -- evidence is preserved and sealed before a non-reversible step.
* **No privilege escalation on recovery** -- rollback only ever *relaxes* a reversible action and
  requires a verified authorizing identity.
* **Untrusted content cannot authorize** -- ``authorized_by`` must come from the caller's verified
  context; an agent-supplied string is not accepted.
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple

from ..runtime_monitoring.models import Severity
from ..security.ids import new_id
from .config import ResponseConfig
from .errors import ResponseOrchestrationError
from .models import (CONTAINMENT_ACTION_SPECS, RESPONSE_LEVEL_ACTIONS, RESPONSE_STATE_TRANSITIONS,
                     RESPONSE_TERMINAL_STATES, ContainmentAction, LoopClassification,
                     ResponseExecution, ResponseLevel, ResponseState, ResponseStep)

#: Risk bands ordered weakest -> strongest, for level selection.
_BAND_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class ResponseOrchestrator:
    """Plans and executes containment responses, idempotently and auditably."""

    def __init__(self, *, store, containment, evidence, incidents, audit=None,
                 config: Optional[ResponseConfig] = None, clock=None):
        self.store = store
        self.containment = containment
        self.evidence = evidence
        self.incidents = incidents
        self.audit = audit
        self.cfg = config or ResponseConfig()
        self._clock = clock
        self._locks: Dict[Tuple[str, str], threading.RLock] = {}
        self._locks_guard = threading.Lock()

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def _lock_for(self, org_id: str, agent_id: Optional[str]) -> threading.RLock:
        key = (org_id, agent_id or "-")
        with self._locks_guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.RLock()
                self._locks[key] = lock
            return lock

    # ------------------------------------------------------------------ level selection
    def select_level(self, *, risk_band: Optional[str] = None,
                     classification: Optional[str] = None,
                     severity: Optional[str] = None) -> ResponseLevel:
        """Choose a response level from trusted evidence.

        A statistical anomaly or a heuristic suspicion NEVER escalates past ``RESTRICT`` on its own --
        only a confirmed policy violation (or a critical risk band) can reach ``SUSPEND``/``INCIDENT``.
        This is the code-level enforcement of "do not automatically impose the most disruptive
        response for every statistical anomaly".
        """
        band = (risk_band or "low").strip().lower()
        rank = _BAND_RANK.get(band, 0)
        cls = None
        if classification is not None:
            try:
                cls = LoopClassification.coerce(classification)
            except ValueError:
                cls = None
        sev = Severity.coerce(severity).value if severity else None

        if cls == LoopClassification.INSUFFICIENT_EVIDENCE:
            return ResponseLevel.OBSERVE
        if cls == LoopClassification.NORMAL_RETRY:
            return ResponseLevel.OBSERVE
        if cls == LoopClassification.SUSPICIOUS_REPETITION:
            # Heuristic only: cap at RESTRICT regardless of the risk band.
            return ResponseLevel.RESTRICT if rank >= _BAND_RANK[self.cfg.restrict_risk_band] \
                else ResponseLevel.REQUIRE_APPROVAL
        if cls == LoopClassification.CONFIRMED_VIOLATION:
            if rank >= _BAND_RANK[self.cfg.suspend_risk_band] or sev == Severity.CRITICAL.value:
                return ResponseLevel.INCIDENT
            if rank >= _BAND_RANK[self.cfg.restrict_risk_band]:
                return ResponseLevel.SUSPEND
            return ResponseLevel.RESTRICT
        # No classification supplied: fall back to the risk band alone, capped at RESTRICT.
        if rank >= _BAND_RANK[self.cfg.suspend_risk_band]:
            return ResponseLevel.RESTRICT
        if rank >= _BAND_RANK[self.cfg.restrict_risk_band]:
            return ResponseLevel.REQUIRE_APPROVAL
        return ResponseLevel.OBSERVE

    def plan(self, *, level: ResponseLevel, agent_id: Optional[str],
             destination: Optional[str] = None, tool_id: Optional[str] = None
             ) -> List[ContainmentAction]:
        """The actions a level authorizes, filtered to those applicable to this target."""
        actions = list(RESPONSE_LEVEL_ACTIONS.get(level, ()))
        out: List[ContainmentAction] = []
        for a in actions:
            if a == ContainmentAction.BLOCK_DESTINATION and not destination:
                continue
            if a == ContainmentAction.DISABLE_TOOL and not tool_id:
                continue
            if a != ContainmentAction.BLOCK_DESTINATION and not agent_id:
                continue
            out.append(a)
        return out[:self.cfg.response_max_actions_per_plan]

    # ------------------------------------------------------------------ execution
    def execute(self, *, org_id: str, level: ResponseLevel, agent_id: Optional[str] = None,
                incident_id: Optional[str] = None, task_id: Optional[str] = None,
                trigger: str = "", authorized_by: Optional[str] = None, approved: bool = False,
                auto: bool = False, destination: Optional[str] = None,
                tool_id: Optional[str] = None, reason: str = "",
                idempotency_key: Optional[str] = None,
                evidence_items: Sequence[dict] = ()) -> ResponseExecution:
        """Plan and execute a containment response. Idempotent per ``idempotency_key``.

        ``authorized_by`` is REQUIRED: containment cannot be authorized by agent-generated content.
        """
        if not authorized_by or not isinstance(authorized_by, str):
            raise ResponseOrchestrationError(
                "containment requires a verified authorizing identity")
        key = idempotency_key or f"{incident_id or 'adhoc'}|{level.value}|{agent_id or '-'}"
        existing = self.store.get_response_by_key(org_id=org_id, idempotency_key=key)
        if existing is not None:
            self._audit("response.execution.duplicate", org_id=org_id, agent_id=agent_id,
                        outcome="ok", reason="idempotent_replay",
                        actor_user_id=authorized_by,
                        extra={"response_id": existing.response_id, "key": key[:200]})
            return existing

        actions = self.plan(level=level, agent_id=agent_id, destination=destination,
                            tool_id=tool_id)
        now = self._now()
        ex = ResponseExecution(
            response_id=new_id("rsp"), org_id=org_id, idempotency_key=key,
            incident_id=incident_id, agent_id=agent_id, task_id=task_id,
            state=ResponseState.PLANNED.value, trigger=trigger[:512],
            requested_by=authorized_by, approved_by=(authorized_by if approved else None),
            created_at=now, updated_at=now)
        self.store.put_response(ex)
        self._audit("response.execution.planned", org_id=org_id, agent_id=agent_id,
                    actor_user_id=authorized_by,
                    extra={"response_id": ex.response_id, "level": level.value,
                           "actions": [a.value for a in actions], "key": key[:200]})

        if level == ResponseLevel.OBSERVE or not actions:
            self._transition(ex, ResponseState.SUCCEEDED, note="observe-only: no containment action")
            self.store.put_response(ex)
            return ex

        with self._lock_for(org_id, agent_id):
            # Re-check under the lock: a concurrent caller may have completed the same key.
            raced = self.store.get_response_by_key(org_id=org_id, idempotency_key=key)
            if raced is not None and raced.response_id != ex.response_id \
                    and raced.state in {s.value for s in RESPONSE_TERMINAL_STATES}:
                return raced
            self._transition(ex, ResponseState.RUNNING, note="containment started")
            self.store.put_response(ex)

            # --- preserve evidence BEFORE any destructive step -------------------------------
            destructive = [a for a in actions
                           if not CONTAINMENT_ACTION_SPECS.get(a, {}).get("reversible", False)]
            if destructive:
                items = list(evidence_items) or [{
                    "kind": "pre_containment_state",
                    "summary": f"state captured before {len(destructive)} non-reversible action(s)",
                    "payload": {"actions": [a.value for a in destructive], "agent_id": agent_id,
                                "level": level.value, "trigger": trigger[:200]}}]
                records = self.evidence.preserve_many(org_id=org_id, items=items,
                                                      incident_id=incident_id, agent_id=agent_id,
                                                      seal=True)
                ex.evidence_ids = tuple(r.evidence_id for r in records)

            ok, failed, unavailable = 0, 0, 0
            for action in actions:
                step = self.containment.execute(
                    action=action, org_id=org_id, agent_id=agent_id, destination=destination,
                    tool_id=tool_id, reason=reason, authorized_by=authorized_by,
                    approved=approved, auto=auto)
                ex.steps.append(step)
                if step.status == "ok":
                    ok += 1
                elif step.status == "unavailable":
                    unavailable += 1
                else:
                    failed += 1
                ex.updated_at = self._now()
                self.store.put_response(ex)

            ex.partial_failures = tuple(
                f"{s.action}:{s.status}" for s in ex.steps if s.status not in ("ok",))
            if ok and (failed or unavailable):
                final = ResponseState.PARTIAL
                note = f"{ok} applied, {failed} failed, {unavailable} unavailable"
            elif ok and not failed and not unavailable:
                final = ResponseState.SUCCEEDED
                note = f"{ok} action(s) applied"
            else:
                final = ResponseState.FAILED
                note = f"no action applied ({failed} failed, {unavailable} unavailable)"
            self._transition(ex, final, note=note)
            self.store.put_response(ex)

        if incident_id:
            try:
                self.incidents.link_response(org_id=org_id, incident_id=incident_id,
                                             response_id=ex.response_id,
                                             actor_user_id=authorized_by)
            except Exception:  # noqa: BLE001 - linking is best-effort; the execution is recorded
                pass
        return ex

    # ------------------------------------------------------------------ rollback
    def rollback(self, *, org_id: str, response_id: str, authorized_by: Optional[str] = None,
                 reason: str = "rollback") -> ResponseExecution:
        """Roll back the reversible steps of an execution, recording every outcome."""
        ex = self.store.get_response(response_id, org_id=org_id)
        if ex is None:
            raise ResponseOrchestrationError("unknown response execution")
        if not authorized_by:
            raise ResponseOrchestrationError("rollback requires a verified authorizing identity")
        if ex.state not in {ResponseState.SUCCEEDED.value, ResponseState.PARTIAL.value,
                            ResponseState.FAILED.value}:
            raise ResponseOrchestrationError(
                f"cannot roll back an execution in state {ex.state}")
        with self._lock_for(org_id, ex.agent_id):
            rolled, skipped, failed = 0, 0, 0
            for step in reversed(ex.steps):
                if step.status != "ok":
                    continue
                rb = self.containment.rollback(step=step, org_id=org_id, agent_id=ex.agent_id,
                                               authorized_by=authorized_by)
                ex.rollback_steps.append(rb)
                if rb.status == "rolled_back":
                    rolled += 1
                elif rb.status == "skipped":
                    skipped += 1
                else:
                    failed += 1
            final = (ResponseState.ROLLED_BACK if failed == 0
                     else ResponseState.ROLLBACK_FAILED)
            self._transition(ex, final,
                             note=f"{rolled} rolled back, {skipped} not reversible, {failed} failed")
            self.store.put_response(ex)
        self._audit("response.execution.rollback", org_id=org_id, agent_id=ex.agent_id,
                    outcome=ex.state, reason=reason, actor_user_id=authorized_by,
                    extra={"response_id": response_id})
        return ex

    # ------------------------------------------------------------------ reads
    def get(self, *, org_id: str, response_id: str) -> Optional[ResponseExecution]:
        return self.store.get_response(response_id, org_id=org_id)

    def list(self, *, org_id: str, incident_id: Optional[str] = None,
             agent_id: Optional[str] = None, limit: int = 100) -> List[ResponseExecution]:
        return self.store.list_responses(org_id=org_id, incident_id=incident_id,
                                         agent_id=agent_id, limit=limit)

    # ------------------------------------------------------------------ state machine
    def _transition(self, ex: ResponseExecution, target: ResponseState, *, note: str = "") -> None:
        current = ResponseState.coerce(ex.state)
        if target == current:
            return
        if target not in RESPONSE_STATE_TRANSITIONS.get(current, frozenset()):
            raise ResponseOrchestrationError(
                f"invalid response transition {current.value} -> {target.value}")
        ex.state = target.value
        ex.updated_at = self._now()
        ex.note = note[:512]
        self._audit("response.execution.state", org_id=ex.org_id, agent_id=ex.agent_id,
                    outcome=target.value, reason=note[:200],
                    extra={"response_id": ex.response_id})

    # ------------------------------------------------------------------ audit helper
    def _audit(self, event: str, *, org_id: Optional[str] = None, agent_id: Optional[str] = None,
               outcome: str = "ok", reason: Optional[str] = None,
               actor_user_id: Optional[str] = None, extra: Optional[dict] = None) -> None:
        if self.audit is not None:
            self.audit.record(event, org_id=org_id, agent_id=agent_id, outcome=outcome,
                              reason=reason, actor_user_id=actor_user_id, extra=extra)
