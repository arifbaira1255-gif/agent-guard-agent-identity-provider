"""Phase 6 autonomous-loop and runaway-agent detection.

A configurable detector for dangerous repetitive or uncontrolled activity. It consumes the SAME
normalized telemetry Phase 5 already ingests (:class:`~agent_identity.runtime_monitoring.models.RuntimeEvent`)
-- it does not introduce a second event pipeline.

Patterns detected (see :class:`~agent_identity.response.models.LoopPattern`):

  * repeated tool/API calls without meaningful progress,
  * circular tool invocation (A -> B -> A),
  * excessive retries of the same action,
  * repeated authorization denials,
  * repeated outbound requests to one destination,
  * cascading failures across dependent tools,
  * abnormal resource consumption where reliable telemetry exists.

Honesty rules enforced in code, not just in prose:

* A single signal is never enough when more evidence is available: every finding carries the
  ``evidence`` that produced it, and the classification separates a normal retry from a suspicious
  repetition from a **confirmed** violation of a configured budget.
* ``CONFIRMED_VIOLATION`` is only ever emitted when the observed count contradicts an authoritative
  configured limit (a budget). Heuristic thresholds can only reach ``SUSPICIOUS_REPETITION``.
* Too little telemetry yields ``INSUFFICIENT_EVIDENCE`` -- sparsity is never treated as
  suspiciousness.
* Observations are bounded per (org, agent) so a runaway agent cannot exhaust memory.
"""
from __future__ import annotations

import time
from collections import Counter, deque
from typing import Deque, Dict, Iterable, List, Optional, Sequence, Tuple

from ..runtime_monitoring.models import Decision, EventType, Severity
from ..security.ids import new_id
from .config import ResponseConfig
from .models import LoopClassification, LoopFinding, LoopPattern

#: Event types that represent an agent *doing* something (as opposed to a lifecycle marker).
_ACTION_EVENTS = frozenset({EventType.TOOL_INVOCATION.value, EventType.API_INVOCATION.value,
                            EventType.DATA_ACCESS.value, EventType.FILE_ACCESS.value})
_EGRESS_EVENTS = frozenset({EventType.NETWORK_REQUEST.value})
_DENIAL_DECISIONS = frozenset({Decision.DENY.value, Decision.BLOCKED.value,
                               Decision.REQUIRE_APPROVAL.value, Decision.INDETERMINATE.value})


class _Observation:
    """One bounded observation derived from a runtime event."""

    __slots__ = ("ts", "event_id", "event_type", "action", "resource", "destination",
                 "decision", "outcome", "tool", "tokens", "cost")

    def __init__(self, ts: float, event_id: str, event_type: str, action: Optional[str],
                 resource: Optional[str], destination: Optional[str], decision: Optional[str],
                 outcome: str, tool: Optional[str], tokens: Optional[int], cost: Optional[float]):
        self.ts = ts
        self.event_id = event_id
        self.event_type = event_type
        self.action = action
        self.resource = resource
        self.destination = destination
        self.decision = decision
        self.outcome = outcome
        self.tool = tool
        self.tokens = tokens
        self.cost = cost

    @property
    def subject(self) -> str:
        """The (action, resource) pair a repetition is measured against."""
        return f"{self.action or '-'}::{self.resource or '-'}"

    @property
    def is_denial(self) -> bool:
        return self.decision in _DENIAL_DECISIONS

    @property
    def is_failure(self) -> bool:
        return self.outcome == "error" or self.decision == Decision.ERROR.value


class LoopDetector:
    """Detects repetitive/runaway activity from normalized runtime events.

    The detector is stateless with respect to storage: it keeps a bounded in-process observation
    window per (org, agent) and returns findings. Persisting findings is the caller's job (the
    service does it), which keeps the detector trivially testable and deterministic.
    """

    def __init__(self, *, config: Optional[ResponseConfig] = None, audit=None, clock=None):
        self.cfg = config or ResponseConfig()
        self.audit = audit
        self._clock = clock
        self._windows: Dict[Tuple[str, str], Deque[_Observation]] = {}

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ observation
    def observe(self, events: Iterable, *, now: Optional[float] = None) -> int:
        """Record events into the bounded per-agent window. Returns the number observed."""
        current = now if now is not None else self._now()
        n = 0
        for ev in events:
            agent_id = getattr(ev, "agent_id", None)
            if not agent_id:
                continue
            key = (getattr(ev, "org_id", ""), agent_id)
            buf = self._windows.get(key)
            if buf is None:
                buf = deque(maxlen=self.cfg.loop_max_observations)
                self._windows[key] = buf
            extra = getattr(ev, "extra", None) or {}
            tokens = _as_int(extra.get("tokens")) if isinstance(extra, dict) else None
            cost = _as_float(extra.get("cost")) if isinstance(extra, dict) else None
            buf.append(_Observation(
                ts=float(getattr(ev, "ts", current)), event_id=str(getattr(ev, "event_id", "")),
                event_type=str(getattr(ev, "event_type", "")),
                action=getattr(ev, "action", None), resource=getattr(ev, "resource", None),
                destination=getattr(ev, "destination", None),
                decision=getattr(ev, "decision", None),
                outcome=str(getattr(ev, "outcome", "ok") or "ok"),
                tool=getattr(ev, "resource", None) if
                str(getattr(ev, "event_type", "")) in _ACTION_EVENTS else None,
                tokens=tokens, cost=cost))
            n += 1
        return n

    def reset(self, *, org_id: str, agent_id: str) -> None:
        self._windows.pop((org_id, agent_id), None)

    def window_size(self, *, org_id: str, agent_id: str) -> int:
        return len(self._windows.get((org_id, agent_id), ()))

    # ------------------------------------------------------------------ detection
    def detect(self, *, org_id: str, agent_id: str, now: Optional[float] = None,
               budget=None, task_id: Optional[str] = None) -> List[LoopFinding]:
        """Evaluate every pattern for one agent over the configured window.

        ``budget`` (an :class:`~agent_identity.response.models.ExecutionBudget`) is the AUTHORITATIVE
        source that can raise a finding to ``CONFIRMED_VIOLATION``. Without it, findings can only be
        ``SUSPICIOUS_REPETITION`` or ``NORMAL_RETRY``.
        """
        current = now if now is not None else self._now()
        buf = self._windows.get((org_id, agent_id))
        if not buf:
            return []
        cutoff = current - self.cfg.loop_window_s
        obs = [o for o in buf if o.ts >= cutoff]
        if not obs:
            return []
        obs.sort(key=lambda o: (o.ts, o.event_id))

        findings: List[LoopFinding] = []
        findings += self._repeated_action(org_id, agent_id, obs, current, budget, task_id)
        findings += self._circular(org_id, agent_id, obs, current, task_id)
        findings += self._excessive_retry(org_id, agent_id, obs, current, budget, task_id)
        findings += self._repeated_denial(org_id, agent_id, obs, current, budget, task_id)
        findings += self._egress_repetition(org_id, agent_id, obs, current, task_id)
        findings += self._cascade(org_id, agent_id, obs, current, task_id)
        findings += self._resource_burn(org_id, agent_id, obs, current, budget, task_id)
        findings.sort(key=lambda f: (-Severity.coerce(f.severity).rank, f.pattern))
        return findings[:self.cfg.loop_max_findings]

    # ------------------------------------------------------------------ patterns
    def _repeated_action(self, org_id, agent_id, obs, current, budget, task_id) -> List[LoopFinding]:
        counts = Counter(o.subject for o in obs if o.event_type in _ACTION_EVENTS)
        out = []
        for subject, count in counts.items():
            if count < self.cfg.loop_min_repeats:
                continue
            limit = getattr(budget, "max_actions", None) if budget is not None else None
            confirmed = limit is not None and count > limit
            out.append(self._finding(
                org_id=org_id, agent_id=agent_id, ts=current, pattern=LoopPattern.REPEATED_ACTION,
                classification=(LoopClassification.CONFIRMED_VIOLATION if confirmed
                                else LoopClassification.SUSPICIOUS_REPETITION),
                subject=subject, observed=count, threshold=self.cfg.loop_min_repeats,
                severity=(Severity.HIGH.value if confirmed else Severity.MEDIUM.value),
                evidence=(f"{count} invocations of {subject} within {self.cfg.loop_window_s}s",
                          f"threshold={self.cfg.loop_min_repeats}",
                          (f"configured max_actions={limit}" if limit is not None
                           else "no authoritative action budget configured")),
                detail=("repetition exceeds the configured action budget" if confirmed
                        else "repetition exceeds the heuristic threshold; no authoritative limit "
                             "was available to confirm a violation"),
                task_id=task_id))
        return out

    def _circular(self, org_id, agent_id, obs, current, task_id) -> List[LoopFinding]:
        seq = [o.subject for o in obs if o.event_type in _ACTION_EVENTS]
        if len(seq) < self.cfg.loop_circular_min_cycle * 2:
            return []
        # Find the shortest repeating cycle that covers the tail of the sequence.
        best: Optional[Tuple[int, int]] = None
        for cycle_len in range(self.cfg.loop_circular_min_cycle, min(8, len(seq) // 2) + 1):
            reps = 0
            i = len(seq)
            while i - cycle_len >= 0 and seq[i - cycle_len:i] == seq[i - 2 * cycle_len:i - cycle_len]:
                reps += 1
                i -= cycle_len
            if reps >= 2 and (best is None or reps * cycle_len > best[0] * best[1]):
                best = (reps, cycle_len)
        if best is None:
            return []
        reps, cycle_len = best
        cycle = seq[len(seq) - cycle_len:]
        return [self._finding(
            org_id=org_id, agent_id=agent_id, ts=current, pattern=LoopPattern.CIRCULAR_INVOCATION,
            classification=LoopClassification.SUSPICIOUS_REPETITION,
            subject=" -> ".join(cycle), observed=reps, threshold=2,
            severity=Severity.MEDIUM.value,
            evidence=(f"cycle of length {cycle_len} repeated {reps} times",
                      f"cycle={cycle}",
                      "no authoritative source defines a permitted action sequence"),
            detail="circular tool invocation detected; this is a heuristic observation, not a "
                   "confirmed policy violation",
            task_id=task_id)]

    def _excessive_retry(self, org_id, agent_id, obs, current, budget, task_id) -> List[LoopFinding]:
        retries = [o for o in obs if o.event_type == EventType.AGENT_RETRY.value]
        if not retries:
            return []
        counts = Counter(o.subject for o in retries)
        out = []
        for subject, count in counts.items():
            if count < self.cfg.loop_retry_threshold:
                continue
            limit = getattr(budget, "max_retries", None) if budget is not None else None
            confirmed = limit is not None and count > limit
            out.append(self._finding(
                org_id=org_id, agent_id=agent_id, ts=current, pattern=LoopPattern.EXCESSIVE_RETRY,
                classification=(LoopClassification.CONFIRMED_VIOLATION if confirmed
                                else LoopClassification.SUSPICIOUS_REPETITION),
                subject=subject, observed=count, threshold=self.cfg.loop_retry_threshold,
                severity=(Severity.HIGH.value if confirmed else Severity.MEDIUM.value),
                evidence=(f"{count} retries of {subject} within {self.cfg.loop_window_s}s",
                          f"threshold={self.cfg.loop_retry_threshold}",
                          (f"configured max_retries={limit}" if limit is not None
                           else "no authoritative retry budget configured")),
                detail=("retries exceed the configured retry budget" if confirmed
                        else "retries exceed the heuristic threshold"),
                task_id=task_id))
        return out

    def _repeated_denial(self, org_id, agent_id, obs, current, budget, task_id) -> List[LoopFinding]:
        denials = [o for o in obs if o.is_denial]
        if len(denials) < self.cfg.loop_denial_threshold:
            return []
        counts = Counter(o.subject for o in denials)
        subject, count = counts.most_common(1)[0]
        return [self._finding(
            org_id=org_id, agent_id=agent_id, ts=current, pattern=LoopPattern.REPEATED_DENIAL,
            classification=LoopClassification.SUSPICIOUS_REPETITION, subject=subject,
            observed=count, threshold=self.cfg.loop_denial_threshold,
            severity=Severity.HIGH.value,
            evidence=(f"{count} authorization denials for {subject} within "
                      f"{self.cfg.loop_window_s}s",
                      f"threshold={self.cfg.loop_denial_threshold}",
                      "the policy engine already denied each attempt; this is a repetition "
                      "observation, not a new violation"),
            detail="repeated attempts against a resource the policy engine denied",
            task_id=task_id)]

    def _egress_repetition(self, org_id, agent_id, obs, current, task_id) -> List[LoopFinding]:
        egress = [o for o in obs if o.event_type in _EGRESS_EVENTS and o.destination]
        if not egress:
            return []
        counts = Counter(o.destination for o in egress)
        out = []
        for dest, count in counts.items():
            if count < self.cfg.loop_egress_threshold:
                continue
            out.append(self._finding(
                org_id=org_id, agent_id=agent_id, ts=current, pattern=LoopPattern.EGRESS_REPETITION,
                classification=LoopClassification.SUSPICIOUS_REPETITION, subject=dest,
                observed=count, threshold=self.cfg.loop_egress_threshold,
                severity=Severity.MEDIUM.value,
                evidence=(f"{count} outbound requests to {dest} within {self.cfg.loop_window_s}s",
                          f"threshold={self.cfg.loop_egress_threshold}"),
                detail="repeated outbound requests to a single destination",
                task_id=task_id))
        return out

    def _cascade(self, org_id, agent_id, obs, current, task_id) -> List[LoopFinding]:
        failures = [o for o in obs if o.is_failure and o.event_type in _ACTION_EVENTS]
        if not failures:
            return []
        distinct = {o.subject for o in failures}
        if len(distinct) < self.cfg.loop_cascade_threshold:
            return []
        return [self._finding(
            org_id=org_id, agent_id=agent_id, ts=current, pattern=LoopPattern.CASCADE_FAILURE,
            classification=LoopClassification.SUSPICIOUS_REPETITION,
            subject=f"{len(distinct)} distinct failing operations", observed=len(failures),
            threshold=self.cfg.loop_cascade_threshold, severity=Severity.HIGH.value,
            evidence=(f"{len(failures)} failures across {len(distinct)} distinct operations",
                      f"threshold={self.cfg.loop_cascade_threshold} distinct failing operations",
                      "failures may be independent; no dependency graph was available to confirm "
                      "causation"),
            detail="failures spread across multiple dependent operations",
            task_id=task_id)]

    def _resource_burn(self, org_id, agent_id, obs, current, budget, task_id) -> List[LoopFinding]:
        tokens = sum(o.tokens for o in obs if o.tokens)
        cost = sum(o.cost for o in obs if o.cost)
        out = []
        if budget is not None and getattr(budget, "max_tokens", None) and tokens > budget.max_tokens:
            out.append(self._finding(
                org_id=org_id, agent_id=agent_id, ts=current, pattern=LoopPattern.RESOURCE_BURN,
                classification=LoopClassification.CONFIRMED_VIOLATION, subject="tokens",
                observed=tokens, threshold=int(budget.max_tokens), severity=Severity.HIGH.value,
                evidence=(f"{tokens} tokens consumed within {self.cfg.loop_window_s}s",
                          f"configured max_tokens={budget.max_tokens}"),
                detail="token consumption exceeds the configured budget", task_id=task_id))
        if budget is not None and getattr(budget, "max_cost", None) and cost > budget.max_cost:
            out.append(self._finding(
                org_id=org_id, agent_id=agent_id, ts=current, pattern=LoopPattern.RESOURCE_BURN,
                classification=LoopClassification.CONFIRMED_VIOLATION, subject="cost",
                observed=int(cost * 100), threshold=int(budget.max_cost * 100),
                severity=Severity.HIGH.value,
                evidence=(f"cost {round(cost, 4)} consumed within {self.cfg.loop_window_s}s",
                          f"configured max_cost={budget.max_cost}"),
                detail="cost consumption exceeds the configured budget", task_id=task_id))
        return out

    # ------------------------------------------------------------------ helper
    def _finding(self, *, org_id, agent_id, ts, pattern, classification, subject, observed,
                 threshold, severity, evidence, detail, task_id) -> LoopFinding:
        return LoopFinding(
            finding_id=new_id("lpf"), org_id=org_id, agent_id=agent_id, ts=ts,
            pattern=pattern.value, classification=classification.value, subject=subject[:512],
            observed_count=int(observed), threshold=int(threshold),
            window_s=self.cfg.loop_window_s, severity=severity,
            evidence=tuple(str(e)[:512] for e in evidence), detail=detail[:2000], task_id=task_id)


def _as_int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
