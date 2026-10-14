"""Phase 5 agent behaviour profiles.

A :class:`~.models.BehaviorProfile` is a **tenant-isolated count aggregate** over observable runtime
activity. It is deliberately a summary of *what was observed*, not a judgement about the agent:

* Only events within the configured **learning window** contribute.
* A profile is ``is_mature`` only once it has ``min_samples`` observations. The drift detector uses
  that flag to decline to reason from sparse data -- insufficient data is never treated as
  suspiciousness.
* Profiles carry a **version** that increments on every rebuild, and there are explicit
  ``reset``/``retrain`` operations so a baseline can be deliberately discarded (e.g. after an
  approved change in an agent's duties).
* Isolation is by ``(org_id, agent_id)`` and every read/write is org-scoped.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional

from ..security.ids import new_id
from .config import MonitoringConfig
from .models import BehaviorProfile, Decision, EventType, RuntimeEvent
from .store import RuntimeMonitoringStore


class BehaviorProfileService:
    """Builds, stores, versions and resets per-agent behavioural baselines."""

    def __init__(self, store: RuntimeMonitoringStore, *,
                 config: Optional[MonitoringConfig] = None, audit=None, clock=None):
        self.store = store
        self.cfg = config or MonitoringConfig()
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ build
    def build(self, *, org_id: str, agent_id: str, events: Optional[List[RuntimeEvent]] = None,
              learning_window_s: Optional[int] = None, min_samples: Optional[int] = None,
              now: Optional[float] = None) -> BehaviorProfile:
        """(Re)build the profile for one agent from its events in the learning window.

        A rebuild increments the version; the caller-supplied ``events`` (if any) are used instead of
        reading the store, which keeps the function pure and deterministic for tests.
        """
        current = now if now is not None else self._now()
        window = int(learning_window_s if learning_window_s is not None
                     else self.cfg.default_learning_window_s)
        minimum = int(min_samples if min_samples is not None else self.cfg.default_min_samples)
        window_start = current - window

        if events is None:
            fetched, _ = self.store.list_events(org_id=org_id, agent_id=agent_id,
                                                since=window_start,
                                                limit=self.cfg.max_events_retained)
            events = list(reversed(fetched))          # chronological

        prev = self.store.get_profile(org_id=org_id, agent_id=agent_id)
        profile = BehaviorProfile(
            profile_id=prev.profile_id if prev else new_id("bpr"),
            org_id=org_id, agent_id=agent_id,
            version=(prev.version + 1) if prev else 1,
            created_at=prev.created_at if prev else current,
            updated_at=current,
            window_start=window_start, window_end=current,
            learning_window_s=window, min_samples=minimum)

        per_hour: Dict[str, int] = {}
        for ev in events:
            if ev.ts < window_start or ev.ts > current:
                continue
            profile.total_events += 1
            tool = _tool_of(ev)
            if tool:
                _bump(profile.tools, tool)
            if ev.resource:
                _bump(profile.resources, ev.resource)
            if ev.destination:
                _bump(profile.destinations, ev.destination)
            if ev.action:
                _bump(profile.actions, ev.action)
            if ev.decision:
                _bump(profile.decisions, ev.decision)
            for dc in ev.data_classes:
                _bump(profile.data_classes, dc)
            hour_key = str(int(ev.ts // 3600))
            per_hour[hour_key] = per_hour.get(hour_key, 0) + 1
            if ev.correlation_id:
                _bump(profile.sequences, ev.correlation_id)
            if ev.is_denial:
                profile.denials += 1
            if ev.is_failure:
                profile.failures += 1
            if ev.event_type == EventType.AGENT_RETRY.value:
                profile.retries += 1
            if ev.event_type in (EventType.JIT_GRANT_CREATED.value,
                                 EventType.APPROVAL_DECIDED.value,
                                 EventType.AGENT_IDENTITY_CHANGED.value):
                profile.privileged_actions += 1
            if ev.event_type in (EventType.DATA_ACCESS.value, EventType.FILE_ACCESS.value) \
                    and ev.data_classes:
                profile.sensitive_reads += 1

        profile.hour_histogram = dict(sorted(per_hour.items())[-24:])
        profile.max_events_per_hour = max(profile.hour_histogram.values(), default=0)
        self.store.put_profile(profile)
        if self.audit is not None:
            self.audit.record("runtime.profile.built", org_id=org_id, agent_id=agent_id,
                              outcome="ok", extra={"version": profile.version,
                                                   "total_events": profile.total_events,
                                                   "mature": profile.is_mature})
        return profile

    def get(self, *, org_id: str, agent_id: str) -> Optional[BehaviorProfile]:
        return self.store.get_profile(org_id=org_id, agent_id=agent_id)

    def list(self, *, org_id: str, limit: int = 100) -> List[BehaviorProfile]:
        return self.store.list_profiles(org_id=org_id, limit=limit)

    # ------------------------------------------------------------------ baselines
    def baseline_sets(self, profile: BehaviorProfile) -> dict:
        """The baseline as plain sets/maps, for drift comparison.

        Returns ``{"tools": {...}, "resources": {...}, "destinations": {...}, "actions": {...}}`` with
        occurrence counts. Empty sets for a non-mature profile are still returned -- the caller checks
        ``profile.is_mature`` before drawing conclusions.
        """
        return {"tools": dict(profile.tools), "resources": dict(profile.resources),
                "destinations": dict(profile.destinations), "actions": dict(profile.actions)}

    # ------------------------------------------------------------------ reset / retrain
    def reset(self, *, org_id: str, agent_id: str, reason: str = "manual_reset",
              actor_user_id: Optional[str] = None) -> None:
        """Discard an established baseline. Deliberate and auditable."""
        self.store.delete_profile(org_id=org_id, agent_id=agent_id)
        if self.audit is not None:
            self.audit.record("runtime.profile.reset", org_id=org_id, agent_id=agent_id,
                              outcome="ok", reason=reason, actor_user_id=actor_user_id)

    def retrain(self, *, org_id: str, agent_id: str, learning_window_s: Optional[int] = None,
                min_samples: Optional[int] = None, actor_user_id: Optional[str] = None,
                now: Optional[float] = None) -> BehaviorProfile:
        """Discard the baseline and rebuild it from the current window (an approved change)."""
        self.store.delete_profile(org_id=org_id, agent_id=agent_id)
        if self.audit is not None:
            self.audit.record("runtime.profile.reset", org_id=org_id, agent_id=agent_id,
                              outcome="ok", reason="retrain", actor_user_id=actor_user_id)
        return self.build(org_id=org_id, agent_id=agent_id, learning_window_s=learning_window_s,
                          min_samples=min_samples, now=now)


# --------------------------------------------------------------------------- helpers
def _bump(counter: Dict[str, int], key: str) -> None:
    counter[key] = counter.get(key, 0) + 1


def _tool_of(ev: RuntimeEvent) -> Optional[str]:
    """Best-effort tool name for an event, without inventing one that was not sent."""
    if ev.event_type not in (EventType.TOOL_INVOCATION.value, EventType.API_INVOCATION.value):
        return None
    for candidate in (ev.extra.get("tool_id") if isinstance(ev.extra, dict) else None,
                      ev.action, ev.resource):
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def is_privileged_action(ev: RuntimeEvent) -> bool:
    return ev.event_type in (EventType.JIT_GRANT_CREATED.value, EventType.APPROVAL_DECIDED.value,
                             EventType.AGENT_IDENTITY_CHANGED.value,
                             EventType.POLICY_CHANGED.value)


def is_sensitive_access(ev: RuntimeEvent) -> bool:
    return ev.event_type in (EventType.DATA_ACCESS.value, EventType.FILE_ACCESS.value) and bool(
        ev.data_classes)


def denial_decision(ev: RuntimeEvent) -> bool:
    return ev.decision in (Decision.DENY.value, Decision.BLOCKED.value,
                           Decision.REQUIRE_APPROVAL.value, Decision.INDETERMINATE.value)
