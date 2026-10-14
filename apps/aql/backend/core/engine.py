"""Agent execution engine.

A minimal but real ReAct-style loop: the engine plans, calls tools, observes
results, and repeats until it produces a final answer or hits the step budget.
LLM calls are stubbed behind ``_call_model`` so the boilerplate runs without
keys — swap in the real provider clients when you wire up credentials.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import get_settings
from .guardrails import ApprovalNotFoundError, ApprovalStore, check_action_risk
from .router import ModelRouter, RouteDecision

logger = logging.getLogger(__name__)


def _iso(timestamp: float | None) -> str | None:
    """Convert a POSIX timestamp to an ISO-8601 UTC string (None-safe)."""
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


@dataclass
class AgentStep:
    """One thought/action/observation cycle."""

    index: int
    thought: str
    action: str | None = None
    action_input: dict[str, Any] = field(default_factory=dict)
    observation: str | None = None


@dataclass
class AgentRun:
    """The full record of one agent invocation."""

    run_id: str
    task: str
    route: RouteDecision
    steps: list[AgentStep] = field(default_factory=list)
    answer: str | None = None
    # running | completed | failed | max_steps | pending_approval | rejected
    status: str = "running"
    error: str | None = None
    approval_id: str | None = None
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None

    @property
    def duration_ms(self) -> int:
        end = self.finished_at or time.time()
        return int((end - self.started_at) * 1000)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "task": self.task,
            "status": self.status,
            "answer": self.answer,
            "error": self.error,
            "approval_id": self.approval_id,
            "duration_ms": self.duration_ms,
            "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at),
            "route": {
                "provider": self.route.provider,
                "model": self.route.model,
                "tier": self.route.tier.value,
                "reason": self.route.reason,
            },
            "steps": [
                {
                    "index": s.index,
                    "thought": s.thought,
                    "action": s.action,
                    "action_input": s.action_input,
                    "observation": s.observation,
                }
                for s in self.steps
            ],
        }


class AgentEngine:
    """Runs an agent task end-to-end."""

    def __init__(
        self,
        router: ModelRouter | None = None,
        guardrails: ApprovalStore | None = None,
    ) -> None:
        self.settings = get_settings()
        self.router = router or ModelRouter()
        # Safety layer: pauses high-risk actions for human approval.
        self.guardrails = guardrails or ApprovalStore()

    # ── LLM boundary (replace with real SDK calls) ──────────────────────────
    def _call_model(self, route: RouteDecision, prompt: str) -> str:
        """Call the model for ``prompt`` via the router's fallback chain.

        The router tries the preferred provider first, walks the fallback
        chain on failure, and finally returns a local stub — so this never
        raises and the engine keeps running with or without API keys.
        """
        result = self.router.call(prompt, prefer=route.provider)
        return result.text

    def _plan(self, run: AgentRun) -> AgentStep:
        thought = self._call_model(run.route, f"Plan the next step for: {run.task}")
        return AgentStep(index=len(run.steps) + 1, thought=thought)

    # ── Public API ──────────────────────────────────────────────────────────
    def _execute(self, run: AgentRun) -> None:
        """The actual work loop (no safety gate — callers gate first)."""
        for _ in range(self.settings.agent_max_steps):
            step = self._plan(run)
            # Tool dispatch would happen here via the tools registry.
            step.observation = "no tool selected (stub)"
            run.steps.append(step)

            # Stub termination: one planning step is enough for the demo.
            run.answer = self._call_model(run.route, f"Answer: {run.task}")
            run.status = "completed"
            break
        else:
            run.status = "max_steps"

    def run(
        self,
        task: str,
        prefer_provider: str | None = None,
        *,
        action_type: str | None = None,
        payload: dict[str, Any] | None = None,
        user_id: str = "anonymous",
        session_id: str = "default",
        run_id: str | None = None,
    ) -> AgentRun:
        """Execute ``task`` and return the completed run record.

        Before doing any work the engine asks the safety layer whether the
        requested action is high-risk. If it is, execution **pauses**: the run
        is persisted with a ``pending_approval`` status plus an approval id,
        and nothing runs until a human approves it via the API.
        """
        route = self.router.route(task, prefer=prefer_provider)
        # ``run_id`` lets the REST layer pre-allocate a task id so it can return
        # it immediately and let the run finish in the background.
        run = AgentRun(run_id=run_id or str(uuid.uuid4()), task=task, route=route)
        action = action_type or "agent.task"
        action_payload = payload or {"task": task}

        # ── Safety gate: pause high-risk actions for human approval ──────────
        try:
            assessment = check_action_risk(action, action_payload)
            if assessment.requires_approval:
                approval = self.guardrails.pause(
                    run_id=run.run_id,
                    action_type=action,
                    payload=action_payload,
                    assessment=assessment,
                    kind="agent",
                    resume_state={"task": task, "prefer_provider": prefer_provider},
                    user_id=user_id,
                    session_id=session_id,
                )
                run.status = "pending_approval"
                run.approval_id = approval.approval_id
                run.answer = (
                    "Paused for human approval — this action is high-risk "
                    f"({', '.join(assessment.matched_rules) or 'unclassified'})."
                )
                run.finished_at = time.time()
                return run
        except Exception as exc:  # noqa: BLE001 — a broken gate must not crash the run
            logger.warning("Guardrail check failed (%s) — continuing", exc)

        try:
            self._execute(run)
        except Exception as exc:  # noqa: BLE001 — surface any failure on the run
            run.status = "failed"
            run.error = str(exc)
        finally:
            run.finished_at = time.time()

        return run

    def resume(
        self,
        run_id: str,
        decision: str = "approve",
        *,
        approver: str | None = None,
        note: str = "",
    ) -> AgentRun:
        """Resume (or reject) a run that was paused for human approval.

        Looks up the pending approval for ``run_id``, records the human
        decision, and — when approved — executes the original task.

        Raises:
            ApprovalNotFoundError: No pending approval exists for ``run_id``.
        """
        approval = self.guardrails.find_by_run(run_id)
        if approval is None:
            raise ApprovalNotFoundError(f"no pending approval for run {run_id}")

        decided = self.guardrails.decide(
            approval.approval_id, decision, approver=approver, note=note
        )
        resume_state = approval.resume_state or {}
        task = resume_state.get("task", "")
        route = self.router.route(task or "rejected")
        run = AgentRun(run_id=run_id, task=task, route=route)
        run.approval_id = decided.approval_id

        if decided.status != "approved":
            run.status = "rejected"
            run.answer = f"Rejected by {approver or 'human'}: {note or 'no note'}"
            run.finished_at = time.time()
            return run

        # Approved → execute the original task for real (gate already passed).
        try:
            self._execute(run)
        except Exception as exc:  # noqa: BLE001
            run.status = "failed"
            run.error = str(exc)
        finally:
            run.finished_at = time.time()
        return run
