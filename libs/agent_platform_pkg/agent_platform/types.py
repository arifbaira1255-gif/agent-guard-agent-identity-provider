"""Core value types exchanged inside the platform.

Immutability is the default: a value that crossed a trust boundary (a model answer, a tool result)
is frozen so no later stage can quietly rewrite what earlier evidence recorded.  Mutable objects are
used only where accumulation is the point (a run's transcript, a metric registry).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "Role", "Message", "ToolCall", "Usage", "ModelResponse",
    "RunOutcome", "StepRecord", "RunResult",
]


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass(frozen=True)
class ToolCall:
    """One tool invocation requested by the model.

    ``raw_arguments`` keeps the exact bytes the model produced: when parsing fails, the raw text is
    what makes the failure diagnosable, and it is what the model is shown on a repair attempt.
    """

    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    id: str = ""
    raw_arguments: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "arguments": dict(self.arguments)}


@dataclass(frozen=True)
class Message:
    """One transcript entry.  ``tool_calls`` is populated on assistant turns only."""

    role: str
    content: str = ""
    name: Optional[str] = None
    tool_call_id: Optional[str] = None
    tool_calls: Tuple[ToolCall, ...] = ()
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # -- convenience constructors ------------------------------------------------------------
    @classmethod
    def system(cls, content: str, **kw: Any) -> "Message":
        return cls(Role.SYSTEM.value, content, **kw)

    @classmethod
    def user(cls, content: str, **kw: Any) -> "Message":
        return cls(Role.USER.value, content, **kw)

    @classmethod
    def assistant(cls, content: str = "", tool_calls: Tuple[ToolCall, ...] = (),
                  **kw: Any) -> "Message":
        return cls(Role.ASSISTANT.value, content, tool_calls=tuple(tool_calls), **kw)

    @classmethod
    def tool_result(cls, content: str, *, tool_call_id: str, name: str, **kw: Any) -> "Message":
        return cls(Role.TOOL.value, content, tool_call_id=tool_call_id, name=name, **kw)

    def to_dict(self) -> dict:
        out: Dict[str, Any] = {"role": self.role, "content": self.content}
        if self.name:
            out["name"] = self.name
        if self.tool_call_id:
            out["tool_call_id"] = self.tool_call_id
        if self.tool_calls:
            out["tool_calls"] = [c.to_dict() for c in self.tool_calls]
        return out


@dataclass(frozen=True)
class Usage:
    """Token and money accounting for one model call (or a run's sum, when aggregated)."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0

    @property
    def total_tokens(self) -> int:
        return int(self.prompt_tokens) + int(self.completion_tokens)

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(self.prompt_tokens + other.prompt_tokens,
                     self.completion_tokens + other.completion_tokens,
                     round(self.cost_usd + other.cost_usd, 8))

    def to_dict(self) -> dict:
        return {"prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.total_tokens, "cost_usd": round(self.cost_usd, 8)}


@dataclass
class ModelResponse:
    """A normalised model answer.

    Both a plain text answer and a tool-call request are valid; a response carrying neither is
    treated as :class:`~agent_platform.errors.InvalidModelOutput` by the orchestrator rather than
    being silently accepted as an empty final answer.
    """

    text: str = ""
    tool_calls: Tuple[ToolCall, ...] = ()
    model: str = ""
    provider: str = ""
    usage: Usage = field(default_factory=Usage)
    finish_reason: str = "stop"
    latency_ms: float = 0.0
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)

    @property
    def is_empty(self) -> bool:
        return not self.tool_calls and not (self.text or "").strip()

    def to_dict(self) -> dict:
        return {"text": self.text, "tool_calls": [c.to_dict() for c in self.tool_calls],
                "model": self.model, "provider": self.provider,
                "usage": self.usage.to_dict(), "finish_reason": self.finish_reason,
                "latency_ms": self.latency_ms}


class RunOutcome(str, Enum):
    """The structured outcome of one agent run (one discriminant per terminal condition)."""

    OK = "ok"
    MAX_STEPS = "max_steps"
    BUDGET_EXCEEDED = "budget_exceeded"
    CANCELLED = "cancelled"
    MODEL_ERROR = "model_error"
    TOOL_DENIED = "tool_denied"
    INVALID_MODEL_OUTPUT = "invalid_model_output"
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"
    VALIDATION_ERROR = "validation_error"
    INTERNAL_ERROR = "internal_error"


@dataclass
class StepRecord:
    """What happened on one loop iteration (the unit a trace and a replay both need)."""

    index: int
    thought: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    tool_results: List[Dict[str, Any]] = field(default_factory=list)
    model: str = ""
    usage: Usage = field(default_factory=Usage)
    duration_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {"index": self.index, "thought": self.thought, "tool_calls": self.tool_calls,
                "tool_results": self.tool_results, "model": self.model,
                "usage": self.usage.to_dict(), "duration_ms": self.duration_ms,
                "error": self.error}


@dataclass
class RunResult:
    """The complete, auditable result of one run.

    Contains the transcript (what actually happened), the per-step records, the accumulated usage,
    the budget snapshot and the reason for a non-OK outcome.  ``ok`` is True only for
    :attr:`RunOutcome.OK`.
    """

    run_id: str
    outcome: RunOutcome
    goal: str = ""
    correlation_id: str = ""
    ok: bool = False
    final_text: str = ""
    steps: int = 0
    tool_calls: int = 0
    usage: Usage = field(default_factory=Usage)
    duration_ms: float = 0.0
    error: Optional[str] = None
    error_code: Optional[str] = None
    transcript: List[Message] = field(default_factory=list)
    step_records: List[StepRecord] = field(default_factory=list)
    plan: Optional[Dict[str, Any]] = None
    budget: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self, *, include_transcript: bool = True) -> dict:
        out: Dict[str, Any] = {
            "run_id": self.run_id,
            "outcome": self.outcome.value,
            "ok": self.ok,
            "goal": self.goal,
            "correlation_id": self.correlation_id,
            "final_text": self.final_text,
            "steps": self.steps,
            "tool_calls": self.tool_calls,
            "usage": self.usage.to_dict(),
            "duration_ms": self.duration_ms,
            "budget": self.budget,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }
        if self.error is not None:
            out["error"] = self.error
        if self.error_code is not None:
            out["error_code"] = self.error_code
        if self.plan is not None:
            out["plan"] = self.plan
        out["step_records"] = [s.to_dict() for s in self.step_records]
        if include_transcript:
            out["transcript"] = [m.to_dict() for m in self.transcript]
        return out
