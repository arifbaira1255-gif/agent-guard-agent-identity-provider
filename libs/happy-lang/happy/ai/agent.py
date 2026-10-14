"""AI sandbox and planning layer for the Happy language (Step 5).

Two responsibilities live here:

1. **Structured planning.**  An ``ai`` declaration in Happy source carries a
   ``prompt`` and a ``goal``.  :class:`PlanGenerator` turns that declaration
   into a *structured, machine-checkable* :class:`Plan` — a JSON document with
   an ordered list of :class:`PlanStep` objects — by asking an
   :class:`~happy.ai.providers.AIProvider` for JSON and validating the reply
   against a strict schema.  A malformed plan is rejected, never executed.

2. **The agent capability sandbox.**  :class:`AgentSandbox` is the runtime
   boundary around an AI agent: it decides which files the agent may *read*,
   which it may *modify*, which commands it may *execute*, and which
   capabilities it may wield.  Every plan step is checked against the sandbox
   before it runs, so a plan that tries to escape its grant is refused with a
   :class:`SandboxViolation`.

The sandbox is deliberately independent of the compiler's static capability
system: the compiler proves what the *code* may do, the sandbox constrains what
the *model* may do at run time.  Both use the same action vocabulary
(:data:`happy.compiler.permissions.CAPABILITY_ACTIONS`) so they agree.

Typical use::

    from happy.ai.agent import PlanGenerator, AgentSandbox

    sandbox = AgentSandbox(read_paths=["src/**"], write_paths=["out/**"])
    plan = PlanGenerator(provider).from_ai_block(ai_ir, sandbox=sandbox)
    for step in plan.steps:
        sandbox.check_step(step)          # raises SandboxViolation if refused
"""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set

from .providers import (
    AIProvider,
    AIRequest,
    ProviderResponseError,
    resolve_provider,
)

__all__ = [
    "StepKind",
    "PlanStep",
    "Plan",
    "PlanError",
    "PlanGenerator",
    "PLAN_SCHEMA",
    "SandboxViolation",
    "SandboxPolicy",
    "AgentSandbox",
]


# ---------------------------------------------------------------------------
# Plan model
# ---------------------------------------------------------------------------
class StepKind:
    """The kinds of step a plan may contain."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    GENERATE = "generate"
    VERIFY = "verify"
    CALL = "call"

    ALL = (READ, WRITE, EXECUTE, GENERATE, VERIFY, CALL)


#: JSON schema (informal) the plan generator asks the model to satisfy.
PLAN_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["goal", "steps"],
    "properties": {
        "goal": {"type": "string"},
        "steps": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "kind", "description"],
                "properties": {
                    "id": {"type": "string"},
                    "kind": {"enum": list(StepKind.ALL)},
                    "description": {"type": "string"},
                    "target": {"type": "string"},
                    "capability": {"type": "string"},
                    "depends_on": {"type": "array", "items": {"type": "string"}},
                    "params": {"type": "object"},
                },
            },
        },
    },
}


class PlanError(Exception):
    """Raised when a model reply cannot be turned into a valid plan."""


@dataclass
class PlanStep:
    """A single, checkable step of an execution plan."""

    id: str
    kind: str
    description: str
    target: Optional[str] = None
    capability: Optional[str] = None
    depends_on: List[str] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "description": self.description,
        }
        if self.target is not None:
            out["target"] = self.target
        if self.capability is not None:
            out["capability"] = self.capability
        if self.depends_on:
            out["depends_on"] = list(self.depends_on)
        if self.params:
            out["params"] = dict(self.params)
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PlanStep":
        if not isinstance(data, Mapping):
            raise PlanError(f"plan step must be an object, got {type(data).__name__}")
        for required in ("id", "kind", "description"):
            if not data.get(required):
                raise PlanError(f"plan step missing required field {required!r}")
        kind = str(data["kind"]).strip().lower()
        if kind not in StepKind.ALL:
            raise PlanError(
                f"unknown step kind {kind!r}; expected one of {list(StepKind.ALL)}"
            )
        depends = data.get("depends_on") or []
        if not isinstance(depends, (list, tuple)):
            raise PlanError("'depends_on' must be a list")
        params = data.get("params") or {}
        if not isinstance(params, Mapping):
            raise PlanError("'params' must be an object")
        return cls(
            id=str(data["id"]),
            kind=kind,
            description=str(data["description"]),
            target=str(data["target"]) if data.get("target") is not None else None,
            capability=(
                str(data["capability"]) if data.get("capability") is not None else None
            ),
            depends_on=[str(d) for d in depends],
            params=dict(params),
        )


@dataclass
class Plan:
    """A structured execution plan produced from an ``ai`` declaration."""

    goal: str
    steps: List[PlanStep] = field(default_factory=list)
    source: Optional[str] = None
    raw: Any = None
    mocked: bool = False

    # -- serialisation --------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {"goal": self.goal, "steps": [s.to_dict() for s in self.steps]}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], **kwargs: Any) -> "Plan":
        if not isinstance(data, Mapping):
            raise PlanError(f"plan must be an object, got {type(data).__name__}")
        goal = data.get("goal")
        if not goal:
            raise PlanError("plan missing required field 'goal'")
        raw_steps = data.get("steps")
        if not isinstance(raw_steps, (list, tuple)):
            raise PlanError("plan missing required field 'steps' (a list)")
        steps = [PlanStep.from_dict(s) for s in raw_steps]
        plan = cls(goal=str(goal), steps=steps, **kwargs)
        plan.validate()
        return plan

    # -- validation -----------------------------------------------------
    def validate(self) -> None:
        """Check structural integrity: unique ids and resolvable dependencies."""
        seen: Set[str] = set()
        for step in self.steps:
            if step.id in seen:
                raise PlanError(f"duplicate step id {step.id!r}")
            seen.add(step.id)
        for step in self.steps:
            for dep in step.depends_on:
                if dep not in seen:
                    raise PlanError(
                        f"step {step.id!r} depends on unknown step {dep!r}"
                    )
        if self._has_cycle():
            raise PlanError("plan contains a dependency cycle")

    def _has_cycle(self) -> bool:
        graph = {s.id: list(s.depends_on) for s in self.steps}
        WHITE, GREY, BLACK = 0, 1, 2
        color = {node: WHITE for node in graph}

        def visit(node: str) -> bool:
            color[node] = GREY
            for nxt in graph.get(node, []):
                if color.get(nxt) == GREY:
                    return True
                if color.get(nxt) == WHITE and visit(nxt):
                    return True
            color[node] = BLACK
            return False

        return any(color[n] == WHITE and visit(n) for n in list(graph))

    # -- queries --------------------------------------------------------
    def step(self, step_id: str) -> Optional[PlanStep]:
        for s in self.steps:
            if s.id == step_id:
                return s
        return None

    def kinds(self) -> List[str]:
        return [s.kind for s in self.steps]

    def __len__(self) -> int:
        return len(self.steps)

    def __iter__(self):
        return iter(self.steps)


# ---------------------------------------------------------------------------
# Plan generation
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = (
    "You are the planning component of the Happy compiler. "
    "Given an AI block's prompt and goal, produce a STRICT JSON execution plan. "
    "Reply with JSON only, no prose, matching this schema:\n"
    + json.dumps(PLAN_SCHEMA, indent=2)
    + "\nEach step's 'kind' must be one of: "
    + ", ".join(StepKind.ALL)
    + ". Use 'capability' to name the authority a step needs "
    "(e.g. file_read, file_write, net, payments, secrets)."
)


class PlanGenerator:
    """Turns ``ai`` declarations into validated :class:`Plan` objects."""

    def __init__(
        self,
        provider: Any = None,
        model: Optional[str] = None,
        max_steps: int = 32,
    ) -> None:
        self.provider: AIProvider = resolve_provider(provider, model=model)
        self.max_steps = max_steps

    # -- public API -----------------------------------------------------
    def from_ai_block(self, ai_block: Any, sandbox: Optional["AgentSandbox"] = None) -> Plan:
        """Build a plan from a lowered :class:`~happy.compiler.ir.IRAi` node."""
        name = getattr(ai_block, "name", None) or "ai"
        prompt = _expr_text(getattr(ai_block, "prompt", None))
        goal = _expr_text(getattr(ai_block, "goal", None))
        return self.generate(prompt=prompt, goal=goal, source=name, sandbox=sandbox)

    def generate(
        self,
        prompt: str = "",
        goal: str = "",
        source: Optional[str] = None,
        sandbox: Optional["AgentSandbox"] = None,
    ) -> Plan:
        """Ask the provider for a plan and validate it.

        When the provider is a mock (or returns nothing usable) a deterministic
        fallback plan is synthesised so the pipeline still has something to
        verify — but the fallback is clearly marked ``mocked``.
        """
        request = AIRequest.from_prompt(
            _user_prompt(prompt, goal),
            system=_SYSTEM_PROMPT,
            temperature=0.0,
            json_schema=PLAN_SCHEMA,
        )
        response = self.provider.complete(request)
        try:
            data = response.json()
            plan = Plan.from_dict(data, source=source, raw=data, mocked=response.mocked)
        except (PlanError, ProviderResponseError) as exc:
            if response.mocked:
                plan = self._fallback_plan(prompt, goal, source)
            else:
                raise PlanError(f"model did not return a valid plan: {exc}") from exc

        if len(plan.steps) > self.max_steps:
            raise PlanError(
                f"plan has {len(plan.steps)} steps, exceeding the limit of {self.max_steps}"
            )
        if sandbox is not None:
            sandbox.check_plan(plan)
        return plan

    # -- fallback -------------------------------------------------------
    def _fallback_plan(self, prompt: str, goal: str, source: Optional[str]) -> Plan:
        """A minimal, deterministic plan used when no real model is available."""
        steps = [
            PlanStep(
                id="s1",
                kind=StepKind.GENERATE,
                description=f"Generate a solution for: {goal or prompt or 'the task'}",
                capability="ai",
            ),
            PlanStep(
                id="s2",
                kind=StepKind.VERIFY,
                description="Verify the generated solution against contracts and rules",
                depends_on=["s1"],
            ),
        ]
        return Plan(goal=goal or prompt or "unspecified goal", steps=steps, source=source, mocked=True)


def _user_prompt(prompt: str, goal: str) -> str:
    parts = []
    if goal:
        parts.append(f"Goal: {goal}")
    if prompt:
        parts.append(f"Prompt: {prompt}")
    if not parts:
        parts.append("Goal: produce a safe, minimal plan.")
    return "\n".join(parts)


def _expr_text(expr: Any) -> str:
    """Best-effort extraction of a string literal from an IR expression."""
    if expr is None:
        return ""
    for attr in ("value", "text", "literal"):
        value = getattr(expr, attr, None)
        if isinstance(value, str):
            return value
    return str(expr) if not hasattr(expr, "children") else ""


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------
class SandboxViolation(Exception):
    """Raised when an agent attempts an action outside its sandbox grant."""

    def __init__(self, message: str, *, action: str = "", target: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.action = action
        self.target = target

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


@dataclass
class SandboxPolicy:
    """The grant an :class:`AgentSandbox` enforces.

    Paths are glob patterns (``src/**``, ``*.hpy``).  An empty ``read_paths`` /
    ``write_paths`` means *nothing* is permitted for that action — the sandbox
    is deny-by-default.  ``allow_network`` and ``allow_execute`` are explicit
    opt-ins.
    """

    read_paths: List[str] = field(default_factory=list)
    write_paths: List[str] = field(default_factory=list)
    execute_commands: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    allow_network: bool = False
    allow_execute: bool = False
    max_steps: int = 32
    #: When True, an unknown capability is allowed (audit-only sandbox).
    permissive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "read_paths": list(self.read_paths),
            "write_paths": list(self.write_paths),
            "execute_commands": list(self.execute_commands),
            "capabilities": list(self.capabilities),
            "allow_network": self.allow_network,
            "allow_execute": self.allow_execute,
            "max_steps": self.max_steps,
            "permissive": self.permissive,
        }


class AgentSandbox:
    """Constrains what an AI agent may read, modify, execute or access.

    The sandbox is the runtime counterpart of the compiler's capability system.
    It is checked *before* a plan step runs, so a plan that tries to escape its
    grant is refused rather than partially executed.
    """

    def __init__(
        self,
        read_paths: Optional[Sequence[str]] = None,
        write_paths: Optional[Sequence[str]] = None,
        execute_commands: Optional[Sequence[str]] = None,
        capabilities: Optional[Sequence[str]] = None,
        allow_network: bool = False,
        allow_execute: bool = False,
        max_steps: int = 32,
        permissive: bool = False,
        policy: Optional[SandboxPolicy] = None,
        root: Optional[str] = None,
    ) -> None:
        self.policy = policy or SandboxPolicy(
            read_paths=list(read_paths or []),
            write_paths=list(write_paths or []),
            execute_commands=list(execute_commands or []),
            capabilities=list(capabilities or []),
            allow_network=allow_network,
            allow_execute=allow_execute,
            max_steps=max_steps,
            permissive=permissive,
        )
        self.root = root
        #: Every decision the sandbox made (for auditing).
        self.audit: List[Dict[str, Any]] = []

    # -- construction from IR ------------------------------------------
    @classmethod
    def from_agent(cls, agent: Any, **overrides: Any) -> "AgentSandbox":
        """Build a sandbox from a lowered :class:`~happy.compiler.ir.IRAgent`.

        The agent's declared capabilities become the sandbox's capability
        grant; path/command grants come from ``overrides`` (the language does
        not yet express them).
        """
        caps = list(getattr(agent, "capabilities", []) or [])
        return cls(capabilities=caps, **overrides)

    # -- path checks ----------------------------------------------------
    def _match(self, path: str, patterns: Sequence[str]) -> bool:
        if not patterns:
            return False
        candidate = path
        if self.root:
            try:
                candidate = os.path.relpath(os.path.abspath(path), os.path.abspath(self.root))
            except ValueError:  # pragma: no cover - different drives
                candidate = path
        candidate = candidate.replace(os.sep, "/")
        for pattern in patterns:
            pat = pattern.replace(os.sep, "/")
            if fnmatch.fnmatch(candidate, pat) or fnmatch.fnmatch(path, pat):
                return True
            # ``src/**`` should also match ``src`` itself.
            if pat.endswith("/**") and candidate == pat[:-3].rstrip("/"):
                return True
        return False

    def check_read(self, path: str) -> bool:
        """Authorise reading ``path``; raise :class:`SandboxViolation` if refused."""
        allowed = self._match(path, self.policy.read_paths)
        self._record("read", path, allowed)
        if not allowed:
            raise SandboxViolation(
                f"agent may not read {path!r} (allowed: {self.policy.read_paths or 'nothing'})",
                action="read",
                target=path,
            )
        return True

    def check_write(self, path: str) -> bool:
        """Authorise modifying ``path``; raise :class:`SandboxViolation` if refused."""
        allowed = self._match(path, self.policy.write_paths)
        self._record("write", path, allowed)
        if not allowed:
            raise SandboxViolation(
                f"agent may not modify {path!r} (allowed: {self.policy.write_paths or 'nothing'})",
                action="write",
                target=path,
            )
        return True

    def check_execute(self, command: str) -> bool:
        """Authorise executing ``command``; raise :class:`SandboxViolation` if refused."""
        allowed = self.policy.allow_execute and any(
            fnmatch.fnmatch(command, pat) or command.split()[0] == pat
            for pat in self.policy.execute_commands
        )
        self._record("execute", command, allowed)
        if not allowed:
            raise SandboxViolation(
                f"agent may not execute {command!r} "
                f"(allowed: {self.policy.execute_commands or 'nothing'})",
                action="execute",
                target=command,
            )
        return True

    def check_capability(self, capability: str) -> bool:
        """Authorise wielding ``capability``; raise :class:`SandboxViolation` if refused."""
        from ..compiler.permissions import _normalise_action

        action = _normalise_action(capability)
        granted = {_normalise_action(c) for c in self.policy.capabilities}
        allowed = action in granted or self.policy.permissive
        self._record("capability", capability, allowed)
        if not allowed:
            raise SandboxViolation(
                f"agent lacks capability {capability!r} "
                f"(granted: {sorted(granted) or 'none'})",
                action="capability",
                target=capability,
            )
        return True

    def check_network(self, target: str = "") -> bool:
        """Authorise a network operation; raise :class:`SandboxViolation` if refused."""
        allowed = self.policy.allow_network
        self._record("network", target, allowed)
        if not allowed:
            raise SandboxViolation(
                f"agent may not use the network ({target or 'unspecified target'})",
                action="network",
                target=target,
            )
        return True

    # -- plan / step checks --------------------------------------------
    def check_step(self, step: PlanStep) -> bool:
        """Authorise a single :class:`PlanStep` against the sandbox grant."""
        if step.kind == StepKind.READ:
            return self.check_read(step.target or "")
        if step.kind == StepKind.WRITE:
            return self.check_write(step.target or "")
        if step.kind == StepKind.EXECUTE:
            return self.check_execute(step.target or "")
        if step.kind == StepKind.CALL:
            if step.capability:
                return self.check_capability(step.capability)
            return True
        if step.kind in (StepKind.GENERATE, StepKind.VERIFY):
            if step.capability:
                return self.check_capability(step.capability)
            return True
        raise SandboxViolation(f"unknown step kind {step.kind!r}", action=step.kind)

    def check_plan(self, plan: Plan) -> bool:
        """Authorise every step of ``plan`` (all-or-nothing)."""
        if len(plan.steps) > self.policy.max_steps:
            raise SandboxViolation(
                f"plan has {len(plan.steps)} steps, exceeding sandbox limit "
                f"{self.policy.max_steps}",
                action="plan",
            )
        for step in plan.steps:
            self.check_step(step)
        return True

    # -- audit ----------------------------------------------------------
    def _record(self, action: str, target: str, allowed: bool) -> None:
        self.audit.append({"action": action, "target": target, "allowed": allowed})

    @property
    def denials(self) -> List[Dict[str, Any]]:
        return [r for r in self.audit if not r["allowed"]]

    def summary(self) -> str:
        return (
            f"sandbox: {len(self.audit)} checks, {len(self.denials)} denied; "
            f"read={self.policy.read_paths or 'none'} "
            f"write={self.policy.write_paths or 'none'}"
        )
