"""Runtime capability & permission enforcement for the Happy runtime.

Step 3 verified *statically* that every sensitive operation inside an agent is
covered by one of the agent's capabilities (diagnostic ``E6003``).  This module
enforces the same rule **at runtime**: when generated code performs a sensitive
operation it calls the active :class:`CapabilityChecker`, which

1. looks up the agent the code is currently executing as,
2. translates the operation (``write_file``, ``http_get`` …) into the abstract
   action it requires (``file_write``, ``net`` …) using the *same* catalogue the
   compiler uses (:data:`~happy.compiler.permissions.ENFORCEMENT_MAP`), and
3. checks that one of the agent's capabilities grants that action and that none
   of its permissions explicitly denies it.

Failures raise :class:`~happy.runtime.errors.CapabilityDenied` (``R2001``) or
:class:`~happy.runtime.errors.PermissionDenied` (``R2002``), resolved to the
``.hpy`` source location of the offending call.

The registry is built from the lowered IR, so the runtime and the compiler can
never disagree about what a capability grants::

    checker = CapabilityChecker.from_module(module)
    checker.enter_agent("Teller")
    checker.check_operation("write_file", loc=("demo.hpy", 14, 9))
"""

from __future__ import annotations

import contextvars
import itertools
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from ..compiler.permissions import (
    AGENT_REQUIRED_ACTIONS,
    CAPABILITY_ACTIONS,
    ENFORCEMENT_MAP,
    _normalise_action,
)
from .errors import CapabilityDenied, PermissionDenied

__all__ = [
    "classify_operation",
    "CapabilityPolicy",
    "OperationRecord",
    "CapabilityRegistry",
    "CapabilityChecker",
    "normalise_action",
    "requires_capability",
]


def normalise_action(name: str) -> str:
    """Canonicalise an action/capability-grant name (compiler-consistent)."""
    return _normalise_action(name)


def requires_capability(operation: str) -> Optional[str]:
    """Return the abstract action ``operation`` requires (``None`` if pure)."""
    return ENFORCEMENT_MAP.get(operation, None)


def _known_actions() -> Set[str]:
    """Every abstract action name the capability model understands."""
    known: Set[str] = set(AGENT_REQUIRED_ACTIONS)
    known |= {a for a in ENFORCEMENT_MAP.values() if a}
    known |= set(CAPABILITY_ACTIONS.values())
    known.add("secrets")
    return known


def classify_operation(operation: str) -> Tuple[bool, Optional[str]]:
    """Classify ``operation`` as ``(known, action)``.

    * listed in the compiler catalogue -> ``(True, action_or_None)``
      (``None`` means explicitly pure);
    * named after an abstract action (``"file_write"``) -> ``(True, action)``;
    * anything else -> ``(False, None)``.  Callers MUST treat this as
      *unknown*, never as pure: an unmapped operation (e.g. a foreign-call
      wrapper) must not silently skip capability checks.
    """
    if operation in ENFORCEMENT_MAP:
        return True, ENFORCEMENT_MAP[operation]
    norm = normalise_action(operation)
    if norm in _known_actions():
        return True, norm
    return False, None


@dataclass
class CapabilityPolicy:
    """How the runtime reacts to a capability/permission denial.

    ``mode`` is ``"enforce"`` (raise), ``"audit"`` (record and allow) or
    ``"off"`` (skip checks).  ``default_allow`` governs operations executed
    outside any agent scope: when False (the default) they are DENIED, so a
    plain script or ``app`` body cannot read a file, open a socket or spawn a
    process without holding a capability; when True they are audited and
    allowed (opt-in, for trusted hosts that wrap ``run_source`` themselves).
    """

    mode: str = "enforce"
    default_allow: bool = False
    trace: bool = False

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"

    @property
    def enabled(self) -> bool:
        return self.mode != "off"


@dataclass
class OperationRecord:
    """A single audited sensitive operation."""

    agent: Optional[str]
    operation: str
    action: Optional[str]
    allowed: bool
    reason: str = ""
    location: Optional[object] = None


@dataclass
class CapabilityRegistry:
    """Static facts about capabilities and permissions, built from the IR."""

    #: capability name -> set of granted actions
    capabilities: Dict[str, Set[str]] = field(default_factory=dict)
    #: permission name -> (can_actions, cannot_actions)
    permissions: Dict[str, Tuple[Set[str], Set[str]]] = field(default_factory=dict)
    #: agent name -> declared capability names
    agent_capabilities: Dict[str, List[str]] = field(default_factory=dict)
    #: agent name -> declared permission names
    agent_permissions: Dict[str, List[str]] = field(default_factory=dict)

    # -- construction ---------------------------------------------------
    @classmethod
    def from_module(cls, module: Any) -> "CapabilityRegistry":
        """Build a registry from a lowered :class:`~happy.compiler.ir.IRModule`."""
        reg = cls()
        for cap in getattr(module, "capabilities", []) or []:
            reg.capabilities[cap.name] = {normalise_action(g) for g in cap.grants}
        for perm in getattr(module, "permissions", []) or []:
            reg.permissions[perm.name] = (
                {normalise_action(a) for a in perm.can},
                {normalise_action(a) for a in perm.cannot},
            )
        for agent in getattr(module, "agents", []) or []:
            reg.agent_capabilities[agent.name] = list(agent.capabilities)
            reg.agent_permissions[agent.name] = list(agent.permissions)
        return reg

    # -- queries --------------------------------------------------------
    def granted_actions(self, agent: str) -> Set[str]:
        out: Set[str] = set()
        for cname in self.agent_capabilities.get(agent, []):
            out |= self.capabilities.get(cname, set())
        return out

    def denied_actions(self, agent: str) -> Set[str]:
        out: Set[str] = set()
        for pname in self.agent_permissions.get(agent, []):
            _, cannot = self.permissions.get(pname, (set(), set()))
            out |= cannot
        return out

    def covering_capability(self, agent: str, action: str) -> Optional[str]:
        for cname in self.agent_capabilities.get(agent, []):
            if action in self.capabilities.get(cname, set()):
                return cname
        return None


#: Unique, never-reused checker ids (``id()`` can be recycled after GC).
_CHECKER_IDS = itertools.count(1)

#: checker-id -> agent stack, per execution context (asyncio task / thread).
_AGENT_STACKS: "contextvars.ContextVar[Mapping[int, Tuple[Optional[str], ...]]]" = (
    contextvars.ContextVar("happy_agent_stacks", default={})
)


class CapabilityChecker:
    """Runtime enforcement of capability and permission rules."""

    def __init__(
        self,
        registry: Optional[CapabilityRegistry] = None,
        policy: Optional[CapabilityPolicy] = None,
        filename: Optional[str] = None,
        source: Optional[str] = None,
    ) -> None:
        self.registry = registry or CapabilityRegistry()
        self.policy = policy or CapabilityPolicy()
        self.filename = filename
        self.source = source
        # The agent scope lives in a ContextVar (an immutable tuple) rather
        # than a shared list: every asyncio task / thread gets its own copy,
        # so an agent suspended at an ``await`` can never lend its
        # capabilities to another task that happens to run in the meantime.
        self._key = next(_CHECKER_IDS)
        self.audit: List[OperationRecord] = []

    # -- agent scope ----------------------------------------------------
    @property
    def _agent_stack(self) -> Tuple[Optional[str], ...]:
        return _AGENT_STACKS.get().get(self._key, ())

    def _set_stack(self, stack: Tuple[Optional[str], ...]) -> None:
        stacks = dict(_AGENT_STACKS.get())
        if stack:
            stacks[self._key] = stack
        else:
            stacks.pop(self._key, None)
        _AGENT_STACKS.set(stacks)

    @property
    def current_agent(self) -> Optional[str]:
        stack = self._agent_stack
        return stack[-1] if stack else None

    def enter_agent(self, agent: Optional[str]) -> None:
        self._set_stack(self._agent_stack + (agent,))

    def exit_agent(self) -> None:
        stack = self._agent_stack
        if stack:
            self._set_stack(stack[:-1])

    # -- core check -----------------------------------------------------
    def check_operation(
        self,
        operation: str,
        agent: Optional[str] = None,
        loc: Optional[object] = None,
        args: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Authorise ``operation`` for ``agent`` (defaults to the current one)."""
        if not self.policy.enabled:
            return True
        if agent is None:
            agent = self.current_agent
        known, action = classify_operation(operation)

        # Fail closed: an operation the capability model has never heard of
        # (e.g. an unsafe foreign-call wrapper) is NOT pure.
        if not known:
            reason = (
                f"operation '{operation}' has no capability mapping "
                "(denied: unknown operations fail closed)"
            )
            self._audit(agent, operation, None, False, reason, loc)
            self._deny_capability(operation, "unknown", agent, loc, reason)
            return False

        # Pure operations require no capability.
        if action is None:
            self._audit(agent, operation, action, True, "pure operation", loc)
            return True

        # Outside any agent scope.
        if agent is None:
            agent_critical = action in AGENT_REQUIRED_ACTIONS
            # Host-touching actions (file/network/process/db) require a
            # capability *somewhere*; performed with no agent they are denied
            # unless the host opted in.  Host-service actions (env, ai, …) stay
            # available outside agents.
            allowed = (not agent_critical) or self.policy.default_allow
            reason = (
                "sensitive operation outside any agent (allowed)"
                if allowed
                else f"sensitive operation '{operation}' outside any agent "
                f"requires capability granting '{action}'"
            )
            self._audit(agent, operation, action, allowed, reason, loc)
            if not allowed:
                self._deny_capability(operation, action, None, loc, reason)
            return allowed

        # Explicit permission denial wins.
        if action in self.registry.denied_actions(agent):
            reason = (
                f"agent '{agent}' is denied action '{action}' by its permissions"
            )
            self._audit(agent, operation, action, False, reason, loc)
            self._deny_permission(operation, action, agent, loc, reason)
            return False

        # Capability coverage.
        covering = self.registry.covering_capability(agent, action)
        if covering is not None:
            self._audit(
                agent, operation, action, True,
                f"covered by capability '{covering}'", loc,
            )
            return True

        reason = (
            f"agent '{agent}' holds no capability granting '{action}' "
            f"required by '{operation}'"
        )
        self._audit(agent, operation, action, False, reason, loc)
        self._deny_capability(operation, action, agent, loc, reason)
        return False

    def require_action(
        self,
        action: str,
        agent: Optional[str] = None,
        loc: Optional[object] = None,
    ) -> bool:
        """Authorise a specific *action* directly (bypassing the op catalogue).

        Used by standard-library functions whose sensitivity is intrinsic
        (e.g. ``std.crypto`` needing ``secrets``) rather than derived from
        :data:`~happy.compiler.permissions.ENFORCEMENT_MAP`.
        """
        if not self.policy.enabled:
            return True
        action = normalise_action(action)
        if agent is None:
            agent = self.current_agent
        if agent is None:
            agent_critical = action in AGENT_REQUIRED_ACTIONS
            allowed = (not agent_critical) or self.policy.default_allow
            reason = (
                f"sensitive action '{action}' outside any agent"
                + (" (allowed)" if allowed else "")
            )
            self._audit(None, action, action, allowed, reason, loc)
            if not allowed:
                self._deny_capability(action, action, None, loc, reason)
            return allowed
        if action in self.registry.denied_actions(agent):
            reason = f"agent '{agent}' is denied action '{action}'"
            self._audit(agent, action, action, False, reason, loc)
            self._deny_permission(action, action, agent, loc, reason)
            return False
        covering = self.registry.covering_capability(agent, action)
        if covering is not None:
            self._audit(
                agent, action, action, True,
                f"covered by capability '{covering}'", loc,
            )
            return True
        reason = f"agent '{agent}' holds no capability granting '{action}'"
        self._audit(agent, action, action, False, reason, loc)
        self._deny_capability(action, action, agent, loc, reason)
        return False

    # -- auditing + failures -------------------------------------------
    def _audit(
        self,
        agent: Optional[str],
        operation: str,
        action: Optional[str],
        allowed: bool,
        reason: str,
        loc: Optional[object],
    ) -> None:
        if self.policy.trace or not allowed:
            self.audit.append(
                OperationRecord(
                    agent=agent,
                    operation=operation,
                    action=action,
                    allowed=allowed,
                    reason=reason,
                    location=loc,
                )
            )

    def _deny_capability(
        self,
        operation: str,
        action: str,
        agent: Optional[str],
        loc: Optional[object],
        reason: str,
    ) -> None:
        if self.policy.enforcing:
            raise CapabilityDenied(
                message=(
                    f"capability denied: '{operation}' requires capability "
                    f"granting '{action}'" + (f" for agent '{agent}'" if agent else "")
                ),
                location=loc,
                filename=self.filename,
                source=self.source,
                suggestion=(
                    "add a capability granting this action to the agent, "
                    "or remove the operation"
                ),
            )

    def _deny_permission(
        self,
        operation: str,
        action: str,
        agent: Optional[str],
        loc: Optional[object],
        reason: str,
    ) -> None:
        if self.policy.enforcing:
            raise PermissionDenied(
                message=(
                    f"permission denied: '{operation}' (action '{action}') is "
                    f"explicitly denied" + (f" for agent '{agent}'" if agent else "")
                ),
                location=loc,
                filename=self.filename,
                source=self.source,
                suggestion="remove the 'cannot' entry, or avoid the operation",
            )

    # -- diagnostics ----------------------------------------------------
    @property
    def denials(self) -> List[OperationRecord]:
        return [r for r in self.audit if not r.allowed]

    @property
    def ok(self) -> bool:
        return not self.denials

    def summary(self) -> str:
        return (
            f"{len(self.audit)} audited operation(s), "
            f"{len(self.denials)} denial(s) (mode={self.policy.mode})"
        )
