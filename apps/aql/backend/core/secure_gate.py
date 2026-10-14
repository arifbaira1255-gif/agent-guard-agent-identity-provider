"""Authorization gate for every tool call an agent makes.

DESIGN RULES (inherited from AgentGuard / Happy LANG):

* **Fail closed.** Unreachable policy server, timeout, malformed answer, missing package, or a
  gate that raises -> the call is DENIED. Uncertainty never reads as "allow".
* **AgentGuard is authoritative.** In ``agentguard`` mode a local allow never overrides a remote
  deny. The local deny-list is applied first and always wins.
* **No silent allow-all in production.** ``allow_all`` exists for local demos only and refuses to
  be built when ``app_env == "production"``.

This module is standard-library only so it can be imported (and unit-tested) without the web
stack. The AgentGuard client is reused from ``agentguard_happy_contract`` (libs/contract) rather
than re-implemented, and is imported lazily.
"""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Iterable, Mapping, Optional

__all__ = [
    "GateDecision",
    "ToolDenied",
    "ToolGate",
    "DenyAllGate",
    "AllowAllGate",
    "LocalPolicyGate",
    "AgentGuardGate",
    "build_gate",
    "split_csv",
]

GATE_MODES = ("agentguard", "local", "deny_all", "allow_all")
_SAFE = re.compile(r"[^A-Za-z0-9._:/@=+~-]")


def split_csv(value: Any) -> frozenset:
    """Parse ``"a, b,,c"`` (or an iterable) into a frozenset of non-empty names."""
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset(p.strip() for p in value.split(",") if p.strip())
    return frozenset(str(p).strip() for p in value if str(p).strip())


@dataclass(frozen=True)
class GateDecision:
    """The outcome of one authorization check."""

    allowed: bool
    reason: str
    gate: str
    decision: str = "DENY"  # ALLOW | DENY | INDETERMINATE
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "gate": self.gate,
            "decision": self.decision,
            "correlation_id": self.correlation_id,
        }


class ToolDenied(PermissionError):
    """Raised when the gate refuses a tool call. Carries the structured decision."""

    def __init__(self, tool: str, decision: GateDecision) -> None:
        super().__init__(f"tool '{tool}' denied: {decision.reason} (gate={decision.gate})")
        self.tool = tool
        self.decision = decision


def _allow(gate: str, reason: str, **kw: Any) -> GateDecision:
    return GateDecision(True, reason, gate, "ALLOW", **kw)


def _deny(gate: str, reason: str, decision: str = "DENY", **kw: Any) -> GateDecision:
    return GateDecision(False, reason, gate, decision, **kw)


class ToolGate:
    """Base class. Subclasses implement :meth:`_decide`; :meth:`authorize` never raises."""

    def __init__(self, *, history: int = 200) -> None:
        self._recent: Deque[Dict[str, Any]] = deque(maxlen=max(1, int(history)))
        self._lock = threading.Lock()
        self.allowed_count = 0
        self.denied_count = 0

    @property
    def name(self) -> str:
        return type(self).__name__

    def _decide(self, tool: str, arguments: Mapping[str, Any], agent_id: Optional[str]) -> GateDecision:
        raise NotImplementedError

    def authorize(
        self, tool: str, arguments: Optional[Mapping[str, Any]] = None, *, agent_id: Optional[str] = None
    ) -> GateDecision:
        """Decide whether ``tool`` may run. Any internal error becomes a denial."""
        try:
            decision = self._decide(tool, dict(arguments or {}), agent_id)
        except Exception as exc:  # noqa: BLE001 - fail closed
            decision = _deny(self.name, f"gate_error:{type(exc).__name__}", "INDETERMINATE")
        with self._lock:
            if decision.allowed:
                self.allowed_count += 1
            else:
                self.denied_count += 1
            # Only the tool name and the decision are kept: arguments may hold secrets.
            self._recent.append({"ts": time.time(), "tool": tool, **decision.to_dict()})
        return decision

    def recent(self, limit: int = 50) -> list:
        with self._lock:
            return list(self._recent)[-max(1, int(limit)):]

    def describe(self) -> Dict[str, Any]:
        return {"gate": self.name, "allowed": self.allowed_count, "denied": self.denied_count}


class DenyAllGate(ToolGate):
    """Refuses everything. The safe default when nothing is configured."""

    def _decide(self, tool, arguments, agent_id):
        return _deny(self.name, "no_authorization_gate_configured")


class AllowAllGate(ToolGate):
    """Allows everything. LOCAL DEMOS ONLY - :func:`build_gate` refuses it in production."""

    def _decide(self, tool, arguments, agent_id):
        return _allow(self.name, "allow_all_gate_demo_only")


class LocalPolicyGate(ToolGate):
    """Static allow/deny lists. Deny wins; anything not on the allow-list is denied."""

    def __init__(self, allow: Iterable[str] = (), deny: Iterable[str] = ()) -> None:
        super().__init__()
        self.allow = split_csv(allow)
        self.deny = split_csv(deny)

    def _decide(self, tool, arguments, agent_id):
        if tool in self.deny:
            return _deny(self.name, "tool_on_denylist")
        if tool in self.allow:
            return _allow(self.name, "tool_on_allowlist")
        return _deny(self.name, "tool_not_on_allowlist")

    def describe(self):
        d = super().describe()
        d.update(allow=sorted(self.allow), deny=sorted(self.deny))
        return d


class AgentGuardGate(ToolGate):
    """Asks AgentGuard (``POST /v1/authorize``) before every tool call.

    Request shape: ``action="tool:<name>"``, ``resource="tool:<name>"``. This matches AgentGuard's
    built-in default policy, which allows ``tool:<name>`` only when the agent's verified credential
    carries that exact capability. The local deny-list is checked first; a local allow-list is NOT
    consulted (AgentGuard owns the decision).

    AgentGuard requires a verified credential AND a per-request proof-of-possession. Supply them
    through ``client_factory`` ("package.module:function" returning an AgentGuard SDK
    ``AuthorizationClient``, which signs proofs itself) or by injecting ``pdp``. A bare static
    token is NOT enough - the server will deny (fail closed).
    """

    ACTION_PREFIX = "tool:"

    def __init__(
        self,
        base_url: str,
        *,
        token: str = "",
        agent_id: str = "aql-1",
        timeout_seconds: float = 3.0,
        environment: str = "development",
        allow_insecure_http: bool = False,
        verify_tls: bool = True,
        deny: Iterable[str] = (),
        pdp: Any = None,
        client_factory: str = "",
    ) -> None:
        super().__init__()
        self.client_factory = client_factory
        self.base_url = base_url
        self.agent_id = agent_id
        self.deny = split_csv(deny)
        self._token = token
        self._pdp_override = pdp
        self._pdp_obj = pdp
        self._pdp_error: Optional[str] = None
        self._opts = dict(
            timeout_seconds=float(timeout_seconds),
            environment=environment,
            allow_insecure_http=bool(allow_insecure_http),
            verify_tls=bool(verify_tls),
        )

    def _pdp(self) -> Any:
        if self._pdp_obj is not None:
            return self._pdp_obj
        if self._pdp_error:
            raise RuntimeError(self._pdp_error)
        try:
            from agentguard_happy_contract.pdp import HttpPdp, SdkPdp  # lazy: libs/contract on path
        except Exception as exc:  # noqa: BLE001
            self._pdp_error = f"agentguard_contract_unavailable:{type(exc).__name__}"
            raise RuntimeError(self._pdp_error) from exc
        try:
            if self.client_factory:
                import importlib

                mod_name, _, attr = self.client_factory.partition(":")
                client = getattr(importlib.import_module(mod_name), attr)()
                self._pdp_obj = SdkPdp(client)
            else:
                self._pdp_obj = HttpPdp(self.base_url, **self._opts)
        except Exception as exc:  # noqa: BLE001 - e.g. plaintext http in production
            self._pdp_error = f"pdp_config_invalid:{type(exc).__name__}"
            raise RuntimeError(self._pdp_error) from exc
        return self._pdp_obj

    def _decide(self, tool, arguments, agent_id):
        if tool in self.deny:
            return _deny(self.name, "tool_on_denylist")
        if not self.base_url and not self.client_factory and self._pdp_override is None:
            return _deny(self.name, "agentguard_url_not_configured", "INDETERMINATE")
        pdp = self._pdp()
        from agentguard_happy_contract.models import AuthorizationRequest

        safe_tool = _SAFE.sub("_", tool)[:128] or "unknown"
        request = AuthorizationRequest(
            action=f"{self.ACTION_PREFIX}{safe_tool}",
            resource=f"tool:{safe_tool}",
            agent_id=_SAFE.sub("_", agent_id or self.agent_id)[:128] or "aql-1",
            requested_capabilities=(safe_tool,),
        )
        result = pdp.decide(request, token=self._token)
        allowed = bool(getattr(result, "allowed", False)) and not bool(
            getattr(result, "indeterminate", False)
        )
        decision = str(getattr(getattr(result, "decision", None), "value", "") or ("ALLOW" if allowed else "DENY"))
        reason = str(getattr(result, "reason", "") or ("allowed" if allowed else "denied"))
        cid = getattr(result, "correlation_id", None)
        if allowed:
            return _allow(self.name, reason, correlation_id=cid)
        return _deny(self.name, reason, decision if decision != "ALLOW" else "DENY", correlation_id=cid)

    def describe(self):
        d = super().describe()
        d.update(base_url=self.base_url, agent_id=self.agent_id, action_prefix=self.ACTION_PREFIX,
                 credentialed=bool(self.client_factory or self._pdp_override is not None))
        return d


def build_gate(
    mode: str,
    *,
    app_env: str = "development",
    allow: Any = "",
    deny: Any = "",
    agentguard_url: str = "",
    agentguard_token: str = "",
    agentguard_agent_id: str = "aql-1",
    agentguard_timeout_seconds: float = 3.0,
    agentguard_allow_insecure_http: bool = False,
    agentguard_verify_tls: bool = True,
    agentguard_client_factory: str = "",
) -> ToolGate:
    """Build the configured gate. Unknown modes and unsafe combinations raise ``ValueError``."""
    mode = (mode or "").strip().lower()
    if mode not in GATE_MODES:
        raise ValueError(f"unknown tool_gate_mode {mode!r}; expected one of {GATE_MODES}")
    if mode == "allow_all":
        if (app_env or "").lower() == "production":
            raise ValueError("tool_gate_mode=allow_all is not permitted when app_env=production")
        return AllowAllGate()
    if mode == "deny_all":
        return DenyAllGate()
    if mode == "local":
        return LocalPolicyGate(allow=allow, deny=deny)
    return AgentGuardGate(
        agentguard_url,
        token=agentguard_token,
        agent_id=agentguard_agent_id,
        timeout_seconds=agentguard_timeout_seconds,
        environment=app_env,
        allow_insecure_http=agentguard_allow_insecure_http,
        verify_tls=agentguard_verify_tls,
        deny=deny,
        client_factory=agentguard_client_factory,
    )
