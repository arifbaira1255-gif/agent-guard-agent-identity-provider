"""The Happy LANG -> AgentGuard authorizer: the trust boundary at the seam.

WHAT THIS FIXES (audit blockers B1 and B4)
------------------------------------------
Happy LANG's ``CapabilityChecker`` runs **in the same process as the code it checks**, so a program
that never calls it is unconstrained, and a local ALLOW was final.  This module makes AgentGuard
the authoritative decision point for a sensitive operation while keeping Happy's local checker as a
fast pre-filter.

RULES, IN ORDER OF PRECEDENCE
-----------------------------
1. **Remote DENY always wins.**  A local ALLOW never overrides it.
2. **Uncertainty is denial.**  INDETERMINATE / timeout / transport failure / malformed answer ->
   deny.
3. **Local DENY short-circuits.**  If Happy's own checker denies, AgentGuard is not even asked
   (a capability the program does not hold cannot be talked into existence remotely).
4. **A declaration is not a grant.**  ``requested_capabilities`` and ``declared_resources`` are
   *claims*.  AgentGuard re-derives identity from the verified credential and decides.

The object is a **drop-in replacement** for ``happy.runtime.capability.CapabilityChecker`` at the
documented extension points -- the ``use_checker`` hooks in ``happy/std/*.py`` and
``RuntimeContext.capabilities`` -- so no Happy LANG source file is modified.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from .config import IntegrationConfig
from .errors import ContractError
from .events import EventForwarder
from .models import (
    ArtifactRef,
    AuthorizationDecision,
    AuthorizationRequest,
    EventType,
    SecurityEvent,
    SecurityEventOutcome,
    SourceLocation,
    new_id,
)
from .pdp import DenyAllPdp, HttpPdp, PolicyDecisionPoint
from .validation import SAFE_TOKEN_RE, canonical_json, sha256_hex

#: AgentGuard's SDK ``ToolGuard`` convention: a protected operation becomes ``tool:<name>``.
ACTION_PREFIX = "tool:"

#: Happy LANG's ``ENFORCEMENT_MAP`` keys that should be turned into a governed resource target, and
#: the argument name the target is taken from.
_RESOURCE_ARG_KEYS = {
    "write_file": "path", "read_file": "path", "append_file": "path", "file_exists": "path",
    "remove_file": "path", "make_dir": "path", "list_dir": "path", "copy_file": "dst",
    "move_file": "dst", "exists": "path", "is_dir": "path", "is_file": "path", "size": "path",
    "http_get": "url", "http_post": "url", "http_request": "url", "download": "url",
    "tcp_connect": "host", "tcp_send": "host", "process": "command", "exec": "command",
    "run": "command", "spawn_process": "command", "shell": "command",
    "env": "name", "getenv": "name", "get": "name", "setenv": "name", "unset": "name",
}


class HappyAuthorizationDenied(Exception):
    """Fallback denial type used when Happy LANG's own ``CapabilityDenied`` is not importable."""

    code = "R2001"

    def __init__(self, message: str, *, location: Optional[object] = None,
                 suggestion: Optional[str] = None, decision: Optional[AuthorizationDecision] = None,
                 correlation_id: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.location = location
        self.suggestion = suggestion
        self.decision = decision
        self.correlation_id = correlation_id


def _denial_error(message: str, *, location: Optional[object],
                  decision: AuthorizationDecision, suggestion: str):
    """Raise Happy LANG's own ``CapabilityDenied`` when available, else the local fallback.

    Using Happy's exception type means an existing program's ``catch`` clauses and diagnostics keep
    working unchanged -- the integration changes the *decision source*, not the error surface.
    """
    try:                                                    # pragma: no cover - depends on import
        from happy.runtime.errors import CapabilityDenied as _HappyCapabilityDenied

        return _HappyCapabilityDenied(
            message=message, location=location, suggestion=suggestion)
    except Exception:                                       # noqa: BLE001 - standalone use
        return HappyAuthorizationDenied(message, location=location, suggestion=suggestion,
                                        decision=decision,
                                        correlation_id=decision.correlation_id)


def _coerce_location(loc: Any) -> SourceLocation:
    """Best-effort conversion of Happy's location shapes into a :class:`SourceLocation`."""
    if loc is None:
        return SourceLocation()
    if isinstance(loc, SourceLocation):
        return loc
    if isinstance(loc, (tuple, list)):
        if len(loc) >= 3:
            return SourceLocation(file=loc[0], line=loc[1], column=loc[2])
        if len(loc) == 2:
            return SourceLocation(line=loc[0], column=loc[1])
        if len(loc) == 1:
            return SourceLocation(file=loc[0])
        return SourceLocation()
    if isinstance(loc, Mapping):
        return SourceLocation(file=loc.get("file"), line=loc.get("line"),
                              column=loc.get("column"))
    return SourceLocation(file=str(loc)[:256])


@dataclass
class AuthorizationRecord:
    """One audited authorization attempt (local pre-filter + remote decision)."""

    operation: str
    action: str
    resource: str
    agent: Optional[str]
    local_allowed: Optional[bool]
    decision: Optional[AuthorizationDecision]
    asked_remote: bool
    latency_ms: int = 0


class AgentGuardAuthorizer:
    """Route a Happy LANG sensitive operation through AgentGuard's authoritative decision.

    Drop-in compatible with ``CapabilityChecker``: it exposes ``check_operation`` and
    ``require_action`` with the same signatures, plus ``enter_agent``/``exit_agent`` delegation.
    """

    def __init__(
        self,
        config: Optional[IntegrationConfig] = None,
        *,
        checker: Any = None,
        pdp: Optional[PolicyDecisionPoint] = None,
        forwarder: Optional[EventForwarder] = None,
        agent_id: Optional[str] = None,
        instance_id: Optional[str] = None,
        org_id: Optional[str] = None,
        agent_scope: Optional[str] = None,
        resource_resolver: Optional[Callable[[str, Optional[Mapping[str, Any]], Any], str]] = None,
        artifact: Optional[ArtifactRef] = None,
        effects: Tuple[str, ...] = (),
        contracts: Tuple[str, ...] = (),
    ) -> None:
        self.config = config or IntegrationConfig.from_env()
        self.checker = checker
        self.agent_id = agent_id or self.config.agent_id or "happy-agent-unknown"
        self.instance_id = instance_id or self.config.instance_id
        self.org_id = org_id or self.config.org_id
        self.agent_scope = agent_scope or self.config.agent_scope
        self.artifact = artifact or ArtifactRef()
        self.effects = tuple(effects)
        self.contracts = tuple(contracts)
        self._resource_resolver = resource_resolver
        # When the integration is ON and no PDP was supplied we install a DenyAll PDP rather than
        # silently falling back to local-only behaviour.
        if pdp is not None:
            self.pdp = pdp
        elif self.config.enabled and self.config.mode != "off":
            self.pdp = HttpPdp(
                self.config.base_url, path=self.config.authorize_path,
                timeout_seconds=self.config.timeout_seconds, verify_tls=self.config.verify_tls,
                ca_bundle=self.config.ca_bundle, max_response_bytes=self.config.max_response_bytes,
                environment=self.config.environment,
                allow_insecure_http=self.config.allow_insecure_http,
                audience=self.config.audience)
        else:
            self.pdp = DenyAllPdp()
        self.forwarder = forwarder if forwarder is not None else EventForwarder(
            None, enabled=False)
        self.audit: list = []

    # -- convenience constructors ------------------------------------------------------------
    @classmethod
    def for_checker(cls, checker: Any, *, config: Optional[IntegrationConfig] = None,
                    **kwargs) -> "AgentGuardAuthorizer":
        """Wrap an existing Happy ``CapabilityChecker`` as the local pre-filter."""
        return cls(config, checker=checker, **kwargs)

    @property
    def enabled(self) -> bool:
        return self.config.is_enabled and self.config.mode != "off"

    @property
    def caching_key(self) -> str:
        """A stable key for a (agent, action, resource) triple, for an embedding cache."""
        return canonical_json({"a": self.agent_scope, "i": self.agent_id})

    # -- agent scope (delegated to the local checker when present) ---------------------------
    @property
    def current_agent(self) -> Optional[str]:
        if self.checker is not None and hasattr(self.checker, "current_agent"):
            return getattr(self.checker, "current_agent")
        return self.agent_scope

    def enter_agent(self, agent: Optional[str]) -> None:
        if self.checker is not None and hasattr(self.checker, "enter_agent"):
            self.checker.enter_agent(agent)

    def exit_agent(self) -> None:
        if self.checker is not None and hasattr(self.checker, "exit_agent"):
            self.checker.exit_agent()

    # -- resource resolution -----------------------------------------------------------------
    def resolve_resource(self, operation: str, args: Optional[Mapping[str, Any]],
                         agent: Optional[str]) -> str:
        """Derive the governed resource target from the call arguments (never from the program)."""
        if self._resource_resolver is not None:
            resolved = self._resource_resolver(operation, args, agent)
            if resolved:
                return str(resolved)
        if isinstance(args, Mapping):
            key = _RESOURCE_ARG_KEYS.get(operation)
            if key and args.get(key) is not None:
                return str(args[key])
            for candidate in ("path", "url", "host", "target", "resource", "name"):
                if args.get(candidate) is not None:
                    return str(args[candidate])
        return self.config.default_resource

    def action_for(self, operation: str) -> Tuple[str, Optional[str]]:
        """Map a Happy operation onto ``(agentguard_action, abstract_action)``.

        The abstract action comes from Happy's own ``ENFORCEMENT_MAP`` so the two sides can never
        disagree about what an operation requires.
        """
        abstract: Optional[str] = None
        try:                                                # pragma: no cover - depends on import
            from happy.runtime.capability import classify_operation

            _known, abstract = classify_operation(operation)
        except Exception:                                   # noqa: BLE001 - standalone use
            abstract = None
        action = f"{ACTION_PREFIX}{operation}"
        if not SAFE_TOKEN_RE.match(action):
            # An unmappable operation name is coerced to a stable sentinel rather than being sent
            # unvalidated: the request must never fail validation inside the authorization path.
            action = f"{ACTION_PREFIX}unmapped"
        return action, abstract

    # -- core decision ----------------------------------------------------------------------
    def authorize_operation(
        self,
        operation: str,
        *,
        agent: Optional[str] = None,
        loc: Any = None,
        args: Optional[Mapping[str, Any]] = None,
        requested_capabilities: Tuple[str, ...] = (),
        _record_audit: bool = True,
    ) -> AuthorizationDecision:
        """Ask AgentGuard about ``operation``.  Does NOT raise -- returns the decision.

        ``_record_audit=False`` lets :meth:`check_operation` record a single, richer audit entry
        (including the local pre-filter outcome) instead of two.
        """
        agent = agent if agent is not None else self.current_agent
        action, abstract = self.action_for(operation)
        resource = self.resolve_resource(operation, args, agent)
        request = AuthorizationRequest(
            action=action, resource=resource, agent_id=self.agent_id,
            instance_id=self.instance_id, org_id=self.org_id,
            requested_capabilities=tuple(requested_capabilities) or (abstract, ) if abstract
            else tuple(requested_capabilities),
            declared_resources=(resource, ), operation=operation,
            source_loc=_coerce_location(loc), agent_scope=agent or self.agent_scope,
            effects=self.effects, contracts=self.contracts, artifact=self.artifact,
            context={"args_keys": sorted(args.keys()) if isinstance(args, Mapping) else []},
        )
        request.validate()
        if not self.enabled:
            # Inert: the integration is disabled, so the local checker's answer stands.
            return AuthorizationDecision.allow("integration_disabled")
        started = time.time()
        decision = self.pdp.decide(request, token=self._token(), proof=self._proof())
        if decision.correlation_id is None:
            decision = AuthorizationDecision.from_agentguard_dict(
                decision.to_agentguard_decision_dict(), correlation_id=request.correlation_id,
                request_id=request.request_id, latency_ms=int((time.time() - started) * 1000))
        if _record_audit:
            self._record(operation, action, resource, agent, None, decision, True,
                         int((time.time() - started) * 1000))
        return decision

    def check_operation(self, operation: str, agent: Optional[str] = None, loc: Any = None,
                        args: Optional[Mapping[str, Any]] = None) -> bool:
        """Authorise ``operation``: local pre-filter, then the authoritative remote decision."""
        agent = agent if agent is not None else self.current_agent
        action, _abstract = self.action_for(operation)
        resource = self.resolve_resource(operation, args, agent)

        # 1. Local pre-filter.  Per Happy's contract ``check_operation`` RETURNS a bool (and raises
        # when the policy is in enforce mode and the operation is not permitted); either a False
        # return or a raised error is final and never reaches the network.
        local_allowed: Optional[bool] = None
        if self.checker is not None and hasattr(self.checker, "check_operation"):
            local_allowed = bool(self.checker.check_operation(operation, agent=agent, loc=loc,
                                                              args=args))
            if not local_allowed:
                # A local denial is final AND must still be auditable.
                self._record(operation, action, resource, agent, False, None, False)
                return False

        # 2. Integration disabled -> the local answer (or the permissive default) stands.
        if not self.enabled:
            self._record(operation, action, resource, agent, local_allowed, None, False)
            return True

        # 3. Authoritative remote decision.
        started = time.time()
        decision = self.authorize_operation(operation, agent=agent, loc=loc, args=args,
                                            _record_audit=False)
        elapsed = int((time.time() - started) * 1000)
        self._record(operation, action, resource, agent, local_allowed, decision, True, elapsed)

        if decision.allowed:
            self._emit(EventType.OPERATION_ROUTED, SecurityEventOutcome.OK, operation=operation,
                       action=action, resource=resource, reason=decision.reason,
                       correlation_id=decision.correlation_id,
                       extra={"decision": decision.decision.value, "latency_ms": elapsed})
            return True

        # 4. Deny (or approval-required, or indeterminate).  Fail closed, always.
        reason = decision.reason or decision.decision.value
        self._emit(EventType.DENIED if not decision.indeterminate else EventType.INDETERMINATE,
                   SecurityEventOutcome.DENIED, operation=operation, action=action,
                   resource=resource, reason=reason, correlation_id=decision.correlation_id,
                   extra={"decision": decision.decision.value})
        raise _denial_error(
            f"capability denied: '{operation}' is not authorized by AgentGuard "
            f"({decision.decision.value}: {reason})",
            location=loc, decision=decision,
            suggestion="request a policy grant from AgentGuard for this action, or remove the "
                       "operation; a capability declared in the .hpy source does not grant access")

    def require_action(self, action: str, agent: Optional[str] = None, loc: Any = None) -> bool:
        """Authorise an abstract action directly (the path ``happy.std.crypto`` uses)."""
        agent = agent if agent is not None else self.current_agent
        local_allowed: Optional[bool] = None
        if self.checker is not None and hasattr(self.checker, "require_action"):
            local_allowed = bool(self.checker.require_action(action, agent=agent, loc=loc))
            if not local_allowed:
                return False
        if not self.enabled:
            self._record(action, f"{ACTION_PREFIX}{action}", self.config.default_resource, agent,
                         local_allowed, None, False)
            return True
        # An abstract action is asked about verbatim so AgentGuard's policy sees the real action.
        request = AuthorizationRequest(
            action=f"{ACTION_PREFIX}{action}", resource=self.config.default_resource,
            agent_id=self.agent_id, instance_id=self.instance_id, org_id=self.org_id,
            requested_capabilities=(action, ), operation=action, source_loc=_coerce_location(loc),
            agent_scope=agent or self.agent_scope, artifact=self.artifact)
        request.validate()
        started = time.time()
        decision = self.pdp.decide(request, token=self._token(), proof=self._proof())
        elapsed = int((time.time() - started) * 1000)
        self._record(action, request.action, request.resource, agent, local_allowed, decision, True,
                     elapsed)
        if decision.allowed:
            return True
        reason = decision.reason or decision.decision.value
        self._emit(EventType.DENIED, SecurityEventOutcome.DENIED, operation=action,
                   action=request.action, resource=request.resource, reason=reason,
                   correlation_id=decision.correlation_id,
                   extra={"decision": decision.decision.value})
        raise _denial_error(
            f"capability denied: action '{action}' is not authorized by AgentGuard "
            f"({decision.decision.value}: {reason})",
            location=loc, decision=decision,
            suggestion="request a policy grant from AgentGuard for this action")

    # -- credential plumbing -----------------------------------------------------------------
    def set_credentials(self, *, token: Optional[str] = None, proof: Optional[dict] = None,
                        proof_provider: Optional[Callable[[], Optional[dict]]] = None) -> None:
        """Supply the credential and its possession proof.

        ``proof_provider`` is the RECOMMENDED form: AgentGuard keeps a replay cache, so a single
        proof may be used exactly once. A provider mints a fresh proof per authorization request,
        which is what makes repeated checks succeed instead of failing with ``replay_detected``.
        """
        self._token_value = token
        self._proof_value = proof
        self._proof_provider = proof_provider

    def _token(self) -> str:
        return getattr(self, "_token_value", "") or ""

    def _proof(self) -> Optional[dict]:
        provider = getattr(self, "_proof_provider", None)
        if provider is not None:
            try:
                fresh = provider()
            except Exception:                                # noqa: BLE001 - fail closed upstream
                return None
            if fresh is not None:
                return fresh
        return getattr(self, "_proof_value", None)

    # -- auditing -----------------------------------------------------------------------------
    def _record(self, operation: str, action: str, resource: str, agent: Optional[str],
                local_allowed: Optional[bool], decision: Optional[AuthorizationDecision],
                asked_remote: bool, latency_ms: int = 0) -> None:
        """Append an audit record.  Auditing must never break enforcement, so it cannot raise."""
        try:
            self.audit.append(AuthorizationRecord(
                operation=operation, action=action, resource=resource, agent=agent,
                local_allowed=local_allowed, decision=decision, asked_remote=asked_remote,
                latency_ms=latency_ms))
        except Exception:                                    # noqa: BLE001 - never fail enforcement
            pass

    def _emit(self, event_type: str, outcome: SecurityEventOutcome, *, operation: str, action: str,
              resource: str, reason: Optional[str], correlation_id: Optional[str],
              extra: Optional[Dict[str, Any]] = None) -> None:
        metadata = {"operation": operation, "action": action}
        if extra:
            metadata.update(extra)
        event = SecurityEvent(
            event_type=event_type, outcome=outcome.value, correlation_id=correlation_id,
            agent_id=self.agent_id, instance_id=self.instance_id, org_id=self.org_id,
            action=action, resource=resource, reason=(reason or "")[:512], metadata=metadata)
        try:
            self.forwarder.report(event)
        except Exception:                                    # noqa: BLE001 - never break execution
            pass

    # -- diagnostics -------------------------------------------------------------------------
    @property
    def denials(self) -> list:
        return [r for r in self.audit
                if r.decision is not None and not r.decision.allowed]

    def summary(self) -> str:
        remote = sum(1 for r in self.audit if r.asked_remote)
        return (f"{len(self.audit)} authorization check(s), {remote} remote, "
                f"{len(self.denials)} denial(s) (enabled={self.enabled}, "
                f"mode={self.config.mode})")


def build_authorizer(config: Optional[IntegrationConfig] = None, **kwargs) -> AgentGuardAuthorizer:
    """Factory used by embedders and tests."""
    return AgentGuardAuthorizer(config, **kwargs)


def install_into_runtime(runtime_context: Any, authorizer: AgentGuardAuthorizer) -> None:
    """Replace a live ``RuntimeContext.capabilities`` with the guarded authorizer.

    ``RuntimeContext`` rebinds the standard-library ``use_checker`` hooks from
    ``self.capabilities`` when it runs, so assigning here is sufficient and no Happy LANG source
    file is touched.
    """
    if not hasattr(runtime_context, "capabilities"):
        raise ContractError("runtime context exposes no 'capabilities' attribute")
    runtime_context.capabilities = authorizer


__all__ = [
    "AgentGuardAuthorizer", "AuthorizationRecord", "HappyAuthorizationDenied",
    "build_authorizer", "install_into_runtime", "ACTION_PREFIX",
]
