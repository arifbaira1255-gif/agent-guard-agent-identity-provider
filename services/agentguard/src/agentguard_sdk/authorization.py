"""Authorization: request a policy decision and enforce it. FAIL CLOSED.

Separation of concerns (a hard requirement of this step):
  * **authentication** (``auth.py``) proves *who* the agent is;
  * **authorization** (this module) decides *whether* an action is permitted;
  * **execution** (``adapters``) runs the action \u2014 and only ever after an explicit ALLOW.

A decision is obtained from a pluggable Policy Decision Point (PDP). The default PDP calls the
AgentGuard control plane (``POST /v1/authorize``), which is the Step 10 policy engine's surface. If
that endpoint is not available, the SDK returns a DENY with reason ``policy_unavailable`` \u2014 it
never falls back to "allow". :meth:`AuthorizationClient.enforce` guarantees the executor is not
invoked unless ``decision.allowed`` is true.
"""
from __future__ import annotations

from typing import Callable, Optional, Protocol, TypeVar

from .errors import AuthorizationError, PolicyUnavailableError, ValidationError
from .models import Decision

T = TypeVar("T")


class PolicyDecisionPoint(Protocol):
    """A pluggable decision source. Implementations MUST fail closed on any error."""

    def decide(self, request: dict) -> Decision:  # pragma: no cover - protocol
        ...


class RemotePdp:
    """Default PDP: asks the AgentGuard control plane for a decision.

    A missing endpoint (404/501) or a transport failure yields a DENY, never an allow.
    """

    def __init__(self, client, *, path: str = "/v1/authorize"):
        self._client = client
        self._path = path

    def decide(self, request: dict) -> Decision:
        from .errors import NotFoundError, TransportError
        try:
            resp = self._client._transport.request("POST", self._path, body=request)
        except NotFoundError:
            return Decision.deny("policy_unavailable")
        except TransportError:
            return Decision.deny("policy_unavailable")
        except AuthorizationError:
            return Decision.deny("policy_denied")
        body = resp.body if isinstance(resp.body, dict) else {}
        return Decision.from_dict(body)


class DenyAllPdp:
    """A PDP that denies everything. The safe default when no policy engine is configured."""

    def decide(self, request: dict) -> Decision:  # noqa: ARG002
        return Decision.deny("no_policy_decision_point_configured")


class StaticPdp:
    """A deterministic PDP for tests and local development. Never use in production."""

    def __init__(self, allowed_actions=(), *, reason: str = "static_allow"):
        self._allowed = set(allowed_actions)
        self._reason = reason

    def decide(self, request: dict) -> Decision:
        action = request.get("action")
        if action in self._allowed:
            return Decision(True, self._reason, policy="static")
        return Decision.deny("static_deny")


class AuthorizationClient:
    def __init__(self, client, *, pdp: Optional[PolicyDecisionPoint] = None,
                 audience: Optional[str] = None):
        self._client = client
        self.audience = audience or client.config.tool_audience
        self.pdp = pdp if pdp is not None else RemotePdp(client)

    # ------------------------------------------------------------------ decide
    def authorize(self, *, action: str, resource: str, context: Optional[dict] = None,
                  correlation_id: Optional[str] = None,
                  credential=None) -> Decision:
        """Request a decision. Returns a :class:`Decision`; never raises for a plain DENY."""
        if not action or not isinstance(action, str):
            raise ValidationError("action is required")
        if not resource or not isinstance(resource, str):
            raise ValidationError("resource is required")
        cred = credential or self._client.authenticator.credentials.ensure_valid()
        proof = self._client.authenticator.make_proof(cred, audience=self.audience)
        request = {
            "action": action, "resource": resource, "context": context or {},
            "token": cred.token, "credential_id": cred.credential_id, "agent_id": cred.agent_id,
            "instance_id": cred.instance_id, "org_id": cred.org_id,
            "proof": proof, "audience": self.audience,
        }
        if correlation_id:
            request["correlation_id"] = correlation_id
        try:
            decision = self.pdp.decide(request)
        except Exception:                                # noqa: BLE001 - fail closed, always
            return Decision.deny("policy_error", correlation_id=correlation_id)
        if not isinstance(decision, Decision):
            return Decision.deny("policy_error", correlation_id=correlation_id)
        return decision

    def require(self, *, action: str, resource: str, context: Optional[dict] = None,
                correlation_id: Optional[str] = None, credential=None) -> Decision:
        """Like :meth:`authorize` but raises :class:`AuthorizationError` on DENY."""
        decision = self.authorize(action=action, resource=resource, context=context,
                                  correlation_id=correlation_id, credential=credential)
        if not decision.allowed:
            if decision.reason == "policy_unavailable":
                raise PolicyUnavailableError("authorization could not be verified")
            raise AuthorizationError(f"action denied: {decision.reason or 'denied'}")
        return decision

    def enforce(self, decision: Decision, executor: Callable[[], T]) -> T:
        """Run ``executor`` ONLY if ``decision.allowed``. This is the anti-bypass guarantee."""
        if not isinstance(decision, Decision) or not decision.allowed:
            reason = getattr(decision, "reason", "denied") or "denied"
            raise AuthorizationError(f"action denied: {reason}")
        return executor()

    def authorize_and_run(self, *, action: str, resource: str, executor: Callable[[], T],
                          context: Optional[dict] = None,
                          correlation_id: Optional[str] = None) -> T:
        """Convenience: decide, then run only on ALLOW."""
        decision = self.require(action=action, resource=resource, context=context,
                                correlation_id=correlation_id)
        return self.enforce(decision, executor)
