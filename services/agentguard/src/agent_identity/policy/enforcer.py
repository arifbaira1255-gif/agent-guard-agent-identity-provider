"""Step 10 enforcement primitive: the anti-bypass gate.

The requirement is that the authorization check happens BEFORE a protected operation executes, and
that a caller cannot bypass it by invoking an internal execution interface directly. This module
provides the single server-side chokepoint:

  * :class:`PolicyEnforcer` wraps a protected callable. Calling it evaluates policy first and runs
    the callable ONLY on an explicit ALLOW. A DENY / REQUIRE_APPROVAL / INDETERMINATE raises and the
    callable is never invoked.
  * :func:`install_policy_engine` is the one place that installs the policy hook into the HTTP
    transport (``set_policy_hook``), so ``POST /v1/authorize`` and any protected route share the
    same decision path.

The enforcer is deliberately small and pure: it never trusts a decision supplied by a client, and it
never treats a missing/indeterminate decision as an allow.
"""
from __future__ import annotations

from typing import Callable, Optional, TypeVar

from ..core.errors import ForbiddenError
from .models import DecisionKind, PolicyDecision
from .service import PolicyDecisionService

T = TypeVar("T")


class PolicyEnforcer:
    """Gate a protected operation behind a policy decision."""

    def __init__(self, service: PolicyDecisionService):
        self.service = service

    def decide(self, *, agent_id: str, tenant: str, action: str, resource: str, **kwargs) -> PolicyDecision:
        return self.service.authorize(agent_id=agent_id, tenant=tenant, action=action,
                                      resource=resource, **kwargs)

    def enforce(self, decision: PolicyDecision, executor: Callable[[], T]) -> T:
        """Run ``executor`` ONLY on an explicit ALLOW. This is the anti-bypass guarantee."""
        if not isinstance(decision, PolicyDecision) or decision.kind is not DecisionKind.ALLOW:
            reason = getattr(decision, "reason", "denied") or "denied"
            raise ForbiddenError(f"action denied: {reason}")
        return executor()

    def authorize_and_run(self, *, agent_id: str, tenant: str, action: str, resource: str,
                          executor: Callable[[], T], **kwargs) -> T:
        decision = self.decide(agent_id=agent_id, tenant=tenant, action=action, resource=resource,
                               **kwargs)
        return self.enforce(decision, executor)


def install_policy_engine(service: PolicyDecisionService, *, transport=None) -> None:
    """Install the policy decision hook into the HTTP transport's ``POST /v1/authorize`` route.

    ``transport`` defaults to ``agent_identity.api.http_transport``. Passing the module explicitly
    keeps this testable without importing the transport at module load.
    """
    if transport is None:
        from ..api import http_transport as transport  # noqa: PLC0415
    from .service import make_policy_hook
    transport.set_policy_hook(make_policy_hook(service))
