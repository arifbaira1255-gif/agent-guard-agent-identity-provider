"""Step 11 transport integration hooks.

The Step 9/10 ``POST /v1/authorize`` route already verifies the credential + possession proof and then
delegates to a pluggable hook (``http_transport.set_policy_hook``). Step 11 plugs a *governance-aware*
hook into that same seam:

* when the request carries a resource descriptor (``resource_id`` + an ``operation``), the hook runs
  the full :class:`~agent_identity.governance.guard.ResourceGuard` pipeline — registry resolution,
  tenant boundary, operation least privilege, tool-registry checks, then the Step 10 policy engine;
* otherwise it falls back to the plain Step 10 policy hook, so existing callers are unchanged.

Only the *decision* crosses the transport. The decision **seal** is never returned to a client: it is
a server-side, single-use token consumed by ``ResourceGuard.enforce`` inside this process. That keeps
the authoritative enforcement point on the server.
"""
from __future__ import annotations

from typing import Optional

from .models import ResourceDescriptor
from .service import GovernanceService


def make_governance_hook(service: GovernanceService):
    """Build a ``set_policy_hook`` callable that enforces governance when a descriptor is present."""
    from ..policy.service import make_policy_hook
    policy_hook = make_policy_hook(service.policy)

    def hook(svc, request: dict) -> dict:  # noqa: ARG001 - signature fixed by the transport
        # Verified, server-injected identity (a client cannot supply these).
        agent_id = request.get("_agent_id") or ""
        tenant = request.get("_org_id") or ""
        instance_id = request.get("_instance_id")

        resource_id = request.get("resource_id")
        operation = request.get("operation")
        if not _descriptor_present(resource_id, operation):
            # No resource descriptor: preserve the Step 10 authorisation behaviour exactly.
            return policy_hook(svc, request)

        context = request.get("context") if isinstance(request.get("context"), dict) else {}
        descriptor = ResourceDescriptor(
            resource_id=resource_id, operation=operation,
            resource_type=request.get("resource_type"),
            tool=request.get("tool"),
            requested_capabilities=tuple(request.get("requested_capabilities") or ()),
            context=context)
        decision = service.guard.decide(
            agent_id=agent_id, tenant=tenant, descriptor=descriptor, instance_id=instance_id,
            claimed_capabilities=tuple(request.get("_capabilities") or ()),
            environment=request.get("environment") or "development",
            credential_status="valid",
            correlation_id=request.get("correlation_id"))
        return decision.to_dict()

    return hook


def _descriptor_present(resource_id, operation) -> bool:
    return isinstance(resource_id, str) and resource_id.strip() \
        and isinstance(operation, str) and operation.strip()


def install_governance(service: GovernanceService, *, transport=None) -> None:
    """Install the governance hook into the HTTP transport's ``POST /v1/authorize`` route.

    ``transport`` defaults to ``agent_identity.api.http_transport``. Passing it explicitly keeps this
    testable without importing the transport at module load.
    """
    if transport is None:
        from ..api import http_transport as transport  # noqa: PLC0415
    transport.set_policy_hook(make_governance_hook(service))


def describe(service: Optional[GovernanceService]) -> dict:
    """Non-secret operational description of the configured governance plane."""
    if service is None:
        return {"configured": False}
    return {"configured": True, "environment": service.cfg.environment,
            "unknown_resource_policy": service.cfg.unknown_resource_policy,
            "unclassified_type_policy": service.cfg.unclassified_type_policy,
            "escalate_at_or_above": service.cfg.escalate_at_or_above,
            "require_tool_approval": service.cfg.require_tool_approval}
