"""Step 11 connector boundary — the standard enforcement interface for tool adapters and connectors.

A connector describes a class of protected resource (its :class:`ResourceType` and a descriptor) and
implements the actual work in :meth:`ResourceConnector.perform`. A ``ResourceConnector`` on its own is
an *internal* interface with no authorization: it is the thing the guard protects, not a way around
it.

:class:`GuardedConnector` is the ONLY wrapper an adapter should hand to callers. Its sole execution
path is ``guard.authorize_and_run`` — so a caller cannot reach ``perform`` without a sealed ALLOW, and
an attempt to call the raw connector directly is a **bypass**, which
:class:`GovernanceService` refuses to expose.

External systems keep their own permissions
-------------------------------------------
The guard proves *the AgentGuard-governed agent is authorized* to ask for an operation. It does NOT
grant the underlying system's own authority: the database credential, the cloud IAM role, the HTTP
API key and the SaaS tenant's ACLs are all still enforced by that system. That is an explicit
integration boundary, documented in ``docs/STEP11_SECURITY_LIMITATIONS.md`` — governance is the
control plane for *who may ask*, not a replacement for the target's access control.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, TypeVar

from .guard import ResourceGuard
from .models import GovernanceDecision, ResourceDescriptor, ResourceType

T = TypeVar("T")


class ResourceConnector(ABC):
    """A class of protected resource. Subclasses implement :meth:`perform` (the real work).

    ``perform`` MUST NOT perform any authorization of its own and MUST NOT be called directly by an
    adapter — it is reached only through :class:`GuardedConnector` / ``GovernanceService.execute``.
    """

    @property
    @abstractmethod
    def resource_type(self) -> ResourceType: ...

    @abstractmethod
    def descriptor(self, *, resource_id: str, operation: str,
                   tool: Optional[str] = None, **kwargs) -> ResourceDescriptor: ...

    @abstractmethod
    def perform(self, *args, **kwargs): ...


class GuardedConnector:
    """Binds a connector to the guard. Every call is authorized first; nothing runs on a non-ALLOW.

    It exposes exactly one operation, :meth:`__call__`, which delegates to
    ``ResourceGuard.authorize_and_run``. There is no ``.perform`` passthrough and no "raw" accessor,
    so an adapter that holds a ``GuardedConnector`` cannot bypass enforcement.
    """

    def __init__(self, guard: ResourceGuard, connector: ResourceConnector):
        self._guard = guard
        self._connector = connector

    @property
    def resource_type(self) -> ResourceType:
        return self._connector.resource_type

    def __call__(self, *, agent_id: str, tenant: str, resource_id: str, operation: str,
                 instance_id: Optional[str] = None, tool: Optional[str] = None,
                 claimed_capabilities=(), requested_capabilities=(), context: Optional[dict] = None,
                 correlation_id: Optional[str] = None, **perform_kwargs):
        """Authorize, then run the connector's work with the supplied arguments."""
        descriptor = self._connector.descriptor(
            resource_id=resource_id, operation=operation, tool=tool,
            requested_capabilities=tuple(requested_capabilities),
            context=context)
        return self._guard.authorize_and_run(
            agent_id=agent_id, tenant=tenant, descriptor=descriptor, instance_id=instance_id,
            claimed_capabilities=tuple(claimed_capabilities), correlation_id=correlation_id,
            executor=lambda: self._run(descriptor=descriptor, **perform_kwargs))

    def _run(self, *, descriptor: ResourceDescriptor, **perform_kwargs):
        return self._connector.perform(descriptor, **perform_kwargs)

    def decide(self, *, agent_id: str, tenant: str, resource_id: str, operation: str,
               instance_id: Optional[str] = None, tool: Optional[str] = None,
               claimed_capabilities=(), requested_capabilities=(), context: Optional[dict] = None,
               correlation_id: Optional[str] = None) -> GovernanceDecision:
        """Return the decision WITHOUT executing — for dry-run / UI pre-checks."""
        descriptor = self._connector.descriptor(
            resource_id=resource_id, operation=operation, tool=tool,
            requested_capabilities=tuple(requested_capabilities), context=context)
        return self._guard.decide(agent_id=agent_id, tenant=tenant, descriptor=descriptor,
                                  instance_id=instance_id,
                                  claimed_capabilities=tuple(claimed_capabilities),
                                  correlation_id=correlation_id)


class HttpApiConnector(ResourceConnector):
    """Reference connector for an outbound HTTP API resource (existence/shape only).

    ``perform`` does NOT actually issue a network request in this step — it returns the *authorized*
    call plan so the surrounding system can execute it with its own credentials. Record a real
    transport (with DLP-aware egress) in Step 12.
    """

    def __init__(self, *, name: str = "http_api"):
        self.name = name

    @property
    def resource_type(self) -> ResourceType:
        return ResourceType.HTTP_API

    def descriptor(self, *, resource_id, operation, tool=None, requested_capabilities=(),
                   context=None) -> ResourceDescriptor:
        ctx = dict(context or {})
        ctx.setdefault("connector", self.name)
        return ResourceDescriptor(resource_id=resource_id, operation=operation,
                                  resource_type=ResourceType.HTTP_API.value, tool=tool,
                                  requested_capabilities=tuple(requested_capabilities),
                                  context=ctx)

    def perform(self, descriptor: ResourceDescriptor, *, method: Optional[str] = None,
                path: Optional[str] = None) -> dict:
        # NOTE: no network call is made here; Step 12 owns the egress path.
        return {"authorized": True, "connector": self.name, "resource_id": descriptor.resource_id,
                "operation": descriptor.operation, "method": method, "path": path}


class DatabaseConnector(ResourceConnector):
    """Reference connector for a database resource. :meth:`perform` returns an authorized plan.

    The database's OWN credentials/permissions still apply — this connector does not execute SQL and
    does not hold a connection. It exists to prove the enforcement shape and to carry the resource
    class through the boundary.
    """

    def __init__(self, *, name: str = "database"):
        self.name = name

    @property
    def resource_type(self) -> ResourceType:
        return ResourceType.DATABASE

    def descriptor(self, *, resource_id, operation, tool=None, requested_capabilities=(),
                   context=None) -> ResourceDescriptor:
        ctx = dict(context or {})
        ctx.setdefault("connector", self.name)
        return ResourceDescriptor(resource_id=resource_id, operation=operation,
                                  resource_type=ResourceType.DATABASE.value, tool=tool,
                                  requested_capabilities=tuple(requested_capabilities),
                                  context=ctx)

    def perform(self, descriptor: ResourceDescriptor, *, statement_kind: Optional[str] = None) -> dict:
        return {"authorized": True, "connector": self.name, "resource_id": descriptor.resource_id,
                "operation": descriptor.operation, "statement_kind": statement_kind}


class ShellConnector(ResourceConnector):
    """Reference connector for a shell/process execution surface.

    It deliberately does NOT run a command. A real shell connector must run inside a sandbox with its
    own isolation; that is explicitly out of scope here and flagged as an integration boundary.
    """

    def __init__(self, *, name: str = "shell"):
        self.name = name

    @property
    def resource_type(self) -> ResourceType:
        return ResourceType.SHELL

    def descriptor(self, *, resource_id, operation, tool=None, requested_capabilities=(),
                   context=None) -> ResourceDescriptor:
        ctx = dict(context or {})
        ctx.setdefault("connector", self.name)
        return ResourceDescriptor(resource_id=resource_id, operation=operation,
                                  resource_type=ResourceType.SHELL.value, tool=tool,
                                  requested_capabilities=tuple(requested_capabilities),
                                  context=ctx)

    def perform(self, descriptor: ResourceDescriptor, *, argv=None) -> dict:
        return {"authorized": True, "connector": self.name, "resource_id": descriptor.resource_id,
                "operation": descriptor.operation, "executed": False,
                "note": "no process is spawned; a sandboxed executor is required"}


class GuardedEgressConnector:
    """Phase 4: binds a connector to the guard AND the egress gateway.

    This is the enforcement boundary for outbound HTTP/tool calls. Its single execution path is
    ``ResourceGuard.authorize_egress_and_run``, so a call runs ONLY when BOTH the governance decision
    and the egress decision (destination policy + SSRF + DLP) are sealed ALLOWs. There is no
    ``.perform`` passthrough and no raw accessor, so an adapter holding a ``GuardedEgressConnector``
    cannot reach the network without passing both chokepoints.

    ``egress_request`` is an :class:`~agent_identity.egress.gateway.EgressRequest` describing the
    outbound destination and payload; the connector's ``perform`` receives the (possibly redacted)
    body via ``perform_kwargs`` when the caller supplies it.
    """

    def __init__(self, guard, connector: ResourceConnector):
        self._guard = guard
        self._connector = connector

    @property
    def resource_type(self) -> ResourceType:
        return self._connector.resource_type

    def __call__(self, *, agent_id: str, tenant: str, resource_id: str, operation: str,
                 egress_request, instance_id: Optional[str] = None, tool: Optional[str] = None,
                 claimed_capabilities=(), requested_capabilities=(), context: Optional[dict] = None,
                 correlation_id: Optional[str] = None, **perform_kwargs):
        descriptor = self._connector.descriptor(
            resource_id=resource_id, operation=operation, tool=tool,
            requested_capabilities=tuple(requested_capabilities), context=context)
        return self._guard.authorize_egress_and_run(
            agent_id=agent_id, tenant=tenant, descriptor=descriptor, egress_request=egress_request,
            instance_id=instance_id, claimed_capabilities=tuple(claimed_capabilities),
            correlation_id=correlation_id,
            executor=lambda: self._connector.perform(descriptor, **perform_kwargs))
