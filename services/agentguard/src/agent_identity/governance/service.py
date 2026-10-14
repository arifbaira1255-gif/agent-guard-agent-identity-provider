"""Step 11 ``GovernanceService`` — composition root and the anti-bypass execution entry point.

This is the object an integration holds. It wires the registry, tool registry and guard together and
exposes:

* **administration** — resource/tool lifecycle (RBAC-checked inside the registries);
* **``execute(...)``** — THE supported way to run a governed operation. It authorizes via the guard and
  runs the connector ONLY on a sealed ALLOW. Adapters and tool shims MUST call this rather than a
  connector directly. A direct call to a connector's ``perform`` is a bypass, and the service does not
  hand out raw connectors.

Cleanup hooks (``register_cleanup``) let other components (Step 7 health/coordination, caches) be
disposed together, mirroring the existing services' lifecycle shape.
"""
from __future__ import annotations

from typing import Callable, List, Optional

from ..core.errors import ValidationError
from .audit import GovernanceAudit
from .config import GovernanceConfig
from .connectors import GuardedConnector, ResourceConnector
from .guard import ResourceGuard
from .models import GovernanceDecision, ResourceDescriptor, ResourceType
from .registry import ResourceRegistry
from .store import GovernanceStore
from .tool_registry import ToolRegistry


class GovernanceService:
    def __init__(self, store: GovernanceStore, policy_service, *, config: Optional[GovernanceConfig] = None,
                 audit_logger=None, clock=None, egress=None):
        self.store = store
        self.policy = policy_service
        self.cfg = config or GovernanceConfig()
        self.audit = GovernanceAudit(store, logger=audit_logger, enabled=self.cfg.audit_enabled,
                                     clock=clock)
        self.resources = ResourceRegistry(store, self.cfg, audit=self.audit, clock=clock)
        self.tools = ToolRegistry(store, self.cfg, audit=self.audit, resources=self.resources,
                                  clock=clock)
        self.guard = ResourceGuard(policy_service, self.resources, self.tools, config=self.cfg,
                                   audit=self.audit, clock=clock, egress=egress)
        self._connectors: dict[str, GuardedConnector] = {}
        self._cleanups: List[Callable[[], None]] = []

    # ================================================================== connectors
    def register_connector(self, connector: ResourceConnector, *, name: Optional[str] = None
                           ) -> GuardedConnector:
        """Wrap a connector in the guard and return the GUARDED handle (never the raw connector)."""
        if not isinstance(connector, ResourceConnector):
            raise ValidationError("connector must be a ResourceConnector")
        guarded = GuardedConnector(self.guard, connector)
        key = name or getattr(connector, "name", None) or connector.resource_type.value
        self._connectors[key] = guarded
        return guarded

    def connector(self, name: str) -> GuardedConnector:
        guarded = self._connectors.get(name)
        if guarded is None:
            raise ValidationError("unknown connector")
        return guarded

    # ================================================================== execution
    def execute(self, *, agent_id: str, tenant: str, resource_id: str, operation: str,
                instance_id: Optional[str] = None, tool: Optional[str] = None,
                claimed_capabilities=(), requested_capabilities=(), context: Optional[dict] = None,
                correlation_id: Optional[str] = None, connector: Optional[str] = None,
                **perform_kwargs):
        """THE supported execution path. Authorize then run; never run on a non-ALLOW.

        ``connector`` selects a registered connector; when omitted the guard's decision is still made
        and the executor is only run on a sealed ALLOW (the caller supplies the work through
        ``perform_kwargs['executor']`` when no connector is used).
        """
        if connector is not None:
            return self.connector(connector)(
                agent_id=agent_id, tenant=tenant, resource_id=resource_id, operation=operation,
                instance_id=instance_id, tool=tool, claimed_capabilities=claimed_capabilities,
                requested_capabilities=requested_capabilities, context=context,
                correlation_id=correlation_id, **perform_kwargs)
        executor = perform_kwargs.pop("executor", None)
        if not callable(executor):
            raise ValidationError("either a registered connector or an 'executor' callable is required")
        descriptor = ResourceDescriptor(resource_id=resource_id, operation=operation, tool=tool,
                                        requested_capabilities=tuple(requested_capabilities),
                                        context=context)
        return self.guard.authorize_and_run(
            agent_id=agent_id, tenant=tenant, descriptor=descriptor, instance_id=instance_id,
            claimed_capabilities=tuple(claimed_capabilities), correlation_id=correlation_id,
            executor=executor)

    def decide(self, *, agent_id: str, tenant: str, resource_id: str, operation: str,
               instance_id: Optional[str] = None, tool: Optional[str] = None,
               claimed_capabilities=(), requested_capabilities=(), context: Optional[dict] = None,
               resource_type: Optional[str] = None, correlation_id: Optional[str] = None,
               ) -> GovernanceDecision:
        """Dry-run: return the governance decision without executing anything."""
        descriptor = ResourceDescriptor(resource_id=resource_id, operation=operation,
                                        resource_type=resource_type, tool=tool,
                                        requested_capabilities=tuple(requested_capabilities),
                                        context=context)
        return self.guard.decide(agent_id=agent_id, tenant=tenant, descriptor=descriptor,
                                 instance_id=instance_id,
                                 claimed_capabilities=tuple(claimed_capabilities),
                                 correlation_id=correlation_id)

    # ================================================================== observability
    def list_audit(self, *, org_id: Optional[str] = None, resource_id: Optional[str] = None,
                   limit: int = 100) -> List[dict]:
        return self.store.list_audit(org_id=org_id, resource_id=resource_id, limit=limit)

    # ================================================================== lifecycle
    def register_cleanup(self, fn: Callable[[], None]) -> None:
        self._cleanups.append(fn)

    def close(self) -> None:
        for fn in reversed(self._cleanups):
            try:
                fn()
            except Exception:                     # noqa: BLE001 - best effort teardown
                pass
        self._cleanups.clear()
