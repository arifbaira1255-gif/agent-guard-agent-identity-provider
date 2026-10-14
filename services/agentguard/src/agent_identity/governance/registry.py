"""Step 11 resource registry service.

The registry is the AUTHORITATIVE source of a resource's type, owner, sensitivity, permitted
operations and applicable policies. It is deliberately small and RBAC-guarded:

* :meth:`register_resource` / :meth:`update_resource` / :meth:`delete_resource` require
  ``resource:write`` (and platform-wide administration of another tenant requires a platform admin —
  enforced by ``Authorizer.require(..., org_id=...)``).
* :meth:`resolve` is the *internal*, actorless lookup the guard uses on the hot path. It returns raw
  registry state; the caller (``ResourceGuard``) is responsible for the tenant boundary check and the
  actual authorization decision. Registry metadata is not secret, and resolution alone never grants
  anything.

Every mutation is audited. Nothing here trusts a caller-supplied *type*: the type is validated
against the closed :class:`ResourceType` vocabulary, and an unknown type is rejected at registration
rather than silently stored.
"""
from __future__ import annotations

import time
from typing import List, Optional

from ..core.errors import ForbiddenError, NotFoundError, ValidationError
from ..security.rbac import (P_RESOURCE_ADMIN, P_RESOURCE_READ, P_RESOURCE_WRITE, Authorizer)
from .audit import (E_RESOURCE_DELETED, E_RESOURCE_DISABLED, E_RESOURCE_ENABLED,
                    E_RESOURCE_REGISTERED, E_RESOURCE_UPDATED, GovernanceAudit)
from .classifier import ResourceClassifier
from .config import GovernanceConfig
from .errors import RegistryValidationError, ResourceNotFoundError
from .models import ResourceRecord, ResourceType, Sensitivity
from .store import GovernanceStore
from .validation import (validate_free_text, validate_id, validate_metadata, validate_operations,
                         validate_policy_refs)


class ResourceRegistry:
    def __init__(self, store: GovernanceStore, config: Optional[GovernanceConfig] = None, *,
                 audit: Optional[GovernanceAudit] = None, clock=None):
        self.store = store
        self.cfg = config or GovernanceConfig()
        self.audit = audit or GovernanceAudit(store, enabled=self.cfg.audit_enabled)
        self._clock = clock
        self.classifier = ResourceClassifier()

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ================================================================== administration
    def register_resource(self, actor, *, resource_id: str, org_id: str, resource_type: str,
                          name: str, owner: str, sensitivity: Optional[str] = None,
                          permitted_operations=(), policy_refs=(), description: str = "",
                          metadata: Optional[dict] = None, enabled: bool = True,
                          correlation_id: Optional[str] = None) -> ResourceRecord:
        """Register (or replace) a governed resource. Requires ``resource:write``."""
        Authorizer.require(actor, P_RESOURCE_WRITE, org_id=org_id)
        rid = validate_id(resource_id, field="resource_id")
        rtype = ResourceType.coerce(resource_type)
        if rtype is None:
            # an unknown type is rejected outright: it must never become "governed but unclassified"
            raise RegistryValidationError("unknown resource_type")
        sens = Sensitivity.coerce(sensitivity) if sensitivity is not None else None
        if sensitivity is not None and sens is None:
            raise RegistryValidationError("unknown sensitivity")
        if sens is None:
            sens = self.classifier.default_sensitivity(rtype)
        ops = validate_operations(permitted_operations)
        if len(ops) > self.cfg.max_permitted_operations:
            raise RegistryValidationError("too many permitted operations")
        refs = validate_policy_refs(policy_refs)
        now = self._now()
        existing = self.store.get_resource(rid)
        created_at = existing.created_at if existing is not None else now
        record = ResourceRecord(
            resource_id=rid, org_id=validate_id(org_id, field="org_id"), resource_type=rtype,
            name=validate_id(name, field="name"), owner=validate_free_text(owner, field="owner",
                                                                         max_len=200),
            sensitivity=sens, permitted_operations=ops, policy_refs=refs, enabled=bool(enabled),
            description=validate_free_text(description, field="description"),
            metadata=validate_metadata(metadata), created_at=created_at, updated_at=now,
            created_by=getattr(actor, "user_id", "") or "")
        self.store.put_resource(record)
        (self.audit.record(E_RESOURCE_UPDATED if existing else E_RESOURCE_REGISTERED,
                           actor_user_id=record.created_by, org_id=record.org_id,
                           resource_id=rid, resource_type=rtype.value, outcome="ok",
                           correlation_id=correlation_id))
        return record

    def update_resource(self, actor, resource_id: str, *, permitted_operations=None,
                        sensitivity: Optional[str] = None, policy_refs=None, description=None,
                        metadata=None, owner: Optional[str] = None,
                        correlation_id: Optional[str] = None) -> ResourceRecord:
        """Update mutable fields. Type and tenant are IMMUTABLE (changing them would re-home a
        resource's governance); re-register under a new id instead."""
        # Permission first (no existence leak to unauthorised callers), then the tenant boundary.
        Authorizer.require(actor, P_RESOURCE_WRITE)
        current = self._get(resource_id)
        Authorizer.require(actor, P_RESOURCE_WRITE, org_id=current.org_id)
        import dataclasses
        sens = current.sensitivity
        if sensitivity is not None:
            parsed = Sensitivity.coerce(sensitivity)
            if parsed is None:
                raise RegistryValidationError("unknown sensitivity")
            sens = parsed
        ops = current.permitted_operations if permitted_operations is None \
            else validate_operations(permitted_operations)
        refs = current.policy_refs if policy_refs is None else validate_policy_refs(policy_refs)
        updated = dataclasses.replace(
            current, permitted_operations=ops, sensitivity=sens, policy_refs=refs,
            description=(validate_free_text(description, field="description")
                         if description is not None else current.description),
            metadata=(validate_metadata(metadata) if metadata is not None else current.metadata),
            owner=(validate_free_text(owner, field="owner", max_len=200)
                   if owner is not None else current.owner),
            updated_at=self._now())
        self.store.put_resource(updated)
        self.audit.record(E_RESOURCE_UPDATED, actor_user_id=getattr(actor, "user_id", ""),
                          org_id=current.org_id, resource_id=resource_id, outcome="ok",
                          correlation_id=correlation_id)
        return updated

    def set_enabled(self, actor, resource_id: str, enabled: bool, *,
                    correlation_id: Optional[str] = None) -> ResourceRecord:
        Authorizer.require(actor, P_RESOURCE_ADMIN)
        current = self._get(resource_id)
        Authorizer.require(actor, P_RESOURCE_ADMIN, org_id=current.org_id)
        import dataclasses
        updated = dataclasses.replace(current, enabled=bool(enabled), updated_at=self._now())
        self.store.put_resource(updated)
        self.audit.record(E_RESOURCE_ENABLED if enabled else E_RESOURCE_DISABLED,
                          actor_user_id=getattr(actor, "user_id", ""), org_id=current.org_id,
                          resource_id=resource_id, outcome="ok", correlation_id=correlation_id)
        return updated

    def delete_resource(self, actor, resource_id: str, *,
                        correlation_id: Optional[str] = None) -> None:
        Authorizer.require(actor, P_RESOURCE_ADMIN)
        current = self._get(resource_id)
        Authorizer.require(actor, P_RESOURCE_ADMIN, org_id=current.org_id)
        self.store.delete_resource(resource_id)
        self.audit.record(E_RESOURCE_DELETED, actor_user_id=getattr(actor, "user_id", ""),
                          org_id=current.org_id, resource_id=resource_id, outcome="ok",
                          correlation_id=correlation_id)

    def list_resources(self, actor, *, org_id: Optional[str] = None) -> List[ResourceRecord]:
        if org_id is not None:
            Authorizer.require(actor, P_RESOURCE_READ, org_id=org_id)
        else:
            Authorizer.require(actor, P_RESOURCE_READ)
        if org_id is None and getattr(actor, "org_id", None) is not None \
                and not getattr(actor, "is_platform_admin", False):
            org_id = actor.org_id
        return self.store.list_resources(org_id=org_id)

    def get_resource(self, actor, resource_id: str) -> ResourceRecord:
        Authorizer.require(actor, P_RESOURCE_READ)
        record = self._get(resource_id)
        Authorizer.require(actor, P_RESOURCE_READ, org_id=record.org_id)
        return record

    # ================================================================== internal (guard path)
    def resolve(self, resource_id: str) -> Optional[ResourceRecord]:
        """Actorless resolution used by the guard. Returns the raw record or None.

        This performs NO authorization: ``ResourceGuard`` must apply the tenant boundary and the
        policy decision. Resolution alone never permits anything.
        """
        if not isinstance(resource_id, str) or not resource_id:
            return None
        return self.store.get_resource(resource_id)

    # ------------------------------------------------------------------ helpers
    def _get(self, resource_id: str) -> ResourceRecord:
        record = self.store.get_resource(resource_id)
        if record is None:
            raise ResourceNotFoundError("resource is not registered")
        return record
