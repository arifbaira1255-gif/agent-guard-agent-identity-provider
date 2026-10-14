"""Step 11 tool registry service.

Approved tools and their capabilities. The security-relevant rules, all enforced here:

1. **A tool must be registered AND approved before it can be invoked** (when
   ``GovernanceConfig.require_tool_approval`` is on, the default). An unregistered or unapproved tool
   is denied by the guard — tools are not implicitly available.
2. **A tool's own manifest can never grant a capability.** Manifest-declared capabilities are stored
   as ``requested_capabilities`` for human review; only ``approved_capabilities`` (set by an
   administrator through :meth:`approve_tool`) influence an authorization decision. There is no code
   path that copies ``requested`` into ``approved``.
3. **Registration and approval are separate authorities.** ``tool:write`` registers; ``tool:approve``
   approves. A registrant cannot approve their own tool.
4. **Disabling a tool takes effect immediately** — the guard re-reads the record on every decision.

Registrations are validated: unsafe capability names, wildcards, unknown risk classes and oversized
manifests are rejected. Every mutation is audited.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import List, Optional

from ..core.errors import ValidationError
from ..security.rbac import (P_TOOL_ADMIN, P_TOOL_APPROVE, P_TOOL_READ, P_TOOL_WRITE, Authorizer)
from .audit import (E_TOOL_APPROVED, E_TOOL_DELETED, E_TOOL_DISABLED, E_TOOL_ENABLED,
                    E_TOOL_MANIFEST_REJECTED, E_TOOL_REGISTERED, GovernanceAudit)
from .config import GovernanceConfig
from .errors import RegistryValidationError
from .models import RiskClass, ToolRecord
from .store import GovernanceStore
from .validation import (validate_capabilities, validate_free_text, validate_id, validate_manifest,
                         validate_policy_refs)


def _manifest_checksum(manifest: dict) -> str:
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ToolRegistry:
    def __init__(self, store: GovernanceStore, config: Optional[GovernanceConfig] = None, *,
                 audit: Optional[GovernanceAudit] = None, resources=None, clock=None):
        self.store = store
        self.cfg = config or GovernanceConfig()
        self.audit = audit or GovernanceAudit(store, enabled=self.cfg.audit_enabled)
        self.resources = resources          # optional ResourceRegistry, for resource linkage checks
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ================================================================== administration
    def register_tool(self, actor, *, org_id: str, name: str, version: str, owner: str,
                      manifest: Optional[dict] = None, resource_id: Optional[str] = None,
                      policy_refs=(), description: str = "", risk: Optional[str] = None,
                      requested_capabilities=(), correlation_id: Optional[str] = None
                      ) -> ToolRecord:
        """Register a tool (unapproved). Requires ``tool:write``.

        Capabilities listed in ``manifest`` or ``requested_capabilities`` are recorded as *requested*
        only and grant nothing. ``approved_capabilities`` starts empty by design.
        """
        Authorizer.require(actor, P_TOOL_WRITE, org_id=org_id)
        n = validate_id(name, field="name")
        v = validate_free_text(version, field="version", max_len=64) or "0"
        try:
            man = validate_manifest(manifest)
        except RegistryValidationError:
            self.audit.record(E_TOOL_MANIFEST_REJECTED, actor_user_id=getattr(actor, "user_id", ""),
                              org_id=org_id, outcome="error", reason="invalid_manifest",
                              correlation_id=correlation_id)
            raise
        # capabilities the tool ASKS for: from the manifest and/or the explicit argument
        req = list(man.get("capabilities") or ())
        req += list(validate_capabilities(requested_capabilities, field="requested_capabilities"))
        req = tuple(sorted(set(validate_capabilities(req, field="requested_capabilities"))))
        rk = RiskClass.coerce(risk or man.get("risk")) or RiskClass.MEDIUM
        rid = None
        if resource_id is not None:
            rid = validate_id(resource_id, field="resource_id")
            if self.resources is not None and self.resources.resolve(rid) is None:
                # a tool may only be bound to a resource that actually exists
                raise RegistryValidationError("resource_id is not a registered resource")
        now = self._now()
        # tool_id is "name@version": a composite of two already-validated ids. It is deliberately NOT
        # passed back through validate_id, whose charset excludes "@".
        tool_id = f"{n}@{v}"
        existing = self.store.get_tool(tool_id)
        created_at = existing.created_at if existing is not None else now
        record = ToolRecord(
            tool_id=tool_id, org_id=validate_id(org_id, field="org_id"), name=n, version=v,
            owner=validate_free_text(owner, field="owner", max_len=200), risk=rk,
            requested_capabilities=req, approved_capabilities=(), resource_id=rid,
            policy_refs=validate_policy_refs(policy_refs), enabled=True, approved=False,
            description=validate_free_text(description, field="description", max_len=2048),
            manifest_checksum=_manifest_checksum(man), created_at=created_at, updated_at=now,
            created_by=getattr(actor, "user_id", "") or "")
        self.store.put_tool(record)
        self.audit.record(E_TOOL_REGISTERED, actor_user_id=record.created_by, org_id=record.org_id,
                          tool_id=tool_id, outcome="ok", correlation_id=correlation_id,
                          extra={"risk": rk.value})
        return record

    def approve_tool(self, actor, tool_id: str, *, approved_capabilities=(), resource_id=None,
                     policy_refs=None, risk: Optional[str] = None,
                     correlation_id: Optional[str] = None) -> ToolRecord:
        """Approve a tool and grant it a NARROW, explicit capability set. Requires ``tool:approve``.

        ``approved_capabilities`` must be a subset of the tool's *requested* capabilities (when it
        requested any) — an approver may narrow but not silently widen a tool's stated intent. If the
        tool requested nothing, an explicit non-empty set is still required for it to do anything.
        """
        # Permission is checked BEFORE the record is loaded, so an unauthorised caller cannot use
        # response differences to probe whether a tool exists (and never reaches the tool at all).
        Authorizer.require(actor, P_TOOL_APPROVE)
        current = self._get(tool_id)
        Authorizer.require(actor, P_TOOL_APPROVE, org_id=current.org_id)   # tenant boundary
        caps = validate_capabilities(approved_capabilities, field="approved_capabilities")
        if current.requested_capabilities:
            excess = set(caps) - set(current.requested_capabilities)
            if excess:
                raise RegistryValidationError(
                    "approved capabilities must be a subset of the requested capabilities")
        rid = current.resource_id
        if resource_id is not None:
            rid = validate_id(resource_id, field="resource_id")
            if self.resources is not None and self.resources.resolve(rid) is None:
                raise RegistryValidationError("resource_id is not a registered resource")
        refs = current.policy_refs if policy_refs is None else validate_policy_refs(policy_refs)
        rk = RiskClass.coerce(risk) if risk is not None else current.risk
        if rk is None:
            raise RegistryValidationError("unknown risk class")
        import dataclasses
        updated = dataclasses.replace(current, approved_capabilities=caps, resource_id=rid,
                                      policy_refs=refs, risk=rk, approved=True,
                                      approved_by=getattr(actor, "user_id", "") or "",
                                      updated_at=self._now())
        self.store.put_tool(updated)
        self.audit.record(E_TOOL_APPROVED, actor_user_id=getattr(actor, "user_id", ""),
                          org_id=current.org_id, tool_id=tool_id, outcome="ok",
                          correlation_id=correlation_id,
                          extra={"approved_capabilities": ",".join(caps)[:256]})
        return updated

    def set_enabled(self, actor, tool_id: str, enabled: bool, *,
                    correlation_id: Optional[str] = None) -> ToolRecord:
        Authorizer.require(actor, P_TOOL_ADMIN)
        current = self._get(tool_id)
        Authorizer.require(actor, P_TOOL_ADMIN, org_id=current.org_id)     # tenant boundary
        import dataclasses
        updated = dataclasses.replace(current, enabled=bool(enabled), updated_at=self._now())
        self.store.put_tool(updated)
        self.audit.record(E_TOOL_ENABLED if enabled else E_TOOL_DISABLED,
                          actor_user_id=getattr(actor, "user_id", ""), org_id=current.org_id,
                          tool_id=tool_id, outcome="ok", correlation_id=correlation_id)
        return updated

    def delete_tool(self, actor, tool_id: str, *, correlation_id: Optional[str] = None) -> None:
        Authorizer.require(actor, P_TOOL_ADMIN)
        current = self._get(tool_id)
        Authorizer.require(actor, P_TOOL_ADMIN, org_id=current.org_id)     # tenant boundary
        self.store.delete_tool(tool_id)
        self.audit.record(E_TOOL_DELETED, actor_user_id=getattr(actor, "user_id", ""),
                          org_id=current.org_id, tool_id=tool_id, outcome="ok",
                          correlation_id=correlation_id)

    def get_tool(self, actor, tool_id: str) -> ToolRecord:
        Authorizer.require(actor, P_TOOL_READ)
        record = self._get(tool_id)
        Authorizer.require(actor, P_TOOL_READ, org_id=record.org_id)       # tenant boundary
        return record

    def list_tools(self, actor, *, org_id: Optional[str] = None) -> List[ToolRecord]:
        if org_id is not None:
            Authorizer.require(actor, P_TOOL_READ, org_id=org_id)
        else:
            Authorizer.require(actor, P_TOOL_READ)
        if org_id is None and getattr(actor, "org_id", None) is not None \
                and not getattr(actor, "is_platform_admin", False):
            org_id = actor.org_id
        return self.store.list_tools(org_id=org_id)

    # ================================================================== internal (guard path)
    def resolve(self, tool_id: str) -> Optional[ToolRecord]:
        """Actorless lookup used by the guard. Performs NO authorization."""
        if not isinstance(tool_id, str) or not tool_id:
            return None
        return self.store.get_tool(tool_id)

    def resolve_by_name(self, name: str, org_id: str) -> Optional[ToolRecord]:
        """Resolve the newest registered version of a tool by name within a tenant."""
        if not isinstance(name, str) or not name:
            return None
        candidates = [t for t in self.store.list_tools(org_id=org_id) if t.name == name]
        if not candidates:
            return None
        return sorted(candidates, key=lambda t: (t.version, t.tool_id))[-1]

    # ------------------------------------------------------------------ helpers
    def _get(self, tool_id: str) -> ToolRecord:
        record = self.store.get_tool(tool_id)
        if record is None:
            raise ValidationError("tool is not registered")
        return record
