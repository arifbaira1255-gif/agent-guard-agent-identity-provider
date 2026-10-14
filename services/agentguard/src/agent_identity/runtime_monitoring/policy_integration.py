"""Phase 5 policy-engine integration (adapter boundary).

Integrates the monitoring plane with the EXISTING enforcement mechanisms without creating a second
enforcement path. Everything here is an *adapter* over interfaces the earlier phases already expose:

* **Policy re-evaluation** → ``policy.service.PolicyDecisionService.authorize(...)`` (Step 10).
* **JIT grant revocation** → ``policy.jit.JitGrantService.revoke_all_for_agent(...)`` (Step 10).
* **Approval requests** → the policy plane's approval mechanism.
* **Grant inventory** → ``policy.store.PolicyStore.list_grants(...)``.

The adapters are duck-typed (they only call documented methods) so the monitoring package keeps zero
import-time dependency on the policy package, and a deployment can inject any object that satisfies
the small protocol. When no policy service is configured, every integration reports
``available: False`` rather than pretending success.

**Non-negotiable:** no method here can ALLOW anything. The strongest action available is to ask the
authoritative engine to re-decide, or to *revoke* privilege -- i.e. the monitoring plane can only
ever tighten, never loosen.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

from .errors import ResponseActionError


@dataclass
class IntegrationResult:
    """The outcome of a call into an external enforcement mechanism."""

    available: bool
    performed: bool
    mechanism: str
    detail: str = ""
    result: Optional[dict] = None

    def to_dict(self) -> dict:
        return {"available": self.available, "performed": self.performed,
                "mechanism": self.mechanism, "detail": self.detail, "result": self.result}


class PolicyIntegration:
    """Adapter over the Step 10 policy plane. Never grants; may only re-decide, request approval or revoke."""

    def __init__(self, *, policy_service=None, jit_service=None, approval_service=None,
                 policy_store=None):
        self.policy_service = policy_service
        self.jit_service = jit_service or policy_service
        self.approval_service = approval_service
        self.policy_store = policy_store or _store_of(policy_service)

    @property
    def available(self) -> bool:
        return self.policy_service is not None

    # ------------------------------------------------------------------ re-evaluation
    def reevaluate(self, *, agent_id: str, tenant: str, action: str, resource: str,
                   context: Optional[dict] = None, correlation_id: Optional[str] = None
                   ) -> IntegrationResult:
        """Ask the authoritative policy engine to re-decide a request. Delegates; does not decide."""
        if self.policy_service is None:
            return IntegrationResult(available=False, performed=False,
                                     mechanism="policy_engine",
                                     detail="no policy service configured")
        try:
            decision = self.policy_service.authorize(
                agent_id=agent_id, tenant=tenant, action=action, resource=resource,
                context=context or {}, correlation_id=correlation_id)
        except TypeError:
            # Older/newer signature: fall back to the minimal documented call.
            decision = self.policy_service.authorize(agent_id=agent_id, tenant=tenant, action=action,
                                                    resource=resource)
        except Exception as e:  # noqa: BLE001 - surface as a failed integration, never crash the plane
            return IntegrationResult(available=True, performed=False, mechanism="policy_engine",
                                     detail=f"policy re-evaluation failed: {type(e).__name__}")
        payload = decision.to_dict() if hasattr(decision, "to_dict") else (
            dict(decision) if isinstance(decision, dict) else {"raw": str(decision)})
        return IntegrationResult(available=True, performed=True, mechanism="policy_engine",
                                 detail="re-evaluation request submitted to the authoritative engine",
                                 result=payload)

    # ------------------------------------------------------------------ JIT revocation
    def revoke_grants_for_agent(self, *, org_id: str, agent_id: str, reason: str,
                                revoked_by: str) -> IntegrationResult:
        """Revoke every live JIT grant for an agent -- a TIGHTENING action delegated to Step 10."""
        if self.jit_service is None or not hasattr(self.jit_service, "revoke_all_for_agent"):
            return IntegrationResult(available=False, performed=False, mechanism="jit_grant_service",
                                     detail="no JIT grant service configured")
        try:
            revoked = self.jit_service.revoke_all_for_agent(org_id=org_id, agent_id=agent_id,
                                                            reason=reason, revoked_by=revoked_by)
        except Exception as e:  # noqa: BLE001
            return IntegrationResult(available=True, performed=False, mechanism="jit_grant_service",
                                     detail=f"revocation failed: {type(e).__name__}")
        count = len(revoked) if isinstance(revoked, (list, tuple)) else revoked
        return IntegrationResult(available=True, performed=True, mechanism="jit_grant_service",
                                 detail="JIT grants revoked via the authoritative grant service",
                                 result={"revoked": count})

    def list_live_grants(self, *, org_id: str, agent_id: str) -> List[dict]:
        if self.policy_store is None or not hasattr(self.policy_store, "list_grants"):
            return []
        try:
            grants = self.policy_store.list_grants(org_id=org_id, agent_id=agent_id,
                                                   active_only=True)
        except Exception:  # noqa: BLE001
            return []
        out = []
        for g in grants or []:
            out.append(g.public_dict() if hasattr(g, "public_dict") else
                       (dict(g) if isinstance(g, dict) else {"raw": str(g)}))
        return out

    # ------------------------------------------------------------------ approval
    def request_approval(self, *, org_id: str, agent_id: str, action: str, resource: str,
                         reason: str) -> IntegrationResult:
        """Raise a human-approval request via the policy plane (delegated, not invented)."""
        if self.approval_service is None or not hasattr(self.approval_service, "request"):
            return IntegrationResult(available=False, performed=False, mechanism="approval_service",
                                     detail="no approval service configured")
        try:
            approval = self.approval_service.request(org_id=org_id, agent_id=agent_id,
                                                     action=action, resource=resource,
                                                     reason=reason)
        except TypeError:
            approval = self.approval_service.request(org_id=org_id, agent_id=agent_id,
                                                     action=action, resource=resource)
        except Exception as e:  # noqa: BLE001
            return IntegrationResult(available=True, performed=False, mechanism="approval_service",
                                     detail=f"approval request failed: {type(e).__name__}")
        payload = approval.public_dict() if hasattr(approval, "public_dict") else (
            dict(approval) if isinstance(approval, dict) else {"raw": str(approval)})
        return IntegrationResult(available=True, performed=True, mechanism="approval_service",
                                 detail="approval request raised in the policy plane",
                                 result=payload)

    # ------------------------------------------------------------------ capability/scope lookup
    def declared_capabilities(self, *, org_id: str, agent_id: str) -> Optional[Sequence[str]]:
        """Read an agent's declared capabilities from the identity registry when reachable.

        Returns ``None`` when the source is unavailable -- callers treat that as
        ``insufficient_evidence``, never as an empty (permissive or restrictive) set.
        """
        getter = getattr(self.policy_service, "declared_capabilities", None)
        if getter is None:
            return None
        try:
            caps = getter(org_id=org_id, agent_id=agent_id)
        except Exception:  # noqa: BLE001
            return None
        return tuple(caps) if caps is not None else None


def _store_of(policy_service):
    return getattr(policy_service, "store", None) if policy_service is not None else None
