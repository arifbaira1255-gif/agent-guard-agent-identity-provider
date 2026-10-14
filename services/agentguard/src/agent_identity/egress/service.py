"""``EgressService`` -- the composition root for the Phase 4 egress/DLP plane.

It wires the store, the policy registry, the DLP engine, the audit log and the
:class:`~agent_identity.egress.gateway.SecureEgressGateway` into one object, and exposes the
supported entry points:

  * ``register_policy`` / ``list_policies`` / ``delete_policy`` -- tenant-scoped egress policy CRUD
    (validated; a malformed host pattern is rejected at registration).
  * ``decide`` / ``request`` -- the governed outbound decision and execution path.
  * ``metrics`` -- counters for blocked traffic, denials, DLP detections, approvals, gateway errors
    and latency, for the observability stack.

The registry is the ONLY writer of egress policy, and the gateway reads policy authoritatively from
the store on every decision -- so a policy change takes effect immediately and no stale allow can
survive it.
"""
from __future__ import annotations

import threading
import time
from typing import List, Optional, Tuple

from ..core.errors import NotFoundError, ValidationError
from ..security.ids import new_id
from .audit import (E_POLICY_DELETED, E_POLICY_DISABLED, E_POLICY_ENABLED, E_POLICY_REGISTERED,
                    E_POLICY_UPDATED, EgressAudit)
from .config import EgressConfig
from .connectors import EgressHttpConnector
from .dlp import DlpEngine
from .errors import EgressValidationError
from .gateway import EgressDecision, EgressRequest, SecureEgressGateway
from .models import (DlpAction, DlpRule, DlpSeverity, EgressOutcome, EgressPolicyRecord, Protocol,
                     RateLimitSpec)
from .policy import validate_host_pattern
from .store import EgressStore


class EgressPolicyRegistry:
    """Validated, tenant-scoped CRUD over egress policy records."""

    def __init__(self, store: EgressStore, audit: Optional[EgressAudit] = None, *, clock=None):
        self.store = store
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def register(self, *, org_id: str, name: str, host_patterns, protocols=None, ports=None,
                 action: str = "allow", priority: int = 100, rate_limit: Optional[dict] = None,
                 max_request_bytes: Optional[int] = None, max_response_bytes: Optional[int] = None,
                 timeout_ms: Optional[int] = None, allow_redirects: bool = False,
                 dlp_enabled: bool = True, description: str = "", created_by: str = "",
                 policy_id: Optional[str] = None) -> EgressPolicyRecord:
        if not org_id or not isinstance(org_id, str):
            raise EgressValidationError("org_id is required")
        if not name or not isinstance(name, str):
            raise EgressValidationError("name is required")
        if not host_patterns:
            raise EgressValidationError("at least one host pattern is required")
        patterns = tuple(validate_host_pattern(p) for p in host_patterns)
        proto_set = frozenset(_coerce_protocols(protocols))
        port_set = frozenset(_coerce_ports(ports))
        act = EgressOutcome(action.strip().upper()) if isinstance(action, str) else action
        if act not in (EgressOutcome.ALLOW, EgressOutcome.DENY, EgressOutcome.REQUIRE_APPROVAL):
            raise EgressValidationError("action must be ALLOW, DENY or REQUIRE_APPROVAL")
        rl = None
        if rate_limit is not None:
            rl = RateLimitSpec(per_second=float(rate_limit.get("per_second", 10.0)),
                               burst=int(rate_limit.get("burst", 20)))
        now = self._now()
        rec = EgressPolicyRecord(
            policy_id=policy_id or new_id("epol"), org_id=org_id, name=name,
            host_patterns=patterns, protocols=proto_set, ports=port_set, action=act,
            priority=int(priority), rate_limit=rl, max_request_bytes=max_request_bytes,
            max_response_bytes=max_response_bytes, timeout_ms=timeout_ms,
            allow_redirects=bool(allow_redirects), dlp_enabled=bool(dlp_enabled),
            description=description, enabled=True, created_at=now, updated_at=now,
            created_by=created_by)
        self.store.put_policy(rec)
        if self.audit is not None:
            self.audit.record(E_POLICY_REGISTERED, org_id=org_id, decision=act.value,
                              reason="policy_registered", policy_id=rec.policy_id,
                              actor_user_id=created_by or None,
                              extra={"host_patterns": ",".join(patterns)})
        return rec

    def update(self, policy_id: str, *, org_id: str, **changes) -> EgressPolicyRecord:
        existing = self.store.get_policy(policy_id)
        if existing is None or existing.org_id != org_id:
            raise NotFoundError("egress policy not found")
        data = existing.public_dict()
        data.update({k: v for k, v in changes.items() if v is not None})
        return self.register(
            org_id=org_id, name=data["name"], host_patterns=data["host_patterns"],
            protocols=data["protocols"], ports=data["ports"], action=data["action"],
            priority=data["priority"], rate_limit=data.get("rate_limit"),
            max_request_bytes=data.get("max_request_bytes"),
            max_response_bytes=data.get("max_response_bytes"), timeout_ms=data.get("timeout_ms"),
            allow_redirects=data.get("allow_redirects", False),
            dlp_enabled=data.get("dlp_enabled", True), description=data.get("description", ""),
            created_by=existing.created_by, policy_id=policy_id)

    def set_enabled(self, policy_id: str, *, org_id: str, enabled: bool) -> EgressPolicyRecord:
        existing = self.store.get_policy(policy_id)
        if existing is None or existing.org_id != org_id:
            raise NotFoundError("egress policy not found")
        rec = EgressPolicyRecord(**{**existing.__dict__, "enabled": bool(enabled),
                                    "updated_at": self._now()})
        self.store.put_policy(rec)
        if self.audit is not None:
            self.audit.record(E_POLICY_ENABLED if enabled else E_POLICY_DISABLED, org_id=org_id,
                              policy_id=policy_id, reason="policy_enabled" if enabled
                              else "policy_disabled")
        return rec

    def delete(self, policy_id: str, *, org_id: str) -> None:
        existing = self.store.get_policy(policy_id)
        if existing is None or existing.org_id != org_id:
            raise NotFoundError("egress policy not found")
        self.store.delete_policy(policy_id)
        if self.audit is not None:
            self.audit.record(E_POLICY_DELETED, org_id=org_id, policy_id=policy_id,
                              reason="policy_deleted")

    def list(self, *, org_id: str) -> List[EgressPolicyRecord]:
        return self.store.list_policies(org_id=org_id)

    def get(self, policy_id: str, *, org_id: str) -> EgressPolicyRecord:
        rec = self.store.get_policy(policy_id)
        if rec is None or rec.org_id != org_id:
            raise NotFoundError("egress policy not found")
        return rec

    # Aliases used by the gateway (which reads policy authoritatively on every decision).
    def list_policies(self, *, org_id: str) -> List[EgressPolicyRecord]:
        return self.store.list_policies(org_id=org_id)

    def get_policy(self, policy_id: str) -> Optional[EgressPolicyRecord]:
        return self.store.get_policy(policy_id)


class EgressService:
    """The Phase 4 composition root."""

    def __init__(self, store: EgressStore, *, config: Optional[EgressConfig] = None,
                 policy_service=None, dlp: Optional[DlpEngine] = None,
                 audit: Optional[EgressAudit] = None, transport=None, clock=None,
                 address_policy=None, rate_limiter=None):
        self.cfg = config or EgressConfig()
        self.store = store
        self.audit = audit or EgressAudit(store, enabled=self.cfg.audit_enabled, clock=clock)
        self.dlp = dlp or DlpEngine(max_inspect_bytes=self.cfg.dlp_max_inspect_bytes,
                                    max_depth=self.cfg.dlp_max_depth,
                                    inspect_encoded=self.cfg.dlp_inspect_encoded,
                                    failure_action=self.cfg.dlp_failure_action)
        self.registry = EgressPolicyRegistry(store, self.audit, clock=clock)
        self.gateway = SecureEgressGateway(
            self.registry, config=self.cfg, policy_service=policy_service, dlp=self.dlp,
            audit=self.audit, transport=transport or EgressHttpConnector(), clock=clock,
            address_policy=address_policy, rate_limiter=rate_limiter)
        self._metrics_lock = threading.Lock()
        self._metrics = {"requests": 0, "allowed": 0, "denied": 0, "approval_required": 0,
                         "indeterminate": 0, "dlp_detections": 0, "dlp_blocked": 0,
                         "ssrf_blocked": 0, "rate_limited": 0, "gateway_errors": 0,
                         "latency_ms_total": 0}

    # ------------------------------------------------------------------ policy CRUD
    def register_policy(self, **kwargs) -> EgressPolicyRecord:
        return self.registry.register(**kwargs)

    def list_policies(self, *, org_id: str) -> List[EgressPolicyRecord]:
        return self.registry.list(org_id=org_id)

    def delete_policy(self, policy_id: str, *, org_id: str) -> None:
        self.registry.delete(policy_id, org_id=org_id)

    # ------------------------------------------------------------------ decisions
    def decide(self, **kwargs) -> EgressDecision:
        d = self.gateway.decide(**kwargs)
        self._count(d)
        return d

    def request(self, **kwargs) -> dict:
        out = self.gateway.request(**kwargs)
        dec = out.get("decision") or {}
        self._count_dict(dec)
        return out

    def enforce(self, decision, executor):
        """Run ``executor`` ONLY for a sealed ALLOW (delegates to the gateway)."""
        return self.gateway.enforce(decision, executor)

    # ------------------------------------------------------------------ metrics
    def _count(self, d: EgressDecision) -> None:
        self._count_dict(d.to_dict())

    def _count_dict(self, dec: dict) -> None:
        with self._metrics_lock:
            self._metrics["requests"] += 1
            outcome = dec.get("decision")
            if outcome == EgressOutcome.ALLOW.value:
                self._metrics["allowed"] += 1
            elif outcome == EgressOutcome.DENY.value:
                self._metrics["denied"] += 1
            elif outcome == EgressOutcome.REQUIRE_APPROVAL.value:
                self._metrics["approval_required"] += 1
            elif outcome == EgressOutcome.INDETERMINATE.value:
                self._metrics["indeterminate"] += 1
            if dec.get("dlp_rule_ids"):
                self._metrics["dlp_detections"] += 1
            if dec.get("reason") == "dlp_blocked":
                self._metrics["dlp_blocked"] += 1
            if str(dec.get("reason", "")).startswith("blocked_address") or \
                    dec.get("reason") == "cloud_metadata_host":
                self._metrics["ssrf_blocked"] += 1
            if dec.get("reason") == "rate_limited":
                self._metrics["rate_limited"] += 1
            if dec.get("reason") == "egress_internal_error":
                self._metrics["gateway_errors"] += 1
            if dec.get("latency_ms") is not None:
                self._metrics["latency_ms_total"] += int(dec["latency_ms"])

    def metrics(self) -> dict:
        with self._metrics_lock:
            m = dict(self._metrics)
        reqs = m["requests"] or 1
        m["avg_latency_ms"] = round(m["latency_ms_total"] / reqs, 2)
        return m

    def health(self) -> dict:
        return {"status": "ok", "component": "egress", "environment": self.cfg.environment,
                "dlp_enabled": self.cfg.dlp_enabled, "default_action": self.cfg.default_action}


# --------------------------------------------------------------------------- coercion helpers
def _coerce_protocols(protocols) -> List[Protocol]:
    if protocols is None:
        return [Protocol.HTTPS]
    out = []
    for p in protocols:
        proto = Protocol.coerce(p)
        if proto is None:
            raise EgressValidationError(f"unknown protocol: {p!r}")
        out.append(proto)
    return out or [Protocol.HTTPS]


def _coerce_ports(ports) -> List[int]:
    if ports is None:
        return [443]
    out = []
    for p in ports:
        try:
            n = int(p)
        except (TypeError, ValueError):
            raise EgressValidationError(f"invalid port: {p!r}")
        if not (1 <= n <= 65535):
            raise EgressValidationError(f"port out of range: {n}")
        out.append(n)
    return out or [443]
