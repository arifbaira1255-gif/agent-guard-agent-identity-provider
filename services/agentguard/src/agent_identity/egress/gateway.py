"""``SecureEgressGateway`` -- the SINGLE outbound enforcement chokepoint.

Every governed outbound request passes through :meth:`SecureEgressGateway.decide` before it may
leave, and the protected transport only ever runs through :meth:`SecureEgressGateway.enforce` (or
:meth:`SecureEgressGateway.request`). There is no other supported execution path.

The decision pipeline (fail closed at every step)
-------------------------------------------------
1. **Validate** the request (tenant, agent, URL, method, body size). Malformed input -> DENY.
2. **Parse** the URL into scheme/host/port. A non-HTTP(S) scheme is DENY.
3. **Rate limit** the tenant+agent (bounded token bucket). Exhausted -> DENY (rate_limited).
4. **SSRF address validation** -- resolve the host ONCE, classify every address, and deny if ANY
   address is in a blocked class (private/loopback/link-local/cloud-metadata/CGNAT/multicast/
   reserved/unspecified/unknown). The validated address set is pinned for the connection, which is
   the DNS-rebinding defence.
5. **Destination policy** -- host/protocol/port match against the tenant's egress rules. No match ->
   the configured default (deny or require_approval). An explicit DENY wins.
6. **DLP** -- inspect the outbound payload. block / require_approval / redact / allow. An inspection
   failure (oversized/undecodable) is INDETERMINATE and the configured failure action applies.
7. **Policy engine** (Step 10, optional) -- consulted as an additional leg; it can only TIGHTEN the
   outcome, never loosen it.
8. **Combine** -- DENY > INDETERMINATE > REQUIRE_APPROVAL > ALLOW.
9. **Audit** every outcome (agent, tenant, destination, operation, decision, policy version, DLP
   rule ids, resolved address class, correlation id).
10. **Seal** an ALLOW. :meth:`enforce` accepts only a sealed ALLOW minted by this process; the seal
    is single-use and short-lived, so a client cannot forge or replay a decision.

Redirects are handled by the gateway itself (never by the transport): each hop is re-validated
through the SAME address + policy pipeline, so a redirect to a private address or a non-allowlisted
host is denied. Redirects are off by default and must be opted into per policy rule.
"""
from __future__ import annotations

import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple, TypeVar

from ..core.errors import ForbiddenError
from ..security.ids import new_id
from .addresses import AddressPolicy, AddressVerdict
from .audit import (E_DLP_APPROVAL, E_DLP_BLOCKED, E_DLP_CLEAN, E_DLP_INDETERMINATE, E_DLP_REDACTED,
                    E_GATEWAY_ERROR, E_RATE_LIMITED, E_REDIRECT_BLOCKED, E_REQUEST_ALLOWED,
                    E_REQUEST_APPROVAL, E_REQUEST_DENIED, E_REQUEST_INDETERMINATE, E_SSRF_BLOCKED,
                    EgressAudit)
from .config import EgressConfig
from .dlp import DlpEngine
from .errors import EgressValidationError
from .models import (DlpOutcome, EgressOutcome, EgressPolicyRecord, Protocol, RateLimitSpec)
from .policy import DestinationPolicy, PolicyVerdict
from .ratelimit import RateLimiter

T = TypeVar("T")

#: Schemes the HTTP egress gateway will carry. Anything else is denied.
_ALLOWED_SCHEMES = {"http": Protocol.HTTP, "https": Protocol.HTTPS}
_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAX_URL_LEN = 4096


# --------------------------------------------------------------------------- request / decision
@dataclass(frozen=True)
class EgressRequest:
    """A request to make an outbound call.

    Everything here is *claimed* by the caller and is therefore UNTRUSTED. The gateway resolves the
    authoritative policy from the tenant's registry; the request only says *where* and *what*.
    """

    url: str
    method: str = "GET"
    headers: Optional[dict] = None
    body: Optional[object] = None
    resource_id: Optional[str] = None
    operation: Optional[str] = None
    context: Optional[dict] = None

    def host_port(self) -> Tuple[str, int, str]:
        """Return ``(host, port, scheme)``. Raises on a malformed URL."""
        if not isinstance(self.url, str) or not self.url.strip():
            raise EgressValidationError("url is required")
        if len(self.url) > _MAX_URL_LEN:
            raise EgressValidationError("url is too long")
        parsed = urllib.parse.urlsplit(self.url.strip())
        scheme = (parsed.scheme or "").lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise EgressValidationError("unsupported url scheme")
        host = parsed.hostname
        if not host:
            raise EgressValidationError("url has no host")
        try:
            port = parsed.port
        except ValueError:
            raise EgressValidationError("url has an invalid port")
        if port is None:
            port = _DEFAULT_PORTS[scheme]
        return host, int(port), scheme


@dataclass(frozen=True)
class EgressDecision:
    """The gateway's decision. ``allowed`` is True ONLY for a sealed ALLOW."""

    outcome: EgressOutcome
    reason: str = ""
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    destination: Optional[str] = None
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    dlp_outcome: Optional[str] = None
    dlp_rule_ids: Tuple[str, ...] = ()
    dlp_severity: Optional[str] = None
    redacted_body: Optional[object] = None
    resolved_ips: Tuple[str, ...] = ()
    address_class: Optional[str] = None
    correlation_id: Optional[str] = None
    decision_id: Optional[str] = None
    seal: Optional[str] = None
    latency_ms: Optional[int] = None

    @property
    def allowed(self) -> bool:
        return self.outcome is EgressOutcome.ALLOW and self.seal is not None

    def to_dict(self) -> dict:
        out = {"allowed": self.allowed, "decision": self.outcome.value, "reason": self.reason,
               "host": self.host, "port": self.port, "protocol": self.protocol,
               "destination": self.destination}
        for k in ("policy_id", "policy_version", "dlp_outcome", "dlp_severity", "address_class",
                  "decision_id", "correlation_id", "latency_ms"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v
        if self.dlp_rule_ids:
            out["dlp_rule_ids"] = list(self.dlp_rule_ids)
        if self.resolved_ips:
            out["resolved_ips"] = list(self.resolved_ips)
        return out

    @classmethod
    def allow(cls, reason: str = "allow", **kw) -> "EgressDecision":
        return cls(EgressOutcome.ALLOW, reason, **kw)

    @classmethod
    def deny(cls, reason: str = "deny", **kw) -> "EgressDecision":
        return cls(EgressOutcome.DENY, reason, **kw)

    @classmethod
    def require_approval(cls, reason: str = "approval_required", **kw) -> "EgressDecision":
        return cls(EgressOutcome.REQUIRE_APPROVAL, reason, **kw)

    @classmethod
    def indeterminate(cls, reason: str = "indeterminate", **kw) -> "EgressDecision":
        return cls(EgressOutcome.INDETERMINATE, reason, **kw)


# --------------------------------------------------------------------------- seal ledger
class _SealLedger:
    """A bounded, single-use ledger of decision seals (mirrors the Step 11 governance seal).

    A seal proves a decision was produced by THIS server process and has not yet been consumed. It is
    intentionally not a signed token: forging one would require code execution inside the trusted
    process, at which point no in-process control is meaningful. The property that matters is that an
    SDK, tool adapter, or remote caller CANNOT fabricate or replay one.
    """

    def __init__(self, *, max_entries: int, ttl_s: float):
        self._max = max(1, int(max_entries))
        self._ttl = float(ttl_s)
        self._entries: dict = {}
        self._lock = threading.Lock()

    def mint(self) -> str:
        token = new_id("eseal")
        now = time.time()
        with self._lock:
            self._entries[token] = now + self._ttl
            if len(self._entries) > self._max:
                self._evict(now)
        return token

    def consume(self, token: Optional[str]) -> bool:
        if not token or not isinstance(token, str):
            return False
        now = time.time()
        with self._lock:
            exp = self._entries.pop(token, None)
            if exp is None or exp < now:
                return False
            return True

    def _evict(self, now: float) -> None:
        for k in [k for k, exp in self._entries.items() if exp < now]:
            self._entries.pop(k, None)
        over = len(self._entries) - self._max
        if over > 0:
            for k in list(self._entries.keys())[:over]:
                self._entries.pop(k, None)


class _BoundedGate:
    """A bounded concurrency gate. Excess callers wait up to the timeout, then fail closed."""

    def __init__(self, limit: int):
        self._sem = threading.BoundedSemaphore(max(1, int(limit)))

    def acquire(self, timeout_s: float) -> bool:
        return self._sem.acquire(timeout=timeout_s)

    def release(self) -> None:
        try:
            self._sem.release()
        except ValueError:  # pragma: no cover - defensive
            pass


# --------------------------------------------------------------------------- gateway
class SecureEgressGateway:
    def __init__(self, policies, *, config: Optional[EgressConfig] = None,
                 policy_service=None, dlp: Optional[DlpEngine] = None,
                 audit: Optional[EgressAudit] = None, address_policy: Optional[AddressPolicy] = None,
                 rate_limiter: Optional[RateLimiter] = None, transport=None, clock=None,
                 seal_ledger=None):
        self.policies = policies
        self.cfg = config or EgressConfig()
        self.policy_service = policy_service
        self.dlp = dlp if dlp is not None else DlpEngine(
            max_inspect_bytes=self.cfg.dlp_max_inspect_bytes, max_depth=self.cfg.dlp_max_depth,
            inspect_encoded=self.cfg.dlp_inspect_encoded, failure_action=self.cfg.dlp_failure_action)
        self.audit = audit or EgressAudit(
            policies.store if policies is not None else None, enabled=self.cfg.audit_enabled)
        self.addresses = address_policy or AddressPolicy(validate_dns=self.cfg.validate_dns)
        self.destination_policy = DestinationPolicy(default_action=self.cfg.default_action)
        self.rate_limiter = rate_limiter or RateLimiter(clock=clock)
        self.transport = transport
        self._clock = clock
        self._gate = _BoundedGate(self.cfg.max_concurrent_requests)
        self._seals = seal_ledger or _SealLedger(max_entries=self.cfg.seal_max_entries,
                                                 ttl_s=self.cfg.seal_ttl_s)

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ================================================================== decide
    def decide(self, *, agent_id: str, tenant: str, request: EgressRequest,
               instance_id: Optional[str] = None, claimed_capabilities=(),
               environment: str = "development", credential_status: str = "valid",
               correlation_id: Optional[str] = None) -> EgressDecision:
        """Resolve, then decide. Never raises for a plain denial; always returns a decision."""
        started = time.perf_counter()
        try:
            decision = self._decide(agent_id=agent_id, tenant=tenant, request=request,
                                    instance_id=instance_id,
                                    claimed_capabilities=claimed_capabilities,
                                    environment=environment, credential_status=credential_status,
                                    correlation_id=correlation_id)
        except EgressValidationError as exc:
            decision = EgressDecision.deny(f"malformed_request:{exc.code}",
                                           correlation_id=correlation_id)
        except Exception:  # noqa: BLE001 - ANY unexpected error fails closed
            self._audit(E_GATEWAY_ERROR, org_id=tenant, agent_id=agent_id, outcome="error",
                        reason="egress_internal_error", correlation_id=correlation_id)
            decision = EgressDecision.indeterminate("egress_internal_error",
                                                    correlation_id=correlation_id)
        latency = int((time.perf_counter() - started) * 1000)
        return EgressDecision(**{**decision.__dict__, "latency_ms": latency})

    def _decide(self, *, agent_id, tenant, request, instance_id, claimed_capabilities, environment,
                credential_status, correlation_id) -> EgressDecision:
        # ---- 1. validate ----------------------------------------------------------------
        if not isinstance(tenant, str) or not tenant.strip():
            return EgressDecision.deny("missing_tenant", correlation_id=correlation_id)
        if not isinstance(agent_id, str) or not agent_id.strip():
            return EgressDecision.deny("missing_agent_id", correlation_id=correlation_id)
        if not isinstance(request, EgressRequest):
            return EgressDecision.deny("missing_egress_request", correlation_id=correlation_id)
        method = (request.method or "GET").strip().upper()
        if method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            return EgressDecision.deny("unsupported_method", correlation_id=correlation_id)
        try:
            host, port, scheme = request.host_port()
        except EgressValidationError as exc:
            return EgressDecision.deny(f"malformed_url:{exc.code}", correlation_id=correlation_id)
        protocol = _ALLOWED_SCHEMES[scheme]
        destination = f"{scheme}://{host}:{port}"

        # ---- 2. request size ------------------------------------------------------------
        body_bytes = _body_size(request.body)
        if body_bytes > self.cfg.max_request_bytes:
            return self._finalize(EgressDecision.deny(
                "request_too_large", host=host, port=port, protocol=protocol.value,
                destination=destination, correlation_id=correlation_id),
                org_id=tenant, agent_id=agent_id, instance_id=instance_id,
                correlation_id=correlation_id, audit=True)

        # ---- 3. rate limit --------------------------------------------------------------
        rl = self._rate_limit_for(tenant, host, port, protocol)
        allowed, retry_after = self.rate_limiter.allow(
            f"{tenant}|{agent_id}|egress", per_second=rl.per_second, burst=rl.burst)
        if not allowed:
            self._audit(E_RATE_LIMITED, org_id=tenant, agent_id=agent_id, instance_id=instance_id,
                        destination=destination, host=host, port=port, protocol=protocol.value,
                        decision=EgressOutcome.DENY.value, reason="rate_limited", outcome="denied",
                        correlation_id=correlation_id, extra={"retry_after_s": round(retry_after, 3)})
            return EgressDecision.deny("rate_limited", host=host, port=port,
                                       protocol=protocol.value, destination=destination,
                                       correlation_id=correlation_id)

        # ---- 4. SSRF address validation -------------------------------------------------
        addresses, verdicts, ssrf_reason = self.addresses.resolve_and_validate(host)
        if ssrf_reason:
            self._audit(E_SSRF_BLOCKED, org_id=tenant, agent_id=agent_id, instance_id=instance_id,
                        destination=destination, host=host, port=port, protocol=protocol.value,
                        decision=EgressOutcome.DENY.value, reason=ssrf_reason, outcome="denied",
                        resolved_ips=tuple(addresses), address_class=_first_class(verdicts),
                        correlation_id=correlation_id)
            return EgressDecision.deny(ssrf_reason, host=host, port=port, protocol=protocol.value,
                                       destination=destination, resolved_ips=tuple(addresses),
                                       address_class=_first_class(verdicts),
                                       correlation_id=correlation_id)

        # ---- 5. destination policy ------------------------------------------------------
        policies = self.policies.list_policies(org_id=tenant) if self.policies is not None else []
        verdict: PolicyVerdict = self.destination_policy.evaluate(
            host=host, protocol=protocol, port=port, policies=policies)
        if verdict.action is EgressOutcome.DENY:
            return self._finalize(EgressDecision.deny(
                verdict.reason, host=host, port=port, protocol=protocol.value,
                destination=destination, policy_id=(verdict.policy.policy_id if verdict.policy else None),
                resolved_ips=tuple(addresses), address_class=_first_class(verdicts),
                correlation_id=correlation_id), org_id=tenant, agent_id=agent_id,
                instance_id=instance_id, correlation_id=correlation_id, audit=True)

        matched_policy: Optional[EgressPolicyRecord] = verdict.policy
        outcome = verdict.action
        reason = verdict.reason

        # ---- 6. DLP ---------------------------------------------------------------------
        dlp_outcome = None
        dlp_rule_ids: Tuple[str, ...] = ()
        dlp_severity = None
        redacted_body = None
        dlp_enabled = self.cfg.dlp_enabled and (matched_policy.dlp_enabled if matched_policy else True)
        if dlp_enabled and request.body is not None:
            result = self.dlp.inspect(request.body)
            dlp_outcome = result.outcome.value
            dlp_rule_ids = result.rule_ids
            dlp_severity = _max_severity(result.findings)
            if result.outcome is DlpOutcome.BLOCK:
                self._audit(E_DLP_BLOCKED, org_id=tenant, agent_id=agent_id, instance_id=instance_id,
                            destination=destination, host=host, port=port, protocol=protocol.value,
                            decision=EgressOutcome.DENY.value, reason=result.reason, outcome="denied",
                            dlp_rule_ids=dlp_rule_ids, dlp_severity=dlp_severity,
                            correlation_id=correlation_id)
                return EgressDecision.deny("dlp_blocked", host=host, port=port,
                                           protocol=protocol.value, destination=destination,
                                           dlp_outcome=dlp_outcome, dlp_rule_ids=dlp_rule_ids,
                                           dlp_severity=dlp_severity, resolved_ips=tuple(addresses),
                                           address_class=_first_class(verdicts),
                                           correlation_id=correlation_id)
            if result.outcome is DlpOutcome.REQUIRE_APPROVAL:
                outcome = EgressOutcome.REQUIRE_APPROVAL
                reason = "dlp_requires_approval"
            elif result.outcome is DlpOutcome.INDETERMINATE:
                # fail closed per config
                if self.cfg.dlp_failure_action == "block":
                    self._audit(E_DLP_INDETERMINATE, org_id=tenant, agent_id=agent_id,
                                instance_id=instance_id, destination=destination, host=host,
                                port=port, protocol=protocol.value,
                                decision=EgressOutcome.DENY.value, reason=result.reason,
                                outcome="denied", correlation_id=correlation_id)
                    return EgressDecision.deny("dlp_indeterminate", host=host, port=port,
                                               protocol=protocol.value, destination=destination,
                                               dlp_outcome=dlp_outcome,
                                               correlation_id=correlation_id)
                outcome = EgressOutcome.REQUIRE_APPROVAL
                reason = "dlp_indeterminate"
            elif result.outcome is DlpOutcome.REDACTED:
                redacted_body = result.redacted_payload
                self._audit(E_DLP_REDACTED, org_id=tenant, agent_id=agent_id,
                            instance_id=instance_id, destination=destination, host=host, port=port,
                            protocol=protocol.value, decision=EgressOutcome.ALLOW.value,
                            reason=result.reason, outcome="ok", dlp_rule_ids=dlp_rule_ids,
                            dlp_severity=dlp_severity, correlation_id=correlation_id)
            elif result.outcome is DlpOutcome.CLEAN:
                self._audit(E_DLP_CLEAN, org_id=tenant, agent_id=agent_id, instance_id=instance_id,
                            destination=destination, host=host, port=port, protocol=protocol.value,
                            decision=EgressOutcome.ALLOW.value, reason="dlp_clean", outcome="ok",
                            correlation_id=correlation_id)

        # ---- 7. policy engine (Step 10) -- can only TIGHTEN -----------------------------
        policy_version = None
        if self.policy_service is not None:
            action = f"egress:{protocol.value}:{method.lower()}"
            request_context = {
                "destination": destination, "host": host, "port": port,
                "protocol": protocol.value, "method": method,
                "resource_id": request.resource_id, "operation": request.operation,
                "dlp_outcome": dlp_outcome, "dlp_rule_ids": list(dlp_rule_ids),
                "address_class": _first_class(verdicts),
            }
            if request.context:
                for k, v in request.context.items():
                    request_context.setdefault(k, v)
            try:
                pd = self.policy_service.authorize(
                    agent_id=agent_id, tenant=tenant, action=action,
                    resource=request.resource_id or destination, instance_id=instance_id,
                    capabilities=tuple(claimed_capabilities or ()),
                    credential_status=credential_status, environment=environment,
                    request_context=request_context, correlation_id=correlation_id)
                policy_version = pd.policy_version
                outcome, reason = _tighten(outcome, reason, pd)
            except Exception:  # noqa: BLE001 - policy outage fails closed
                outcome = EgressOutcome.INDETERMINATE
                reason = "policy_engine_error"

        # ---- 8. combine + seal ----------------------------------------------------------
        decision = EgressDecision(
            outcome=outcome, reason=reason, host=host, port=port, protocol=protocol.value,
            destination=destination,
            policy_id=(matched_policy.policy_id if matched_policy else None),
            policy_version=policy_version, dlp_outcome=dlp_outcome, dlp_rule_ids=dlp_rule_ids,
            dlp_severity=dlp_severity, redacted_body=redacted_body, resolved_ips=tuple(addresses),
            address_class=_first_class(verdicts), correlation_id=correlation_id,
            decision_id=new_id("edec"))
        if outcome is EgressOutcome.ALLOW:
            decision = EgressDecision(**{**decision.__dict__, "seal": self._seals.mint()})
        return self._finalize(decision, org_id=tenant, agent_id=agent_id, instance_id=instance_id,
                              correlation_id=correlation_id, audit=True)

    # ================================================================== enforce
    def enforce(self, decision: EgressDecision, executor: Callable[[], T]) -> T:
        """Run ``executor`` ONLY for a sealed ALLOW. Otherwise raise and never invoke it."""
        if not isinstance(decision, EgressDecision) or decision.outcome is not EgressOutcome.ALLOW:
            reason = getattr(decision, "reason", "denied") or "denied"
            raise ForbiddenError(f"egress denied: {reason}")
        if not self._seals.consume(decision.seal):
            raise ForbiddenError("egress denied: invalid_or_consumed_decision_seal")
        return executor()

    def request(self, *, agent_id: str, tenant: str, request: EgressRequest,
                instance_id: Optional[str] = None, claimed_capabilities=(),
                environment: str = "development", correlation_id: Optional[str] = None,
                transport=None) -> dict:
        """Decide, then execute the outbound call ONLY on a sealed ALLOW.

        Redirects are followed by the gateway (never the transport) and each hop is re-validated.
        Returns a structured result: ``{"decision": ..., "response": {...}}``.
        """
        decision = self.decide(agent_id=agent_id, tenant=tenant, request=request,
                               instance_id=instance_id, claimed_capabilities=claimed_capabilities,
                               environment=environment, correlation_id=correlation_id)
        if not decision.allowed:
            return {"decision": decision.to_dict(), "response": None}
        if not self._gate.acquire(self.cfg.read_timeout_ms / 1000.0):
            return {"decision": EgressDecision.indeterminate("gateway_overloaded").to_dict(),
                    "response": None}
        try:
            response = self._execute(decision=decision, request=request, tenant=tenant,
                                     agent_id=agent_id, instance_id=instance_id,
                                     correlation_id=correlation_id,
                                     transport=transport or self.transport)
        finally:
            self._gate.release()
        return {"decision": decision.to_dict(), "response": response}

    # ------------------------------------------------------------------ execution
    def _execute(self, *, decision, request, tenant, agent_id, instance_id, correlation_id,
                 transport) -> dict:
        """Execute the request, following (and re-validating) redirects up to the configured cap."""
        if transport is None:
            return {"executed": False, "reason": "no_transport_configured",
                    "note": "an egress transport must be supplied to perform real I/O"}
        body = decision.redacted_body if decision.redacted_body is not None else request.body
        current = request
        hops = 0
        while True:
            try:
                resp = transport.send(
                    url=current.url, method=(current.method or "GET").upper(),
                    headers=dict(current.headers or {}), body=body,
                    resolved_ips=decision.resolved_ips,
                    connect_timeout_s=self.cfg.connect_timeout_ms / 1000.0,
                    read_timeout_s=self.cfg.read_timeout_ms / 1000.0,
                    max_response_bytes=self.cfg.max_response_bytes)
            except Exception as exc:  # noqa: BLE001 - transport failure is reported, not hidden
                self._audit(E_GATEWAY_ERROR, org_id=tenant, agent_id=agent_id,
                            instance_id=instance_id, destination=decision.destination,
                            host=decision.host, port=decision.port, protocol=decision.protocol,
                            decision=EgressOutcome.ALLOW.value, reason=f"transport_error:{type(exc).__name__}",
                            outcome="error", correlation_id=correlation_id)
                return {"executed": False, "reason": f"transport_error:{type(exc).__name__}"}
            status = int(resp.get("status", 0))
            location = _header(resp.get("headers") or {}, "location")
            if status in (301, 302, 303, 307, 308) and location:
                hops += 1
                if not self._redirects_allowed(decision, tenant):
                    self._audit(E_REDIRECT_BLOCKED, org_id=tenant, agent_id=agent_id,
                                instance_id=instance_id, destination=decision.destination,
                                host=decision.host, port=decision.port,
                                protocol=decision.protocol, decision=EgressOutcome.DENY.value,
                                reason="redirect_not_permitted", outcome="denied",
                                correlation_id=correlation_id)
                    return {"executed": False, "reason": "redirect_not_permitted", "status": status}
                if hops > self.cfg.max_redirects:
                    return {"executed": False, "reason": "too_many_redirects", "status": status}
                target = urllib.parse.urljoin(current.url, location)
                # re-validate the redirect target through the SAME pipeline
                redirect_req = EgressRequest(url=target, method="GET" if status == 303 else current.method,
                                             headers=current.headers, body=None)
                try:
                    r_host, r_port, r_scheme = redirect_req.host_port()
                except EgressValidationError:
                    return {"executed": False, "reason": "redirect_malformed", "status": status}
                r_addresses, r_verdicts, r_reason = self.addresses.validate_redirect(r_host)
                if r_reason:
                    self._audit(E_REDIRECT_BLOCKED, org_id=tenant, agent_id=agent_id,
                                instance_id=instance_id, destination=target, host=r_host,
                                port=r_port, protocol=r_scheme, decision=EgressOutcome.DENY.value,
                                reason=f"redirect_{r_reason}", outcome="denied",
                                resolved_ips=tuple(r_addresses), correlation_id=correlation_id)
                    return {"executed": False, "reason": f"redirect_{r_reason}", "status": status}
                r_policies = self.policies.list_policies(org_id=tenant) if self.policies else []
                r_verdict = self.destination_policy.evaluate(
                    host=r_host, protocol=_ALLOWED_SCHEMES[r_scheme], port=r_port, policies=r_policies)
                if r_verdict.action is not EgressOutcome.ALLOW:
                    self._audit(E_REDIRECT_BLOCKED, org_id=tenant, agent_id=agent_id,
                                instance_id=instance_id, destination=target, host=r_host,
                                port=r_port, protocol=r_scheme, decision=EgressOutcome.DENY.value,
                                reason=f"redirect_{r_verdict.reason}", outcome="denied",
                                correlation_id=correlation_id)
                    return {"executed": False, "reason": f"redirect_{r_verdict.reason}",
                            "status": status}
                current = redirect_req
                decision = EgressDecision(**{**decision.__dict__, "resolved_ips": tuple(r_addresses),
                                             "host": r_host, "port": r_port,
                                             "destination": target})
                continue
            return {"executed": True, "status": status, "headers": _safe_headers(resp.get("headers") or {}),
                    "body": resp.get("body"), "redirects": hops}

    def _redirects_allowed(self, decision: EgressDecision, tenant: str) -> bool:
        if not self.cfg.revalidate_redirects:
            return False
        if decision.policy_id and self.policies is not None:
            rec = self.policies.get_policy(decision.policy_id)
            if rec is not None:
                return bool(rec.allow_redirects)
        return bool(self.cfg.allow_redirects_default)

    # ------------------------------------------------------------------ helpers
    def _rate_limit_for(self, tenant: str, host: str, port: int, protocol: Protocol) -> RateLimitSpec:
        if self.policies is not None:
            policies = self.policies.list_policies(org_id=tenant)
            verdict = self.destination_policy.evaluate(host=host, protocol=protocol, port=port,
                                                       policies=policies)
            if verdict.policy is not None and verdict.policy.rate_limit is not None:
                return verdict.policy.rate_limit
        return RateLimitSpec(per_second=self.cfg.default_rate_per_second,
                             burst=self.cfg.default_rate_burst)

    def _finalize(self, decision: EgressDecision, *, org_id, agent_id, instance_id, correlation_id,
                  audit: bool) -> EgressDecision:
        if audit:
            outcome = "ok" if decision.outcome is EgressOutcome.ALLOW else "denied"
            event = {EgressOutcome.ALLOW: E_REQUEST_ALLOWED,
                     EgressOutcome.DENY: E_REQUEST_DENIED,
                     EgressOutcome.REQUIRE_APPROVAL: E_REQUEST_APPROVAL,
                     EgressOutcome.INDETERMINATE: E_REQUEST_INDETERMINATE}[decision.outcome]
            self._audit(event, org_id=org_id, agent_id=agent_id, instance_id=instance_id,
                        destination=decision.destination, host=decision.host, port=decision.port,
                        protocol=decision.protocol, decision=decision.outcome.value,
                        reason=decision.reason, outcome=outcome, policy_id=decision.policy_id,
                        policy_version=decision.policy_version, dlp_rule_ids=decision.dlp_rule_ids,
                        dlp_severity=decision.dlp_severity, resolved_ips=decision.resolved_ips,
                        address_class=decision.address_class, correlation_id=correlation_id)
        return decision

    def _audit(self, event, **kwargs) -> None:
        if self.audit is None:
            return
        self.audit.record(event, **kwargs)


# --------------------------------------------------------------------------- module helpers
def _body_size(body) -> int:
    if body is None:
        return 0
    if isinstance(body, (bytes, bytearray)):
        return len(body)
    if isinstance(body, str):
        return len(body.encode("utf-8"))
    try:
        import json
        return len(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    except Exception:  # noqa: BLE001
        return 0


def _first_class(verdicts: List[AddressVerdict]) -> Optional[str]:
    for v in verdicts:
        if v.blocked:
            return v.address_class.value
    return verdicts[0].address_class.value if verdicts else None


def _max_severity(findings) -> Optional[str]:
    from .models import DlpSeverity
    best = None
    for f in findings:
        sev = DlpSeverity.coerce(f.severity)
        if sev is None:
            continue
        if best is None or sev.rank > best.rank:
            best = sev
    return best.value if best else None


def _header(headers: dict, name: str) -> Optional[str]:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def _safe_headers(headers: dict) -> dict:
    """Return response headers with any credential-looking value redacted."""
    out = {}
    for k, v in headers.items():
        if k.lower() in ("set-cookie", "authorization", "proxy-authorization"):
            out[k] = "[REDACTED]"
        else:
            out[k] = v
    return out


def _tighten(outcome: EgressOutcome, reason: str, policy_decision) -> Tuple[EgressOutcome, str]:
    """Apply a Step 10 policy decision as a TIGHTENING-ONLY leg.

    A policy DENY/INDETERMINATE/REQUIRE_APPROVAL can only make the outcome stricter; a policy ALLOW
    never loosens an egress DENY/REQUIRE_APPROVAL.
    """
    from ..policy.models import DecisionKind
    rank = {EgressOutcome.ALLOW: 0, EgressOutcome.REQUIRE_APPROVAL: 1,
            EgressOutcome.INDETERMINATE: 2, EgressOutcome.DENY: 3}
    mapped = {DecisionKind.ALLOW: EgressOutcome.ALLOW,
              DecisionKind.DENY: EgressOutcome.DENY,
              DecisionKind.REQUIRE_APPROVAL: EgressOutcome.REQUIRE_APPROVAL,
              DecisionKind.INDETERMINATE: EgressOutcome.INDETERMINATE}[policy_decision.kind]
    if rank[mapped] > rank[outcome]:
        return mapped, (policy_decision.reason or mapped.value)
    return outcome, reason
