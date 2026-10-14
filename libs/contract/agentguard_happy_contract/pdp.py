"""Pluggable Policy Decision Points (PDP) for the integration.

A PDP answers exactly one question: given an :class:`AuthorizationRequest`, is the operation
permitted?  Every implementation **fails closed** -- an error, a timeout, an unreachable endpoint, a
non-2xx response or an unparseable body becomes ``INDETERMINATE`` (never ALLOW).

Implementations provided:

* :class:`HttpPdp` -- stdlib HTTP client for AgentGuard's **existing** ``POST /v1/authorize``.
  This is the production path and requires no AgentGuard source change.
* :class:`SdkPdp` -- reuses AgentGuard's own Universal Agent SDK client (duck-typed), so credential
  acquisition, proof of possession and the SDK's own fail-closed transport are reused rather than
  re-implemented.
* :class:`CallablePdp` -- adapts any callable (used by tests and by embedders).
* :class:`DenyAllPdp` -- the safe default when the integration is enabled but nothing is wired.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping, Optional, Protocol

from .errors import SerializationError, ValidationError
from .models import AuthorizationDecision, AuthorizationRequest
from .validation import canonical_json

DEFAULT_AUTHORIZE_PATH = "/v1/authorize"


class PolicyDecisionPoint(Protocol):
    """A decision source.  Implementations MUST fail closed on any error."""

    def decide(self, request: AuthorizationRequest, *, token: str = "",
               proof: Optional[dict] = None) -> AuthorizationDecision:  # pragma: no cover
        ...


def coerce_decision(raw: Any, *, correlation_id: Optional[str] = None,
                    request_id: Optional[str] = None,
                    latency_ms: Optional[int] = None) -> AuthorizationDecision:
    """Normalise whatever a PDP returned into an :class:`AuthorizationDecision`.

    Anything unrecognised becomes ``INDETERMINATE`` -- a garbled answer must never read as ALLOW.
    """
    if isinstance(raw, AuthorizationDecision):
        result = raw
    elif isinstance(raw, Mapping):
        result = AuthorizationDecision.from_agentguard_dict(
            raw, correlation_id=correlation_id, request_id=request_id, latency_ms=latency_ms)
    elif hasattr(raw, "allowed"):
        # AgentGuard SDK ``Decision`` (a frozen dataclass with ``allowed``/``reason``/...).
        result = AuthorizationDecision.from_agentguard_dict(
            {
                "allowed": bool(getattr(raw, "allowed", False)),
                "reason": getattr(raw, "reason", "") or "",
                "decision_id": getattr(raw, "decision_id", None),
                "policy": getattr(raw, "policy", None),
                "obligations": list(getattr(raw, "obligations", ()) or ()),
                "correlation_id": getattr(raw, "correlation_id", None),
            },
            correlation_id=correlation_id, request_id=request_id, latency_ms=latency_ms)
    else:
        return AuthorizationDecision.make_indeterminate(
            "unrecognised_pdp_result", correlation_id=correlation_id, request_id=request_id)
    if result.correlation_id is None and correlation_id is not None:
        result = AuthorizationDecision(
            decision=result.decision, allowed=result.allowed, reason=result.reason,
            decision_id=result.decision_id, policy=result.policy,
            policy_version=result.policy_version, obligations=result.obligations,
            correlation_id=correlation_id, request_id=request_id or result.request_id,
            latency_ms=latency_ms or result.latency_ms, indeterminate=result.indeterminate,
            contract_version=result.contract_version)
    return result


class DenyAllPdp:
    """Denies everything.  The safe default when the integration is on but no PDP is configured."""

    def decide(self, request: AuthorizationRequest, *, token: str = "",
               proof: Optional[dict] = None) -> AuthorizationDecision:
        return AuthorizationDecision.deny("no_policy_decision_point_configured",
                                         correlation_id=request.correlation_id,
                                         request_id=request.request_id)


class CallablePdp:
    """Adapts a callable into a PDP.

    The callable is tried as ``fn(request, token=..., proof=...)`` then as ``fn(request)``, so both
    a full-PDP and a simple stub can be supplied.
    """

    def __init__(self, fn: Callable[..., Any]) -> None:
        if not callable(fn):
            raise ValidationError("CallablePdp requires a callable", field="fn")
        self._fn = fn

    def decide(self, request: AuthorizationRequest, *, token: str = "",
               proof: Optional[dict] = None) -> AuthorizationDecision:
        started = time.time()
        try:
            try:
                raw = self._fn(request, token=token, proof=proof)
            except TypeError:
                raw = self._fn(request)
        except Exception as exc:                            # noqa: BLE001 - fail closed
            return AuthorizationDecision.make_indeterminate(
                f"pdp_error:{type(exc).__name__}", correlation_id=request.correlation_id,
                request_id=request.request_id)
        latency = int((time.time() - started) * 1000)
        return coerce_decision(raw, correlation_id=request.correlation_id,
                               request_id=request.request_id, latency_ms=latency)


class SdkPdp:
    """Reuse AgentGuard's own SDK client (``AgentGuardClient``/``AuthorizationClient``).

    This is preferred when the SDK is available: it reuses the SDK's credential lifecycle,
    proof-of-possession signing and fail-closed transport instead of re-implementing them.
    """

    def __init__(self, client: Any) -> None:
        if not hasattr(client, "authorize"):
            raise ValidationError("SdkPdp requires an object exposing authorize(...)",
                                  field="client")
        self._client = client

    def decide(self, request: AuthorizationRequest, *, token: str = "",
               proof: Optional[dict] = None) -> AuthorizationDecision:
        started = time.time()
        body = request.to_authorize_body(token=token or "", proof=proof)
        try:
            try:
                raw = self._client.authorize(action=request.action, resource=request.resource,
                                             context=body.get("context"),
                                             correlation_id=request.correlation_id)
            except TypeError:
                raw = self._client.authorize(request.action, request.resource,
                                             body.get("context"), request.correlation_id)
        except Exception as exc:                            # noqa: BLE001 - fail closed
            return AuthorizationDecision.make_indeterminate(
                f"policy_unavailable:{type(exc).__name__}", correlation_id=request.correlation_id,
                request_id=request.request_id)
        latency = int((time.time() - started) * 1000)
        return coerce_decision(raw, correlation_id=request.correlation_id,
                               request_id=request.request_id, latency_ms=latency)


class HttpPdp:
    """Stdlib HTTP PDP against AgentGuard's existing ``POST /v1/authorize``.

    Bounds enforced here: a connect/read timeout, a maximum response size, and TLS verification
    (with an optional CA bundle / client certificate for mTLS).  A non-2xx status, an oversized
    body or an unparseable body all become ``INDETERMINATE``.
    """

    def __init__(
        self,
        base_url: str,
        *,
        path: str = DEFAULT_AUTHORIZE_PATH,
        timeout_seconds: float = 5.0,
        verify_tls: bool = True,
        ca_bundle: Optional[str] = None,
        max_response_bytes: int = 65536,
        environment: str = "development",
        allow_insecure_http: bool = False,
        audience: Optional[str] = None,
        token_provider: Optional[Callable[[], str]] = None,
        proof_provider: Optional[Callable[[], Optional[dict]]] = None,
        user_agent: str = "happy-agentguard-integration/1.0",
    ) -> None:
        if not isinstance(base_url, str) or not (
                base_url.startswith("http://") or base_url.startswith("https://")):
            raise ValidationError("base_url must be an absolute http(s) URL", field="base_url")
        if base_url.startswith("http://") and environment == "production" \
                and not allow_insecure_http:
            raise ValidationError(
                "plaintext http:// is not permitted in production", field="base_url")
        self.url = base_url.rstrip("/") + (path if path.startswith("/") else "/" + path)
        self.timeout_seconds = float(timeout_seconds)
        self.verify_tls = bool(verify_tls)
        self.ca_bundle = ca_bundle
        self.max_response_bytes = int(max_response_bytes)
        self.audience = audience
        self.user_agent = user_agent
        self._token_provider = token_provider
        self._proof_provider = proof_provider

    # -- internals ---------------------------------------------------------------------------
    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self.url.startswith("https://"):
            return None
        if not self.verify_tls:
            context = ssl._create_unverified_context()      # noqa: S323 - explicit opt-out only
            return context
        if self.ca_bundle:
            return ssl.create_default_context(cafile=self.ca_bundle)
        return ssl.create_default_context()

    def _post(self, url: str, payload: dict, headers: dict) -> tuple:
        data = canonical_json(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json")
        request.add_header("User-Agent", self.user_agent)
        for key, value in headers.items():
            if value is not None:
                request.add_header(key, str(value))
        context = self._ssl_context()
        with urllib.request.urlopen(request, timeout=self.timeout_seconds,
                                   context=context) as response:  # noqa: S310 - URL validated
            status = int(getattr(response, "status", 200))
            raw = response.read(self.max_response_bytes + 1)
        if len(raw) > self.max_response_bytes:
            raise SerializationError("authorization response exceeded the size bound",
                                     field="response")
        return status, raw

    # -- decision ----------------------------------------------------------------------------
    def decide(self, request: AuthorizationRequest, *, token: str = "",
               proof: Optional[dict] = None) -> AuthorizationDecision:
        started = time.time()
        try:
            effective_token = token or (self._token_provider() if self._token_provider else "")
            effective_proof = proof
            if effective_proof is None and self._proof_provider is not None:
                effective_proof = self._proof_provider()
            body = request.to_authorize_body(token=effective_token or "", proof=effective_proof,
                                            audience=self.audience)
            headers = {"X-Correlation-Id": request.correlation_id}
            if effective_token:
                headers["Authorization"] = f"Bearer {effective_token}"
            status, raw = self._post(self.url, body, headers)
        except urllib.error.HTTPError as exc:
            return AuthorizationDecision.make_indeterminate(
                f"pdp_http_{exc.code}", correlation_id=request.correlation_id,
                request_id=request.request_id,
                latency_ms=int((time.time() - started) * 1000))
        except Exception as exc:                            # noqa: BLE001 - fail closed
            return AuthorizationDecision.make_indeterminate(
                f"pdp_unavailable:{type(exc).__name__}", correlation_id=request.correlation_id,
                request_id=request.request_id,
                latency_ms=int((time.time() - started) * 1000))
        latency = int((time.time() - started) * 1000)
        if status < 200 or status >= 300:
            return AuthorizationDecision.make_indeterminate(
                f"pdp_status_{status}", correlation_id=request.correlation_id,
                request_id=request.request_id, latency_ms=latency)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:                                   # noqa: BLE001 - fail closed
            return AuthorizationDecision.make_indeterminate(
                "pdp_malformed_response", correlation_id=request.correlation_id,
                request_id=request.request_id, latency_ms=latency)
        return coerce_decision(parsed, correlation_id=request.correlation_id,
                               request_id=request.request_id, latency_ms=latency)


__all__ = [
    "PolicyDecisionPoint", "DenyAllPdp", "CallablePdp", "SdkPdp", "HttpPdp",
    "coerce_decision", "DEFAULT_AUTHORIZE_PATH",
]
