"""``AgentGuardClient`` \u2014 the single entry point of the Python SDK.

Composes the four SDK concerns without conflating them:
  * ``authenticator``  \u2014 who the agent is (credential + proof of possession);
  * ``authorization``  \u2014 whether an action is permitted (policy decision + enforcement);
  * ``events``         \u2014 security-event reporting with correlation ids;
  * ``transport``      \u2014 TLS-verified, bounded, cancellable HTTP.

It reuses the EXISTING AgentGuard identity plane (``agent_identity``) for all cryptography: the
agent-side key, the CSR/proof formats and the credential model are the core library's, not a
re-implementation.
"""
from __future__ import annotations

import secrets
import time
from typing import Optional

from .auth import AgentAuthenticator
from .authorization import AuthorizationClient, PolicyDecisionPoint
from .config import SdkConfig
from .credentials import CredentialManager
from .errors import ValidationError
from .events import SecurityEventReporter
from .models import AgentIdentity, Credential, Decision, VerificationResult
from .transport import CancellationToken, Transport


class AgentGuardClient:
    def __init__(self, config: SdkConfig, *, agent_id: Optional[str] = None,
                 instance_id: Optional[str] = None, key=None, transport: Optional[Transport] = None,
                 pdp: Optional[PolicyDecisionPoint] = None, clock=time.time):
        self.config = config
        self.agent_id = agent_id
        self.instance_id = instance_id
        self._clock = clock
        self._transport = transport or Transport(config)
        self.authenticator = AgentAuthenticator(self, key=key, clock=clock)
        self.authorization = AuthorizationClient(self, pdp=pdp)
        self.events = SecurityEventReporter(self)

    # ------------------------------------------------------------------ internals
    @property
    def _transport_(self):
        return self._transport

    def _new_idempotency_key(self, scope: str) -> str:
        return f"sdk-{scope}-{secrets.token_hex(12)}"

    def _provision_headers(self) -> dict:
        """Headers for control-plane bootstrap calls (register/instance/issue/rotate/revoke/status).

        Uses the provisioning bearer token when configured. The agent's own credential is NOT used
        here \u2014 it does not exist yet at bootstrap time. The token is never logged.
        """
        tok = self.config.control_plane_token
        return {"Authorization": f"Bearer {tok}"} if tok else {}

    def _request(self, method: str, path: str, *, body=None, idempotency_key=None,
                 cancel: Optional[CancellationToken] = None, expect=(200, 201, 204),
                 headers: Optional[dict] = None):
        return self._transport.request(method, path, body=body, idempotency_key=idempotency_key,
                                       cancel=cancel, expect=expect, headers=headers)

    # ------------------------------------------------------------------ identity
    def register_agent(self, *, org_id: str, agent_name: str, agent_type: str, owner: str,
                       description: str = "", capabilities=(), environment: str = "development",
                       metadata: Optional[dict] = None,
                       idempotency_key: Optional[str] = None) -> AgentIdentity:
        body = {"org_id": org_id, "agent_name": agent_name, "agent_type": agent_type,
                "owner": owner, "description": description,
                "capabilities": list(capabilities) if capabilities else None,
                "environment": environment, "metadata": metadata}
        resp = self._request("POST", "/v1/agents", body=body,
                             idempotency_key=idempotency_key or self._new_idempotency_key("register"),
                             headers=self._provision_headers())
        ident = AgentIdentity.from_dict(resp.body or {})
        self.agent_id = ident.agent_id
        return ident

    def get_agent(self, agent_id: Optional[str] = None) -> AgentIdentity:
        aid = agent_id or self.agent_id
        if not aid:
            raise ValidationError("agent_id is required")
        resp = self._request("GET", f"/v1/agents/{aid}", headers=self._provision_headers())
        return AgentIdentity.from_dict(resp.body or {})

    def create_instance(self, agent_id: Optional[str] = None, *, session_id: Optional[str] = None) -> dict:
        aid = agent_id or self.agent_id
        if not aid:
            raise ValidationError("agent_id is required")
        resp = self._request("POST", "/v1/instances",
                             body={"agent_id": aid, "session_id": session_id},
                             headers=self._provision_headers())
        body = resp.body if isinstance(resp.body, dict) else {}
        if body.get("instance_id"):
            self.instance_id = body["instance_id"]
        return body

    def bind(self, *, agent_id: str, instance_id: str) -> "AgentGuardClient":
        """Bind this client to an existing agent instance (no server round-trip)."""
        self.agent_id = agent_id
        self.instance_id = instance_id
        return self

    # ------------------------------------------------------------------ credentials
    def issue_credential(self, *, ttl_seconds: Optional[int] = None) -> Credential:
        return self.authenticator.credentials.acquire(ttl_seconds=ttl_seconds)

    def ensure_credential(self, *, ttl_seconds: Optional[int] = None) -> Credential:
        return self.authenticator.credentials.ensure_valid(ttl_seconds=ttl_seconds)

    def renew_credential(self) -> Credential:
        return self.authenticator.credentials.renew()

    def credential_status(self, credential_id: Optional[str] = None) -> dict:
        cid = credential_id or (self.authenticator.credentials.current() or Credential("", "", "", "")).credential_id
        if not cid:
            raise ValidationError("credential_id is required")
        resp = self._request("GET", f"/v1/credentials/{cid}/status",
                             headers=self._provision_headers())
        return resp.body if isinstance(resp.body, dict) else {}

    def verify_credential(self, token: str, proof: Optional[dict] = None, *,
                          audience: Optional[str] = None) -> VerificationResult:
        return self.authenticator.verify(token, proof, audience=audience)

    def revoke_credential(self, credential_id: str, reason: str = "revoked_by_agent",
                          detail: Optional[str] = None) -> dict:
        return self.authenticator.revoke(credential_id, reason, detail)

    # ------------------------------------------------------------------ authorization
    def authorize(self, *, action: str, resource: str, context: Optional[dict] = None,
                  correlation_id: Optional[str] = None) -> Decision:
        return self.authorization.authorize(action=action, resource=resource, context=context,
                                            correlation_id=correlation_id)

    def require(self, *, action: str, resource: str, context: Optional[dict] = None,
                correlation_id: Optional[str] = None) -> Decision:
        return self.authorization.require(action=action, resource=resource, context=context,
                                          correlation_id=correlation_id)

    # ------------------------------------------------------------------ governed egress (Phase 4)
    def governed_request(self, *, url: str, method: str = "GET", headers: Optional[dict] = None,
                         body=None, resource_id: Optional[str] = None,
                         operation: Optional[str] = None, context: Optional[dict] = None,
                         correlation_id: Optional[str] = None) -> dict:
        """Make an outbound request through the AgentGuard egress gateway.

        The server-side gateway applies destination policy, SSRF/address protection and DLP, and
        returns a structured decision. The SDK NEVER decides egress itself -- it forwards the request
        and surfaces the server's decision, so a blocked or approval-required operation is reported
        to the caller rather than silently attempted.

        Returns the server's ``{"decision": {...}, "response": {...}}`` payload. A DENY /
        REQUIRE_APPROVAL / INDETERMINATE decision is returned (not raised) so the caller can handle
        it explicitly; use :meth:`require_egress` to raise instead.
        """
        payload = {"url": url, "method": method, "headers": headers, "body": body,
                   "resource_id": resource_id, "operation": operation, "context": context}
        resp = self._request("POST", "/v1/egress/request", body=payload,
                             idempotency_key=self._new_idempotency_key("egress"),
                             headers=self._auth_headers(correlation_id))
        return resp.body if isinstance(resp.body, dict) else {}

    def require_egress(self, **kwargs) -> dict:
        """Like :meth:`governed_request` but raises ``ForbiddenError`` on a non-ALLOW decision."""
        out = self.governed_request(**kwargs)
        decision = (out or {}).get("decision") or {}
        if not decision.get("allowed"):
            from .errors import AuthorizationError
            raise AuthorizationError(f"egress denied: {decision.get('reason') or 'denied'}")
        return out

    def _auth_headers(self, correlation_id: Optional[str]) -> dict:
        """Credential + correlation headers for an authenticated data-plane call."""
        headers = {}
        cred = self.authenticator.credentials.current()
        if cred is not None and getattr(cred, "token", None):
            headers["Authorization"] = f"Bearer {cred.token}"
        if correlation_id:
            headers["X-Correlation-Id"] = correlation_id
        return headers

    # ------------------------------------------------------------------ events
    def report_event(self, event_type: str, **kwargs):
        return self.events.report(event_type, **kwargs)

    def flush_events(self) -> int:
        return self.events.flush()

    # ------------------------------------------------------------------ lifecycle
    def close(self) -> None:
        try:
            self.events.flush()
        except Exception:                                # noqa: BLE001
            pass

    def __enter__(self) -> "AgentGuardClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
