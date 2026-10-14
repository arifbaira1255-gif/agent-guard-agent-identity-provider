"""Agent authentication: credential acquisition + proof-of-possession request signing.

This is the SDK's *authentication* half. It is deliberately separate from authorization (see
``authorization.py``) and from tool execution (see ``adapters``): authenticating an agent never
implies that any action is permitted.

Proof of possession reuses the EXISTING AgentGuard proof format (``crypto.keys.proof_bytes`` /
``DOMAIN_PROOF``) so a proof produced by this SDK verifies against the same server-side verifier as
one produced by the core library \u2014 no duplicated crypto.
"""
from __future__ import annotations

import time
from typing import Optional

from .credentials import CredentialManager
from .errors import AuthenticationError, ValidationError
from .models import Credential, VerificationResult


class AgentAuthenticator:
    def __init__(self, client, *, key=None, audience: Optional[str] = None, clock=time.time):
        self._client = client
        self._clock = clock
        self.audience = audience or client.config.default_audience
        self.credentials = CredentialManager(client, key=key, clock=clock)

    # ------------------------------------------------------------------ identity
    @property
    def key(self):
        return self.credentials.key

    def authenticate(self, *, ttl_seconds: Optional[int] = None) -> Credential:
        """Ensure the agent holds a valid credential and return it."""
        return self.credentials.ensure_valid(ttl_seconds=ttl_seconds)

    # ------------------------------------------------------------------ proof of possession
    def make_proof(self, credential: Optional[Credential] = None, *, audience: Optional[str] = None,
                   request_id: Optional[str] = None) -> dict:
        """Sign a fresh possession proof bound to ``audience`` for the given credential.

        The proof timestamp comes from the SDK clock (injectable), so a deployment whose clock is
        offset from the server's can be aligned in tests without weakening the freshness check.
        """
        cred = credential or self.credentials.ensure_valid()
        if not cred.credential_id:
            raise ValidationError("no credential to prove possession of")
        return self.key.make_proof(cred.credential_id, audience or self.audience,
                                   request_id=request_id, timestamp=int(self._clock()))

    def auth_headers(self, *, audience: Optional[str] = None, request_id: Optional[str] = None,
                     correlation_id: Optional[str] = None) -> dict:
        """Headers that authenticate the agent to an AgentGuard-protected service.

        The credential token is sent as a bearer-style ``AgentPassport`` value and the possession
        proof travels alongside it. Neither is ever logged by the SDK.
        """
        cred = self.credentials.ensure_valid()
        proof = self.make_proof(cred, audience=audience, request_id=request_id)
        import json as _json
        headers = {
            "Authorization": f"AgentPassport {cred.token}",
            "X-Agent-Proof": _json.dumps(proof, separators=(",", ":")),
            "X-Agent-Id": cred.agent_id,
            "X-Agent-Instance-Id": cred.instance_id,
        }
        if correlation_id:
            headers["X-Correlation-Id"] = correlation_id
        return headers

    # ------------------------------------------------------------------ verification
    def verify(self, token: str, proof: Optional[dict] = None, *, audience: Optional[str] = None,
               expected_agent_id: Optional[str] = None,
               expected_instance_id: Optional[str] = None,
               correlation_id: Optional[str] = None) -> VerificationResult:
        """Ask AgentGuard to verify a credential (and optional proof). Never raises on an invalid
        credential \u2014 an invalid verdict is a result, not an error."""
        body = {"token": token, "proof": proof, "audience": audience or self.audience,
                "expected_agent_id": expected_agent_id,
                "expected_instance_id": expected_instance_id,
                "correlation_id": correlation_id}
        resp = self._client._transport.request("POST", "/v1/credentials/verify", body=body,
                                               headers=self._client._provision_headers())
        return VerificationResult.from_dict(resp.body or {})

    def revoke(self, credential_id: str, reason: str = "revoked_by_agent",
               detail: Optional[str] = None) -> dict:
        """Revoke a credential (self-service or administrative, subject to server authorization)."""
        resp = self._client._transport.request(
            "POST", "/v1/credentials/revoke",
            body={"credential_id": credential_id, "reason": reason, "detail": detail},
            headers=self._client._provision_headers())
        if credential_id == (self.credentials.current() or Credential("", "", "", "")).credential_id:
            self.credentials.invalidate()
        return resp.body if isinstance(resp.body, dict) else {}
