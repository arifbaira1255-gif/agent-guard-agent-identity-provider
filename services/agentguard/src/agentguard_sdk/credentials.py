"""Credential acquisition, renewal and lifecycle handling.

The SDK uses the RECOMMENDED deployment mode: the agent generates and keeps its own ephemeral
Ed25519 key (``AgentSideKey``) and sends only the public key + a proof of possession. The private
key never leaves the process, is never serialised, and is never sent to the server.

Renewal is proactive: :meth:`CredentialManager.ensure_valid` renews when the credential is within
``credential_renewal_skew_seconds`` of expiry, so a long-running agent does not fail mid-operation.
A revoked or expired credential is surfaced as a typed error and the cached credential is dropped.
"""
from __future__ import annotations

import threading
import time
from typing import Optional

from .errors import (AuthenticationError, CredentialExpiredError, CredentialRevokedError,
                     ValidationError)
from .models import Credential


class CredentialManager:
    def __init__(self, client, *, key=None, renewal_skew_seconds: Optional[int] = None,
                 clock=time.time):
        self._client = client
        self._clock = clock
        self._lock = threading.RLock()
        self._credential: Optional[Credential] = None
        self._key = key
        self._skew = (renewal_skew_seconds if renewal_skew_seconds is not None
                      else client.config.credential_renewal_skew_seconds)

    # ------------------------------------------------------------------ state
    @property
    def key(self):
        """The agent-side key used for proof-of-possession. Created lazily on first use."""
        if self._key is None:
            from agent_identity.crypto.client import AgentSideKey
            self._key = AgentSideKey()
        return self._key

    def current(self) -> Optional[Credential]:
        with self._lock:
            return self._credential

    def invalidate(self) -> None:
        """Drop the cached credential (e.g. after a revocation or a 401 from the server)."""
        with self._lock:
            self._credential = None

    # ------------------------------------------------------------------ acquire / renew
    def acquire(self, *, ttl_seconds: Optional[int] = None) -> Credential:
        """Issue a fresh credential for the client's agent/instance and cache it."""
        agent_id = self._client.agent_id
        instance_id = self._client.instance_id
        if not agent_id or not instance_id:
            raise ValidationError("client is not bound to an agent instance")
        csr = self.key.csr(agent_id, instance_id)
        body = {"agent_id": agent_id, "instance_id": instance_id,
                "public_key": csr["public_key"], "pop_signature": csr["pop_signature"]}
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        elif self._client.config.default_credential_ttl_seconds is not None:
            body["ttl_seconds"] = self._client.config.default_credential_ttl_seconds
        resp = self._client._transport.request(
            "POST", "/v1/credentials/issue", body=body,
            idempotency_key=self._client._new_idempotency_key("issue"),
            headers=self._client._provision_headers())
        cred = Credential.from_dict(resp.body or {})
        if not cred.credential_id or not cred.token:
            raise AuthenticationError("credential issuance returned an incomplete credential")
        with self._lock:
            self._credential = cred
        return cred

    def renew(self) -> Credential:
        """Rotate the current credential (new keypair) and cache the replacement."""
        with self._lock:
            old = self._credential
        if old is None:
            return self.acquire()
        csr = self.key.csr(self._client.agent_id, self._client.instance_id)
        body = {"credential_id": old.credential_id, "public_key": csr["public_key"],
                "pop_signature": csr["pop_signature"]}
        resp = self._client._transport.request("POST", "/v1/credentials/rotate", body=body,
                                               headers=self._client._provision_headers())
        cred = Credential.from_dict(resp.body or {})
        with self._lock:
            self._credential = cred
        return cred

    def ensure_valid(self, *, ttl_seconds: Optional[int] = None) -> Credential:
        """Return a usable credential, acquiring or renewing as needed. Raises if it cannot."""
        with self._lock:
            cred = self._credential
        if cred is None:
            return self.acquire(ttl_seconds=ttl_seconds)
        if cred.is_expired(self._clock(), skew_seconds=self._skew):
            return self.renew()
        return cred

    # ------------------------------------------------------------------ status
    def status(self) -> dict:
        """Ask the server for the authoritative status of the cached credential."""
        with self._lock:
            cred = self._credential
        if cred is None:
            return {"credential_id": None, "status": "none"}
        resp = self._client._transport.request(
            "GET", f"/v1/credentials/{cred.credential_id}/status",
            headers=self._client._provision_headers())
        return resp.body if isinstance(resp.body, dict) else {"status": "unknown"}

    def assert_usable(self) -> Credential:
        """Raise a typed error if the cached credential is expired or revoked."""
        cred = self.ensure_valid()
        st = self.status().get("status")
        if st == "revoked":
            self.invalidate()
            raise CredentialRevokedError("credential has been revoked")
        if st == "expired":
            self.invalidate()
            raise CredentialExpiredError("credential has expired")
        return cred
