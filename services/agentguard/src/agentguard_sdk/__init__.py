"""AgentGuard Universal Agent SDK \u2014 Python.

Production-grade client for AI agents that need to integrate with AgentGuard security controls:
agent registration and identity association, secure authentication, credential acquisition and
renewal, tool/action authorization, policy-decision enforcement, secure HTTP, request signing
(proof of possession), security-event reporting, correlation ids, structured errors, timeouts,
bounded retries, cancellation, and credential revocation/expiration handling.

The SDK is a THIN client over the existing AgentGuard control plane. It reuses the core
``agent_identity`` library for all cryptography (agent-side keys, CSR/proof formats, credential
model) and never re-implements identity, KMS, mTLS or authorization internals.

Quick start::

    from agentguard_sdk import AgentGuardClient, SdkConfig

    client = AgentGuardClient(SdkConfig(base_url="https://agentguard.internal"),
                              agent_id="agt_...", instance_id="my-agent-instance-...")
    client.ensure_credential()                       # authenticate
    decision = client.authorize(action="tool:send_email", resource="mailbox:ops")
    if decision.allowed:
        ...                                          # only now is it safe to act
"""
from .auth import AgentAuthenticator
from .authorization import (AuthorizationClient, DenyAllPdp, PolicyDecisionPoint, RemotePdp,
                            StaticPdp)
from .client import AgentGuardClient
from .config import SDK_VERSION, SdkConfig
from .credentials import CredentialManager
from .errors import (AgentGuardError, AuthenticationError, AuthorizationError, CancelledError,
                     ConfigurationError, ConflictError, CredentialExpiredError,
                     CredentialRevokedError, NotFoundError, PolicyUnavailableError,
                     RateLimitedError, ServerError, TimeoutError, TransportError, ValidationError)
from .events import SecurityEventReporter
from .models import (AgentIdentity, Credential, Decision, SecurityEvent, ToolCall,
                     VerificationResult)
from .transport import CancellationToken, Response, Transport

__all__ = [
    "AgentGuardClient", "SdkConfig", "SDK_VERSION",
    "AgentAuthenticator", "CredentialManager", "AuthorizationClient", "SecurityEventReporter",
    "PolicyDecisionPoint", "RemotePdp", "DenyAllPdp", "StaticPdp",
    "Transport", "CancellationToken", "Response",
    "AgentIdentity", "Credential", "Decision", "VerificationResult", "SecurityEvent", "ToolCall",
    "AgentGuardError", "ConfigurationError", "ValidationError", "TransportError", "TimeoutError",
    "CancelledError", "AuthenticationError", "CredentialExpiredError", "CredentialRevokedError",
    "AuthorizationError", "PolicyUnavailableError", "NotFoundError", "ConflictError",
    "RateLimitedError", "ServerError",
]
__version__ = SDK_VERSION
