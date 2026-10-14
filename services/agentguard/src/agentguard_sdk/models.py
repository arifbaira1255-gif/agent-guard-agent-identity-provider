"""Typed SDK models. Immutable, secret-safe (``repr`` never prints bearer material)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Tuple


def _parse_iso(value: Optional[str]) -> Optional[float]:
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    org_id: str
    agent_name: str
    agent_type: str
    owner: str
    capabilities: Tuple[str, ...] = ()
    environment: str = ""
    status: str = ""
    fingerprint: str = ""
    spiffe_id: Optional[str] = None
    parent_agent_id: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "AgentIdentity":
        return cls(
            agent_id=d.get("agent_id", ""), org_id=d.get("org_id", ""),
            agent_name=d.get("agent_name", ""), agent_type=d.get("agent_type", ""),
            owner=d.get("owner", ""), capabilities=tuple(d.get("capabilities") or ()),
            environment=d.get("environment", ""), status=d.get("status", ""),
            fingerprint=d.get("fingerprint", ""), spiffe_id=d.get("spiffe_id"),
            parent_agent_id=d.get("parent_agent_id"))


@dataclass(frozen=True)
class Credential:
    """A short-lived Agent Passport credential. ``token`` is bearer material: never logged."""

    credential_id: str
    agent_id: str
    instance_id: str
    org_id: str
    issued_at: str = ""
    expires_at: str = ""
    capabilities: Tuple[str, ...] = ()
    spiffe_id: Optional[str] = None
    token: str = field(default="", repr=False)

    def __repr__(self) -> str:
        return (f"Credential(credential_id={self.credential_id!r}, agent_id={self.agent_id!r}, "
                f"instance_id={self.instance_id!r}, expires_at={self.expires_at!r}, token=<redacted>)")

    @property
    def expires_at_epoch(self) -> Optional[float]:
        return _parse_iso(self.expires_at)

    def expires_in(self, now: Optional[float] = None) -> float:
        exp = self.expires_at_epoch
        if exp is None:
            return 0.0
        return exp - (now if now is not None else time.time())

    def is_expired(self, now: Optional[float] = None, *, skew_seconds: float = 0.0) -> bool:
        return self.expires_in(now) <= skew_seconds

    @classmethod
    def from_dict(cls, d: dict) -> "Credential":
        return cls(
            credential_id=d.get("credential_id", ""), agent_id=d.get("agent_id", ""),
            instance_id=d.get("instance_id", ""), org_id=d.get("org_id", ""),
            issued_at=d.get("issued_at", ""), expires_at=d.get("expires_at", ""),
            capabilities=tuple(d.get("capabilities") or ()), spiffe_id=d.get("spiffe_id"),
            token=d.get("token", ""))


@dataclass(frozen=True)
class Decision:
    """The outcome of an authorization request. ``allowed`` is the ONLY thing that gates execution."""

    allowed: bool
    reason: str = ""
    decision_id: Optional[str] = None
    policy: Optional[str] = None
    obligations: Tuple[dict, ...] = ()
    correlation_id: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "Decision":
        return cls(
            allowed=bool(d.get("allowed")),
            reason=d.get("reason", "") or "",
            decision_id=d.get("decision_id"), policy=d.get("policy"),
            obligations=tuple(d.get("obligations") or ()),
            correlation_id=d.get("correlation_id"))

    @classmethod
    def deny(cls, reason: str, *, correlation_id: Optional[str] = None) -> "Decision":
        return cls(False, reason, correlation_id=correlation_id)


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: str = ""
    agent_id: Optional[str] = None
    instance_id: Optional[str] = None
    org_id: Optional[str] = None
    capabilities: Tuple[str, ...] = ()
    correlation_id: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "VerificationResult":
        return cls(
            valid=bool(d.get("valid")), reason=d.get("reason", "") or "",
            agent_id=d.get("agent_id"), instance_id=d.get("instance_id"), org_id=d.get("org_id"),
            capabilities=tuple(d.get("capabilities") or ()),
            correlation_id=d.get("correlation_id"))


@dataclass(frozen=True)
class SecurityEvent:
    event_type: str
    outcome: str = "ok"
    correlation_id: Optional[str] = None
    agent_id: Optional[str] = None
    instance_id: Optional[str] = None
    org_id: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    reason: Optional[str] = None
    metadata: Optional[dict] = None

    def to_dict(self) -> dict:
        out: dict = {"event_type": self.event_type, "outcome": self.outcome}
        for k in ("correlation_id", "agent_id", "instance_id", "org_id", "action", "resource",
                  "reason"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v
        if self.metadata:
            out["metadata"] = self.metadata
        return out


@dataclass(frozen=True)
class ToolCall:
    """A normalized tool/action invocation an agent wants to perform."""

    tool: str
    arguments: dict = field(default_factory=dict)
    resource: Optional[str] = None
    context: Optional[dict] = None

    def action(self) -> str:
        return f"tool:{self.tool}"

    def to_authorization_body(self) -> dict:
        body: dict[str, Any] = {"action": self.action(), "resource": self.resource or self.tool}
        ctx = dict(self.context or {})
        ctx.setdefault("tool", self.tool)
        ctx.setdefault("arguments", self.arguments)
        body["context"] = ctx
        return body
