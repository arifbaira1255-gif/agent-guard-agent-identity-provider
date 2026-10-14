"""Phase 4 egress/DLP domain models.

ADDITIVE, immutable models for the egress-security and DLP planes. Nothing here holds secrets: an
egress policy record is a *rule* (a destination class, a protocol, a port set, an action), and a DLP
rule is a *pattern* (a regex + a severity + an action). Neither ever stores the sensitive content it
is designed to detect.

Key types
---------
* :class:`Protocol` / :class:`EgressOutcome` / :class:`DlpAction` / :class:`DlpSeverity` /
  :class:`AddressClass` -- closed vocabularies so an unknown value is detectable and denied.
* :class:`EgressPolicyRecord` -- a tenant-scoped egress rule: which destinations are reachable, over
  which protocols/ports, with which action, and the limits that apply.
* :class:`RateLimitSpec` -- a bounded connection/request rate limit.
* :class:`DlpRule` -- a configurable detection rule (pattern, severity, action, redaction strategy).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import FrozenSet, Optional, Tuple

from ..core.models import iso  # reuse the existing ISO-8601 formatter


# --------------------------------------------------------------------------- vocabularies
class Protocol(str, enum.Enum):
    """The transport protocol an egress request may use. Closed set => unknown is explicit."""

    HTTPS = "https"
    HTTP = "http"
    TCP = "tcp"
    TLS = "tls"

    @classmethod
    def coerce(cls, value) -> Optional["Protocol"]:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None


class EgressOutcome(str, enum.Enum):
    """The four explicit egress outcomes. There is no implicit fifth state."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    INDETERMINATE = "INDETERMINATE"


class DlpAction(str, enum.Enum):
    """What to do when a DLP rule matches."""

    ALLOW = "allow"                    # record the finding, let the payload through unchanged
    REDACT = "redact"                  # replace the matched span, then allow
    BLOCK = "block"                    # refuse the outbound request
    REQUIRE_APPROVAL = "require_approval"   # hold for a human decision

    @classmethod
    def coerce(cls, value) -> Optional["DlpAction"]:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None


class DlpSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def coerce(cls, value) -> Optional["DlpSeverity"]:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {DlpSeverity.LOW: 0, DlpSeverity.MEDIUM: 1, DlpSeverity.HIGH: 2,
                  DlpSeverity.CRITICAL: 3}


class AddressClass(str, enum.Enum):
    """The class of a resolved IP address. Only ``PUBLIC`` is reachable by default."""

    PUBLIC = "public"
    PRIVATE = "private"                # RFC1918 / ULA
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"          # 169.254.0.0/16, fe80::/10
    CLOUD_METADATA = "cloud_metadata"  # 169.254.169.254 and friends
    CGNAT = "cgnat"                    # 100.64.0.0/10
    MULTICAST = "multicast"
    RESERVED = "reserved"              # 0.0.0.0/8, 240.0.0.0/4, documentation, benchmarking
    UNSPECIFIED = "unspecified"        # 0.0.0.0 / ::
    UNKNOWN = "unknown"                # could not be parsed


#: Address classes that are NEVER reachable, regardless of policy. This is the SSRF floor: a
#: destination that resolves to any of these is denied before policy is even consulted.
BLOCKED_ADDRESS_CLASSES = frozenset({
    AddressClass.PRIVATE, AddressClass.LOOPBACK, AddressClass.LINK_LOCAL,
    AddressClass.CLOUD_METADATA, AddressClass.CGNAT, AddressClass.MULTICAST,
    AddressClass.RESERVED, AddressClass.UNSPECIFIED, AddressClass.UNKNOWN,
})

#: The well-known cloud metadata endpoints (AWS/GCP/Azure/OpenStack/DigitalOcean). These are blocked
#: by address class already; the explicit list makes the intent auditable and catches hostnames.
CLOUD_METADATA_HOSTS = frozenset({
    "169.254.169.254", "metadata.google.internal", "metadata.goog",
    "169.254.170.2", "fd00:ec2::254", "metadata.azure.com",
})

ID_MAX = 200
HOST_MAX = 253


# --------------------------------------------------------------------------- rate limits
@dataclass(frozen=True)
class RateLimitSpec:
    """A bounded rate limit. ``per_second`` is the sustained rate; ``burst`` the bucket depth."""

    per_second: float = 10.0
    burst: int = 20

    def __post_init__(self):
        if self.per_second <= 0:
            raise ValueError("per_second must be positive")
        if self.burst < 1:
            raise ValueError("burst must be >= 1")


# --------------------------------------------------------------------------- egress policy
@dataclass(frozen=True)
class EgressPolicyRecord:
    """A tenant-scoped egress rule.

    A rule matches a request when the request's host matches one of ``host_patterns`` (exact host or
    a ``*.suffix`` wildcard), the protocol is in ``protocols`` and the port is in ``ports``. The
    ``action`` then applies. Rules are evaluated most-specific-first; an explicit DENY always wins
    over an ALLOW at the same specificity.

    ``host_patterns`` are the ONLY place a wildcard is permitted, and only as a leading ``*.`` label
    (never a bare ``*``, never a mid-label wildcard) -- so a rule can never silently match everything.
    """

    policy_id: str
    org_id: str
    name: str
    host_patterns: Tuple[str, ...]
    protocols: FrozenSet[Protocol] = frozenset({Protocol.HTTPS})
    ports: FrozenSet[int] = frozenset({443})
    action: EgressOutcome = EgressOutcome.ALLOW
    priority: int = 100
    rate_limit: Optional[RateLimitSpec] = None
    max_request_bytes: Optional[int] = None
    max_response_bytes: Optional[int] = None
    timeout_ms: Optional[int] = None
    allow_redirects: bool = False
    dlp_enabled: bool = True
    description: str = ""
    enabled: bool = True
    created_at: float = 0.0
    updated_at: float = 0.0
    created_by: str = ""

    def public_dict(self) -> dict:
        return {
            "policy_id": self.policy_id, "org_id": self.org_id, "name": self.name,
            "host_patterns": list(self.host_patterns),
            "protocols": sorted(p.value for p in self.protocols),
            "ports": sorted(self.ports), "action": self.action.value, "priority": self.priority,
            "rate_limit": ({"per_second": self.rate_limit.per_second, "burst": self.rate_limit.burst}
                           if self.rate_limit else None),
            "max_request_bytes": self.max_request_bytes,
            "max_response_bytes": self.max_response_bytes, "timeout_ms": self.timeout_ms,
            "allow_redirects": self.allow_redirects, "dlp_enabled": self.dlp_enabled,
            "description": self.description, "enabled": self.enabled,
            "created_at": iso(self.created_at), "updated_at": iso(self.updated_at),
        }


# --------------------------------------------------------------------------- DLP rules
@dataclass(frozen=True)
class DlpRule:
    """A configurable DLP detection rule.

    ``pattern`` is a Python regular expression. ``redaction`` is the replacement template used when
    ``action`` is REDACT (``\\1``-style backreferences are supported). ``min_entropy`` (optional)
    additionally requires the matched span to look random, which reduces false positives on
    placeholder-looking values.

    A rule NEVER stores the content it matches: findings carry the rule id, the severity, the span
    offsets and a *redacted* preview only.
    """

    rule_id: str
    name: str
    pattern: str
    severity: DlpSeverity = DlpSeverity.HIGH
    action: DlpAction = DlpAction.REDACT
    category: str = "custom"
    redaction: str = "[REDACTED]"
    min_entropy: Optional[float] = None
    enabled: bool = True
    description: str = ""

    def public_dict(self) -> dict:
        return {"rule_id": self.rule_id, "name": self.name, "severity": self.severity.value,
                "action": self.action.value, "category": self.category, "enabled": self.enabled,
                "description": self.description}


@dataclass
class DlpFinding:
    """One DLP match. Carries NO raw sensitive content -- only ids, offsets and a redacted preview."""

    rule_id: str
    category: str
    severity: str
    action: str
    location: str = ""            # a JSON-path-ish pointer to where the match was found
    span_start: int = 0
    span_end: int = 0
    preview: str = "[REDACTED]"

    def to_dict(self) -> dict:
        return {"rule_id": self.rule_id, "category": self.category, "severity": self.severity,
                "action": self.action, "location": self.location, "span_start": self.span_start,
                "span_end": self.span_end, "preview": self.preview}


@dataclass
class DlpResult:
    """The outcome of inspecting one payload."""

    outcome: DlpOutcome
    findings: Tuple[DlpFinding, ...] = ()
    redacted_payload: Optional[object] = None
    reason: str = ""
    inspected_bytes: int = 0
    truncated: bool = False

    @property
    def blocked(self) -> bool:
        return self.outcome is DlpOutcome.BLOCK

    @property
    def requires_approval(self) -> bool:
        return self.outcome is DlpOutcome.REQUIRE_APPROVAL

    @property
    def rule_ids(self) -> Tuple[str, ...]:
        return tuple(sorted({f.rule_id for f in self.findings}))

    def to_dict(self) -> dict:
        return {"outcome": self.outcome.value, "reason": self.reason,
                "findings": [f.to_dict() for f in self.findings],
                "rule_ids": list(self.rule_ids), "inspected_bytes": self.inspected_bytes,
                "truncated": self.truncated}


class DlpOutcome(str, enum.Enum):
    """The aggregate DLP outcome for a payload."""

    CLEAN = "clean"
    REDACTED = "redacted"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    INDETERMINATE = "indeterminate"    # inspection could not complete -> fail closed


# --------------------------------------------------------------------------- audit event
@dataclass
class EgressAuditEvent:
    """One audited egress/DLP decision. No secrets, no payloads -- ids and reason codes only."""

    event_id: str
    ts: float
    event: str
    org_id: Optional[str] = None
    agent_id: Optional[str] = None
    instance_id: Optional[str] = None
    destination: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    resource_id: Optional[str] = None
    operation: Optional[str] = None
    decision: str = ""
    reason: Optional[str] = None
    outcome: str = "ok"
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    dlp_rule_ids: Tuple[str, ...] = ()
    dlp_severity: Optional[str] = None
    resolved_ips: Tuple[str, ...] = ()
    address_class: Optional[str] = None
    actor_user_id: Optional[str] = None
    correlation_id: Optional[str] = None
    latency_ms: Optional[int] = None
    extra: dict = field(default_factory=dict)
