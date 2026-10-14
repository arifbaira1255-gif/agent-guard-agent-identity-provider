"""Destination policy evaluation: host/protocol/port matching and allow/deny resolution.

A request is matched against the tenant's egress policy records. Matching is deliberately strict:

* a host pattern is either an EXACT host (``api.stripe.com``) or a single leading-label wildcard
  (``*.stripe.com``). A bare ``*``, a mid-label wildcard (``api.*.com``) and a suffix-only pattern
  (``.stripe.com``) are all rejected at registration -- a rule can never silently match everything.
* protocol and port must both be in the rule's sets.
* the most specific matching rule wins (exact host beats wildcard; higher ``priority`` beats lower).
* an explicit DENY always beats an ALLOW at the same specificity.

If no rule matches, the configured ``default_action`` applies (deny or require_approval -- never
allow).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .errors import EgressValidationError
from .models import EgressOutcome, EgressPolicyRecord, Protocol

_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
                      r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")
_WILDCARD_RE = re.compile(r"^\*\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
                          r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$")


def validate_host_pattern(pattern: str) -> str:
    """Validate a host pattern. Returns the normalised (lowercased) pattern.

    Rejects: empty, bare ``*``, mid-label wildcards, leading dots, whitespace, over-long values.
    """
    if not isinstance(pattern, str) or not pattern.strip():
        raise EgressValidationError("host pattern is required")
    p = pattern.strip().lower()
    if len(p) > 253:
        raise EgressValidationError("host pattern is too long")
    if p == "*" or p == "*.":
        raise EgressValidationError("a bare wildcard host pattern is not permitted")
    if "*" in p:
        if not _WILDCARD_RE.match(p):
            raise EgressValidationError("wildcard is only permitted as a leading '*.' label")
        return p
    if p.startswith("."):
        raise EgressValidationError("host pattern must not start with a dot")
    if not _HOST_RE.match(p):
        raise EgressValidationError("host pattern contains invalid characters")
    return p


def host_matches(pattern: str, host: str) -> bool:
    """True when ``host`` matches ``pattern`` (exact or leading ``*.`` wildcard)."""
    p = (pattern or "").strip().lower()
    h = (host or "").strip().lower().rstrip(".")
    if not p or not h:
        return False
    if p.startswith("*."):
        suffix = p[2:]
        # a wildcard matches exactly one-or-more labels under the suffix, never the apex itself
        return h.endswith("." + suffix) and h != suffix
    return h == p


@dataclass(frozen=True)
class PolicyVerdict:
    """The result of matching a request against the egress policy set."""

    action: EgressOutcome
    reason: str
    policy: Optional[EgressPolicyRecord] = None
    matched: bool = False

    @property
    def allowed(self) -> bool:
        return self.action is EgressOutcome.ALLOW


class DestinationPolicy:
    """Evaluates a destination against a set of egress policy records."""

    def __init__(self, *, default_action: str = "deny"):
        if default_action not in ("deny", "require_approval"):
            raise EgressValidationError("default_action must be 'deny' or 'require_approval'")
        self.default_action = default_action

    def evaluate(self, *, host: str, protocol: Protocol, port: int,
                 policies: List[EgressPolicyRecord]) -> PolicyVerdict:
        """Return the winning verdict for a destination.

        Specificity ordering: exact-host rules before wildcard rules; then higher ``priority``;
        then DENY before ALLOW. A disabled rule is ignored.
        """
        candidates: List[Tuple[int, int, int, EgressPolicyRecord]] = []
        for rec in policies:
            if not rec.enabled:
                continue
            if protocol not in rec.protocols:
                continue
            if port not in rec.ports:
                continue
            best_specificity = -1
            for pat in rec.host_patterns:
                if host_matches(pat, host):
                    # exact host = 2, wildcard = 1
                    spec = 1 if pat.startswith("*.") else 2
                    if spec > best_specificity:
                        best_specificity = spec
            if best_specificity < 0:
                continue
            # sort key: specificity desc, priority desc, deny-first (DENY must sort HIGHER)
            deny_first = 1 if rec.action is EgressOutcome.DENY else 0
            candidates.append((best_specificity, rec.priority, deny_first, rec))
        if not candidates:
            if self.default_action == "require_approval":
                return PolicyVerdict(EgressOutcome.REQUIRE_APPROVAL, "no_matching_policy",
                                     matched=False)
            return PolicyVerdict(EgressOutcome.DENY, "no_matching_policy", matched=False)
        candidates.sort(key=lambda c: (c[0], c[1], c[2]), reverse=True)
        winner = candidates[0][3]
        return PolicyVerdict(winner.action, f"policy:{winner.policy_id}", policy=winner, matched=True)
