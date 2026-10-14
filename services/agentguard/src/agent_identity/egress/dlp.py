"""Data Loss Prevention: modular detection, classification, redaction and decisions.

The DLP pipeline inspects an OUTBOUND payload and decides whether it may leave. It is deliberately
modular: a :class:`DlpRule` is data (a regex + severity + action), so an organisation can add its own
patterns without touching code.

What it detects (default rule set)
----------------------------------
* **API keys / access tokens** -- AWS, GCP, GitHub, Slack, Stripe, generic bearer/JWT, private keys.
* **Passwords / private credentials** -- ``password=``, ``secret:``, connection strings, PEM blocks.
* **Personal information (PII)** -- email, phone, SSN, national IDs, IP addresses.
* **Financial identifiers** -- credit-card numbers (Luhn-checked), IBAN, bank-account-like values.
* **Sensitive enterprise data** -- internal-only markers, classification banners.
* **Organisation-specific patterns** -- supplied per tenant.

Honest limits (documented, not hidden)
--------------------------------------
* Detection is **pattern + context based**, not semantic. It cannot understand meaning; it will have
  false positives (a test card number) and false negatives (a secret in an unexpected format).
* Encoded payloads are decoded **once** (base64 / percent / hex) and re-scanned; deeply nested or
  multiply-encoded content may evade detection. This is stated, not claimed away.
* Oversized payloads are NOT silently passed: they are reported as ``INDETERMINATE`` and the
  configured ``dlp_failure_action`` (block by default) applies.
* **No sensitive content is ever stored.** A finding carries the rule id, severity, span offsets and
  a fixed ``[REDACTED]`` preview -- never the matched text.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .models import DlpAction, DlpFinding, DlpOutcome, DlpResult, DlpRule, DlpSeverity


# --------------------------------------------------------------------------- default rules
def _rule(rule_id, name, pattern, severity, action, category, redaction="[REDACTED]",
          min_entropy=None, description="") -> DlpRule:
    return DlpRule(rule_id=rule_id, name=name, pattern=pattern, severity=severity, action=action,
                   category=category, redaction=redaction, min_entropy=min_entropy,
                   description=description)


#: The curated default rule set. Ordered most-specific-first; the engine applies every matching rule
#: and combines the outcomes (block > require_approval > redact > allow).
DEFAULT_RULES: Tuple[DlpRule, ...] = (
    # ---- private keys / credentials (highest severity) --------------------------------------
    _rule("dlp.private_key", "PEM private key",
          r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
          DlpSeverity.CRITICAL, DlpAction.BLOCK, "credentials",
          description="A PEM-encoded private key block"),
    _rule("dlp.aws_secret", "AWS secret access key",
          r"(?i)aws[_\- ]?(?:secret[_\- ]?)?access[_\- ]?key[\"'\s:=]{1,4}([A-Za-z0-9/+=]{40})",
          DlpSeverity.CRITICAL, DlpAction.BLOCK, "api_keys", min_entropy=3.0,
          description="An AWS secret access key assignment"),
    _rule("dlp.aws_access_key_id", "AWS access key id",
          r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b",
          DlpSeverity.HIGH, DlpAction.REDACT, "api_keys",
          description="An AWS access key id"),
    _rule("dlp.gcp_service_account", "GCP service-account key",
          r"\"type\"\s*:\s*\"service_account\"",
          DlpSeverity.CRITICAL, DlpAction.BLOCK, "credentials",
          description="A GCP service-account JSON key"),
    _rule("dlp.github_token", "GitHub token",
          r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b",
          DlpSeverity.CRITICAL, DlpAction.BLOCK, "api_keys",
          description="A GitHub personal access / app token"),
    _rule("dlp.slack_token", "Slack token",
          r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
          DlpSeverity.CRITICAL, DlpAction.BLOCK, "api_keys",
          description="A Slack API token"),
    _rule("dlp.stripe_key", "Stripe secret key",
          r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
          DlpSeverity.CRITICAL, DlpAction.BLOCK, "api_keys",
          description="A Stripe secret/restricted key"),
    _rule("dlp.jwt", "JSON Web Token",
          r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
          DlpSeverity.HIGH, DlpAction.REDACT, "api_keys",
          description="A JWT (header.payload.signature)"),
    _rule("dlp.bearer", "Bearer token",
          r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{20,}=*)",
          DlpSeverity.HIGH, DlpAction.REDACT, "api_keys", min_entropy=3.0,
          description="An Authorization: Bearer token"),
    _rule("dlp.generic_api_key", "Generic API key assignment",
          r"(?i)\b(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret)"
          r"[\"'\s:=]{1,4}([A-Za-z0-9\-._~+/]{16,})",
          DlpSeverity.HIGH, DlpAction.REDACT, "api_keys", min_entropy=3.0,
          description="A generic api_key/token/secret assignment"),
    _rule("dlp.password", "Password / secret assignment",
          r"(?i)\b(?:password|passwd|pwd|secret|passphrase)[\"'\s:=]{1,4}([^\s\"',;]{6,})",
          DlpSeverity.HIGH, DlpAction.REDACT, "credentials",
          description="A password/secret assignment"),
    _rule("dlp.connection_string", "Connection string with credentials",
          r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:@/]+:[^\s@/]+@",
          DlpSeverity.CRITICAL, DlpAction.BLOCK, "credentials",
          description="A database/broker URI containing a password"),

    # ---- financial identifiers --------------------------------------------------------------
    _rule("dlp.credit_card", "Payment card number",
          r"\b(?:\d[ -]?){13,19}\b",
          DlpSeverity.CRITICAL, DlpAction.BLOCK, "financial",
          description="A 13-19 digit number (Luhn-validated before it counts)"),
    _rule("dlp.iban", "IBAN",
          r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
          DlpSeverity.HIGH, DlpAction.REDACT, "financial",
          description="An International Bank Account Number"),

    # ---- personal information ---------------------------------------------------------------
    _rule("dlp.email", "Email address",
          r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
          DlpSeverity.MEDIUM, DlpAction.REDACT, "pii",
          description="An email address"),
    _rule("dlp.ssn", "US Social Security Number",
          r"\b\d{3}-\d{2}-\d{4}\b",
          DlpSeverity.HIGH, DlpAction.REDACT, "pii",
          description="A US SSN"),
    _rule("dlp.phone", "Phone number",
          r"(?<!\d)(?:\+\d{1,3}[ .\-]?)?(?:\(\d{2,4}\)[ .\-]?)?\d{3}[ .\-]?\d{3,4}[ .\-]?\d{3,4}(?!\d)",
          DlpSeverity.LOW, DlpAction.REDACT, "pii",
          description="A phone number"),

    # ---- sensitive enterprise data ----------------------------------------------------------
    _rule("dlp.classification_banner", "Internal classification marker",
          r"(?i)\b(?:CONFIDENTIAL|INTERNAL ONLY|RESTRICTED|DO NOT DISTRIBUTE|PROPRIETARY)\b",
          DlpSeverity.MEDIUM, DlpAction.REQUIRE_APPROVAL, "enterprise",
          description="An internal classification banner"),
)


# --------------------------------------------------------------------------- helpers
def shannon_entropy(value: str) -> float:
    """Shannon entropy (bits/char) of a string. Used to reject placeholder-looking matches."""
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def luhn_valid(number: str) -> bool:
    """Luhn checksum. Used to keep the credit-card rule from firing on arbitrary digit runs."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _decode_candidates(text: str) -> List[str]:
    """Return decoded variants of ``text`` for a single round of encoding.

    Handles base64 (standard + urlsafe), percent-encoding and hex. Only substrings that look like
    encoded data are decoded, and the result is bounded, so this cannot blow up on a large payload.
    """
    out: List[str] = []
    # percent-encoding
    if "%" in text:
        try:
            dec = urllib.parse.unquote(text)
            if dec != text:
                out.append(dec)
        except Exception:  # noqa: BLE001
            pass
    # base64-ish runs (>= 16 chars, valid alphabet, padded length)
    for m in re.finditer(r"[A-Za-z0-9+/_\-]{16,}={0,2}", text):
        token = m.group(0)
        if len(token) > 8192:
            continue
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(token + "=" * (-len(token) % 4))
                dec = raw.decode("utf-8", errors="strict")
                if dec and dec.isprintable() and dec != token:
                    out.append(dec)
                    break
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
    # hex runs
    for m in re.finditer(r"\b[0-9a-fA-F]{32,}\b", text):
        token = m.group(0)
        if len(token) % 2:
            continue
        try:
            dec = bytes.fromhex(token).decode("utf-8", errors="strict")
            if dec and dec.isprintable():
                out.append(dec)
        except (ValueError, UnicodeDecodeError):
            continue
    return out


# --------------------------------------------------------------------------- detector
class Detector:
    """A compiled DLP rule. Immutable after construction."""

    def __init__(self, rule: DlpRule):
        self.rule = rule
        try:
            self._re = re.compile(rule.pattern)
        except re.error as exc:  # pragma: no cover - validated at registration
            raise ValueError(f"invalid DLP pattern for {rule.rule_id}: {exc}") from exc

    def scan(self, text: str, *, location: str = "") -> List[DlpFinding]:
        """Find every match of this rule in ``text``. Applies the entropy gate and the Luhn gate."""
        findings: List[DlpFinding] = []
        for m in self._re.finditer(text):
            span = m.group(0)
            # entropy gate: reject low-entropy (placeholder-looking) matches
            if self.rule.min_entropy is not None:
                candidate = m.group(1) if m.groups() else span
                if shannon_entropy(candidate) < self.rule.min_entropy:
                    continue
            # Luhn gate for the payment-card rule
            if self.rule.rule_id == "dlp.credit_card" and not luhn_valid(span):
                continue
            findings.append(DlpFinding(
                rule_id=self.rule.rule_id, category=self.rule.category,
                severity=self.rule.severity.value, action=self.rule.action.value,
                location=location, span_start=m.start(), span_end=m.end(),
                preview="[REDACTED]"))
        return findings


#: Credential-like KEY names. When a structured payload has a key matching one of these, the
#: associated VALUE is redacted unconditionally -- the value need not independently match a pattern.
#: This is the contextual-inspection leg: ``{"password": "hunter2"}`` and ``{"token": "<anything>"}``
#: are redacted even when the value would not match a detector on its own.
_CREDENTIAL_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|passphrase|secret|client_secret|consumer_secret|"
    r"api[_\-\s]?key|apikey|access[_\-\s]?token|auth[_\-\s]?token|refresh[_\-\s]?token|"
    r"bearer[_\-\s]?token|token|authorization|set[_\-\s]?cookie|private[_\-\s]?key)")


def is_credential_key(key: str) -> bool:
    """True when ``key`` names a credential (case-insensitive)."""
    return bool(_CREDENTIAL_KEY_RE.fullmatch((key or "").strip()))


class Redactor:
    """Applies redaction to a payload according to the matched rules.

    Redaction is performed by the detector regexes; the engine additionally redacts the VALUE of any
    dict key that :func:`is_credential_key` recognises (contextual redaction).
    """

    def __init__(self, detectors: List[Detector]):
        self._by_id = {d.rule.rule_id: d for d in detectors}

    def redact_text(self, text: str, rule_ids: Tuple[str, ...]) -> str:
        out = text
        for rid in rule_ids:
            det = self._by_id.get(rid)
            if det is None or det.rule.action is not DlpAction.REDACT:
                continue
            out = det._re.sub(det.rule.redaction, out)
        return out

    def redact_value(self, value: Any) -> str:
        """Redact an arbitrary scalar value to a safe string."""
        if value is None:
            return "[REDACTED]"
        if isinstance(value, (str, int, float, bool)):
            return "[REDACTED]"
        try:
            import json
            return "[REDACTED]"
        except Exception:  # noqa: BLE001
            return "[REDACTED]"


# --------------------------------------------------------------------------- engine
class DlpEngine:
    """The DLP pipeline: inspect a payload, classify findings, decide, and redact.

    The engine is stateless and thread-safe (compiled regexes are read-only).
    """

    def __init__(self, rules: Optional[Tuple[DlpRule, ...]] = None, *, max_inspect_bytes: int = 512 * 1024,
                 max_depth: int = 12, inspect_encoded: bool = True, failure_action: str = "block"):
        if failure_action not in ("block", "require_approval"):
            raise ValueError("failure_action must be 'block' or 'require_approval'")
        self.rules = tuple(rules if rules is not None else DEFAULT_RULES)
        self.detectors = [Detector(r) for r in self.rules if r.enabled]
        self.redactor = Redactor(self.detectors)
        self.max_inspect_bytes = max_inspect_bytes
        self.max_depth = max_depth
        self.inspect_encoded = inspect_encoded
        self.failure_action = failure_action

    # ------------------------------------------------------------------ public API
    def inspect(self, payload: Any) -> DlpResult:
        """Inspect an outbound payload (str, bytes, dict, list, or scalar).

        Returns a :class:`DlpResult`. Never raises for a normal payload; an inspection failure
        (oversized / undecodable) yields ``INDETERMINATE`` so the caller can fail closed.
        """
        try:
            text, truncated = self._flatten(payload)
        except _TooLarge:
            return DlpResult(outcome=DlpOutcome.INDETERMINATE, reason="payload_too_large",
                             inspected_bytes=self.max_inspect_bytes, truncated=True)
        except Exception as exc:  # noqa: BLE001 - any inspection error fails closed
            return DlpResult(outcome=DlpOutcome.INDETERMINATE,
                             reason=f"inspection_error:{type(exc).__name__}")

        findings: List[DlpFinding] = []
        for det in self.detectors:
            findings.extend(det.scan(text))
        if self.inspect_encoded:
            for variant in _decode_candidates(text):
                for det in self.detectors:
                    findings.extend(det.scan(variant, location="decoded"))

        # Contextual detection: a credential-like KEY with a non-empty value is a finding even when
        # no detector matches the value's own text.
        findings.extend(self._contextual_findings(payload))

        if not findings:
            return DlpResult(outcome=DlpOutcome.CLEAN, findings=(), inspected_bytes=len(text),
                             truncated=truncated)

        outcome = self._combine(findings)
        redacted = None
        if outcome is DlpOutcome.REDACTED:
            redacted = self._redact_payload(payload, tuple(sorted({f.rule_id for f in findings})))
        return DlpResult(outcome=outcome, findings=tuple(findings), redacted_payload=redacted,
                         reason=self._reason(outcome, findings), inspected_bytes=len(text),
                         truncated=truncated)

    def _contextual_findings(self, payload: Any) -> List[DlpFinding]:
        """Walk a structured payload and emit a REDACT finding for every credential-like key whose
        value is non-empty. Bounded by ``max_depth``; never walks non-container scalars."""
        out: List[DlpFinding] = []

        def walk(node: Any, depth: int) -> None:
            if depth > self.max_depth:
                return
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(k, str) and is_credential_key(k) and v not in (None, "", []):
                        out.append(DlpFinding(rule_id="dlp.credential_key", category="credentials",
                                              severity=DlpSeverity.HIGH.value,
                                              action=DlpAction.REDACT.value,
                                              location=f"key:{k}",
                                              preview="[REDACTED]"))
                    else:
                        walk(v, depth + 1)
            elif isinstance(node, list):
                for v in node:
                    walk(v, depth + 1)

        walk(payload, 0)
        return out

    # ------------------------------------------------------------------ internals
    def _combine(self, findings: List[DlpFinding]) -> DlpOutcome:
        """Combine per-finding actions. block > require_approval > redact > allow."""
        actions = {f.action for f in findings}
        if DlpAction.BLOCK.value in actions:
            return DlpOutcome.BLOCK
        if DlpAction.REQUIRE_APPROVAL.value in actions:
            return DlpOutcome.REQUIRE_APPROVAL
        if DlpAction.REDACT.value in actions:
            return DlpOutcome.REDACTED
        return DlpOutcome.CLEAN

    @staticmethod
    def _reason(outcome: DlpOutcome, findings: List[DlpFinding]) -> str:
        cats = sorted({f.category for f in findings})
        return f"dlp_{outcome.value}:{','.join(cats)}"

    def _flatten(self, payload: Any) -> Tuple[str, bool]:
        """Flatten a payload to a single inspectable string, bounded by ``max_inspect_bytes``.

        Structured payloads are walked to ``max_depth``; string leaves are joined with a separator
        that cannot itself create a false match boundary. A payload larger than the ceiling raises
        :class:`_TooLarge` (the caller maps that to INDETERMINATE).
        """
        parts: List[str] = []
        total = 0

        def add(s: str) -> None:
            nonlocal total
            total += len(s)
            if total > self.max_inspect_bytes:
                raise _TooLarge()
            parts.append(s)

        def walk(node: Any, depth: int) -> None:
            if depth > self.max_depth:
                add("[DEPTH_LIMIT]")
                return
            if node is None:
                return
            if isinstance(node, str):
                add(node)
            elif isinstance(node, (int, float, bool)):
                add(str(node))
            elif isinstance(node, bytes):
                add(node.decode("utf-8", errors="replace"))
            elif isinstance(node, dict):
                for k, v in node.items():
                    add(str(k))
                    walk(v, depth + 1)
            elif isinstance(node, (list, tuple, set)):
                for v in node:
                    walk(v, depth + 1)
            else:
                add(str(node))

        if isinstance(payload, (bytes, bytearray)):
            text = bytes(payload).decode("utf-8", errors="replace")
            if len(text) > self.max_inspect_bytes:
                raise _TooLarge()
            return text, False
        if isinstance(payload, str):
            if len(payload) > self.max_inspect_bytes:
                raise _TooLarge()
            return payload, False
        walk(payload, 0)
        return "\n".join(parts), False

    def _redact_payload(self, payload: Any, rule_ids: Tuple[str, ...]) -> Any:
        """Return a redacted copy of the payload (structure preserved)."""
        if isinstance(payload, str):
            return self.redactor.redact_text(payload, rule_ids)
        if isinstance(payload, (bytes, bytearray)):
            return self.redactor.redact_text(
                bytes(payload).decode("utf-8", errors="replace"), rule_ids).encode("utf-8")

        def walk(node: Any, depth: int) -> Any:
            if depth > self.max_depth:
                return node
            if isinstance(node, str):
                return self.redactor.redact_text(node, rule_ids)
            if isinstance(node, dict):
                out = {}
                for k, v in node.items():
                    # Contextual redaction: a credential-like KEY redacts its value outright.
                    if isinstance(k, str) and is_credential_key(k):
                        out[k] = "[REDACTED]"
                    else:
                        out[k] = walk(v, depth + 1)
                return out
            if isinstance(node, list):
                return [walk(v, depth + 1) for v in node]
            if isinstance(node, tuple):
                return tuple(walk(v, depth + 1) for v in node)
            return node

        return walk(payload, 0)


class _TooLarge(Exception):
    """Internal: the payload exceeded the inspection ceiling."""
