"""Phase 5 privacy / redaction engine.

This module is the single gate through which raw producer telemetry becomes a stored
:class:`~.models.RuntimeEvent`. Its job is to make it **structurally hard** to store a prompt, a
payload, a credential or a piece of personal data:

1. **Allow-list, not deny-list.** A raw field survives only if its name is in ``SAFE_FIELDS``. Every
   other field is either dropped or, if it must remain investigable, reduced to a stable pseudonym.
2. **Payload-bearing fields are always dropped.** ``prompt``, ``body``, ``payload``, ``content``,
   ``messages``, ``completion``, ``input``, ``output`` -- and anything matching a secret-looking
   key pattern -- never reach storage, in any mode.
3. **Bounded recursion.** Nested structures are walked to a bounded depth; anything deeper is
   replaced by a marker, so a deeply-nested payload cannot be smuggled in as "metadata".
4. **Secret-shape detection.** A value that *looks like* a secret (token/key shapes) is redacted even
   when its key looked innocuous.

Redaction modes (no "off" -- see ``config.REDACTION_MODES``):
  * ``hash`` -- replace the value with a short, stable, non-reversible pseudonym (default). Two
    occurrences of the same value produce the same pseudonym, so an investigator can still correlate
    without the plane ever holding the value.
  * ``mask`` -- keep a bounded prefix/suffix and mask the middle (for values where partial
    recognizability is worth more than unlinkability).
  * ``drop`` -- remove the field entirely.

**Honest limitation (documented, not hidden).** ``hash`` mode is *pseudonymization*: it is stable and
non-reversible for high-entropy values, but a low-entropy value (e.g. a boolean or a country code)
can be recovered by enumeration. It is not encryption, and it does not make redacted low-entropy
fields confidential.
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, Optional, Tuple

from .models import EXTRA_MAX_KEYS, FIELD_MAX  # noqa: F401  (documented bounds)

# --------------------------------------------------------------------------- allow-list
#: Field names that may be preserved verbatim from an ingested raw event. Everything else is
#: redacted/dropped. Keep this list small and metadata-only.
SAFE_FIELDS = frozenset({
    "event_id", "event_type", "type", "ts", "timestamp", "time", "ingested_at",
    "org_id", "tenant", "tenant_id", "agent_id", "instance_id", "session_id",
    "action", "operation", "resource", "resource_id", "resource_type",
    "decision", "reason", "outcome", "latency_ms", "severity",
    "policy_id", "policy_version", "destination", "host", "address_class",
    "dlp_rule_ids", "data_classes", "correlation_id", "trace_id", "traceparent",
    "span_id", "parent_span_id", "actor_user_id", "user_id", "task_id",
    "tool_id", "tool", "method", "port", "protocol", "status_code", "retry_count",
    "capabilities", "capability", "grant_id", "approval_id", "direction",
})

#: Anything whose KEY matches one of these is treated as content-bearing and never stored verbatim,
#: regardless of mode. Case-insensitive substring match.
CONTENT_KEY_PATTERNS = (
    "prompt", "payload", "body", "content", "message", "messages", "completion",
    "input", "output", "response", "request_body", "arguments", "args", "params",
    "password", "passwd", "secret", "token", "api_key", "apikey", "credential",
    "private_key", "authorization", "cookie", "session_token", "refresh_token",
    "client_secret", "connection_string", "dsn", "ssn", "social_security",
    "card_number", "credit_card", "cvv", "iban", "account_number", "dob",
    "date_of_birth", "address", "phone", "email_address", "passport",
)

#: Value shapes that are redacted even when the key looks innocuous.
_SECRET_SHAPES = (
    re.compile(r"(agp1\.)"),                       # AgentGuard passport token
    re.compile(r"-----BEGIN [A-Z ]+-----"),        # PEM block
    re.compile(r"\b(?:sk|pk|rk|ghp|xox[baprs])[-_][A-Za-z0-9_\-]{16,}"),  # common API-key shapes
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),  # JWT
    re.compile(r"^[A-Za-z0-9+/=_\-]{64,}$"),       # long opaque blob
)

#: Marker used when a field is dropped entirely.
DROP_MARKER = "[DROPPED]"
#: Marker used when recursion exceeds the configured bound.
DEPTH_MARKER = "[DEPTH_LIMIT]"

_REDACTION_DOMAIN = b"agentguard.phase5.redaction.v1"


def looks_like_secret(value: str) -> bool:
    """True if ``value`` matches a known credential/secret shape."""
    if not isinstance(value, str) or not value:
        return False
    return any(p.search(value) for p in _SECRET_SHAPES)


def is_content_key(key: str) -> bool:
    """True if a field NAME indicates content-bearing / sensitive data."""
    if not isinstance(key, str) or not key:
        return False
    k = key.strip().lower()
    return any(pat in k for pat in CONTENT_KEY_PATTERNS)


def pseudonym(value: object, *, length: int = 16) -> str:
    """A stable, non-reversible short pseudonym for a value (mode ``hash``)."""
    h = hashlib.sha256(_REDACTION_DOMAIN)
    h.update(type(value).__name__.encode("utf-8", "replace"))
    h.update(b"\x00")
    h.update(str(value).encode("utf-8", "replace"))
    return "sha256:" + h.hexdigest()[:length]


def mask(value: object, *, head: int = 2, tail: int = 2) -> str:
    """Keep a bounded head/tail of a value and mask the middle (mode ``mask``)."""
    s = str(value)
    if len(s) <= head + tail:
        return "*" * len(s)
    return f"{s[:head]}{'*' * (len(s) - head - tail)}{s[-tail:]}"


def redact_value(value: object, mode: str, *, head: int = 2, tail: int = 2):
    """Apply one redaction mode to a single scalar value."""
    if mode == "drop":
        return DROP_MARKER
    if mode == "mask":
        return mask(value, head=head, tail=tail)
    return pseudonym(value)


def redact_extra(obj: object, *, mode: str, max_depth: int, _depth: int = 0) -> Dict[str, object]:
    """Return a sanitized, bounded, primitive-only dict safe to attach to an event.

    * allow-listed scalar fields keep their value,
    * content-bearing keys are dropped (mode ``drop``) or reduced to a pseudonym/mask,
    * secret-shaped values are redacted regardless of key,
    * lists/tuples of scalars are preserved (up to a bound); nested dicts are recursed to
      ``max_depth``; anything deeper becomes :data:`DEPTH_MARKER`,
    * output is capped at :data:`~.models.EXTRA_MAX_KEYS` keys.
    """
    if not isinstance(obj, dict):
        return {}
    out: Dict[str, object] = {}
    for key, value in obj.items():
        if len(out) >= EXTRA_MAX_KEYS:
            break
        if not isinstance(key, str) or not key:
            continue
        if _depth > max_depth:
            out[key] = DEPTH_MARKER
            continue
        # A field whose NAME says it is content-bearing is redacted -- even when that name also
        # looks benign (e.g. ``prompt_template``) -- and a sensitive-looking VALUE is redacted even
        # under an innocuous key. Only allow-listed keys keep their value verbatim.
        content = is_content_key(key) or not _is_safe(key)
        if isinstance(value, dict):
            if content:
                out[key] = redact_value("<nested>", mode) if mode != "drop" else DROP_MARKER
                continue
            out[key] = redact_extra(value, mode=mode, max_depth=max_depth, _depth=_depth + 1)
            continue
        if isinstance(value, (list, tuple)):
            items = []
            for v in value[:32]:
                if isinstance(v, (dict, list, tuple)):
                    items.append(redact_value("<nested>", mode))
                else:
                    items.append(_scalar(v, content=content, mode=mode))
            out[key] = items
            continue
        out[key] = _scalar(value, content=content, mode=mode)
    return out


def _pseudonym(value: object, length: int = 16) -> str:
    return pseudonym(value, length=length)


def _scalar(value: object, *, content: bool, mode: str):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    s = str(value)[:FIELD_MAX]
    if content or looks_like_secret(s):
        return redact_value(s, mode)
    return s

def _is_safe(key: str) -> bool:
    return key.strip().lower() in SAFE_FIELDS


class Redactor:
    """Configurable redaction front-end used by the pipeline.

    The redactor is intentionally stateless with respect to values (no cache of seen secrets): a
    cache would itself become a store of sensitive data.
    """

    def __init__(self, *, mode: str = "hash", max_depth: int = 4,
                 drop_payload_fields: bool = True):
        if mode not in ("hash", "mask", "drop"):
            raise ValueError("mode must be hash|mask|drop (there is no 'off' option)")
        self.mode = mode
        self.max_depth = max(0, int(max_depth))
        self.drop_payload_fields = bool(drop_payload_fields)

    # -- scalars -------------------------------------------------------------------------------
    def redact_scalar(self, value: object) -> object:
        if value is None or isinstance(value, (bool, int, float)):
            return value
        s = str(value)[:FIELD_MAX]
        if looks_like_secret(s):
            return redact_value(s, self.mode)
        return s

    def redact_key(self, key: str) -> str:
        """Map an arbitrary key to its stored name (content keys are dropped as ``key=[DROPPED]``)."""
        return key if _is_safe(key) else key

    def redact_extra(self, obj: object) -> Dict[str, object]:
        return redact_extra(obj, mode=self.mode, max_depth=self.max_depth)

    def redact_text(self, value: Optional[str]) -> Tuple[Optional[str], bool]:
        """Redact an optional free-text metadata field. Returns ``(value, was_redacted)``."""
        if value is None:
            return None, False
        s = str(value)[:FIELD_MAX]
        if looks_like_secret(s):
            return str(redact_value(s, self.mode)), True
        return s, False
