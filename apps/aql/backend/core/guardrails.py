"""Safety layer for AQL-1 — risk classification + human-in-the-loop approval.

An autonomous agent that can send email, delete rows, move money or run shell
commands is only as safe as the gate in front of those actions. This module is
that gate.

Two halves:

1. **Risk classification** — :func:`check_action_risk` scores an action against
   an extensible rule table (action-type mapping + regex/keyword patterns) and
   returns a structured :class:`RiskAssessment`. It is deterministic and
   offline-safe: no network, no model call, no keys.

2. **Pause → persist → resume** — when an action is high-risk the agent must
   *stop* rather than act. :class:`ApprovalStore` persists the full paused run
   to Supabase (in-memory fallback when unconfigured) and hands back an
   approval id. A human then approves or rejects it through the API, and the
   run resumes (or is marked rejected).

Design goals
------------
* **Never hard-fails.** No Supabase keys → in-memory store. A broken store
  degrades to a warning, not a crash.
* **Typed failures.** ``GuardrailError`` and friends, never bare ``Exception``.
* **Extensible.** Adding a dangerous action class is one entry in ``RISK_RULES``.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import get_settings

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Typed exceptions
# ══════════════════════════════════════════════════════════════════════════════
class GuardrailError(Exception):
    """Base class for every guardrail failure."""


class RiskCheckError(GuardrailError):
    """The risk classifier could not evaluate an action."""


class ApprovalStoreError(GuardrailError):
    """The pending-approval store could not be read or written."""


class ApprovalNotFoundError(GuardrailError):
    """No pending approval exists for the given id / run id."""


class ApprovalStateError(GuardrailError):
    """The approval exists but is not in a state that allows this operation."""


# ══════════════════════════════════════════════════════════════════════════════
# Risk levels
# ══════════════════════════════════════════════════════════════════════════════
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"

#: Ordering used to take the *maximum* risk across all matched rules.
_RISK_ORDER = {RISK_LOW: 0, RISK_MEDIUM: 1, RISK_HIGH: 2}


# ══════════════════════════════════════════════════════════════════════════════
# Rule table
# ══════════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class RiskRule:
    """One entry in the risk rule table.

    A rule fires when **both** hold:

    * its ``action_types`` matches the action's type (``"*"`` matches anything,
      otherwise a dotted-prefix / equality match), **and**
    * either ``patterns`` is empty (the action type alone is enough) or at least
      one regex in ``patterns`` matches the flattened payload text.

    Adding a new dangerous class of action is a single entry in ``RISK_RULES``.
    """

    rule_id: str
    category: str
    risk_level: str
    action_types: tuple[str, ...]
    patterns: tuple[str, ...]
    description: str


#: The rule table. Order does not matter — every rule is evaluated and the
#: highest risk wins, so rules compose instead of shadowing each other.
RISK_RULES: tuple[RiskRule, ...] = (
    # ── 1. Sending email / messages to external recipients ────────────────────
    RiskRule(
        rule_id="external_communication.send",
        category="external_communication",
        risk_level=RISK_HIGH,
        action_types=(
            "email.send", "send.email", "email", "mail.send",
            "message.send", "send.message", "message", "sms.send", "send.sms",
            "notification.send", "send.notification", "dm.send", "slack.send",
            "whatsapp.send", "telegram.send", "tweet.post", "post.social",
        ),
        patterns=(
            r"\b(send|sending|email|e-mail|mail|message|sms|dm|notify|"
            r"notification|broadcast|reply|forward)\b",
            r"\b(to|recipient|cc|bcc|external|customer|client|user|list|"
            r"everyone|all\s+contacts)\b",
        ),
        description="Sends an email or message to an external recipient.",
    ),
    # ── 2. Deleting database records ──────────────────────────────────────────
    RiskRule(
        rule_id="data_deletion.records",
        category="data_deletion",
        risk_level=RISK_HIGH,
        action_types=(
            "db.delete", "database.delete", "record.delete", "row.delete",
            "table.delete", "sql.delete", "db.drop", "table.drop",
            "db.truncate", "table.truncate", "delete.record", "delete.row",
            "delete.rows", "delete.records", "delete.table", "delete.database",
        ),
        patterns=(
            r"\b(delete|deleting|deleted|remove|removing|drop|dropping|"
            r"truncate|purge|wipe|erase|destroy)\b",
            r"\b(record|records|row|rows|table|tables|database|db|collection|"
            r"document|documents|entry|entries|user|users|account|accounts)\b",
            r"\b(delete\s+from|drop\s+table|truncate\s+table)\b",
        ),
        description="Deletes database records or drops a table.",
    ),
    # ── 3. Financial actions ──────────────────────────────────────────────────
    RiskRule(
        rule_id="financial.money_movement",
        category="financial",
        risk_level=RISK_HIGH,
        action_types=(
            "payment.create", "payment.send", "payment.transfer", "payment.charge",
            "transfer.create", "transfer.send", "refund.create", "refund.issue",
            "purchase.create", "purchase.execute", "order.place", "invoice.charge",
            "stripe.charge", "stripe.refund", "stripe.payout", "payout.create",
            "withdraw.create", "deposit.create", "billing.charge", "checkout.create",
        ),
        patterns=(
            r"\b(pay|payment|paying|paid|transfer|transfers|wire|remit|refund|"
            r"reimburse|purchase|buy|checkout|charge|invoice|payout|withdraw|"
            r"deposit|billing|subscription|stripe|paypal|credit\s+card|"
            r"bank\s+account|money|funds|usd|eur|amount)\b",
            r"[$€£]\s?\d",
        ),
        description="Executes a financial action (payment, transfer, refund, purchase).",
    ),
    # ── 4. Shell / command execution ──────────────────────────────────────────
    RiskRule(
        rule_id="shell.execution",
        category="shell_execution",
        risk_level=RISK_HIGH,
        action_types=(
            "shell.exec", "shell.run", "command.run", "command.exec", "bash.exec",
            "sh.exec", "zsh.exec", "powershell.exec", "subprocess.run",
            "subprocess.exec", "os.system", "exec.shell", "run.command",
        ),
        patterns=(
            r"\b(shell|bash|sh|zsh|powershell|cmd|command|terminal|console|"
            r"subprocess|exec|execute|spawn|system\s+call)\b",
            r"(rm\s+-rf|sudo\s|chmod\s|chown\s|curl\s|wget\s|\|\s*sh\b|"
            r"&&\s*rm\b|;\s*rm\b|>\s*/dev/)",
        ),
        description="Runs a shell / system command.",
    ),
    # ── 5. File deletion ──────────────────────────────────────────────────────
    RiskRule(
        rule_id="file_deletion",
        category="file_deletion",
        risk_level=RISK_HIGH,
        action_types=(
            "file.delete", "file.remove", "fs.delete", "fs.remove", "file.unlink",
            "directory.delete", "dir.delete", "folder.delete", "delete.file",
            "delete.folder", "delete.directory",
        ),
        patterns=(
            r"\b(delete|remove|unlink|rm|erase|wipe|purge)\b",
            r"\b(file|files|folder|folders|directory|directories|dir|path|"
            r"\.txt|\.csv|\.json|\.pdf|\.docx|\.xlsx|\.zip)\b",
        ),
        description="Deletes a file or directory.",
    ),
    # ── 6. Credential / secret access ─────────────────────────────────────────
    RiskRule(
        rule_id="credential_access",
        category="credential_access",
        risk_level=RISK_HIGH,
        action_types=(
            "credential.read", "credential.access", "secret.read", "secret.access",
            "env.read", "key.access", "key.read", "token.read", "vault.read",
            "password.read", "read.credential", "read.secret", "read.env",
        ),
        patterns=(
            r"(credential|credentials|secret|secrets|api[\s_-]?key|apikey|"
            r"private[\s_-]?key|password|passwd|token|bearer|vault|\.env|"
            r"env\s+var|environment\s+variable|access[\s_-]?key|_key\b)",
        ),
        description="Reads credentials, secrets or environment variables.",
    ),
    # ── 7. Bulk data export ───────────────────────────────────────────────────
    RiskRule(
        rule_id="bulk_export",
        category="bulk_export",
        risk_level=RISK_HIGH,
        action_types=(
            "data.export", "bulk.export", "db.dump", "db.export", "table.export",
            "report.export", "export.data", "export.bulk", "export.csv",
            "export.all", "download.all", "backup.create",
        ),
        patterns=(
            r"\b(export|dump|extract|download|backup|exfiltrate|scrape)\b",
            r"\b(all|entire|full|bulk|every|whole|complete|mass)\b",
            r"\b(records|rows|users|table|database|dataset|customers|pii|"
            r"personal\s+data)\b",
        ),
        description="Exports data in bulk (potential data exfiltration).",
    ),
    # ── 8. Medium-risk: writes / mutations that are not destructive ───────────
    RiskRule(
        rule_id="data_mutation.write",
        category="data_mutation",
        risk_level=RISK_MEDIUM,
        action_types=(
            "db.write", "db.insert", "db.update", "record.update", "record.create",
            "file.write", "file.create", "file.overwrite", "email.draft",
            "message.draft", "config.update", "settings.update",
        ),
        patterns=(),
        description="Mutates stored data (non-destructive write).",
    ),
    # ── 9. Medium-risk: outbound network calls ────────────────────────────────
    RiskRule(
        rule_id="network.outbound",
        category="network",
        risk_level=RISK_MEDIUM,
        action_types=(
            "http.request", "http.post", "http.put", "http.patch", "http.delete",
            "webhook.call", "api.call", "web.fetch",
        ),
        patterns=(),
        description="Makes an outbound network request that can change remote state.",
    ),
    # ── 10. Low-risk: read-only / informational ───────────────────────────────
    RiskRule(
        rule_id="read_only",
        category="read_only",
        risk_level=RISK_LOW,
        action_types=(
            "web_search", "search", "read", "file.read", "db.read", "db.select",
            "http.get", "echo", "now", "python_exec", "file_generator",
            "summarize", "translate", "classify", "compute", "calculate",
        ),
        patterns=(),
        description="Read-only or purely computational action.",
    ),
)

#: Convenience index: category → rule ids, for docs and tests.
RULES_BY_CATEGORY: dict[str, list[str]] = {}
for _rule in RISK_RULES:  # pragma: no branch
    RULES_BY_CATEGORY.setdefault(_rule.category, []).append(_rule.rule_id)


# ══════════════════════════════════════════════════════════════════════════════
# RiskAssessment
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class RiskAssessment:
    """The structured verdict returned by :func:`check_action_risk`."""

    action_type: str
    risk_level: str = RISK_LOW
    is_high_risk: bool = False
    reasons: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    requires_approval: bool = False
    categories: list[str] = field(default_factory=list)
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "risk_level": self.risk_level,
            "is_high_risk": self.is_high_risk,
            "reasons": list(self.reasons),
            "matched_rules": list(self.matched_rules),
            "requires_approval": self.requires_approval,
            "categories": list(self.categories),
            "checked_at": self.checked_at,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Classification helpers
# ══════════════════════════════════════════════════════════════════════════════
def _normalise_action_type(action_type: str) -> str:
    """Lower-case and dot-normalise an action type.

    ``"send_email"``, ``"Send-Email"`` and ``"send.email"`` all become
    ``"send.email"`` so the rule table only has to spell each action once.
    """
    text = (action_type or "").strip().lower()
    text = re.sub(r"[\s_\-/]+", ".", text)
    return re.sub(r"\.+", ".", text).strip(".")


def _flatten_payload(payload: Any) -> str:
    """Flatten any payload into a single lower-cased search string.

    Dict keys are included as well as values, so ``{"to": "x@y.com"}`` and
    ``{"recipient": "x@y.com"}`` are both searchable.
    """
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload.lower()
    if isinstance(payload, dict):
        parts: list[str] = []
        for key, value in payload.items():
            parts.append(str(key))
            parts.append(_flatten_payload(value))
        return " ".join(parts).lower()
    if isinstance(payload, (list, tuple, set)):
        return " ".join(_flatten_payload(v) for v in payload).lower()
    return str(payload).lower()


def _action_type_matches(rule: RiskRule, action_type: str) -> bool:
    """True when ``rule`` applies to ``action_type``.

    ``"*"`` matches anything; otherwise an exact match or a dotted-prefix match
    in either direction (so ``"email"`` covers ``"email.send"`` and vice versa).
    """
    if not action_type:
        return False
    for candidate in rule.action_types:
        if candidate == "*":
            return True
        norm = _normalise_action_type(candidate)
        if not norm:
            continue
        if action_type == norm:
            return True
        if action_type.startswith(norm + ".") or norm.startswith(action_type + "."):
            return True
    return False


def _patterns_match(rule: RiskRule, text: str) -> bool:
    """True when the rule has no patterns (type-only) or one of them matches."""
    if not rule.patterns:
        return True
    for pattern in rule.patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        except re.error as exc:  # pragma: no cover — a bad rule is a bug
            logger.warning("Invalid guardrail pattern %r (%s)", pattern, exc)
    return False


def check_action_risk(action_type: str, payload: Any = None) -> RiskAssessment:
    """Classify ``action_type`` (+ ``payload``) as low / medium / high risk.

    Deterministic and offline-safe: pure regex + table lookup, no network and
    no model call, so it behaves identically with or without API keys.

    Args:
        action_type: The action being attempted, e.g. ``"email.send"``,
            ``"db.delete"``, ``"payment.transfer"``, ``"shell.exec"``.
        payload: Anything describing the action (dict / str / list). Its keys
            and values are flattened into the text the patterns match against.

    Returns:
        A :class:`RiskAssessment`. ``requires_approval`` is ``True`` only for a
        high-risk action while guardrails are enabled in settings.

    Raises:
        RiskCheckError: If classification itself fails (should not happen for
            well-formed input — the caller can treat this as "block").
    """
    try:
        settings = get_settings()
        normalised = _normalise_action_type(action_type)
        text = _flatten_payload(payload)

        matched: list[RiskRule] = []
        for rule in RISK_RULES:
            if not _action_type_matches(rule, normalised):
                continue
            if not _patterns_match(rule, text):
                continue
            matched.append(rule)

        if matched:
            # Highest risk across every matched rule wins.
            level = max(matched, key=lambda r: _RISK_ORDER[r.risk_level]).risk_level
        else:
            # Unknown action type with no matching rule → treat as medium so an
            # unrecognised capability is never silently waved through.
            level = RISK_MEDIUM

        is_high = level == RISK_HIGH
        enabled = bool(getattr(settings, "guardrails_enabled", True))

        return RiskAssessment(
            action_type=action_type,
            risk_level=level,
            is_high_risk=is_high,
            reasons=[r.description for r in matched]
            or ["Unrecognised action type — treated as medium risk by default."],
            matched_rules=[r.rule_id for r in matched],
            requires_approval=is_high and enabled,
            categories=sorted({r.category for r in matched}),
        )
    except GuardrailError:
        raise
    except Exception as exc:  # noqa: BLE001 — classification must be total
        raise RiskCheckError(f"risk check failed for {action_type!r}: {exc}") from exc


# ══════════════════════════════════════════════════════════════════════════════
# Pending approvals — pause / persist / resume
# ══════════════════════════════════════════════════════════════════════════════
APPROVAL_PENDING = "pending"
APPROVAL_APPROVED = "approved"
APPROVAL_REJECTED = "rejected"


@dataclass
class PendingApproval:
    """A paused run waiting for a human decision."""

    approval_id: str
    run_id: str
    action_type: str
    payload: dict[str, Any]
    risk: dict[str, Any]
    kind: str = "agent"  # agent | orchestrator
    status: str = APPROVAL_PENDING
    user_id: str = "anonymous"
    session_id: str = "default"
    resume_state: dict[str, Any] = field(default_factory=dict)
    approver: str | None = None
    note: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    decided_at: str | None = None

    @property
    def is_pending(self) -> bool:
        return self.status == APPROVAL_PENDING

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "run_id": self.run_id,
            "action_type": self.action_type,
            "payload": self.payload,
            "risk": self.risk,
            "kind": self.kind,
            "status": self.status,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "resume_state": self.resume_state,
            "approver": self.approver,
            "note": self.note,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PendingApproval":
        """Rebuild from a stored row (extra keys are ignored)."""
        known = {
            "approval_id", "run_id", "action_type", "payload", "risk", "kind",
            "status", "user_id", "session_id", "resume_state", "approver",
            "note", "created_at", "decided_at",
        }
        return cls(**{k: v for k, v in data.items() if k in known})


class ApprovalStore:
    """Persists paused runs and their decisions.

    Backed by :class:`~memory.state.StateManager`, which uses Supabase when
    ``SUPABASE_URL`` + ``SUPABASE_SERVICE_ROLE_KEY`` are configured and an
    in-memory dict otherwise — so this works with **no API keys present**.
    """

    def __init__(self, state: Any | None = None) -> None:
        self.settings = get_settings()
        if state is None:
            from memory.state import StateManager

            state = StateManager()
        self.state = state

    @property
    def is_local(self) -> bool:
        """True when approvals live in memory only (no Supabase configured)."""
        return bool(getattr(self.state, "is_local", True))

    # ── write ────────────────────────────────────────────────────────────────
    def pause(
        self,
        *,
        run_id: str,
        action_type: str,
        payload: dict[str, Any] | None = None,
        assessment: RiskAssessment | None = None,
        kind: str = "agent",
        resume_state: dict[str, Any] | None = None,
        user_id: str = "anonymous",
        session_id: str = "default",
    ) -> PendingApproval:
        """Persist a paused run and return its :class:`PendingApproval`.

        Raises:
            ApprovalStoreError: If the record cannot be persisted at all.
        """
        try:
            risk = (
                assessment.to_dict()
                if assessment is not None
                else check_action_risk(action_type, payload).to_dict()
            )
            approval = PendingApproval(
                approval_id=str(uuid.uuid4()),
                run_id=run_id,
                action_type=action_type,
                payload=dict(payload or {}),
                risk=risk,
                kind=kind,
                user_id=user_id,
                session_id=session_id,
                resume_state=dict(resume_state or {}),
            )
            self.state.save_approval(approval.approval_id, approval.to_dict())
            logger.info(
                "Paused run %s for human approval (%s, %s)",
                run_id, approval.approval_id, action_type,
            )
            return approval
        except GuardrailError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ApprovalStoreError(f"could not persist approval: {exc}") from exc

    def decide(
        self,
        approval_id: str,
        decision: str,
        *,
        approver: str | None = None,
        note: str = "",
    ) -> PendingApproval:
        """Record a human decision (``approve`` / ``reject``) on an approval.

        Raises:
            ApprovalNotFoundError: No such approval.
            ApprovalStateError: The approval was already decided.
            ApprovalStoreError: The decision could not be persisted.
        """
        approval = self.get(approval_id)
        if not approval.is_pending:
            raise ApprovalStateError(
                f"approval {approval_id} is already {approval.status}"
            )
        status = (
            APPROVAL_APPROVED
            if str(decision).strip().lower() in {"approve", "approved", "yes", "ok"}
            else APPROVAL_REJECTED
        )
        patch = {
            "status": status,
            "approver": approver,
            "note": note,
            "decided_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            self.state.update_approval(approval_id, patch)
        except Exception as exc:  # noqa: BLE001
            raise ApprovalStoreError(f"could not record decision: {exc}") from exc
        approval.status = status
        approval.approver = approver
        approval.note = note
        approval.decided_at = patch["decided_at"]
        return approval

    # ── read ─────────────────────────────────────────────────────────────────
    def get(self, approval_id: str) -> PendingApproval:
        """Fetch one approval by id.

        Raises:
            ApprovalNotFoundError: No such approval.
            ApprovalStoreError: The store could not be read.
        """
        try:
            row = self.state.get_approval(approval_id)
        except Exception as exc:  # noqa: BLE001
            raise ApprovalStoreError(f"could not read approval: {exc}") from exc
        if not row:
            raise ApprovalNotFoundError(f"no approval with id {approval_id}")
        return PendingApproval.from_dict(row)

    def find_by_run(self, run_id: str) -> PendingApproval | None:
        """Return the most recent approval for ``run_id``, if any.

        Searches **every** status, not just pending, so a caller can tell an
        already-decided run (→ 409) apart from an unknown one (→ 404).
        """
        for row in self.list(status=None, limit=500):
            if row.run_id == run_id:
                return row
        return None

    def list(
        self, status: str | None = APPROVAL_PENDING, limit: int = 50
    ) -> list[PendingApproval]:
        """List approvals, newest first, optionally filtered by status."""
        try:
            rows = self.state.list_approvals(status=status, limit=limit)
        except Exception as exc:  # noqa: BLE001 — listing must not crash the API
            logger.warning("Could not list approvals (%s)", exc)
            return []
        return [PendingApproval.from_dict(r) for r in rows]


__all__ = [
    "check_action_risk",
    "RiskAssessment",
    "RiskRule",
    "RISK_RULES",
    "RULES_BY_CATEGORY",
    "ApprovalStore",
    "PendingApproval",
    "GuardrailError",
    "RiskCheckError",
    "ApprovalStoreError",
    "ApprovalNotFoundError",
    "ApprovalStateError",
    "RISK_LOW",
    "RISK_MEDIUM",
    "RISK_HIGH",
    "APPROVAL_PENDING",
    "APPROVAL_APPROVED",
    "APPROVAL_REJECTED",
]
