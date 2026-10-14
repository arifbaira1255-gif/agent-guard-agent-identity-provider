"""Billing for AQL-1 — plans, subscriptions, usage limits and manual payments.

* **Plans** — :data:`PLANS` is a typed, ordered catalogue (Free / Pro / Team)
  shared by the backend endpoints and the dashboard's pricing cards.
* **Subscriptions & usage** — :class:`BillingStore` persists the current tier,
  billing period and monthly token counter through
  :class:`memory.state.StateManager` (Supabase, with an in-memory fallback).
* **Manual Payoneer / bank-transfer workflow** — a user pays to the configured
  Payoneer email (or bank account), then submits a transaction reference and a
  screenshot. The submission is stored as a ``payment_verifications`` row in
  ``pending`` state; an admin approves it, which activates the subscription.

Design goals: never hard-fail (works with no Supabase), typed failures
(``BillingError`` and friends) and idempotent approvals (a payment can only be
decided once, so a double-click can never extend a subscription twice).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import get_settings

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# Typed exceptions
# ══════════════════════════════════════════════════════════════════════════════
class BillingError(Exception):
    """Base class for every billing failure."""


class BillingConfigError(BillingError):
    """Billing is misconfigured (e.g. asking to pay for the Free tier)."""


class BillingStoreError(BillingError):
    """The subscription/usage store could not be read or written."""


class PaymentValidationError(BillingError):
    """A payment submission was malformed (maps to HTTP 400)."""


class PaymentNotFoundError(BillingError):
    """No payment verification exists with the given id (HTTP 404)."""


class PaymentStateError(BillingError):
    """The payment was already decided or is a duplicate (HTTP 409)."""


class SubscriptionNotFoundError(BillingError):
    """No subscription exists for the given user."""


class TokenLimitExceededError(BillingError):
    """The user has exhausted their monthly token allowance."""


# ══════════════════════════════════════════════════════════════════════════════
# Feature flags
# ══════════════════════════════════════════════════════════════════════════════
#: Canonical, ordered feature keys. The dashboard renders its comparison table
#: from this list, so adding a feature is a one-line change on both sides.
FEATURE_KEYS: tuple[str, ...] = (
    "api_access",
    "priority_routing",
    "observability_history",
    "team_management",
    "sso",
)

#: Human-readable labels for the feature comparison table.
FEATURE_LABELS: dict[str, str] = {
    "api_access": "REST API access",
    "priority_routing": "Priority model routing",
    "observability_history": "Observability history",
    "team_management": "Team management",
    "sso": "SSO-ready",
}


def _features(**enabled: bool) -> dict[str, bool]:
    """Build a complete feature map, defaulting every key to ``False``.

    Returning a *complete* map (rather than only the enabled keys) means the
    frontend never has to guess whether a missing key means "off" or "unknown".
    """
    return {key: bool(enabled.get(key, False)) for key in FEATURE_KEYS}


# ══════════════════════════════════════════════════════════════════════════════
# Plans / tiers
# ══════════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class Plan:
    """One commercial tier.

    Prices are USD per month, paid manually via Payoneer or bank transfer.
    """

    id: str
    name: str
    price_usd: float
    monthly_token_limit: int
    max_concurrent_runs: int
    seats: int
    features: dict[str, bool]
    description: str
    highlights: tuple[str, ...] = ()

    @property
    def is_free(self) -> bool:
        return self.price_usd == 0

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the API."""
        return {
            "id": self.id,
            "name": self.name,
            "price_usd": self.price_usd,
            "monthly_token_limit": self.monthly_token_limit,
            "max_concurrent_runs": self.max_concurrent_runs,
            "seats": self.seats,
            "features": dict(self.features),
            "description": self.description,
            "highlights": list(self.highlights),
        }


#: Alias kept for callers that prefer the word "tier".
Tier = Plan

#: The catalogue, cheapest first. This is the single source of truth shared by
#: the backend endpoints and the dashboard's pricing cards.
PLANS: tuple[Plan, ...] = (
    Plan(
        id="free",
        name="Free",
        price_usd=0.0,
        monthly_token_limit=50_000,
        max_concurrent_runs=1,
        seats=1,
        features=_features(),
        description="Kick the tyres: a single agent, a small monthly token budget.",
        highlights=(
            "50k tokens / month",
            "1 concurrent run",
            "1 seat",
            "Community support",
        ),
    ),
    Plan(
        id="pro",
        name="Pro",
        price_usd=29.0,
        monthly_token_limit=2_000_000,
        max_concurrent_runs=5,
        seats=1,
        features=_features(
            api_access=True,
            priority_routing=True,
            observability_history=True,
        ),
        description="For builders shipping agents to production.",
        highlights=(
            "2M tokens / month",
            "5 concurrent runs",
            "REST API access",
            "Priority model routing",
            "Observability history",
        ),
    ),
    Plan(
        id="team",
        name="Team",
        price_usd=99.0,
        monthly_token_limit=10_000_000,
        max_concurrent_runs=25,
        seats=10,
        features=_features(
            api_access=True,
            priority_routing=True,
            observability_history=True,
            team_management=True,
            sso=True,
        ),
        description="Shared workspaces, seats and SSO for whole teams.",
        highlights=(
            "10M tokens / month",
            "25 concurrent runs",
            "10 seats",
            "Team management",
            "SSO-ready",
        ),
    ),
)

#: Ordered tier ids, cheapest first.
PLAN_ORDER: tuple[str, ...] = tuple(p.id for p in PLANS)

#: The tier every user starts on and falls back to.
DEFAULT_TIER = "free"

#: Subscription statuses that grant the tier's paid features.
ACTIVE_STATUSES: frozenset[str] = frozenset({"active", "trialing"})

#: Statuses that keep the tier for display but suspend its paid features.
RESTRICTED_STATUSES: frozenset[str] = frozenset(
    {"past_due", "unpaid", "incomplete", "incomplete_expired", "paused"}
)


def get_plan(tier_id: str | None) -> Plan:
    """Return the plan for ``tier_id``, falling back to Free.

    An unknown tier id is never an error — it degrades to Free, which is the
    safe direction (a typo can't accidentally grant Team features).
    """
    wanted = (tier_id or DEFAULT_TIER).strip().lower()
    for plan in PLANS:
        if plan.id == wanted:
            return plan
    logger.warning("Unknown tier %r — falling back to %s", tier_id, DEFAULT_TIER)
    return PLANS[0]


def plan_catalogue() -> list[dict[str, Any]]:
    """The full plan catalogue, ready to serialise."""
    return [plan.to_dict() for plan in PLANS]


# ══════════════════════════════════════════════════════════════════════════════
# Records
# ══════════════════════════════════════════════════════════════════════════════
def _utcnow_iso() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _month_start_iso() -> str:
    """First instant of the current UTC month — the default usage period."""
    now = datetime.now(timezone.utc)
    return now.replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    ).isoformat()


def _as_int(value: Any, default: int = 0) -> int:
    """Coerce ``value`` to int without ever raising."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass
class Subscription:
    """A user's billing state.

    ``tier`` is always a valid plan id; ``status`` uses a simple vocabulary (``active``, ``canceled``, …)
    (``active``, ``trialing``, ``past_due``, ``canceled``, …).
    """

    user_id: str
    tier: str = DEFAULT_TIER
    status: str = "active"
    payoneer_reference: str = ""
    last_payment_id: str = ""
    current_period_start: str = ""
    current_period_end: str = ""
    cancel_at_period_end: bool = False
    updated_at: str = field(default_factory=_utcnow_iso)

    @property
    def plan(self) -> Plan:
        return get_plan(self.tier)

    @property
    def is_active(self) -> bool:
        """True when the tier's paid features should be granted."""
        return self.status in ACTIVE_STATUSES

    def effective_features(self) -> dict[str, bool]:
        """Feature flags actually in force right now.

        A ``past_due`` subscription keeps its tier for display but loses its
        paid features until payment succeeds — the policy the webhook handlers
        implement.
        """
        if self.is_active:
            return dict(self.plan.features)
        return _features()

    def to_dict(self) -> dict[str, Any]:
        plan = self.plan
        return {
            "user_id": self.user_id,
            "tier": plan.id,
            "tier_name": plan.name,
            "status": self.status,
            "is_active": self.is_active,
            "payoneer_reference": self.payoneer_reference,
            "last_payment_id": self.last_payment_id,
            "current_period_start": self.current_period_start,
            "current_period_end": self.current_period_end,
            "cancel_at_period_end": self.cancel_at_period_end,
            "updated_at": self.updated_at,
            "price_usd": plan.price_usd,
            "monthly_token_limit": plan.monthly_token_limit,
            "max_concurrent_runs": plan.max_concurrent_runs,
            "seats": plan.seats,
            "features": self.effective_features(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Subscription":
        """Rebuild from a stored payload, tolerating missing/extra keys."""
        return cls(
            user_id=str(data.get("user_id", "anonymous")),
            tier=str(data.get("tier", DEFAULT_TIER)),
            status=str(data.get("status", "active")),
            payoneer_reference=str(data.get("payoneer_reference", "") or ""),
            last_payment_id=str(data.get("last_payment_id", "") or ""),
            current_period_start=str(data.get("current_period_start", "") or ""),
            current_period_end=str(data.get("current_period_end", "") or ""),
            cancel_at_period_end=bool(data.get("cancel_at_period_end", False)),
            updated_at=str(data.get("updated_at", "") or _utcnow_iso()),
        )


@dataclass
class Usage:
    """Monthly token/run consumption for one user."""

    user_id: str
    period_start: str = field(default_factory=_month_start_iso)
    tokens_used: int = 0
    tokens_limit: int = 0
    runs_used: int = 0

    @property
    def remaining(self) -> int:
        """Tokens left this period (never negative)."""
        return max(0, self.tokens_limit - self.tokens_used)

    @property
    def percent_used(self) -> float:
        """Share of the allowance consumed, 0–100."""
        if self.tokens_limit <= 0:
            return 0.0
        return round(min(100.0, (self.tokens_used / self.tokens_limit) * 100), 2)

    @property
    def is_exhausted(self) -> bool:
        return self.tokens_limit > 0 and self.tokens_used >= self.tokens_limit

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "period_start": self.period_start,
            "tokens_used": self.tokens_used,
            "tokens_limit": self.tokens_limit,
            "tokens_remaining": self.remaining,
            "percent_used": self.percent_used,
            "runs_used": self.runs_used,
            "is_exhausted": self.is_exhausted,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Usage":
        return cls(
            user_id=str(data.get("user_id", "anonymous")),
            period_start=str(data.get("period_start", "") or _month_start_iso()),
            tokens_used=_as_int(data.get("tokens_used")),
            tokens_limit=_as_int(data.get("tokens_limit")),
            runs_used=_as_int(data.get("runs_used")),
        )


# ══════════════════════════════════════════════════════════════════════════════
# Store
# ══════════════════════════════════════════════════════════════════════════════
class BillingStore:
    """Persistence for subscriptions, usage and webhook idempotency.

    Delegates to :class:`memory.state.StateManager`, which already owns the
    Supabase client and the in-memory fallback — so this class never has to
    know whether Supabase is configured.
    """

    def __init__(self, state: Any | None = None) -> None:
        if state is None:
            # Imported lazily so ``core.billing`` stays importable on its own.
            from memory.state import StateManager

            state = StateManager()
        self._state = state

    @property
    def is_local(self) -> bool:
        """True when billing rows live in memory only."""
        return bool(getattr(self._state, "is_local", True))

    # ── subscriptions ────────────────────────────────────────────────────────
    def get_subscription(self, user_id: str) -> Subscription | None:
        """Fetch a user's subscription, or ``None`` when they have none."""
        try:
            payload = self._state.get_subscription(user_id)
        except Exception as exc:  # noqa: BLE001 - degrade, never crash
            logger.warning("Subscription read failed for %s (%s)", user_id, exc)
            raise BillingStoreError(str(exc)) from exc
        return Subscription.from_dict(payload) if payload else None

    def save_subscription(self, sub: Subscription) -> Subscription:
        """Upsert a subscription, stamping ``updated_at``."""
        sub.updated_at = _utcnow_iso()
        try:
            self._state.save_subscription(sub.user_id, sub.to_dict())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Subscription write failed for %s (%s)", sub.user_id, exc)
            raise BillingStoreError(str(exc)) from exc
        return sub

    def list_subscriptions(self, limit: int = 200) -> list[Subscription]:
        """All subscriptions, newest first."""
        try:
            rows = self._state.list_subscriptions(limit=limit)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Subscription list failed (%s)", exc)
            return []
        return [Subscription.from_dict(r) for r in rows]

    # ── usage ────────────────────────────────────────────────────────────────
    def get_usage(self, user_id: str) -> Usage | None:
        """Fetch a user's usage row, or ``None`` when they have none."""
        try:
            payload = self._state.get_usage(user_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Usage read failed for %s (%s)", user_id, exc)
            raise BillingStoreError(str(exc)) from exc
        return Usage.from_dict(payload) if payload else None

    def save_usage(self, usage: Usage) -> Usage:
        """Upsert a usage row."""
        try:
            self._state.save_usage(usage.user_id, usage.to_dict())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Usage write failed for %s (%s)", usage.user_id, exc)
            raise BillingStoreError(str(exc)) from exc
        return usage

    # ── payment verifications ────────────────────────────────────────────────
    def save_payment(self, payment: "PaymentVerification") -> "PaymentVerification":
        """Insert/update one payment verification row."""
        try:
            self._state.save_payment_verification(payment.id, payment.to_row())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Payment write failed for %s (%s)", payment.id, exc)
            raise BillingStoreError(str(exc)) from exc
        return payment

    def get_payment(self, payment_id: str) -> "PaymentVerification | None":
        try:
            row = self._state.get_payment_verification(payment_id)
        except Exception as exc:  # noqa: BLE001
            raise BillingStoreError(str(exc)) from exc
        return PaymentVerification.from_row(row) if row else None

    def list_payments(
        self,
        *,
        status: str | None = None,
        user_id: str | None = None,
        limit: int = 200,
    ) -> "list[PaymentVerification]":
        try:
            rows = self._state.list_payment_verifications(
                status=status, user_id=user_id, limit=limit
            )
        except Exception as exc:  # noqa: BLE001
            raise BillingStoreError(str(exc)) from exc
        return [PaymentVerification.from_row(r) for r in rows]

    def upload_screenshot(self, path: str, data: bytes, content_type: str) -> bool:
        return bool(self._state.upload_payment_screenshot(path, data, content_type))

    def screenshot_url(self, path: str) -> str:
        return self._state.payment_screenshot_url(path) if path else ""


#: Statuses a payment verification can be in.
PAYMENT_STATUSES: tuple[str, ...] = ("pending", "approved", "rejected")
PAYMENT_METHODS: tuple[str, ...] = ("payoneer", "bank_transfer")
_ALLOWED_SCREENSHOT_TYPES: dict[str, tuple[bytes, ...]] = {
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/jpeg": (b"\xff\xd8\xff",),
    "image/webp": (b"RIFF",),
    "application/pdf": (b"%PDF",),
}
_EXT = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp",
        "application/pdf": "pdf"}


@dataclass
class PaymentVerification:
    """A user-submitted proof of manual payment awaiting admin review."""

    id: str
    user_id: str
    tier: str
    amount_usd: float
    method: str
    reference: str
    email: str = ""
    sender_name: str = ""
    screenshot_path: str = ""
    status: str = "pending"
    note: str = ""
    reviewer: str = ""
    created_at: str = field(default_factory=_utcnow_iso)
    decided_at: str | None = None

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id, "user_id": self.user_id, "tier": self.tier,
            "amount_usd": self.amount_usd, "method": self.method,
            "reference": self.reference, "email": self.email,
            "sender_name": self.sender_name,
            "screenshot_path": self.screenshot_path, "status": self.status,
            "note": self.note, "reviewer": self.reviewer,
            "created_at": self.created_at, "decided_at": self.decided_at,
        }

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "PaymentVerification":
        known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        data = {k: v for k, v in row.items() if k in known}
        data["amount_usd"] = float(data.get("amount_usd") or 0)
        for k in ("email", "sender_name", "screenshot_path", "note", "reviewer"):
            data[k] = data.get(k) or ""
        return cls(**data)


# ══════════════════════════════════════════════════════════════════════════════
# Service
# ══════════════════════════════════════════════════════════════════════════════
class BillingService:
    """Business logic tying plans, the store and manual payments together."""

    def __init__(
        self,
        store: BillingStore | None = None,
    ) -> None:
        self.store = store or BillingStore()

    # ── reads ────────────────────────────────────────────────────────────────
    def plans(self) -> list[dict[str, Any]]:
        """The plan catalogue (always available, keys or not)."""
        return plan_catalogue()

    def get_subscription(self, user_id: str) -> Subscription:
        """Return the user's subscription, synthesising a Free one if absent.

        A brand-new user has no row; rather than 404 we hand back a local Free
        subscription so the dashboard always has something to render.
        """
        sub = self.store.get_subscription(user_id)
        if sub is None:
            sub = Subscription(user_id=user_id, tier=DEFAULT_TIER, status="active")
        return sub

    def get_usage(self, user_id: str) -> Usage:
        """Return the user's usage row, defaulting to their tier's allowance."""
        sub = self.get_subscription(user_id)
        usage = self.store.get_usage(user_id)
        limit = sub.plan.monthly_token_limit
        if usage is None:
            return Usage(user_id=user_id, tokens_limit=limit)
        # A tier change (or a new billing period) re-bases the allowance.
        if usage.tokens_limit != limit:
            usage.tokens_limit = limit
        return usage

    def subscription_summary(self, user_id: str) -> dict[str, Any]:
        """Everything the dashboard's "current plan" card needs, in one call."""
        sub = self.get_subscription(user_id)
        usage = self.get_usage(user_id)
        return {
            "subscription": sub.to_dict(),
            "usage": usage.to_dict(),
            "features": sub.effective_features(),
            "renewal_date": sub.current_period_end or None,
            "cancel_at_period_end": sub.cancel_at_period_end,
            "billing_enabled": bool(get_settings().billing_enabled),
            "payoneer_configured": get_settings().payoneer_configured,
        }

    # ── manual payments ──────────────────────────────────────────────────────
    def payment_info(self) -> dict[str, Any]:
        """Where to send money — rendered on the Billing/Upgrade page."""
        st = get_settings()
        return {
            "payoneer_email": st.payoneer_email,
            "payoneer_payment_url": st.payoneer_payment_url,
            "bank_transfer_details": st.bank_transfer_details,
            "currency": "USD",
            "plans": [
                {"id": p.id, "name": p.name, "price_usd": p.price_usd}
                for p in PLANS if not p.is_free
            ],
            "instructions": (
                "Send the exact plan price, then submit your transaction ID "
                "and a screenshot below. An admin verifies it and activates "
                "your plan."
            ),
        }

    def submit_payment(
        self,
        *,
        user_id: str,
        tier: str,
        reference: str,
        method: str = "payoneer",
        email: str = "",
        sender_name: str = "",
        screenshot: bytes | None = None,
        screenshot_type: str = "",
    ) -> PaymentVerification:
        """Record a user's proof of payment as a ``pending`` verification."""
        st = get_settings()
        plan = get_plan(tier)
        if plan.is_free or plan.id != (tier or "").strip().lower():
            raise PaymentValidationError("Choose a paid plan: 'pro' or 'team'.")
        reference = (reference or "").strip()
        if not 4 <= len(reference) <= 120:
            raise PaymentValidationError(
                "Transaction ID / reference must be 4-120 characters."
            )
        if method not in PAYMENT_METHODS:
            raise PaymentValidationError(
                f"method must be one of: {', '.join(PAYMENT_METHODS)}."
            )
        if not screenshot:
            raise PaymentValidationError("A payment screenshot is required.")
        if len(screenshot) > st.payment_screenshot_max_bytes:
            raise PaymentValidationError("Screenshot is too large (max 5 MB).")
        magics = _ALLOWED_SCREENSHOT_TYPES.get(screenshot_type)
        if not magics or not any(screenshot.startswith(m) for m in magics):
            raise PaymentValidationError(
                "Screenshot must be a PNG, JPEG, WebP or PDF file."
            )
        # A reference can back only one live (pending/approved) submission.
        for existing in self.store.list_payments(limit=1000):
            if (
                existing.reference.lower() == reference.lower()
                and existing.status != "rejected"
            ):
                raise PaymentStateError(
                    "This transaction reference was already submitted."
                )

        payment_id = uuid.uuid4().hex
        path = f"{user_id}/{payment_id}.{_EXT[screenshot_type]}"
        if not self.store.upload_screenshot(path, screenshot, screenshot_type):
            path = ""  # local/demo mode: no object storage available
        payment = PaymentVerification(
            id=payment_id, user_id=user_id, tier=plan.id,
            amount_usd=plan.price_usd, method=method, reference=reference,
            email=(email or "").strip()[:200],
            sender_name=(sender_name or "").strip()[:120],
            screenshot_path=path,
        )
        return self.store.save_payment(payment)

    def my_payments(self, user_id: str) -> list[dict[str, Any]]:
        rows = self.store.list_payments(user_id=user_id, limit=50)
        return [self._payment_dict(p, with_url=False) for p in rows]

    def admin_payments(self, status: str | None = None) -> list[dict[str, Any]]:
        if status and status not in PAYMENT_STATUSES:
            raise PaymentValidationError("Unknown status filter.")
        rows = self.store.list_payments(status=status, limit=500)
        return [self._payment_dict(p, with_url=True) for p in rows]

    def _payment_dict(self, p: PaymentVerification, *, with_url: bool) -> dict[str, Any]:
        data = p.to_row()
        data["screenshot_url"] = (
            self.store.screenshot_url(p.screenshot_path) if with_url else ""
        )
        data["has_screenshot"] = bool(p.screenshot_path)
        data.pop("screenshot_path", None)
        return data

    def _decide(self, payment_id: str) -> PaymentVerification:
        payment = self.store.get_payment(payment_id)
        if payment is None:
            raise PaymentNotFoundError(f"No payment {payment_id!r}.")
        if payment.status != "pending":
            raise PaymentStateError(f"Payment already {payment.status}.")
        return payment

    def approve_payment(
        self, payment_id: str, *, reviewer: str = "admin", note: str = ""
    ) -> dict[str, Any]:
        """Approve a payment and activate the user's paid tier."""
        payment = self._decide(payment_id)
        now = datetime.now(timezone.utc)
        end = now + timedelta(days=get_settings().payment_period_days)
        sub = self.get_subscription(payment.user_id)
        sub.tier = payment.tier
        sub.status = "active"
        sub.payoneer_reference = payment.reference
        sub.last_payment_id = payment.id
        sub.current_period_start = now.isoformat()
        sub.current_period_end = end.isoformat()
        sub.cancel_at_period_end = False
        self.store.save_subscription(sub)
        self.store.save_usage(
            Usage(
                user_id=payment.user_id,
                period_start=_month_start_iso(),
                tokens_used=0,
                tokens_limit=sub.plan.monthly_token_limit,
                runs_used=0,
            )
        )
        payment.status = "approved"
        payment.reviewer = reviewer
        payment.note = note[:500]
        payment.decided_at = now.isoformat()
        self.store.save_payment(payment)
        return self._payment_dict(payment, with_url=False)

    def reject_payment(
        self, payment_id: str, *, reviewer: str = "admin", note: str = ""
    ) -> dict[str, Any]:
        payment = self._decide(payment_id)
        payment.status = "rejected"
        payment.reviewer = reviewer
        payment.note = note[:500]
        payment.decided_at = _utcnow_iso()
        self.store.save_payment(payment)
        return self._payment_dict(payment, with_url=False)

    # ── usage enforcement ────────────────────────────────────────────────────
    def check_token_limit(self, user_id: str) -> dict[str, Any]:
        """Report whether ``user_id`` may start another run.

        Returns ``{allowed, tier, tokens_used, tokens_limit, tokens_remaining,
        percent_used, reason}``. Never raises for a normal over-limit case —
        the caller decides what to do with ``allowed: False``.
        """
        sub = self.get_subscription(user_id)
        usage = self.get_usage(user_id)
        allowed = not usage.is_exhausted
        return {
            "allowed": allowed,
            "tier": sub.tier,
            "status": sub.status,
            "tokens_used": usage.tokens_used,
            "tokens_limit": usage.tokens_limit,
            "tokens_remaining": usage.remaining,
            "percent_used": usage.percent_used,
            "reason": "" if allowed else "monthly token limit reached",
        }

    def record_usage(
        self, user_id: str, *, tokens: int = 0, runs: int = 1
    ) -> Usage:
        """Add consumption to the current period, resetting on a new month.

        The period rollover is handled here so a stale row from last month can
        never silently consume this month's allowance.
        """
        sub = self.get_subscription(user_id)
        usage = self.store.get_usage(user_id)
        period = _month_start_iso()

        if usage is None or usage.period_start != period:
            usage = Usage(
                user_id=user_id,
                period_start=period,
                tokens_used=0,
                tokens_limit=sub.plan.monthly_token_limit,
                runs_used=0,
            )

        usage.tokens_limit = sub.plan.monthly_token_limit
        usage.tokens_used += max(0, _as_int(tokens))
        usage.runs_used += max(0, _as_int(runs))
        return self.store.save_usage(usage)


# ══════════════════════════════════════════════════════════════════════════════
# Module-level singleton
# ══════════════════════════════════════════════════════════════════════════════
_service: BillingService | None = None


def get_billing_service() -> BillingService:
    """Return the process-wide :class:`BillingService` (lazily built)."""
    global _service
    if _service is None:
        _service = BillingService()
    return _service


def reset_billing_service() -> None:
    """Drop the cached service — used by tests to isolate state."""
    global _service
    _service = None
