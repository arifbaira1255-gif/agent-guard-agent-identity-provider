"""Billing REST endpoints for AQL-1 (manual Payoneer / bank-transfer workflow).

Mounted at ``/v1/billing``. The whole prefix is exempt from the API-key
middleware (``AUTH_PUBLIC_PATHS``) because each route authenticates itself:

User routes (Supabase session JWT in ``Authorization: Bearer <jwt>``):

* ``GET  /v1/billing/plans``          — Free / Pro / Team catalogue (public).
* ``GET  /v1/billing/payment-info``   — Payoneer email + bank details (public).
* ``GET  /v1/billing/subscription``   — the caller's tier, usage and features.
* ``POST /v1/billing/payments``       — submit transaction ID + screenshot.
* ``GET  /v1/billing/payments``       — the caller's own submissions.

Admin routes (``X-Admin-Token: <ADMIN_TOKEN>``, constant-time compared):

* ``GET  /v1/billing/admin/payments?status=pending``
* ``POST /v1/billing/admin/payments/{id}/approve``
* ``POST /v1/billing/admin/payments/{id}/reject``
"""

from __future__ import annotations

import hmac
import json
import logging
import urllib.request

from fastapi import APIRouter, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from core.billing import (
    BillingError,
    BillingStoreError,
    PaymentNotFoundError,
    PaymentStateError,
    PaymentValidationError,
    get_billing_service,
)
from core.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/billing", tags=["billing"])


class DecisionRequest(BaseModel):
    """Body for approve / reject."""

    note: str = Field("", max_length=500)


# ── Identity ─────────────────────────────────────────────────────────────────
def _caller(request: Request) -> tuple[str, str]:
    """Resolve ``(user_id, email)`` from the caller's Supabase session JWT.

    With Supabase configured a valid token is mandatory (401 otherwise). With
    no Supabase (local dev) the caller is ``anonymous``.
    """
    st = get_settings()
    if not st.supabase_url:
        return "anonymous", ""
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    req = urllib.request.Request(
        f"{st.supabase_url.rstrip('/')}/auth/v1/user",
        headers={
            "Authorization": f"Bearer {token}",
            "apikey": st.supabase_anon_key or st.supabase_service_role_key,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            user = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 — bad/expired token or outage
        raise HTTPException(status_code=401, detail="Invalid session.") from exc
    uid = str(user.get("id") or "")
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid session.")
    return uid, str(user.get("email") or "")


def _require_admin(request: Request) -> str:
    expected = get_settings().admin_token
    if not expected:
        raise HTTPException(status_code=503, detail="Admin approvals are not configured.")
    supplied = request.headers.get("x-admin-token", "")
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(status_code=403, detail="Invalid admin token.")
    return "admin"


def _http(exc: BillingError) -> HTTPException:
    if isinstance(exc, PaymentValidationError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, PaymentNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, PaymentStateError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


# ── Public ───────────────────────────────────────────────────────────────────
@router.get("/plans")
def list_plans() -> dict:
    service = get_billing_service()
    return {
        "plans": service.plans(),
        "billing_enabled": bool(get_settings().billing_enabled),
        "payoneer_configured": get_settings().payoneer_configured,
    }


@router.get("/payment-info")
def payment_info() -> dict:
    return get_billing_service().payment_info()


# ── User ─────────────────────────────────────────────────────────────────────
@router.get("/subscription")
def get_subscription(request: Request) -> dict:
    user_id, _ = _caller(request)
    try:
        return get_billing_service().subscription_summary(user_id)
    except BillingStoreError as exc:
        raise HTTPException(status_code=500, detail=f"Could not read subscription: {exc}") from exc
    except BillingError as exc:
        raise _http(exc) from exc


@router.post("/payments", status_code=201)
async def submit_payment(
    request: Request,
    tier: str = Form(...),
    reference: str = Form(...),
    method: str = Form("payoneer"),
    sender_name: str = Form(""),
    screenshot: UploadFile | None = None,
) -> dict:
    user_id, email = _caller(request)
    limit = get_settings().payment_screenshot_max_bytes
    data = b""
    ctype = ""
    if screenshot is not None:
        data = await screenshot.read(limit + 1)
        ctype = (screenshot.content_type or "").lower()
    try:
        payment = get_billing_service().submit_payment(
            user_id=user_id, tier=tier, reference=reference, method=method,
            email=email, sender_name=sender_name,
            screenshot=data, screenshot_type=ctype,
        )
    except BillingError as exc:
        raise _http(exc) from exc
    return {"payment": get_billing_service()._payment_dict(payment, with_url=False)}


@router.get("/payments")
def my_payments(request: Request) -> dict:
    user_id, _ = _caller(request)
    try:
        return {"payments": get_billing_service().my_payments(user_id)}
    except BillingError as exc:
        raise _http(exc) from exc


# ── Admin ────────────────────────────────────────────────────────────────────
@router.get("/admin/payments")
def admin_list(request: Request, status: str | None = None) -> dict:
    _require_admin(request)
    try:
        return {"payments": get_billing_service().admin_payments(status)}
    except BillingError as exc:
        raise _http(exc) from exc


@router.post("/admin/payments/{payment_id}/approve")
def admin_approve(payment_id: str, request: Request, body: DecisionRequest | None = None) -> dict:
    reviewer = _require_admin(request)
    try:
        return {"payment": get_billing_service().approve_payment(
            payment_id, reviewer=reviewer, note=(body.note if body else ""))}
    except BillingError as exc:
        raise _http(exc) from exc


@router.post("/admin/payments/{payment_id}/reject")
def admin_reject(payment_id: str, request: Request, body: DecisionRequest | None = None) -> dict:
    reviewer = _require_admin(request)
    try:
        return {"payment": get_billing_service().reject_payment(
            payment_id, reviewer=reviewer, note=(body.note if body else ""))}
    except BillingError as exc:
        raise _http(exc) from exc
