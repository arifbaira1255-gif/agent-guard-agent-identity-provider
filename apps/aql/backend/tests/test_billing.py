"""Tests for billing: plan catalogue, manual payment verification, approvals.

Everything runs against the in-memory StateManager fallback (no Supabase) and
the FastAPI TestClient; no network is touched.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from core.billing import (
    PLANS,
    BillingService,
    BillingStore,
    PaymentNotFoundError,
    PaymentStateError,
    PaymentValidationError,
    get_plan,
    reset_billing_service,
)
from core.config import get_settings
from main import app

PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 64


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    st = get_settings()
    monkeypatch.setattr(st, "supabase_url", "", raising=False)
    monkeypatch.setattr(st, "admin_token", "secret-admin", raising=False)
    monkeypatch.setattr(st, "payoneer_email", "pay@example.com", raising=False)
    reset_billing_service()
    yield
    reset_billing_service()


def _svc() -> BillingService:
    return BillingService(store=BillingStore())


def _submit(svc, ref="TXN-1001", tier="pro", user="u1", **kw):
    return svc.submit_payment(
        user_id=user, tier=tier, reference=ref,
        screenshot=kw.pop("screenshot", PNG),
        screenshot_type=kw.pop("screenshot_type", "image/png"), **kw,
    )


def test_catalogue_has_three_tiers_and_no_stripe_fields():
    assert [p.id for p in PLANS] == ["free", "pro", "team"]
    assert "stripe_price_id" not in get_plan("pro").to_dict()


def test_submit_creates_pending_payment_without_activating():
    svc = _svc()
    p = _submit(svc)
    assert p.status == "pending" and p.amount_usd == 29.0
    assert svc.get_subscription("u1").tier == "free"


@pytest.mark.parametrize("kw", [
    {"tier": "free"}, {"tier": "enterprise"}, {"ref": "abc"},
    {"screenshot": b""}, {"screenshot": b"not-an-image"},
    {"screenshot_type": "text/html"}, {"method": "cash"},
])
def test_submit_validation(kw):
    with pytest.raises(PaymentValidationError):
        _submit(_svc(), **kw)


def test_duplicate_reference_rejected_but_reusable_after_rejection():
    svc = _svc()
    p = _submit(svc)
    with pytest.raises(PaymentStateError):
        _submit(svc, user="u2")
    svc.reject_payment(p.id)
    assert _submit(svc, user="u2").status == "pending"


def test_approve_activates_tier_and_resets_usage():
    svc = _svc()
    p = _submit(svc, tier="team")
    svc.record_usage("u1", tokens=500)
    out = svc.approve_payment(p.id, reviewer="admin")
    assert out["status"] == "approved"
    sub = svc.get_subscription("u1")
    assert sub.tier == "team" and sub.is_active and sub.current_period_end
    assert svc.get_usage("u1").tokens_used == 0
    assert svc.get_usage("u1").tokens_limit == get_plan("team").monthly_token_limit


def test_decision_is_final():
    svc = _svc()
    p = _submit(svc)
    svc.approve_payment(p.id)
    with pytest.raises(PaymentStateError):
        svc.approve_payment(p.id)
    with pytest.raises(PaymentStateError):
        svc.reject_payment(p.id)
    with pytest.raises(PaymentNotFoundError):
        svc.approve_payment("missing")


def test_reject_leaves_user_on_free():
    svc = _svc()
    p = _submit(svc)
    assert svc.reject_payment(p.id, note="no funds")["status"] == "rejected"
    assert svc.get_subscription("u1").tier == "free"


# ── HTTP layer ────────────────────────────────────────────────────────────────
client = TestClient(app)
ADMIN = {"X-Admin-Token": "secret-admin"}


def test_public_endpoints():
    assert client.get("/v1/billing/plans").status_code == 200
    info = client.get("/v1/billing/payment-info").json()
    assert info["payoneer_email"] == "pay@example.com"


def test_http_submit_then_admin_approves():
    r = client.post(
        "/v1/billing/payments",
        data={"tier": "pro", "reference": "HTTP-REF-1", "method": "payoneer"},
        files={"screenshot": ("proof.png", PNG, "image/png")},
    )
    assert r.status_code == 201, r.text
    pid = r.json()["payment"]["id"]
    assert client.get("/v1/billing/admin/payments").status_code == 403
    pending = client.get("/v1/billing/admin/payments?status=pending", headers=ADMIN)
    assert pid in [p["id"] for p in pending.json()["payments"]]
    ok = client.post(f"/v1/billing/admin/payments/{pid}/approve", headers=ADMIN, json={})
    assert ok.status_code == 200
    assert client.post(
        f"/v1/billing/admin/payments/{pid}/approve", headers=ADMIN, json={}
    ).status_code == 409
    sub = client.get("/v1/billing/subscription").json()["subscription"]
    assert sub["tier"] == "pro"


def test_http_missing_screenshot_is_400():
    r = client.post("/v1/billing/payments", data={"tier": "pro", "reference": "NOSHOT-1"})
    assert r.status_code == 400


def test_admin_disabled_without_token(monkeypatch):
    monkeypatch.setattr(get_settings(), "admin_token", "", raising=False)
    assert client.get("/v1/billing/admin/payments", headers=ADMIN).status_code == 503
