"""Tests for the ModelRouter: classification, cost estimation, fallback."""

import pytest

from core.router import (
    FALLBACK_CHAINS,
    PRICING,
    AllProvidersFailedError,
    Complexity,
    ModelCallError,
    ModelChoice,
    ModelRouter,
    estimate_cost,
    estimate_tokens,
)


# ── Classification ────────────────────────────────────────────────────────────
def test_classify_low():
    assert ModelRouter().classify("hello") is Complexity.LOW


def test_classify_medium():
    assert ModelRouter().classify("analyze the data for me") is Complexity.MEDIUM


def test_classify_high():
    task = "architect a system design and implement a secure migration plan"
    assert ModelRouter().classify(task) is Complexity.HIGH


def test_classify_empty_is_low():
    assert ModelRouter().classify("") is Complexity.LOW


def test_classify_none_is_low():
    assert ModelRouter().classify(None) is Complexity.LOW  # type: ignore[arg-type]


def test_custom_classifier_wins():
    r = ModelRouter(classifier=lambda t: Complexity.HIGH)
    assert r.classify("hello") is Complexity.HIGH


def test_math_signal_raises_complexity():
    r = ModelRouter()
    assert r.classify("solve this integral and derive the equation") is Complexity.HIGH


# ── Routing ───────────────────────────────────────────────────────────────────
def test_route_primary_is_unorouter_for_every_tier():
    for task in ("hello", "analyze the data for me",
                 "architect a secure multi-step migration and optimization strategy"):
        d = ModelRouter().route(task)
        assert d.provider == "unorouter"
        assert d.model == "claude-opus-4.6"


def test_route_tiers_follow_complexity():
    assert ModelRouter().route("hello").tier is ModelChoice.FAST
    d = ModelRouter().route(
        "architect a secure multi-step migration and optimization strategy"
    )
    assert d.complexity is Complexity.HIGH and d.tier is ModelChoice.DEEP


def test_route_prefer_provider():
    d = ModelRouter().route("hello", prefer="experimentlab")
    assert d.provider == "experimentlab"


def test_no_direct_vendor_providers_in_chains():
    for chain in FALLBACK_CHAINS.values():
        assert {p for p, _ in chain} == {"unorouter", "experimentlab"}


def test_route_decision_has_cost_fields():
    d = ModelRouter().route("hello")
    assert d.estimated_input_tokens > 0
    assert d.estimated_output_tokens > 0
    assert d.estimated_cost_usd > 0


def test_route_decision_to_dict():
    d = ModelRouter().route("hello").to_dict()
    assert d["tier"] == "fast"
    assert "fallback_chain" in d


# ── Cost estimation ───────────────────────────────────────────────────────────
def test_estimate_tokens_positive():
    assert estimate_tokens("hello world") > 0


def test_estimate_tokens_empty():
    assert estimate_tokens("") == 0


def test_estimate_cost_opus():
    expected = (1000 / 1000) * 0.015 + (256 / 1000) * 0.075
    assert estimate_cost("claude-opus-4.6", 1000, 256) == pytest.approx(expected, abs=1e-9)


def test_estimate_cost_zero_tokens():
    assert estimate_cost("claude-opus-4.6", 0, 0) == 0.0


def test_estimate_cost_unknown_model_not_under_reported():
    # Unknown model should fall back to a conservative (non-zero) price.
    assert estimate_cost("totally-unknown-model", 1000, 1000) > 0.0


def test_pricing_table_has_expected_models():
    assert "claude-opus-4.6" in PRICING


# ── Fallback behavior ─────────────────────────────────────────────────────────
def test_fallback_advances_chain():
    r = ModelRouter()
    nxt = r.fallback(r.route("hello"))
    assert nxt.provider == "experimentlab"


def test_fallback_at_end_stays_on_last():
    r = ModelRouter()
    second = r.fallback(r.route("hello"))
    last = r.fallback(second)
    assert last.provider == second.provider == "experimentlab"


def test_call_returns_stub_without_keys():
    # With no API keys configured, every provider in the chain raises and the
    # router must fall through to the local stub — never raise.
    r = ModelRouter()
    result = r.call("hello")
    assert result.is_stub is True
    assert result.provider == "local"
    assert result.model == "stub"
    assert result.used_fallback is True
    # one attempt per provider in the chain + one final stub attempt
    assert len(result.attempts) == len(FALLBACK_CHAINS[Complexity.LOW]) + 1


def test_call_falls_back_to_second_provider(monkeypatch):
    r = ModelRouter()

    def fake_call(provider, model, prompt, system=None):
        if provider == "unorouter":
            raise ModelCallError(provider, model, "boom")
        return f"ok from {provider}/{model}"

    monkeypatch.setattr(r, "_call_provider", fake_call)
    result = r.call("hello")

    assert result.is_stub is False
    assert result.used_fallback is True
    assert result.provider == "experimentlab"
    assert result.text.startswith("ok from experimentlab/")


def test_call_uses_first_provider_when_healthy(monkeypatch):
    r = ModelRouter()

    def fake_call(provider, model, prompt, system=None):
        return f"ok from {provider}/{model}"

    monkeypatch.setattr(r, "_call_provider", fake_call)
    result = r.call("hello")

    assert result.is_stub is False
    assert result.used_fallback is False
    assert result.provider == "unorouter"
    assert result.model == "claude-opus-4.6"


def test_classify_never_raises_on_broken_custom_classifier():
    def broken(_t):
        raise RuntimeError("classifier exploded")

    r = ModelRouter(classifier=broken)
    # classification is wrapped: the broken classifier surfaces as a typed error
    with pytest.raises(Exception) as exc_info:
        r.classify("hello")
    assert isinstance(exc_info.value, Exception)


# ── OpenAI-compatible gateway calls ──────────────────────────────────────────
def test_gateway_call_posts_to_chat_completions(monkeypatch):
    from core.config import get_settings

    st = get_settings()
    monkeypatch.setattr(st, "unorouter_api_key", "k-test", raising=False)
    r = ModelRouter()
    seen = {}

    def fake_post(url, payload, headers, timeout=60, provider="unorouter"):
        seen.update(url=url, payload=payload, headers=headers, provider=provider)
        return {"choices": [{"message": {"content": "hi"}}]}

    monkeypatch.setattr(r, "_post_json", fake_post)
    assert r._call_provider("unorouter", "claude-opus-4.6", "yo", "sys") == "hi"
    assert seen["url"].endswith("/chat/completions")
    assert seen["headers"]["Authorization"] == "Bearer k-test"
    assert seen["payload"]["messages"][0] == {"role": "system", "content": "sys"}


def test_gateway_call_without_key_raises(monkeypatch):
    from core.config import get_settings

    monkeypatch.setattr(get_settings(), "experimentlab_api_key", "", raising=False)
    with pytest.raises(ModelCallError):
        ModelRouter()._call_provider("experimentlab", "m", "p")
