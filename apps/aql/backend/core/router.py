"""Model router — picks the best LLM for a given task.

The router is the heart of AQL-1's "operating layer" claim: instead of
hard-coding one provider, it inspects the task, scores its complexity, routes
to the model that fits best (cost, latency, capability), estimates the cost of
the request, and — if the chosen provider fails — walks a fallback chain until
something answers. It never hard-fails: the last link in the chain is a local
stub response.

Design goals
------------
* **Runs with zero API keys.** Classification is a local heuristic; the model
  call degrades to a stub. Add keys in ``.env`` to go live.
* **Explainable.** Every decision carries the signals that produced it.
* **Typed failures.** ``RouterError`` and friends, never bare ``Exception``.
* **UnoRouter + ExperimentLab gateways.** All model traffic goes through
  OpenAI-compatible endpoints: UnoRouter (``UNOROUTER_API_KEY``) is primary and
  ExperimentLab (``EXPERIMENTLAB_API_KEY``) is the fallback. There are no direct
  OpenAI/Anthropic dependencies; with no keys it degrades to the local stub.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from .config import get_settings

# ── Optional tokenizer (falls back to a char heuristic if unavailable) ────────
try:  # pragma: no cover - depends on the environment
    import tiktoken

    _ENCODER = tiktoken.get_encoding("cl100k_base")
except Exception:  # noqa: BLE001 - any import/encoding failure → heuristic
    _ENCODER = None


# ══════════════════════════════════════════════════════════════════════════════
# Typed exceptions
# ══════════════════════════════════════════════════════════════════════════════
class RouterError(Exception):
    """Base class for every router failure."""


class ClassificationError(RouterError):
    """Raised when complexity classification cannot be completed."""


class ModelCallError(RouterError):
    """Raised when a single provider/model call fails (triggers fallback)."""

    def __init__(self, provider: str, model: str, message: str) -> None:
        self.provider = provider
        self.model = model
        super().__init__(f"{provider}/{model}: {message}")


class AllProvidersFailedError(RouterError):
    """Raised only if even the local stub fallback is unavailable."""


# ══════════════════════════════════════════════════════════════════════════════
# Enums & data structures
# ══════════════════════════════════════════════════════════════════════════════
class Complexity(str, Enum):
    """Task complexity bucket produced by :meth:`ModelRouter.classify`."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class ModelChoice(str, Enum):
    """Logical model tiers the router can select (kept for compatibility)."""

    FAST = "fast"          # cheap, low-latency — classification, routing
    BALANCED = "balanced"  # general reasoning — default
    DEEP = "deep"          # hard reasoning / long context


# Complexity → logical tier
_COMPLEXITY_TO_TIER: dict[Complexity, ModelChoice] = {
    Complexity.LOW: ModelChoice.FAST,
    Complexity.MEDIUM: ModelChoice.BALANCED,
    Complexity.HIGH: ModelChoice.DEEP,
}


@dataclass(frozen=True)
class RouteDecision:
    """The router's verdict for one request."""

    provider: str          # "unorouter" | "experimentlab"
    model: str
    tier: ModelChoice
    reason: str
    complexity: Complexity = Complexity.MEDIUM
    signals: tuple[str, ...] = ()
    estimated_input_tokens: int = 0
    estimated_output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    fallback_chain: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "tier": self.tier.value,
            "complexity": self.complexity.value,
            "reason": self.reason,
            "signals": list(self.signals),
            "estimated_input_tokens": self.estimated_input_tokens,
            "estimated_output_tokens": self.estimated_output_tokens,
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
            "fallback_chain": [f"{p}/{m}" for p, m in self.fallback_chain],
        }


@dataclass
class RouterResult:
    """The outcome of an actual (fallback-aware) model call."""

    text: str
    provider: str
    model: str
    complexity: Complexity
    used_fallback: bool = False
    is_stub: bool = False
    estimated_cost_usd: float = 0.0
    attempts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "provider": self.provider,
            "model": self.model,
            "complexity": self.complexity.value,
            "used_fallback": self.used_fallback,
            "is_stub": self.is_stub,
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
            "attempts": self.attempts,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Pricing table — USD per 1,000 tokens (public list prices, approximate)
# ══════════════════════════════════════════════════════════════════════════════
#: model id → (input $/1K tokens, output $/1K tokens)
#: Default model served through the UnoRouter gateway (Opus-class Claude).
UNOROUTER_MODEL_DEFAULT = "claude-opus-4.6"

PRICING: dict[str, tuple[float, float]] = {
    # UnoRouter serves Claude as a pass-through; the rates mirror Anthropic
    # list prices for an Opus-class model ($15 / $75 per 1M tokens).
    "claude-opus-4.6": (0.01500, 0.07500),
}

#: Sentinel model ids; resolved to the configured models at call time.
EXPERIMENTLAB_MODEL_DEFAULT = "experimentlab-default"

#: Fallback chain per complexity — UnoRouter first, ExperimentLab second, then
#: the local stub (handled by the executor, not listed here).
FALLBACK_CHAINS: dict[Complexity, tuple[tuple[str, str], ...]] = {
    c: (
        ("unorouter", UNOROUTER_MODEL_DEFAULT),
        ("experimentlab", EXPERIMENTLAB_MODEL_DEFAULT),
    )
    for c in Complexity
}

#: Default output-token budget per complexity (used for cost estimation).
_OUTPUT_BUDGET: dict[Complexity, int] = {
    Complexity.LOW: 256,
    Complexity.MEDIUM: 768,
    Complexity.HIGH: 2048,
}


# ══════════════════════════════════════════════════════════════════════════════
# Heuristic signal tables
# ══════════════════════════════════════════════════════════════════════════════
_HIGH_HINTS = (
    "analyze", "analyse", "architect", "design", "debug", "refactor",
    "strategy", "research", "prove", "derive", "optimize", "optimise",
    "plan", "multi-step", "step by step", "compare", "evaluate",
    "trade-off", "tradeoff", "algorithm", "complexity", "theorem",
    "proof", "migrate", "security", "audit", "implement", "build",
    "integrate", "benchmark", "root cause", "end-to-end",
)
_LOW_HINTS = (
    "classify", "tag", "extract", "summarize briefly", "summarise briefly",
    "translate", "yes/no", "one word", "rename", "format", "hello", "hi ",
    "what is the capital", "list the", "convert",
)
_CODE_HINTS = (
    "```", "def ", "class ", "import ", "function", "code", "bug",
    "traceback", "regex", "sql", "api", "endpoint", "typescript", "python",
)
_MATH_HINTS = (
    "equation", "integral", "derivative", "matrix", "probability", "solve",
    "calculate", "formula", "∑", "∫", "√", "percent", "variance",
)
_MULTISTEP_HINTS = (
    "then", "after that", "step 1", "first,", "second,", "finally",
    "and then", "followed by", "next,",
)


def _count_matches(text: str, hints: tuple[str, ...]) -> list[str]:
    return [h for h in hints if h in text]


# ══════════════════════════════════════════════════════════════════════════════
# Token & cost estimation
# ══════════════════════════════════════════════════════════════════════════════
def estimate_tokens(text: str) -> int:
    """Estimate the token count of ``text``.

    Uses ``tiktoken`` when available, otherwise a ~4-chars-per-token heuristic.
    """
    if not text:
        return 0
    if _ENCODER is not None:
        try:
            return len(_ENCODER.encode(text))
        except Exception:  # noqa: BLE001 - fall through to heuristic
            pass
    return max(1, len(text) // 4)


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate USD cost for a call to ``model``.

    Unknown models fall back to the most expensive known price so estimates
    never silently under-report.
    """
    in_price, out_price = PRICING.get(model, (0.003, 0.015))
    return (input_tokens / 1000.0) * in_price + (output_tokens / 1000.0) * out_price


# ══════════════════════════════════════════════════════════════════════════════
# The router
# ══════════════════════════════════════════════════════════════════════════════
class ModelRouter:
    """Deterministic, explainable model selection with provider fallback."""

    def __init__(
        self,
        classifier: Callable[[str], Complexity] | None = None,
        use_llm_classifier: bool = True,
    ) -> None:
        self.settings = get_settings()
        self._classifier = classifier
        self._use_llm_classifier = use_llm_classifier

    # ── Classification ───────────────────────────────────────────────────────
    def _heuristic_score(self, task: str) -> tuple[int, list[str]]:
        """Return (score, signals) for ``task`` using lightweight heuristics."""
        text = (task or "").lower()
        words = len(text.split())
        score = 0
        signals: list[str] = []

        # Length signals
        if words > 200:
            score += 3
            signals.append("very_long_prompt")
        elif words > 80:
            score += 2
            signals.append("long_prompt")
        elif words > 30:
            score += 1
            signals.append("medium_prompt")

        # Keyword signals
        high = _count_matches(text, _HIGH_HINTS)
        if high:
            score += min(2 * len(high), 6)
            signals.append(f"high_keywords:{','.join(high[:4])}")

        low = _count_matches(text, _LOW_HINTS)
        if low:
            score -= min(2 * len(low), 4)
            signals.append(f"low_keywords:{','.join(low[:4])}")

        # Domain signals
        if _count_matches(text, _CODE_HINTS):
            score += 1
            signals.append("code")
        if _count_matches(text, _MATH_HINTS):
            score += 2
            signals.append("math")
        if _count_matches(text, _MULTISTEP_HINTS) or re.search(r"\b\d\.\s", text):
            score += 1
            signals.append("multi_step")

        return score, signals

    def _score_to_complexity(self, score: int) -> Complexity:
        if score <= 0:
            return Complexity.LOW
        if score <= 3:
            return Complexity.MEDIUM
        return Complexity.HIGH

    def _llm_classify(self, task: str) -> Complexity | None:
        """Optional LLM classifier (disabled: the heuristic is the default)."""
        return None

    def classify(self, task: str) -> Complexity:
        """Categorise ``task`` as ``Low``, ``Medium`` or ``High``.

        A custom ``classifier`` passed to ``__init__`` wins; otherwise the
        optional LLM classifier is tried (when a key is present) and the local
        heuristic is the guaranteed fallback.
        """
        try:
            if self._classifier is not None:
                return self._classifier(task)
            if self._use_llm_classifier:
                llm = self._llm_classify(task)
                if llm is not None:
                    return llm
            score, _ = self._heuristic_score(task)
            return self._score_to_complexity(score)
        except Exception as exc:  # noqa: BLE001 - never let classification crash
            raise ClassificationError(str(exc)) from exc

    def classify_detailed(self, task: str) -> tuple[Complexity, list[str]]:
        """Like :meth:`classify` but also returns the heuristic signals."""
        score, signals = self._heuristic_score(task)
        return self._score_to_complexity(score), signals

    # ── Provider helpers ────────────────────────────────────────────────────
    def _unorouter_enabled(self) -> bool:
        """True when a UnoRouter key is set."""
        return bool(getattr(self.settings, "unorouter_api_key", ""))

    def _resolve_model(self, provider: str, model: str) -> str:
        """Swap provider sentinels for the configured model names."""
        if provider == "unorouter" and model == UNOROUTER_MODEL_DEFAULT:
            return self.settings.unorouter_model or UNOROUTER_MODEL_DEFAULT
        if provider == "experimentlab" and model == EXPERIMENTLAB_MODEL_DEFAULT:
            return (
                self.settings.experimentlab_model
                or self.settings.unorouter_model
                or UNOROUTER_MODEL_DEFAULT
            )
        return model

    def _base_url(self, provider: str) -> str:
        """Normalised base URL (no trailing slash) for an OpenAI-compatible provider."""
        if provider == "experimentlab":
            base = (self.settings.experimentlab_base_url or "").strip()
            return (base or "https://api.experimentlab.ai/v1").rstrip("/")
        base = (self.settings.unorouter_base_url or "").strip()
        return (base or "https://api.unorouter.com/v1").rstrip("/")

    def _api_key(self, provider: str) -> str:
        if provider == "experimentlab":
            return self.settings.experimentlab_api_key
        return self.settings.unorouter_api_key

    # ── Routing ──────────────────────────────────────────────────────────────
    def route(self, task: str, prefer: str | None = None) -> RouteDecision:
        """Return the model to use for ``task``.

        ``prefer`` may be ``"unorouter"`` or ``"experimentlab"`` to
        bias the provider; the complexity tier still decides the model class.
        """
        complexity, signals = self.classify_detailed(task)
        tier = _COMPLEXITY_TO_TIER[complexity]
        chain = FALLBACK_CHAINS[complexity]

        # Pick the primary from the chain, honouring a provider preference.
        primary = chain[0]
        if prefer:
            for candidate in chain:
                if candidate[0] == prefer:
                    primary = candidate
                    break
            else:
                # Preferred provider not in the chain — synthesise a sensible one.
                primary = (prefer, self._default_model_for(prefer, complexity))

        provider, model = primary
        model = self._resolve_model(provider, model)

        input_tokens = estimate_tokens(task)
        output_tokens = _OUTPUT_BUDGET[complexity]
        cost = estimate_cost(model, input_tokens, output_tokens)

        reason = (
            f"complexity={complexity.value}; tier={tier.value}; "
            f"provider={provider}; signals={','.join(signals) or 'none'}"
        )

        return RouteDecision(
            provider=provider,
            model=model,
            tier=tier,
            reason=reason,
            complexity=complexity,
            signals=tuple(signals),
            estimated_input_tokens=input_tokens,
            estimated_output_tokens=output_tokens,
            estimated_cost_usd=cost,
            fallback_chain=chain,
        )

    def _default_model_for(self, provider: str, complexity: Complexity) -> str:
        return self._resolve_model(
            provider,
            EXPERIMENTLAB_MODEL_DEFAULT
            if provider == "experimentlab"
            else UNOROUTER_MODEL_DEFAULT,
        )

    def fallback(self, decision: RouteDecision) -> RouteDecision:
        """Return the next model in the fallback chain after ``decision``."""
        chain = decision.fallback_chain or FALLBACK_CHAINS[decision.complexity]
        current = (decision.provider, decision.model)
        try:
            idx = chain.index(current)
        except ValueError:
            # The model may have been resolved from the sentinel; match provider.
            idx = next(
                (i for i, link in enumerate(chain) if link[0] == decision.provider), -1
            )
        nxt = chain[idx + 1] if idx + 1 < len(chain) else chain[-1]
        nxt_model = self._resolve_model(nxt[0], nxt[1])
        return RouteDecision(
            provider=nxt[0],
            model=nxt_model,
            tier=decision.tier,
            reason=f"fallback from {decision.provider}/{decision.model}",
            complexity=decision.complexity,
            signals=decision.signals,
            estimated_input_tokens=decision.estimated_input_tokens,
            estimated_output_tokens=decision.estimated_output_tokens,
            estimated_cost_usd=estimate_cost(
                nxt_model, decision.estimated_input_tokens, decision.estimated_output_tokens
            ),
            fallback_chain=chain,
        )

    # ── Execution with fallback ──────────────────────────────────────────────
    def _call_provider(
        self, provider: str, model: str, prompt: str, system: str | None = None
    ) -> str:
        """Call one provider. Raises :class:`ModelCallError` on any failure."""
        if provider in ("unorouter", "experimentlab"):
            # Both gateways expose an OpenAI-compatible chat-completions API, so
            # one POST (standard-library urllib) serves either of them.
            key = self._api_key(provider)
            if not key:
                raise ModelCallError(
                    provider, model, f"{provider.upper()}_API_KEY not set"
                )
            url = f"{self._base_url(provider)}/chat/completions"
            messages = (
                ([{"role": "system", "content": system}] if system else [])
                + [{"role": "user", "content": prompt}]
            )
            payload: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "stream": False,
            }
            headers = {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            try:
                data = self._post_json(url, payload, headers, provider=provider)
                return data["choices"][0]["message"]["content"] or ""
            except ModelCallError:
                raise
            except Exception as exc:  # noqa: BLE001 — malformed/partial body
                raise ModelCallError(provider, model, str(exc)) from exc

        raise ModelCallError(provider, model, "unknown provider")

    def _post_json(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        timeout: int = 60,
        provider: str = provider,
    ) -> dict[str, Any]:
        """POST ``payload`` as JSON and return the decoded response body.

        Standard library only (``urllib``), so the UnoRouter provider adds no
        SDK dependency. Transport, HTTP and decode failures are surfaced as a
        typed :class:`ModelCallError`, which the fallback chain then handles.
        """
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:  # 4xx/5xx — carry the API message
            detail = ""
            try:
                detail = exc.read().decode("utf-8")[:500]
            except Exception:  # noqa: BLE001 - body may be unreadable
                pass
            raise ModelCallError(
                provider,
                str(payload.get("model", "?")),
                f"HTTP {exc.code}: {detail or exc.reason}",
            ) from exc
        except Exception as exc:  # noqa: BLE001 - DNS, TLS, timeout, refused
            raise ModelCallError(
                provider, str(payload.get("model", "?")), str(exc)
            ) from exc
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ModelCallError(
                provider,
                str(payload.get("model", "?")),
                f"invalid JSON response: {raw[:200]!r}",
            ) from exc

    def _stub_response(self, task: str, decision: RouteDecision) -> str:
        """Local, always-available response so the system never hard-fails."""
        return (
            f"[stub:{decision.provider}/{decision.model}] "
            f"complexity={decision.complexity.value} :: {task}"
        )

    def call(
        self,
        task: str,
        prefer: str | None = None,
        system: str | None = None,
    ) -> RouterResult:
        """Route ``task`` and execute it, walking the fallback chain.

        Tries each ``(provider, model)`` in the chain in order; on
        :class:`ModelCallError` it moves to the next. If every provider fails
        (e.g. no API keys), it returns a local stub response — never raises.
        """
        decision = self.route(task, prefer=prefer)
        chain = decision.fallback_chain or FALLBACK_CHAINS[decision.complexity]
        attempts: list[dict[str, Any]] = []

        for index, (provider, raw_model) in enumerate(chain):
            model = self._resolve_model(provider, raw_model)
            try:
                text = self._call_provider(provider, model, task, system=system)
                attempts.append(
                    {"provider": provider, "model": model, "status": "ok"}
                )
                return RouterResult(
                    text=text,
                    provider=provider,
                    model=model,
                    complexity=decision.complexity,
                    used_fallback=index > 0,
                    is_stub=False,
                    estimated_cost_usd=estimate_cost(
                        model,
                        decision.estimated_input_tokens,
                        decision.estimated_output_tokens,
                    ),
                    attempts=attempts,
                )
            except ModelCallError as exc:
                attempts.append(
                    {"provider": provider, "model": model, "status": "error",
                     "error": str(exc)}
                )
                continue

        # Every provider failed → local stub. The system never hard-fails.
        try:
            text = self._stub_response(task, decision)
        except Exception as exc:  # noqa: BLE001 - truly unrecoverable
            raise AllProvidersFailedError(str(exc)) from exc

        attempts.append({"provider": "local", "model": "stub", "status": "ok"})
        return RouterResult(
            text=text,
            provider="local",
            model="stub",
            complexity=decision.complexity,
            used_fallback=True,
            is_stub=True,
            estimated_cost_usd=0.0,
            attempts=attempts,
        )


__all__ = [
    "ModelRouter",
    "RouteDecision",
    "RouterResult",
    "Complexity",
    "ModelChoice",
    "RouterError",
    "ClassificationError",
    "ModelCallError",
    "AllProvidersFailedError",
    "PRICING",
    "FALLBACK_CHAINS",
    "UNOROUTER_MODEL_DEFAULT",
    "EXPERIMENTLAB_MODEL_DEFAULT",
    "estimate_tokens",
    "estimate_cost",
]
