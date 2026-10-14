"""Model routing: one interface, several providers, bounded and fail-closed.

WHY A ROUTER AND NOT A CLIENT
-----------------------------
A production agent must be able to (a) run against a deterministic provider in tests with no network,
(b) fail over between providers without the agent loop knowing, and (c) stop when model spend crosses
a ceiling.  Those three concerns live here, not in the orchestrator.

FAIL-CLOSED RULE
----------------
No provider, no answer: when every route fails the router raises
:class:`~agent_platform.errors.ProviderUnavailable`.  It never invents a completion, and it never
silently downgrades an error into an empty-but-OK response.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple

from .config import PlatformConfig
from .errors import ConfigError, ModelError, ProviderUnavailable, InvalidModelOutput
from .types import Message, ModelResponse, ToolCall, Usage
from .validation import canonical_json, truncate

__all__ = [
    "ModelProvider", "RouteRequest", "Route", "TIERS",
    "DeterministicProvider", "OpenAICompatibleProvider", "CallableProvider",
    "ModelRouter", "coerce_response", "estimate_tokens", "parse_openai_tool_calls",
    "price_usage",
]

#: Routing tiers.  A caller asks for a *class* of model; the router picks a concrete one.
Tier = str
TIERS: Tuple[str, ...] = ("fast", "balanced", "deep")


# ---------------------------------------------------------------------------------------------
# Token estimation
# ---------------------------------------------------------------------------------------------
def estimate_tokens(text: str) -> int:
    """Cheap, provider-independent token estimate (~4 chars/token, floored at 1 for non-empty).

    Used for *budget enforcement* only.  A real provider's reported usage always wins when present,
    so an estimate never inflates a bill -- and when no usage is reported the estimate still stops a
    runaway loop.
    """
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


def _prompt_text(messages: Sequence[Message]) -> str:
    parts: List[str] = []
    for message in messages:
        parts.append(f"{message.role}:{message.content}")
        for call in message.tool_calls or ():
            parts.append(f"{call.name}:{canonical_json(call.arguments)}")
    return "\n".join(parts)


# ---------------------------------------------------------------------------------------------
# Provider protocol
# ---------------------------------------------------------------------------------------------
@dataclass
class RouteRequest:
    """Everything a provider needs for one call (already resolved by the router)."""

    messages: List[Message]
    model: str
    tools: List[Dict[str, Any]] = field(default_factory=list)
    temperature: float = 0.0
    max_tokens: int = 1024
    timeout_s: float = 60.0
    tier: Tier = "balanced"
    metadata: Dict[str, Any] = field(default_factory=dict)


class ModelProvider(Protocol):
    """A model source.  ``name`` appears in traces and usage records."""

    name: str

    def complete(self, request: RouteRequest) -> ModelResponse:  # pragma: no cover - protocol
        ...


class CallableProvider:
    """Adapts ``fn(request) -> ModelResponse | str | dict`` into a provider.

    The flexible return type is what lets an embedder plug in an in-house gateway without writing a
    class; every shape is normalised through :func:`coerce_response`.
    """

    def __init__(self, fn: Callable[[RouteRequest], Any], name: str = "callable") -> None:
        if not callable(fn):
            raise ConfigError("CallableProvider requires a callable")
        self._fn = fn
        self.name = name

    def complete(self, request: RouteRequest) -> ModelResponse:
        started = time.monotonic()
        try:
            raw = self._fn(request)
        except Exception as exc:  # noqa: BLE001 - normalised into a provider failure
            raise ProviderUnavailable(f"{self.name} failed: {type(exc).__name__}") from exc
        response = coerce_response(raw, model=request.model, provider=self.name)
        response.latency_ms = (time.monotonic() - started) * 1000.0
        return response


class DeterministicProvider:
    """A scripted provider: no network, deterministic, used by tests and offline evaluation.

    Accepts a sequence of responses (consumed in order, the last repeating) or a callable taking the
    request.  Anything not matching the script is a hard error -- a scripted run that quietly returns
    a default would make a broken test look green.
    """

    name = "deterministic"

    def __init__(self, script: Any, *, repeat_last: bool = True) -> None:
        self._callable: Optional[Callable[[RouteRequest], Any]] = None
        self._script: List[Any] = []
        if callable(script):
            self._callable = script
        else:
            self._script = list(script)
            if not self._script:
                raise ConfigError("DeterministicProvider requires at least one scripted response")
        self._index = 0
        self._repeat_last = repeat_last
        self.calls: List[RouteRequest] = []

    def complete(self, request: RouteRequest) -> ModelResponse:
        self.calls.append(request)
        if self._callable is not None:
            raw = self._callable(request)
        else:
            index = min(self._index, len(self._script) - 1)
            if self._index < len(self._script) - 1 or not self._repeat_last:
                self._index += 1
            raw = self._script[index]
        if isinstance(raw, BaseException):
            raise ProviderUnavailable(f"deterministic script raised {type(raw).__name__}")
        return coerce_response(raw, model=request.model, provider=self.name)


# ---------------------------------------------------------------------------------------------
# Response coercion
# ---------------------------------------------------------------------------------------------
def coerce_response(raw: Any, *, model: str = "", provider: str = "") -> ModelResponse:
    """Normalise any provider return shape into a :class:`ModelResponse`.

    A ``None``/empty answer is an error, not an empty success: an agent that treats "nothing" as
    "final answer" reports success while having done nothing.
    """
    if isinstance(raw, ModelResponse):
        if not raw.provider:
            raw.provider = provider
        if not raw.model:
            raw.model = model
        return raw
    if raw is None:
        raise InvalidModelOutput("provider returned no response")
    if isinstance(raw, str):
        response = ModelResponse(text=raw, model=model, provider=provider)
    elif isinstance(raw, Mapping):
        calls = raw.get("tool_calls") or ()
        coerced_calls: List[ToolCall] = []
        for call in calls:
            if isinstance(call, ToolCall):
                coerced_calls.append(call)
            elif isinstance(call, Mapping):
                coerced_calls.append(ToolCall(
                    name=str(call.get("name") or ""),
                    arguments=dict(call.get("arguments") or {}),
                    id=str(call.get("id") or ""),
                    raw_arguments=str(call.get("raw_arguments") or "")))
        usage_raw = raw.get("usage") or {}
        usage = usage_raw if isinstance(usage_raw, Usage) else Usage(
            prompt_tokens=int((usage_raw or {}).get("prompt_tokens", 0) or 0),
            completion_tokens=int((usage_raw or {}).get("completion_tokens", 0) or 0),
            cost_usd=float((usage_raw or {}).get("cost_usd", 0.0) or 0.0))
        response = ModelResponse(
            text=str(raw.get("text") or raw.get("content") or ""),
            tool_calls=tuple(coerced_calls), model=str(raw.get("model") or model),
            provider=str(raw.get("provider") or provider), usage=usage,
            finish_reason=str(raw.get("finish_reason") or "stop"),
            raw=dict(raw.get("raw") or {}))
    else:
        raise InvalidModelOutput(f"unrecognised provider response type {type(raw).__name__}")
    if response.is_empty:
        raise InvalidModelOutput("provider returned an empty response (no text, no tool calls)")
    return response


# ---------------------------------------------------------------------------------------------
# OpenAI-compatible HTTP provider
# ---------------------------------------------------------------------------------------------
def parse_openai_tool_calls(raw: Any) -> Tuple[ToolCall, ...]:
    """Parse ``choices[0].message.tool_calls`` from an OpenAI-compatible response.

    An unparseable ``function.arguments`` becomes a :class:`ToolCall` with empty ``arguments`` and the
    original string in ``raw_arguments``, so the orchestrator can return a structured
    ``invalid_tool_arguments`` result that *shows the model its own text* -- rather than silently
    calling the tool with no arguments, which is how a wrong call becomes a wrong action.
    """
    calls: List[ToolCall] = []
    for item in raw or ():
        if not isinstance(item, Mapping):
            continue
        function = item.get("function") or {}
        name = str(function.get("name") or "")
        arguments_text = function.get("arguments")
        arguments: Dict[str, Any] = {}
        if isinstance(arguments_text, Mapping):
            arguments = dict(arguments_text)
            arguments_text = canonical_json(arguments)
        elif isinstance(arguments_text, str) and arguments_text.strip():
            try:
                parsed = json.loads(arguments_text)
                if isinstance(parsed, Mapping):
                    arguments = dict(parsed)
            except Exception:  # noqa: BLE001 - preserved for the repair turn
                pass
        calls.append(ToolCall(name=name, arguments=arguments,
                              id=str(item.get("id") or ""),
                              raw_arguments=str(arguments_text or "")))
    return tuple(calls)


class OpenAICompatibleProvider:
    """HTTP provider for any OpenAI-compatible ``/chat/completions`` endpoint (stdlib only).

    Bounds enforced here (not left to the caller): a connect/read timeout, a maximum response size, a
    maximum number of retries with backoff, and TLS verification with an optional CA bundle.  Every
    failure is normalised so the router can fail over.
    """

    name = "openai_compatible"

    def __init__(self, config: PlatformConfig, *,
                 opener: Optional[Callable[..., Any]] = None) -> None:
        if not config.base_url:
            raise ConfigError("OpenAICompatibleProvider requires base_url")
        self.config = config
        self.url = config.base_url.rstrip("/") + "/chat/completions"
        self._opener = opener or urllib.request.urlopen

    # -- transport ---------------------------------------------------------------------------
    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self.url.startswith("https://"):
            return None
        if not self.config.verify_tls:
            return ssl._create_unverified_context()  # noqa: S323 - explicit opt-in only
        if self.config.ca_bundle:
            return ssl.create_default_context(cafile=self.config.ca_bundle)
        return ssl.create_default_context()

    def _post(self, payload: dict) -> dict:
        data = canonical_json(payload).encode("utf-8")
        request = urllib.request.Request(self.url, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json")
        request.add_header("User-Agent", "agentguard-agent-platform/0.1")
        if self.config.api_key:
            request.add_header("Authorization", f"Bearer {self.config.api_key}")
        last: Optional[BaseException] = None
        attempts = max(1, int(self.config.max_retries) + 1)
        for attempt in range(attempts):
            try:
                with self._opener(request, float(self.config.request_timeout_s),
                                  self._ssl_context()) as response:
                    raw = response.read(int(self.config.max_response_bytes) + 1)
                if len(raw) > int(self.config.max_response_bytes):
                    raise ModelError("model response exceeded the configured size bound")
                parsed = json.loads(raw.decode("utf-8"))
                if not isinstance(parsed, Mapping):
                    raise ModelError("model response was not a JSON object")
                return dict(parsed)
            except urllib.error.HTTPError as exc:
                last = exc
                if int(getattr(exc, "code", 0)) in (400, 401, 403, 404, 422):
                    break  # a client-side error will not fix itself with a retry
            except Exception as exc:  # noqa: BLE001 - retried, then surfaced
                last = exc
            if attempt + 1 < attempts:
                time.sleep(min(2.0, 0.25 * (2 ** attempt)))
        raise ProviderUnavailable(
            f"{self.name} request failed after {attempts} attempt(s): "
            f"{type(last).__name__ if last else 'unknown'}")

    # -- request -----------------------------------------------------------------------------
    def _payload(self, request: RouteRequest) -> dict:
        payload: Dict[str, Any] = {
            "model": request.model,
            "messages": [_to_openai_message(m) for m in request.messages],
            "temperature": float(request.temperature),
            "max_tokens": int(request.max_tokens),
        }
        if request.tools:
            payload["tools"] = [{"type": "function", "function": t} for t in request.tools]
            payload["tool_choice"] = "auto"
        return payload

    def complete(self, request: RouteRequest) -> ModelResponse:
        started = time.monotonic()
        body = self._post(self._payload(request))
        choices = body.get("choices") or []
        if not choices or not isinstance(choices[0], Mapping):
            raise ModelError("model response contained no choices")
        message = choices[0].get("message") or {}
        content = message.get("content") or ""
        if isinstance(content, list):  # some gateways return content parts
            content = "".join(str(part.get("text", "")) if isinstance(part, Mapping) else str(part)
                              for part in content)
        usage_raw = body.get("usage") or {}
        prompt_tokens = int(usage_raw.get("prompt_tokens", 0) or 0)
        completion_tokens = int(usage_raw.get("completion_tokens", 0) or 0)
        if not prompt_tokens and not completion_tokens:
            prompt_tokens = estimate_tokens(_prompt_text(request.messages))
            completion_tokens = estimate_tokens(str(content))
        return ModelResponse(
            text=str(content), tool_calls=parse_openai_tool_calls(message.get("tool_calls")),
            model=str(body.get("model") or request.model), provider=self.name,
            usage=Usage(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                        cost_usd=price_usage(self.config, request.model, prompt_tokens,
                                             completion_tokens)),
            finish_reason=str(choices[0].get("finish_reason") or "stop"),
            latency_ms=(time.monotonic() - started) * 1000.0,
            raw={"id": body.get("id"), "object": body.get("object")})


def _to_openai_message(message: Message) -> dict:
    out: Dict[str, Any] = {"role": message.role}
    if message.role == "tool":
        out["tool_call_id"] = message.tool_call_id or ""
        if message.name:
            out["name"] = message.name
        out["content"] = message.content
        return out
    out["content"] = message.content or ""
    if message.tool_calls:
        out["tool_calls"] = [
            {"id": call.id or f"call_{i}", "type": "function",
             "function": {"name": call.name,
                          "arguments": call.raw_arguments or canonical_json(call.arguments)}}
            for i, call in enumerate(message.tool_calls)]
    return out


def price_usage(config: PlatformConfig, model: str, prompt_tokens: int,
                completion_tokens: int) -> float:
    """Cost in USD for a call, using the configured per-1M-token prices (0.0 when unpriced)."""
    prices = (config.price_per_million or {}).get(model)
    if not prices:
        return 0.0
    if isinstance(prices, Mapping):
        in_price = float(prices.get("input", 0.0) or 0.0)
        out_price = float(prices.get("output", 0.0) or 0.0)
    else:
        pair = list(prices)
        in_price = float(pair[0]) if pair else 0.0
        out_price = float(pair[1]) if len(pair) > 1 else 0.0
    return round((prompt_tokens / 1_000_000.0) * in_price
                 + (completion_tokens / 1_000_000.0) * out_price, 8)


# ---------------------------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------------------------
@dataclass
class Route:
    """One candidate model+provider pairing, in the order it will be tried."""

    provider: ModelProvider
    model: str
    tier: Tier = "balanced"


class ModelRouter:
    """Try routes in order, enforce spend ceilings, and fail closed when nothing answers.

    ``charge`` (optional) is called with each response so token/cost budgets are charged at the
    moment the spend is incurred -- before the answer is handed to the loop that acts on it.
    """

    def __init__(self, config: Optional[PlatformConfig] = None, *,
                 providers: Optional[Mapping[str, ModelProvider]] = None,
                 routes: Optional[Sequence[Route]] = None,
                 cheap_provider: Optional[ModelProvider] = None,
                 charge: Optional[Callable[[ModelResponse], None]] = None,
                 tracer: Any = None, max_routes: int = 3) -> None:
        self.config = config or PlatformConfig.from_env()
        self._providers: Dict[str, ModelProvider] = dict(providers or {})
        self._charge = charge
        self.tracer = tracer
        self.max_routes = max(1, int(max_routes))
        if routes is not None:
            self.routes: List[Route] = list(routes)[: self.max_routes]
        else:
            primary = self._providers.get(self.config.provider) or cheap_provider
            if primary is None:
                primary = self._build_default_provider()
            self.routes = [Route(primary, self.config.model)]
            for alt in list(self.config.fallback_models or ())[: self.max_routes - 1]:
                self.routes.append(Route(primary, str(alt), tier="balanced"))

    def _build_default_provider(self) -> ModelProvider:
        if self.config.provider == "deterministic":
            raise ConfigError("provider 'deterministic' requires an explicit script: construct "
                              "ModelRouter(routes=[Route(DeterministicProvider([...]), model)])")
        return OpenAICompatibleProvider(self.config)

    # -- registration ------------------------------------------------------------------------
    def register(self, name: str, provider: ModelProvider) -> None:
        self._providers[name] = provider

    @property
    def route_names(self) -> List[str]:
        return [f"{r.provider.name}:{r.model}" for r in self.routes]

    # -- completion --------------------------------------------------------------------------
    def complete(self, messages: Sequence[Message], *, tools: Sequence[Dict[str, Any]] = (),
                 tier: Tier = "balanced", model: Optional[str] = None,
                 max_tokens: Optional[int] = None,
                 temperature: Optional[float] = None) -> ModelResponse:
        """Return the first successful response, or raise :class:`ProviderUnavailable`."""
        ordered = self.routes
        if model:
            ordered = [r for r in self.routes if r.model == model] or self.routes
        errors: List[str] = []
        for route in ordered[: self.max_routes]:
            request = RouteRequest(
                messages=list(messages), model=model or route.model, tools=list(tools),
                temperature=float(self.config.temperature if temperature is None else temperature),
                max_tokens=int(self.config.max_tokens_per_call if max_tokens is None
                               else max_tokens),
                timeout_s=float(self.config.request_timeout_s), tier=tier)
            span = None
            if self.tracer is not None:
                span = self.tracer.span("model.call", provider=route.provider.name,
                                        model=request.model, tier=tier,
                                        messages=len(request.messages), tools=len(request.tools))
            try:
                response = route.provider.complete(request)
            except Exception as exc:  # noqa: BLE001 - fail over, record, continue
                errors.append(f"{route.provider.name}:{request.model}:{type(exc).__name__}")
                if span is not None:
                    span.finish(error=type(exc).__name__)
                continue
            if span is not None:
                span.finish(model=response.model, tokens=response.usage.total_tokens,
                            cost_usd=response.usage.cost_usd,
                            finish_reason=response.finish_reason)
            if self._charge is not None:
                self._charge(response)
            return response
        raise ProviderUnavailable(
            "no model route produced a response (" + "; ".join(errors or ["no routes"]) + ")")

    def describe(self) -> List[Dict[str, Any]]:
        return [{"provider": r.provider.name, "model": r.model, "tier": r.tier}
                for r in self.routes]
