"""AI provider abstraction for the Happy language (Step 5).

Happy is *AI-native*: an ``ai`` block or ``ai { ... }`` expression is a
first-class language construct, and the compiler must be able to talk to a
model without caring which vendor is behind it.  This module defines that
seam.

The design has three layers:

* **Data model** — :class:`Message`, :class:`AIRequest`, :class:`AIResponse`,
  :class:`Usage`, :class:`ToolCall`.  Everything is a plain dataclass so it can
  be serialised, diffed and asserted on in tests.
* **The interface** — :class:`AIProvider`, an abstract base class with a single
  required method :meth:`AIProvider.complete`.  Concrete adapters translate the
  neutral request into a vendor payload and the vendor reply back into an
  :class:`AIResponse`.
* **The registry** — :func:`get_provider` / :func:`resolve_provider` build the
  right adapter from a name, reading API keys from the environment.  A
  :class:`MockProvider` is always available so the whole pipeline can be tested
  deterministically without network access.

Adapters
--------
======================  ==========================  ==========================
Provider                Env var(s)                  Default model
======================  ==========================  ==========================
``openai``              ``OPENAI_API_KEY``          ``gpt-4o-mini``
``claude`` / ``anthropic`` ``ANTHROPIC_API_KEY``    ``claude-3-5-sonnet-latest``
``gemini`` / ``google`` ``GEMINI_API_KEY`` / ``GOOGLE_API_KEY``  ``gemini-1.5-flash``
``local``               ``HAPPY_LOCAL_LLM_URL``     ``local-model``
``mock``                —                           ``mock-1``
======================  ==========================  ==========================

The HTTP adapters use only the standard library (``urllib``) so the toolchain
has **no third-party runtime dependency**; if a key is missing the adapter
raises :class:`ProviderUnavailable` rather than silently degrading.

Typical use::

    from happy.ai.providers import get_provider

    provider = get_provider("openai")            # reads OPENAI_API_KEY
    resp = provider.complete("Write a haiku about compilers")
    print(resp.text)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

__all__ = [
    "Role",
    "Message",
    "ToolCall",
    "Usage",
    "AIRequest",
    "AIResponse",
    "AIProviderError",
    "ProviderUnavailable",
    "ProviderResponseError",
    "AIProvider",
    "OpenAIProvider",
    "ClaudeProvider",
    "GeminiProvider",
    "LocalLLMProvider",
    "MockProvider",
    "PROVIDER_REGISTRY",
    "register_provider",
    "get_provider",
    "resolve_provider",
    "available_providers",
    "provider_from_env",
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class Role:
    """Canonical chat roles."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class ToolCall:
    """A model's request to invoke a tool/function."""

    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    call_id: Optional[str] = None


@dataclass
class Message:
    """A single chat message in a provider-neutral form."""

    role: str
    content: str
    name: Optional[str] = None
    tool_call_id: Optional[str] = None
    #: Tool calls emitted by an assistant turn (empty for other roles).
    tool_calls: List["ToolCall"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"role": self.role, "content": self.content}
        if self.name:
            out["name"] = self.name
        if self.tool_call_id:
            out["tool_call_id"] = self.tool_call_id
        if self.tool_calls:
            out["tool_calls"] = [
                {
                    "id": tc.call_id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments),
                    },
                }
                for tc in self.tool_calls
            ]
        return out

    @classmethod
    def system(cls, content: str) -> "Message":
        return cls(Role.SYSTEM, content)

    @classmethod
    def user(cls, content: str) -> "Message":
        return cls(Role.USER, content)

    @classmethod
    def assistant(cls, content: str) -> "Message":
        return cls(Role.ASSISTANT, content)


@dataclass
class Usage:
    """Token accounting for a single completion."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass
class AIRequest:
    """A provider-neutral completion request."""

    messages: List[Message] = field(default_factory=list)
    model: Optional[str] = None
    temperature: float = 0.0
    max_tokens: Optional[int] = None
    system: Optional[str] = None
    #: When set, the provider is asked to return strict JSON.
    json_schema: Optional[Dict[str, Any]] = None
    stop: Optional[List[str]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_prompt(
        cls,
        prompt: str,
        system: Optional[str] = None,
        **kwargs: Any,
    ) -> "AIRequest":
        messages: List[Message] = []
        if system:
            messages.append(Message.system(system))
        messages.append(Message.user(prompt))
        return cls(messages=messages, system=system, **kwargs)

    def all_messages(self) -> List[Message]:
        """Return the message list, prepending ``system`` if it is separate."""
        if self.system and not (self.messages and self.messages[0].role == Role.SYSTEM):
            return [Message.system(self.system)] + list(self.messages)
        return list(self.messages)


@dataclass
class AIResponse:
    """A provider-neutral completion response."""

    text: str = ""
    model: Optional[str] = None
    provider: Optional[str] = None
    usage: Usage = field(default_factory=Usage)
    tool_calls: List[ToolCall] = field(default_factory=list)
    finish_reason: Optional[str] = None
    raw: Any = None
    #: True when the response came from a mock / offline provider.
    mocked: bool = False

    # -- convenience ----------------------------------------------------
    def json(self) -> Any:
        """Parse :attr:`text` as JSON, tolerating ```json fences."""
        return parse_json_response(self.text)

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.text


def parse_json_response(text: str) -> Any:
    """Parse JSON from a model reply, stripping Markdown code fences.

    Models frequently wrap JSON in ```json ... ``` fences; this helper removes
    them before parsing so callers do not have to.
    """
    if text is None:
        raise ProviderResponseError("empty response")
    stripped = text.strip()
    if stripped.startswith("```"):
        # Drop the opening fence (``` or ```json) and the trailing fence.
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise ProviderResponseError(f"response is not valid JSON: {exc}") from exc


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class AIProviderError(Exception):
    """Base class for provider failures."""


class ProviderUnavailable(AIProviderError):
    """The provider cannot be used (missing key, missing endpoint, ...)."""


class ProviderResponseError(AIProviderError):
    """The provider returned something we could not interpret."""


# ---------------------------------------------------------------------------
# The interface
# ---------------------------------------------------------------------------
class AIProvider(ABC):
    """Unified interface every AI backend implements.

    Subclasses must set :attr:`name` and :attr:`default_model` and implement
    :meth:`complete`.  :meth:`is_available` reports whether the provider is
    usable in the current environment (e.g. its API key is present).
    """

    #: Short provider identifier (``"openai"``, ``"claude"`` ...).
    name: str = "provider"
    #: Model used when a request does not name one.
    default_model: str = "default"
    #: Environment variables that may hold the API key, in priority order.
    env_keys: Sequence[str] = ()
    #: Capability flags probed by the tool loop and the verifier.
    supports_tools: bool = True
    supports_json: bool = True
    supports_streaming: bool = False
    is_local: bool = False

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 60.0,
        **options: Any,
    ) -> None:
        self.api_key = api_key if api_key is not None else self._read_key()
        self.model = model or self.default_model
        self.base_url = base_url or self.default_base_url()
        self.timeout = timeout
        self.options = options
        #: Number of completions served (useful for tests / budgeting).
        self.call_count = 0

    # -- configuration --------------------------------------------------
    def _read_key(self) -> Optional[str]:
        for var in self.env_keys:
            value = os.environ.get(var)
            if value:
                return value
        return None

    def default_base_url(self) -> Optional[str]:
        return None

    def is_available(self) -> bool:
        """Return True when this provider can actually serve a request."""
        return bool(self.api_key)

    # -- the one required method ---------------------------------------
    @abstractmethod
    def complete(self, request: Any, **kwargs: Any) -> AIResponse:
        """Serve a completion.

        ``request`` may be an :class:`AIRequest` or a plain ``str`` prompt.
        """

    # -- helpers --------------------------------------------------------
    def _coerce_request(self, request: Any, **kwargs: Any) -> AIRequest:
        if isinstance(request, AIRequest):
            req = request
        elif isinstance(request, str):
            req = AIRequest.from_prompt(request)
        else:
            raise AIProviderError(
                f"expected AIRequest or str, got {type(request).__name__}"
            )
        if kwargs:
            for key, value in kwargs.items():
                if hasattr(req, key):
                    setattr(req, key, value)
        if req.model is None:
            req.model = self.model
        return req

    def _post_json(self, url: str, payload: Dict[str, Any], headers: Mapping[str, str]) -> Dict[str, Any]:
        """POST ``payload`` as JSON and return the decoded response body."""
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        for key, value in headers.items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:  # pragma: no cover - network
            detail = exc.read().decode("utf-8", "replace") if exc.fp else ""
            raise ProviderResponseError(
                f"{self.name} HTTP {exc.code}: {detail[:400]}"
            ) from exc
        except urllib.error.URLError as exc:  # pragma: no cover - network
            raise ProviderUnavailable(f"{self.name} unreachable: {exc.reason}") from exc
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:  # pragma: no cover - network
            raise ProviderResponseError(
                f"{self.name} returned non-JSON body: {body[:200]}"
            ) from exc

    def __repr__(self) -> str:  # pragma: no cover - convenience
        return f"<{type(self).__name__} model={self.model!r} available={self.is_available()}>"


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------
class OpenAIProvider(AIProvider):
    """Adapter for the OpenAI Chat Completions API."""

    name = "openai"
    default_model = "gpt-4o-mini"
    env_keys = ("OPENAI_API_KEY",)

    def default_base_url(self) -> str:
        return os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")

    def complete(self, request: Any, **kwargs: Any) -> AIResponse:
        req = self._coerce_request(request, **kwargs)
        if not self.is_available():
            raise ProviderUnavailable(
                "OPENAI_API_KEY is not set; export it or use the mock provider"
            )
        payload: Dict[str, Any] = {
            "model": req.model or self.model,
            "messages": [m.to_dict() for m in req.all_messages()],
            "temperature": req.temperature,
        }
        if req.max_tokens is not None:
            payload["max_tokens"] = req.max_tokens
        if req.stop:
            payload["stop"] = req.stop
        if req.json_schema is not None:
            payload["response_format"] = {"type": "json_object"}
        body = self._post_json(
            f"{self.base_url}/chat/completions",
            payload,
            {"Authorization": f"Bearer {self.api_key}"},
        )
        self.call_count += 1
        return self._parse(body, req)

    def _parse(self, body: Dict[str, Any], req: AIRequest) -> AIResponse:
        choices = body.get("choices") or []
        if not choices:
            raise ProviderResponseError("openai response contained no choices")
        message = choices[0].get("message", {})
        usage = body.get("usage") or {}
        return AIResponse(
            text=message.get("content") or "",
            model=body.get("model", req.model),
            provider=self.name,
            usage=Usage(
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                total_tokens=usage.get("total_tokens", 0),
            ),
            finish_reason=choices[0].get("finish_reason"),
            raw=body,
        )


# ---------------------------------------------------------------------------
# Anthropic Claude
# ---------------------------------------------------------------------------
class ClaudeProvider(AIProvider):
    """Adapter for the Anthropic Messages API."""

    name = "claude"
    default_model = "claude-3-5-sonnet-latest"
    env_keys = ("ANTHROPIC_API_KEY", "CLAUDE_API_KEY")

    def default_base_url(self) -> str:
        return os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")

    def complete(self, request: Any, **kwargs: Any) -> AIResponse:
        req = self._coerce_request(request, **kwargs)
        if not self.is_available():
            raise ProviderUnavailable(
                "ANTHROPIC_API_KEY is not set; export it or use the mock provider"
            )
        system_parts: List[str] = []
        messages: List[Dict[str, Any]] = []
        for msg in req.all_messages():
            if msg.role == Role.SYSTEM:
                system_parts.append(msg.content)
            else:
                messages.append({"role": msg.role, "content": msg.content})
        payload: Dict[str, Any] = {
            "model": req.model or self.model,
            "messages": messages,
            "max_tokens": req.max_tokens or 1024,
            "temperature": req.temperature,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        if req.stop:
            payload["stop_sequences"] = req.stop
        body = self._post_json(
            f"{self.base_url}/messages",
            payload,
            {
                "x-api-key": self.api_key or "",
                "anthropic-version": "2023-06-01",
            },
        )
        self.call_count += 1
        return self._parse(body, req)

    def _parse(self, body: Dict[str, Any], req: AIRequest) -> AIResponse:
        blocks = body.get("content") or []
        text = "".join(
            block.get("text", "")
            for block in blocks
            if isinstance(block, dict) and block.get("type") == "text"
        )
        usage = body.get("usage") or {}
        prompt_tokens = usage.get("input_tokens", 0)
        completion_tokens = usage.get("output_tokens", 0)
        return AIResponse(
            text=text,
            model=body.get("model", req.model),
            provider=self.name,
            usage=Usage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            finish_reason=body.get("stop_reason"),
            raw=body,
        )


# ---------------------------------------------------------------------------
# Google Gemini
# ---------------------------------------------------------------------------
class GeminiProvider(AIProvider):
    """Adapter for the Google Gemini ``generateContent`` API."""

    name = "gemini"
    default_model = "gemini-1.5-flash"
    env_keys = ("GEMINI_API_KEY", "GOOGLE_API_KEY")

    def default_base_url(self) -> str:
        return os.environ.get(
            "GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
        )

    def complete(self, request: Any, **kwargs: Any) -> AIResponse:
        req = self._coerce_request(request, **kwargs)
        if not self.is_available():
            raise ProviderUnavailable(
                "GEMINI_API_KEY / GOOGLE_API_KEY is not set; export it or use the mock provider"
            )
        contents: List[Dict[str, Any]] = []
        system_parts: List[str] = []
        for msg in req.all_messages():
            if msg.role == Role.SYSTEM:
                system_parts.append(msg.content)
                continue
            role = "model" if msg.role == Role.ASSISTANT else "user"
            contents.append({"role": role, "parts": [{"text": msg.content}]})
        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": req.temperature},
        }
        if req.max_tokens is not None:
            payload["generationConfig"]["maxOutputTokens"] = req.max_tokens
        if req.json_schema is not None:
            payload["generationConfig"]["responseMimeType"] = "application/json"
        if system_parts:
            payload["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_parts)}]}
        model = req.model or self.model
        url = f"{self.base_url}/models/{model}:generateContent?key={self.api_key}"
        body = self._post_json(url, payload, {})
        self.call_count += 1
        return self._parse(body, req)

    def _parse(self, body: Dict[str, Any], req: AIRequest) -> AIResponse:
        candidates = body.get("candidates") or []
        if not candidates:
            raise ProviderResponseError("gemini response contained no candidates")
        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        usage = body.get("usageMetadata") or {}
        return AIResponse(
            text=text,
            model=req.model,
            provider=self.name,
            usage=Usage(
                prompt_tokens=usage.get("promptTokenCount", 0),
                completion_tokens=usage.get("candidatesTokenCount", 0),
                total_tokens=usage.get("totalTokenCount", 0),
            ),
            finish_reason=candidates[0].get("finishReason"),
            raw=body,
        )


# ---------------------------------------------------------------------------
# Local LLM (Ollama / llama.cpp / vLLM compatible)
# ---------------------------------------------------------------------------
class LocalLLMProvider(AIProvider):
    """Adapter for a local, OpenAI-compatible chat endpoint.

    Works with Ollama (``/v1/chat/completions``), llama.cpp server, vLLM and
    LM Studio.  The endpoint is read from ``HAPPY_LOCAL_LLM_URL`` (default
    ``http://localhost:11434/v1``).
    """

    name = "local"
    default_model = "local-model"
    env_keys = ("HAPPY_LOCAL_LLM_KEY",)

    def default_base_url(self) -> str:
        return os.environ.get("HAPPY_LOCAL_LLM_URL", "http://localhost:11434/v1")

    def is_available(self) -> bool:
        # A local endpoint needs no key; availability is "configured".
        return bool(self.base_url)

    def complete(self, request: Any, **kwargs: Any) -> AIResponse:
        req = self._coerce_request(request, **kwargs)
        payload: Dict[str, Any] = {
            "model": req.model or self.model,
            "messages": [m.to_dict() for m in req.all_messages()],
            "temperature": req.temperature,
            "stream": False,
        }
        if req.max_tokens is not None:
            payload["max_tokens"] = req.max_tokens
        headers: Dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = self._post_json(f"{self.base_url}/chat/completions", payload, headers)
        self.call_count += 1
        choices = body.get("choices") or []
        if not choices:
            raise ProviderResponseError("local provider returned no choices")
        message = choices[0].get("message", {})
        usage = body.get("usage") or {}
        return AIResponse(
            text=message.get("content") or "",
            model=body.get("model", req.model),
            provider=self.name,
            usage=Usage(
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                total_tokens=usage.get("total_tokens", 0),
            ),
            finish_reason=choices[0].get("finish_reason"),
            raw=body,
        )


# ---------------------------------------------------------------------------
# Mock provider (deterministic, offline)
# ---------------------------------------------------------------------------
class MockProvider(AIProvider):
    """A deterministic provider for tests and offline development.

    It never touches the network.  Responses are produced by a *responder*
    callable ``(AIRequest) -> str`` supplied at construction time; when none is
    given the provider echoes a canned reply.  This is what the verification
    pipeline's tests use to feed both valid and deliberately broken code.
    """

    name = "mock"
    default_model = "mock-1"
    env_keys = ()
    supports_tools = True
    supports_json = True
    supports_streaming = False
    is_local = True

    def __init__(
        self,
        responder: Optional[Callable[[AIRequest], Any]] = None,
        responses: Optional[Sequence[str]] = None,
        mark_mocked: bool = True,
        **options: Any,
    ) -> None:
        super().__init__(**options)
        self._responder = responder
        self._responses = list(responses or [])
        self._index = 0
        #: When False, responses are marked as if they came from a real model
        #: (used by tests that exercise the "untrusted model output" path).
        self.mark_mocked = mark_mocked
        self.requests: List[AIRequest] = []

    def is_available(self) -> bool:
        return True

    def complete(self, request: Any, **kwargs: Any) -> AIResponse:
        req = self._coerce_request(request, **kwargs)
        self.requests.append(req)
        self.call_count += 1

        if self._responder is not None:
            text = self._responder(req)
        elif self._responses:
            text = self._responses[min(self._index, len(self._responses) - 1)]
            self._index += 1
        else:
            last = req.all_messages()[-1].content if req.all_messages() else ""
            text = f"[mock:{self.model}] {last}"

        if not isinstance(text, str):
            text = json.dumps(text)
        return AIResponse(
            text=text,
            model=req.model or self.model,
            provider=self.name,
            usage=Usage(
                prompt_tokens=sum(len(m.content.split()) for m in req.all_messages()),
                completion_tokens=len(text.split()),
                total_tokens=0,
            ),
            finish_reason="stop",
            mocked=self.mark_mocked,
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
#: Provider name -> adapter class.
PROVIDER_REGISTRY: Dict[str, type] = {
    "openai": OpenAIProvider,
    "claude": ClaudeProvider,
    "anthropic": ClaudeProvider,
    "gemini": GeminiProvider,
    "google": GeminiProvider,
    "local": LocalLLMProvider,
    "ollama": LocalLLMProvider,
    "mock": MockProvider,
}

#: Canonical names, in preference order, used when auto-detecting.
_CANONICAL_ORDER = ("openai", "claude", "gemini", "local", "mock")


def register_provider(name: str, cls: type) -> None:
    """Register a custom provider adapter under ``name``."""
    if not issubclass(cls, AIProvider):
        raise TypeError("provider class must subclass AIProvider")
    PROVIDER_REGISTRY[name.lower()] = cls


def available_providers() -> List[str]:
    """Return the canonical provider names known to the registry."""
    return list(_CANONICAL_ORDER)


def get_provider(name: str, **options: Any) -> AIProvider:
    """Instantiate the provider called ``name``.

    Raises :class:`ProviderUnavailable` for an unknown name.
    """
    key = (name or "").strip().lower()
    cls = PROVIDER_REGISTRY.get(key)
    if cls is None:
        raise ProviderUnavailable(
            f"unknown AI provider {name!r}; known: {sorted(PROVIDER_REGISTRY)}"
        )
    return cls(**options)


def provider_from_env(prefer: Optional[Sequence[str]] = None) -> AIProvider:
    """Return the first *available* provider, honouring ``prefer`` order.

    Falls back to :class:`MockProvider` so callers always get something usable.
    """
    order = list(prefer or _CANONICAL_ORDER)
    for name in order:
        try:
            provider = get_provider(name)
        except ProviderUnavailable:
            continue
        if provider.is_available():
            return provider
    return MockProvider()


def resolve_provider(
    provider: Any = None,
    model: Optional[str] = None,
    **options: Any,
) -> AIProvider:
    """Coerce ``provider`` into an :class:`AIProvider` instance.

    ``provider`` may be ``None`` (auto-detect from the environment), a provider
    name (``"openai"``), an already-built :class:`AIProvider`, or a callable
    ``(AIRequest) -> str`` (wrapped in a :class:`MockProvider`).
    """
    if isinstance(provider, AIProvider):
        if model:
            provider.model = model
        return provider
    if provider is None:
        return provider_from_env()
    if isinstance(provider, str):
        return get_provider(provider, model=model, **options)
    if callable(provider):
        return MockProvider(responder=provider, model=model or "mock-1")
    raise ProviderUnavailable(f"cannot resolve provider from {type(provider).__name__}")
