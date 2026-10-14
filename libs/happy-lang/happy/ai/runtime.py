"""Runtime bridge between Happy's ``ai`` expressions and real providers.

Happy source may contain ``ai`` blocks/expressions (e.g. ``ai { "summarise:
" + doc }``).  At runtime those lower to ``__happy_ai__`` calls, which the
generated preamble routes into :class:`AIRunner`.  The runner:

* resolves the best available provider from the environment
  (``OPENAI_API_KEY`` / ``ANTHROPIC_API_KEY`` / ``GEMINI_API_KEY`` / a local
  Ollama endpoint), and
* when **no** provider is configured, falls back to a deterministic, clearly
  marked offline response — it never pretends a model was called.

The runner also exposes :meth:`complete_structured` for JSON-shaped requests and
:meth:`with_tools` to attach a :class:`~happy.ai.tools.ToolRegistry`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .providers import (
    AIProvider,
    AIProviderError,
    AIRequest,
    AIResponse,
    MockProvider,
    ProviderUnavailable,
    provider_from_env,
)

__all__ = ["AIRunner", "AIResult"]


@dataclass
class AIResult:
    """The outcome of one AI call, with provenance."""

    text: str = ""
    live: bool = False           # True when a real provider served the request
    provider: str = "offline"
    model: Optional[str] = None
    error: Optional[str] = None
    response: Optional[AIResponse] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "live": self.live,
            "provider": self.provider,
            "model": self.model,
            "error": self.error,
        }


#: Deterministic, obviously-offline fallback template.
_OFFLINE_TEMPLATE = "[offline-ai] {prompt}"


class AIRunner:
    """Executes ``ai`` expressions, preferring a live provider."""

    def __init__(
        self,
        provider: Optional[AIProvider] = None,
        system: Optional[str] = None,
        allow_offline: bool = True,
    ) -> None:
        self._provider = provider
        self.system = system
        self.allow_offline = allow_offline
        self.tools: Any = None
        self.history: List[AIResult] = []

    # -- construction ---------------------------------------------------
    @classmethod
    def from_env(cls, prefer: Optional[List[str]] = None) -> "AIRunner":
        """Build a runner from the environment.

        If no provider is genuinely configured, the runner is created in
        *offline* mode (no provider) rather than silently substituting a mock
        model \u2014 a program must never believe it called a real model when it
        did not.
        """
        try:
            provider = provider_from_env(prefer=prefer)
        except (ProviderUnavailable, AIProviderError):
            provider = None
        if isinstance(provider, MockProvider):
            provider = None
        return cls(provider=provider)

    @property
    def provider(self) -> Optional[AIProvider]:
        return self._provider

    @property
    def live(self) -> bool:
        """True when a real, usable provider is attached."""
        if self._provider is None:
            return False
        try:
            return bool(self._provider.is_available())
        except Exception:  # pragma: no cover - defensive
            return False

    def with_tools(self, registry: Any) -> "AIRunner":
        self.tools = registry
        return self

    # -- completion -----------------------------------------------------
    def complete(
        self,
        prompt: Any,
        system: Optional[str] = None,
        json_schema: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> str:
        result = self.call(prompt, system=system, json_schema=json_schema, **kwargs)
        return result.text

    def call(
        self,
        prompt: Any,
        system: Optional[str] = None,
        json_schema: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AIResult:
        text_prompt = prompt if isinstance(prompt, str) else str(prompt)
        if self._provider is None or not self._safe_available():
            return self._offline(text_prompt)

        request = AIRequest.from_prompt(
            text_prompt, system=system or self.system, json_schema=json_schema
        )
        try:
            if self.tools is not None and getattr(
                self._provider, "supports_tools", False
            ):
                from .tools import run_tool_loop

                loop = run_tool_loop(self._provider, request, self.tools)
                response = loop.response
            else:
                response = self._provider.complete(request)
        except AIProviderError as exc:
            result = AIResult(
                text=_OFFLINE_TEMPLATE.format(prompt=text_prompt),
                live=False,
                provider=getattr(self._provider, "name", "unknown"),
                error=str(exc),
            )
            self.history.append(result)
            return result
        except Exception as exc:  # noqa: BLE001 - never crash a Happy program
            result = AIResult(
                text=_OFFLINE_TEMPLATE.format(prompt=text_prompt),
                live=False,
                provider=getattr(self._provider, "name", "unknown"),
                error=f"{type(exc).__name__}: {exc}",
            )
            self.history.append(result)
            return result

        result = AIResult(
            text=response.text,
            live=True,
            provider=response.provider or getattr(self._provider, "name", "unknown"),
            model=response.model,
            response=response,
        )
        self.history.append(result)
        return result

    def complete_structured(
        self, prompt: Any, schema: Optional[Dict[str, Any]] = None, **kwargs: Any
    ) -> AIResult:
        """Return an :class:`AIResult` whose ``response.json()`` is populated."""
        return self.call(prompt, json_schema=schema, **kwargs)

    # -- helpers --------------------------------------------------------
    def _safe_available(self) -> bool:
        try:
            return bool(self._provider.is_available())
        except Exception:  # pragma: no cover - defensive
            return False

    def _offline(self, prompt: str) -> AIResult:
        result = AIResult(
            text=_OFFLINE_TEMPLATE.format(prompt=prompt),
            live=False,
            provider="offline",
        )
        self.history.append(result)
        return result
