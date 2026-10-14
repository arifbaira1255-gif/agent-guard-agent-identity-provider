"""Happy's AI-native layer (Step 5).

* :mod:`happy.ai.providers` — the :class:`AIProvider` abstraction and its
  OpenAI / Claude / Gemini / Local adapters.
* :mod:`happy.ai.agent` — structured plan generation and the agent capability
  sandbox.
* :mod:`happy.ai.verifier` — the trust-state verification pipeline that forces
  AI output through the real compiler before it may run.

    from happy.ai import get_provider, PlanGenerator, AgentSandbox, VerificationPipeline
"""

from .providers import (
    AIProvider,
    AIRequest,
    AIResponse,
    AIProviderError,
    ClaudeProvider,
    GeminiProvider,
    LocalLLMProvider,
    Message,
    MockProvider,
    OpenAIProvider,
    ProviderResponseError,
    ProviderUnavailable,
    Role,
    ToolCall,
    Usage,
    available_providers,
    get_provider,
    provider_from_env,
    register_provider,
    resolve_provider,
)
from .agent import (
    AgentSandbox,
    Plan,
    PlanError,
    PlanGenerator,
    PlanStep,
    SandboxPolicy,
    SandboxViolation,
    StepKind,
)
from .verifier import (
    GateOutcome,
    GateResult,
    TrustState,
    VerificationError,
    VerificationPipeline,
    VerificationResult,
    verify_source,
)

__all__ = [
    # providers
    "AIProvider",
    "AIRequest",
    "AIResponse",
    "AIProviderError",
    "Message",
    "Role",
    "ToolCall",
    "Usage",
    "OpenAIProvider",
    "ClaudeProvider",
    "GeminiProvider",
    "LocalLLMProvider",
    "MockProvider",
    "ProviderUnavailable",
    "ProviderResponseError",
    "get_provider",
    "resolve_provider",
    "provider_from_env",
    "register_provider",
    "available_providers",
    # agent / sandbox
    "PlanGenerator",
    "Plan",
    "PlanStep",
    "PlanError",
    "StepKind",
    "AgentSandbox",
    "SandboxPolicy",
    "SandboxViolation",
    # verifier
    "VerificationPipeline",
    "VerificationResult",
    "VerificationError",
    "TrustState",
    "GateOutcome",
    "GateResult",
    "verify_source",
]
