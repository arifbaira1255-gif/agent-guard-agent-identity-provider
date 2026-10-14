"""AgentGuard Agent Platform -- a complete agent runtime on top of the security control plane.

The platform is an ADDITIVE layer.  It consumes the existing ``agentguard_happy_contract`` package
(secure execution runtime, authorizer, request models) and the existing AgentGuard / Happy LANG trees;
it modifies none of them.

Layout
------

``config``        deployment configuration + feature flags (safe by default)
``types``         messages, tool calls, usage, run results
``router``        model providers, failover, cost accounting
``tools``         tool declarations, schema validation, THE authorization gate
``budget``        wall-clock / step / tool / token / cost enforcement, cancellation
``memory``        bounded working set + searchable episodic store
``orchestrator``  the bounded ReAct loop
``sandbox``       bridge to the M2 secure execution runtime
``events``        bounded, redacted audit event forwarding
``tracing``       spans + metrics (OTLP-shaped export)
``evaluation``    deterministic scorers + task-suite runner
``cli``           run / tools / doctor / eval

Safety posture, stated plainly
------------------------------

* The tool gate defaults to **deny-all**: an unconfigured deployment refuses protected work.
* Model spend is charged against **hard budgets**, checked before each unit of work.
* Untrusted code runs **only** through the M2 runtime, and refuses when no isolation backend exists.
* Secrets are redacted before they reach a log, a trace, an audit event or long-term memory.
* ``production`` configuration refuses plaintext endpoints, disabled TLS verification and
  authorization mode ``off`` at construction time (fail closed).
"""
from __future__ import annotations

from .budget import BudgetAccountant, CancellationToken, RunBudget
from .config import ENVIRONMENTS, MODES, PlatformConfig
from .errors import (
    AuthorizationDenied,
    BudgetExceeded,
    ConfigError,
    InvalidModelOutput,
    InvalidToolArguments,
    ModelError,
    PlatformError,
    ProviderUnavailable,
    RunCancelled,
    SandboxUnavailable,
    ToolError,
    UnknownTool,
)
from .evaluation import BUILTIN_SCORERS, SMOKE_SUITE, EvalReport, EvalTask, Scorer, ScorerResult, run_suite
from .events import EventBus, PlatformEvent, http_event_sink, recording_sink, stdout_event_sink
from .ids import new_id, sequence_id
from .memory import EpisodicMemory, MemoryRecord, WorkingMemory, tokenize
from .orchestrator import (
    DEFAULT_SYSTEM_PROMPT,
    AgentOrchestrator,
    NullPlanner,
    Planner,
    PlanResult,
    StaticPlanner,
)
from .router import (
    TIERS,
    CallableProvider,
    DeterministicProvider,
    ModelProvider,
    ModelRouter,
    OpenAICompatibleProvider,
    Route,
    RouteRequest,
    estimate_tokens,
    parse_openai_tool_calls,
    price_usage,
)
from .sandbox import SandboxBridge, SandboxResult, workspace_snapshot
from .tools import (
    AUTHORIZED,
    DENIED,
    AllowAllGate,
    AuthorizationGate,
    CallableGate,
    ContractGate,
    DenyAllGate,
    ToolGuard,
    ToolRegistry,
    ToolResult,
    ToolSpec,
)
from .tracing import NOOP_TRACER, Metrics, Span, Tracer
from .types import (
    Message,
    ModelResponse,
    Role,
    RunOutcome,
    RunResult,
    StepRecord,
    ToolCall,
    Usage,
)
from .validation import (
    SchemaError,
    canonical_json,
    check_schema,
    redact,
    sha256_hex,
    truncate,
    validate_against_schema,
)
from .version import (
    FEATURES,
    PLATFORM_NAME,
    PLATFORM_VERSION,
    REQUIRED_CONTRACT_VERSION,
    platform_header,
)

__version__ = PLATFORM_VERSION

__all__ = [
    # identity
    "PLATFORM_NAME", "PLATFORM_VERSION", "REQUIRED_CONTRACT_VERSION", "FEATURES",
    "platform_header",
    # config
    "PlatformConfig", "MODES", "ENVIRONMENTS",
    # errors
    "PlatformError", "ConfigError", "BudgetExceeded", "ModelError", "ProviderUnavailable",
    "ToolError", "UnknownTool", "InvalidToolArguments", "AuthorizationDenied",
    "SandboxUnavailable", "RunCancelled", "InvalidModelOutput",
    # types
    "Role", "Message", "ToolCall", "Usage", "ModelResponse", "RunOutcome", "StepRecord",
    "RunResult",
    # budget
    "RunBudget", "BudgetAccountant", "CancellationToken",
    # router
    "ModelRouter", "ModelProvider", "RouteRequest", "Route", "TIERS", "DeterministicProvider",
    "OpenAICompatibleProvider", "CallableProvider", "estimate_tokens", "price_usage",
    "parse_openai_tool_calls",
    # tools
    "ToolRegistry", "ToolSpec", "ToolResult", "ToolGuard", "AuthorizationGate", "DenyAllGate",
    "AllowAllGate", "CallableGate", "ContractGate", "AUTHORIZED", "DENIED",
    # memory
    "EpisodicMemory", "MemoryRecord", "WorkingMemory", "tokenize",
    # orchestration
    "AgentOrchestrator", "Planner", "NullPlanner", "StaticPlanner", "PlanResult",
    "DEFAULT_SYSTEM_PROMPT",
    # sandbox
    "SandboxBridge", "SandboxResult", "workspace_snapshot",
    # observability
    "EventBus", "PlatformEvent", "recording_sink", "stdout_event_sink", "http_event_sink",
    "Tracer", "Span", "Metrics", "NOOP_TRACER",
    # evaluation
    "EvalTask", "Scorer", "ScorerResult", "BUILTIN_SCORERS", "EvalReport", "run_suite",
    "SMOKE_SUITE",
    # validation
    "canonical_json", "sha256_hex", "redact", "truncate", "SchemaError", "check_schema",
    "validate_against_schema",
    # ids
    "new_id", "sequence_id",
]
