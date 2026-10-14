"""Command-line interface: run a goal, list tools, doctor the deployment, run an evaluation.

The ``doctor`` command is the one that matters most operationally -- it answers "will this deployment
refuse work it should refuse, and can it do the work it should do" without running a real task.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, List, Optional

from .config import PlatformConfig
from .errors import ConfigError
from .evaluation import SMOKE_SUITE, run_suite
from .events import EventBus, recording_sink
from .memory import EpisodicMemory, WorkingMemory
from .orchestrator import AgentOrchestrator
from .router import DeterministicProvider, ModelRouter, Route
from .sandbox import SandboxBridge
from .tools import AllowAllGate, DenyAllGate, ToolGuard, ToolRegistry
from .tracing import Tracer
from .version import PLATFORM_NAME, PLATFORM_VERSION

__all__ = ["build_agent", "main"]


def build_agent(config: PlatformConfig, *, gate: Optional[Any] = None,
                provider: Optional[Any] = None, workspace_root: str = ".",
                register_builtins: bool = True) -> AgentOrchestrator:
    """Assemble a complete agent from configuration (the same path tests and the CLI both use)."""
    if not config.enabled:
        raise ConfigError("agent platform is disabled: set AGENT_PLATFORM_ENABLED=true or pass "
                          "enabled=True to build a live agent")
    tracer = Tracer(enabled=config.tracing_enabled)
    events = EventBus(capacity=config.max_events_buffer, enabled=config.emit_events, tracer=tracer)
    events.add_sink(recording_sink())

    sandbox = None
    if config.sandbox_enabled:
        sandbox = SandboxBridge(
            require_isolation=config.require_isolation,
            on_event=lambda **kw: events.record(event_type=kw.get("event_type", "platform.event"),
                                                outcome=kw.get("outcome", "ok"),
                                                reason=kw.get("reason", "")))

    registry = ToolRegistry()
    if register_builtins:
        from .builtin_tools import register_builtin_tools

        register_builtin_tools(registry, workspace_root=workspace_root,
                               sandbox_bridge=sandbox, include_sandbox=sandbox is not None)

    guard = ToolGuard(
        registry, gate=gate or DenyAllGate(), allowlist=config.tool_allowlist,
        on_event=lambda **kw: events.record(event_type=kw.get("event_type"),
                                            outcome=kw.get("outcome"),
                                            reason=kw.get("reason", ""),
                                            metadata=kw.get("metadata") or {}),
        tracer=tracer)

    routes = [Route(provider, config.model)] if provider is not None else None
    router = ModelRouter(config, routes=routes, tracer=tracer)
    memory = EpisodicMemory(capacity=config.memory_capacity) if config.memory_enabled else None
    return AgentOrchestrator(router, guard, config=config, memory=memory,
                             working_memory=WorkingMemory(
                                 max_messages=config.working_memory_max_messages),
                             tracer=tracer, events=events, sandbox=sandbox)


def _doctor(config: PlatformConfig, agent: Optional[AgentOrchestrator]) -> dict:
    """Report the deployment's real posture -- what is on, and what would be refused."""
    checks: dict = {
        "platform": f"{PLATFORM_NAME} {PLATFORM_VERSION}",
        "enabled": config.enabled,
        "environment": config.environment,
        "authorization_mode": config.mode,
        "require_authorization": config.require_authorization,
        "isolation_mode": config.isolation_mode,
        "sandbox_enabled": config.sandbox_enabled,
        "memory_enabled": config.memory_enabled,
        "tracing_enabled": config.tracing_enabled,
        "emit_events": config.emit_events,
        "allowlist": list(config.tool_allowlist),
        "production_checks": "pass" if config.environment != "production" else "enforced",
    }
    if agent is not None:
        checks["gate"] = agent.guard.gate.name
        checks["tools"] = agent.guard.registry.names()
        checks["routes"] = agent.router.route_names
        checks["default_gate_is_deny"] = agent.guard.gate.name == DenyAllGate.__name__
        if agent.sandbox is not None:
            checks["sandbox"] = agent.sandbox.summary()
    return checks


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-platform",
                                     description="Run and inspect the AgentGuard agent platform.")
    parser.add_argument("--version", action="version",
                        version=f"{PLATFORM_NAME} {PLATFORM_VERSION}")
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="run one goal")
    run_p.add_argument("goal")
    run_p.add_argument("--plan", action="store_true", help="generate a plan first")
    run_p.add_argument("--json", action="store_true", help="print the full result as JSON")
    run_p.add_argument("--allow-all", action="store_true",
                       help="use the test-only allow-all gate (never in production)")

    sub.add_parser("tools", help="list registered tools")
    sub.add_parser("doctor", help="report the deployment's security posture")

    eval_p = sub.add_parser("eval", help="run the offline evaluation suite")
    eval_p.add_argument("--suite", default="smoke")
    eval_p.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    config = PlatformConfig.from_env()

    if args.command == "doctor":
        agent = None
        if config.enabled:
            try:
                agent = build_agent(config)
            except Exception as exc:  # noqa: BLE001 - reported, not raised
                print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}, indent=2))
        print(json.dumps(_doctor(config, agent), indent=2, default=str))
        return 0

    if args.command == "tools":
        registry = ToolRegistry()
        from .builtin_tools import register_builtin_tools

        register_builtin_tools(registry, workspace_root=".")
        for spec in registry.all():
            print(f"{spec.name:>20}  protected={str(spec.protected):<5}  action={spec.action}")
        return 0

    if args.command == "eval":
        provider = DeterministicProvider(["ready", "done", "cannot help"])
        agent = build_agent(config.with_overrides(enabled=True, environment="development"),
                            gate=AllowAllGate(), provider=provider)
        report = run_suite(agent, SMOKE_SUITE, suite_name=args.suite)
        print(json.dumps(report.to_dict(), indent=2) if args.json else report.render())
        return 0 if report.failed == 0 else 1

    if args.command == "run":
        gate = AllowAllGate() if args.allow_all else DenyAllGate()
        agent = build_agent(config, gate=gate, workspace_root=os.getcwd())
        result = agent.run(args.goal, plan=args.plan)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, default=str))
        else:
            print(f"outcome={result.outcome.value} ok={result.ok} steps={result.steps} "
                  f"tool_calls={result.tool_calls} tokens={result.usage.total_tokens}")
            print(result.final_text or (result.error or ""))
        return 0 if result.ok else 2

    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(main())
