# Architecture

```
 Browser ─► Next.js (apps/aql/frontend) ─► FastAPI (apps/aql/backend)
                                              │  agent / orchestrator
                                              ▼
                                   ToolRegistry.call(name, **args)
                                              │
                              ┌───────────────┴────────────────┐
                              │ core/secure_gate.ToolGate      │  deny-by-default, fail-closed
                              │  local allow-list              │
                              │  or AgentGuard POST /v1/authorize
                              └───────────────┬────────────────┘
                                   ALLOW      │      DENY → ToolDenied (recorded, handler never runs)
                                              ▼
                      handler (web_search, file_generator, echo, now, …)
                      python_exec / happy_run → core/secure_exec
                                              ▼
                      libs/contract.run_in_jail → docker | podman | bwrap | namespaces
```

## Decision rules
* Deny wins: the local deny-list is applied before anything else.
* AgentGuard is authoritative in `agentguard` mode; a local allow never overrides a remote deny.
* Unreachable policy server, timeout, malformed answer, import failure, bad config → deny.
* `allow_all` cannot be built when `APP_ENV=production`.
* Audit history records tool name + decision + reason + correlation id. Never arguments.

## Tool-call contract with AgentGuard
`action = "tool:<name>"`, `resource = "tool:<name>"`. AgentGuard's default policy allows an action
only if the agent's verified credential carries that exact capability, so issue the AQL agent
credential with capabilities such as `tool:web_search`. AgentGuard also requires a per-request
proof-of-possession, which is why the gate takes an SDK client via `AGENTGUARD_CLIENT_FACTORY`
(see HOSTING.md) instead of a bare token.

## Not yet integrated (honest backlog)
* `libs/agent_platform_pkg` (budgeted ReAct loop, ToolGuard, tracing, evals) is a separate runtime;
  AQL's own engine/orchestrator still drive agents. Unifying them is the next milestone.
* AQL's MCP client (`tools/mcp_client.py`) is not routed through the gate yet — only registry
  tools are. Do not expose MCP servers to untrusted agents until it is.
* Happy programs run via `happy run` inside the jail; the contract's richer
  `SecureExecutionRuntime` (capability-level authorization per operation) is not used by `happy_run`.
