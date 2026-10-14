# Agentic Platform — AQL-1 + AgentGuard + Happy LANG

One repository, one story: **an AI-agent platform whose agents cannot run code or call tools
unless they are authorized, and whose code runs in a kernel-enforced jail or not at all.**

| Layer | Path | Role |
|---|---|---|
| **Product** | `apps/aql` | AQL-1: FastAPI backend (agents, orchestrator, router, guardrails/approvals, billing via manual Payoneer flow, MCP client) + Next.js dashboard |
| **Control plane** | `services/agentguard` | AgentGuard: agent identity, credentials, policy, audit |
| **Language / jail** | `libs/happy-lang` | Happy LANG: compiler, contracts, capabilities, verifier, isolation backends |
| **Seam** | `libs/contract` | Typed, versioned contract between AgentGuard and Happy (`HttpPdp`, `SdkPdp`, `run_in_jail`) |
| **Runtime lib** | `libs/agent_platform_pkg` | Standalone agent runtime (ReAct loop, budgets, ToolGuard). Not yet wired into AQL — see ARCHITECTURE |

## What this merge changed in AQL-1

1. **Every tool call goes through a gate** (`core/secure_gate.py`). Default: a local allow-list.
   Optional: AgentGuard decides. Any error, timeout or misconfiguration → **deny**.
2. **`python_exec` is no longer a bare subprocess.** It is `disabled` by default, or runs inside
   Happy's jail (`isolated`), or — development only — a host subprocess with a scrubbed
   environment (`unsafe_dev`, refused in production). Previously it inherited every secret in the
   server's environment.
3. **New tool `happy_run`**: compiles and runs a Happy program inside the jail. No host fallback.
4. **`GET /v1/security/posture`**: shows the active gate, recent allow/deny decisions (tool names
   only, never arguments) and observed isolation status.

## Quick start

```bash
cp .env.example .env            # fill in values
docker compose up -d --build    # backend :8000, frontend :3000
bash scripts/verify.sh          # 25 security tests, no network needed
```

Read `docs/HOSTING.md` before going public and `docs/SECURITY_AND_LIMITATIONS.md` before you
tell anyone this is "secure".
