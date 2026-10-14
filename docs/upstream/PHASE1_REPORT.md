# AgentGuard Agent Platform — Phase 1 Report

**Version:** `agentguard-agent-platform 0.1.0` (built against integration contract `1.0.0`)
**Date:** 2026-10-12
**Scope:** Phase 1 of the roadmap — an agent runtime layer built **on top of** the existing
AgentGuard ↔ Happy LANG integration (M2). Nothing below the platform layer was modified.

---

## 1. What was verified (not claimed) in this run

| Suite | Command | Result |
|---|---|---|
| M2 integration contract suite | `pytest tests/` | **208 passed** |
| M2 + platform, combined | `pytest tests/ platform/tests/` | **362 passed in 28.77s** |
| Platform suite alone | `pytest platform/tests/` | **154 passed in 0.17s** |
| AgentGuard (upstream) | `python -m unittest discover tests` | 1187 tests, **1 error** (`FileNotFoundError: sdks/conformance/vectors.json`), 287 skipped |
| Happy LANG (upstream) | per-file sweep | 598 passed, **6 failed / 4 errors** — all `unshare: fork failed` (sandbox PID ceiling) |

The two upstream figures are the **unchanged baselines** carried from M2: the upstream trees are
byte-identical (`diff -rq` clean), so these are the same environment-caused failures M2 documented,
not new regressions.

Reproduce:

```bash
cd integration
export PYTHONPATH=contract:platform
python3 -m pytest tests/ platform/tests/ -q     # 362 passed
```

---

## 2. What was built — the `agent_platform` package

A new, additive package at `integration/platform/agent_platform/`. It consumes only the public
interfaces of `agentguard_happy_contract` (secure runtime, authorizer, models); it modifies neither
AgentGuard, Happy LANG, nor the contract.

| Module | Responsibility |
|---|---|
| `version.py` | platform identity + required contract version (version skew is a loud failure) |
| `errors.py` | structured error codes, incl. `BudgetExceeded(kind=…)` for wall_clock/steps/tool_calls/tokens/cost/cancelled |
| `types.py` | `Message`, `ToolCall`, `Usage`, `ModelResponse`, `RunOutcome`, `RunResult` |
| `config.py` | `PlatformConfig` + feature flags, env-driven, **safe by default**, fail-closed in `production` |
| `budget.py` | `RunBudget`, `BudgetAccountant`, `CancellationToken` — enforced at point of use |
| `router.py` | provider protocol, `DeterministicProvider`, `OpenAICompatibleProvider`, failover, token/cost pricing |
| `tools.py` | `ToolRegistry`, `ToolSpec`, `ToolResult`, and **`ToolGuard`** — the single path from a model's request to a side effect |
| `memory.py` | `WorkingMemory` (bounded + compaction) and `EpisodicMemory` (capacity-capped, redacted) |
| `orchestrator.py` | the bounded ReAct loop; `NullPlanner` / `StaticPlanner`; per-run budget wiring |
| `sandbox.py` | `SandboxBridge` → M2 `SecureExecutionRuntime`; refuses to run untrusted code with no isolation |
| `events.py` | bounded, redacted audit event bus; sinks for memory, stdout, and AgentGuard's `/v1/security/events` |
| `tracing.py` | spans + metrics (OTLP-shaped export) |
| `evaluation.py` | deterministic scorers + task-suite runner (`EvalReport`) |
| `builtin_tools.py` | `list_dir`, `read_file` (root-jailed), `http_get` (https + host allowlist + no cross-host redirect), `run_happy_program` (sandbox-only) |
| `cli.py` | `run` / `tools` / `doctor` / `eval` |

### Security posture (as implemented, not as hoped)

* **Tool gate defaults to deny-all.** An unconfigured deployment refuses protected work; `doctor`
  reports `default_gate_is_deny: true`.
* **Deny is the failure mode of a broken gate.** A gate that raises is recorded as
  `gate_error:<Type>` and denies — never allows.
* **Budgets are charged before the thing they bound**: wall clock + cancellation before every step,
  the tool-call ceiling inside `ToolGuard` (so it holds on every entry path), token/cost the moment
  a model response is received.
* **Path jail below the policy.** `safe_join` applies `realpath` to both sides, so traversal *and*
  symlink escapes are refused even under an allow-all policy.
* **Untrusted code never runs on the host.** `run_happy_program` requires the bridge, and the bridge
  refuses when no isolation backend is observed.
* **Secrets are scrubbed in the funnel.** `truncate()` scrubs credential-shaped text, and `redact()`
  scrubs secret-keyed fields, so tokens cannot survive into a log, span, audit record or memory.

---

## 3. Bugs found by the tests and fixed in this run

Six genuine defects were found by running the suites, not by inspection:

1. **Step-budget off-by-one** — a run using its whole budget ended as a `BudgetExceeded` exception one
   step *past* the limit instead of the precise `MAX_STEPS` outcome. Fixed by checking the ceiling
   before charging.
2. **Malformed-arguments handling** — extra/rejected arguments were not surfaced with the model's own
   raw text, so a repair attempt had nothing to work from.
3. **Tool-call budget not wired** — `ToolGuard._charge` was only set by some callers; the ceiling was
   therefore not enforced on every entry path. Now wired per run in the orchestrator.
4. **Token/cost budget never charged** — `charge_usage` existed but was never called, so
   `max_tokens` / `max_cost_usd` were declarative only. Now charged at receipt.
5. **Denial reason flattened** — the gate's own reason was replaced by a generic string, destroying
   the evidence. Now propagated.
6. **Events never flushed** — a short run's audit events stayed buffered. Now flushed at run end.

Additionally: compaction notes accumulated without bound in `WorkingMemory`, and `EpisodicMemory`'s
TTL compared a `time.time` stamp against a monotonic clock. Both fixed.

---

## 4. Known limitations — read this before believing any security claim

1. **No real LLM was wired in this run.** Every test and the end-to-end proof use
   `DeterministicProvider` (scripted, no network). The `OpenAICompatibleProvider` is implemented and
   unit-tested at the request/response-shaping level, but has **not** been exercised against a live
   model endpoint. Treat "works with a real model" as **unverified**.
2. **Isolation is the M2 runtime's, not new.** The platform adds a refusal layer and a bridge; it does
   not strengthen the OS boundary. The M2 guarantees and M2's limitations transfer unchanged
   (`namespaces` shares the host kernel; CPU limits are advisory; no independent verification).
3. **No production isolation backend pinned.** `isolation_mode=auto` may select a weaker backend.
4. **`ContractGate` is adapter-tested, not integration-tested** against a live AgentGuard PDP; the
   live path is exercised through the contract's own suite, not through the platform.
5. **The event HTTP sink does not retry.** A down audit endpoint keeps events in a bounded buffer;
   durability is the operator's responsibility (this is deliberate — a blocking audit call must not
   stall a run).
6. **In-process, single-node.** No distributed scheduler, no persistent run store across processes,
   no multi-agent coordination yet.
7. **`AllowAllGate` exists** and is used in tests. It is named to be unmissable, and `production`
   config refuses `mode="off"`, but it remains a foot-gun if wired deliberately.

---

## 5. Answers to "kya bana, kya nahi bana" (short)

**Bana hua (verified this run):** AgentGuard ↔ Happy LANG integration contract + secure execution
runtime (M2, 208 tests) · a working agent runtime layer (Phase 1, 154 tests) with orchestration,
tools + authorization gate, budgets, memory, routing, tracing, evaluation, sandbox bridge and CLI.

**Adhoora:** real-model integration, production isolation pinning, live PDP integration test,
distributed/persistent run store, multi-agent.

**Bilkul nahi bana:** frontier model training, GPU infrastructure, massive data pipelines, a hosted
multi-tenant control plane, an observability UI.

---

## 6. Exact next milestone

**Phase 2 — Make it real and observable:**
1. Point `OpenAICompatibleProvider` at a live model endpoint; add a live-model evaluation run.
2. Pin the isolation backend (`isolation_mode=required`, explicit backend) with a startup assertion
   that fails closed.
3. Add an integration test that drives `ContractGate` against a live AgentGuard PDP.
4. Persist runs and events (postgres or file-backed) so a run survives a process restart.
5. Ship the `/v1/security/events` sink with retry + dead-letter, and a minimal run-inspection view.
