> **Deployment note (v11-payoneer):** billing no longer uses Stripe. Users pay to the
> configured Payoneer email / bank account, submit a transaction ID + screenshot on
> `/dashboard/billing`, and an admin approves it at `/dashboard/admin/payments`
> (`X-Admin-Token` = `ADMIN_TOKEN`). LLM traffic goes through UnoRouter (primary) and
> ExperimentLab (fallback). Schema: `supabase/migrations/0001_aql1_schema.sql`.
> Older Stripe sections below are historical.

# AQL-1 — Autonomous AI Agent Operating Layer

A production-shaped project boilerplate for **AQL-1**, an operating layer that
plans, remembers, and acts through tools. Backend is **Python + FastAPI**;
frontend is **Next.js (TypeScript + Tailwind CSS)**.

> The boilerplate runs **out of the box with no API keys** — every external
> dependency (LLM, Pinecone, Supabase) has a local fallback. Add real keys in
> `.env` to switch to live services.

---

## Project tree

```
aql-1-boilerplate/
├── README.md
├── .gitignore
├── backend/
│   ├── main.py                 # FastAPI app entrypoint
│   ├── requirements.txt        # Python dependencies
│   ├── .env.example            # Backend env template
│   ├── core/                   # Agent execution engine + router + orchestrator
│   │   ├── config.py           # Typed settings (pydantic-settings)
│   │   ├── auth.py             # API-key auth + rate limiting middleware
│   │   ├── engine.py           # ReAct-style agent loop
│   │   ├── guardrails.py       # Safety layer: risk rules + human approval
│   │   ├── billing.py          # Stripe plans, subscriptions, webhooks
│   │   ├── observability.py    # Execution logs, routing savings, traces
│   │   ├── orchestrator.py     # Multi-agent team (planner/executor/reviewer)
│   │   └── router.py           # Complexity routing + cost + fallback chain
│   ├── memory/                 # Vector DB + state management
│   │   ├── manager.py          # Long-term MemoryManager (store/fetch/audit)
│   │   ├── vector_store.py     # Pinecone wrapper (+ local fallback)
│   │   └── state.py            # Supabase run + audit + approval + api-key store
│   ├── tools/                  # MCP integrators
│   │   ├── registry.py         # Tool catalogue + dispatch (echo, now,
│   │   │                       #   web_search, python_exec, file_generator)
│   │   └── mcp_client.py       # JSON-RPC MCP client (stdio)
│   ├── api/                    # REST endpoints
│   │   ├── routes.py           # /health /tools /agent /memory /orchestrate
│   │   │                       #   + /agent/approve /agent/approvals
│   │   │                       #   + /v1/agent/run /v1/agent/status /v1/keys
│   │   └── billing.py          # /v1/billing plans, subscription, checkout,
│   │                           #   portal, webhook
│   ├── sdk/                    # Client SDKs
│   │   ├── client.py           # AQL1Client (in-process helper)
│   │   ├── python/             # Standalone Python SDK (sync + async)
│   │   │   ├── aql1.py         # AQL1 / AsyncAQL1 + transports + errors
│   │   │   ├── pyproject.toml  # Packaging (zero required deps)
│   │   │   ├── README.md       # Install, quickstart, method reference
│   │   │   ├── examples/       # quickstart, async, approvals, errors, keys
│   │   │   └── tests/          # 43 tests (mocked transport)
│   │   └── ts/                 # Standalone TypeScript SDK
│   │       ├── src/            # index.ts, types.ts, errors.ts
│   │       ├── package.json    # Packaging (zero runtime deps)
│   │       ├── tsconfig.json   # Strict build config
│   │       ├── README.md       # Install, quickstart, method reference
│   │       ├── examples/       # quickstart, async, approvals, errors, keys
│   │       └── test/           # 35 tests (mocked transport)
│   └── tests/
│       ├── test_api.py         # API smoke tests
│       ├── test_router.py      # Router: classification, cost, fallback
│       ├── test_unorouter.py   # UnoRouter: payload/headers, fallback, stub
│       ├── test_memory.py      # Memory: store/fetch/log/fallback
│       ├── test_orchestrator.py # Orchestrator: plan/loop/revision/cap
│       ├── test_guardrails.py  # Safety: risk rules, pause/approve/reject
│       ├── test_observability.py # Observability: logs, routing savings, traces
│       ├── test_auth.py        # REST API: API keys, 401/429, /v1 run + status
│       └── test_billing.py     # Billing: plans, checkout, webhooks, idempotency
└── frontend/
    ├── package.json
    ├── tsconfig.json
    ├── tailwind.config.ts
    ├── postcss.config.js
    ├── next.config.js
    ├── .env.local.example
    ├── app/
    │   ├── layout.tsx          # Root layout (+ no-flash theme script)
    │   ├── page.tsx            # Starter page (talks to backend)
    │   ├── dashboard/
    │   │   ├── page.tsx        # Control-plane dashboard
    │   │   ├── observability/
    │   │   │   └── page.tsx    # Cost savings, success chart, trace logs
    │   │   └── billing/
    │   │       └── page.tsx    # Plans, token usage, invoices
    │   └── globals.css         # Tailwind + light/dark theme tokens
    ├── components/
    │   ├── AgentConsole.tsx    # Run-agent UI
    │   └── dashboard/
    │       ├── ui.tsx          # Primitives + useTheme/ThemeToggle
    │       ├── Sidebar.tsx     # Collapsible nav
    │       ├── ExecutionPanel.tsx  # Live run timeline
    │       ├── ApprovalsModal.tsx  # Human-in-the-loop approvals
    │       ├── demo.ts         # Offline demo data
    │       ├── observability-demo.ts  # Offline observability data
    │       └── billing-demo.ts # Offline billing data
    └── lib/
        └── api.ts              # Typed API client (single HTTP entry point)
```

---

## Backend — setup & run

```bash
cd backend

# 1. Create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment (optional — works without keys)
cp .env.example .env             # then edit .env

# 4. Run the API
uvicorn main:app --reload --port 8000
```

- API root: http://localhost:8000
- Interactive docs (Swagger): http://localhost:8000/docs
- Health check: http://localhost:8000/health

### Run the tests

```bash
cd backend
pytest -q
```

### Key endpoints

| Method | Path                  | Purpose                          |
|--------|-----------------------|----------------------------------|
| GET    | `/health`             | Liveness probe                   |
| GET    | `/tools`              | List registered tools (schemas)  |
| POST   | `/route`              | Preview model routing for a task |
| POST   | `/agent/run`          | Execute an agent task            |
| GET    | `/agent/runs`         | List recent runs                 |
| GET    | `/agent/runs/{id}`    | Fetch one run                    |
| POST   | `/memory`             | Store a memory item              |
| POST   | `/memory/query`       | Semantic search over memory      |
| POST   | `/memory/recall`      | Top-K memories (user/session filter) |
| POST   | `/memory/build-context` | Prompt-ready memory block      |
| POST   | `/memory/logs`        | Append an audit record           |
| GET    | `/memory/logs`        | List audit rows (newest first)   |
| POST   | `/orchestrate`        | Run the multi-agent team         |
| POST   | `/agent/risk-check`   | Classify an action's risk        |
| POST   | `/agent/approve`      | Approve/reject a paused run      |
| GET    | `/agent/approvals`    | List approvals (pending by default) |
| GET    | `/agent/approvals/{id}` | Fetch one approval             |
| POST   | `/v1/agent/run`       | **Start a run (API-key auth)**   |
| GET    | `/v1/agent/status/{id}` | **Run status / progress**      |
| POST   | `/v1/keys`            | **Mint an API key**              |
| GET    | `/v1/keys`            | **List API keys**                |
| DELETE | `/v1/keys/{id}`       | **Revoke an API key**            |

### Model routing (`core/router.py`)

`ModelRouter` inspects each task and routes it to the cheapest model that can
handle it, with automatic fallback. It runs with **no API keys** (local
heuristic + stub fallback).

**Complexity → model**

| Complexity | Signals (heuristic)                                   | Primary model              |
|------------|-------------------------------------------------------|----------------------------|
| **Low**    | short prompt, low-keywords (classify, translate, …)   | `gpt-4o-mini` / `deepseek-chat` |
| **Medium** | medium length, some reasoning keywords                | `gpt-4o-mini` / `claude-3-5-haiku` (UnoRouter) |
| **High**   | long prompt, code/math, multi-step, high-keywords     | `claude-opus-4.6` (UnoRouter) / `gpt-4o` |

An optional **GPT-4o-mini classifier** is used when `OPENAI_API_KEY` is set;
the local heuristic is the guaranteed fallback.

**Pricing table** (USD per 1,000 tokens, input / output):

| Model | Input | Output |
|-------|-------|--------|
| `gpt-4o-mini` | $0.00015 | $0.00060 |
| `gpt-4o` | $0.00250 | $0.01000 |
| `claude-3-5-haiku-latest` | $0.00080 | $0.00400 |
| `claude-3-5-sonnet-latest` | $0.00300 | $0.01500 |
| `claude-opus-4.6` (UnoRouter) | $0.01500 | $0.07500 |
| `deepseek-chat` | $0.00014 | $0.00028 |

**Fallback chain** — on provider failure the router walks the chain, then
returns a local stub so the system never hard-fails:

- Low: `openai/gpt-4o-mini` → `deepseek/deepseek-chat` → `anthropic/claude-3-5-haiku` → stub
- Medium: `openai/gpt-4o-mini` → `anthropic/claude-3-5-haiku` → `openai/gpt-4o` → stub
- High: `anthropic/claude-3-5-sonnet` → `openai/gpt-4o` → `openai/gpt-4o-mini` → stub

When **`UNOROUTER_API_KEY` is set**, every `anthropic` link above is served
through **UnoRouter** instead (and `UNOROUTER_MODEL` replaces the model). That
makes the High chain `unorouter/claude-opus-4.6` → `openai/gpt-4o` →
`openai/gpt-4o-mini` → stub. Remove the key and the table above is exactly what
you get — key-less behaviour is unchanged.

```python
from core.router import ModelRouter

r = ModelRouter()
d = r.route("architect a secure multi-step migration plan")
print(d.complexity, d.provider, d.model, d.estimated_cost_usd)

result = r.call("hello")          # executes with fallback; never raises
print(result.text, result.is_stub)
```

### Providers & UnoRouter (Claude gateway)

**UnoRouter** is an OpenAI-compatible gateway that serves Claude/Anthropic
models. AQL-1 uses it as the Claude provider, so **no Anthropic SDK dependency
is needed** — the call is a plain `POST` via the standard-library `urllib`.

```bash
# .env
UNOROUTER_API_KEY=sk-your-unorouter-key
UNOROUTER_BASE_URL=https://api.unorouter.com/v1   # default
UNOROUTER_MODEL=claude-opus-4.6                   # default
```

| Setting | Env var | Default |
|---------|---------|---------|
| `unorouter_api_key` | `UNOROUTER_API_KEY` | *(empty)* |
| `unorouter_base_url` | `UNOROUTER_BASE_URL` | `https://api.unorouter.com/v1` |
| `unorouter_model` | `UNOROUTER_MODEL` | `claude-opus-4.6` |

**How it works**

* The provider issues `POST {base_url}/chat/completions` with an OpenAI-compatible
  body — `{"model": ..., "messages": [{"role": "system"|"user", "content": ...}], "stream": false}` —
  and header `Authorization: Bearer <UNOROUTER_API_KEY>`.
* **When the key is set, UnoRouter becomes the primary provider for Claude
  traffic**: every `anthropic` link in the fallback chain is swapped for
  `unorouter`, so High-complexity tasks lead with `claude-opus-4.6`.
* `core/engine.py` and `core/orchestrator.py` inherit this automatically — they
  route every model call through `ModelRouter`, so their calls hit UnoRouter
  whenever the key is present.
* **Failure handling:** a non-2xx response, a network error or a malformed body
  becomes a typed `ModelCallError`, and the router walks on to the next link in
  the fallback chain. With no key at all it degrades to the local stub — the
  system never hard-fails.
* The API key is read **only** from the environment / `config.py`. Never commit a
  real key: `.env.example` ships a placeholder and `.env` is git-ignored.

```python
from core.router import ModelRouter

r = ModelRouter()
d = r.route("architect a secure multi-step migration plan")
print(d.provider, d.model)   # -> unorouter claude-opus-4.6   (when the key is set)
print(d.fallback_chain)      # -> (('unorouter', 'claude-opus-4.6'), ('openai', 'gpt-4o'), ...)
```

### Long-term memory (`memory/manager.py`)

`MemoryManager` is the façade the agent uses to remember across sessions. It
**reuses** `memory/vector_store.py` (Pinecone) and `memory/state.py` (Supabase),
so it inherits their graceful degradation: with **no keys it still works**
against local in-memory stores.

```python
from memory.manager import MemoryManager

mgr = MemoryManager()

# 1. STORE — embed + upsert with metadata
mgr.store("User prefers concise Urdu answers", user_id="u1", session_id="s1")

# 2. FETCH — top-K relevant memories (optionally filtered)
hits = mgr.fetch("how should I answer?", user_id="u1", top_k=3)
# -> [{"id": ..., "text": ..., "score": 0.83, "metadata": {...}}, ...]

# 3. LOG — append a session/run audit record
mgr.log(user_id="u1", session_id="s1", prompt="hi", response="hello",
        model="gpt-4o-mini", provider="openai", latency_ms=180)

# bonus helpers
ctx = mgr.build_context("how should I answer?", user_id="u1")
mgr.record("hi", "hello", user_id="u1", model="gpt-4o-mini")  # stores both turns + audits
mgr.history(user_id="u1")                                       # audit rows, newest first
```

**API surface:** `store(text, *, user_id, session_id, role, run_id, model, metadata)`,
`fetch(query, *, top_k, user_id, session_id, role, min_score)`,
`log(*, user_id, session_id, prompt, response, model, provider, input_tokens,
output_tokens, cost_usd, latency_ms)`, plus `record()`, `history()` and
`build_context()`. Every method degrades by default (logs a warning and carries
on); pass `strict=True` to raise the typed errors `MemoryStoreError` /
`MemoryFetchError` / `MemoryAuditError` instead.

**Pinecone metadata schema** (one vector per memory):

| Field | Type | Notes |
|-------|------|-------|
| `text` | string | the raw text, so hits are self-describing |
| `user_id` | string | filter key (`"anonymous"` by default) |
| `session_id` | string | filter key (`"default"` by default) |
| `role` | string | `user` / `assistant` / `system` |
| `timestamp` | string | ISO-8601 UTC |
| `kind` | string | `"interaction"` |
| `run_id` | string | optional agent-run link |
| `model` | string | optional model that produced it |
| *(extra)* | primitive | any caller-supplied metadata, coerced to str/int/float/bool |

**Supabase audit table** (`memory_audit`) — create with:

```sql
create table memory_audit (
  log_id         uuid primary key,
  user_id        text not null,
  session_id     text not null,
  role           text default 'assistant',
  prompt         text,
  response       text,
  model          text,
  provider       text,
  input_tokens   integer default 0,
  output_tokens  integer default 0,
  total_tokens   integer default 0,
  cost_usd       numeric(12,8) default 0,
  latency_ms     integer default 0,
  created_at     timestamptz default now()
);
```

Token counts default to an estimate from the text and `cost_usd` defaults to the
router's pricing table, so an audit row is complete even when the caller only
supplies the prompt, response and model.

### Using the Python SDK

```python
from sdk import AQL1Client

client = AQL1Client("http://localhost:8000")
run = client.run("Plan a launch checklist for AQL-1")
print(run.answer, run.duration_ms)

# Multi-agent orchestration
state = client.orchestrate("First research the market, then write a summary file")
print(state["status"], state["final_output"])
```

### Multi-agent orchestration (`core/orchestrator.py`)

A single prompt is not answered by one model call but by a **team of three
specialised agents** that hand a shared state back and forth until the work is
done.

| Agent | Role |
|-------|------|
| `PlannerAgent` | Decomposes the prompt into an ordered list of sub-tasks (id, description, suggested tool). |
| `ExecutionAgent` | Runs each sub-task with a registered tool (`web_search`, `python_exec`, `file_generator`, `echo`). |
| `ReviewerAgent` | Validates each result and returns a verdict — `approved` or `needs-revision` — with feedback. |

**Control loop** — `plan → execute → review → (revise & re-execute if rejected) → … → final`:

```python
from core.orchestrator import MultiAgentOrchestrator

orch = MultiAgentOrchestrator()          # memory on by default
state = orch.run("First search the web for AI news, then calculate 12 * 8, then write a summary file")

print(state.status)        # completed | max_iterations | failed
print(state.iteration)     # how many plan→execute→review passes ran
print(state.total_cost_usd)
print(state.final_output)
```

**Shared state** — `OrchestrationState` carries the original prompt, the plan
(`SubTask[]`), per-step results (`StepResult[]`), review feedback
(`ReviewVerdict[]`), the iteration count, the recalled memory context and the
final output. `state.to_dict()` is fully JSON-serialisable.

**Behaviour**

* Every model call goes through `ModelRouter`, so **cost estimation and provider
  fallback are inherited** — a sub-task's `StepResult` records the model,
  provider and cost that actually answered.
* With **no API keys** the router returns stubs, so each agent falls back to its
  deterministic local implementation (heuristic planner, real tool execution,
  heuristic reviewer) and the loop still completes.
* `MemoryManager` is used **optionally**: relevant past context is recalled at
  the start and the finished run is stored at the end. Pass `use_memory=False`
  to disable it.
* A rejected sub-task is re-executed on the next iteration; the loop stops when
  every sub-task is approved or `max_iterations` (default 3) is reached — it
  never hard-fails.

**Typed exceptions:** `OrchestrationError` → `PlanningError` / `ExecutionError`
/ `ReviewError`.

---

## Safety & human approval (`core/guardrails.py`)

An agent that can send email, delete rows, move money or run shell commands is
only as safe as the gate in front of those actions. `core/guardrails.py` is that
gate: a deterministic, offline-safe risk classifier plus a pause → persist →
resume flow for anything dangerous.

### Risk rule table

`check_action_risk(action_type, payload)` matches the action against an
extensible rule table (`RISK_RULES`) — an action-type mapping plus regex/keyword
patterns over the flattened payload. Every rule is evaluated and the **highest**
risk wins, so rules compose instead of shadowing each other.

| Rule id | Category | Level | Examples |
|---|---|---|---|
| `external_communication.send` | external_communication | **high** | `email.send`, `message.send`, `sms.send`, `slack.send` |
| `data_deletion.records` | data_deletion | **high** | `db.delete`, `row.delete`, `table.drop`, `DELETE FROM …` |
| `financial.money_movement` | financial | **high** | `payment.transfer`, `refund.create`, `purchase.create`, `stripe.charge` |
| `shell.execution` | shell_execution | **high** | `shell.exec`, `command.run`, `subprocess.run`, `rm -rf` |
| `file_deletion` | file_deletion | **high** | `file.delete`, `folder.delete`, `fs.remove` |
| `credential_access` | credential_access | **high** | `secret.read`, `env.read`, `key.access`, `OPENAI_API_KEY` |
| `bulk_export` | bulk_export | **high** | `data.export`, `db.dump`, `backup.create`, "all users" |
| `data_mutation.write` | data_mutation | medium | `db.write`, `file.write`, `config.update` |
| `network.outbound` | network | medium | `http.post`, `webhook.call`, `api.call` |
| `read_only` | read_only | low | `web_search`, `echo`, `db.read`, `python_exec` |

An **unrecognised** action type defaults to **medium** — an unknown capability is
never silently waved through. Adding a new dangerous class is one entry in
`RISK_RULES`.

### `RiskAssessment` schema

```json
{
  "action_type": "email.send",
  "risk_level": "high",
  "is_high_risk": true,
  "reasons": ["Sends an email or message to an external recipient."],
  "matched_rules": ["external_communication.send"],
  "requires_approval": true,
  "categories": ["external_communication"],
  "checked_at": "2026-10-01T06:20:00+00:00"
}
```

### Pause → persist → resume

When `requires_approval` is true the agent **stops** instead of acting:

1. `AgentEngine.run(...)` / `MultiAgentOrchestrator.run(...)` call
   `check_action_risk` before executing.
2. High-risk → the full run state is persisted via `ApprovalStore.pause(...)`
   and the run returns `status: "pending_approval"` with an `approval_id`.
   **Nothing is executed.**
3. A human calls `POST /agent/approve` with the id and a decision.
4. Approved → the run resumes and executes; rejected → `status: "rejected"`.

```bash
# 1) a high-risk run pauses
curl -s -X POST localhost:8000/agent/run -H 'content-type: application/json' \
  -d '{"task":"Send the newsletter","action_type":"email.send","payload":{"to":"all@x.com"}}'
# -> {"status":"pending_approval","approval_id":"dc5f5c7d-…", …}

# 2) see what is waiting
curl -s localhost:8000/agent/approvals

# 3) approve (or reject) it — this resumes the run
curl -s -X POST localhost:8000/agent/approve -H 'content-type: application/json' \
  -d '{"approval_id":"dc5f5c7d-…","decision":"approve","approver":"arif","note":"ok"}'
# -> {"status":"completed","result":{…}}
```

### Supabase table — `pending_approvals`

```sql
create table pending_approvals (
  approval_id  uuid primary key,
  payload      jsonb not null,   -- the full PendingApproval record
  created_at   timestamptz default now()
);
```

The `payload` jsonb holds: `approval_id`, `run_id`, `action_type`, `payload`,
`risk` (the `RiskAssessment`), `kind` (`agent` | `orchestrator`), `status`
(`pending` | `approved` | `rejected`), `user_id`, `session_id`, `resume_state`,
`approver`, `note`, `created_at`, `decided_at`.

**No Supabase keys?** `ApprovalStore` falls back to an in-memory dict, so the
whole flow works offline — the module never hard-fails.

**Typed exceptions:** `GuardrailError` → `RiskCheckError` /
`ApprovalStoreError` / `ApprovalNotFoundError` / `ApprovalStateError`.

---

## REST API & authentication (`core/auth.py`)

The `/v1/*` routes are the stable, versioned surface for programmatic clients.
They sit behind `APIKeyMiddleware`, which authenticates every request against
**hashed** API keys and enforces a per-key rate limit.

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/agent/run` | Start an autonomous run. Async by default (returns a `task_id`); pass `wait: true` to run synchronously and get the full result. Goes through the guardrail gate, so a high-risk action returns `status: "pending_approval"` with an `approval_id` instead of executing. |
| GET | `/v1/agent/status/{task_id}` | Status of a run: `status`, `progress` (steps completed/total/percent), timestamps, `cost_usd`, `tokens`, the `approval_id` when paused, and the final `result` once finished. **404** for an unknown task id. |
| POST | `/v1/keys` | Mint a key. The **raw key is returned exactly once** — only its hash is stored. |
| GET | `/v1/keys` | List keys (metadata only — never the raw key or its hash). |
| DELETE | `/v1/keys/{key_id}` | Revoke (deactivate) a key. |

```bash
# 1) mint a key (returns the raw key ONCE — store it now)
curl -X POST localhost:8000/v1/keys -H 'Content-Type: application/json' \
  -d '{"name":"ci","owner_id":"team-a"}'
# -> {"api_key":"aql1_…","key":{…},"warning":"Store this key now …"}

# 2) start a run (async)
curl -X POST localhost:8000/v1/agent/run \
  -H 'Authorization: Bearer aql1_…' -H 'Content-Type: application/json' \
  -d '{"task":"Draft the weekly report"}'
# -> {"task_id":"…","status":"running","status_url":"/v1/agent/status/…"}

# 3) poll it
curl localhost:8000/v1/agent/status/<task_id> -H 'X-API-Key: aql1_…'
```

### Auth header

Either form is accepted; `X-API-Key` wins when both are present.

```
Authorization: Bearer <key>
X-API-Key: <key>
```

Missing, invalid or revoked keys get **401** with a machine-readable body:

```json
{"error":"unauthorized","code":"missing_api_key","detail":"no API key supplied"}
```

`code` is one of `missing_api_key`, `invalid_api_key`, `revoked_api_key`,
`auth_error`. Public routes (`/health`, `/docs`, `/redoc`, `/openapi.json`,
`/`) never require a key — configurable via `AUTH_PUBLIC_PATHS`.

### `api_keys` table schema

```sql
create table api_keys (
  key_hash   text primary key,   -- SHA-256 of the raw key (never plaintext)
  payload    jsonb not null,     -- the full APIKeyRecord
  created_at timestamptz default now()
);
```

The `payload` jsonb holds: `key_id`, `key_hash`, `name`, `owner_id`, `scopes`,
`active`, `created_at`, `last_used_at`, `rate_limit_requests`,
`rate_limit_window_seconds`, `prefix`.

**Keys are never stored in plaintext.** `hash_api_key()` is a SHA-256 hex
digest, so verification is a single indexed lookup by hash and a leaked
database cannot be replayed against the API.

### Rate limiting

A **sliding window** per key (default 60 requests / 60 s, overridable per key at
creation). Exceeding it returns **429** with `Retry-After` and the standard
headers:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1759300000
Retry-After: 42
```

```json
{"error":"rate_limited","code":"rate_limit_exceeded","retry_after":42}
```

### Configuration

```bash
AUTH_ENABLED=true              # false = middleware is a no-op (local dev)
API_KEYS_TABLE=api_keys
API_KEY_PREFIX=aql1_
RATE_LIMIT_REQUESTS=60
RATE_LIMIT_WINDOW_SECONDS=60
AUTH_PUBLIC_PATHS=/health,/docs,/redoc,/openapi.json,/docs/oauth2-redirect,/
```

**No Supabase keys?** The key store and rate limiter fall back to in-memory
implementations, so the app boots and the middleware works offline. A broken
store degrades to a 401 (never a 500).

**Typed exceptions:** `AuthError` → `APIKeyError` (`MissingAPIKeyError` /
`InvalidAPIKeyError` / `RevokedAPIKeyError`) / `APIKeyStoreError` /
`RateLimitExceededError`.

### Python SDK

```python
from sdk import AQL1Client

client = AQL1Client("http://localhost:8000", api_key="aql1_…")

raw = client.create_key("ci")["api_key"]        # mint (shown once)
task = client.run_task("Draft the weekly report")  # async by default
print(client.task_status(task["task_id"]))        # poll
print(client.run_task("Say hi", wait=True))       # synchronous
client.revoke_key(key_id)
```

---

## Frontend — setup & run

```bash
cd frontend

# 1. Install dependencies
npm install

# 2. Configure environment (optional)
cp .env.local.example .env.local   # NEXT_PUBLIC_API_URL=http://localhost:8000

# 3. Start the dev server
npm run dev
```

Open http://localhost:3000 — the starter page shows backend status, lets you
run an agent task, and lists the registered tools.

> Start the **backend first** so the frontend can reach it. CORS is preconfigured
> for `http://localhost:3000`.

### Dashboard (`app/dashboard/page.tsx`)

The control plane lives at **http://localhost:3000/dashboard** (the starter page
links to it). It is a single client component composed of small, fully typed
sub-components under `components/dashboard/`.

**Layout**

* **Sidebar** (`Sidebar.tsx`) — Agents, Runs, Observability, Billing, Settings,
each with a Lucide icon, an active-item state, and a **collapsible/compact
mode** (icons only, with tooltips). A pinned **Approvals** entry shows a live
count badge whenever runs are waiting for a human.
* **Header** — the active view's title, a connection badge (`live` / `demo`),
an Approvals button with the same count badge, and the theme toggle.
* **Main column** — the Agents view hosts the execution panel; Runs,
Observability, Billing and Settings render lightweight views over the same run
state.

**Execution panel** (`ExecutionPanel.tsx`)

A live run timeline for the multi-agent orchestrator. It flattens an
`OrchestrationState` into ordered entries — `PlannerAgent`, then each
`ExecutionAgent` step (agent name, tool chip, status, duration, tokens, cost),
then its `ReviewerAgent` verdict, then the final synthesis — with a **running
cost total**, a step counter, skeleton loading states, an empty state, and
auto-scroll so new entries stream into view.

* **Wired to:** `POST /orchestrate` (via `api.orchestrate()`), with
  `GET /health` + `GET /tools` for the connection badge and Settings view.
* **Graceful fallback:** if the API is unreachable the panel replays
  `DEMO_ORCHESTRATION` from `components/dashboard/demo.ts` and shows a
  "Backend unreachable — showing a demo run" notice, so the UI is always
  explorable.

**Pending Approvals modal** (`ApprovalsModal.tsx`)

Lists paused runs from **`GET /agent/approvals`** and shows the action type,
risk level, the reasons it was flagged, the matched rules and the raw payload.
**Approve & resume** / **Reject** call **`POST /agent/approve`** with an
optional approver name and note, then refresh the list and the sidebar badge.
Errors (404 unknown id, 409 already decided) surface inline. Offline it falls
back to `DEMO_APPROVALS` and simulates the round-trip.

**Theme toggle**

A three-way **Light / Dark / System** segmented control. The choice is persisted
in `localStorage` (`aql1-theme`) and, in System mode, follows the OS
`prefers-color-scheme` live. An inline script in `app/layout.tsx` applies the
resolved theme before first paint, so there is no flash. All colours come from
CSS custom properties in `globals.css` (light on `:root`, dark on `.dark`), so
one class on `<html>` re-themes the whole app.

**API client** — `lib/api.ts` remains the single place that performs HTTP. It
exports typed methods (`orchestrate`, `approvals`, `approval`, `approve`,
`riskCheck`, `runs`, `runById`, `getLogs`, …), the shared domain types, and an
`ApiError` with a request timeout, so callers can degrade to demo data instead
of crashing.

### Observability (`app/dashboard/observability/page.tsx`)

Reached from the sidebar's **Observability** item (a real route, not an
in-page tab). It reads a single payload from **`GET /api/logs`** and renders
three panels.

**1. Total cost saved via Model Routing** — the headline metric. `ModelRouter`
classifies every call (Low / Medium / High) and sends it to the cheapest model
that can handle it; this card prices the *same tokens* as if every call had
gone to the most expensive model in the pricing table, and reports the delta.

| Field | Meaning |
|---|---|
| `actual_cost_usd` | What routing really spent |
| `baseline_cost_usd` | The counterfactual "all-premium" spend |
| `saved_usd` / `saved_pct` | The difference and its percentage |
| `premium_model` | Which model the baseline is priced against |
| `tiers[]` | Per-tier `tier`, `model`, `provider`, `calls`, `tokens`, `cost_usd`, `baseline_cost_usd`, `saved_usd` |

The baseline is computed as a **ratio of the recorded cost** (`_premium_ratio`
in `core/observability.py`), so a workload that already ran entirely on the
premium model correctly reports zero savings.

**2. Success vs Failure rate** — a donut with the overall success rate, plus a
chart with a stacked **success (green) / failed (red) bar per time bucket** and
a **blue success-rate trend line**. Rendered as **inline SVG** — no chart
dependency was added. The line lives in its own panel above the bars, only
plots buckets that actually had calls (an empty bucket has no rate — plotting
0% would read as total failure), and the axis tick step is chosen so labels are
uniform (`0, 2, 4, 6, 8`) rather than ragged. Includes a legend, per-bucket
hover tooltips, and an empty state.

**3. Step-by-step trace logs** — an expandable table of every agent call,
grouped by run with a **per-run cost subtotal**, plus a search box and filters
by **status** and **agent**.

| Column | Source |
|---|---|
| Timestamp | `timestamp` |
| Run id | group header (`run_id`) |
| Agent | `agent` |
| Tool | `tool` |
| Status | `status` — `success` / `failed` / `skipped` |
| Latency (ms) | `latency_ms` |
| Tokens | `total_tokens` (prompt / completion in the expanded row) |
| Cost per task | `cost_usd` |
| Model · tier | `model`, `provider`, `complexity` |

Expanding a row reveals prompt/completion/total tokens, the trace id, the full
ISO timestamp, the status badge and the step detail.

**`GET /api/logs` contract** — assembled by `core/observability.py` from the
runs already persisted by `memory/state.py`. Query params: `run_id`, `status`
(`all` to disable), `agent`, `limit` (default 500).

```jsonc
{
  "generated_at": "2026-10-01T08:26:00+00:00",
  "summary":  { "runs": 5, "calls": 17, "succeeded": 17, "failed": 0,
                "success_rate": 1.0, "total_tokens": 3412,
                "total_cost_usd": 0.0931, "avg_cost_usd": 0.00548,
                "avg_latency_ms": 502, "total_latency_ms": 8534 },
  "routing":  { "premium_model": "claude-opus-4.6", "actual_cost_usd": 0.0931,
                "baseline_cost_usd": 0.2840, "saved_usd": 0.1909,
                "saved_pct": 67.2, "tiers": [ /* TierBreakdown[] */ ] },
  "success":  { "total": 17, "succeeded": 17, "failed": 0, "success_rate": 1.0,
                "series": [ { "label": "08:20:43", "start": "…", "success": 4,
                              "failure": 0, "total": 4, "success_rate": 1.0 } ] },
  "traces":   [ { "trace_id": "…", "run_id": "…", "timestamp": "…",
                  "agent": "PlannerAgent", "tool": "plan", "status": "success",
                  "latency_ms": 165, "prompt_tokens": 9, "completion_tokens": 5,
                  "total_tokens": 14, "cost_usd": 0.00087,
                  "complexity": "High", "model": "claude-opus-4.6",
                  "provider": "unorouter", "detail": "…" } ],
  "count": 17
}
```

The page degrades to the deterministic dataset in
`components/dashboard/observability-demo.ts` whenever the API is unreachable,
showing a **"demo data — backend unreachable"** badge instead of a blank page.

**SDK** — `AQL1Client.logs()` returns the whole payload; `.traces()` and
`.savings()` are convenience accessors.

---

## Billing (`core/billing.py` + `api/billing.py`)

Stripe subscriptions with three tiers. `core/billing.py` is the single source
of truth for the catalogue — the backend serves it and the dashboard renders
it, so the two can never drift apart.

### Tiers

| Tier | Price | Monthly tokens | Concurrent runs | Seats | Features |
|---|---|---|---|---|---|
| **Free** | $0/mo | 50k | 1 | 1 | — |
| **Pro** | $29/mo | 2M | 5 | 1 | API access, priority routing, observability history |
| **Team** | $99/mo | 10M | 25 | 10 | everything in Pro + team management, SSO-ready |

Feature flags are a **complete map** (`api_access`, `priority_routing`,
`observability_history`, `team_management`, `sso`) — every key is always
present, so the frontend never has to guess whether a missing key means "off"
or "unknown". Adding a feature is one entry in `FEATURE_KEYS`.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/billing/plans` | The three tiers with prices, limits and features |
| GET | `/v1/billing/subscription` | The caller's tier, status, usage vs limit, renewal date, features |
| POST | `/v1/billing/checkout` | Create a Stripe Checkout Session → returns its URL |
| POST | `/v1/billing/portal` | Create a Stripe Billing Portal session |
| POST | `/v1/billing/webhook` | Stripe webhook receiver (signature-verified) |

`/v1/billing/webhook` is **exempt from API-key auth** (Stripe cannot send a
key) and is authenticated by its Stripe signature instead. A user with no
billing row gets a synthesised **Free** subscription rather than a 404, so the
dashboard always has something to render.

### Webhook events handled

| Event | Effect |
|---|---|
| `checkout.session.completed` | Activate the subscription; set tier, token limit and features |
| `customer.subscription.created` | Sync tier, status, period end and token limit from the price id |
| `customer.subscription.updated` | Sync tier/status/period (upgrades, downgrades, scheduled cancels) |
| `customer.subscription.deleted` | Downgrade to **Free**, re-base the token limit, disable paid features |
| `invoice.payment_succeeded` | Mark active and **reset the monthly token counter** for the new period |
| `invoice.payment_failed` | Mark `past_due` and restrict paid features (tier retained for display) |
| `customer.subscription.trial_will_end` | Log/notify only — no state change |

Handlers are **idempotent**: each event id is recorded in `stripe_events` and a
replay is a no-op, so a retried webhook can never double-apply a tier change.
Unknown event types are acknowledged with a 200 (Stripe retries any non-2xx).
A bad signature returns **400**; a handler failure still returns 200 so Stripe
can retry.

### Supabase tables

```sql
create table subscriptions (
  user_id  text primary key,
  payload  jsonb not null,   -- tier, status, stripe ids, period, cancel flag
  updated_at timestamptz default now()
);

create table usage (
  user_id  text primary key,
  payload  jsonb not null,   -- period_start, tokens_used, tokens_limit, runs_used
  updated_at timestamptz default now()
);

create table stripe_events (
  event_id text primary key, -- webhook idempotency key
  payload  jsonb not null,   -- { event_id, type, processed_at }
  created_at timestamptz default now()
);
```

`BillingStore` delegates to `memory/state.py`, which already owns the Supabase
client and the in-memory fallback — so billing never has to know whether
Supabase is configured.

### Usage enforcement

`check_token_limit(user_id)` returns
`{allowed, tier, tokens_used, tokens_limit, tokens_remaining, percent_used, reason}`
and `record_usage(user_id, tokens=…, runs=…)` adds consumption, **resetting the
counter when the billing period rolls over** so a stale row can never silently
consume this month's allowance. A tier change re-bases the allowance
immediately.

### Configuration

| Env var | Purpose |
|---|---|
| `STRIPE_SECRET_KEY` | Stripe API key (empty → demo mode) |
| `STRIPE_WEBHOOK_SECRET` | Webhook signing secret (empty → signature not verified, with a warning) |
| `STRIPE_PUBLISHABLE_KEY` | Publishable key for the frontend |
| `STRIPE_PRICE_ID_PRO` / `STRIPE_PRICE_ID_TEAM` | One Stripe Price per paid tier |
| `BILLING_ENABLED` | `false` serves the catalogue but never touches Stripe |
| `BILLING_SUCCESS_URL` / `BILLING_CANCEL_URL` | Where Checkout returns the user |
| `SUBSCRIPTIONS_TABLE` / `USAGE_TABLE` / `STRIPE_EVENTS_TABLE` | Table names |

**Graceful degradation** — with no Stripe keys the catalogue still serves,
subscriptions resolve to a local Free state, and checkout/portal return demo
URLs instead of raising. Typed exceptions (`BillingError` →
`BillingConfigError` / `BillingStoreError` / `StripeGatewayError` /
`WebhookVerificationError`) plus logging, never a raw crash.

### Dashboard (`app/dashboard/billing/page.tsx`)

Reached from the sidebar's **Billing** item. Five panels: **current plan**
(tier, status badge, renewal date, "Manage billing" → Stripe Portal), **token
usage** (progress bar with a warning state near/over the limit), **pricing
tiers** (Free/Pro/Team with the current tier highlighted and a CTA that starts
Checkout), **feature comparison** (a table of which tier enables what), and
**billing history** (invoices, with an empty state). Loading skeletons
throughout, and a graceful demo-data fallback with a "backend unreachable"
badge when the API is down.

**SDK** — `AQL1Client.plans()`, `.subscription()`, `.create_checkout(tier)` and
`.create_portal()`.

---

## Client SDKs

Two lightweight, first-party SDKs wrap the versioned `/v1` REST API. Both are
dependency-light, fully typed, and share the same method surface, error
hierarchy, and retry behaviour.

| SDK | Path | Install | Runtime deps |
|---|---|---|---|
| **Python** | [`sdk/python/`](sdk/python/) | `pip install ./sdk/python` | none (stdlib transport) |
| **TypeScript** | [`sdk/ts/`](sdk/ts/) | `npm install ./sdk/ts` | none (global `fetch`) |

Each folder has its own README with the full method reference, plus runnable
scripts under `examples/`.

### Quickstart — Python

```python
from aql1 import AQL1

client = AQL1(api_key="sk-...")          # base_url defaults to http://localhost:8000
response = client.run_agent(prompt="Summarise today's AI news",
                            allow_human_approval=True)
print(response.task_id, response.status)

status = client.wait_for_completion(response.task_id, poll_interval=1.0, timeout=120)
print(status.status, status.cost_usd, status.tokens, status.result)
```

An async client mirrors it exactly:

```python
from aql1 import AsyncAQL1

async with AsyncAQL1(api_key="sk-...") as client:
    started = await client.run_agent(prompt="Draft a launch plan")
    async for status in client.stream_progress(started.task_id):
        print(status.status, status.progress.percent)
```

### Quickstart — TypeScript

```ts
import { AQL1 } from 'aql1';

const client = new AQL1({ apiKey: 'sk-...' });
const response = await client.runAgent({ prompt: "Summarise today's AI news",
                                         allowHumanApproval: true });
console.log(response.task_id, response.status);

const status = await client.waitForCompletion(response.task_id, { pollInterval: 1 });
console.log(status.status, status.cost_usd, status.result);
```

### API surface

| Python | TypeScript | Endpoint |
|---|---|---|
| `run_agent(prompt, ...)` | `runAgent({ prompt, ... })` | `POST /v1/agent/run` |
| `get_status(task_id)` | `getStatus(taskId)` | `GET /v1/agent/status/{task_id}` |
| `wait_for_completion(task_id, ...)` | `waitForCompletion(taskId, ...)` | polls `get_status` |
| `approve(approval_id, ...)` | `approve(approvalId, ...)` | `POST /agent/approve` |
| `wait_for_approval(...)` / `resume_after_approval(...)` | `waitForApproval(...)` / `resumeAfterApproval(...)` | `GET /agent/approvals/{id}` |
| `create_key(name, ...)` | `createKey(name, ...)` | `POST /v1/keys` |
| `list_keys()` | `listKeys()` | `GET /v1/keys` |
| `revoke_key(key_id)` | `revokeKey(keyId)` | `DELETE /v1/keys/{key_id}` |
| `stream_progress(task_id)` *(async only)* | `streamProgress(taskId)` | async iterator over status |

Both clients accept `base_url`/`baseUrl`, `timeout`, `max_retries`/`maxRetries`,
and a custom `transport` — so you can plug in `httpx`, axios, undici, a proxy,
or a test double.

### Auth

The key is sent as `Authorization: Bearer <key>` on every request. Keys are
stored **hashed** (SHA-256) server-side, so `create_key`/`createKey` returns the
raw key **exactly once** — store it immediately. See
*REST API & authentication* above for the `api_keys` schema and rate limits.

### Errors

Both SDKs raise the same typed hierarchy — nothing is swallowed:

```
AQL1Error                       base class
├── AuthenticationError         401 — missing / invalid / revoked key
├── RateLimitError              429 — exposes retry_after, limit, remaining, reset
├── NotFoundError               404 — unknown resource
├── ValidationError             422 — request body rejected
├── APIError                    any other non-2xx (status code + parsed body)
├── APIConnectionError          request never reached the server
├── TimeoutError                request exceeded the configured timeout
├── ApprovalRequiredError       high-risk run paused but approval was disallowed
└── ApprovalRejectedError       a paused run was rejected by a human
```

### Retries

`429`, `408`, `409`, `425` and `5xx` responses — plus network failures — are
retried with **exponential backoff + full jitter**, honouring `Retry-After`
when the server sends it. `401`/`403`/`404`/`422` are terminal and never
retried. Defaults: `max_retries=2` (3 attempts total), `backoff_factor=0.5`,
`max_backoff=30s`.

### Tests

```bash
# Python — 43 tests, mocked transport, no network
cd sdk/python && pip install ".[dev]" && pytest -q

# TypeScript — 35 tests, mocked transport, no network
cd sdk/ts && npm install && npm test
```

---

## How it fits together

1. **`core/router.py`** classifies a task (Low / Medium / High), picks the
   matching model, estimates token cost, and executes with a provider
   fallback chain that ends in a local stub.
2. **`core/engine.py`** runs the agent loop, calling the router and (in
   production) dispatching tools from the registry.
3. **`tools/registry.py`** holds callable tools; **`tools/mcp_client.py`**
   connects to external MCP servers over JSON-RPC.
4. **`memory/`** persists long-term vectors (Pinecone) and run state (Supabase).
5. **`api/routes.py`** exposes everything over REST; **`sdk/`** wraps it for
   Python consumers; the **Next.js** app is the human control plane.

## Going live

Replace the stubs with real integrations:

- `core/engine.py` → `_call_model()`: it already routes through `ModelRouter`;
  set `OPENAI_API_KEY` / `UNOROUTER_API_KEY` to go live.
- **Claude/Anthropic** traffic is served via **UnoRouter** — set
  `UNOROUTER_API_KEY` (see *Providers & UnoRouter*). No Anthropic SDK is needed.
- `memory/vector_store.py` → `_hash_embed()`: use a real embedding model
  (set `OPENAI_API_KEY` and `MemoryManager` picks up `text-embedding-3-small`
  automatically via `embed_text()`; point the Pinecone index at matching dims).
- `tools/mcp_client.py`: add SSE/HTTP transports for remote MCP servers.
- **Billing**: set `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` and the two
  `STRIPE_PRICE_ID_*` values, then point a Stripe webhook at
  `/v1/billing/webhook` (see *Billing*).
