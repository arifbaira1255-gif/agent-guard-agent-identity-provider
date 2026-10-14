# AQL-1 TypeScript SDK

A lightweight, fully-typed TypeScript client for the **AQL-1** autonomous agent
operating layer REST API.

- **Zero runtime dependencies** — the default transport is the global `fetch`.
- **Strictly typed** — every request/response shape is declared; no `any` in the public surface.
- **Typed errors** — every non-2xx response maps to a specific error class.
- **Automatic retries** — exponential backoff + jitter for `429`/`5xx`/network errors, honouring `Retry-After`.
- **Async everywhere** — `Promise`-returning methods plus an async iterator for progress.

---

## Install

```bash
npm install aql1
# or, from this folder
npm install && npm run build
```

Requires Node 18+ (for the global `fetch`). Works in any modern bundler
(Vite, Next.js, esbuild) and in Deno/Bun.

---

## Quickstart

```ts
import { AQL1 } from 'aql1';

const client = new AQL1({ apiKey: 'sk-...' }); // baseUrl defaults to http://localhost:8000

const response = await client.runAgent({
  prompt: "Summarise today's AI news",
  allowHumanApproval: true,
});
console.log(response.task_id, response.status);

// Poll until it settles
const status = await client.waitForCompletion(response.task_id, {
  pollInterval: 1,
  timeout: 120,
});
console.log(status.status, status.cost_usd, status.tokens, status.result);
```

---

## Configuration

| Option | Default | Description |
|---|---|---|
| `apiKey` | *required* | Sent as `Authorization: Bearer <key>`. |
| `baseUrl` | `http://localhost:8000` | API root. |
| `timeout` | `30` | Per-request timeout in seconds. |
| `maxRetries` | `2` | Retries for `429`/`5xx`/network errors (3 attempts total). |
| `transport` | `FetchTransport` | Custom transport implementing `Transport`. |
| `backoffFactor` | `0.5` | Base for exponential backoff. |
| `maxBackoff` | `30` | Backoff ceiling in seconds. |
| `defaultHeaders` | `{}` | Extra headers merged into every request. |

### Custom transport

Any object with a `request(req)` method works — swap in axios, undici, a proxy,
or a test double:

```ts
import type { Transport, TransportRequest, TransportResponse } from 'aql1';

class MyTransport implements Transport {
  async request(req: TransportRequest): Promise<TransportResponse> {
    // ... your HTTP call ...
    return { status: 200, headers: {}, body: '{}' };
  }
}

const client = new AQL1({ apiKey: 'sk-...', transport: new MyTransport() });
```

---

## Method reference

### Agent runs

| Method | Endpoint | Notes |
|---|---|---|
| `runAgent({ prompt, allowHumanApproval?, wait?, waitForCompletion?, actionType?, payload?, userId?, sessionId?, provider?, pollInterval?, timeout?, onProgress? })` | `POST /v1/agent/run` | Async by default — resolves with a task handle. `wait: true` runs server-side synchronously; `waitForCompletion: true` polls client-side. |
| `getStatus(taskId)` | `GET /v1/agent/status/{task_id}` | Resolves with a `TaskStatus`. Throws `NotFoundError` for an unknown id. |
| `waitForCompletion(taskId, { pollInterval?, timeout?, onProgress?, signal? })` | polls `getStatus` | Resolves when terminal. `pending_approval` counts as terminal. Throws `TimeoutError`. |
| `approve(approvalId, { decision?, approver?, note? })` | `POST /agent/approve` | Approve or reject a paused run. |
| `waitForApproval(approvalId, { pollInterval?, timeout? })` | `GET /agent/approvals/{id}` | Resolves once a human decides. |
| `resumeAfterApproval(approvalId, ...)` | — | Waits for the decision; throws `ApprovalRejectedError` on rejection. |

### Key management

| Method | Endpoint |
|---|---|
| `createKey(name, { ownerId?, scopes?, rateLimitRequests?, rateLimitWindowSeconds? })` | `POST /v1/keys` |
| `listKeys()` | `GET /v1/keys` |
| `revokeKey(keyId)` | `DELETE /v1/keys/{key_id}` |

`createKey` resolves with an `APIKeyCreated` whose `api_key` field holds the
**raw key — shown exactly once**. Only its SHA-256 hash is stored server-side.

### Streaming

```ts
for await (const status of client.streamProgress(taskId, { pollInterval: 1 })) {
  console.log(status.status, status.progress.percent);
  if (status.status === 'completed') break;
}
```

---

## Human-in-the-loop

A high-risk action (sending external email, deleting records, moving money,
shell execution, credential access, bulk export) **pauses** the run instead of
executing it.

```ts
const started = await client.runAgent({
  prompt: 'Email the Q3 report to the client.',
  actionType: 'email.send',
  payload: { to: 'client@example.com' },
  allowHumanApproval: true,
});

if (started.status === 'pending_approval') {
  console.log('needs approval:', started.approval_id);
  await client.approve(started.approval_id!, { decision: 'approve', approver: 'arif' });
  const status = await client.waitForCompletion(started.task_id);
}
```

With `allowHumanApproval: false`, the SDK throws `ApprovalRequiredError`
(carrying `approvalId`) instead of silently returning a paused run.

---

## Error handling

```
AQL1Error                       base class for everything below
├── AuthenticationError         401 — missing / invalid / revoked key
├── RateLimitError              429 — exposes retryAfter, limit, remaining, reset
├── NotFoundError               404 — unknown resource
├── ValidationError             422 — request body rejected
├── APIError                    any other non-2xx (has statusCode + parsed body)
├── APIConnectionError          request never reached the server
├── TimeoutError                request exceeded the configured timeout
├── ApprovalRequiredError       high-risk run paused but approval was disallowed
└── ApprovalRejectedError       a paused run was rejected by a human
```

```ts
import { AQL1, AuthenticationError, RateLimitError, APIError } from 'aql1';

try {
  await client.runAgent({ prompt: '...' });
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.error('bad key:', error.code);            // e.g. "invalid_api_key"
  } else if (error instanceof RateLimitError) {
    console.error('retry after', error.retryAfter);   // honour the server's number
  } else if (error instanceof APIError) {
    console.error(error.statusCode, error.message, error.body);
  }
}
```

Errors are **never swallowed** — every failure surfaces as one of the classes above.

---

## Retry behaviour

| Condition | Behaviour |
|---|---|
| `429`, `408`, `409`, `425`, `5xx` | Retried up to `maxRetries`, honouring `Retry-After` when present. |
| Network errors (DNS, refused, reset) | Retried with exponential backoff + jitter. |
| `401`, `403`, `404`, `422` | **Not** retried — these are terminal. |

Backoff is `min(maxBackoff, backoffFactor * 2**attempt)` multiplied by a random
factor in `[0.5, 1.0]` (full jitter), so concurrent clients don't synchronise
their retries.

---

## Examples

Runnable scripts live in [`examples/`](examples/):

| Script | Shows |
|---|---|
| `quickstart.ts` | Start a run, poll it, print the result. |
| `async-quickstart.ts` | `streamProgress` async iteration. |
| `approvals.ts` | The pause → approve → resume flow. |
| `error-handling.ts` | Every error class and how to react. |
| `manage-keys.ts` | Mint, list, and revoke API keys. |

```bash
export AQL1_API_KEY=sk-...
npx tsx examples/quickstart.ts
```

---

## Build & test

```bash
npm run build       # emit dist/ with .d.ts declarations
npm run typecheck   # tsc --noEmit, zero errors
npm test            # compile + run the unit tests (node:test)
```

The test suite injects a mock transport — no network, no server required.

---

## License

MIT
