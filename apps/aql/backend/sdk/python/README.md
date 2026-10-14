# AQL-1 Python SDK

A lightweight, dependency-free Python client for the **AQL-1** autonomous agent
operating layer REST API. Ships a synchronous client (`AQL1`) and an
asynchronous one (`AsyncAQL1`).

- **Zero required dependencies** — the default transport is the standard library.
- **Fully typed** — dataclass models, `py.typed` marker, no `Any` in the public surface.
- **Typed errors** — every non-2xx response maps to a specific exception.
- **Automatic retries** — exponential backoff + jitter for `429`/`5xx`/network errors, honouring `Retry-After`.

---

## Install

```bash
# From this folder
pip install .

# With the optional httpx transport (faster, pooled connections)
pip install ".[httpx]"

# For development (tests, linting, type checking)
pip install ".[dev]"
```

Requires Python 3.9+.

---

## Quickstart

```python
from aql1 import AQL1

client = AQL1(api_key="sk-...")          # base_url defaults to http://localhost:8000

response = client.run_agent(prompt="Summarise today's AI news",
                            allow_human_approval=True)
print(response.task_id, response.status)

# Poll until it settles
status = client.wait_for_completion(response.task_id, poll_interval=1.0, timeout=120)
print(status.status, status.cost_usd, status.tokens)
print(status.result)
```

Use it as a context manager so the transport is closed for you:

```python
with AQL1(api_key="sk-...") as client:
    status = client.get_status("task-id")
```

---

## Async

```python
import asyncio
from aql1 import AsyncAQL1

async def main():
    async with AsyncAQL1(api_key="sk-...") as client:
        started = await client.run_agent(prompt="Draft a launch plan")

        # Async-iterate progress updates
        async for status in client.stream_progress(started.task_id):
            print(status.status, status.progress.percent)
            if status.is_terminal:
                break

asyncio.run(main())
```

`AsyncAQL1` defaults to a thread-backed stdlib transport. For a native async
HTTP stack, pass `transport=AsyncHttpxTransport()`.

---

## Configuration

| Option | Default | Description |
|---|---|---|
| `api_key` | *required* | Sent as `Authorization: Bearer <key>`. |
| `base_url` | `http://localhost:8000` | API root. |
| `timeout` | `30.0` | Per-request timeout in seconds. |
| `max_retries` | `2` | Retries for `429`/`5xx`/network errors (so 3 attempts total). |
| `transport` | `UrllibTransport` | Custom transport implementing the protocol. |
| `backoff_factor` | `0.5` | Base for exponential backoff. |
| `max_backoff` | `30.0` | Backoff ceiling in seconds. |
| `default_headers` | `{}` | Extra headers merged into every request. |

### Custom transport

Any object with a matching `request(...)` method works:

```python
class MyTransport:
    def request(self, method, url, *, headers, json_body, timeout):
        # ... your HTTP call ...
        return TransportResponse(status_code=200, headers={}, body=b"{}")

client = AQL1(api_key="sk-...", transport=MyTransport())
```

---

## Method reference

### Agent runs

| Method | Endpoint | Notes |
|---|---|---|
| `run_agent(prompt, *, allow_human_approval=True, wait=False, action_type=None, payload=None, user_id="anonymous", session_id="default", provider=None)` | `POST /v1/agent/run` | Async by default — returns a `RunResponse` with the `task_id`. `wait=True` runs server-side synchronously. |
| `get_status(task_id)` | `GET /v1/agent/status/{task_id}` | Returns a `TaskStatus`. Raises `NotFoundError` for an unknown id. |
| `wait_for_completion(task_id, *, poll_interval=1.0, timeout=300.0, on_progress=None)` | polls `get_status` | Blocks until terminal. `pending_approval` counts as terminal. Raises `TimeoutError`. |
| `approve(approval_id, *, decision="approve", approver=None, note="")` | `POST /agent/approve` | Approve or reject a paused run. |
| `wait_for_approval(approval_id, *, poll_interval=2.0, timeout=600.0)` | `GET /agent/approvals/{id}` | Blocks until a human decides. |
| `resume_after_approval(approval_id, ...)` | — | Waits for the decision; raises `ApprovalRejectedError` on rejection. |

### Key management

| Method | Endpoint |
|---|---|
| `create_key(name, *, owner_id="anonymous", scopes=None, rate_limit_requests=None, rate_limit_window_seconds=None)` | `POST /v1/keys` |
| `list_keys()` | `GET /v1/keys` |
| `revoke_key(key_id)` | `DELETE /v1/keys/{key_id}` |

`create_key` returns an `APIKeyCreated` whose `api_key` field holds the **raw
key — shown exactly once**. Only its SHA-256 hash is stored server-side.

### Async-only extras

| Method | Description |
|---|---|
| `stream_progress(task_id, *, poll_interval=1.0, timeout=300.0)` | Async generator yielding `TaskStatus` until terminal. |
| `aclose()` | Close the async transport. |

---

## Human-in-the-loop

A high-risk action (sending external email, deleting records, moving money,
shell execution, credential access, bulk export) **pauses** the run instead of
executing it.

```python
started = client.run_agent(
    prompt="Email the Q3 report to the client.",
    action_type="email.send",
    payload={"to": "client@example.com"},
    allow_human_approval=True,
)

if started.is_pending_approval:
    print("needs approval:", started.approval_id)
    client.approve(started.approval_id, decision="approve", approver="arif")
    status = client.wait_for_completion(started.task_id)
```

With `allow_human_approval=False`, the SDK raises `ApprovalRequiredError`
(carrying `approval_id`) instead of silently returning a paused run.

---

## Error handling

```
AQL1Error                       base class for everything below
├── AuthenticationError         401 — missing / invalid / revoked key
├── RateLimitError              429 — exposes retry_after, limit, remaining, reset
├── NotFoundError               404 — unknown resource
├── ValidationError             422 — request body rejected
├── APIError                    any other non-2xx (has status_code + parsed body)
├── APIConnectionError          request never reached the server
├── TimeoutError                request exceeded the configured timeout
├── ApprovalRequiredError       high-risk run paused but approval was disallowed
└── ApprovalRejectedError       a paused run was rejected by a human
```

```python
from aql1 import AQL1, AuthenticationError, RateLimitError, APIError

try:
    client.run_agent(prompt="...")
except AuthenticationError as exc:
    print("bad key:", exc.code)                 # e.g. "invalid_api_key"
except RateLimitError as exc:
    print("retry after", exc.retry_after, "s")  # honour the server's own number
except APIError as exc:
    print(exc.status_code, exc.message, exc.body)
```

Errors are **never swallowed** — every failure surfaces as one of the types above.

---

## Retry behaviour

| Condition | Behaviour |
|---|---|
| `429`, `408`, `409`, `425`, `5xx` | Retried up to `max_retries`, honouring `Retry-After` when present. |
| Network errors (DNS, refused, reset) | Retried with exponential backoff + jitter. |
| `401`, `403`, `404`, `422` | **Not** retried — these are terminal. |

Backoff is `min(max_backoff, backoff_factor * 2**attempt)` multiplied by a
random factor in `[0.5, 1.0]` (full jitter), so concurrent clients don't
synchronise their retries.

---

## Examples

Runnable scripts live in [`examples/`](examples/):

| Script | Shows |
|---|---|
| `quickstart.py` | Start a run, poll it, print the result. |
| `async_quickstart.py` | `AsyncAQL1` with `stream_progress`. |
| `approvals.py` | The pause → approve → resume flow. |
| `error_handling.py` | Every exception type and how to react. |
| `manage_keys.py` | Mint, list, and revoke API keys. |

```bash
export AQL1_API_KEY=sk-...
python examples/quickstart.py
```

---

## Tests

```bash
pip install ".[dev]"
pytest -q
```

The suite mocks the HTTP layer entirely — no network, no server required.

---

## License

MIT
