# AgentGuard SDK Quick Start

Step 9 ships a **Universal Agent SDK** in four languages so AI agents can integrate with AgentGuard
security controls. All four SDKs (Python, TypeScript/JavaScript, Go and Rust) are implemented,
compiled and tested \u2014 see "Status" below for the exact suites that ran.

## What the SDK does

The SDK is a **thin client** over the existing AgentGuard control plane. It never re-implements
identity, KMS, mTLS or authorization internals \u2014 it reuses them. It provides, consistently across
languages:

1. **Registration & identity association** \u2014 `register_agent` / `create_instance`.
2. **Secure authentication** \u2014 `issue_credential` / `ensure_credential` (short-lived Agent
   Passport + Ed25519 proof-of-possession).
3. **Credential lifecycle** \u2014 proactive renewal, revocation, expiration handling.
4. **Authorization** \u2014 `authorize` / `require` / `enforce`, always fail-closed.
5. **Secure HTTP** \u2014 TLS verification on by default, bounded timeouts, bounded retries,
   cancellation, max response size.
6. **Security events** \u2014 `report_event` / `flush_events` with correlation ids.

## The one rule that matters

> **Authorize BEFORE you execute. The SDK makes it impossible to skip the check.**

`ToolGuard.execute(name, fn, ...)` calls the underlying tool `fn` **only** after an explicit ALLOW.
A DENY raises `ToolGuardError` and the tool body never runs. This is the anti-bypass guarantee.

## Python \u2014 5 lines

```python
from agentguard_sdk import AgentGuardClient, SdkConfig
from agentguard_sdk.adapters import ToolGuard

client = AgentGuardClient(SdkConfig(base_url="https://agentguard.internal"),
                          agent_id="agt_1", instance_id="inst_1")
client.ensure_credential()                     # authenticate

guard = ToolGuard(client)
result = guard.execute("read_db", read_db)     # runs ONLY if authorized
```

Full example: `examples/sdk_quickstart_python.py`.

## TypeScript / JavaScript \u2014 5 lines

```js
import { AgentGuardClient, SdkConfig, ToolGuard } from '@agentguard/sdk';

const client = new AgentGuardClient(SdkConfig.fromEnv(),
                                    { agentId: 'agt_1', instanceId: 'inst_1' });
await client.ensureCredential();

const guard = new ToolGuard(client);
const result = await guard.execute('read_db', readDb);   // runs ONLY if authorized
```

Full example: `examples/sdk_quickstart_js.mjs`.

## Configuration

| Env var | Meaning |
|---|---|
| `AGENTGUARD_BASE_URL` | Control-plane base URL (default `http://127.0.0.1:8443`) |
| `AGENTGUARD_ENV` | `development` \| `staging` \| `production` |
| `AGENTGUARD_CONTROL_PLANE_TOKEN` | Provisioning bearer token for bootstrap calls only |
| `AGENTGUARD_VERIFY_TLS` | `true`/`false` (false is refused outside development) |
| `AGENTGUARD_CA_BUNDLE` | Optional CA bundle path |

No credential, token or private key is ever hard-coded; secrets come from the environment. The
agent's own ephemeral Ed25519 private key is generated in-process and never leaves it.

## Framework adapters

Only adapters that are actually implemented and tested are shipped. Today that is the **generic
`ToolGuard`** (works with ANY tool-calling framework that can invoke a function). Framework-specific
adapters (LangChain, OpenAI function calling, MCP, \u2026) are a documented extension point \u2014 see
`docs/STEP9_SDK.md` \u2014 and are NOT claimed as supported until implemented and tested.

## Status by language

| Language | Status |
|---|---|
| Python | Implemented + unit tested (40) + conformance tested (7) + integration tested against real PostgreSQL + Redis (11) |
| TypeScript/JavaScript | Implemented + tested \u2014 `node --test test/`: 33 passed, 0 failed |
| Go | Implemented + compiled + `go vet` clean + tested \u2014 `go test ./...`: 33 passed, 0 failed |
| Rust | Implemented + compiled + tested \u2014 `cargo test`: 29 passed, 0 failed (10 unit + 9 conformance + 9 integration + 1 doc-test) |

Cross-language byte compatibility (Ed25519 proofs + canonical JSON) is proven by the shared
conformance vectors in `sdks/conformance/vectors.json`: the Python suite generates them, and the
Python, Node, Go and Rust suites all assert they reproduce those exact bytes and signatures.

**Go and Rust integration tests run against protocol-faithful local HTTP servers** (a TLS `httptest`
server in Go, a live HTTP server thread in Rust), not against a production AgentGuard instance. The
Python integration suite runs against a real server with real PostgreSQL and Redis. This distinction
is deliberate and is also recorded in `docs/STEP9_FINAL_REPORT.md` \u00a74 and \u00a76.
