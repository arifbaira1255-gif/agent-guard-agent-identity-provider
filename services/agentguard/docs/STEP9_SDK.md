# AgentGuard Universal Agent SDK — API Reference & Versioning

**Version:** all SDKs at `0.2.0`
**Scope:** the client side of AgentGuard. The policy decision engine is Step 10 (§8 of the final report).

A note on honesty: everything marked "verified" in this document was executed in this repository's
test suites. Anything not implemented is listed under *Known limitations*, not described as if it works.

---

## 1. Why four SDKs

Agents are written in whatever language their authors already use. AgentGuard's controls are only
useful if they are reachable from inside those agents without rewriting them. Four SDKs therefore
expose **one conceptual interface**:

| Language | Package | Import |
|---|---|---|
| Python | `agentguard-sdk` (`src/agentguard_sdk`) | `from agentguard_sdk import AgentGuardClient, SdkConfig` |
| TypeScript / JavaScript | `@agentguard/sdk` (ESM, Node ≥18) | `import { AgentGuardClient, SdkConfig } from '@agentguard/sdk'` |
| Go | `github.com/agentguard/sdk-go` | `import agentguard "github.com/agentguard/sdk-go"` |
| Rust | `agentguard-sdk` | `use agentguard_sdk::{Client, Config};` |

---

## 2. The five-step agent lifecycle

Every SDK, every language, same order. Authentication and authorization are deliberately separate
steps: holding a credential proves *who you are*, never *what you may do*.

```
1. IDENTITY        register agent -> agent_id, create instance -> instance_id
2. AUTHENTICATION  acquire credential (proves possession of the agent's own key)
3. AUTHORIZATION   ask for a decision on (action, resource) -- BEFORE acting
4. EXECUTION       run the protected action ONLY on ALLOW
5. REPORTING       emit a security event with the correlation id
```

### Operation map

| Operation | Python | TypeScript | Go | Rust |
|---|---|---|---|---|
| Construct client | `AgentGuardClient(cfg)` | `new AgentGuardClient(cfg)` | `NewClient(cfg, agent, inst)` | `Client::new(cfg, agent, inst)` |
| Register agent | `register_agent(...)` | `registerAgent(...)` | `RegisterAgent(...)` | `register_agent(...)` |
| Create instance | `create_instance()` | `createInstance()` | `CreateInstance()` | `create_instance(None)` |
| Bind existing identity | `bind(a, i)` | `bind(a, i)` | `Bind(a, i)` | `bind(a, i)` |
| Acquire credential | `issue_credential()` | `issueCredential()` | `IssueCredential()` | `issue_credential()` |
| Renew / rotate | `renew_credential()` | `renewCredential()` | `RenewCredential()` | `renew_credential()` |
| Ensure (auto-renew) | `ensure_credential()` | `ensureCredential()` | `EnsureCredential()` | `ensure_credential()` |
| Revoke | `revoke_credential(id)` | `revokeCredential(id)` | `RevokeCredential(id,...)` | `revoke_credential(id, r)` |
| Credential status | `credential_status(id)` | `credentialStatus(id)` | `CredentialStatus(id)` | `credential_status(Some(id))` |
| Verify credential | `verify_credential(...)` | `verifyCredential(...)` | `VerifyCredential(...)` | `verify_credential(...)` |
| Possession proof | `make_proof(aud)` | `makeProof(aud)` | `MakeProof(aud)` | `make_proof(Some(aud))` |
| **Authorize** | `authorize(a, r, ctx)` | `authorize(a, r, ctx)` | `Authorize(a, r, ctx)` | `authorize(a, r, ctx)` |
| Require (error on DENY) | `require(...)` | `require(...)` | `Require(...)` | `require(...)` |
| Gate execution | `enforce(d, fn)` | `enforce(d, fn)` | `Enforce(d, fn)` | `enforce(&d, fn)` |
| Report event | `report_event(...)` | `reportEvent(...)` | `ReportEventDetailed(...)` | `report_event(...)` |
| Flush events | `flush_events()` | `flushEvents()` | `FlushEvents()` | `flush_events()` |

---

## 3. Configuration

Fail-closed by construction. `Config::new` / `NewConfig` / `SdkConfig` validate immediately, and any
field mutated afterwards can be re-checked (`Validate()` / `validate()`).

| Rule | Enforced behaviour |
|---|---|
| Absolute base URL required | A relative URL is rejected |
| Environment must be `development`\|`staging`\|`production` | Anything else is rejected |
| No plaintext in production | `http://` + `production` is rejected |
| TLS verification ON by default | Disabling it is rejected outside `development` |
| Timeout bounded | `(0, 300s]` |
| Retries bounded | `[0, 10]`, only on safe-to-repeat requests |
| Response size bounded | Oversized responses are refused, not truncated silently |
| Secrets never printed | Tokens appear as `<redacted>` in config/credential string forms |

**Never hard-code a credential.** The provisioning token comes from the environment or a secret
manager:

```
AGENTGUARD_BASE_URL=https://agentguard.internal
AGENTGUARD_ENV=production
AGENTGUARD_CONTROL_PLANE_TOKEN=<from your secret manager, never from source control>
```

---

## 4. Authorization semantics

### Decisions

```json
{ "allowed": true, "reason": "capability_match", "policy": "capability-default",
  "decision_id": "dec_...", "correlation_id": "cor_..." }
```

`allowed` is the **only** field that gates execution. `reason` values the SDKs' tests exercise:
`capability_match`, `no_matching_capability`, `invalid_signature`, `policy_unavailable`,
`policy_denied`, `policy_error`.

### Fail-closed rules (verified by tests)

| Situation | Result |
|---|---|
| No credential and issuance fails | **DENY** |
| Policy engine unreachable / 404 / timeout | **DENY** (`policy_unavailable`) |
| Decision body unparseable or missing `allowed` | **DENY** |
| Possession proof invalid | **DENY** (`invalid_signature`) |
| PDP implementation throws/panics | **DENY** (recovered, never propagated as allow) |
| Credential expired or unparseable expiry | Treated as unusable; renew attempted |
| `Enforce`/`enforce` called with a DENY | Executor is **not** invoked; an error is returned |

### The anti-bypass guarantee

```go
// Go
decision := client.Authorize("tool:read", "db:customers", nil)
result, err := client.Enforce(decision, protectedAction)  // runs ONLY on allowed == true
```

```rust
// Rust
let decision = client.authorize("tool:read", "db:customers", None)?;
let result = client.enforce(&decision, protected_action)?;  // runs ONLY on allowed == true
```

Calling an SDK method **never** executes a tool function. A tool runs only when a decision explicitly
allowed it, and the tool guard reports both outcomes as security events.

---

## 5. Proof of possession

Credentials are bound to an **agent-side Ed25519 key** generated in-process. The private key is never
serialised, never logged, never transmitted. Every authorization request carries a fresh proof.

```
signing input = "agentguard-proof-v1\n" || canonical_json({
    "audience", "credential_id", "nonce", "request_id", "timestamp", "v": 1 })

signing input (CSR) = "agentguard-csr-v1\n" || canonical_json({
    "agent_id", "instance_id", "public_key" })
```

`canonical_json` is compact, key-sorted, ASCII-escaped — byte-identical across Python, TypeScript, Go
and Rust. This is enforced, not assumed: the Python SDK generates the fixture in
`sdks/conformance/vectors.json`, and the Python, Node, Go and Rust suites all assert that they
reproduce those exact bytes and signatures.

**Nonces are single-use by construction**: each proof gets a fresh 18-byte random nonce and a fresh
`request_id`, so a captured proof cannot be replayed as-is. Server-side replay defence is AgentGuard's
(existing Step 1–8 machinery), not the SDK's.

---

## 6. Error model

Stable class codes, identical in all four languages:

| Code | Meaning | Retryable |
|---|---|---|
| `configuration_error` | Invalid SDK configuration | no |
| `validation_error` | Invalid request arguments | no |
| `transport_error` | Network/TLS failure (reduced to a class, never a URL) | yes |
| `timeout` | Request exceeded its timeout | yes |
| `cancelled` | Caller cancelled | no |
| `authentication_failed` | Credential rejected | no |
| `credential_expired` / `credential_revoked` | Credential no longer usable | no |
| `forbidden` | Authorization denied | no |
| `policy_unavailable` | Decision could not be established | yes |
| `not_found` / `conflict` / `rate_limited` / `server_error` | HTTP-mapped | varies |
| `tool_denied` | A guarded tool call was denied | no |

**Class codes are the contract.** In Go the server's own `error` string is preserved as
`Error.ServerCode`; in Rust as `Error.server_code`. It can never overwrite the class code a caller
switches on — that would silently change retry behaviour.

`correlation_id` is carried on requests and surfaced on decisions, errors and events, so an agent
action can be traced end-to-end through AgentGuard's logs.

---

## 7. Reliability behaviour

| Concern | Behaviour | Verified in |
|---|---|---|
| Timeout | Per-request, typed `timeout` error | Python, Go, Rust |
| Retries | Exponential backoff + jitter, bounded | Python, Go, Rust |
| Retry safety | GET/HEAD, or any request with an `Idempotency-Key`. A non-idempotent POST is **never** replayed | Go, Python |
| Cancellation | Checked before each attempt; a cancelled call issues **zero** requests | Go, Rust |
| Broken connection | Typed `transport_error`, never a panic | Rust, Go |
| Event durability | A failed flush **retains** the buffered events rather than dropping evidence | Python, TypeScript, Go, Rust |
| Secret hygiene | Bearer material scrubbed from event metadata; unknown keys dropped | all four |

---

## 8. Tool guard (framework-agnostic adapter)

```go
// Go
guard := agentguard.NewToolGuard(client)
result, err := guard.Execute("read_customer", func() (any, error) { /* real work */ })
```

```rust
// Rust
let mut guard = ToolGuard::new(&mut client);
let value = guard.execute("read_customer", || "ok")?;
```

Properties: the call is normalized into a `tool:<name>` authorization request; a DENY returns
`tool_denied` **without invoking the function**; the outcome is reported as a security event. This is
an adapter *interface* for tool-calling workflows — no specific third-party framework adapter is
provided (see limitations).

---

## 9. Versioning and compatibility policy

1. **Protocol versioning is separate from package versioning.** Signed payloads embed a domain
   separator with their own version (`agentguard-proof-v1`, `agentguard-csr-v1`) and a `v` field. The
   server accepts a documented window of protocol versions, so a package can be upgraded without a
   flag day.
2. **Semver for packages.** All four SDKs share the same major/minor so a cross-language deployment
   stays on one wire behaviour.
3. **Error codes and decision semantics are the stable interface.** Adding a code is a minor change;
   changing the meaning of an existing code, or the fail-closed default, is a major one.
4. **Unknown response fields are ignored**, not rejected — forward compatibility for Step 10.
5. **Cross-language parity is tested, not assumed**: any change to canonical JSON or signing must keep
   all four conformance suites green against the shared fixture.

---

## 10. Known limitations

1. **Rust `ca_bundle` is not wired** — set it and the transport refuses with `configuration_error`
   (fail closed) rather than silently ignoring it. Python/TypeScript/Go support a custom CA.
2. **Rust is synchronous** — no async runtime integration.
3. **Go and Rust integration tests use faithful stubs**, not a live control plane. Python integration
   tests run against a real server with real PostgreSQL and Redis.
4. **No named third-party framework adapters** (LangChain, LlamaIndex, LangGraph, …). Only the generic
   tool guard exists. No such support is claimed.
5. **No package publication or SDK-specific CI pipeline** was added in this step.

---

## 11. Getting started

```bash
# Python
PYTHONPATH=src:. python3 examples/sdk_quickstart_python.py

# TypeScript / JavaScript
node examples/sdk_quickstart_js.mjs

# Go
cd sdks/go && go run ./examples/quickstart

# Rust
cd sdks/rust && cargo run --example quickstart
```

All four read `AGENTGUARD_BASE_URL` / `AGENTGUARD_ENV` and take the token from
`AGENTGUARD_CONTROL_PLANE_TOKEN`. Each prints the lifecycle: credential acquired, decision obtained,
action gated, events flushed — and prints `DENIED` **without executing the action** when the policy
does not allow it.

### Running the SDK test suites

```bash
# Python (unit + conformance)
PYTHONPATH=src:. python3 -m unittest tests.test_sdk_unit tests.test_sdk_conformance

# Python integration (needs real PostgreSQL + Redis)
AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=... AGENTGUARD_TEST_PG_PASSWORD=... \
AGENTGUARD_TEST_REDIS_HOST=127.0.0.1 PYTHONPATH=src:. python3 -m unittest tests.test_sdk_integration

# TypeScript
cd sdks/typescript && npm test

# Go
cd sdks/go && go test ./...

# Rust
cd sdks/rust && cargo test
```
