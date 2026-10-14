# AgentGuard × Happy LANG — Integration Contract

The typed, versioned contract and the adapter that make **AgentGuard the authoritative
authorization point for a Happy LANG runtime**.

This package is the implementation of milestone **M1** from the Step 1 integration audit, and it
closes the two HIGH blockers that audit identified:

| Blocker | Finding | Closed by |
|---|---|---|
| **B1** | No versioned, typed interface existed between the two projects | `version.py`, `models.py`, `schema.py` — a versioned contract with JSON Schemas for all six payloads |
| **B4** | Happy LANG was not a security boundary, and nothing at the seam enforced that | `authorizer.py` — makes AgentGuard's decision preemptive, with uncertainty denied |

## The one rule that matters

> **A Happy LANG capability declaration, a passing contract, or a clean compile is NOT authorization.**

A program that declares `capability FileWriter { grants file_write }` and compiles perfectly is
still **denied** unless AgentGuard grants the operation. The local checker is a fast *pre-filter*;
AgentGuard is the *authority*.

Precedence, in order:

1. **Remote DENY always wins** — a local ALLOW never overrides it.
2. **Uncertainty is denial** — unreachable PDP, timeout, transport error, malformed answer →
   `INDETERMINATE` → deny.
3. **Local DENY short-circuits** — AgentGuard is not even contacted.
4. **Declarations are claims** — `requested_capabilities` / `declared_resources` are never grants.

---

## Installation

The package is dependency-free (standard library only) and needs no changes to either project.

```bash
export PYTHONPATH="$PWD/integration/contract:$PYTHONPATH"
```

Install into the Happy LANG tree by copying the directory, or leave it side-by-side and extend
`PYTHONPATH`. `happy` and `agentguard_sdk` are imported **lazily**, so the package imports cleanly
even when Happy LANG is not on the path (useful for AgentGuard-side tooling and for the tests).

Requirements: Python 3.10+ (uses `from __future__ import annotations` throughout).

## Configuration

**The integration is OFF by default.** With the flag unset, Happy LANG behaves exactly as it did
before: nothing is contacted, nothing is enforced, and no AgentGuard deployment is affected. This is
what makes it safe to ship into an existing deployment.

| Variable | Default | Meaning |
|---|---|---|
| `HAPPY_AGENTGUARD_ENABLED` | `false` | Master switch. **Everything is inert while false.** |
| `HAPPY_AGENTGUARD_MODE` | `enforce` | `enforce` (deny raises) · `audit` (record only) · `off` (skip remote) |
| `HAPPY_AGENTGUARD_BASE_URL` | `http://127.0.0.1:8443` | AgentGuard base URL |
| `HAPPY_AGENTGUARD_ENV` | `development` | `development` · `staging` · `production` |
| `HAPPY_AGENTGUARD_AGENT_ID` | — | Agent identity (must match the credential) |
| `HAPPY_AGENTGUARD_INSTANCE_ID` | — | Instance identity |
| `HAPPY_AGENTGUARD_ORG_ID` | — | Tenant / organization |
| `HAPPY_AGENTGUARD_SCOPE` | — | Happy LANG agent scope (e.g. `Teller`) |
| `HAPPY_AGENTGUARD_TIMEOUT_SECONDS` | `5.0` | Per-request timeout (bounds a hung PDP) |
| `HAPPY_AGENTGUARD_VERIFY_TLS` | `true` | TLS verification. **Cannot be disabled in production.** |
| `HAPPY_AGENTGUARD_CA_BUNDLE` | — | Custom CA bundle / mTLS material |
| `HAPPY_AGENTGUARD_ALLOW_INSECURE_HTTP` | `false` | Permit `http://` in production (TLS-terminating sidecar) |
| `HAPPY_AGENTGUARD_MAX_RESPONSE_BYTES` | `65536` | Response size bound |
| `HAPPY_AGENTGUARD_AUDIENCE` | `agentguard:tool` | Credential audience |
| `HAPPY_AGENTGUARD_ROUTE_EGRESS` | `false` | Route network operations through AgentGuard's egress gateway |
| `HAPPY_AGENTGUARD_REQUIRE_ISOLATION` | `false` | Refuse to execute when no OS-level isolation backend is available |
| `HAPPY_AGENTGUARD_EMIT_EVENTS` | `true` | Forward security events to AgentGuard's audit chain |
| `AGENTGUARD_CONTROL_PLANE_TOKEN` | — | Bearer token for the audit/event route |

Production is fail-closed on transport: plaintext `http://` and `verify_tls=false` are **rejected
at configuration time**, not at request time.

## Supported features

- **Typed, versioned contract** — `AuthorizationRequest` / `AuthorizationDecision` /
  `SecurityEvent` / `ExecutionRequest` / `ExecutionResult`, each with `validate()`, `to_dict()`,
  `from_dict()` and a JSON Schema in `schema.py`.
- **Authoritative authorization** — `AgentGuardAuthorizer` is a drop-in replacement for
  `CapabilityChecker` (`check_operation`, `require_action`, `enter_agent`, `exit_agent`).
- **Structured execution** — `IntegratedExecutor.execute()` runs a real `.hpy` program through
  compile → validate → authorize → run, and returns one `ResultKind` per outcome: `ok`,
  `authorization_denied`, `policy_violation`, `require_approval`, `compile_error`,
  `validation_error`, `runtime_error`, `resource_limit`, `cancelled`, `timeout`,
  `isolation_unavailable`, `integration_error`, `internal_error`.
- **Bounded requests** — length caps, charset checks, capability/resource counts, and hard ceilings
  on timeout / memory / output / operations.
- **Secret hygiene** — no credential material in `to_dict()`; event metadata is redacted and bounded.
- **Audit forwarding** — `EventForwarder` + `http_event_sink` post to AgentGuard's existing
  `POST /v1/security/events`, reaching its tamper-evident audit chain.
- **Egress routing** — `GuardedEgress` sends network operations through AgentGuard's
  `POST /v1/egress/request` so destination policy, address protection and DLP apply.

## Usage

```python
from agentguard_happy_contract import (
    AgentGuardAuthorizer, IntegratedExecutor, IntegrationConfig,
    ExecutionResource, ExecutionLimits,
)

config = IntegrationConfig.from_env()          # off unless HAPPY_AGENTGUARD_ENABLED is true

executor = IntegratedExecutor(config)
result = executor.execute_source(
    open("examples/banking.hpy").read(),
    filename="examples/banking.hpy",
    agent_id="agt_123",
    requested_capabilities=("file_write",),
    declared_resources=(ExecutionResource(kind="file", target="/data/out.json", access="write"),),
    limits=ExecutionLimits(timeout_s=10, max_memory_mb=256),
)
if not result.ok:
    print(result.result.value, result.error, result.correlation_id)
```

To install the authorizer into an existing Happy runtime, replace the context's checker — this is
Happy LANG's own extension point, and no Happy source file is touched:

```python
from agentguard_happy_contract import AgentGuardAuthorizer, IntegrationConfig
from agentguard_happy_contract.authorizer import install_into_runtime

authorizer = AgentGuardAuthorizer(IntegrationConfig.from_env())
authorizer.set_credentials(token=TOKEN, proof_provider=mint_fresh_proof)
install_into_runtime(runtime_context, authorizer)
```

> **Fresh proof per request.** AgentGuard keeps a replay cache and rejects a reused nonce with
> `replay_detected`. Always pass `proof_provider=` (a callable) rather than a fixed `proof=`.

## Limitations

These are **known and deliberate**, and each is a candidate for a later milestone:

1. **The Happy LANG runtime is not a boundary.** `IntegratedExecutor` installs the authorizer on the
   `RuntimeContext` it creates. A program that reaches a protected operation through a path that
   does not consult the checker is still unconstrained — this is exactly why AgentGuard must never
   treat a Happy compile or contract check as authorization.
2. **OS-level isolation is unavailable in this environment.** Happy's isolation backends need
   namespace support (`unshare`) that the audit sandbox lacks, so `require_isolation` cannot be
   satisfied here. Set it in any environment where untrusted code really runs.
3. **The policy engine requires the `opa` binary.** Without it AgentGuard falls back to its built-in
   **deny-by-default capability hook** (which is what the integration tests exercise). The
   disposition logic above is unchanged; only the richness of the policy changes.
4. **Proof-of-possession is service-held in development.** Real deployments should use an
   agent-held key (Mode B) and the SDK's credential lifecycle rather than `create_proof`.
5. **Live KMS / SPIRE / SIEM / Kubernetes paths are not verified here** (audit blockers B3/B5/B6).
6. **`audit` mode is a migration aid, not a production setting.** It records decisions without
   blocking; use it only while rolling out, then move to `enforce`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Everything is denied with `no_policy_decision_point_configured` | Integration enabled but no PDP wired | Pass `pdp=`, or disable the integration |
| `INDETERMINATE / pdp_unavailable:...` | AgentGuard unreachable, wrong `BASE_URL`, or timeout too low | Check connectivity; raise `HAPPY_AGENTGUARD_TIMEOUT_SECONDS`. This is a **denial by design**. |
| Second and later calls fail with `replay_detected` | Reusing one possession proof | Use `proof_provider=` so each request mints a fresh proof |
| `invalid_proof` | Proof not signed for the configured `audience` | Mint the proof for `HAPPY_AGENTGUARD_AUDIENCE` |
| `missing_credential` | No token supplied | `authorizer.set_credentials(token=...)` |
| `no_matching_capability` | AgentGuard's credential lacks the exact action (e.g. `tool:write_file`) | Grant it in AgentGuard — this is the control working |
| `UnsupportedContractVersion` | Peer speaks a different contract version | Align `CONTRACT_VERSION`; see `EVOLUTION_RULE` in `version.py` |
| `ValidationError: invalid execution request` | Malformed/oversized/incomplete request | Inspect `exc.errors` — every problem is reported together |
| Denials happen locally with no network call | Happy's local checker denied first | Expected: the local pre-filter short-circuits |
| `isolation_unavailable` | `require_isolation` set without a usable backend | Provide namespaces/container isolation or unset the flag |

## Tests

```bash
cd integration && python3 -m pytest tests/ -p no:cacheprovider
# 103 passed
```

| File | Covers |
|---|---|
| `test_contract_models.py` | Typed models, versioning, redaction, all result kinds |
| `test_request_validation.py` | Negative/input-validation tests at the trust boundary |
| `test_authorizer.py` | Precedence rules, fail-closed behaviour, auditing |
| `test_compatibility.py` | Wire compatibility, version negotiation, non-invasiveness |
| `test_integration_e2e.py` | Real `.hpy` artifact + real AgentGuard HTTP server, end to end |

`tests/live_stack.py` boots a **real** AgentGuard `IdentityService` + HTTP transport on an ephemeral
port and issues a **real** credential, so the end-to-end tests hit the genuine authentication and
authorization path rather than a mock.

## Contract evolution

**Additive only.** New fields MUST be optional, unknown fields MUST be ignored, and no existing field
may change type or meaning. A breaking change requires a new `CONTRACT_VERSION` plus a matching entry
in `SUPPORTED_CONTRACT_VERSIONS`. Both sides fail **closed** on an unknown version.
