# AgentGuard SDK API Reference

Version `0.1.0`. The public surface is intentionally identical across languages so an agent can be
ported between Python, TypeScript/JavaScript, Go and Rust without re-learning the model.

## Naming map

| Concept | Python | TypeScript/JS | Go | Rust |
|---|---|---|---|---|
| Config | `SdkConfig` | `SdkConfig` | `Config` | `Config` |
| Client | `AgentGuardClient` | `AgentGuardClient` | `Client` | `Client` |
| Credential | `Credential` | `Credential` | `Credential` | `Credential` |
| Decision | `Decision` | `Decision` | `Decision` | `Decision` |
| PDP | `PolicyDecisionPoint` | `PolicyDecisionPoint` | `PolicyDecisionPoint` | `PolicyDecisionPoint` |

## Configuration

```python
SdkConfig(
    base_url="https://agentguard.internal",   # required, absolute http(s)
    environment="production",                 # development|staging|production
    timeout_seconds=10.0,                     # per-request bound
    max_retries=3,                            # bounded, exponential backoff + jitter
    verify_tls=True,                          # false is refused outside development
    control_plane_token=...,                  # provisioning token, env-provided
)
```

Fail-closed rules (all languages): plaintext `http://` is refused in production; disabled TLS
verification is refused outside development; timeouts and retry counts are bounded.

## Client

| Method | Purpose |
|---|---|
| `register_agent(...)` | Register an agent and associate identity |
| `create_instance(...)` | Create a runtime instance |
| `issue_credential()` | Acquire a short-lived Agent Passport (key + possession proof) |
| `ensure_credential()` | Acquire or renew as needed (proactive, skew-aware) |
| `renew_credential()` | Rotate the credential |
| `credential_status(id)` | Authoritative status (active/revoked/expired) |
| `verify_credential(token, proof)` | Ask the control plane to verify |
| `revoke_credential(id, reason)` | Revoke |
| `authorize(action, resource, context)` | Request a decision (never raises on DENY) |
| `require(action, resource, context)` | `authorize` but raises on DENY |
| `enforce(decision, executor)` | Run `executor` ONLY on ALLOW |
| `report_event(type, ...)` | Buffer a security event |
| `flush_events()` | Send buffered events |

## Authorization & the PDP

`authorize` returns a `Decision { allowed, reason, decision_id, policy, correlation_id }`. The
`PolicyDecisionPoint` is pluggable:

- `RemotePDP` (default) \u2014 calls `POST /v1/authorize` on the control plane.
- `DenyAllPDP` \u2014 denies everything (the safe no-policy-engine default).
- `StaticPDP` \u2014 deterministic allow/deny for tests and local dev only.

**Fail-closed invariant:** a transport failure, a missing endpoint (404/501), or a PDP exception all
yield a DENY with reason `policy_unavailable` / `policy_error`. The SDK never falls back to "allow".

## Errors

Every error carries a stable `code` (e.g. `credential_expired`, `credential_revoked`, `forbidden`,
`policy_unavailable`, `transport_error`, `timeout`, `cancelled`) and an optional `correlation_id`.
Errors never carry credentials, tokens or private keys \u2014 only ids, codes and short messages.

## Security events

`report_event(event_type, outcome=..., correlation_id=..., action=..., resource=..., metadata=...)`
reports through the existing AgentGuard security logger. Metadata is allow-listed (a closed set of
non-secret keys) and any value that looks like bearer material is redacted before it leaves the
process.

## Versioning & compatibility

- SemVer `0.1.0`. The wire protocol (paths, JSON shape, canonical JSON + Ed25519 proof format) is
  the compatibility contract.
- Cross-language byte compatibility is verified by `sdks/conformance/vectors.json` (reproduced by
  both the Python and Node test suites).
- The SDK's `default_policy_hook` is a deny-by-default **capability placeholder**, not a policy
  language. It is replaced by the Step 10 policy engine via `set_policy_hook` on the control plane;
  the SDK surface (`authorize`/`require`/`enforce`) is unchanged.
