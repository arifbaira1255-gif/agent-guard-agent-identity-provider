# Step 11 — Enterprise Tool & Resource Governance: Implementation Plan

**Repository:** AgentGuard (`agentguard_v6`, built on the verified `agentguard_v5` Step 10 tree)
**Scope:** Step 11 only. Steps 1–10 reused, not rebuilt. Step 12 boundary prepared.
**Inspection first:** the plan below was written AFTER reading the actual Step 10 code
(`policy/{models,service,enforcer,jit,cache,engine,approval,audit}.py`, `storage/postgres/policy.py`,
migration `0005`, `api/http_transport.py`, `api/enterprise_http.py`, `security/rbac.py`,
`agentguard_sdk/*`), not from the report alone.

---

## 1. What exists and must be reused (verified by inspection)

| Existing component | Verified behaviour | How Step 11 reuses it |
|---|---|---|
| `PolicyDecisionService.authorize(agent_id, tenant, action, resource, ..., request_context, resource_tenant, ...)` | Assembles `PolicyInput` server-side; four outcomes; default-deny `no_matching_policy`; caches ALLOW only | The governance guard calls it as the policy leg of every decision, and pushes resource/operation/registry data through the **existing `request_context` seam** |
| `DecisionKind` / `PolicyDecision` | `allowed` is `True` only for ALLOW; INDETERMINATE never allows | Reused as the governance outcome vocabulary (no parallel decision type) |
| `PolicyEnforcer.enforce/authorize_and_run` | Runs the executor only on ALLOW | Governance builds on the same anti-bypass pattern at the resource boundary |
| `JitGrantService` | Exact-scope, mandatory expiry, revocable, forbidden self-escalating actions | JIT grants remain the time-boxed path for a not-permanently-entitled agent; the guard honours them via the policy service |
| `RiskSignalProvider` | Neutral stub (Step 10 left it for Step 11) | Governance *feeds* resource sensitivity/type/registry state into the risk input rather than replacing the provider |
| `ApprovalProvider.check` | Minimal, fail-closed | A `REQUIRE_APPROVAL` governance outcome is satisfied only by a valid approval |
| `PolicyStore` / `PgPolicyStore` + migration 0005 | RLS via `app.current_org`, `ag_guard_status` trigger applied ONLY to `policies` | New tables go in a **new** migration 0006; policy tables/engine untouched |
| `security/rbac.py` | Closed `PERMISSIONS` set + `ROLE_PERMISSIONS` matrix + `Authorizer` | Adds governance permissions to the existing closed set/matrix |
| `observability/logging.py` `SecurityLogger` | Allow-listed + secret-redacted | Governance audit fans out to it via a `GovernanceAudit` recorder |
| `api/http_transport.py` `set_policy_hook` + `/v1/authorize` | Credential verified, then hook; fails closed | Tool governance admits resource descriptors on the same verified path |
| `agentguard_sdk` `AuthorizationClient` / `ToolGuard` | Explicitly documented as "SDK-side, not an enforcement boundary" | SDK gains a governance client, but **server-side** remains authoritative |

**No duplicate policy engine, decision type or data model is introduced.**

## 2. Smallest compatible integration points

1. `request_context` (existing `PolicyInput` field) — carry `resource_type`, `sensitivity`, `operation`,
   `registry_status`, `tool_id`, `approved_capabilities`, `requested_capabilities`.
2. `resource_tenant` (existing) — enforce tenant boundary for the *resource* owner.
3. `set_policy_hook` (existing) — extend the authorize body to accept a resource descriptor.
4. `Authorizer.require` + `PERMISSIONS` (existing) — governance administration permissions.
5. New migration 0006 + new PG repos — additive; no change to policy tables.

## 3. Design — the governance layer

```
                 ┌──────────────────────────── ResourceGuard (single chokepoint) ─────────────────────┐
 agent request → │ 1 validate → 2 resolve ResourceDescriptor (registry) → 3 tenant + operation check   │
                 │ → 4 tool-registry check (approved capabilities only) → 5 policy decision (Steps 10) │
                 │ → 6 escalate to REQUIRE_APPROVAL for restricted/approval ops (never downgrade)      │
                 │ → 7 audit → 8 mint sealed decision │                                                │
                 └─────────────────────────────────────────────────────────────────────────────────────┘
                                   ↓ ALLOW only            ↓ anything else
                            connector executor      ForbiddenError (executor never runs)
```

* **`ResourceType`** — `tool, tool_server, http_api, database, filesystem, shell, cloud, internal_service, custom`.
* **`Sensitivity`** — `public, internal, confidential, restricted` (drives approval escalation).
* **`ResourceRecord`** — `resource_id, org_id, resource_type, owner, sensitivity, permitted_operations,
  policy_refs, enabled, description, metadata`. Enforced **permitted operations** = least privilege.
* **`ToolRecord`** — `tool_id, org_id, name, version, risk, requested_capabilities,
  approved_capabilities, enabled, approved, resource_id, policy_refs, manifest_checksum`.
  **Manifest-declared capabilities are recorded as *requested* only and never grant anything.**
* **`ResourceGuard`** — validates, classifies, resolves the registry record, checks tenant + operation,
  checks the tool registry, delegates to the Step 10 policy service, escalates where required, audits,
  and mints a **sealed** decision. `enforce()` runs the executor only for a sealed ALLOW; a client
  cannot forge one (the seal is a server-side nonce in a bounded single-use ledger).
* **Unknown / unclassified resources** — explicit: an unregistered resource is DENY (`unknown_resource`);
  an unrecognised *type* is DENY (`unclassified_resource`). Configurable only between
  `deny` and `require_approval` — never `allow`.
* **Connectors** — `ResourceConnector` (type + descriptor + a pure `perform()`), and
  `GuardedConnector` whose only execution path is `guard.authorize_and_run`. `GovernanceService.execute()`
  is the supported entry for adapters. External systems' own permissions are documented as an
  **integration boundary**, not claimed as enforced.
* **Audit** — `GovernanceAudit` writes to the durable `governance_audit` table *and* the existing
  `SecurityLogger` with agent, tenant, resource, operation, decision, policy version, correlation id.
* **Fail closed** — any exception (registry error, policy outage, timeout) yields DENY/INDETERMINATE;
  the executor never runs. Concurrency-safe (the ledger is lock-guarded, and the registry record is
  read authoritatively on every decision — there is no cross-request record cache to go stale).

## 4. Files

**Created:** `src/agent_identity/governance/{__init__,errors,models,config,classifier,registry,
tool_registry,audit,guard,connectors,service,hooks}.py`,
`src/agent_identity/governance/rego/governance.rego`,
`src/agent_identity/storage/postgres/governance.py`,
`src/agent_identity/storage/postgres/migrations/0006_step11_governance.sql`,
`tests/test_governance_unit.py`, `tests/test_governance_pg_integration.py`,
`docs/STEP11_GOVERNANCE.md`, `docs/STEP11_SECURITY_LIMITATIONS.md`, `docs/STEP11_FINAL_REPORT.md`.

**Modified:** `security/rbac.py` (+governance permissions), `api/enterprise_http.py`
(+`/v1/admin/resources`, `/v1/admin/tools` — RBAC-checked), `api/http_transport.py` (accept an optional
resource descriptor on `/v1/authorize`).

**Deliberately NOT modified:** the three non-Python SDKs (TypeScript/Go/Rust) and the Python SDK
surface. Server-side enforcement (`guard.py` / `service.py` / `hooks.py`) is the required chokepoint
and is language-agnostic; a governance *client* for the SDKs is future work, so no SDK connector class
was added. (`agentguard_sdk/adapters/tool_guard.py` was inspected, not changed.)

## 5. Acceptance criteria mapping

| Requirement | Where enforced | Test |
|---|---|---|
| Never authorized merely because the agent requests it | `ResourceGuard` runs before the executor; registry + policy both required | `test_unregistered_resource_denied`, `test_agent_claim_does_not_grant` |
| Authorization at the execution boundary | `GuardedConnector` / `GovernanceService.execute` | `test_connector_bypass_attempt_denied` |
| Operation-level + resource-level | registry `permitted_operations` | `test_operation_not_permitted_denied` |
| Cross-tenant isolation | registry org + `resource_tenant` | `test_cross_tenant_resource_isolation` |
| Expired/revoked JIT | Step 10 JIT via policy leg | `test_expired_jit_grant_denied` |
| Policy change / stale decision | Step 10 cache invalidation | `test_policy_change_invalidates_governance` |
| Unknown/malformed | classifier + explicit config | `test_unknown_resource_denied`, `test_malformed_request_denied` |
| Tool registration + unauthorised change | `ToolRegistry` + RBAC + approval | `test_tool_registration_requires_permission`, `test_manifest_cannot_self_grant` |
| Concurrency + failure | lock-guarded ledger; fail-closed | `test_concurrent_decisions_are_consistent`, `test_registry_failure_fails_closed` |

---

## 6. Integration boundaries — what is NOT universally enforced

Step 11 enforces authorization at the **chokepoint**, not at every possible I/O call. The following
are explicitly out of scope and MUST be mediated in a later step; no universal-enforcement claim is
made for them (full detail in `STEP11_SECURITY_LIMITATIONS.md`):

* **Direct cloud-provider SDK calls** (`boto3` / `google-cloud-*` / `azure-*`) made from agent code —
  governed only if they are routed through a `ResourceConnector`, which this step does not force.
* **Raw outbound HTTP** (sockets, `requests`, `urllib`) that does not pass through
  `HttpApiConnector` — the real egress path with DLP is **Step 12**.
* **Direct database connections** with embedded credentials — the `DatabaseConnector` is a reference
  shape that holds no connection and executes no SQL; the database's own permissions still apply.
* **Raw filesystem I/O and process/shell execution** — `ShellConnector.perform` returns an authorized
  plan and spawns nothing; a sandboxed executor is required.
* **Tool implementations that never consult `GovernanceService`** — an unwrapped tool is simply
  ungoverned; adapters MUST be wrapped by convention and review.
* **External systems' own authority** (DB credentials, cloud IAM, API keys, SaaS ACLs) — granted and
  enforced by that system, not by AgentGuard; governance answers *who may ask*, not *what the target
  permits*.

Implemented in this step: the `ResourceGuard` chokepoint, registries, enforcement interface,
fail-closed decisions, audit, PostgreSQL persistence (migration 0006 + RLS), RBAC, and the transport
hook. Not implemented (deliberate): real transports, egress/DLP filtering, sandboxed executors, a full
approval workflow, and a live risk engine.
