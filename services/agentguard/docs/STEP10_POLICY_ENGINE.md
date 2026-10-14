# Step 10 — Policy Engine and Just-in-Time Authorization

This document describes the AgentGuard policy decision and enforcement plane added in Step 10. It is
**additive**: Steps 1–9 (identity, SPIFFE/SPIRE, PostgreSQL, Redis, KMS/HSM, mTLS, RBAC, SDK) are
reused unchanged, and no existing data model or engine was duplicated.

---

## 1. Architecture

```
                       ┌──────────────────────────────────────────────────────────┐
   verified credential │  POST /v1/authorize  (SDK)   /v1/admin/policies/* (admin) │
   (Steps 1–9)         └───────────────┬──────────────────────────┬───────────────┘
                                       │                          │
                        set_policy_hook│                          │ RBAC (policy:read/write/activate)
                                       ▼                          ▼
                        ┌──────────────────────────────────────────────────────┐
                        │            PolicyDecisionService                     │
                        │  authorize()  ·  lifecycle (create/validate/test/    │
                        │  activate/rollback/disable/delete)                   │
                        └───┬───────────┬───────────┬───────────┬──────────────┘
                            │           │           │           │
              ┌─────────────▼──┐  ┌─────▼─────┐ ┌───▼──────┐ ┌──▼─────────────┐
              │ PolicyEngine   │  │ JitGrant  │ │ Decision │ │ Approval /     │
              │ (OPA + Rego)   │  │ Service   │ │ Cache    │ │ Risk providers │
              │ HTTP | CLI     │  │           │ │ (Redis)  │ │ (interfaces)   │
              └───────┬────────┘  └─────┬─────┘ └───┬──────┘ └──┬─────────────┘
                      │                 │           │           │
              ┌───────▼─────────────────▼───────────▼───────────▼──────────────┐
              │  PolicyStore  (PostgreSQL, migration 0005, RLS)  +  PolicyAudit │
              └──────────────────────────────────────────────────────────────────┘
```

**One decision path.** Every protected operation funnels through `PolicyDecisionService.authorize`.
The HTTP transport's `POST /v1/authorize` calls it via the `set_policy_hook` extension point that
Step 9 already defined; the `PolicyEnforcer` is the in-process chokepoint for any other protected
callable. There is no second policy engine and no second data model.

### Components

| Module | Responsibility |
|---|---|
| `policy/models.py` | Immutable domain models: `DecisionKind`, `PolicyDecision`, `PolicyRecord`, `PolicyVersion`, `JitGrant`, `ApprovalRequest`, `RiskSignal`, `PolicyInput`. |
| `policy/engine.py` | `PolicyEngine` contract + `OpaHttpEngine` (production), `OpaCliEngine` (dev/CI), `NullEngine` (fail closed). Rego validation, namespacing, bounded resources. |
| `policy/service.py` | `PolicyDecisionService` — decision + lifecycle; `make_policy_hook` for the transport. |
| `policy/jit.py` | `JitGrantService` — issue / find-live / revoke, with explicit expiry and least privilege. |
| `policy/cache.py` | `DecisionCache` — Redis-backed, tenant/identity/version-scoped, TTL-bounded, invalidatable. |
| `policy/approval.py` | `RiskSignalProvider` + `ApprovalProvider` interfaces and minimal fail-closed implementations. |
| `policy/store.py` / `policy/memory_store.py` / `storage/postgres/policy.py` | `PolicyStore` interface + in-memory and PostgreSQL backends. |
| `policy/audit.py` | `PolicyAudit` — durable append-only log + the existing structured security logger. |
| `policy/enforcer.py` | `PolicyEnforcer` (anti-bypass gate) + `install_policy_engine`. |
| `policy/rego/example.rego` | A complete, working example policy. |

---

## 2. Supported policy inputs

The engine receives a single JSON document assembled **server-side from verified state**. A client
can never supply these fields directly — the transport injects `_agent_id`, `_instance_id`,
`_org_id` and `_capabilities` only after the credential and possession proof verify.

| Input | Source |
|---|---|
| `agent_id`, `instance_id` | verified credential (Steps 1–9) |
| `tenant` | verified credential / session tenant scope |
| `action`, `resource` | the request |
| `capabilities[]` | verified credential |
| `credential_status` | credential verifier (`valid` / revoked / expired) |
| `environment` | request context |
| `request_context` | non-secret request metadata |
| `risk{level,score,reasons}` | `RiskSignalProvider` (Step 11+ supplies a real one) |
| `jit_grants[]` | live JIT grants for this agent (from the store) |
| `approval{valid,...}` | `ApprovalProvider` |
| `policy_version` | the active version being evaluated |
| `resource_tenant` | the tenant that owns the target resource |
| `denied_actions[]`, `approval_required_actions[]` | policy configuration |
| `is_sub_agent`, `parent_agent_id` | agent lineage (Steps 1–9) |

---

## 3. Policy lifecycle

```
create ──► draft version ──► validate ──► test (cases) ──► activate ──► active
                                                              │
                                              rollback ◄──────┘ (to a retired version)
                                                              │
                                                          disable / delete
```

* **Creation** — `POST /v1/admin/policies` (requires `policy:write`). A platform-wide policy
  (`org_id = null`) additionally requires a platform administrator.
* **Validation** — `POST /v1/admin/policies/{id}/validate`. Rejects empty/oversized source, a
  missing or duplicate package, a package other than `agentguard.authz`, a missing `decision` rule,
  and a denylist of dangerous builtins (`http.send`, `net.lookup_ip_addr`, `opa.runtime`, `trace`,
  `print`). Comments are stripped first, so prose cannot fool the checks.
* **Testing** — `POST /v1/admin/policies/{id}/test` with `cases: [{input, expect}]`. Runs the
  version through the real engine **before** activation and stores the summary on the version.
* **Activation** — `POST /v1/admin/policies/{id}/activate` (requires `policy:activate`). Retires the
  previous active version, marks the new one active, and **invalidates the decision cache** for the
  affected scope.
* **Rollback** — `POST /v1/admin/policies/{id}/rollback` to a previously active (retired) version.
* **Ownership & permissions** — every policy records `owner_user_id`; administration is gated by
  `policy:read` / `policy:write` / `policy:activate` (added to the Step 8 RBAC matrix; tenant admins
  and platform admins hold them, developers and auditors get read-only).
* **Change auditing** — every lifecycle action is written to `policy_audit` (append-only, enforced
  by a database trigger) and to the existing structured security logger.

**Persistence.** Authoritative definitions live in PostgreSQL (`policies`, `policy_versions`,
migration `0005_step10_policy.sql`) under Row-Level Security keyed on the same `app.current_org` /
`app.platform_admin` GUCs as migration 0004. Redis is used **only** for the transient decision cache
and its generation counters.

---

## 4. JIT grant lifecycle

```
issue (bounded TTL) ──► active ──► (expires_at passes) ──► expired
                          │
                          └──► revoke ──► revoked (terminal)
```

A grant defines exactly: `grant_id`, `org_id`, `agent_id`, `instance_id`, `action`, `resource`,
`issued_at`, `expires_at`, `policy_version`, `status`, `issued_by`, `reason`, `context`.

* **Explicit expiration** — `expires_at` is mandatory; the TTL is bounded by `jit_max_ttl_s`
  (default 1 h, hard cap 24 h). There is no API path to a permanent grant.
* **Least privilege** — matching is exact on `(org_id, agent_id, action, resource)`; wildcards are
  rejected at issuance, and administrative/self-escalating actions (`policy:activate`, `role:assign`,
  `jit:grant`, …) can never be granted through JIT.
* **Revocation** — `revoke` flips the grant to `revoked` immediately; `revoke_all_for_agent` cuts off
  every live grant for an agent. A revoked grant can never be re-activated.
* **Effect on decisions** — a live grant satisfies a **default-deny** (`no_matching_policy`) but can
  never override an explicit policy `DENY`.

---

## 5. Default-deny behaviour

* If a policy engine is configured and **no active policy applies**, the decision is `DENY`
  (`no_matching_policy`).
* If the engine is unreachable, times out, is overloaded, or returns an unparseable/undefined
  result, the decision is `INDETERMINATE` — which is **never** an allow.
* `PolicyDecision.allowed` is `True` **only** for `ALLOW`. `REQUIRE_APPROVAL` and `INDETERMINATE`
  both block execution.
* When no policy engine is configured (`engine = "none"`), the authorization surface keeps the
  Step 9 deny-by-default capability check — nothing silently becomes more permissive.

---

## 6. Administration permissions

| Permission | Grants |
|---|---|
| `policy:read` | list/read policies and versions, run validation and tests |
| `policy:write` | create policies and versions, delete policies |
| `policy:activate` | activate, roll back, disable a policy version |

Platform-wide policies (`org_id = null`) additionally require `platform:admin`. Tenant-scoped
policies require the caller's verified tenant to match.

---

## 7. Cache invalidation

* Only `ALLOW` decisions are cached; a `DENY`/`REQUIRE_APPROVAL`/`INDETERMINATE` is always
  re-evaluated.
* Keys embed tenant + agent + action + resource + active policy version, built through the existing
  `KeyBuilder` (hash-tagged by `{env.tenant}`, SHA-256 hashed components).
* Every entry has a bounded TTL (`cache_ttl_ms`, capped by `cache_max_ttl_ms`).
* **No stale allow survives a change**: policy activation/rollback/disable/delete, JIT
  issue/revoke, and approval decisions bump a per-tenant generation counter, logically killing all
  prior entries before their TTL expires.
* A cache read/write failure is treated as a miss — the engine is still consulted. A cache is never
  a reason to allow.

---

## 8. Operational failure modes

| Failure | Behaviour |
|---|---|
| OPA unreachable / times out | `INDETERMINATE` → deny (fail closed); audited as `policy.engine.unavailable` |
| OPA overloaded (concurrency gate full) | `INDETERMINATE` → deny |
| Malformed policy result | `INDETERMINATE` → deny |
| Redis down | cache treated as a miss; decisions still evaluated authoritatively |
| PostgreSQL down | policy administration and JIT issuance fail; decisions cannot be evaluated → deny |
| Approval provider absent | `REQUIRE_APPROVAL` stays blocking (never auto-allowed) |

Bounded resources: `eval_timeout_ms` (default 250 ms), `max_input_bytes` (64 KiB),
`max_policy_bytes` (256 KiB), `max_concurrent_evals` (32). There are no unbounded waits.

---

## 9. Example policy

See `src/agent_identity/policy/rego/example.rego`. It demonstrates the full contract with a single
`else` chain (a complete rule must produce exactly one output):

```rego
package agentguard.authz

decision := {"decision": "DENY", "reason": "explicitly_denied"} {
    some i
    input.denied_actions[i] == input.action
} else := {"decision": "DENY", "reason": "tenant_boundary_violation"} {
    input.resource_tenant != ""
    input.resource_tenant != input.tenant
} else := {"decision": "REQUIRE_APPROVAL", "reason": "high_risk"} {
    input.risk.level == "high"
    not input.approval.valid
} else := {"decision": "ALLOW", "reason": "capability_match"} {
    some i
    input.capabilities[i] == input.action
} else := {"decision": "DENY", "reason": "default_deny"}
```

---

## 10. Testing and deployment

### Running the tests

```bash
# Unit + integration (real OPA binary required)
PYTHONPATH=src:. python -m unittest tests.test_policy_unit

# PostgreSQL-backed store + full decision path (real PostgreSQL required)
AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres \
AGENTGUARD_TEST_PG_PASSWORD=postgres PYTHONPATH=src:. \
  python -m unittest tests.test_policy_pg_integration

# OPA-server (HTTP engine) tests
AGENTGUARD_TEST_OPA_URL=http://127.0.0.1:8181 PYTHONPATH=src:. \
  python -m unittest tests.test_policy_unit
```

### Deployment

1. Apply migration `0005_step10_policy.sql` (the existing `migrate.migrate(db)` runs it).
2. Run OPA as a sidecar: `opa run --server --addr 127.0.0.1:8181` (production) or use the CLI engine
   for single-node/dev.
3. Configure via environment:
   ```
   AGENTGUARD_POLICY_ENGINE=opa
   AGENTGUARD_OPA_MODE=http
   AGENTGUARD_OPA_URL=http://127.0.0.1:8181
   AGENTGUARD_POLICY_EVAL_TIMEOUT_MS=250
   AGENTGUARD_POLICY_CACHE_TTL_MS=5000
   AGENTGUARD_JIT_MAX_TTL_S=3600
   ```
4. Install the hook at startup: `install_policy_engine(policy_service)`.
5. Create and activate a policy through `/v1/admin/policies`.

---

## 11. Integration boundary for Step 11 (Tool and Resource Governance)

Step 10 deliberately stops at the decision plane. Step 11 should build on these seams:

* **`PolicyEnforcer`** — wrap each governed tool/resource operation with
  `authorize_and_run(...)`. The enforcer already guarantees the check precedes execution and that a
  non-`ALLOW` decision never runs the callable.
* **`RiskSignalProvider`** — replace `NeutralRiskProvider` with the real risk engine. The interface
  (`signal_for(org_id, agent_id, action, resource, context) -> RiskSignal`) is stable.
* **`ApprovalProvider`** — replace `StoreApprovalProvider` with the full Step 17 workflow. The
  `check(...)` contract (return a valid approval or `None`) is what the decision path depends on.
* **`PolicyInput.request_context`** — carry tool/resource metadata (tool name, resource class,
  data-sensitivity tags) into policy without changing the engine.
* **`JitGrantService`** — issue grants from tool-governance flows; the exact-scope, bounded-TTL,
  revocable semantics are already enforced.
* **`PolicyStore`** — add tool/resource registry tables in a new migration; do not extend the
  policy tables.
