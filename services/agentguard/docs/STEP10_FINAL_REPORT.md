# Step 10 — Final Report: Policy Engine and Just-in-Time Authorization

**Repository:** AgentGuard (`agentguard_v5`, built on `agentguard_v4_step9`)
**Scope:** Step 10 only. Steps 1–9 reused, not rebuilt. Step 11 boundary prepared.
**Date:** 2026-10-11

---

## 1. Existing components reused

| Component | How Step 10 reuses it |
|---|---|
| **Identity / credential verifier** (Steps 1–9) | `POST /v1/authorize` verifies the credential + possession proof first; the verified `agent_id`, `instance_id`, `org_id`, `capabilities` are injected as `_agent_id` / `_instance_id` / `_org_id` / `_capabilities` and become the policy input. A client can never supply them. |
| **SPIFFE/SPIRE** | Untouched. The policy plane consumes the already-verified identity; no new trust material. |
| **PostgreSQL** | Migration `0005_step10_policy.sql` extends the existing schema (same `migrate.migrate()` chain, same `Database.run()` helper, same RLS GUC contract `app.current_org` / `app.platform_admin` as migration 0004). |
| **Redis** | Used only for the transient decision cache + generation counters, through the existing `StateBackend` and `KeyBuilder` (hash-tagged `{env.tenant}`, SHA-256 hashed components). |
| **KMS/HSM** | Untouched. No new key material; policy source is not secret. |
| **mTLS** | Untouched. The policy hook sits behind the existing transport. |
| **RBAC** (Step 8) | Extended the existing matrix with `policy:read` / `policy:write` / `policy:activate`; reused `Authorizer.require`, `EffectiveAccess`, `effective_access`. |
| **SDK** (Step 9) | Reused the `set_policy_hook` extension point that Step 9 explicitly reserved for Step 10. The default deny-by-default capability hook is preserved as the fallback. |
| **Audit / observability** | Reused `SecurityLogger` (allow-listed, secret-redacted) and `current_correlation_id()`; added a durable `policy_audit` table. |
| **Errors / ids / models** | Reused `IdentityError` hierarchy, `new_id()`, `iso()`. |

**No duplicate policy engine or data model was created.**

---

## 2. Files created and modified

### Created (13)
```
src/agent_identity/policy/__init__.py
src/agent_identity/policy/models.py
src/agent_identity/policy/errors.py
src/agent_identity/policy/config.py
src/agent_identity/policy/engine.py
src/agent_identity/policy/store.py
src/agent_identity/policy/memory_store.py
src/agent_identity/policy/jit.py
src/agent_identity/policy/cache.py
src/agent_identity/policy/approval.py
src/agent_identity/policy/audit.py
src/agent_identity/policy/service.py
src/agent_identity/policy/enforcer.py
src/agent_identity/policy/rego/example.rego
src/agent_identity/storage/postgres/policy.py
src/agent_identity/storage/postgres/migrations/0005_step10_policy.sql
tests/test_policy_unit.py
tests/test_policy_pg_integration.py
docs/STEP10_POLICY_ENGINE.md
docs/STEP10_FINAL_REPORT.md
```

### Modified (3)
```
src/agent_identity/security/rbac.py          # +3 permissions, granted to tenant/platform admins; read to all
src/agent_identity/api/enterprise_http.py    # +policy_service param, +_dispatch_policy (policies/JIT/approvals)
src/agent_identity/api/http_transport.py     # (unchanged code; the Step 9 set_policy_hook seam is now used)
```

---

## 3. Policy engine and integrations implemented

* **Clean evaluation interface** — `PolicyEngine` protocol with three backends: `OpaHttpEngine`
  (production, `opa run --server`), `OpaCliEngine` (dev/CI, `opa eval`), `NullEngine` (fail closed).
* **OPA + Rego** — policies are Rego modules; the engine namespaces each version into
  `agentguard.policies.<id>_v<version>` so many policies coexist in one OPA instance. No bespoke
  policy language was invented.
* **Context-rich evaluation** — identity, tenant, action, resource, capabilities, credential status,
  environment, request context, risk signals, live JIT grants, approval state, policy version,
  resource tenant, and agent lineage are all supplied.
* **Explicit decisions** — `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `INDETERMINATE`. `allowed` is `True`
  only for `ALLOW`; `INDETERMINATE` is never an allow.
* **Lifecycle** — create / validate / test / activate / rollback / disable / delete, with ownership,
  RBAC administration permissions, versioning, and change auditing.
* **Persistence** — PostgreSQL (`policies`, `policy_versions`, `jit_grants`, `approvals`,
  `policy_audit`) under RLS; Redis only for the transient decision cache.
* **Diagnostics without secrets** — decisions expose reason codes, policy id/version, decision id,
  latency and cache flag; no policy source or secret is returned to callers.

---

## 4. JIT authorization behaviour

* A grant names exactly one `(org_id, agent_id, action, resource)` tuple plus `instance_id`,
  `issued_at`, `expires_at`, `policy_version`, `grant_id`, `status`, `issued_by`, `reason`.
* **Explicit expiration** — mandatory; TTL bounded by `jit_max_ttl_s` (default 1 h, hard cap 24 h).
  No API path to a permanent grant.
* **Least privilege** — exact matching only; wildcards rejected; administrative/self-escalating
  actions (`policy:activate`, `role:assign`, `jit:grant`, `approval:decide`, …) can never be granted.
* **Revocation** — immediate and terminal; `revoke_all_for_agent` cuts off every live grant.
* **Effect** — a live grant satisfies a default-deny (`no_matching_policy`) but can never override an
  explicit policy `DENY`.

---

## 5. Enforcement points

| Point | Mechanism | Guarantee |
|---|---|---|
| `POST /v1/authorize` (SDK) | `set_policy_hook(make_policy_hook(service))` | The credential is verified first; the policy decision is returned as `allowed`/`decision`. Fails closed on any error. |
| Any protected callable | `PolicyEnforcer.enforce` / `authorize_and_run` | The executor runs **only** on an explicit `ALLOW`; a `DENY`/`REQUIRE_APPROVAL`/`INDETERMINATE` raises `ForbiddenError` and the callable is never invoked. |
| Policy administration | `_dispatch_policy` → `PolicyDecisionService` | Every lifecycle call is RBAC-checked (`policy:read`/`write`/`activate`); platform-wide policies require `platform:admin`. |

**Anti-bypass:** the decision is assembled server-side from verified state; a client cannot forge
`_agent_id`/`_org_id`/`_capabilities` (the transport overwrites them after verification), and the
enforcer refuses any non-`ALLOW` decision object. Verified by grep + tests
(`EnforcerTests`, `SdkIntegrationTests`).

---

## 6. Security tests and regression results

**Command:**
```bash
PYTHONPATH=src:. AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres \
AGENTGUARD_TEST_PG_PASSWORD=postgres AGENTGUARD_TEST_REDIS_HOST=127.0.0.1 \
python3 -m unittest tests.test_policy_unit tests.test_policy_pg_integration \
  tests.test_identity tests.test_kms tests.test_pg_unit tests.test_sdk_unit \
  tests.test_sdk_conformance tests.test_http_and_adapters tests.test_state_unit \
  tests.test_security_unit tests.test_step7_ha tests.test_pg_integration \
  tests.test_security_pg tests.test_state_integration tests.test_sdk_integration \
  tests.test_spiffe_core tests.test_spiffe_bundlekeys tests.test_spiffe_provider tests.test_mtls
```

**Result (actual):**
```
Ran 661 tests in 69.854s
OK (skipped=3)
```
The 3 skips are the SPIRE-agent-dependent integration tests (`test_spire_integration`,
`test_mtls_spire_integration`) which require a live SPIRE agent socket — not started, and not
required for Step 10.

**Step 10 test coverage (48 new tests, all passing):**

| Requirement | Test(s) |
|---|---|
| Policy decisions (4 outcomes) | `test_allow_decision`, `test_require_approval`, `test_indeterminate_is_never_allow`, `test_default_deny_when_no_policy` |
| Allow/deny boundaries | `test_deny_boundary_wrong_resource`, `test_deny_boundary_wrong_action` |
| Policy versioning | `test_version_immutability`, `test_activate_and_rollback`, `test_version_immutability_pg` |
| JIT expiration | `test_jit_expiration`, `test_jit_grant_expiry_and_revocation` |
| Revocation | `test_jit_revocation`, `test_no_stale_allow_after_jit_revocation` |
| Concurrent authorization | `test_concurrent_authorization` (24 threads) |
| Cache invalidation | `test_no_stale_allow_after_policy_change`, `test_allow_is_cached`, `test_cache_scoped_by_tenant` |
| Cross-tenant isolation | `test_cross_tenant_policy_isolation`, `test_jit_cross_tenant_isolation`, `test_cross_tenant_isolation` (PG) |
| Policy-engine failure | `test_engine_outage_fails_closed`, `test_null_engine_fails_closed`, `test_http_engine_outage_fails_closed` |
| Approval-required | `test_approval_gates_execution`, `test_denied_approval_does_not_allow` |
| SDK integration | `test_hook_allows_via_policy`, `test_transport_authorize_uses_hook`, `test_transport_fails_closed_on_invalid_credential` |
| Anti-bypass enforcement | `test_enforcer_blocks_non_allow`, `test_enforcer_rejects_indeterminate` |
| Policy validation | `test_validate_rejects_bad_policy` |
| Administration permissions | `test_policy_admin_requires_permission`, `test_platform_policy_requires_platform_admin` |
| Audit append-only | `test_audit_append_only` (DB trigger rejects UPDATE) |
| Regression | all 613 pre-existing tests still pass |

---

## 7. Performance results

Measured on this sandbox (single node, Python 3.11, OPA v0.68.0, PostgreSQL 15, Redis 7). These are
**observed** numbers, not guarantees; production figures depend on hardware, policy complexity and
deployment topology.

| Scenario | n | p50 | p95 | mean |
|---|---|---|---|---|
| OPA **HTTP** engine, uncached | 500 | **1.05 ms** | 1.63 ms | 1.84 ms |
| OPA **CLI** engine, uncached | 200 | 19.9 ms | 73.5 ms | 26.8 ms |
| Decision cache hit | 200 | **0.010 ms** | 0.016 ms | — |

| Scenario | Throughput |
|---|---|
| Cached decisions, 8 threads × 100 | **~91,600 req/s** (HTTP engine config) |
| Cached decisions, 8 threads × 50 | ~59,300 req/s (CLI engine config) |

**Cache hit/miss:** only `ALLOW` decisions are cached; a hit returns in ~0.01 ms, a miss re-evaluates
through OPA. **Policy update propagation:** activation/rollback/disable/delete bump the tenant
generation, so the next request re-evaluates immediately (no stale allow). **Engine outage:** every
evaluation returns `INDETERMINATE` within the bounded timeout (250 ms default) and denies.

The CLI engine is ~20× slower than HTTP because it spawns a process per evaluation — it is intended
for development/CI, not production. No zero-latency or unlimited-scale claims are made.

---

## 8. Remaining limitations

1. **Risk signals are a neutral stub.** `NeutralRiskProvider` reports "no signal available". The
   real risk engine is Step 11+. The interface is stable and tested with `StaticRiskProvider`.
2. **Approvals are minimal.** `StoreApprovalProvider` supports request/decide/check with bounded
   expiry — enough to gate execution safely. Routing, quorum, notifications and escalation are
   Step 17.
3. **OPA is the isolation boundary.** `validate_rego` rejects dangerous builtins and oversized
   source, but it is a guard, not a sandbox. OPA must run with a timeout (enforced) and, in
   production, as a separate process/sidecar with its own resource limits.
4. **CLI engine is not for production.** It spawns a process per evaluation; use the HTTP engine.
5. **No policy bundle distribution.** Policies are pushed to OPA per evaluation (HTTP) or written to
   a temp dir (CLI). A signed-bundle distribution mechanism is not implemented.
6. **Cache is per-tenant generation-based.** Invalidation is logical (generation bump), not a key
   scan; entries expire by TTL. This is correct but means a burst of invalidations leaves dead keys
   until TTL.
7. **SPIRE-agent integration tests were not run** (no live SPIRE agent in this sandbox); they are
   unrelated to Step 10 and were skipped, not failed.
8. **No load test at scale.** Throughput was measured with 8 threads on one node; no multi-node or
   sustained-load benchmark was performed.

---

## 9. Integration boundary for Step 11 — Tool and Resource Governance

Step 10 stops at the decision plane. Step 11 should build on these seams **without modifying the
policy tables or engine**:

| Seam | Contract |
|---|---|
| `PolicyEnforcer.authorize_and_run(...)` | Wrap each governed tool/resource operation. Guarantees the check precedes execution. |
| `RiskSignalProvider.signal_for(org_id, agent_id, action, resource, context) -> RiskSignal` | Replace `NeutralRiskProvider` with the real risk engine. |
| `ApprovalProvider.check(...) -> ApprovalRequest \| None` | Replace `StoreApprovalProvider` with the Step 17 workflow. |
| `PolicyInput.request_context` | Carry tool name, resource class and data-sensitivity tags into policy. |
| `JitGrantService.issue(...)` | Issue grants from tool-governance flows (exact scope, bounded TTL, revocable). |
| `PolicyStore` | Add tool/resource registry tables in a **new** migration; do not extend the policy tables. |
| `install_policy_engine(service)` | The single startup call that wires the decision path. |

---

## 10. Honest status

* **Implemented and verified:** policy engine (OPA/Rego, HTTP + CLI), four-outcome decisions,
  lifecycle with versioning/rollback/audit, JIT grants with expiry/revocation/least-privilege,
  decision cache with invalidation, enforcement at the SDK and in-process chokepoints, RBAC
  administration permissions, PostgreSQL persistence with RLS, append-only audit.
* **Implemented as interfaces only (by design):** risk signals, human approvals.
* **Not implemented (out of scope):** policy bundle distribution, the full Step 17 approval
  workflow, the Step 11 tool/resource registry.
* **Test evidence:** 661 tests pass, 3 skipped (SPIRE-agent-dependent). No test was skipped or
  ignored to make the suite pass.
