# Step 11 — Enterprise Tool & Resource Governance · FINAL REPORT

**Repository:** AgentGuard `agentguard_v6` (built on the verified `agentguard_v5` Step 10 tree)
**Scope delivered:** Step 11 only. Steps 1–10 reused, not rebuilt. Step 12 is *not* implemented.
**Evidence:** every number below was executed in this run against **real OPA 0.68.0, real
PostgreSQL 15.19 and real Redis 7**. Nothing here is projected or fabricated.

---

## 1. Existing components reused (inspected before coding)

| Reused | How |
|---|---|
| `PolicyDecisionService.authorize(...)` (Step 10) | the policy leg of every governance decision |
| `DecisionKind` / `PolicyDecision` | the decision vocabulary (no parallel decision type) |
| `JitGrantService` (Step 10) | time-boxed path for a not-permanently-entitled agent |
| `RiskSignalProvider` / `NeutralRiskProvider` | risk input (fed resource/tool context) |
| `ApprovalProvider` (`StoreApprovalProvider`) | satisfies a `REQUIRE_APPROVAL` outcome |
| `PolicyStore` / `PgPolicyStore` + migration 0005 | policy persistence — **untouched** |
| `security/rbac.py` (`PERMISSIONS`, role matrix, `Authorizer`) | governance permissions added to the closed set |
| `observability/logging.py` (`SecurityLogger`) | governance audit fan-out, same correlation IDs |
| `storage/postgres` (`Database`, `migrate`, RLS GUC contract) | migration 0006 + PG store |
| `api/http_transport.py` `set_policy_hook` / `/v1/authorize` | governance hook seam |
| `PolicyEnforcer` anti-bypass pattern | mirrored at the resource boundary |

**No duplicate policy engine, decision type or data model was introduced.**

## 2. Files created and modified

**Created (18)**
```
src/agent_identity/governance/__init__.py          errors.py        models.py
                              validation.py        config.py        classifier.py
                              store.py             memory_store.py  audit.py
                              registry.py          tool_registry.py guard.py
                              connectors.py        service.py       hooks.py
                              rego/governance.rego
src/agent_identity/storage/postgres/governance.py
src/agent_identity/storage/postgres/migrations/0006_step11_governance.sql
tests/test_governance_unit.py
tests/test_governance_pg_integration.py
benchmarks/bench_step11_governance.py
docs/STEP11_IMPLEMENTATION_PLAN.md  docs/STEP11_GOVERNANCE.md
docs/STEP11_SECURITY_LIMITATIONS.md docs/STEP11_FINAL_REPORT.md
```

**Modified (3)**
* `security/rbac.py` — added `resource:read|write|admin`, `tool:read|write|approve|admin` to the closed
  `PERMISSIONS` set and the role matrix (platform admin = all; tenant admin = all; developer = read +
  register, **no approve/admin**; analyst / readonly auditor = read).
* `api/enterprise_http.py` — optional `governance_service`; `/v1/admin/resources` and `/v1/admin/tools`
  routes (RBAC enforced inside the registries).
* `api/http_transport.py` — documented the optional Step 11 resource descriptor on `/v1/authorize`.
* `docs/STEP11_IMPLEMENTATION_PLAN.md` — acceptance map + integration-boundary section.

**Deliberately NOT modified:** the Python/TypeScript/Go/Rust SDK surfaces (server-side enforcement is
the chokepoint; SDK clients are future work), the Step 10 policy tables/engine, and migrations 0001–0005.

## 3. Policy engine and integrations implemented

* **`ResourceGuard`** — one chokepoint: validate → classify → resolve registry record → tenant boundary
  → operation least privilege → tool-registry checks → Step 10 policy decision → escalation → audit →
  seal. Every step fails closed.
* **Registry context into policy** — `resource_type`, `sensitivity`, `registry_status`,
  `permitted_operations`, `tool_id`, `tool_risk`, `approved_capabilities` are merged into the Step 10
  `PolicyInput.request_context`, so Rego can decide on the resource class, not just the action string.
* **`ResourceRegistry` / `ToolRegistry`** — RBAC-guarded, audited, tenant-scoped; PostgreSQL under RLS.
* **Escalation (tightening only)** — a permitted DESTRUCTIVE operation (`delete|admin|deploy|execute`)
  on a resource classified at/above `escalate_at_or_above` (default `confidential`) becomes
  `REQUIRE_APPROVAL`. Escalation can never turn a DENY/INDETERMINATE into an allow.
* **Example Rego policy** — `rego/governance.rego`, a single complete `else` chain (no
  `eval_conflict_error`), no `http.send`, engine-namespaced per policy version.

## 4. JIT authorization behaviour

A Step 10 JIT grant is exact `(org, agent, action, resource)` with a mandatory bounded expiry and
immediate revocation. Governance consumes it through the policy leg, so it **satisfies a default-deny
but never overrides an explicit DENY**, and it is tenant-scoped. Proven by
`test_jit_grant_satisfies_default_deny_then_revocation_denies` (grant → ALLOW via `jit_grant`;
revoke → DENY), `test_expired_jit_grant_denied` (deterministic clock advance), and
`test_jit_grant_is_tenant_scoped`.

## 5. Enforcement points

| Boundary | Mechanism |
|---|---|
| Server API | `POST /v1/authorize` (+ optional resource descriptor) via `set_policy_hook` |
| Tool adapters / connectors | `GovernanceService.execute` / `GuardedConnector.__call__` → `ResourceGuard.authorize_and_run` |
| Direct run | `ResourceGuard.enforce` accepts **only a sealed ALLOW**; `_SealLedger` is single-use + bounded TTL |
| Registry administration | RBAC checked **before** record load (no existence leak), then tenant boundary |
| Persistence | migration 0006; RLS on `resources`, `tools`, `governance_audit`; append-only audit trigger |
| Cleanliness | no path in the codebase exposes the raw connector (`GuardedConnector` has no `perform`) |

## 6. Security tests and regression results — ACTUAL output

```
$ PYTHONPATH=src:. python3 -m unittest tests.test_governance_unit
Ran 61 tests in 1.154s
OK

$ AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres \
  AGENTGUARD_TEST_PG_PASSWORD=postgres PYTHONPATH=src:. \
  python3 -m unittest tests.test_governance_pg_integration
Ran 9 tests in 0.392s
OK

$ # FULL REGRESSION (existing suite + Step 11)
Ran 731 tests in 68.737s
OK (skipped=1)
```

**70 new Step 11 tests, 0 failures.** 731 = 661 (pre-change baseline) + 61 + 9. The single skip is a
pre-existing SPIRE-agent-dependent test unrelated to Step 11 (no live SPIRE agent in this sandbox) —
skipped, not failed. No regressions were introduced; the shared files (`rbac.py`, `enterprise_http.py`,
`http_transport.py`) were changed and the whole suite re-run green afterwards.

Coverage includes: authorised/unauthorised operations; resource- and operation-level restrictions;
cross-tenant isolation (application check **and** RLS proven with a non-superuser role);
expired/revoked JIT; policy change invalidating a governance allow; unknown/unclassified resources;
malformed requests; tool registration/approval/disable; manifest cannot self-grant; approve cannot
exceed requested capabilities; unauthorised registry changes; concurrent decisions (24 threads) and
single-use seal consumption (16 threads, exactly 1 success); policy-engine outage; registry failure;
audit content and correlation IDs.

## 7. Performance results — MEASURED

| Path | p50 | p95 | p99 | note |
|---|---|---|---|---|
| **OPA HTTP engine** — ALLOW (registry + tool + Rego) | **0.584 ms** | 1.008 ms | 19.78 ms | production engine |
| **OPA HTTP engine** — throughput, 8 threads, ALLOW | — | — | — | **538 decisions/s**, 0 errors |
| OPA CLI engine — ALLOW | 13.40 ms | 75.6 ms | 86.7 ms | dev/CI only (process per eval) |
| DENY unknown resource (both engines) | 0.013 ms | 0.018 ms | 0.026 ms | short-circuit, no Rego eval |
| DENY operation not permitted (both engines) | 0.019 ms | 0.023 ms | 0.026 ms | short-circuit, no Rego eval |

Reproduce: `PYTHONPATH=src:. python -m benchmarks.bench_step11_governance` (and
`AGENTGUARD_BENCH_ENGINE=http AGENTGUARD_TEST_OPA_URL=http://127.0.0.1:8181 …`). These are
container-specific and are **not** a zero-latency or unlimited-scale claim.

**Cache honesty:** the Step 10 decision cache is Redis-backed and is **not wired** in this harness, so
**no cache-hit benefit is claimed**. What is measured is the *uncached* decision cost. Cache safety
(ALLOW-only, policy-version + tenant/identity scoping, generation invalidation on any policy/JIT/
approval change, fail-closed on backend error) is covered by the Step 10 tests. Governance adds no
cross-request cache: the registry record is read authoritatively each decision, so a registry change
applies on the very next request.

## 8. Remaining limitations

* **Not universally enforced** — direct cloud SDKs, raw sockets, direct DB connections, raw filesystem
  I/O and un-wrapped tools bypass the chokepoint. Full list: `STEP11_SECURITY_LIMITATIONS.md`.
* External systems keep their own permissions (DB credentials, cloud IAM, API keys, SaaS ACLs).
* The decision **seal is in-process**, not a signed bearer token (correct against remote forgery;
  in-process code execution is out of scope for any in-process control).
* Risk signals are a **stub**; escalation is rule-based. Full approval workflow is **Step 17**.
* Reference connectors perform **no real I/O** (they return an authorized plan).
* No signed policy bundles or manifest signature verification (checksum only).
* Registry writes are last-writer-wins (row-revision bumped; no optimistic-concurrency precondition).
* Only the Python side was extended; TS/Go/Rust remain at their Step 1–9 conformance level.

## 9. Integration boundary for Step 12 (Egress Gateway & DLP)

Step 12 builds on, without modifying: `ResourceGuard.decide/enforce`,
`GovernanceService.execute`, `GovernanceService.register_connector`, `ResourceConnector.perform` +
`GuardedConnector`, `GovernanceConfig`, and the `governance_audit` table. A DLP-aware egress transport
substitutes for the reference `HttpApiConnector` inside a `GuardedConnector` — the enforcement,
tenancy, capability and audit contracts above then apply unchanged. **No Step 12 code was written.**

## 10. Acceptance criteria

> *No protected operation may be treated as authorized merely because an agent requests it.*

**Met.** A request supplies only an *untrusted descriptor*; authorization requires (a) a tenant-matching
registry record, (b) the operation present in that record's `permitted_operations`, (c) for tools, an
approved + enabled registration with the capabilities inside the **administrator-granted** set, and
(d) a sealed ALLOW from the Step 10 policy engine (or an explicit JIT grant / valid approval). Proven
by `test_agent_claim_does_not_grant_authority`, `test_unknown_resource_denied_by_default`,
`test_ghost_capability_denied`, `test_enforce_requires_sealed_allow`,
`test_denied_decision_never_executes`, `test_guarded_connector_runs_only_on_allow`,
`test_service_execute_is_the_enforced_path`, and `test_service_never_exposes_raw_connector`.
