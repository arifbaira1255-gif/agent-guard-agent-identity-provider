# AgentGuard — Step 7 Final Report
## Distributed High-Availability Identity Service

**Date:** 2026-10-11 · **Scope:** Step 7 only (Steps 1–6 reused unchanged; Step 8 not implemented)

---

## 1. Existing components reused

| Component | Origin | Reused as-is? |
|---|---|---|
| `IdentityService` + API (`api/service.py`) | Steps 1–6 | Yes — extended with idempotency wiring |
| PostgreSQL repositories (`storage/postgres/`) | Steps 1–4 | Yes (orgs, agents, instances, credentials, revocations, trust, keystore) |
| `Database` + bounded retry/pool (`storage/postgres/db.py`) | Steps 1–4 | Yes |
| Redis security-state (`state/`) — replay, versioned cache, rate limits, locks, temp state | Steps 1–4 | Yes |
| KMS/HSM layer (`kms/`) | Step 5 | Yes (untouched) |
| mTLS + SPIFFE/SPIRE (`mtls/`, `spiffe/`) | Step 6 | Yes (untouched) |
| Thread-safe `Metrics` registry (`spiffe/metrics.py`) | Steps 1–6 | Yes — extended with Step 7 metric names |
| Allow-list `SecurityLogger` + correlation IDs | Steps 1–6 | Yes |

Nothing in Steps 1–6 was rebuilt. Step 7 only **composes** these and adds the HA layer.

---

## 2. Files created and modified

### Created
| Path | Purpose |
|---|---|
| `src/agent_identity/ha/__init__.py` | Package exports |
| `src/agent_identity/ha/retry.py` | Bounded exponential backoff + full jitter |
| `src/agent_identity/ha/idempotency.py` | Tenant-scoped, bounded-retention idempotency store (memory + PostgreSQL) |
| `src/agent_identity/ha/coordination.py` | Advisory-lock job runner + periodic scheduler |
| `src/agent_identity/ha/health.py` | Liveness vs readiness aggregator (sanitized) |
| `src/agent_identity/ha/metrics.py` | Step 7 metric-name constants |
| `src/agent_identity/ha/factory.py` | `build_ha()` — composes the HA stack |
| `src/agent_identity/storage/postgres/migrations/0003_step7_idempotency_coordination.sql` | `idempotency_records` + `coordination_jobs` tables, triggers |
| `deploy/kubernetes/identity-service.yaml` | Multi-replica Deployment, probes, PDB, HPA, pool sizing |
| `docs/STEP7_HA.md` | Topology, operation, failure modes, recovery, scaling, SPOFs, troubleshooting |
| `tests/test_step7_ha.py` | 41 tests (unit + real PG + real multi-instance) |
| `scripts/benchmark_step7.py` | Real benchmark harness |

### Modified
| Path | Change |
|---|---|
| `src/agent_identity/api/service.py` | `_idempotent` + `_await_in_progress` helpers; wired into `register_agent` and `issue_credential`; new constructor params (`idempotency`, `instance_id`, `metrics`); credential-op metric counters |
| `src/agent_identity/api/http_transport.py` | `/livez`, `/readyz`, `/metrics`; `Idempotency-Key` header; `serve_forever()` graceful shutdown |
| `src/agent_identity/core/config.py` | `idempotency_ttl_seconds`, `idempotency_stale_seconds` |
| `src/agent_identity/spiffe/metrics.py` | Step 7 metric names added to the shared registry |

---

## 3. Reliability and concurrency improvements

* **Statelessness** — durable authoritative state stays in PostgreSQL, transient distributed state in Redis; local caches are read-through + version-tagged (existing `state/cache.py`), invalidated on write, TTL-bounded.
* **Atomic idempotency reservation** — a single `INSERT … ON CONFLICT DO NOTHING` makes exactly one instance win a given `(scope, operation, key)`; concurrent identical requests **wait briefly** and receive the winner's result (a retry on another replica returns the same credential) instead of failing.
* **No credential leakage** — stored responses are Fernet-encrypted at rest and only returned to the same actor + same request digest; a different actor/body for a matching key is a hard `ConflictError` (verified by `test_different_actor_is_conflict_never_leaks`).
* **Bounded retention + crash recovery** — records carry `expires_at` (purged by a job); an `in_progress` reservation whose owner died is taken over by exactly one instance (`takeover_stale`).
* **Coordination without unnecessary locks** — scheduled jobs use a PostgreSQL **session advisory lock** (auto-released on instance death); request handling uses **no** locks. A replica that can't take the lock skips the job.
* **Fail-closed failure recovery** — PG outage → `StorageUnavailableError` + deny (no fallback store); Redis outage → replay checks raise, caches bypass to PG; retries are bounded and only for idempotent operations; non-idempotent ops pass `retry_on=()`.
* **Safe rotation/revocation under concurrency** — reused existing DB constraints/conditional writes (`earliest-effective-wins` revocations, immutable columns, terminal states).

---

## 4. Deployment changes

`deploy/kubernetes/identity-service.yaml` (new reference manifest):

* **3 replicas** (HPA 3–12 on CPU), `RollingUpdate` with `maxUnavailable: 0` + `maxSurge: 1` (never below desired count during rollout).
* **Liveness** (`/livez`, process-only) vs **readiness** (`/readyz`, DB + schema + Redis + SPIFFE/KMS/trust where configured) vs **startup** probe.
* **Graceful shutdown** — `terminationGracePeriodSeconds: 30`, `preStop` drain hook, server drains in-flight requests then closes the pool/Redis.
* **Resources** — requests `250m/256Mi`, limits `1/512Mi`; non-root, read-only root FS, drop all caps.
* **Connection-pool sizing guidance** — `pool_min=2`, `pool_max=10` with a documented rule: `replicas × pool_max` must stay below the DB's `max_connections`.
* **PodDisruptionBudget** — `minAvailable: 2`.

---

## 5. Test results

Full regression (real PostgreSQL 15 + Redis 7, in-sandbox): **485 tests run, 12 skipped, 0 errors, 4 failures — all 4 pre-existing in the untouched baseline** (verified against `extracted/agentguard-agent-identity`).

| Suite | Result |
|---|---|
| Unit + integration (full `discover`) | 485 ran · 4 failures (pre-existing) · 12 skipped |
| `tests/test_step7_ha.py` | **41/41 pass** (with real PG + Redis) |
| Real Redis integration (`test_state_integration`) | 26/26 pass |
| Real PG concurrency tests | pass (unchanged from baseline) |

The 4 pre-existing failures (`test_concurrent_migrators_apply_once`, `test_fresh_apply_idempotent_and_tamper_detection`, `test_service_refuses_unmigrated_database`, `test_bad_credentials_fail_closed_without_leaking_secret`) fail identically in the baseline because the test role is a **superuser** (`CREATE ROLE … SUPERUSER`), which changes migration-guard and auth-failure behaviour. They are environmental, not regressions.

### Step 7 test coverage (41 tests)
* **Concurrency** — concurrent idempotent registration (24 threads → 1 agent), concurrent idempotent issuance (24 → 1 credential), 40 distinct registrations across two instances, PG-level `reserve` single-winner (32 threads → 1 NEW).
* **Idempotency** — replay returns byte-identical token; different body/actor → conflict; tenant isolation; `fail()` frees key; completed record is terminal; purge bounded.
* **Outage/retry** — bounded backoff, gives-up-after-bound, non-retryable propagates, no-retry-when-empty, transient-outage recovery, service denies when idempotency store is down.
* **Multi-instance** — credential issued on one instance verifies on another; revocation on one is visible on the other; idempotent issuance across instances returns the same credential; restart-survival (new instance over same PG+Redis); both instances report ready.
* **Coordination** — duplicate job prevented across two runners; ledger records runner.
* **Graceful shutdown** — `serve_forever` runs `on_shutdown` and exits cleanly.

---

## 6. Actual multi-instance tests performed

Real **multi-instance** tests (not single-process) were run against shared PostgreSQL + Redis:

* `MultiInstanceIntegration` builds **two independent `IdentityService` instances** (`inst-1`, `inst-2`, plus a third "restarted" `inst-3`) over the **same** database and the **same** Redis keyspace, then asserts cross-instance consistency: issued credential verifies on the other replica, revocation is visible on the other replica, idempotent issuance across replicas returns the same token, and 40 concurrent registrations split across the two instances all yield distinct agent IDs.

Single-process tests (in-memory idempotency, coordination scheduling, retry) are clearly separated in `test_step7_ha.py` (unit classes) from the real multi-instance tier.

---

## 7. Remaining single points of failure

All are **infrastructure** (the service has no leader and no single replica whose loss breaks correctness):

| Component | Impact if down | Mitigation |
|---|---|---|
| **PostgreSQL** | No authoritative reads/writes; readiness fails; service denies | HA Postgres (replication + failover), backups, PITR |
| **Redis** | Replay checks deny; caches bypass to PG; rate limits fail closed | Sentinel/cluster; replay quarantine on state loss |
| **KMS/HSM** | No signing ⇒ no issuance/rotation; readiness fails | Multi-region KMS / HSM cluster |
| **SPIRE** | No SVIDs/bundles ⇒ mTLS + SPIFFE verification deny | SPIRE HA, agent on every node |
| **Load balancer / ingress** | No traffic reaches replicas | Redundant, health-checked LBs |

---

## 8. Integration boundary for Step 8 (Enterprise AuthN, RBAC, Multi-tenancy)

Step 7 leaves a clean seam for Step 8:

* **Tenant scope already exists** — organizations are the tenant boundary; idempotency is already tenant-scoped (`scope = org_id`); PostgreSQL composite FKs enforce the tenant boundary at the DB level. Step 8 adds *policies/roles*, not a new tenant primitive.
* **Actor identity is threaded but coarse** — every control-plane call carries an `actor` string (currently `system`/`http:admin`/`spawn:…`); idempotency already distinguishes actors. Step 8 replaces this with authenticated principals + roles/permissions and an authorization decision point **before** `_idempotent`/`produce`.
* **No RBAC was implemented** — `register_agent`/`issue_credential`/`revoke_*`/`rotate_*` remain single-actor admin operations gated only by the admin bearer token. Step 8's authorization layer slots in as a pre-check in `handle()` and/or a guard in the service methods.
* **Idempotency is RBAC-ready** — the `actor` field on `idempotency_records` is exactly the field Step 8's subject/principal should populate to prevent cross-tenant or cross-role credential leakage.
* **Multi-tenancy readiness** — a `scope`-aware `_idempotent` and per-tenant cache keys (`state/`) mean Step 8 can add row-level security / tenant isolation without restructuring storage.

**Do-not-implement checklist for Step 8:** full RBAC roles/permissions, enterprise authentication (OIDC/SAML/LDAP), multi-tenant policy enforcement, tenant quotas/billing — none were touched in Step 7.

---

## Infrastructure-dependent behaviour that could not be tested

* **Real AWS KMS / PKCS#11 HSM** — adapters code-complete, not exercised against a live service (no cloud account/HSM); `local-dev` provider used in tests.
* **Real SPIRE** — mTLS/SPIFFE integration test needs Docker + a SPIRE deployment, unavailable here; SPIFFE health is wired as an optional readiness check.
* **PostgreSQL failover / Redis Sentinel failover** — reconnect/quarantine/bypass paths unit-tested with simulated failures, but no real failover performed.
* **Multi-node network partitions** — tested as process-level concurrency against shared PG+Redis, not a real partition.
* **Benchmarks are single-process, single-instance** (see §Benchmark): multi-replica throughput requires a load balancer, not available in-sandbox.

---

## Benchmark (real numbers, no claims)

`scripts/benchmark_step7.py` — real PostgreSQL 15 + Redis 7, 1 instance, single process, `pool_max=32`, isolated Redis key-prefix.

| Workload | n | wall (s) | ops/s | p50 | p90 | p99 | mean |
|---|---|---|---|---|---|---|---|
| Identity lookup (`get_agent_identity`) | 2000 | 2.866 | 697.7 | 1.06 ms | 1.44 ms | 17.41 ms | 1.43 ms |
| Identity creation (`register_agent`) | 500 | 0.638 | 783.8 | 1.03 ms | 1.44 ms | 5.96 ms | 1.28 ms |
| Credential issuance (`issue_credential`) | 500 | 3.007 | 166.3 | 4.46 ms | 6.06 ms | 53.07 ms | 6.01 ms |
| Revocation check (`verify_credential`) | 2000 | 8.925 | 224.1 | 3.01 ms | 4.19 ms | 57.07 ms | 4.46 ms |
| Concurrent lookup (8 threads) | 4000 | 16.967 | 235.8 | — | — | — | — |

These are measured, not extrapolated. No scalability claims are made beyond "the service is stateless and scales horizontally; PostgreSQL is the shared bottleneck."
