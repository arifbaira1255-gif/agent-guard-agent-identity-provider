# AgentGuard Phase 9 — High Availability & Horizontal Scaling

## 1. Stateless replicas, shared state

The identity service is **stateless**: any replica can serve any request. All state lives in shared
infrastructure:

| State | Store | Consistency requirement |
|---|---|---|
| Organizations, agents, instances, credentials, revocations | **PostgreSQL** (authoritative) | strong (single primary) |
| Enterprise users, memberships, sessions, audit | **PostgreSQL** | strong |
| Policy, governance, egress/DLP, runtime, response, assurance | **PostgreSQL** | strong |
| Replay cache, permission cache, rate limits, locks | **Redis** | strong enough for security decisions; **fails closed** |
| Idempotency ledger, coordination ledger | **PostgreSQL** | strong |
| Metrics registry | process-local | per-replica (aggregate at scrape time) |

**No security decision depends on process-local state.** A revocation issued on replica A is
observed by replica B because both read the same PostgreSQL store; a replayed nonce is rejected by
any replica because the replay marker lives in Redis.

## 2. What was validated (real PostgreSQL 15.19 + Redis)

`tests/test_phase9_ha.py` — **5 tests, all passing**:

| Test | Property proven |
|---|---|
| `test_concurrent_issuance_across_replicas_is_safe` | 6 concurrent issuances across 2 replicas → **0 errors, all credential IDs unique** |
| `test_revocation_propagates_across_replicas` | revoke on replica A → replica B returns `valid=False, reason="revoked"` |
| `test_agent_visible_across_replicas` | an agent created on A is readable on B |
| `test_single_winner_across_instances` | two `CoordinationRunner`s → replica B is **skipped** while A holds the advisory lock; runs after release |
| `test_replay_marker_shared_across_instances` | a nonce stored by instance A is **rejected** by instance B |

## 3. Scaling configuration

* **Deployment:** `replicas: 3`, `maxUnavailable: 0`, `maxSurge: 1`.
* **HPA:** CPU target 70%, `minReplicas: 3`, `maxReplicas: 12`, 300s scale-down stabilization.
* **PDB:** `minAvailable: 2` — a node drain cannot take the service below quorum.
* **Readiness-aware routing:** `/readyz` returns 503 when a dependency is down, so the Service
  removes the replica before it can serve a wrong decision.

## 4. Connection-pool sizing

PostgreSQL `max_connections` must exceed `replicas × AGENTGUARD_PG_POOL_MAX` plus headroom for the
migration Job and operators. With 12 replicas × pool 10 = 120, size the server at ≥ 200 (the
reference StatefulSet sets `max_connections=200`).

## 5. Backpressure & failure handling

* The HTTP server bounds concurrency (`AGENTGUARD_MAX_WORKERS`, default 64) and **sheds** excess
  connections rather than queueing unboundedly — it never skips authentication to keep up.
* Redis operations use bounded retries with exponential backoff; on exhaustion the request is
  **refused** (fail closed), never allowed.
* PostgreSQL uses a bounded pool with a statement timeout (`AGENTGUARD_PG_STATEMENT_TIMEOUT_MS`).

## 6. Consistency guarantees & remaining single points of failure

**Guarantees:** linearizable reads/writes for security state via the single PostgreSQL primary;
replay protection is globally consistent via Redis.

**Remaining SPOFs (documented, not hidden):**
1. **PostgreSQL primary** — a single writer. HA requires a managed service or an operator with
   automated failover. The bundled StatefulSet is a reference, not HA.
2. **Redis** — required for a correct decision. HA requires a managed service or Sentinel/Cluster.
3. **KMS/HSM provider** — a hard dependency where configured; an outage blocks signing/verification.
4. **In-process rate limiter** (Phase 8) — per-replica, so the effective limit is
   `replicas × limit`. A shared Redis limiter is the documented production path and is **not**
   implemented in this phase.
5. **In-process metrics registry** — per-replica; aggregate at scrape time.

## 7. Duplicate & out-of-order events

* **Duplicate delivery:** the idempotency ledger is shared in PostgreSQL; a retried request with the
  same key and body returns the original outcome, and a different body returns `CONFLICT`.
* **Out-of-order:** audit records are hash-chained in insertion order; the chain head is the
  authority, so a late-arriving record cannot be spliced into the middle undetected.
