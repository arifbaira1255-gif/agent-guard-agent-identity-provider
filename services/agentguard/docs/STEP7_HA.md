# Step 7 — Distributed High-Availability Identity Service

This document describes how AgentGuard's identity service runs as **multiple stateless replicas**
that share PostgreSQL (durable, authoritative) and Redis (distributed transient state), and how it
stays correct under concurrency, dependency outages and rolling restarts.

It builds on Steps 1–6 and reuses them unchanged: the identity engine (`IdentityService`), the
PostgreSQL repositories, the Redis security-state layer, the KMS/HSM key layer and the mTLS/SPIFFE
transport. Step 7 adds only the pieces required for safe multi-instance operation.

---

## 1. Deployment topology

```
                    ┌─────────────────────────── load balancer / mTLS ingress ───────────────────────────┐
                    │                                                                                    │
        ┌───────────▼───────────┐   ┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
        │ identity replica #1   │   │ identity replica #2│   │ identity replica #3│  │ ... (HPA 3..12)   │
        │  stateless process    │   │  stateless process │   │  stateless process │  │                   │
        └───┬───────────┬───────┘   └───┬───────────┬────┘   └───┬───────────┬────┘   └───┬───────────┬───┘
            │           │               │           │            │           │            │           │
   durable  │           │ transient     │           │            │           │            │           │
   state    │           │ state         │           │            │           │            │           │
        ┌───▼───────────▼───────────────▼───────────▼────────────▼───────────▼────────────▼───────────▼───┐
        │  PostgreSQL (authoritative)                    │  Redis (distributed transient state)             │
        │  orgs, agents, instances, credentials,         │  replay cache, versioned caches, rate limits,    │
        │  revocations, trust, keystore, idempotency,    │  distributed locks, temp security state          │
        │  coordination ledger                           │                                                  │
        └────────────────────────────────────────────────┴──────────────────────────────────────────────────┘
                    │                                                          │
        ┌───────────▼───────────┐                                  ┌───────────▼───────────┐
        │ KMS / HSM (Step 5)    │                                  │ SPIRE agent (Step 6)  │
        │ sign-only key custody │                                  │ SVIDs + trust bundles │
        └───────────────────────┘                                  └───────────────────────┘
```

* **No authoritative security decision depends on local process memory.** Every replica reads the
  same PostgreSQL rows and the same Redis keys. Local caches are accelerators only (see §3).
* **Any replica can serve any request.** There is no leader for request handling; coordination is
  used only for scheduled jobs (§6).

### Wiring

```python
from agent_identity.core.config import IdentityConfig
from agent_identity.storage.postgres import PgConfig, build_postgres_storage
from agent_identity.state import RedisConfig, build_security_state
from agent_identity.ha.factory import build_ha

pg = build_postgres_storage(PgConfig.from_env(), master_keys=[os.environ["AGENT_IDENTITY_MASTER_KEY"].encode()])
st = build_security_state(RedisConfig.from_env())
ha = build_ha(pg, st, IdentityConfig.from_env()).start()   # idempotency + coordination + health
svc = ha.service
```

---

## 2. Statelessness: where each kind of state lives

| State | Location | Why |
|---|---|---|
| Organizations, agents, instances, credentials, revocations, trust roots/issuer certs | **PostgreSQL** | Authoritative; must survive restarts and be shared by all replicas |
| Service-held private keys | **KMS/HSM** (or Fernet-encrypted `keystore_keys` in dev) | Sign-only; never in process memory beyond a single call |
| Replay nonces, versioned caches, rate-limit buckets, distributed locks, temp security state | **Redis** | Transient, distributed, TTL-bounded |
| Idempotency records | **PostgreSQL** | Must be durable and shared so a retry on another replica is recognised |
| Coordination job ledger | **PostgreSQL** | Bookkeeping for scheduled jobs |
| Per-instance metrics, in-flight request state | **process memory** | Not authoritative; safe to lose on restart |

---

## 3. Consistency and concurrency

Correctness under concurrent registration, issuance, rotation, revocation, status changes and trust
updates is enforced by the **database**, not by application-level locking:

* **Uniqueness constraints** — `agents.agent_id`, `credentials.credential_id`, `revocations`
  `(target_type, target_id)`, `spiffe_bindings.spiffe_id`, and the idempotency primary key
  `(scope, operation, idem_key)` make duplicate creation impossible.
* **Composite foreign keys** — `agent_instances (agent_id, org_id)` and
  `credentials (instance_id, agent_id, org_id)` enforce the tenant boundary at the DB level.
* **Immutable columns + terminal states** — triggers reject moving an agent between orgs/parents,
  re-activating a terminated agent, un-revoking a binding, or resetting a completed idempotency
  record.
* **Earliest-effective-wins revocations** — `ON CONFLICT ... WHERE EXCLUDED.effective_at <
  revocations.effective_at` guarantees a race between two revocations keeps the earliest.
* **Optimistic concurrency** — `put_agent`/`put_instance`/`put_issuer_cert` use conditional
  `ON CONFLICT ... WHERE` clauses and raise `ConflictError` when a concurrent writer changed an
  immutable field.
* **Row-level locking** — PostgreSQL's own row locks during `UPDATE`/`INSERT ... ON CONFLICT`
  serialise conflicting transitions; no application lock is needed.

**Preventing conflicting security-critical transitions across instances:** because every transition
is a single conditional SQL statement, two replicas racing on the same target cannot both succeed —
one commits, the other gets a constraint/`ConflictError`. The versioned cache (§4) ensures a
replica never serves a stale `active`/`not-revoked` answer after another replica committed a change.

---

## 4. Safe local caches with invalidation

`state/cache.py` implements a **versioned read-through cache**:

* reader: read version token `V` → read cached entry → hit only if `entry.V == V` → else read
  PostgreSQL and store tagged with `V`;
* writer: commit to PostgreSQL **first**, then replace `V` with a fresh random token (invalidate).

Any entry loaded before a commit carries a token the writer's bump invalidates. Residual staleness
is bounded by the entry TTL (agent 30 s, revocation 10 s) if the invalidation bump itself fails
(counted and logged). Redis failure ⇒ **bypass to PostgreSQL** (still correct, just slower). A
corrupted entry is treated as a miss. Negative results are cached only under the same version check.

---

## 5. Idempotency (registration + credential issuance)

`ha/idempotency.py` + `IdentityService._idempotent`:

* **Explicit scope** — key is `(scope, operation, idem_key)`; `scope` is the organization id (or
  `_system`). The same key under a different tenant is a different record.
* **Atomic reservation** — the first caller `INSERT`s an `in_progress` row; concurrent callers see
  it and do **not** re-execute the transition.
* **Bounded retention** — every record has `expires_at`; a coordination job purges expired rows.
* **Safe duplicate handling** — a replay with the **same actor and same request digest** returns the
  stored result (the credential is returned byte-identical, so a retry is safe).
* **Conflict detection** — a different body or a different actor for the same key is a hard
  `ConflictError`.
* **No credential leakage** — the stored response is Fernet-encrypted at rest and is only returned
  to the actor that created it. An unauthorized caller presenting a matching key gets a conflict,
  never the credential.
* **Crash recovery** — an `in_progress` reservation older than `idempotency_stale_seconds` may be
  taken over by exactly one instance (`takeover_stale`), so a crashed request cannot wedge a key.

HTTP: send `Idempotency-Key: <opaque>` on `POST /v1/agents` and `POST /v1/credentials/issue`.

---

## 6. Multi-instance coordination

`ha/coordination.py` runs scheduled jobs under a **PostgreSQL session advisory lock**
(`pg_try_advisory_lock`), which is stronger than a Redis lock: it is tied to the database that owns
the authoritative state, is released automatically if the instance dies, and cannot be lost by a
Redis failover. A replica that cannot take the lock **skips** the job — another replica is running
it. Jobs:

| Job | Purpose |
|---|---|
| `purge_expired_material` | delete service-held ephemeral keys of expired/revoked credentials |
| `purge_idempotency` | bounded retention of the idempotency ledger |
| `reconcile` | read-only drift detection (orphaned orgs, expired credentials with live keys) |

**No distributed lock is introduced where a DB transaction or an idempotent operation suffices.**
Request handling uses no locks at all; only these scheduled jobs are serialised.

---

## 7. Health and readiness

`ha/health.py` + `GET /livez`, `GET /readyz`:

* **Liveness** (`/livez`) — process only. Never touches a dependency, so a dependency outage cannot
  cause a restart storm.
* **Readiness** (`/readyz`) — `database` (reachable **and** schema matches this build), `redis`,
  and — where configured — `spiffe`, `kms`, `trust`. Any required capability down ⇒ `503 not_ready`
  and the replica is removed from the load balancer.

Both endpoints are unauthenticated (the orchestrator must reach them) but return only coarse
`ok`/`fail` per capability — never versions, hostnames, connection strings, identities or error
text. `GET /metrics` (authenticated) exposes Prometheus metrics.

---

## 8. Failure recovery

* **PostgreSQL outage** — `Database.run` retries transient errors (SQLSTATE `08*`, `40001`,
  `40P01`, `57P0*`, pool timeouts) with bounded exponential backoff + jitter; after the bound it
  raises `StorageUnavailableError` and callers **deny** (fail closed). Readiness flips to
  `not_ready`. No fallback store, ever.
* **Redis outage** — replay checks **raise** (callers deny); caches **bypass** to PostgreSQL (still
  correct); rate limits fail closed by default. Readiness flips to `not_ready`.
* **Transient network failures** — bounded retries with full jitter (`ha/retry.py`); only
  idempotent operations are retried. Non-idempotent operations pass `retry_on=()`.
* **Service restarts** — durable state is in PostgreSQL; a restarted replica re-reads it. A
  credential issued before the restart still verifies (proven by the restart-survival test).
* **Dependency recovery** — the pool health-checks connections; readiness recovers automatically
  once the dependency answers again.
* **Partial request failures** — a failed idempotent operation calls `fail()` to free the key for a
  safe retry; a completed side effect whose idempotency record could not be written is retried
  (bounded) so a later duplicate cannot slip through after the stale window.
* **Interrupted credential rotation** — rotation issues the new credential first, then revokes the
  old after a grace window; an interruption leaves the old credential valid until its grace expires
  (never a gap where neither works).
* **Conflicting concurrent updates** — resolved by DB constraints/conditional writes (§3).

**Never silently bypass identity or revocation checks to preserve availability.** Every failure
path denies.

---

## 9. Observability

* **Per-instance health** — `/livez`, `/readyz`; `instance_id` in diagnostics.
* **Request latency/errors** — `agentguard_requests_total`, `agentguard_request_errors_total`,
  `agentguard_request_latency_seconds`.
* **Dependency latency/failures** — `agentguard_dependency_up`,
  `agentguard_dependency_latency_seconds`, `agentguard_dependency_failures_total`; PostgreSQL and
  Redis emit their own (`agentguard_pg_*`, `agentguard_redis_*`).
* **DB pool** — `agentguard_pg_pool_size`, `Database.pool_stats()`.
* **Credential operations** — `agentguard_credential_operations_total{reason=issue|rotate|revoke}`.
* **Idempotency** — `agentguard_idempotency_{new,replay,in_progress,conflict,takeover}_total`.
* **Reconciliation/coordination** — `agentguard_reconciliation_{runs,drift}_total`,
  `agentguard_coordination_job_{runs,skipped,failures}_total`.
* **Structured logs with correlation IDs** — the allow-list `SecurityLogger`; `correlation_id` is
  propagated via a context variable. No tokens, keys or identities are ever logged.

---

## 10. Scaling guidance

* **Replicas** — stateless; scale horizontally (HPA on CPU). Readiness removes unhealthy replicas.
* **PostgreSQL** — the shared bottleneck. Size `pool_max` so `replicas × pool_max` stays below the
  server's `max_connections` (leave headroom for migrations/operators). Use a connection pooler
  (PgBouncer) at high replica counts. Read replicas are **not** used for authoritative reads.
* **Redis** — one primary is authoritative for locks/replay; use Sentinel/cluster for HA. All keys
  are TTL-bounded and tenant-hash-tagged.
* **KMS/HSM** — signing throughput is the ceiling for issuance; cache public keys, never private.

---

## 11. Known single points of failure

| Component | Impact if down | Mitigation |
|---|---|---|
| **PostgreSQL** | No authoritative reads/writes; readiness fails; service denies | HA Postgres (streaming replication + failover), backups, PITR |
| **Redis** | Replay checks deny; caches bypass to PG; rate limits fail closed | Redis Sentinel/cluster; replay quarantine on state loss |
| **KMS/HSM** | No signing ⇒ no issuance/rotation; readiness fails | Multi-region KMS / HSM cluster; key replication |
| **SPIRE** | No SVIDs/bundles ⇒ mTLS and SPIFFE verification deny | SPIRE HA (multiple servers), agent on every node |
| **Load balancer / ingress** | No traffic reaches replicas | Redundant LBs, health-checked backends |

These are **infrastructure** SPOFs, not application SPOFs: the service itself has no leader and no
single replica whose loss breaks correctness.

---

## 12. Operational troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `/readyz` = `not_ready`, `database: fail` | PG down or schema mismatch | Check PG; run migrations as a deploy step; verify `schema_migrations` |
| `/readyz` = `not_ready`, `redis: fail` | Redis down / auth / TLS | Check Redis; verify password/TLS CA; replay will quarantine until healthy |
| `409 conflict` on issue/register | Idempotency key reused with a different body/actor | Use a fresh key per distinct request; keys are per-tenant |
| `409 an identical request is already in progress` | Concurrent duplicate in flight | Retry after the first completes; stale reservations auto-expire |
| Issuance slow / failing | KMS/HSM throttling or down | Check KMS health; verify region/credentials; readiness reflects it |
| mTLS handshakes failing | SPIRE bundle stale / SVID expired | Check SPIRE agent; readiness `spiffe: fail` |
| Coordination job never runs | Another replica holds the advisory lock | Expected; check `coordination_jobs` ledger for the last runner |
| Stale revocation briefly accepted | Cache invalidation bump failed | Bounded by revocation TTL (10 s); check `agentguard_cache_invalidation_failures_total` |

---

## 13. Infrastructure-dependent behaviour that could not be tested here

* **Real AWS KMS / PKCS#11 HSM** — the adapters are code-complete but were not exercised against a
  live service (no cloud account / HSM available). The `local-dev` provider is used in tests.
* **Real SPIRE** — the mTLS/SPIFFE integration test requires Docker + a SPIRE deployment; it was
  not run in this environment. SPIFFE health is wired as an optional readiness check.
* **PostgreSQL failover / Redis Sentinel failover** — the code paths (reconnect, quarantine,
  bypass) are unit-tested with simulated failures, but a real failover was not performed.
* **Multi-node network partitions** — tested as process-level concurrency against shared PG+Redis,
  not as a real network partition.
