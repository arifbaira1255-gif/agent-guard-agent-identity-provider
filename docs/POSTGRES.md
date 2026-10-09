# PostgreSQL persistence (Step 3) — WIP: unit-tested, NOT yet run against a real PostgreSQL

Status: 24 unit tests pass without a database (config, error mapping, retry, fail-closed, SQL constants,
guards, migration file checks). The 23 real-PostgreSQL tests (`tests/test_pg_integration.py`) and
`benchmarks/bench_pg.py` exist but have NOT been executed yet; the SQL schema and queries are unverified until they pass.

## Architecture
```
IdentityService / SpiffeIdentityProvider  (unchanged callers)
  -> storage/interfaces.py (existing ABCs)  <- Memory* (dev/tests)   <- Pg* (storage/postgres/repos.py)
                                                                      -> Database (pool, tx, retry, health) -> psycopg 3
```
Reused unchanged: all domain models, the registry/trust/revocation interfaces, `BindingRegistry`, the crypto code.
In PostgreSQL: orgs, issuer certs + trust roots, agents (+key rotation/retired keys, lineage), instances, spawn
(parent/child) records, credential metadata, revocations, SPIFFE bindings, and the encrypted key store.
Not in PostgreSQL: replay cache (Step 4, Redis), high-volume audit stream (ClickHouse).

## Schema (migrations/0001_initial.sql)
Times are epoch DOUBLE PRECISION (exact round-trip) + `row_created_at/updated_at`. Tenant boundary: composite FKs
(`agent_id, org_id`) on instances/credentials/bindings. DB triggers: `terminated` is terminal, agent
org/parent/lineage/created_at immutable, bindings only `active -> revoked`. Revocations: one row per target, earliest
`effective_at` wins (atomic upsert). Binding: one SPIFFE ID per (agent, instance), never re-pointed. Indexes only for
actual access paths: PK lookups, `agents(parent)`, `agent_instances(agent)`, `credentials(instance|agent|expires)`,
`agents(org,status)`.

## Setup
Local (Docker): `cp .env.example .env` (set a password), then
```
docker compose -f integration/postgres/docker-compose.yml --env-file .env up -d
pip install -e '.[postgres]'
set -a; . ./.env; set +a
PYTHONPATH=src python -m agent_identity.storage.postgres migrate
PYTHONPATH=src python -m agent_identity.storage.postgres check
```
Use in code:
```python
cfg = PgConfig.from_env()
st = build_postgres_storage(cfg, master_keys=[os.environ["AGENT_IDENTITY_MASTER_KEY"]])
svc = IdentityService(config, root_key_id=ROOT_KEY_ID, **st.service_kwargs())   # keep ROOT_KEY_ID across restarts
provider = SpiffeIdentityProvider(svc, spire_cfg, transport, bindings=st.bindings)
```
Tests: `AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=... AGENTGUARD_TEST_PG_PASSWORD=... PYTHONPATH=src:. python -m unittest -v tests.test_pg_integration`
(role must be able to CREATE DATABASE; each test class uses a throwaway DB).

## Production
- `AGENTGUARD_ENV=production`: IdentityService and SpiffeIdentityProvider REFUSE in-memory registries/bindings.
- TLS `verify-full` (or `verify-ca`) + `sslrootcert` required; `auto_migrate` forbidden: run `migrate` as a deploy step with a
  MIGRATOR role (DDL). Runtime role: `GRANT SELECT, INSERT, UPDATE ON ALL TABLES` (+ `DELETE` on `keystore_keys` only; the service deletes
  ephemeral keys), no DDL, no superuser. Passwords via `AGENTGUARD_PG_PASSWORD_FILE`/env, never logged.
- The key store keeps ONLY Fernet-encrypted private keys; the master key(s) must come from a secret manager/KMS and are never in the DB.
  Rotate with `master_keys=[new, old]`. Losing the master key = losing all signing keys.
- Backups: encrypt them (they contain encrypted keys + identity state); back up the master key SEPARATELY; test restores; a restored DB
  older than the latest revocations would "un-revoke" identities: after any restore, re-apply revocations from your audit log before serving.
- Pool: `AGENTGUARD_PG_POOL_MAX` x replicas must stay below PG `max_connections`.

## Failure behaviour (all DENY, no fallback store)
DB down / pool exhausted / timeout / deadlock / serialization failure => bounded retry (idempotent upserts) then
`StorageUnavailableError`; verifiers turn any storage exception into `valid=False`. Schema missing/behind/ahead/checksum-drift =>
`SchemaMismatchError` at startup and `readiness()` not ready. Unique/FK/trigger violations => `ConflictError` (no retry). Messages never
contain driver text, DSNs, or passwords.

## Observability
`db.metrics.render_prometheus()`: `agentguard_pg_operations_total{op}`, `_operation_failures_total{type}`, `_query_latency_seconds`,
`_retries_total`, `_connection_failures_total`, `_transaction_failures_total{sqlstate}`. Health: `db.liveness()`, `db.health()`,
`db.readiness()` (DB reachable AND schema matches). Migration status: `python -m agent_identity.storage.postgres status`.

## Known limitations
- Service methods do read-modify-write (e.g. `rotate_agent_key`): two concurrent rotations of the SAME agent can lose one update; the
  `version` column exists but the domain model/service do not use it yet (needs a small service change).
- `list_all()` credentials is unbounded (used by `purge_expired_material`); needs pagination before large deployments.
- No row-level security: tenant isolation is by composite FKs + application checks.
- Benchmarks not yet measured.
