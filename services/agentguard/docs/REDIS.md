# Redis distributed security state (Step 4) — WIP: integration-tested on a plain redis:7 only

Status: 69 unit tests pass without Redis. The 26 real-Redis tests (`tests/test_state_integration.py`) were run by the project owner
against `redis:7` (no password-protected/TLS/sentinel/cluster setup verified) and all passed (wip7). Not yet verified: TLS, ACL users,
Sentinel/Cluster modes, and `benchmarks/bench_redis.py` numbers (none reported).

## Responsibility split
| PostgreSQL (authoritative, durable) | Redis (distributed, transient / accelerator) |
|---|---|
| agents, instances, credentials metadata, revocations, trust, bindings, encrypted keys | replay/nonce state, rate-limit counters, locks, temp security records, version-checked caches of PG reads |
Redis is never the only copy of anything that must survive Redis loss. Not cached: private keys, secrets, tokens, credential payloads.

## Architecture
```
IdentityService / SpiffeIdentityProvider -> existing ABCs (ReplayCache, AgentRegistry, RevocationRegistry)
  -> RedisReplayCache, CachedAgentRegistry, CachedRevocationRegistry  (state/replay.py, state/cache.py)
  -> DistributedRateLimiter, DistributedLock, TempStateStore            (new, state/*.py)
  -> StateBackend (state/backend.py)  <- MemoryBackend (tests/dev)  <- RedisBackend (Lua + atomic commands, redis-py)
```
Wiring: `st = build_security_state(RedisConfig.from_env())`; `svc = IdentityService(cfg, root_key_id=ID, **st.service_kwargs(pg_storage))`;
`SpiffeIdentityProvider(..., replay=st.replay, bindings=pg_storage.bindings)`.

## Key schema
`agentguard:v1:{<env>.<tenant>}:<domain>:<resource>:<id>` — `{env.tenant}` is the Cluster hash tag. All parts validated
(`[A-Za-z0-9_.-]`, no `: { } *` or whitespace). Nonces, tokens, IPs, subjects and cache ids are SHA-256 hashed before use. System-wide state uses tenant
`_system`. Tenant-scoped code gets a `TenantKeys`/`TenantTempState` handle FIXED to one tenant (it has no way to name another), and stored
envelopes carry their tenant: a record copied under another tenant's key is rejected.
Domains: `replay` (nonce, marker), `ratelimit`, `lock`, `tmp` (authz_decision|approval|grant|challenge|risk), `idcache`, `revcache`.

## Atomic operations (no GET -> decide -> SET)
Replay: one Lua script (marker check + `SET NX PX`). Rate limit: token-bucket Lua (uses Redis `TIME`), fixed-window `INCR`+`PEXPIRE` Lua.
Lock: `SET NX PX`, owner-checked release/extend by compare-and-delete/expire Lua. Temp-state transition: compare-and-set (`KEEPTTL`);
single-use consume: compare-and-delete. Every write requires a positive TTL (max 31 days at the backend; policy caps per feature).

## Consistency model (PostgreSQL <-> Redis)
Reader: read version token V, read entry (hit only if entry.V == V), else read PostgreSQL and store entry tagged with the V read BEFORE the DB read.
Writer: commit to PostgreSQL FIRST, then replace V with a fresh random token. Tokens are random (not counters) to avoid ABA after eviction/restart.
- Stale window: from PG commit until the version bump (milliseconds), plus up to the cache TTL (agent 30s, revocation 10s defaults) if the bump itself fails
  (counted in `agentguard_cache_invalidation_failures_total` and logged). Writes that bypass the cached wrappers (manual SQL) are visible after TTL.
- Redis down => reads go straight to PostgreSQL (correct, slower). PostgreSQL errors propagate => deny. Corrupt entries => miss.
- Negative results ("not revoked") are cached only under the version check, never trusted without it.

## Failure behaviour
| Situation | Replay | Rate limit | Lock | Cache | Temp state |
|---|---|---|---|---|---|
| Redis unavailable/timeout/auth/pool exhausted | RAISE -> request denied (no local fallback) | DENY (`on_error="deny"`, default) or bounded per-process bucket (`"local"`) | not acquired | bypass to PostgreSQL | raises |
| Redis restart / failover with data loss | marker missing -> QUARANTINE one replay window (all checks refused), then resume | counters restart (limits briefly looser) | locks lost (see assumptions) | versions regenerate; entries invalid | records gone (treated as expired) |
| Corrupted/foreign value | n/a | `StateCorruptError` -> deny/degraded | n/a | miss | `StateCorruptError` |
Limits: JWT-SVID single-use tokens can outlive the quarantine window; keep them short-lived. A fresh deployment calls `ensure_marker()` so it does not quarantine.
Locks assume a single authoritative primary (NOT Redlock): after failover or a pause longer than the TTL two holders can briefly coexist, so correctness
must stay with PostgreSQL constraints/transactions; locks only avoid duplicate work.

## Production configuration (environment driven)
`AGENTGUARD_ENV=production` forces: TLS with hostname verification, a password (or `_PASSWORD_FILE`), no credentials in URLs; `IdentityService` /
`SpiffeIdentityProvider` refuse a per-process replay cache unless `AGENTGUARD_ALLOW_LOCAL_REPLAY=1` (single instance only).
Variables: `AGENTGUARD_REDIS_{HOST,PORT,DB,USERNAME,PASSWORD,PASSWORD_FILE,TLS,TLS_CA_CERT,TLS_CLIENT_CERT,TLS_CLIENT_KEY,TLS_CHECK_HOSTNAME,URL,MODE,SENTINELS,SENTINEL_MASTER,POOL_MAX,COMMAND_TIMEOUT_S,CONNECT_TIMEOUT_S,KEY_PREFIX}`.
`mode=sentinel|cluster` is implemented but UNTESTED. Server guidance: `integration/redis/redis.production.example.conf`
(TLS, ACL user with minimal commands, `maxmemory-policy volatile-ttl` — never `allkeys-*`, AOF + replicas, memory sizing: replay keys ~100-150 bytes each).

## Local development
```
cp .env.example .env     # set AGENTGUARD_REDIS_PASSWORD
docker compose -f integration/redis/docker-compose.yml --env-file .env up -d
pip install -e '.[redis]'
export AGENTGUARD_TEST_REDIS_HOST=127.0.0.1 AGENTGUARD_TEST_REDIS_PASSWORD=<same password>
PYTHONPATH=src:. python -m unittest -v tests.test_state_integration
PYTHONPATH=src:. python benchmarks/bench_redis.py
```
Without Redis: `PYTHONPATH=src:. python -m unittest tests.test_state_unit`.

## Observability
`st.metrics.render_prometheus()`: `agentguard_redis_{commands,errors,retries,reconnects}_total`, `agentguard_redis_command_latency_seconds`,
`agentguard_cache_{hits,misses,bypass,corrupt,invalidations,invalidation_failures}_total`, `agentguard_replay_{allowed,rejected,quarantined}_total`,
`agentguard_ratelimit_{allowed,rejected,degraded}_total`, `agentguard_lock_{acquired,contended,release_lost}_total`, `agentguard_state_corrupt_total`.
`backend.pool_stats()` (best effort) for connection use. Logs carry operation name, error kind and exception type only: never driver text, keys, tokens, or values.

## Known limitations
- Real-Redis behaviour (Lua, TLS, auth, reconnect, sentinel/cluster) not yet verified; no benchmark numbers yet.
- No pub/sub invalidation: cross-instance freshness relies on the version token read per lookup (one extra Redis GET per cached read).
- Rate-limit counters are lost on Redis data loss; `local` fallback is per process.
- Temp-state is a foundation only (no policy engine). Key-space metrics (count of keys) are not exported.
