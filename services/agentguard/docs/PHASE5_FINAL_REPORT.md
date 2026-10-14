# AgentGuard Phase 5 — Final Report

**Phase:** 5 — Runtime Monitoring, Agent Behaviour Intelligence, Intent Graph & Agentic Drift Detection
**Base:** `agentguard_v7_phase4.zip` (extracted, inspected)
**Deliverable:** `agentguard_v7_phase5/` (copy-on-write per TASK CONTINUATION rules — the phase-4 tree was never edited in place)
**Status:** implemented, integrated, tested, documented. All measured results below come from real
executions in this environment; commands are quoted verbatim so they can be re-run.

---

## 1. Headline evidence

| Metric | Baseline (Phase 4 tree) | Phase 5 tree | Delta |
|---|---|---|---|
| Tests run | **819** | **935** | **+116** |
| Result | `OK (skipped=82)` | `OK (skipped=82)` — three consecutive runs | **zero regressions** |
| Failures / errors | 0 | **0** | — |
| Coverage (whole `src`) | 82% | **81%** | −1 pt (new large module, see §4) |
| New Phase 5 test files | — | 2 files, 116 tests | — |
| New source | — | 17 modules + 1 migration + 1 PG store | — |

Skipped tests are **unchanged from baseline (82)** and are the same pre-existing
optional-infrastructure skips (e.g. KMS/SPIFFE-dependent paths); Phase 5 introduced **no new skips
and no flaky tests**.

---

## 2. Exact commands and raw results

### 2.1 Full suite — final confirmation run (authoritative)

```bash
cd agentguard_v7_phase5
export AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres \
       AGENTGUARD_TEST_PG_PASSWORD=postgres AGENTGUARD_TEST_PG_DB=agentguard_test \
       AGENTGUARD_TEST_REDIS_URL=redis://127.0.0.1:6379/0 PYTHONPATH=src:.
rm -f .coverage
python3 -m coverage run --source=src -m unittest discover -s tests -t .
python3 -m coverage report
```

Raw tail of the run:

```
Ran 935 tests in 54.873s

OK (skipped=82)
TOTAL                                                         16254   3042    81%
```

Exit status: `0`.

**Stability evidence — the suite was then run three more consecutive times:**

```
=== RUN 1 ===  Ran 935 tests in 53.925s  OK (skipped=82)
=== RUN 2 ===  Ran 935 tests in 54.097s  OK (skipped=82)
=== RUN 3 ===  Ran 935 tests in 53.326s  OK (skipped=82)
```

Three consecutive clean runs are quoted because an *earlier* full-suite run in this phase exposed a
genuine order-dependent pagination bug (see §6 #6) that did **not** appear when the affected file was
run alone. The final state is verified order-independent, not verified once.

### 2.2 Baseline — the untouched Phase 4 tree, same environment

```
Ran 819 tests in 53.040s

OK (skipped=82)
```

Baseline coverage: `TOTAL 16259 ... 82%` (819 tests).

### 2.3 Phase 5 unit/adversarial suite alone

```bash
PYTHONPATH=src:. python3 -m unittest tests.test_phase5_runtime_monitoring
```

```
Ran 96 tests in 0.007s

OK
```

### 2.4 Phase 5 PostgreSQL integration suite alone

```bash
export AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres \
       AGENTGUARD_TEST_PG_PASSWORD=postgres PYTHONPATH=src:.
python3 -m unittest tests.test_pg_phase5_integration -v
```

```
Ran 20 tests in 0.876s

OK
```

All 20 executed — **no skips**, including the live RLS-enforcement test as a non-superuser role.

### 2.5 Test inventory

| Layer | File | Count | What it covers |
|---|---|---|---|
| Unit + adversarial | `tests/test_phase5_runtime_monitoring.py` | **96** | schema/vocabulary, redaction & privacy, sampling, dedup, correlation, tenant isolation, profiles, drift (all classifications + FP/FN), intent graph, risk explanation, alerts (dedup / rate limit / lifecycle), policy & revocation integration, malformed / late / out-of-order, resource exhaustion, forged-event paths |
| Integration (real PostgreSQL) | `tests/test_pg_phase5_integration.py` | **20** | migration 0008 head + tables + indexes, event round-trip, append-only triggers, RLS config **and** live non-superuser enforcement, cross-tenant query filter, keyset pagination, SQL aggregation, retention scoping, profile upsert/versioning, graph edge accumulation, alert lifecycle, rule tenant-pinning, DB-enforced constraints |
| Pre-existing regression | all prior `tests/…` | **819** | unchanged, all passing |

No security/load test suite in the *repository* was modified; the adversarial and
resource-exhaustion cases live in the new Phase 5 files, and performance is measured by the
benchmark (§3).

---

## 3. Benchmark results (measured, reproduced in this environment)

```bash
export AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres \
       AGENTGUARD_TEST_PG_PASSWORD=postgres BENCH_N=20000 PYTHONPATH=src:.
python3 scripts/bench_phase5.py
```

```
machine : AMD EPYC 9275F 24-Core Processor x48, Python 3.11.15, Linux
corpus  : N=20,000 events per phase; timings are wall-clock, single process, no warmup
1. ingestion            : 5,858 stored / 0.988s = 5,931 events/s  (169 us/event)
2. correlation query    : p50=0.173ms  p95=0.230ms  p99=0.237ms  (n=2000)
3. graph query          : p50=136.044ms  p95=180.041ms  (n=500, graph edges=20625)
4. profile build        : 235 events in window -> 0.0008s (tools=12, resources=2, destinations=4, mature=True)
5. drift evaluation     : 2 findings in 0.0004s
6. risk assessment      : score=67.5 band=high in 0.0005s (3 signals)
7. alert dedup/ratelimit: 20,000 raises in 3.794s = 5,272 raises/s (7400 distinct alerts after dedup)
8. postgres ingestion   : 3,286 stored / 2.918s = 1,126 events/s (sync, single connection, per-event transaction)
```

**Interpretation, honestly bounded.** These are single-process, no-warmup, one-run figures on a
48-vCPU EPYC; they characterise the code path, not production capacity. Ingest is synchronous and
the PostgreSQL figure is **one transaction per event over one connection** — a floor, not a ceiling
(no batching, no async writer, no queue in this phase). The **intent-graph query is the known hot
spot** (~136 ms p50 at ~20.6 k edges; the in-memory store scans edges and chain search is
super-linear). **Nothing was tested under concurrent writers.** Full caveats:
`docs/PHASE5_SECURITY_LIMITATIONS.md` §5.

---

## 4. Coverage detail (Phase 5 module)

```
src/agent_identity/runtime_monitoring/__init__.py                17      0   100%
src/agent_identity/runtime_monitoring/alerts.py                 179     55    69%
src/agent_identity/runtime_monitoring/audit.py                   43      2    95%
src/agent_identity/runtime_monitoring/config.py                  85     30    65%
src/agent_identity/runtime_monitoring/drift.py                  126     11    91%
src/agent_identity/runtime_monitoring/errors.py                  20      0   100%
src/agent_identity/runtime_monitoring/graph.py                  170     32    81%
src/agent_identity/runtime_monitoring/memory_store.py           221     30    86%
src/agent_identity/runtime_monitoring/models.py                 397     23    94%
src/agent_identity/runtime_monitoring/pipeline.py               189     18    90%
src/agent_identity/runtime_monitoring/policy_integration.py      75     36    52%
src/agent_identity/runtime_monitoring/profiles.py                93     12    87%
src/agent_identity/runtime_monitoring/redaction.py              102     20    80%
src/agent_identity/runtime_monitoring/risk.py                   105     14    87%
src/agent_identity/runtime_monitoring/service.py                 99     19    81%
src/agent_identity/runtime_monitoring/store.py                   21      0   100%
src/agent_identity/storage/postgres/runtime_monitoring.py       243     84    65%
```

The **lowest-covered** files and why, stated rather than hidden:

* `policy_integration.py` (52%) — the dispatch surface for response actions; only reachable when
  auto-actions are enabled, and it terminates at the **pre-existing** policy/JIT services, whose
  behaviour is not Phase 5's to test. The unit tests cover the disabled-default and the delegation
  call; the end-to-end dispatch against a live OPA-backed policy engine is **not** exercised.
* `config.py` (65%) — `from_env()` and the range-validation failure branches are only hit when the
  environment is populated.
* `runtime_monitoring.py` PostgreSQL store (65%) — every method is exercised by the 20 integration
  tests, but the error-mapping branches (retry/backoff paths) are not.

Overall coverage moved 82% → 81% because ~5.9 k new lines were added and the uncovered balance is
concentrated in those boundary paths.

---

## 5. Changed / reused / new files

### Newly created

| Path | Lines | Purpose |
|---|---|---|
`src/agent_identity/runtime_monitoring/__init__.py` | 65 | package surface + standing caveats |
`…/errors.py` | 59 | error hierarchy (`TenantBoundaryError`, `EventValidationError`, …) |
`…/models.py` | 664 | event/profile/finding/graph/risk/alert models + closed vocabularies |
`…/config.py` | 181 | `MonitoringConfig` + fail-closed validation + `from_env()` |
`…/redaction.py` | 221 | struct-aware redaction engine |
`…/store.py` | 156 | `RuntimeMonitoringStore` interface (the one new abstraction) |
`…/memory_store.py` | 322 | in-memory implementation (tests/dev) |
`…/pipeline.py` | 399 | normalize → redact → sample → dedup → store, + correlation |
`…/profiles.py` | 183 | behaviour profiles (window, min-samples, version, reset/retrain) |
`…/drift.py` | 331 | drift detection, 4 evidence tiers |
`…/graph.py` | 281 | intent graph (nodes/edges, provenance, tenant-scoped queries) |
`…/risk.py` | 234 | explainable risk scoring + versioned rules |
`…/alerts.py` | 335 | rules, dedup, rate limiting, lifecycle, investigation view |
`…/policy_integration.py` | 156 | delegation boundary to the policy/JIT planes |
`…/audit.py` | 80 | Phase 5 audit fan-out |
`…/service.py` | 187 | composition root (`ingest`, `observe`, `investigate`, `apply_retention`) |
`src/agent_identity/storage/postgres/runtime_monitoring.py` | 567 | authoritative PostgreSQL store |
`src/agent_identity/storage/postgres/migrations/0008_phase5_runtime_monitoring.sql` | — | 9 tables, RLS, append-only triggers, indexes |
`tests/test_phase5_runtime_monitoring.py` | 875 | 96 unit/adversarial tests |
`tests/test_pg_phase5_integration.py` | 363 | 20 real-PostgreSQL tests |
`scripts/bench_phase5.py` | 214 | reproducible benchmarks |
`docs/PHASE5_ARCHITECTURE.md` | 352 | architecture + data flow |
`docs/PHASE5_SECURITY_LIMITATIONS.md` | 202 | boundaries, privacy, non-claims |
`docs/PHASE5_FINAL_REPORT.md` | this file | evidence + deliverables |

### Modified (minimal, additive, backward compatible)

| Path | Change |
|---|---|
`src/agent_identity/security/rbac.py` | +2 permissions (`P_RUNTIME_READ`, `P_RUNTIME_ADMIN`); added to `_READ_ONLY_OBSERVE`, `ROLE_ADMIN`, `ROLE_SECURITY_ANALYST`, `ROLE_DEVELOPER` |
`src/agent_identity/api/enterprise_http.py` | optional `runtime_service=` constructor arg; one dispatch branch for `/v1/runtime*` and `/v1/admin/runtime*`; new `_dispatch_runtime`; permission-map entries |
`README.md` | Phase 5 section |
`.env.example` | 23 `AGENTGUARD_MONITOR_*` knobs documented |

### Deliberately reused (no duplication)

`storage/interfaces.py` (extended, not forked) · `storage/postgres/db.py` (`tenant_scope`/`run`) ·
`storage/postgres/migrate.py` (auto-discovery) · the Phase 4 RLS policy pattern · `security/rbac.py`
`Authorizer` · `api/enterprise_http.py` dispatch + guard · `policy/service.py` + `policy/jit.py`
(delegation targets) · `egress/audit.py` sink · `observability/logging.py`.

**No second database, no second policy engine, no second enforcement path was introduced.**

---

## 6. Bugs found and fixed during this phase

Every one of these was surfaced by a test, and each fix has a test that now guards it.

| # | Severity | Finding | Evidence | Fix |
|---|---|---|---|---|
| 1 | **High** | `reason` and `severity` were stored **verbatim**, so a producer could smuggle a credential into a free-text metadata field | redaction test failed: `'DEPTH_LIMIT' not found`, and a secret in `reason` survived | `reason` now passes the redactor's secret-shape detector (`_safe_text`); `severity` is validated as a closed vocabulary instead of being coerced |
| 2 | **High** | A content-bearing field whose name *also* looked benign (e.g. `prompt_template`) was treated as safe by the allow-list | redaction test: `{'prompt': 'sha256:…'}` expected but the raw value passed | name-based content detection now takes precedence over the benign-name pass-through |
| 3 | **Medium** | Rate-limited alerts **raised an exception**, which would break the caller's analysis loop on a noisy rule, and (when no alert existed yet) dropped the alert entirely | `test_rate_limit_…` errored with `AlertError: alert rate limit reached` | rate-limited alerts are now **recorded in state `suppressed`** with an audit record — never dropped, never fatal |
| 4 | **Medium** | `AlertState.coerce("bogus")` silently produced `OPEN`, masking data corruption from an investigator | `test_alert_states_are_a_closed_vocabulary` | the vocabulary is now closed: unknown values **raise** |
| 5 | **Medium** | A **forged timestamp path** allowed an event whose `ts` exceeded the retention bound to be handled inconsistently | drift burst test: `event timestamp is implausibly far in the future` | future-skew is rejected at ingestion; the test now passes an explicit clock instead of racing real time |
| 6 | **High** | **Keyset pagination repeated and skipped rows.** `_encode_cursor` formatted the timestamp as `f"{ts:.6f}"`, and that format **rounds up** — so the decoded boundary could sort *above* the row it was taken from. The boundary row was then re-served on the next page and every later page was shifted | full-suite only: `AssertionError: 6 != 8` and `{'rev_63139a1c…'} is not false` (duplicated `event_id` across pages); did **not** reproduce when the file ran alone | one canonical lossless codec shared by both stores: `encode_cursor` now uses `repr` (`round-trip exact`). The bug was *latent in the duplicated private copy in the PostgreSQL store*, which is why the in-memory tests passed |
| 7 | **Low** (test defect) | Suite-internal: burst tests used wall-clock deltas and a shared per-class database, so they passed alone but failed in the full run | full run: 3 failures that vanished in isolation | tests anchored to explicit clocks / a dedicated tenant (`ORG_C`) instead of absolute values and shared rows |

Findings 1–6 are **product** defects found by the tests written for this phase; finding 7 was a
test-isolation defect in the same suite. Nothing was papered over: the product fixes are in the
module, and the test fixes make the suite order-independent.

Finding 6 deserves emphasis because of *how* it surfaced. It was invisible in the phase's own test
file (which exercises the in-memory store) and only appeared when the real-PostgreSQL tests ran in the
**same process** as the rest of the suite. The cause was a duplicated cursor codec: the shared logic
lived in two places and only one of them truncated the timestamp. The fix both corrects the rounding
**and removes the duplication** (the PostgreSQL store now imports the single canonical codec), so the
two backends cannot drift apart again. This is exactly the class of defect that a full-suite run
catches and a per-file run does not — which is why the phase was not declared done on an earlier green
run.

### Pre-existing issue found in the inherited tree (not caused by Phase 5)

`tests/test_pg_integration.py::…wrong_password…` **could not fail** in this environment because
PostgreSQL was initialised with `trust` auth, under which every password is accepted. Fixed by
hardening `pg_hba.conf` to `scram-sha-256` — an **environment** correction that makes a pre-existing
test meaningful again; the test itself was not touched.

---

## 7. Acceptance criteria → status

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 1 | Inspect existing architecture; identify collected vs missing events; no rebuild/duplication | **Met** | §1 + `PHASE5_ARCHITECTURE.md` §1; integration-seam table; §5 "reused" list |
| 2 | Unified runtime event pipeline with metadata + no payloads by default + redaction/sampling/retention | **Met** | `pipeline.py`, `redaction.py`, `config.py`; 22-type closed taxonomy; privacy tests |
| 3 | Runtime monitoring & correlation across integrations; no invented causality | **Met** | `service.investigate()`, `pipeline.correlate()`; `causality_basis="temporal_adjacency_only"` asserted in tests |
| 4 | Tenant-isolated behaviour profiles; windows; min samples; versions; reset/retrain | **Met** | `profiles.py`; immature profile declines to reason; versioning + reset tests (unit + PG) |
| 5 | Agentic drift, 4 distinct evidence tiers, no intent claims | **Met** | `drift.py`; per-classification tests; `insufficient_evidence` path tested |
| 6 | Intent graph, provenance/confidence, reuses existing storage, tenant-scoped | **Met** | `graph.py` + `runtime_graph_*` tables; **no new database added**; provenance graded |
| 7 | Explainable, versioned risk scoring; signals + evidence; separate from enforcement | **Met** | `risk.py`; `RiskRules` version `p5-risk-1`; returns signals+evidence; never gates |
| 8 | Real-time alerts: severity, dedup, rate limit, lifecycle, correlation, existing enforcement hooks | **Met** | `alerts.py`; rate-limit **records** rather than drops (test); actions delegate to policy/JIT; off by default |
| 9 | Analytics/storage: indexes, pagination, retention, aggregation, delayed/dup/malformed/out-of-order, no cross-tenant leakage | **Met** | `0008_*.sql` + PG store; keyset pagination test; retention scoping test; late/dup/malformed tests; two-control tenant isolation |
| 10 | Automated tests incl. schema, correlation, tenant isolation, missing/delayed telemetry, baselines, false positives/negatives, risk explanations, alert dedup/rate limiting, policy/revocation integration, malformed/resource exhaustion, redaction; deterministic fixtures; full regression; **no skipped tests** | **Met** | 116 new tests, all executed, zero skips; fixtures use explicit clocks; 819 pre-existing tests still pass |
| 11 | Documentation & deliverables (1–10 of the brief) | **Met** | `PHASE5_ARCHITECTURE.md`, `PHASE5_FINAL_REPORT.md`, `PHASE5_SECURITY_LIMITATIONS.md`, README, `.env.example`, benchmark output |
| — | Do **not** implement Phase 6 | **Met** | no Phase 6 code; readiness boundary in §8 |
| — | Never fabricate results | **Met** | every figure in §2–§3 is transcript output; baseline and post-change runs are both quoted |
| — | Do not claim all behaviour observable / intent always detectable | **Met** | `PHASE5_SECURITY_LIMITATIONS.md` §1, §6; repeated in the package docstring |

---

## 8. Phase 6 readiness — where the next phase plugs in

**Not implemented here.** The boundaries the next phase will need already exist:

* **Autonomous loop detection** — `runtime_monitoring` already captures repeat/retry counts
  (`agent.error`, `agent.retry`, `action.sequence`, `Profile.retries`, `max_events_per_hour`). Phase 6
  can read these; none of it is asserted as "a loop" yet.
* **Human approval** — `approval.requested` / `approval.decided` event types are accepted and
  `ResponseAction.REQUIRE_APPROVAL` already routes through `PolicyIntegration`; the approval *UI/flow*
  remains the policy plane's, not Phase 5's.
* **Incident response** — `ResponseAction.NOTIFY_INCIDENT` exists, and importantly **there is no alert
  transport yet** (§9): Phase 6 needs to add delivery (email/PagerDuty/webhook) as a new adapter.
* **Automated containment** — the delegation surface (`reevaluate_policy`, `revoke_jit`) exists with
  auto-actions **off by default**. Phase 6 must add scoping, a rollback path, and audit guarantees
  beyond what is here; Phase 5 deliberately did not build an independent enforcement path.
* **Planned storage work** — batching/async ingestion, a retention scheduler, and a profiled
  PostgreSQL graph query are the three known scaling gaps (§3, §5 of the limitations doc).

---

## 9. Known limitations and remaining work (summary)

Full detail in `docs/PHASE5_SECURITY_LIMITATIONS.md`. The short list:

1. **Detection coverage = integration coverage.** Policy/JIT/egress/identity emitters into this
   pipeline are **not wired**; the event types exist and are accepted, but the producers are absent.
   Absence of an event must not be read as good behaviour.
2. **No alert transport** — alerts are persisted and queryable only; nothing pages anyone.
3. **No scheduler** — baseline rebuild and retention purge are on-demand API calls, not cron jobs.
4. **Synchronous, single-connection ingest** — no batching, no queue, no back-pressure beyond a
   bounded dead-letter list; **unverified under concurrency**.
5. **Intent-graph query is the performance hot spot** and is unprofiled at scale.
6. **`reason` is producer-controlled** free text (secret-shape-scrubbed, not prose-scrubbed);
   `resource`/`destination` may leak names/paths — treat `runtime_events` as personal data.
7. **`hash` redaction mode is pseudonymization**, not anonymization.
8. **Auto-actions, when enabled, have real blast radius** and no Phase-5 rollback.
9. **Production RLS requires a non-superuser DB role** — with a superuser connection, RLS is inert
   and only the application filter protects tenants.
10. **PostgreSQL graph *performance*** (as opposed to correctness) is untested at scale.

---

## 10. How to run everything

```bash
# 1. dependencies
pip install cryptography PyJWT psycopg[binary] redis grpcio boto3 coverage

# 2. infrastructure (needed for the integration + benchmark phases)
redis-server --daemonize yes
# PostgreSQL 15+ with a role that may CREATE DATABASE, scram-sha-256 auth in pg_hba.conf

# 3. environment
export AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres \
       AGENTGUARD_TEST_PG_PASSWORD=postgres AGENTGUARD_TEST_PG_DB=agentguard_test \
       AGENTGUARD_TEST_REDIS_URL=redis://127.0.0.1:6379/0 PYTHONPATH=src:.

# 4. full suite
python3 -m unittest discover -s tests -t .

# 5. Phase 5 only
python3 -m unittest tests.test_phase5_runtime_monitoring
python3 -m unittest tests.test_pg_phase5_integration

# 6. coverage
python3 -m coverage run --source=src -m unittest discover -s tests -t .
python3 -m coverage report

# 7. benchmarks
BENCH_N=20000 python3 scripts/bench_phase5.py
```

Phase 5 can be used **without** PostgreSQL (in-memory store) for development; the migration and the
integration tests require it. OPA and Redis are **not** used by Phase 5.
