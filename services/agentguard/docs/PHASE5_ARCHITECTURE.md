# AgentGuard Phase 5 — Architecture

**Scope:** Runtime Monitoring, Agent Behaviour Intelligence, Intent Graph & Agentic Drift Detection.
A single consolidated observability / intelligence plane layered on top of Steps 1–11 and Phase 4.

---

## 1. Where Phase 5 sits

Phase 5 is **additive and read-mostly**. It does not replace, wrap or reinterpret any earlier phase,
and it never becomes an enforcement point.

```
                 Step 10 Policy Engine  ── authoritative ALLOW / DENY / REQUIRE_APPROVAL
                          ▲                        │
                          │ delegates only         │ decisions
                          │ (never bypasses)       ▼
┌─────────────────────────┴──────────────────────────────────────────────────────┐
│  PHASE 5  runtime_monitoring                                                   │
│                                                                                │
│  ingest ─► normalize ─► redact ─► sample ─► dedup ─► store ──┬─► profiles      │
│                                                              ├─► intent graph  │
│                                                              ├─► drift         │
│                                                              ├─► risk          │
│                                                              └─► alerts ─► response actions
│                                                                                │
│  store = RuntimeMonitoringStore  (Memory…  |  PgRuntimeMonitoringStore)        │
└────────────────────────────────────────────────────────────────────────────────┘
                 ▲                                          │
   existing telemetry (Phase 4 egress/DLP, governance,       │ /v1/runtime/*
   policy audit, identity audit, SDK producers)               │ /v1/admin/runtime/*
```

### Integration seams actually used

| Seam | How Phase 5 uses it | Direction |
|---|---|---|
| `storage/interfaces.py` | Phase 5 adds **one** interface (`RuntimeMonitoringStore`); no new database technology | read/write (own tables only) |
| `storage/postgres/migrate.py` | migration `0008_phase5_runtime_monitoring.sql`, auto-discovered by version prefix | additive |
| `storage/postgres/db.py` | `tenant_scope()` / `run()` — every Phase 5 SQL statement goes through it | reuse |
| `security/rbac.py` | adds `runtime:read`, `runtime:admin`; granted to read-only-observer, admin, analyst, developer | additive |
| `api/enterprise_http.py` | adds `/v1/runtime/*` and `/v1/admin/runtime/*` behind the existing dispatch + permission guard | additive |
| `policy/service.py`, `policy/jit.py` | **outbound only** — response actions call the policy plane; it stays authoritative | delegate |
| `egress/audit.py` sink | Phase 5 audit records fan out to the same audit pipeline | emit |
| `observability/logging.py` | no payload logging; `reason` codes only | emit |

**Nothing existing was modified within its own behaviour.** The only edits to pre-existing files are:
`security/rbac.py` (two new permissions, added to four role sets), `api/enterprise_http.py` (a new
optional constructor argument, one dispatch line, new route handlers), `README.md`, `.env.example`.

---

## 2. Runtime event pipeline

`pipeline.RuntimeEventPipeline`

```
raw dict ─► alias resolution ─► required-field check ─► EventType.coerce (CLOSED vocabulary)
        ─► ts validation (future skew / retention horizon) ─► tenant claim check
        ─► Redactor (struct-aware) ─► sampler ─► dedup ─► store.put_event ─► horizon update
```

Every normalised event carries the canonical envelope:

| Field | Meaning |
|---|---|
| `event_id` | server-assigned `rev_…` (never trusted from the producer) |
| `org_id` | **tenant** — the isolation key for every read and write |
| `agent_id`, `instance_id`, `session_id` | actor + runtime instance |
| `event_type` | closed vocabulary (see below) |
| `ts` / `ingested_at` | producer time / server time |
| `action`, `resource`, `resource_type` | what was done, to what |
| `decision`, `outcome`, `reason` | policy outcome and error/deny reason |
| `policy_id`, `policy_version` | which policy version decided |
| `destination`, `address_class` | egress target and its class |
| `data_classes`, `dlp_rule_ids` | classification / DLP rule references |
| `severity`, `latency_ms` | producer-supplied severity, duration |
| `correlation_id`, `trace_id`, `span_id`, `parent_span_id` | correlation + trace context |
| `actor_user_id`, `task_id` | human actor, trusted-app task context |
| `late`, `redacted`, `sampled` | **integrity flags** — the consumer can see what happened to the record |
| `dedup_key`, `extra` | idempotency key, redacted metadata bag |

### Event taxonomy (22 ingestible types)

`agent.initialized`, `agent.identity.changed`, `agent.terminated`,
`tool.invocation`, `api.invocation`,
`authorization.decision`, `authorization.failure`,
`jit.grant.created`, `jit.grant.expired`, `jit.grant.revoked`,
`data.access`, `file.access`, `network.request`,
`dlp.detection`, `dlp.blocked`,
`approval.requested`, `approval.decided`,
`policy.changed`, `policy.enforcement.failure`,
`agent.error`, `agent.retry`, `action.sequence`.

`action.sequence` is in the vocabulary but is **derived** — it is emitted by the correlation layer
and is *rejected* at ingestion (`DERIVED_EVENT_TYPES`), so a producer cannot forge a correlated
sequence.

### Failure semantics — deliberate, not accidental

| Condition | Behaviour | Why |
|---|---|---|
| malformed event (bad type, missing field, bad ts) | **rejected**, never stored | garbage must not poison the baseline |
| `ts` > now + `max_future_skew_s` | **rejected** | a forged future timestamp would defeat the retention guard and the late detector |
| `ts` < now − `max_event_age_s` | **rejected** | retention horizon is enforced at the door |
| `ts` < max_seen − `late_threshold_s` | **stored**, `late=True` | out-of-order arrival is normal, not an error |
| duplicate `dedup_key` (same tenant) | **deduplicated**, not stored | idempotent consumers |
| duplicate `event_id` | **deduplicated** | replay protection |
| sampling | **stored**, `sampled=True` | sampled-in records are flagged so stats can be weighted |
| unknown event type | **rejected** (closed vocabulary) | silently inventing a type would hide producer bugs |
| failing store | routed to a bounded dead-letter list; `IngestResult(rejected)` | no memory blow-up under an outage |

---

## 3. Privacy / redaction engine

`redaction.Redactor` — the single gate through which **all** free-form data reaches storage.

1. **Immediate drop** of a denylist of payload-bearing keys (`prompt`, `completion`, `messages`,
   `content`, `body`, `payload`, `credentials`, `password`, `token`, `secret`, `authorization`, …)
   — including nested and case/`-`/`_`-variant spellings.
2. **Allow-list pass-through** for a fixed set of non-sensitive operational keys (`tool_id`,
   `method`, `status_code`, `port`, `protocol`, `direction`, `grant_id`, …).
3. **Content-shape detection** — a *value* containing an obvious prompt/credential shape is redacted
   **even under an innocuous key**, so a producer cannot smuggle content through `extra.note`.
4. **Value-shape secret detection** — AWS keys, GCP keys, GitHub/Slack tokens, JWTs, PEM key
   material, `Bearer …`, `user:pass@host` URLs.
5. **Depth limit** (`redaction_max_depth`, default 6) → `"DEPTH_LIMIT"` so a deeply nested payload
   cannot exhaust the walker; key count and value length are capped too.
6. Modes: `drop` (default) / `hash` (mode-tagged non-reversible digest) / `mask`.

**Redaction is unconditional.** There is no config path that disables it; config only selects the
mode and the depth.

---

## 4. Correlation

`pipeline.correlate()` + `service.investigate()`

An investor-facing action sequence is assembled **only** from IDs the telemetry actually carries:

* events are grouped by `correlation_id` when present, else by `trace_id`, else treated as a
  standalone single-event sequence (provenance `single_event`);
* ordering within a group is by `ts` (producer time), with `ingested_at` retained for auditors;
* the sequence records `which agent → which tool/resource → what decision → what followed → whether
  it was blocked, approved or completed`.

**Honest-causality rule (enforced in code, not just docs):** when no correlation/trace ID links two
events, Phase 5 reports them as **temporally adjacent, not causally related**
(`causality="unknown"`, `causality_basis="temporal_adjacency_only"`). It never asserts a causal chain
it cannot evidence.

`service.investigate()` returns one bundle: sequences, related drift findings, risk assessments,
graph chains and open alerts — all scoped to one tenant.

---

## 5. Behaviour profiles

`profiles.BehaviorProfileService`, model `BehaviorProfile`

Learnable, tenant-isolated, versioned. Per `(org_id, agent_id)` it accumulates: tool / resource /
destination / action / decision / data-class frequencies, hourly histogram, action-sequence patterns,
denial / failure / retry counts, privileged-action and sensitive-read counts, peak events-per-hour.

* **Configurable learning window** (`learning_window_s`, default 7 days) — only events inside the
  window feed the profile.
* **Minimum sample threshold** (`default_min_samples`, default 50) — `is_mature` is **False** below
  it, and every consumer (drift, risk, graph) *declines to reason* from an immature profile.
  Insufficient data is never treated as evidence of anything.
* **Versioning** — every build/retrain increments `version`; `reset()` clears the baseline, records
  the reset in the audit log with the acting user, and starts again at v1.
* **Incremental vs full** builds are compared in tests to prove the two code paths agree.

---

## 6. Drift detection

`drift.DriftDetector` — findings, never verdicts. Each finding carries
`classification`, `category`, `observed`, `expected`, `evidence[]`, `confidence`.

| Check | Category | Classification when triggered |
|---|---|---|
| tool not in declared capabilities | `unauthorized_tool` | `confirmed_violation` |
| tool outside declared tool set | `unexpected_tool` | `confirmed_violation` |
| destination outside declared/observed set | `unexpected_destination` | `confirmed_violation` / `statistical_anomaly` |
| repeated authorization denials ≥ threshold | `repeated_denials` | `heuristic_suspicion` |
| action frequency ≥ baseline × multiplier | `access_burst` | `statistical_anomaly` |
| action sequence unseen in a mature baseline | `suspicious_sequence` | `heuristic_suspicion` |
| sensitive-resource access pattern | `unusual_data_access` | `heuristic_suspicion` |
| not enough telemetry to judge | — | `insufficient_evidence` (explicit) |

The four classifications are *structurally* distinct:

* **`confirmed_violation`** — the observation contradicts an **authoritative** source (declared
  capabilities, policy). Evidence tier `authoritative`.
* **`statistical_anomaly`** — deviates from a **mature** baseline beyond a configured threshold.
  Evidence tier `baseline`.
* **`heuristic_suspicion`** — matches a pattern rule with no authoritative contradiction. Evidence
  tier `heuristic`.
* **`insufficient_evidence`** — emitted rather than guessing when the baseline is immature.

**Drift means "observed behaviour departs from the approved envelope". Phase 5 never claims to know
an agent's internal intent from telemetry.** The word "intent" in "intent graph" refers to the
*relationship model*, not a claim about cognition.

---

## 7. Intent graph

`graph.IntentGraph` over the existing store — **no second database was introduced.**

* **Nodes** (`NodeKind`): `agent`, `identity`, `task`, `tool`, `resource`, `policy`, `permission`,
  `event`, `data_class`, `destination`.
* **Edges** (`EdgeKind`): `agent_tool`, `agent_resource`, `agent_destination`, `agent_policy`,
  `agent_task`, `task_resource`, `event_subject`, `resource_destination`.

Every edge carries `count`, `first_seen`, `last_seen`, `provenance`, `confidence`.

**Provenance is explicit and graded** so an investigator can discount weak links:

| Provenance | Confidence | Meaning |
|---|---|---|
| `direct_observation` | 1.0 | the event *directly* states this relationship |
| `derived` | 0.6 | inferred from a canonical field (e.g. resource + destination on one event) |
| `repeated_pattern` | 0.5 | observed ≥ N times (statistical, not asserted) |

`agent_task` edges only ever come from **task context supplied by a trusted application**; Phase 5
never invents a task→resource scope.

Queries: `agent_toolchain()`, `shortest_path()`, `suspicious_chains()`, `stats()`. Every query and
every mutation takes `org_id` and is tenant-filtered; `clear()` requires an acting user for the audit
trail.

---

## 8. Risk scoring

`risk.RiskScorer` + versioned `RiskRules`

Eight configurable, versioned signals: `policy_violation`, `dlp_finding`, `destination_risk`,
`behavioral_deviation`, `repeated_auth_failure`, `abnormal_frequency`, `sensitive_resource_access`,
`correlated_suspicion`.

Output is **explainable and complete**:

```json
{ "score": 67.5, "band": "high",
  "rule_version": "p5-risk-1",
  "signals": [ {"kind":"policy_violation","weight":25,"observed":3,"threshold":1,"detail":"…"} ],
  "evidence": ["…"] }
```

**Stated limits, not merely implied:**

* It is a **weighted heuristic**, not a statistically calibrated or scientifically validated
  predictor. Nothing in the codebase calls it a prediction.
* It is **advisory**. The score never gates an operation. Enforcement stays with the policy engine.
* Thresholds ship with the calibrated band cuts (`band_thresholds()`) and are exercised by fixtures
  in the test suite so a change in weights is visible.

---

## 9. Alerts and response

`alerts.AlertService`

* **Severity** `low|medium|high|critical`; **rule**-driven (`min_severity`, `event_types`,
  `drift_classes`, `risk_threshold`).
* **Deduplication** — same `(rule, agent, drift_class/title)` inside `dedup_window_s` increments
  `occurrence_count` on the existing open alert instead of creating a new one.
* **Rate limiting** — beyond `max_per_window` per `rate_window_s` the alert is **recorded in state
  `suppressed`** (never silently dropped, never raised to the caller as a hard failure) and an
  audit record `runtime.alert.rate_limited` is written. An investigator can always see what was
  suppressed.
* **Lifecycle** — `open → acknowledged → investigating → resolved`, plus `suppressed`; transitions
  are validated and audited, with the acting user.
* **Investigation view** — `investigation_view(alert_id)` returns the alert, its related events,
  any drift finding and any risk assessment, tenant-scoped.
* **Response actions** are **off by default** (`allow_auto_actions=False`). When an operator enables
  them, the four available actions — `reevaluate_policy`, `revoke_jit`, `require_approval`,
  `notify_incident` — are dispatched through `PolicyIntegration` to the **existing policy/JIT
  planes**. Phase 5 has no enforcement path of its own; it cannot allow or deny anything.

---

## 10. Storage and scale

`storage/postgres/runtime_monitoring.py` + `migrations/0008_phase5_runtime_monitoring.sql`

Nine tables: `runtime_events`, `runtime_behavior_profiles`, `runtime_drift_findings`,
`runtime_graph_nodes`, `runtime_graph_edges`, `runtime_risk_assessments`, `runtime_alert_rules`,
`runtime_alerts`, `runtime_monitoring_audit`.

* **Append-only** — `runtime_events` and `runtime_monitoring_audit` carry a `BEFORE UPDATE OR
  DELETE` trigger that raises (`append-only`), so telemetry cannot be rewritten. Verifying this is a
  test, not a claim.
* **RLS on all nine tables** — `USING (org_id = current_setting('app.current_org', true)
  OR current_setting('app.platform_admin', true) = 'on')`, following the Phase 4 pattern exactly.
* **Indexes for the real query shapes** — `(org_id, ts DESC)`, `(org_id, agent_id, ts DESC)`,
  `(org_id, correlation_id)`, `(org_id, trace_id)`, `(org_id, event_type, ts DESC)`,
  `(org_id, dedup_key)` unique, alert-rate `(org_id, rule_id, ts DESC)`, findings-by-class,
  graph `(org_id, kind)`, `(org_id, src_kind, src_id)`.
* **Keyset cursor pagination** — `(ts, event_id)` cursor; ordered `ts DESC, event_id DESC`. Verified
  against real PostgreSQL that pages neither duplicate nor skip, including at boundaries.
* **Retention** — `purge_before(cutoff, org_id=…)` is org-scoped and deletes only old rows (tested:
  another tenant's rows are untouched).
* **Aggregation** — `aggregate_by_type()`, `count_events()`, `count_by_agent()` push the reduction
  into SQL rather than pulling rows into Python.
* **Cross-tenant leakage prevention** — belt **and** braces: the application filters `org_id` on
  every query *and* RLS enforces it at the database. Both are tested, the second one against a real
  non-superuser role.

---

## 11. HTTP surface

| Method | Route | Permission |
|---|---|---|
| GET | `/v1/runtime/events` | `runtime:read` |
| GET | `/v1/runtime/investigate` | `runtime:read` |
| GET | `/v1/runtime/profiles`, `/v1/runtime/profiles/{agent_id}` | `runtime:read` |
| GET | `/v1/runtime/findings` | `runtime:read` |
| GET | `/v1/runtime/risk` | `runtime:read` |
| GET | `/v1/runtime/graph`, `/v1/runtime/graph/suspicious` | `runtime:read` |
| GET | `/v1/runtime/alerts`, `/v1/runtime/alerts/{alert_id}` | `runtime:read` |
| GET | `/v1/runtime/health`, `/v1/runtime/metrics` | `runtime:read` |
| POST | `/v1/runtime/ingest` | `runtime:admin` |
| POST | `/v1/runtime/observe` | `runtime:admin` |
| GET/POST | `/v1/admin/runtime/rules` | `runtime:read` / `runtime:admin` |
| DELETE | `/v1/admin/runtime/rules/{rule_id}` | `runtime:admin` |
| POST | `/v1/admin/runtime/profiles/{agent_id}/{rebuild,reset,retrain}` | `runtime:admin` |
| POST | `/v1/admin/runtime/alerts/{alert_id}/{acknowledge,investigate,resolve,suppress}` | `runtime:admin` |
| POST | `/v1/admin/runtime/retention` | `runtime:admin` |
| POST | `/v1/admin/runtime/graph/clear` | `runtime:admin` |

**Tenant resolution is fail-closed**: a non-platform-admin may not name a foreign `org_id` (the
request is rejected, not silently retargeted); a platform admin may. When `runtime_service` is not
wired, the whole surface 404s and the rest of the API is byte-for-byte unchanged.

---

## 12. Configuration

All knobs are `AGENTGUARD_MONITOR_*` and are documented in `.env.example`; every one is validated in
`MonitoringConfig.validate()` with a bounded range (no unbounded retention, no zero windows, no
negative thresholds). Defaults are conservative: payload-bearing fields dropped, sampling **off**,
auto-actions **off**, retention 30 days.

See `docs/PHASE5_SECURITY_LIMITATIONS.md` for what Phase 5 explicitly does **not** guarantee, and
`docs/PHASE5_FINAL_REPORT.md` for the measured evidence.
