# AgentGuard Phase 5 — Security Boundaries, Privacy & Known Limitations

This document is deliberately unflattering. It states what Phase 5 **does not** guarantee, so an
operator can make an informed decision rather than trusting a summary.

---

## 1. What Phase 5 can and cannot observe

Phase 5 sees **only** what instrumented code emits. The ingest path is real and tested, but
coverage is bounded by the telemetry producers.

**Uninstrumented by default — these paths are invisible unless a producer is wired:**

| Path | Status |
|---|---|
| Step 10 policy engine decisions | event types exist and are accepted; the policy service does **not** emit them yet |
| JIT grant lifecycle (`jit.grant.*`) | event types accepted; no emitter wired in this environment |
| Phase 4 egress / DLP detections | event types accepted; the egress module does not push to this pipeline yet |
| Governance approval decisions | event types accepted; no emitter wired |
| Identity / instance lifecycle | event types accepted; identity service does not emit |
| Any tool/API call the integration does not wrap | **invisible** |

Consequences an operator must accept:

* **Absence of an event is not evidence that nothing happened.** A quiet agent and an unmonitored
  agent look identical. Phase 5 never reports "no drift detected" as "the agent behaved correctly".
* Drift checks that depend on a field (e.g. `destination`) are **silently inapplicable** when the
  producer omits that field. The suite covers the missing-telemetry case, but the honest framing is:
  *detection coverage equals integration coverage.*
* `chain` / "downstream actions followed" analysis is limited to what correlation and trace IDs
  link. Without them, Phase 5 reports temporal adjacency and says so.

### Events not modelled at all
Phase 5 has no event type for model/weights changes, prompt-injection attempts detected inside a
model, memory/RAG store mutation, or tool-schema drift. These are out of scope for this phase.

---

## 2. What, precisely, is redacted — and what is not

**Redacted by default:** full prompts, completions, message arrays, request/response bodies, file
contents, credentials, tokens, private keys, connection strings, and any value matching a known
secret shape — anywhere they appear, including nested and under innocuous keys.

**NOT redacted — carry these with care:**

| Field | Why it survives | Risk |
|---|---|---|
| `resource` | needed to know *what* was touched | may embed a path, table, queue or bucket name (possible data-shape leak) |
| `destination` | needed for destination-risk and egress analysis | may reveal internal hostnames/topology |
| `reason` | needed to distinguish a deny from an error | free text — a producer can encode content here |
| `action`, `resource_type`, `address_class` | needed for behaviour baselining | low |
| `policy_id`, `tool_id`, grant IDs | needed for correlation | identifiers, not secrets |
| `agent_id`, `instance_id`, `session_id`, `actor_user_id` | the subjects of investigation | **personal data in a GDPR sense** |

`reason` is passed through the redactor's secret-shape detector, so a credential pasted into it is
pseudonymized — but `reason` is **not** scrubbed of ordinary prose. Treat it as producer-controlled.

**Operational consequences:**

* `runtime_events` is **not** a safe place for personal data. Retention (default 30 days) and access
  control (`runtime:read`) are the only mitigations; there is no per-field encryption.
* The **hash** redaction mode produces a deterministic, unsalted digest. It is fine for correlation
  ("are these two the same prompt?") but it is a **dictionary-attackable** pseudonym, not
  anonymization. Do not treat hashed payloads as de-identified data.
* Redaction happens **at ingestion**. Nothing scrubs already-stored rows if you later discover a
  field you wish you had dropped — you must purge (`/v1/admin/runtime/retention`) and re-ingest.
* Phase 5 logs no payloads; the alert/audit records contain IDs, counts and reason codes only.

---

## 3. Tenant isolation — verified, with one caveat

Two independent controls, both tested (`tests/test_pg_phase5_integration.py`):

1. **Application filter** — every read/write passes `org_id=`; cross-tenant reads return empty.
2. **Row-Level Security** — all nine tables have RLS enabled with a tenant-scoped policy.

The caveat, stated plainly:

> **PostgreSQL exempts SUPERUSER and BYPASSRLS roles from RLS.** The test role in this environment is
> a superuser (it must be, to `CREATE DATABASE`), so a test that ran as the superuser would *pass
> whether or not RLS worked*. That is why the suite (a) asserts the RLS *configuration* — policies
> present, `rowsecurity` on, no `USING (true)` policy — **and** (b) runs a live cross-tenant read as a
> purpose-created **non-superuser, non-BYPASSRLS** role, which is the test that actually proves
> enforcement.

**Production requirement:** the application must connect as a **non-superuser, non-BYPASSRLS** role
with `SELECT/INSERT` (plus `DELETE` for retention) on the `runtime_*` tables only. If it connects as
a superuser, control (2) is inert and only the application filter protects tenants. This is not
optional hardening — it is the difference between one control and two.

Neither control protects against an operator who holds the application's DB credentials and runs
their own SQL. Isolation is against *tenants*, not against the platform itself.

---

## 4. Alerts, response actions and their blast radius

* **Automated containment is OFF by default** (`allow_auto_actions=False`). No response action fires
  unless an operator enables it *and* attaches it to a rule via `auto_actions`.
* Phase 5 **cannot allow or deny anything.** Its only response verbs delegate to the Step 10 policy /
  JIT planes. There is no Phase 5 enforcement path to bypass — this is a structural property, not a
  configuration choice.
* Consequences to accept when enabling auto-actions: a **false positive can trigger a real policy
  reevaluation or JIT revocation**, i.e. availability impact on a legitimate agent. Rate limiting
  caps alert volume but does **not** suppress the first action in a window. There is no built-in
  rollback for an action already taken by the policy plane; recovery is the policy plane's
  (re-grant) responsibility.
* **Suppressed** alerts are recorded, not dropped — but the responder must look at
  `state=suppressed` to see them. They do **not** page anyone.

---

## 5. Where the numbers come from — and what they do not mean

The benchmark (`scripts/bench_phase5.py`, results in `PHASE5_FINAL_REPORT.md`) is
**single-process, no-warmup, in-memory (except one PostgreSQL phase), one run, no concurrency.**
It measures code-path cost. It is **not** a capacity guarantee and **not** a load test. Specifically:

* The ingest path is **synchronous** and, for PostgreSQL, **one transaction per event on one
  connection** — the ~1.1k events/s figure is a single-connection floor, not a scalable ceiling.
  There is no batching, no async writer and no queue; those are Phase 6+ work.
* The **intent-graph query is the hot spot** (~135 ms p50 at ~20 k edges): the in-memory store
  performs an edge scan and the chain search is super-linear in edges. At larger graphs this will
  degrade further. The PostgreSQL store uses the graph indexes, but no graph query has been profiled
  at scale.
* Alert raising (~5.3 k/s) includes dedup and rate-limit checks against an in-memory store; against
  PostgreSQL each raise is a query plus a write.
* **Nothing here has been tested under concurrent writers.** Race behaviour at the store is
  unverified.

---

## 6. Explicit non-claims

Phase 5 does **not** claim, and the code does not attempt:

* that **all** AI behaviour can be observed;
* that **malicious intent** can be detected — only that observed activity departed from a declared or
  learned envelope;
* that risk scores are **validated predictions** of anything;
* that a clean result means an agent is safe;
* that the drift/risk thresholds are **calibrated** for your environment — they are defaults with
  fixtures, not tuned to production data;
* that **real-time** performance was achieved — the pipeline is synchronous and measured, not
  streamed or benchmarked under load;
* that the **hash** redaction mode anonymizes data;
* immunity to a **compromised producer** — a producer that emits well-formed, allow-listed events can
  bias a baseline over time (there is no producer attestation in this phase).

---

## 7. Environment-specific notes from this build

Recorded because they materially affect what "tests pass" means here.

1. **PostgreSQL authentication.** The cluster was initialised with `trust` auth, which made the
   pre-existing wrong-password test (`test_pg_integration.py`) unable to fail, because *any* password
   is accepted. `pg_hba.conf` was hardened to `scram-sha-256` so the suite exercises real
   authentication. **This was an environment fix, not a change to the test.**
2. **`CREATE ROLE` takes no bind parameters.** The first version of the RLS test used a parameter
   placeholder, which PostgreSQL rejects for utility statements (`syntax error at or near "$1"`).
   The role-creation literals are now in-file constants with a run-scoped name; nothing user-supplied
   is interpolated into DDL.
3. **Retention horizon vs. clock.** Ingestion rejects events older than `max_event_age_s`. Test
   fixtures therefore anchor an event timestamp **relative to the wall clock**, not to a hardcoded
   epoch constant — a fixed epoch would have meant "impossible in the past" and the fixtures would
   have failed for the wrong reason. This is fail-closed behaviour working correctly, and it is
   documented rather than worked around.
4. **`ag_%` databases and roles accumulate.** Throwaway per-class databases and per-run roles are
   dropped in `tearDownClass`; the earlier failed runs had to be cleaned from the cluster manually
   before the suite could be trusted.
5. **A pagination defect was visible only in a full-suite run.** The PostgreSQL store carried a
   *duplicate* keyset-cursor codec that formatted the timestamp as `f"{ts:.6f}"`. That format
   **rounds up**, so the decoded boundary could sort above the row the cursor was taken from, making a
   page walk re-serve the boundary event and shift every later page. The in-memory tests passed
   throughout; the defect reproduced only when the PostgreSQL tests ran in the same process as the
   rest of the suite. It is fixed (one canonical lossless codec, `repr`, shared by both stores). The
   general lesson is recorded here because it is a real limitation on confidence: **a per-file green
   run does not establish correctness for this codebase** -- the full suite must be run, and more than
   once.

---

## 8. Dependencies on external infrastructure

| Capability | Needs | Status here |
|---|---|---|
| Durable event storage | PostgreSQL | **exercised** (real PG 15) |
| All of Phase 5 in-memory | nothing | **exercised** |
| Response actions (`reevaluate_policy`, `revoke_jit`, …) | Step 10 policy/JIT services | integration boundary implemented; pre-existing service behaviour unchanged; end-to-end dispatch **not** exercised against a live policy engine |
| Trace/correlation context | producer-supplied IDs | honoured when present; **absent** by default from current producers |
| Alert notification/escalation delivery | **not implemented** | alerts are stored and queryable; no email/PagerDuty/Slack transport exists in this phase |
| Redis / OPA | not used by Phase 5 | Phase 5 neither reads nor needs them |
| Behaviour baselines | accumulated telemetry | near-empty on a fresh deployment; drift will correctly report `insufficient_evidence` until `min_samples` is reached |

---

## 9. Still stubbed, mocked or unready

* No alert **transport** (only persistence + query).
* No **streaming/queue** ingestion; no back-pressure beyond the bounded dead-letter list.
* No **scheduled** baseline rebuild or retention sweep — both are on-demand calls
  (`/v1/admin/runtime/profiles/{id}/rebuild`, `/v1/admin/runtime/retention`). No cron/scheduler is
  registered, so retention does not run itself.
* No **UI**; everything is API + Python.
* The **policy engine and JIT emitters** for policy/JIT event types are not wired (see §1).
* The **PostgreSQL graph-query path** is implemented and covered by integration tests for
  upsert/read, but its *performance* is unprofiled at scale.