# AgentGuard Phase 6 — Security Limitations & Unimplemented Integrations

This document exists so that no claim in the Phase 6 report exceeds what was actually built and
tested. Read it before relying on the response plane.

---

## 1. What is NOT claimed

* **Not** autonomous defense against every attack. Detection covers the seven patterns in
  `loops.py` over the telemetry that is actually emitted. An attack that produces no telemetry, or
  telemetry no integration emits, is invisible.
* **Not** guaranteed immediate termination of every agent. See §3.
* **Not** cryptographically tamper-proof audit. See §4.
* **Not** a complete credential inventory. See §5.

---

## 2. Detection coverage equals integration coverage

Phase 5's limitation carries forward unchanged: the **producers** that would emit policy, JIT, egress
and identity events into the pipeline are not wired in this repository. The event types exist and are
accepted, but if nothing emits them, the loop detector sees nothing.

**A quiet agent and an unmonitored agent look identical.** This is the single most important
limitation of the phase.

---

## 3. Containment cannot interrupt an agent that does not cooperate

`BudgetService.guard()` is a **server-side boundary**: it refuses operations that pass through it. It
cannot reach into a running agent process.

* An agent runtime that never calls `guard()` is **not constrained by it**.
* `suspend_agent` delegates to the identity plane's `revoke_agent`, which stops *new* authenticated
  operations. It does not kill an in-flight process.
* `isolate_workload` requires a deployment adapter that is **not implemented here**; without one the
  action reports `unavailable`.

**Consequence:** containment is effective at the authorization boundary, not at the process boundary.
Immediate termination is guaranteed only for integrations that actually implement it.

---

## 4. The audit log is a hash chain, not a notarization

`verify_chain()` detects modification, reordering and removal of records **within the stored log**.
It does **not** detect an attacker who rewrites the entire log and recomputes every hash — that
requires publishing the head hash to an external append-only system, which is **not implemented**.

Also: `response_audit` and `response_loop_findings` reject `UPDATE` via a trigger, but `DELETE` is
permitted (the retention path needs it). Append-only here means "no in-place modification", not
"undeletable".

---

## 5. Credential revocation depends on an inventory that may not exist

`revoke_credentials` / `rotate_credentials` call `identity_service.list_credentials(agent_id=…)`.
When that inventory is unavailable the action reports `available: True, performed: False` with
`"no credential inventory available for this agent"` — it does **not** claim to have revoked
anything. A credential the identity plane does not know about cannot be revoked by this plane.

---

## 6. RLS requires a non-superuser database role

Migration 0009 enables Row-Level Security on all eight response tables with the same GUC contract as
migrations 0004–0008. **PostgreSQL exempts SUPERUSER and BYPASSRLS roles from RLS.**

The test suite connects as a superuser (it must, to `CREATE DATABASE`), so it verifies the tenant
boundary two ways that do hold: (a) the application-level `org_id=` filter through the real store, and
(b) the RLS *configuration* (policies present, `rowsecurity` on), plus (c) a live cross-tenant read as
a purpose-created **non-superuser** role that returns no rows.

**Production requirement: the application must connect as a non-superuser role.**

---

## 7. Auto-containment is OFF by default

`containment_allow_auto = False` and `containment_high_impact_requires_approval = True` are the
defaults. Automated containment does not run until an operator explicitly enables it, and high-impact
actions require an approved human decision.

**Blast radius:** `suspend_agent`, `revoke_credentials` and `revoke_jit_grants` are **not reversible**
and have no Phase 6 rollback. `rollback()` reports `skipped` for them with the reason — it never
pretends to have undone them.

---

## 8. Response level selection is conservative by design

A `SUSPICIOUS_REPETITION` (heuristic) finding is **capped at `RESTRICT`** regardless of risk band.
Only a `CONFIRMED_VIOLATION` (contradicts a configured budget) or a critical risk band can reach
`SUSPEND`/`INCIDENT`. This is deliberate: the most disruptive response is never imposed for a
statistical anomaly.

---

## 9. Incident correlation is key-based

Correlation requires a shared `(agent_id, subject)`. A genuinely multi-agent campaign that shares no
subject appears as several incidents. This is a documented coverage limit, not a silent failure.

---

## 10. Evidence digests are not notarization

An evidence digest proves the referenced bytes are unchanged **if the reference is still resolvable**.
It does not survive deletion of the referenced store, and it is not a signature.

---

## 11. Privacy

* No table stores secrets, prompts or payloads. Approvals store a **fingerprint** plus a bounded
  primitive-only `params` bag; evidence stores a **reference + digest**.
* `reason` and `detail` are producer-controlled free text. Treat `response_*` tables as personal data
  and apply the tenant's retention policy.
* The audit `extra` bag accepts only primitives and is bounded — it is not a payload channel.

---

## 12. Stubs, mocks and external dependencies

| Component | Status |
|---|---|
| `PgResponseStore` | **Real**, tested against PostgreSQL 15. |
| `MemoryResponseStore` | **Real** in-memory backend, used by unit tests. |
| Policy / JIT / identity / egress / governance adapters | **Real delegation** to existing services; report `unavailable` when the service is absent. |
| `deployment_adapter.isolate` | **Not implemented** — no deployment integration exists. |
| `ContainmentIntegrations.rollback_action` | **Not implemented** — rollback reports `unavailable`. |
| Alert transport (paging/notification) | **Not implemented** — Phase 6 persists and exposes; it does not notify. |
| Scheduler (baseline rebuild, retention) | **Not implemented** — retention is an on-demand call. |
| External audit anchoring | **Not implemented**. |
| SIEM export | **Not implemented** (next phase). |

---

## 13. Phase 7 boundary (not implemented here)

Self-Healing Policy Intelligence, Tamper-Evident Audit (external anchoring), Compliance Evidence and
SIEM Integrations are **out of scope for this task** and are not implemented. The seams they will need
are in place: `ResponseAudit.chain_head()` exposes the head hash for anchoring, `EvidenceService`
carries retention metadata, and the audit stream is already structured for export.
