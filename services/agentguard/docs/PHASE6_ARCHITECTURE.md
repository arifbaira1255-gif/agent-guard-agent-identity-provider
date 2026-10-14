# AgentGuard Phase 6 — Architecture

**Autonomous Loop Detection, Risk-Based Human Approval, Incident Management, Automated Containment,
Credential/Permission Revocation, Cross-Component Response Orchestration, Evidence Preservation and
Safe Failure Handling.**

Phase 6 adds a **response plane** on top of Phases 1–5. It introduces **no second database, no second
event pipeline and no competing authorization path**: every enforcement action delegates to a mechanism
that already exists.

---

## 1. Where it sits

```
  Phase 5 (detection)                 Phase 6 (response)                    Existing enforcement
  ───────────────────                 ──────────────────                    ────────────────────
  runtime events ──┐
  behavioral profile│                 ┌──────────────┐
  intent graph      ├──► LoopDetector │  findings    │
  drift findings    │                 └──────┬───────┘
  risk assessment ──┘                        │ classification + risk band
                                             ▼
                                    ┌──────────────────┐
                                    │ select_level()   │  observe / require_approval /
                                    └────────┬─────────┘  restrict / suspend / incident
                                             ▼
                                    ┌──────────────────┐        ┌──────────────────────────┐
                                    │  Orchestrator    │───────►│ policy engine (deny,     │
                                    │  (state machine, │        │   require approval)      │
                                    │   idempotent)    │───────►│ JIT grant service        │
                                    └────────┬─────────┘        │ identity plane (suspend, │
                                             │                  │   revoke/rotate creds)   │
                                    ┌────────▼─────────┐        │ egress gateway (block)   │
                                    │ ContainmentEngine│───────►│ governance registry      │
                                    │ (delegating)     │        │   (disable tool)         │
                                    └────────┬─────────┘        │ budget boundary (limit)  │
                                             │                  │ deployment adapter       │
                                    ┌────────▼─────────┐        │   (isolate workload)     │
                                    │ Evidence + Audit │        └──────────────────────────┘
                                    └──────────────────┘
```

**Separation of concerns is structural, not aspirational.** `loops.py` detects. The Phase 5 risk
engine assesses. `orchestrator.py` coordinates. `containment.py` delegates. Nothing in Phase 6 can
*allow* an operation — the strongest action available is to tighten.

---

## 2. Module map (`src/agent_identity/response/`)

| Module | Responsibility |
|---|---|
| `config.py` | Fail-closed configuration. **Auto-containment OFF by default.** |
| `models.py` | Net-new records + closed vocabularies + the operation fingerprint. |
| `store.py` | Storage interface (PostgreSQL authoritative, memory for tests). |
| `memory_store.py` | In-memory backend (lock-guarded, insertion-ordered audit). |
| `loops.py` | Loop/runaway detection: 7 patterns, bounded windows, explainable evidence. |
| `budgets.py` | Execution budgets + emergency stops — the **server-side enforcement boundary**. |
| `approvals.py` | Risk-based human approval bound to an operation fingerprint. |
| `incidents.py` | Incident lifecycle + conservative correlation. |
| `containment.py` | Containment engine + adapters over existing enforcement mechanisms. |
| `orchestrator.py` | Idempotent, auditable response state machine with rollback. |
| `evidence.py` | Evidence preservation (references + digests, sealing, retention). |
| `audit.py` | Hash-chained response audit log. |
| `service.py` | Composition root. |

Storage: `src/agent_identity/storage/postgres/response.py` + migration
`0009_phase6_response.sql` (8 tables, RLS, append-only triggers).

---

## 3. Detection (`loops.py`)

Seven patterns over a bounded per-`(org, agent)` observation window:

| Pattern | Signal |
|---|---|
| `repeated_action` | N invocations of the same `(action, resource)` |
| `circular_invocation` | A→B→A cycle repeated ≥2× |
| `excessive_retry` | N `agent.retry` events for one subject |
| `repeated_denial` | N authorization denials for one subject |
| `egress_repetition` | N outbound requests to one destination |
| `cascade_failure` | Failures across ≥N distinct operations |
| `resource_burn` | Tokens/cost over the configured budget |

**Classification is honest by construction:**

* `CONFIRMED_VIOLATION` is emitted **only** when the observed count contradicts an authoritative
  configured budget. A heuristic threshold can never reach it.
* `SUSPICIOUS_REPETITION` is the ceiling for heuristic signals.
* `INSUFFICIENT_EVIDENCE` when telemetry is too sparse — sparsity is never treated as suspiciousness.
* Every finding carries its `evidence` tuple and the threshold that produced it.

---

## 4. Budgets and emergency stops (`budgets.py`)

`BudgetService.guard()` is the enforcement entry point. It **raises** rather than advising:

1. An active emergency stop is checked **first** — a stop cannot be bypassed by a generous budget.
2. The budget is consumed **atomically in the store** (PostgreSQL: one conditional
   `UPDATE … RETURNING`; memory: a lock-guarded read-modify-write). A refused operation never
   advances the counter.
3. If the budget store cannot be read, `budget_fail_closed` (default **True**) refuses the operation
   and records `fail_closed=True`, so "over budget" and "could not establish a budget" are
   distinguishable.

Dimensions: `actions`, `retries`, `requests`, `concurrency`, `tokens`, `cost`, plus a wall-clock
`deadline`. Scoping: task budget (more specific) → agent budget.

---

## 5. Human approval (`approvals.py`)

Every request carries `operation_fingerprint(org_id, agent_id, action, resource, params)` — a SHA-256
over the canonical operation. `check()` recomputes it and refuses on mismatch, so **a modified request
cannot reuse an approval granted for a different action, resource, tenant or parameter set**.

* Separation of duties (default on): the requester cannot approve their own request.
* Expiry is evaluated against the injected clock; an expired PENDING approval is transitioned to
  `EXPIRED` and never satisfies a check.
* Delegation is recorded. Pending requests are capped per agent.
* Approver tenant membership and required permission are verified; refusals are audited.

---

## 6. Incidents (`incidents.py`)

Lifecycle: `detected → triage → investigating → containment → recovery → closed → post_review`, with
validated transitions and a bounded timeline.

**Correlation is key-based, never time-based.** Two detections join one incident only when they share
`(agent_id, subject)`. Time proximity alone is explicitly insufficient — unrelated events that merely
happened close together stay separate incidents.

---

## 7. Containment (`containment.py`)

Every action delegates through a duck-typed adapter and reports `available: False` when its mechanism
is not configured — it never pretends success.

| Action | Delegates to | Impact | Reversible |
|---|---|---|---|
| `deny_protected_operations` | policy engine | high | yes |
| `require_approval` | policy engine | medium | yes |
| `revoke_jit_grants` | JIT grant service | high | no |
| `suspend_agent` | identity plane | high | no |
| `revoke_credentials` | identity plane | high | no |
| `rotate_credentials` | identity plane | high | no |
| `block_destination` | egress gateway | medium | yes |
| `disable_tool` | governance registry | medium | yes |
| `limit_budget` | budget boundary | low | yes |
| `isolate_workload` | deployment adapter | high | no |

Safety: `containment_allow_auto` defaults **False**; high-impact actions require an approved human
decision by default; `authorized_by` must be a verified identity from the caller's context (an
agent-generated string is not accepted); every action is scoped and audited.

---

## 8. Orchestration (`orchestrator.py`)

```
PLANNED ──► RUNNING ──► SUCCEEDED
   │           │    └──► PARTIAL
   │           └───────► FAILED
   └──► SUCCEEDED (observe-only)
              SUCCEEDED/PARTIAL/FAILED ──► ROLLED_BACK | ROLLBACK_FAILED
```

* **Idempotency** — keyed by `(org_id, idempotency_key)`; a duplicate delivery returns the existing
  execution. Enforced by a UNIQUE index in PostgreSQL, so it holds across processes.
* **Concurrency** — a per-`(org, agent)` lock serializes overlapping containment for one target.
* **Evidence before destruction** — evidence is preserved and **sealed** before any non-reversible
  step.
* **Honest outcomes** — any failed step yields `PARTIAL`; nothing applied yields `FAILED`. Success is
  never reported for a plan that did not fully apply.
* **No privilege escalation on recovery** — rollback only relaxes a reversible action and requires a
  verified identity.

---

## 9. Evidence and audit (`evidence.py`, `audit.py`)

Evidence stores **references and digests**, never raw payloads. Sealed evidence is exempt from
retention purging — that is the mechanism used to preserve evidence before a destructive step.

The audit log is a **hash chain**: each record carries `prev_hash` and
`hash = SHA-256(prev_hash | canonical record)`. `verify_chain()` recomputes it and reports the first
divergence, so a modified, reordered or removed record is **detected**.

> **Stated precisely:** this is a hash chain, **not a notarization**. An attacker with write access to
> the whole log could recompute every subsequent hash and produce a self-consistent chain. Detecting
> that requires external anchoring, which is **not implemented**. Do not describe this as
> cryptographically tamper-proof.

---

## 10. API surface

| Method | Route | Permission |
|---|---|---|
| GET | `/v1/response/findings` | `response:read` |
| GET | `/v1/response/budgets` | `response:read` |
| GET | `/v1/response/emergency-stops` | `response:read` |
| GET | `/v1/response/approvals` · `/v1/response/approvals/{id}` | `response:read` |
| GET | `/v1/response/incidents` · `/v1/response/incidents/{id}` | `response:read` |
| GET | `/v1/response/executions` · `/v1/response/executions/{id}` | `response:read` |
| GET | `/v1/response/evidence` | `response:read` |
| GET | `/v1/response/audit` · `/v1/response/audit/verify` | `response:read` |
| GET | `/v1/response/health` | `response:read` |
| POST | `/v1/response/evaluate` · `/v1/response/observe` | `response:admin` |
| POST | `/v1/response/approvals` | `response:admin` |
| POST | `/v1/response/approvals/decide/{id}` | **`response:approve`** |
| POST | `/v1/response/approvals/cancel/{id}` · `/delegate/{id}` | `response:admin` |
| POST | `/v1/admin/response/budgets` · `DELETE …/budgets/{id}` | `response:admin` |
| POST | `/v1/admin/response/emergency-stop` · `…/emergency-stop/{id}` | `response:admin` |
| POST | `/v1/admin/response/incidents` · `…/incidents/{id}/transition\|resolve\|post-review` | `response:admin` |
| POST | `/v1/admin/response/contain` | `response:admin` |
| POST | `/v1/admin/response/executions/{id}/rollback` | `response:admin` |
| POST | `/v1/admin/response/evidence` · `…/evidence/{id}/seal` · `…/retention` | `response:admin` |

When the service is not wired, the whole surface 404s and every existing route is unchanged.

---

## 11. Failure handling

| Failure | Behaviour |
|---|---|
| Budget store unavailable | **Fail closed** for protected operations (`budget_fail_closed=True`). |
| Policy service unavailable | Containment step recorded `failed`; execution becomes `PARTIAL`/`FAILED`. Never a false success. |
| Credential revocation fails | Recorded per-credential (`revoked`/`failed` counts); the step is not reported as applied. |
| Approval service unavailable | `check()` returns no approval → the caller fails closed. |
| Telemetry delayed/incomplete | `INSUFFICIENT_EVIDENCE`; no escalation on sparsity. |
| Agent cannot be interrupted | Documented limitation — see the security/limitations doc. |
| Containment partially succeeds | `PARTIAL` with `partial_failures` listing each step. |
| Audit store cannot accept events | The action still executes; the audit failure is surfaced, not swallowed. |
