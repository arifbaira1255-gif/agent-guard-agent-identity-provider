# Phase 7 — Assurance Plane Architecture

Self-Healing Policy Intelligence · Tamper-Evident Audit · Compliance Evidence · SIEM Integration

## 1. Purpose and scope

Phase 7 adds an **assurance plane** on top of Phases 1–6. It does not replace or duplicate any
existing service: it consumes the signals those services already produce, and it routes every policy
change back through the **existing policy engine**. It introduces **no second database, no second
event pipeline and no competing authorization path**.

| Capability | Module | Reuses |
|---|---|---|
| Self-healing policy intelligence | `assurance/recommendation_engine.py` | evidence from policy/DLP/drift/incident planes |
| Safe policy lifecycle | `assurance/lifecycle.py` | `policy.service.PolicyDecisionService`, `policy.engine.validate_rego` |
| Tamper-evident audit | `assurance/audit.py` | `kms.interfaces.KeyManagementProvider`, `crypto.encoding` |
| Compliance evidence | `assurance/compliance.py` | audit chain, evidence store |
| SIEM integration | `assurance/siem.py` | `observability.logging.SecurityLogger` |
| Event correlation | `assurance/correlation.py` | runtime event vocabulary |
| Composition root | `assurance/service.py` | injected into `api/enterprise_http.py` |

## 2. Component and data-flow diagram

```
                    ┌──────────────────────── trusted signals ────────────────────────┐
                    │ authorization_denial · policy_violation · dlp_detection ·       │
                    │ drift_alert · incident · suspicious_tool_use · admin_feedback · │
                    │ false_positive                                                  │
                    └───────────────────────────────┬─────────────────────────────────┘
                                                    ▼
   POST /v1/admin/assurance/evidence      ┌──────────────────────────┐
   ──────────────────────────────────────▶│  SecurityEvidence store  │  (reference + SHA-256
                                          └────────────┬─────────────┘   digest, never payload)
                                                       ▼
   POST /v1/admin/assurance/analyze       ┌──────────────────────────┐
   ──────────────────────────────────────▶│  RecommendationEngine    │  observed_facts /
                                          │  (explainable, gated)    │  heuristic_conclusions /
                                          └────────────┬─────────────┘  proposed_change
                                                       ▼
                                          ┌──────────────────────────┐
                                          │  PolicyRecommendation    │  confidence + uncertainty
                                          └────────────┬─────────────┘
                                                       ▼  (human decides to open a proposal)
   POST /v1/admin/assurance/proposals     ┌──────────────────────────────────────────────┐
   ──────────────────────────────────────▶│  PolicyLifecycleService                      │
                                          │  draft→validated→simulated→pending_approval  │
                                          │  →approved→canary→active→rolled_back         │
                                          └───────┬───────────────────────┬──────────────┘
                                                  │                       │
                        validate_rego + static    │                       │  create_policy /
                        security checks           │                       │  create_version /
                                                  ▼                       ▼  activate / rollback
                                          ┌──────────────┐        ┌──────────────────────┐
                                          │  PolicyEngine│        │ PolicyDecisionService│
                                          │  (existing)  │◀───────│  (existing, reused)  │
                                          └──────────────┘        └──────────────────────┘
                                                  │
   every transition ──────────────────────────────┼──────────────────────────────────────┐
                                                  ▼                                      │
                                          ┌──────────────────────────┐                   │
                                          │  TamperEvidentAudit      │  hash chain +      │
                                          │  (append-only, signed)   │  Ed25519 signature │
                                          └────────────┬─────────────┘  + checkpoints     │
                                                       ▼                                 │
   GET /v1/assurance/audit/verify ──────────▶ verify_chain + verify_checkpoint            │
                                                                                         │
   runtime events ──▶ CorrelationService (normalize · dedup · correlate) ─────────────────┘
                              │
                              ▼
                     ┌──────────────────┐   classification gate → redaction → queue →
                     │  SiemService     │   batch → bounded retry → delivery status
                     └────────┬─────────┘
                              ▼
        syslog_tls · syslog_tcp · http · splunk_hec · elastic_bulk · webhook
```

## 3. Storage

One new migration, `0010_phase7_assurance.sql`, additive only. Nine tables:

`assurance_evidence`, `assurance_recommendations`, `assurance_proposals`,
`assurance_compliance_mappings`, `assurance_siem_events`, `assurance_siem_deliveries`,
`assurance_correlations`, `assurance_audit`, `assurance_checkpoints`.

* Tenant-scoped tables carry `org_id` and run under **Row-Level Security** with the same GUC contract
  as migrations 0004–0009 (`app.current_org`, `app.platform_admin`).
* `assurance_audit` is **append-only against UPDATE** (a trigger rejects it) and is ordered by a
  global `insert_order` counter; the record's own per-tenant `seq` is part of the hashed content.
* `assurance_compliance_mappings` is platform-wide with a UNIQUE `(framework, control_id)` index, so
  the seed catalogue is idempotent.

Two backends implement one interface (`assurance/store.py`): `PostgresAssuranceStore` (authoritative)
and `MemoryAssuranceStore` (unit tests / single-process dev).

## 4. Provenance model

Every record carries an explicit `provenance`:

| Value | Meaning |
|---|---|
| `observed_fact` | a directly recorded, authoritative observation |
| `heuristic` | a rule/pattern conclusion drawn from observations |
| `derived` | an aggregate/analytics output computed from other records |
| `recommendation` | a proposed action — **never** an observation |

A recommendation is never presented as a fact; a correlation finding is `derived` and references the
original event ids rather than replacing them.

## 5. HTTP surface

All routes are optional: when `assurance_service` is not injected, `/v1/assurance*` and
`/v1/admin/assurance*` return 404 and every existing route is unchanged.

| Method | Route | Authority |
|---|---|---|
| GET | `/v1/assurance/recommendations[/{id}]` | `assurance:read` |
| GET | `/v1/assurance/proposals[/{id}]` | `assurance:read` |
| GET | `/v1/assurance/audit` · `/audit/verify` · `/audit/checkpoints` | `assurance:read` |
| GET | `/v1/assurance/compliance/controls` · `/compliance/report` | `assurance:read` |
| GET | `/v1/assurance/siem/destinations` · `/siem/deliveries` | `assurance:read` |
| GET | `/v1/assurance/correlations` · `/health` | `assurance:read` |
| POST | `/v1/admin/assurance/evidence` · `/analyze` | `assurance:admin` |
| POST | `/v1/admin/assurance/compliance/seed` | `assurance:admin` |
| POST | `/v1/admin/assurance/siem/events` · `/siem/flush` · `/correlate` | `assurance:admin` |
| POST | `/v1/admin/assurance/audit/checkpoint` | `assurance:admin` |
| POST | `/v1/admin/assurance/proposals` | `policy:write` |
| POST | `/v1/admin/assurance/proposals/{id}/{validate,simulate,submit}` | `policy:read` |
| POST | `/v1/admin/assurance/proposals/{id}/decide` | `assurance:approve` |
| POST | `/v1/admin/assurance/proposals/{id}/{canary,canary-record,activate,rollback}` | `policy:activate` |
| POST | `/v1/admin/assurance/emergency` | `policy:write` |

## 6. RBAC additions

Three new permissions, deliberately split so the identity that authors a change is not the identity
that authorizes it:

* `assurance:read` — investigation (recommendations, audit, compliance, SIEM status, correlations)
* `assurance:admin` — configuration (evidence, analysis, compliance seeding, SIEM destinations)
* `assurance:approve` — approve/reject a policy proposal

Role grants: platform admin (all three); tenant admin (all three); security analyst
(`read` + `approve`); security operator (`read` + `admin`); developer (`read`); read-only auditor
(`read`).

## 7. Reliability and operational safety

* **Health** — `GET /v1/assurance/health` reports audit-chain status, signature requirement, SIEM
  queue depth, per-destination health and delivery metrics; `status` is `degraded` when the chain
  fails to verify or the queue is full.
* **Fail-closed audit** — when the audit store cannot be written, the protected operation is refused
  (`audit_fail_closed=True`). A SIEM outage does **not** stop the security plane
  (`siem_fail_closed=False`), but the failure is always recorded and surfaced.
* **Backpressure** — a full queue either rejects (fail closed, surfaced) or drops the oldest
  (explicit, recorded as `dead_letter`). Never a silent drop.
* **Bounded retries** — exponential backoff with jitter, capped; exhaustion dead-letters the event.
* **Rate limiting** — a per-destination events/second ceiling; a rate-limited pass re-queues rather
  than dropping.

## 8. What this phase does NOT do

* It does not implement the next phase (Enterprise Dashboard, API, CLI, Observability, Developer
  Platform).
* It does not claim certification, perfect autonomous remediation or absolute audit immutability.
* It does not verify live vendor SIEM endpoints (see `PHASE7_SECURITY_LIMITATIONS.md`).
