# Phase 7 — Policy Recommendation & Approval Workflow

## 1. What the system does and does not claim

The recommendation engine **analyzes trusted security signals and proposes policy improvements**. It
is a recommendation engine, not an autonomous policy author.

* It does **not** claim to reliably infer every attack.
* It does **not** claim to automatically discover perfect policies.
* It **never** activates a policy. A newly generated policy cannot become active solely because a
  model recommended it.

## 2. Trusted signal sources

| Signal | Meaning | Direction |
|---|---|---|
| `authorization_denial` | a policy decision denied a request | gap / review |
| `policy_violation` | a confirmed policy violation | tighten |
| `dlp_detection` | a DLP finding at the egress boundary | tighten |
| `drift_alert` | an Agentic Drift alert | tighten |
| `incident` | an incident investigation | tighten |
| `suspicious_tool_use` | a repeated suspicious tool-use pattern | tighten |
| `admin_feedback` | approved administrative feedback | corroborates a gap |
| `false_positive` | a confirmed false-positive investigation | loosen |

## 3. Epistemic discipline

Every recommendation keeps three layers **separate** and never conflates them:

* `observed_facts` — what the signals actually recorded (counts, subjects, sources, severity),
* `heuristic_conclusions` — what the rules infer, explicitly labelled as inference,
* `proposed_change` — the recommendation itself (an action, not a fact).

`confidence` and `uncertainty` are both explicit. A recommendation whose confidence is below
`recommendation_min_confidence` (default 0.35) is emitted as `review` (no change) rather than as an
actionable proposal. Every recommendation carries its `test_requirements` and `rollback_plan`.

### Confidence model (heuristic, documented)

For a tighten recommendation: `confidence = min(0.95, 0.4 + 0.1·min(count,5) + 0.05·severity_rank)`.
More corroborating signals and higher severity raise confidence, capped at 0.95 — the cap encodes
that counts alone can never be certain. A repeated authorization denial **without** corroborating
admin feedback is emitted as `review` with confidence ≤ 0.5, because the same pattern is equally
consistent with an agent probing its limits.

## 4. Lifecycle

```
draft ──validate──▶ validated ──simulate──▶ simulated ──submit──▶ pending_approval
                                                                        │
                                              ┌─────── decide ─────────┤
                                              ▼                         ▼
                                          rejected                  approved
                                                                        │
                                                          ┌── start_canary ──▶ canary
                                                          │                      │
                                                          │        record_canary │ (healthy + enough samples)
                                                          ▼                      ▼
                                                       rejected              activate
                                                                                 │
                                                                                 ▼
                                                                              active
                                                                                 │
                                                                          rollback
                                                                                 ▼
                                                                            rolled_back
```

Every transition is recorded in the tamper-evident audit chain with the actor and a note.

## 5. Hard guarantees

1. **No auto-activation.** `proposal_allow_auto_activate` defaults to `False`; activation requires an
   explicit, authorized call.
2. **Approval required.** `proposal_require_approval` defaults to `True`; a proposal must be approved
   before activation.
3. **Separation of duties.** The proposal creator may not approve their own proposal. A high-impact
   change (impact ≥ `proposal_high_impact_level`, default `high`) requires **two distinct approvers**.
4. **Checksum binding.** An approval is bound to the proposal's current checksum, so a proposal
   modified after an approval cannot reuse it.
5. **Static security checks.** A change that would silently broaden privilege, weaken tenant
   isolation or disable a required control is refused (`UnsafeChangeError`). The checks are
   **heuristic text checks** — a guardrail, not a proof of safety.
6. **Schema validation.** The proposed Rego is validated through the existing
   `policy.engine.validate_rego` before it is stored.
7. **Simulation before activation.** A proposal can be run against representative events; the summary
   is recorded.
8. **Canary.** A canary serves a fraction of traffic; it auto-rejects when the observed deny-rate
   delta exceeds `proposal_canary_max_deny_delta` and cannot be promoted before
   `proposal_canary_min_samples` healthy samples.
9. **Rollback.** An active proposal can be rolled back to a previously validated version through the
   existing policy engine, which retains retired versions for exactly this purpose.
10. **Emergency path.** An emergency change is marked `emergency`, still requires an authorized actor,
    is still validated (including the static checks) and audited, and is flagged for mandatory
    post-hoc review. It does **not** bypass the static security checks.

## 6. Operator workflow (example)

```bash
# 1. record trusted signals (or let the existing planes feed them)
curl -X POST /v1/admin/assurance/evidence -d '{"kind":"dlp_detection","summary":"...","agent_id":"a1"}'

# 2. analyze -> recommendations (explainable, never auto-applied)
curl -X POST /v1/admin/assurance/analyze

# 3. open a proposal from a recommendation (policy:write)
curl -X POST /v1/admin/assurance/proposals -d '{"proposed_rego":"...","impact_level":"high"}'

# 4. validate -> simulate -> submit
curl -X POST /v1/admin/assurance/proposals/{id}/validate
curl -X POST /v1/admin/assurance/proposals/{id}/simulate -d '{"cases":[...]}'
curl -X POST /v1/admin/assurance/proposals/{id}/submit

# 5. two distinct approvers decide (assurance:approve)
curl -X POST /v1/admin/assurance/proposals/{id}/decide -d '{"decision":"approved"}'

# 6. canary, then activate (policy:activate)
curl -X POST /v1/admin/assurance/proposals/{id}/canary
curl -X POST /v1/admin/assurance/proposals/{id}/canary-record -d '{"samples":50,"deny_delta":0.02}'
curl -X POST /v1/admin/assurance/proposals/{id}/activate

# 7. roll back if needed
curl -X POST /v1/admin/assurance/proposals/{id}/rollback -d '{"to_version":1}'
```

## 7. Configuration

| Env var | Default | Effect |
|---|---|---|
| `AGENTGUARD_ASSURANCE_REC_MIN_SIGNALS` | 2 | minimum corroborating signals |
| `AGENTGUARD_ASSURANCE_REC_REPEAT_THRESHOLD` | 3 | repeats before a pattern is treated as real |
| `AGENTGUARD_ASSURANCE_REC_MIN_CONFIDENCE` | 0.35 | below this → `review`, not actionable |
| `AGENTGUARD_ASSURANCE_PROPOSAL_REQUIRE_APPROVAL` | true | approval before activation |
| `AGENTGUARD_ASSURANCE_PROPOSAL_ALLOW_AUTO_ACTIVATE` | false | never auto-activate |
| `AGENTGUARD_ASSURANCE_PROPOSAL_HIGH_IMPACT_TWO_APPROVERS` | true | two distinct approvers for high impact |
| `AGENTGUARD_ASSURANCE_PROPOSAL_CANARY_FRACTION` | 0.1 | canary traffic fraction |
| `AGENTGUARD_ASSURANCE_PROPOSAL_CANARY_MAX_DENY_DELTA` | 0.25 | canary auto-reject threshold |

In production, `proposal_require_approval` must be `True` (enforced at config construction).
