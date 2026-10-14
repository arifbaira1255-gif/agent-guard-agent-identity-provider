# Step 11 — Enterprise Tool & Resource Governance

Step 11 adds a **unified resource-governance layer** on top of the Step 9/10 identity + policy plane.
Every protected operation an AI agent wants to perform on a tool, HTTP API, database, file, shell,
cloud service or internal service is authorized **server-side, before it runs**, from the authoritative
registry + policy engine — with explicit, fail-closed decisions and a single enforcement chokepoint.

> **Status:** implemented and tested in this repository against **real OPA, real PostgreSQL 15 and real
> Redis**. See `STEP11_FINAL_REPORT.md` for exact counts and `STEP11_SECURITY_LIMITATIONS.md` for the
> honest boundary of what is and is not enforced.

---

## 1. Architecture

```
                       ┌───────────────────────── ResourceGuard (single chokepoint) ─────────────────────────┐
 agent / SDK / tool ─▶ │ 1 validate ─▶ 2 classify ─▶ 3 resolve registry record ─▶ 4 tenant boundary          │
        adapter        │ ─▶ 5 operation least privilege ─▶ 6 tool-registry checks ─▶ 7 policy decision (Step 10) │
                       │ ─▶ 8 escalation ─▶ 9 audit ─▶10 SEAL an ALLOW                                     │
                       └────────────────────────────────────────────────────────────────────────────────────┘
                                        │ ALLOW (sealed)                    │ anything else
                                        ▼                                   ▼
                              connector executor                    ForbiddenError — executor NEVER runs
```

Components (all under `src/agent_identity/governance/`):

| Module | Responsibility |
|---|---|
| `models.py` | Closed vocabularies (`ResourceType`, `Sensitivity`, `Operation`, `RiskClass`), `ResourceRecord`, `ToolRecord`, `ResourceDescriptor`, `GovernanceDecision` |
| `validation.py` | Rejects wildcards, traversal, braces, over-long ids; flat-primitive metadata only; manifest shape |
| `classifier.py` | Best-effort type/carrier inference used only to *detect* an unclassified value |
| `config.py` | Fail-closed configuration (unknown/unclassified handling ∈ {deny, require_approval}) |
| `registry.py` | `ResourceRegistry` — RBAC-guarded resource lifecycle |
| `tool_registry.py` | `ToolRegistry` — registration, approval, capability grants |
| `guard.py` | `ResourceGuard` — the decision pipeline + the anti-forgery **seal** |
| `connectors.py` | `ResourceConnector` (internal) / `GuardedConnector` (the enforced handle) |
| `service.py` | `GovernanceService` — composition root and the `execute()` entry point |
| `hooks.py` | Installs the governance hook into the HTTP transport's `POST /v1/authorize` |
| `audit.py` | `GovernanceAudit` → PostgreSQL `governance_audit` + `SecurityLogger` |
| `rego/governance.rego` | Example governance policy (complete `else` chain, no `http.send`) |

**Reused, not rebuilt:** the Step 10 `PolicyDecisionService` (policy leg), `JitGrantService`,
`ApprovalProvider`, `PolicyEnforcer` pattern, `security/rbac.py`, `observability/logging.py`, the
PostgreSQL migration/RLS machinery, and the SDK's `ToolGuard` seam.

---

## 2. Supported policy inputs

The guard assembles the policy input **server-side from verified state**. A client can never supply
identity or tenant. The governance registry adds these fields to the Step 10
`PolicyInput.request_context`:

| Field | Source | Trust |
|---|---|---|
| `resource_id`, `operation` | request descriptor | untrusted (validated) |
| `resource_type`, `sensitivity` | **registry** | authoritative |
| `registry_status` | guard (`registered` / absent) | authoritative |
| `permitted_operations[]` | **registry** | authoritative |
| `tool_id`, `tool_risk`, `approved_capabilities[]` | **tool registry** | authoritative |
| `claimed_capabilities[]` | request | untrusted |
| `agent_id`, `tenant`, `capabilities[]` | **verified credential** | authoritative |

Example policy fragment (`rego/governance.rego`):

```rego
decision := {"decision": "REQUIRE_APPROVAL", "reason": "restricted_destructive_operation"} {
    input.request_context.sensitivity == "restricted"
    is_destructive(input.request_context.operation)
    not input.approval.valid
}
```

---

## 3. Policy & JIT lifecycle (reused from Step 10)

* Policies: create → validate → test → **activate** → rollback/disable, versioned and namespaced per
  version in OPA; persisted in PostgreSQL under RLS; append-only audit.
* **JIT grants**: a Step 10 grant is exactly `(org, agent, action, resource)` with a mandatory,
  bounded expiry and immediate revocation. Governance reuses it: a live grant satisfies a
  default-deny, but **never overrides an explicit DENY**, and it is always tenant-scoped.

## 4. Governance lifecycle

**Resource** — register (`resource:write`) → update / enable / disable / delete (`resource:admin`).
Type and tenant are immutable after registration.

**Tool** — register (`tool:write`) → **approve** (`tool:approve`, grants the capability set) →
enable/disable (`tool:admin`) → delete. Registration and approval are **separate authorities**.

---

## 5. Default-deny behaviour

1. No applicable policy and no live grant → `DENY (no_matching_policy)`.
2. Unregistered resource → `DENY (unknown_resource)`; unclassified type → `DENY (unclassified_resource)`.
   Configurable only to `require_approval` — **there is no `allow` option** (`config.py` rejects it).
3. Registered but operation not in `permitted_operations` → `DENY (operation_not_permitted)`.
4. Registered but another tenant → `DENY (tenant_boundary_violation)`.
5. Tool unregistered / unapproved / disabled → `DENY (tool_not_registered | tool_not_approved | tool_disabled)`.
6. Requested capability outside the tool's **approved** set → `DENY (capability_not_approved)`.
7. Policy engine timeout/outage → `INDETERMINATE`, never `ALLOW`.

---

## 6. Administration permissions

| Permission | Grants |
|---|---|
| `resource:read` / `resource:write` / `resource:admin` | read / register+update / enable+disable+delete |
| `tool:read` / `tool:write` / `tool:approve` / `tool:admin` | read / register / approve+grant / enable+disable+delete |

Role defaults: **platform admin** = all; **tenant admin** = all governance perms; **developer** =
read + register (no approve/admin); **security analyst / readonly auditor** = read only.
Permission is checked **before** a record is loaded (no existence leak to unauthorised callers).

---

## 7. Policy decision caching & invalidation

Decision caching is the **Step 10** cache: Redis-backed, **ALLOW only**, keyed by tenant + identity +
action + resource + active policy version, bounded TTL, with a per-tenant generation counter bumped by
any policy activation/rollback, JIT issue/revoke or approval decision (so no stale ALLOW survives an
invalidation), and fail-closed on a cache-backend error.

Governance adds **no** cross-request cache of its own: the resource/tool registry record is read
authoritatively on **every** decision, so a registry change (disable, un-approve, permission removal,
tenant move) takes effect on the very next request with no staleness window.

> **Measured note:** the governance benchmark does **not** wire the Redis cache, so it reports the
> *uncached* decision cost (see §10). No cache-hit benefit is claimed anywhere in this step.

---

## 8. Operational failure modes

| Failure | Behaviour |
|---|---|
| OPA engine down / timeout | `INDETERMINATE` → deny (fail closed) |
| Registry/DB error | `INDETERMINATE` → deny (fail closed) |
| Approval provider error | treated as "no approval" → `REQUIRE_APPROVAL` |
| Malformed descriptor | `DENY (malformed_*)`, no exception escapes the guard |
| Decision seal consumed/expired | `ForbiddenError`, executor not run |

## 9. Example policies & testing

* Example policy: `src/agent_identity/governance/rego/governance.rego`.
* Tests: `tests/test_governance_unit.py` (real OPA CLI + in-memory stores) and
  `tests/test_governance_pg_integration.py` (real PostgreSQL + migration 0006 + RLS).

Reproducible commands:

```bash
# unit (real OPA binary required)
PYTHONPATH=src:. python3 -m unittest -v tests.test_governance_unit

# real PostgreSQL integration (spins up a throwaway database + migrations 0001..0006)
AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres \
AGENTGUARD_TEST_PG_PASSWORD=postgres PYTHONPATH=src:. \
  python3 -m unittest -v tests.test_governance_pg_integration
```

## 10. Deployment

1. Apply migrations: `python -m agent_identity.storage.postgres migrate` (adds 0006: `resources`,
   `tools`, `governance_audit`).
2. Build the store: `create_governance_store(db)` and the service:
   `GovernanceService(store, policy_service, config=GovernanceConfig.from_env())`.
3. Register connectors: `svc.register_connector(HttpApiConnector())` — hand adapters the returned
   **guarded** handle, never the raw connector.
4. Install the transport hook: `agent_identity.governance.install_governance(svc)`.
5. Expose admin routes: `EnterpriseHttpApi(..., governance_service=svc)`.
6. Configure via env: `AGENTGUARD_GOV_UNKNOWN_POLICY`, `AGENTGUARD_GOV_UNCLASSIFIED_POLICY`,
   `AGENTGUARD_GOV_ESCALATE_AT`, `AGENTGUARD_GOV_APPROVE_DESTRUCTIVE`,
   `AGENTGUARD_GOV_REQUIRE_TOOL_APPROVAL` (all values fail closed).

---

## 11. API surface (transport)

| Route | Method | Permission |
|---|---|---|
| `/v1/admin/resources` | GET / POST | `resource:read` / `resource:write` |
| `/v1/admin/resources/{id}` | GET / DELETE | `resource:read` / `resource:admin` |
| `/v1/admin/resources/{id}/(update\|enable\|disable)` | POST | `resource:write` / `resource:admin` |
| `/v1/admin/tools` | GET / POST | `tool:read` / `tool:write` |
| `/v1/admin/tools/{id}` | GET / DELETE | `tool:read` / `tool:admin` |
| `/v1/admin/tools/{id}/(approve\|enable\|disable)` | POST | `tool:approve` / `tool:admin` |
| `/v1/authorize` | POST | credential + (optional) resource descriptor |

`POST /v1/authorize` gains an **optional** governed-target body: `resource_id`, `operation`,
`resource_type?`, `tool?`, `requested_capabilities?`. When present the full governance pipeline runs;
when absent the Step 10 behaviour is unchanged. Only the **decision** is returned — the seal stays
server-side.

## 12. Integration boundary for Step 12

`ResourceGuard.decide/enforce`, `GovernanceService.execute`, `ResourceConnector.perform`, the
`connectors` registry, `GovernanceConfig` and the `governance_audit` table are the seams Step 12
(egress gateway & DLP) builds on. A `GuardedConnector` is where an egress/DLP-filtered transport will
be substituted for the reference `HttpApiConnector`. **No Step 12 code is implemented here.**
