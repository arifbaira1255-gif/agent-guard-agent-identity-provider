# AgentGuard Phase 4 — Enterprise Egress Security, DLP, Network Enforcement & Tool Governance

**Status:** implemented, integrated, tested. This document is the architecture + data-flow reference
for the Phase 4 plane. It is deliberately explicit about what is enforced and what is not.

> **Honest scope statement (read first).** Phase 4 is an **application-level** egress control plane.
> It governs outbound traffic that is *routed through it*. It does **not** transparently intercept
> all machine traffic. Transparent interception requires OS/container/network configuration
> (network namespace, egress proxy, or firewall) — see
> [`PHASE4_SECURITY_LIMITATIONS.md`](PHASE4_SECURITY_LIMITATIONS.md) for the exact deployment
> requirements and the list of bypass paths. No claim of universal network enforcement is made.

---

## 1. What Phase 4 adds (and what it reuses)

Phase 4 is **additive**. It does not modify the Step 1–11 tables, interfaces or behaviour. It adds a
new `agent_identity.egress` package and wires it into the existing enforcement boundary.

| Capability | Where it lives | Reuses |
|---|---|---|
| Tool & resource governance | `governance/` (Step 11) | unchanged; extended with an egress leg |
| Secure egress gateway | `egress/gateway.py` | Step 10 policy engine, Step 11 seal pattern |
| Network access enforcement | `egress/addresses.py`, `egress/policy.py` | — |
| Data Loss Prevention | `egress/dlp.py` | — |
| Sensitive data detection & redaction | `egress/dlp.py` | — |
| Security policy integration | `egress/rego/egress.rego` | Step 10 OPA engine |
| Runtime authorization & audit | `egress/audit.py`, `egress/service.py` | Step 1–11 audit + `SecurityLogger` |
| Adversarial testing | `tests/test_egress_*.py` | existing test harness |

---

## 2. Architecture

```
                          ┌──────────────────────────────────────────────────────────┐
   agent / tool / SDK ───▶│  ResourceGuard.authorize_egress_and_run(...)              │
                          │  (governance/guard.py)  ── the REAL enforcement boundary  │
                          └───────────────┬──────────────────────────┬───────────────┘
                                          │ leg 1                    │ leg 2
                                          ▼                          ▼
                          ┌────────────────────────┐   ┌──────────────────────────────────┐
                          │ Step 11 governance     │   │ SecureEgressGateway.decide(...)   │
                          │ decide() → sealed ALLOW│   │ (egress/gateway.py)               │
                          └────────────────────────┘   └───────────────┬──────────────────┘
                                                                       │
        ┌──────────────────────────────────────────────────────────────┼───────────────────────┐
        │ 1 validate  2 parse  3 rate-limit  4 SSRF/address  5 destination policy  6 DLP        │
        │ 7 policy engine (tighten-only)  8 combine  9 audit  10 seal                            │
        └──────────────────────────────────────────────────────────────┬───────────────────────┘
                                                                       │ sealed ALLOW only
                                                                       ▼
                                                       ┌───────────────────────────────┐
                                                       │ EgressHttpConnector.send(...)  │
                                                       │ (pinned to validated IPs)      │
                                                       └───────────────────────────────┘
```

### 2.1 The two-leg enforcement boundary

`ResourceGuard.authorize_egress_and_run` composes **two** chokepoints, and the executor runs only
when **both** are sealed ALLOWs:

1. **Governance leg** (`ResourceGuard.decide`) — *may this agent touch this resource?* (Step 11:
   resource registry, sensitivity, permitted operations, risk, policy engine).
2. **Egress leg** (`SecureEgressGateway.decide`) — *may this payload leave to this destination?*
   (destination policy + SSRF/address protection + DLP).

A DENY / REQUIRE_APPROVAL / INDETERMINATE from **either** leg raises `ForbiddenError` and the
executor is never reached. This is what makes the control real at the execution boundary rather than
SDK-side: the SDK cannot reach the network without passing both.

`GuardedEgressConnector` (`governance/connectors.py`) binds a connector to the guard + gateway and
exposes **only** that composed path — there is no `.perform` passthrough and no raw accessor.

### 2.2 The egress decision pipeline (fail closed at every step)

| # | Step | Fail-closed behaviour |
|---|---|---|
| 1 | Validate request (tenant, agent, URL, method, body size) | malformed → DENY |
| 2 | Parse URL (scheme/host/port) | non-HTTP(S) scheme → DENY |
| 3 | Rate limit (tenant+agent token bucket) | exhausted → DENY (`rate_limited`) |
| 4 | **SSRF address validation** (resolve once, classify every address) | any blocked class → DENY |
| 5 | **Destination policy** (host/protocol/port match) | no match → default (deny / require_approval) |
| 6 | **DLP** (inspect outbound payload) | block / require_approval / redact / allow; inspection failure → INDETERMINATE → configured failure action |
| 7 | Policy engine (Step 10, optional) | outage → INDETERMINATE; can only **tighten** |
| 8 | Combine | DENY > INDETERMINATE > REQUIRE_APPROVAL > ALLOW |
| 9 | Audit | every outcome recorded |
| 10 | Seal | ALLOW is sealed; `enforce` accepts only a sealed, single-use, short-lived ALLOW |

### 2.3 DNS-rebinding defence

A hostname is resolved **once**; every returned address is classified; the request is **pinned** to
the validated address set. A hostname that resolves to *any* blocked class is denied (a mixed answer
is treated as hostile). Redirects are re-validated through the same pipeline on every hop. This
defeats the classic TOCTOU rebinding attack: the gateway connects to the address it validated, not
to a fresh resolution.

---

## 3. Data flow (a governed outbound request)

```
SDK.governed_request(url, body)
  └─▶ POST /v1/egress/request  (RBAC: policy:read)
        └─▶ EgressService.request(...)
              └─▶ SecureEgressGateway.decide(...)
                    ├─ rate limit ──────────────▶ audit egress.rate_limited
                    ├─ SSRF/address ────────────▶ audit egress.ssrf.blocked
                    ├─ destination policy ──────▶ audit egress.request.denied
                    ├─ DLP ─────────────────────▶ audit egress.dlp.{clean,redacted,blocked,approval_required,indeterminate}
                    ├─ policy engine (tighten) ─▶ (Step 10 audit)
                    └─ seal ALLOW ──────────────▶ audit egress.request.allowed
              └─▶ (sealed ALLOW only) EgressHttpConnector.send(...)
                    └─ redirect? re-validate each hop ─▶ audit egress.redirect.blocked
        ◀── {"decision": {...}, "response": {...}}
```

Every audit event carries: agent id, tenant, destination, host, port, protocol, resource id,
operation, decision, reason, policy id + version, DLP rule ids, DLP severity, resolved address
**class** (never the payload), correlation id, latency. **No secrets, no payloads, no connection
strings are ever recorded.**

---

## 4. Configuration

All configuration is environment-driven and fail-closed. There is deliberately **no "allow
everything" knob**.

| Env var | Default | Meaning |
|---|---|---|
| `AGENTGUARD_ENV` | `development` | `development` \| `staging` \| `production` |
| `AGENTGUARD_EGRESS_DEFAULT_ACTION` | `deny` | no-match action: `deny` \| `require_approval` (never `allow`) |
| `AGENTGUARD_EGRESS_VALIDATE_DNS` | `true` | resolve + classify hostnames |
| `AGENTGUARD_EGRESS_REVALIDATE_REDIRECTS` | `true` | re-validate every redirect hop |
| `AGENTGUARD_EGRESS_ALLOW_REDIRECTS` | `false` | follow redirects by default (per-policy opt-in) |
| `AGENTGUARD_EGRESS_MAX_REDIRECTS` | `3` | redirect cap (1..10) |
| `AGENTGUARD_EGRESS_MAX_REQUEST_BYTES` | `1048576` | outbound body ceiling |
| `AGENTGUARD_EGRESS_MAX_RESPONSE_BYTES` | `4194304` | inbound body ceiling |
| `AGENTGUARD_EGRESS_CONNECT_TIMEOUT_MS` | `2000` | connect timeout |
| `AGENTGUARD_EGRESS_READ_TIMEOUT_MS` | `10000` | read timeout |
| `AGENTGUARD_EGRESS_MAX_CONCURRENCY` | `64` | bounded concurrency gate |
| `AGENTGUARD_EGRESS_RATE_PER_SECOND` | `20` | default sustained rate |
| `AGENTGUARD_EGRESS_RATE_BURST` | `40` | default burst |
| `AGENTGUARD_DLP_ENABLED` | `true` | enable DLP |
| `AGENTGUARD_DLP_FAILURE_ACTION` | `block` | inspection failure: `block` \| `require_approval` |
| `AGENTGUARD_DLP_MAX_INSPECT_BYTES` | `524288` | DLP inspection ceiling |
| `AGENTGUARD_DLP_MAX_DEPTH` | `12` | structured-payload walk depth |
| `AGENTGUARD_DLP_INSPECT_ENCODED` | `true` | decode base64/percent/hex once and re-scan |
| `AGENTGUARD_EGRESS_SEAL_TTL_S` | `30` | decision-seal TTL |
| `AGENTGUARD_EGRESS_AUDIT_ENABLED` | `true` | enable egress audit |

Secrets (outbound credentials) are supplied by the caller/connector and are **never** stored in
egress config or in the egress tables.

---

## 5. Migration

Migration `0007_phase4_egress_dlp.sql` is applied by the existing `migrate.py` (checksummed,
advisory-locked, forward-only). It is **additive**: it creates `egress_policies` and `egress_audit`
and does not touch any Step 1–11 table.

```bash
# apply all migrations (0001..0007)
PYTHONPATH=src:. python -m agent_identity.storage.postgres.migrate
```

`egress_audit` is append-only (a trigger rejects UPDATE/DELETE). Both tables run under Row-Level
Security with the same GUC contract as migrations 0004–0006 (`app.current_org`, `app.platform_admin`).

---

## 6. SDK & API

### 6.1 Python SDK

```python
from agentguard_sdk import AgentGuardClient

client = AgentGuardClient(...)
out = client.governed_request(
    url="https://api.stripe.com/v1/charges", method="POST",
    body={"amount": 1000}, resource_id="api:stripe", operation="write")
# out == {"decision": {...}, "response": {...}}
if not out["decision"]["allowed"]:
    ...  # handle DENY / REQUIRE_APPROVAL / INDETERMINATE explicitly

# or raise on a non-ALLOW:
client.require_egress(url="https://api.stripe.com/v1/charges", method="POST", body={...})
```

The SDK **never** decides egress itself — it forwards the request and surfaces the server's decision,
so a blocked or approval-required operation is reported rather than silently attempted.

### 6.2 HTTP API

| Method | Path | Permission | Purpose |
|---|---|---|---|
| `POST` | `/v1/egress/request` | `policy:read` | governed outbound request → structured decision |
| `GET` | `/v1/admin/egress/policies` | `policy:read` | list egress policies |
| `POST` | `/v1/admin/egress/policies` | `policy:write` | register an egress policy |
| `GET` | `/v1/admin/egress/policies/{id}` | `policy:read` | fetch one policy |
| `DELETE` | `/v1/admin/egress/policies/{id}` | `policy:write` | delete a policy |
| `POST` | `/v1/admin/egress/policies/{id}/enable` | `policy:write` | enable |
| `POST` | `/v1/admin/egress/policies/{id}/disable` | `policy:write` | disable |
| `GET` | `/v1/admin/egress/audit` | `policy:read` | egress audit events |
| `GET` | `/v1/admin/egress/metrics` | `policy:read` | egress metrics |

All routes are RBAC-checked via the existing `Authorizer`. When no egress service is configured the
routes return `404` (existing behaviour unchanged).

### 6.3 Registering a policy

```python
egress.register_policy(
    org_id="acme", name="allow stripe",
    host_patterns=["api.stripe.com"], protocols=["https"], ports=[443],
    action="ALLOW", rate_limit={"per_second": 10, "burst": 20},
    allow_redirects=False, dlp_enabled=True)
```

Host patterns are validated: an exact host or a single leading `*.` wildcard. A bare `*`, a
mid-label wildcard and a leading dot are all rejected at registration.

---

## 7. Reproducible test commands

```bash
# unit tests (no external services)
PYTHONPATH=src:. python -m unittest -v tests.test_egress_unit

# guard <-> egress boundary tests (requires the `opa` binary)
PYTHONPATH=src:. python -m unittest -v tests.test_egress_guard_integration

# PostgreSQL integration tests (requires a reachable PostgreSQL)
AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres \
  AGENTGUARD_TEST_PG_PASSWORD=postgres PYTHONPATH=src:. \
  python -m unittest -v tests.test_egress_pg_integration

# the complete suite (existing + new)
AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=postgres \
  AGENTGUARD_TEST_PG_PASSWORD=postgres AGENTGUARD_TEST_REDIS_URL=redis://127.0.0.1:6379/0 \
  PYTHONPATH=src:. python -m unittest discover -s tests -t .
```

---

## 8. Next phase boundary (NOT implemented here)

Phase 5 — **Runtime Monitoring, Agent Behavior Analytics, Intent Graph and Agentic Drift
Detection** — is deliberately **not** implemented in this task. The integration seams Phase 4 leaves
for it:

* **Audit stream** — `egress_audit` (append-only, RLS) plus the `SecurityLogger` structured stream
  already carry per-decision events with correlation ids; Phase 5 can consume these as its behaviour
  signal without schema changes.
* **Metrics** — `EgressService.metrics()` exposes blocked traffic, denials, DLP detections,
  approvals, gateway errors and latency; Phase 5 can extend this surface.
* **Decision records** — every decision is a structured `EgressDecision` with a stable reason code,
  which is the natural input for intent-graph construction and drift baselines.
* **Policy version** — recorded on every decision, so a drift detector can attribute behaviour
  changes to policy changes.

See [`PHASE4_SECURITY_LIMITATIONS.md`](PHASE4_SECURITY_LIMITATIONS.md) for the full limitations and
bypass-path list.
