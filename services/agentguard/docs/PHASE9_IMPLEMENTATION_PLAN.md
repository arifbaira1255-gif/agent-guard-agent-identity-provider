# AgentGuard Phase 9 — Implementation Plan

**Scope:** Enterprise Deployment, Scalability, Disaster Recovery, Performance Engineering &
Adversarial Security Validation.

**Method:** Extend the actual Phase 8 repository (`agentguard_v7_phase8` → `agentguard_v7_phase9`).
No prior phase is rebuilt. All new work reuses the existing service, storage, auth, policy,
assurance, egress, governance, response, observability and HA components.

---

## 1. Repository assessment (measured, not assumed)

| Fact | Value |
|---|---|
| Python source | 270 `.py` files, ~38,849 LOC under `src/` |
| Tests | 32 test modules, ~14,412 LOC under `tests/` |
| Migrations | 10 SQL migrations (`0001`–`0010`) |
| Verified baseline | **1119 tests OK, 187 skipped** (real PostgreSQL 15.19 + Redis) |
| Pre-existing defect | `console/index.html` was absent from the packaged archive → 1 failing test (Phase 8 `ConsoleAssetTests`) |

### Stateful components
* **PostgreSQL** — authoritative: organizations, agents, instances, credentials, revocations, audit,
  enterprise users/memberships/sessions, policy, governance, egress/DLP, runtime monitoring,
  response, assurance + idempotency ledger + coordination ledger.
* **Redis** — distributed transient security state: replay cache, permission cache, caches, rate
  limits, locks. **Fails closed** (quarantine) — never silently allows on a Redis outage.
* **KMS/HSM** — external signing authority (`local-dev` refused outside development).
* **Process-local (each replica)** — in-memory metrics registry, in-memory idempotency store used
  **only** in the dev harness.

### Single points of failure (documented, §5)
* PostgreSQL is the authoritative store — HA topology required; backup/restore is the RPO anchor.
* Redis is required for a correct security decision (replay protection) — HA topology required.
* KMS/HSM provider is required where configured — a hard dependency for signing/verification.
* The in-process `RateLimiter` (Phase 8) is per-replica — documented limitation, unchanged here.

### Deployment assumptions found
* `deploy/kubernetes/identity-service.yaml` is the ONLY pre-existing manifest. It references
  `args: ["serve"]` — **no `serve` entrypoint existed**. That gap is closed in this phase.
* No Dockerfile, no CI workflow, no backup/restore tooling, no benchmark harness for the
  control-plane round trip, no adversarial suite. All added here.

---

## 2. Pre-flight capability audit (blockers vs. resolved)

| Capability | Status | Detail |
|---|---|---|
| Python 3.11 + cryptography/psycopg/redis/PyJWT/boto3 | **resolved** | installed |
| PostgreSQL 15.19 server | **resolved** | local cluster started; `postgres`/`postgres`, db `agentguard_test` |
| Redis server | **resolved** | `redis-server` installed, `PING → PONG` |
| Kubernetes manifest validation | **resolved** | `kubeconform v0.6.7` + `kubectl v1.30.0 --client` |
| SBOM generation | **resolved** | `cyclonedx-py` |
| Dependency CVE scan | **resolved** | `pip-audit` |
| Python static analysis | **resolved** | `bandit` |
| Container **build/run** | **BLOCKED** | no container runtime (`docker`/`podman`/`buildah` unavailable, no daemon in sandbox) |
| Live cluster apply | **BLOCKED** | no Kubernetes API server; manifests are client-side validated only |
| Live SIEM vendor endpoint | **BLOCKED** | unchanged from Phase 7 (transports unit-tested only) |
| AWS KMS / PKCS#11 HSM | **BLOCKED** | no credentials/device; `local-dev` used and labelled as such |

Blocked items are reported as **blocked/unverified**, never as passed (brief §10).

---

## 3. Implementation plan (dependency-aware)

1. **Fix the inherited defect** — restore `console/index.html`; re-run the Phase 8 suite to green.
2. **Production entrypoint** — `src/agent_identity/server.py`: composes the real auth/RBAC/audit
   stack + Phase 8 `/v2` management API + the Step 7 health aggregator; env validation; graceful
   shutdown + connection drain; health/readiness/liveness. Unconfigured planes report
   `available:false` — never a fabricated success.
3. **Container** — multi-stage `Dockerfile` (build → minimal runtime, non-root UID 10001, pinned
   deps, no embedded credentials) + `.dockerignore`.
4. **Kubernetes** — namespace, ServiceAccount, ConfigMap/Secret (example), Deployment with probes +
   preStop drain + resources + restricted securityContext, Service, NetworkPolicy, Ingress,
   migration Job, PDB, HPA, plus reference PostgreSQL/Redis StatefulSets.
5. **Self-hosted topology** — `deploy/compose/docker-compose.production.yml` (TLS-terminating proxy,
   PG, Redis with TLS, migrations, app) + private-cloud bootstrap/upgrade/rollback docs.
6. **HA validation** — multi-instance tests over a *shared* PostgreSQL + Redis: concurrent identity
   issuance, revocation propagation across instances, duplicate/out-of-order event handling,
   idempotent replay across replicas, coordination advisory-lock single-winner.
7. **DR** — `scripts/dr_backup.py` / `scripts/dr_restore.py` producing a checksummed, manifest-bearing
   logical backup; automated restore drill that restores into a **throwaway database** and verifies
   tenant boundaries, policy integrity and audit-chain verification survive.
8. **Performance** — `benchmarks/phase9_bench.py`: reproducible p50/p95/p99 + throughput for auth,
   identity issue/verify, policy evaluation, JIT authz, governance decision, egress/DLP decision,
   audit write + verify, incident creation; machine spec + dataset + concurrency printed inline.
9. **Adversarial suite** — `tests/test_phase9_adversarial.py`: authn/authz bypass, cross-tenant,
   privilege escalation, replay/concurrency, policy-enforcement bypass, SSRF/egress bypass, DLP
   evasion, unsafe redirect/destination validation, prompt-injection-driven tool use, resource
   exhaustion, audit tampering, unsafe rollback, secret redaction. Fix confirmed high/critical.
10. **Supply chain** — SBOM (CycloneDX) + `pip-audit` + `bandit` + secret scan over the real tree;
    `scripts/supply_chain.sh`; results captured as artifacts.
11. **CI/CD** — `.github/workflows/agentguard-ci.yml`: lint → unit → integration (PG+Redis service
    containers) → migration check → SBOM → scans → manifest validation → artifact + SHA256SUMS;
    security-critical failures are release-blocking.
12. **Docs & deliverables** — this plan, deployment, private-cloud, HA, DR, benchmarks, security
    assessment, supply chain, CI/CD, final report, limitations.

## 4. Non-goals (explicit)
* **Phase 10** (final hardening, commercial readiness, licensing, v1.0 validation) — not implemented.
* No claim of zero vulnerabilities, guaranteed availability, or unlimited scalability.
* No changes to security semantics of prior phases; new code is additive.
