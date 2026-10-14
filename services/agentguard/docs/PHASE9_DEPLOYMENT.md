# AgentGuard Phase 9 — Production Deployment

**Scope:** production container image, Kubernetes topology, self-hosted topology, configuration
validation, migration procedure, and the exact evidence of what was validated in this environment.

> **Honesty statement.** In the build environment there is **no container runtime and no Kubernetes
> API server**. Therefore: the Dockerfile is **authored and statically validated** but **not built**;
> the Kubernetes manifests are **client-side validated with `kubeconform -strict` (22 resources, 0
> invalid)** and `kubectl kustomize` builds cleanly, but were **not applied to a live cluster**. The
> application server itself **was** run and exercised over real HTTP. See §7 for the tested vs.
> documented-only matrix.

---

## 1. Container image

`Dockerfile` is a two-stage build:

| Stage | Base | Purpose |
|---|---|---|
| `builder` | `python:3.11.9-slim-bookworm` | installs `.[postgres,redis,aws]` into `/opt/venv` (build toolchain never reaches runtime) |
| `runtime` | `python:3.11.9-slim-bookworm` | copies only `/opt/venv` + `src/` + `console/`; runs as **UID 10001**, non-root |

Properties enforced by `tests/test_phase9_deployment.py`:
* multi-stage (`FROM` count ≥ 2);
* `USER 10001:10001`, never `root`;
* no credential literals baked in;
* `HEALTHCHECK` hits the **process-only** `/livez`;
* `.dockerignore` excludes `.env`, `*.pem`, `*.key`, `tests`.

```bash
docker build -t agentguard/agent-identity:0.1.0 .
docker run --rm -p 8443:8443 --env-file .env agentguard/agent-identity:0.1.0 serve
```

Entrypoint: `python -m agent_identity.server` with subcommands **`serve`** (default) and
**`migrate`**.

---

## 2. Configuration validation (fail-closed)

`agent_identity.server.validate_environment()` refuses to start when the environment is unsafe.
Outside `development` it **requires**:

| Requirement | Reason |
|---|---|
| `AGENTGUARD_SESSION_SECRET` ≥ 32 chars | session integrity |
| `AGENT_IDENTITY_MASTER_KEY` set | credential encryption |
| `AGENTGUARD_KMS_PROVIDER` ≠ `local-dev` | no dev signer in production |
| `AGENTGUARD_PG_SSLMODE` ∈ {`verify-full`,`verify-ca`} | DB TLS with cert verification |
| `AGENTGUARD_REDIS_TLS=1` | cache/replay state over TLS |

A refusal exits **2** with a structured `startup_refused` line — it never silently downgrades a
control. Verified by `tests/test_phase9_server.py::EnvironmentValidationTests`.

---

## 3. Kubernetes topology

`deploy/kubernetes/` (apply with `kubectl apply -k deploy/kubernetes`):

| File | Resources |
|---|---|
| `00-namespace.yaml` | Namespace with **restricted** Pod Security Admission |
| `10-configmap.yaml` | non-secret config (no credentials) |
| `11-secrets.example.yaml` | **example only** — provision via External Secrets/Vault/CSI |
| `20-serviceaccount.yaml` | ServiceAccounts with `automountServiceAccountToken: false` |
| `30-postgres-statefulset.yaml` | reference PostgreSQL primary (headless Service + StatefulSet) |
| `31-redis-statefulset.yaml` | reference Redis (AOF, `noeviction`, password) |
| `40-migrate-job.yaml` | migration **Job** (separate from the Deployment) |
| `identity-service.yaml` | Deployment (3 replicas) + Service |
| `60-networkpolicy.yaml` | default-deny + explicit allow |
| `70-ingress.yaml` | TLS-terminating Ingress |
| `80-pdb-hpa.yaml` | PodDisruptionBudget + HorizontalPodAutoscaler |
| `kustomization.yaml` | kustomize entry point |

Key hardening (asserted by `tests/test_phase9_deployment.py`):
* `runAsNonRoot`, `runAsUser: 10001`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`;
* **three probes** — `startupProbe` + `livenessProbe` (`/livez`, process-only) + `readinessProbe`
  (`/readyz`, dependency-aware);
* `terminationGracePeriodSeconds: 30` + `preStop` drain;
* `maxUnavailable: 0` rolling update;
* resource requests **and** limits;
* default-deny NetworkPolicy for both Ingress and Egress.

### Deployment order
```bash
kubectl apply -k deploy/kubernetes
kubectl -n agentguard wait --for=condition=complete job/agentguard-migrate --timeout=300s
kubectl -n agentguard rollout status deploy/agentguard-identity
```

---

## 4. Health & readiness semantics

| Endpoint | Meaning | On dependency failure |
|---|---|---|
| `/livez` | process is alive | **stays 200** (a DB outage must not restart a healthy process) |
| `/readyz` | every capability needed for a correct security decision is up | **503** → LB removes the instance |
| `/healthz` | alias of `/livez` | — |

`/readyz` checks PostgreSQL (pool + schema) and Redis (ping). In `staging`/`production` a missing
Redis is a **startup failure**, not a degraded mode — replay protection cannot be skipped.

---

## 5. Graceful shutdown

On `SIGTERM`/`SIGINT`: the listener stops accepting (`begin_drain`), in-flight requests finish
within `AGENTGUARD_SHUTDOWN_GRACE_S` (default 25s), then the process closes the pool and exits.
Verified live: `kill -TERM` produced `{"event":"shutdown_signal"}` → `{"event":"stopped"}`.

---

## 6. Database migrations

Migrations are **never** run at application startup in production (`AGENTGUARD_PG_AUTO_MIGRATE=0`).
They run as an explicit step:

```bash
python -m agent_identity.server migrate
# {"event": "migrate_ok", "applied": [1..10], "head": 10}
# second run: {"event": "migrate_ok", "applied": [], "head": 10}   <- idempotent
```

Verified live against PostgreSQL 15.19 (see `docs/PHASE9_FINAL_REPORT.md`).

---

## 7. Tested vs. documented-only (this environment)

| Item | Status |
|---|---|
| Application server over real HTTP (`/livez`, `/readyz`, console, auth, 401, 413) | **TESTED** |
| Fail-closed config validation | **TESTED** |
| Graceful SIGTERM shutdown | **TESTED** |
| `migrate` subcommand + idempotency (real PostgreSQL 15.19) | **TESTED** |
| Kubernetes manifest syntax + schema (`kubeconform -strict`) | **TESTED** (22 valid, 0 invalid) |
| `kubectl kustomize` build | **TESTED** |
| Manifest security properties (non-root, probes, netpol, PDB/HPA) | **TESTED** (static assertions) |
| **Container image build/run** | **BLOCKED** — no container runtime in the sandbox |
| **Live cluster apply / rollout** | **BLOCKED** — no Kubernetes API server |
| **Managed cloud PostgreSQL/Redis** | **DOCUMENTED ONLY** — not provisioned here |
| **AWS KMS / PKCS#11 HSM** | **DOCUMENTED ONLY** — no credentials/device; `local-dev` used and labelled |

No claim is made that this deployment is "production-ready" beyond the tested items above.
