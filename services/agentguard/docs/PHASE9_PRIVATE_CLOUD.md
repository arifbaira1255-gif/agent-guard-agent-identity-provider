# AgentGuard Phase 9 — Private-Cloud & Self-Hosted Operations

A deployment path for on-prem / private-cloud operators. **Which parts were tested in this
environment is stated explicitly at the end** — do not read this as a claim of universal
compatibility.

---

## 1. Prerequisites

| Component | Minimum | Notes |
|---|---|---|
| Linux host(s) | 4 vCPU / 8 GB RAM | per app replica; DB/Redis sized separately |
| Container runtime | Docker 24+ / containerd | for the Compose path |
| Kubernetes | 1.27+ (if using the K8s path) | with an ingress controller and a CSI driver |
| PostgreSQL | 15.x | TLS-capable; `verify-full` required in production |
| Redis | 7.x | TLS-capable; AOF enabled; `noeviction` |
| KMS/HSM | AWS KMS, GCP KMS, Azure Key Vault, or PKCS#11 | **not** `local-dev` in production |
| DNS | `agentguard.<your-domain>` | resolves to the ingress / proxy |
| TLS | server cert + key, and CA bundles for PG/Redis | from your PKI or cert-manager |

---

## 2. Network & DNS

* Ingress/proxy terminates **TLS 1.2+** on 443 and re-encrypts to the app on 8443.
* App → PostgreSQL 5432 (TLS, `verify-full`), App → Redis 6379/6380 (TLS).
* App → KMS endpoint over 443. **Block the cloud metadata IP `169.254.169.254`** (the NetworkPolicy
  in `deploy/kubernetes/60-networkpolicy.yaml` already excludes it).
* No inbound path to PostgreSQL or Redis from outside the cluster/network.

---

## 3. TLS configuration

* **Edge:** `deploy/compose/nginx.conf` (self-hosted) or the Ingress (`70-ingress.yaml`).
* **PostgreSQL:** mount the CA at `/etc/pg/ca.pem`, set `AGENTGUARD_PG_SSLMODE=verify-full` and
  `AGENTGUARD_PG_SSLROOTCERT=/etc/pg/ca.pem`.
* **Redis:** set `AGENTGUARD_REDIS_TLS=1` and `AGENTGUARD_REDIS_TLS_CA_CERT=/etc/redis/ca.pem`.
  (The server refuses to start in production without `AGENTGUARD_REDIS_TLS=1`.)

---

## 4. Database & cache provisioning

* **PostgreSQL:** prefer a managed service or an operator (CloudNativePG/Patroni) for automated
  failover, PITR and backups. The bundled StatefulSet is a **single-primary reference**, not HA.
* **Redis:** prefer a managed service or Sentinel/Cluster. Redis holds **transient security state**
  (replay cache, caches, rate limits, locks) and is required for a correct decision — the app
  **fails closed** if it is unavailable.

---

## 5. KMS/HSM provider setup

Set `AGENTGUARD_KMS_PROVIDER` to your provider and supply credentials via the workload identity
(IRSA / Workload Identity / managed identity) — **never** a static key in a manifest. The audit
signer and credential encryption use this interface; `local-dev` is refused outside development.

---

## 6. Initial administrator bootstrap

One-time, audited:

```bash
AGENTGUARD_BOOTSTRAP_EMAIL=admin@your-domain \
AGENTGUARD_BOOTSTRAP_PASSWORD='<strong, unique>' \
python -m agent_identity.server serve --bootstrap-admin
```

Outside development the server **refuses** to bootstrap without both values. Rotate the bootstrap
password immediately after first login.

---

## 7. Secure configuration & secret injection

* Secrets come from a secret manager (External Secrets Operator, Vault CSI, Sealed Secrets, or the
  cloud CSI driver) — never committed.
* `deploy/kubernetes/11-secrets.example.yaml` is an **example**; replace it.
* The ConfigMap holds **no** credentials (asserted by a test).

---

## 8. Upgrade procedure

```bash
# 1. Back up first (see docs/PHASE9_DR.md)
bash scripts/dr_backup.sh /backups

# 2. Apply migrations (idempotent)
kubectl -n agentguard delete job agentguard-migrate --ignore-not-found
kubectl -n agentguard apply -f deploy/kubernetes/40-migrate-job.yaml
kubectl -n agentguard wait --for=condition=complete job/agentguard-migrate --timeout=300s

# 3. Roll out the new image (maxUnavailable: 0 -> no dropped requests)
kubectl -n agentguard set image deploy/agentguard-identity identity=agentguard/agent-identity:<new>
kubectl -n agentguard rollout status deploy/agentguard-identity
```

## 9. Rollback procedure

```bash
kubectl -n agentguard rollout undo deploy/agentguard-identity
kubectl -n agentguard rollout status deploy/agentguard-identity
```

**Schema rollback:** migrations are forward-only. If a release requires a schema change that cannot
be reversed, restore from the pre-upgrade backup (`scripts/dr_restore.sh`) into a fresh database and
repoint the app — this is the documented, tested recovery path.

---

## 10. Backup configuration

See `docs/PHASE9_DR.md`. Minimum: nightly `scripts/dr_backup.sh` to durable object storage, with the
manifest retained alongside the dump, and a **scheduled restore drill** into a throwaway database.

---

## 11. Operational troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `/readyz` 503, `checks.redis=fail` | Redis down / TLS mismatch | check Redis health, `AGENTGUARD_REDIS_TLS`, CA bundle |
| `/readyz` 503, `checks.database=fail` | PG down / schema mismatch | check PG, run `migrate` |
| Startup exits 2, `startup_refused` | unsafe config | read the `reason` field; fix the env |
| 401 on every request | session secret changed / clock skew | verify `AGENTGUARD_SESSION_SECRET`, NTP |
| 413 responses | body over 256 KiB | raise the limit deliberately or fix the client |
| Replay/quarantine errors | Redis state was lost | Redis recovered; requests are refused until the marker is re-established |

---

## 12. Tested vs. documented-only

| Item | Status |
|---|---|
| Application server, config validation, graceful shutdown, migrations | **TESTED** (this sandbox) |
| Kubernetes manifest syntax/schema + kustomize build | **TESTED** (client-side) |
| Compose topology file | **AUTHORED, NOT RUN** — no container runtime here |
| Managed cloud PG/Redis, cloud KMS, cert-manager, ingress controller | **DOCUMENTED ONLY** |
| Multi-cloud / every-Kubernetes-distribution compatibility | **NOT CLAIMED** — no evidence |
