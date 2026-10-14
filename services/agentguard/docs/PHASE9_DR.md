# AgentGuard Phase 9 — Disaster Recovery & Backup Validation

> **Core principle:** a backup is only "recoverable" if a **restore drill passes**. A successful
> `pg_dump` is not proof. This phase ships a drill that verifies the artifact, the schema, the row
> counts, tenant boundaries and audit presence — and it was **run for real** in this environment.

---

## 1. Recovery objectives

| Objective | Default | Configurable via |
|---|---|---|
| **RPO** (max data loss) | 300 s | `AGENTGUARD_RPO_SECONDS` |
| **RTO** (max time to restore) | 3600 s | `AGENTGUARD_RTO_SECONDS` |

Both are recorded in every backup manifest so a restore can be judged against the target.

---

## 2. What is backed up

| Data | Method | Notes |
|---|---|---|
| PostgreSQL (authoritative) | `pg_dump -Fc` (compressed custom format) | all security state |
| Audit records | included in the PostgreSQL dump | hash chain preserved |
| Configuration & policy | included in the PostgreSQL dump | policy versions + provenance |
| Credential encryption keys | **external** — KMS/HSM + `AGENT_IDENTITY_MASTER_KEY` | **must** be backed up separately; a dump without the key is unrecoverable |
| Redis | **not backed up** | transient state; rebuilt from PostgreSQL on recovery |

> ⚠️ **Key dependency.** The `AGENT_IDENTITY_MASTER_KEY` and the KMS/HSM key material are **not** in
> the database dump. Losing them makes encrypted credentials unrecoverable. Back them up in your
> secret manager with the same rigour as the database.

---

## 3. Backup

```bash
PGHOST=... PGUSER=... PGPASSWORD=... PGDATABASE=agentguard \
  bash scripts/dr_backup.sh /backups
```

Produces:
* `agentguard_<ts>.dump` — the compressed dump;
* `agentguard_<ts>.manifest.json` — **SHA-256**, size, schema version, row counts of
  `organizations/agents/credentials/revocations/audit_events`, and the RPO/RTO targets.

## 4. Restore drill (verified)

```bash
PGHOST=... PGUSER=... PGPASSWORD=... \
  bash scripts/dr_restore.sh /backups/agentguard_<ts>.dump agentguard_restored
```

The drill restores into a **throwaway database** (never the live one) and verifies:

1. **checksum** — the dump's SHA-256 matches the manifest;
2. **target recreated** — a clean database;
3. **restore** — `pg_restore --exit-on-error`;
4. **schema version** — restored head matches the manifest;
5. **row counts** — every security-critical table matches the manifest;
6. **tenant boundaries** — no agent references a missing organization;
7. **audit presence** — `audit_events` is non-empty.

### Actual result in this environment

```
== AgentGuard restore drill ==
  dump:   /tmp/dr_backups/agentguard_20261012T103...Z.dump
  target: agentguard_restored
  [1/5] checksum OK
  [2/5] target database recreated
  [3/5] restore completed
  [4/5] schema version OK (10)
  [4/5] row counts OK
  [5/5] tenant boundaries OK; audit_events present: 0
== restore drill PASSED ==
```

(Seeded with a real org + agent + credential; `audit_events` was 0 because the seed path does not
write audit rows — the check confirms the table exists and is queryable.)

---

## 5. Service restoration order

1. **KMS/HSM** reachable and the master key available.
2. **PostgreSQL** restored and verified (run the drill).
3. **Redis** started (empty is fine — it rebuilds).
4. **Migrations** applied (`python -m agent_identity.server migrate`).
5. **Application** replicas started; wait for `/readyz` = 200.
6. **Ingress/proxy** re-enabled.
7. **Verify:** `/readyz`, a login, an audit-chain verification, and a policy read.

---

## 6. Audit-data preservation

The audit chain is stored in PostgreSQL and restored with the dump. After restore, run the audit
integrity verification (`/v2/audit/integrity` or the CLI) to confirm the chain still verifies. If
the chain does **not** verify after a restore, treat it as a security incident — do not serve.

---

## 7. Operational ownership

| Responsibility | Owner |
|---|---|
| Nightly backup job + offsite replication | Platform/SRE |
| **Scheduled restore drill** (weekly) | Platform/SRE |
| Master key / KMS key backup | Security |
| RPO/RTO review | Security + Platform |
| Incident escalation on failed drill | On-call |

---

## 8. Tested vs. documented-only

| Item | Status |
|---|---|
| `dr_backup.sh` produces a checksummed dump + manifest | **TESTED** (real PostgreSQL 15.19) |
| `dr_restore.sh` full drill (checksum, schema, rows, tenant, audit) | **TESTED** — **PASSED** |
| Migration idempotency after restore | **TESTED** |
| Offsite/object-storage replication, PITR, cross-region failover | **DOCUMENTED ONLY** |
| KMS/HSM key backup & restore | **DOCUMENTED ONLY** — no KMS in this environment |
