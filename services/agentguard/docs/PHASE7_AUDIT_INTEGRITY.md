# Phase 7 — Audit Integrity Model & Verification

## 1. What is provided

| Mechanism | Implementation |
|---|---|
| Canonical serialization | fixed, sorted-key, whitespace-free JSON over a closed field set (`_HASH_FIELDS`) |
| Hash chaining | `hash = SHA-256(prev_hash ‖ canonical(record))`, per tenant, in insertion order |
| Digital signatures | Ed25519 over the domain-separated hash, through the **existing KMS/HSM layer** |
| Key identifiers | `key_id` + `key_version` recorded per record (rotation-compatible) |
| Integrity verification | `verify_chain` recomputes the chain and reports the first divergence |
| Missing/reordered/modified detection | `verify_chain` compares `prev_hash` and recomputes each hash in insertion order |
| Protected checkpoints | signed digest of the chain head (`AuditCheckpoint`), verifiable against the chain |
| Access controls | `assurance:read` for reads; `assurance:admin` for checkpoint creation |
| Retention | `audit_retention_days` (0 = keep forever; the table is append-only against UPDATE) |
| Verification reports & alerts | `GET /v1/assurance/audit/verify`; health reports `audit_chain_ok` |

## 2. Threat model

**In scope (detected):**

* Modification of a record's content after it was written → hash mismatch.
* Reordering of records → `prev_hash` mismatch.
* Removal of a record from the middle of the chain → `prev_hash` mismatch.
* Forging a record without the signing key → signature invalid.
* Truncation of the tail → detected **only** by a checkpoint (see below).
* Rewriting the whole chain without the signing key → signatures invalid.

**Out of scope / not prevented:**

* An attacker who controls **all** storage **and** all checkpoints can delete or rewrite the tail and
  the remaining chain still verifies. Hash chaining alone does not prevent deletion or truncation.
* An attacker with the signing key can forge records. Key custody is therefore the critical control.
* An attacker with DDL rights can disable the append-only trigger (the PG integration test does
  exactly this to prove the hash chain still detects the tamper).
* A superuser/BYPASSRLS database role is exempt from RLS.

## 3. Honest statement of limits

> This is **tamper-EVIDENT, not tamper-PROOF**. Hash chaining alone does not prevent every form of
> deletion or truncation, especially if an attacker controls all relevant storage and checkpoints.
> Signatures raise the bar but do not make the log immutable. Do **not** describe this system as
> absolutely immutable or tamper-proof.

## 4. Checkpoints — the only truncation defence

A checkpoint is a signed digest of the chain head at a point in time:

```
checkpoint = { checkpoint_id, org_id, seq, head_hash, record_count, ts }
signature  = Ed25519( SHA-256( canonical(checkpoint) ) )
```

`verify_checkpoint` checks the signature, then confirms the chain still contains at least
`record_count` records and that the record at `seq` still hashes to `head_hash`. A mismatch means
records were removed or the chain was rewritten after the checkpoint was taken.

**Checkpoints must be exported/anchored externally** (a separate account, an append-only object
store, a transparency log, or a third party) to be meaningful. A checkpoint stored only in the same
database as the chain provides no protection against an attacker who controls that database.

## 5. Key management

* Signing goes through `kms.interfaces.KeyManagementProvider`; **private keys never live in
  application code**.
* `KmsAuditSigner` wraps the provider; `key_id`/`key_version` are recorded per record so a record
  stays verifiable across rotation.
* `LocalEd25519Signer` is a **development/test-only** in-process signer. It **refuses to run in
  staging or production**.
* `NullSigner` (unsigned mode) is only permitted when `audit_require_signature=False`, which is
  itself refused in production.

## 6. Verification instructions

```bash
# verify the chain and the latest checkpoint for a tenant
curl -s /v1/assurance/audit/verify | jq
# -> {"chain":{"ok":true,"checked":N,"broken_at":null,"reason":"chain intact",
#             "signatures_verified":N},
#     "checkpoint":{"ok":true,"reason":"checkpoint verified","seq":N},
#     "ok":true}

# list checkpoints
curl -s /v1/assurance/audit/checkpoints | jq

# create a checkpoint (assurance:admin)
curl -X POST /v1/admin/assurance/audit/checkpoint
```

Programmatically:

```python
from agent_identity.assurance import AssuranceService, MemoryAssuranceStore, AssuranceConfig
svc = AssuranceService(MemoryAssuranceStore(), config=AssuranceConfig(environment="development"))
svc.audit.record("policy.activated", org_id="acme", actor_user_id="usr_admin")
assert svc.verify_audit(org_id="acme")["ok"] is True
```

## 7. Configuration

| Env var | Default | Effect |
|---|---|---|
| `AGENTGUARD_ASSURANCE_AUDIT_REQUIRE_SIGNATURE` | true | refuse unsigned records (must be true in production) |
| `AGENTGUARD_ASSURANCE_AUDIT_FAIL_CLOSED` | true | refuse the operation when the audit store is down |
| `AGENTGUARD_ASSURANCE_AUDIT_CHECKPOINT_INTERVAL` | 1000 | emit a signed checkpoint every N records |
| `AGENTGUARD_ASSURANCE_AUDIT_SIGNING_KEY_ID` | `audit_signing` | KMS key id (never a raw key) |
| `AGENTGUARD_ASSURANCE_AUDIT_SIGNATURE_DOMAIN` | `agentguard:audit:v1` | domain separation label |
| `AGENTGUARD_ASSURANCE_AUDIT_RETENTION_DAYS` | 0 | 0 = keep forever |

## 8. Production checklist

1. Inject a `KmsAuditSigner` backed by the real KMS/HSM (never the local signer).
2. Connect to PostgreSQL as a **non-superuser** role so RLS is effective.
3. Export checkpoints to an **external** append-only location on a schedule.
4. Alert on `audit_chain_ok=false` and on any `verify_checkpoint` failure.
5. Restrict `assurance:admin` (checkpoint creation) to a small set of operators.
