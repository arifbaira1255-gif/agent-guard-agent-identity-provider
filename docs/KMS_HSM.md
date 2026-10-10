# Step 5 — Enterprise KMS/HSM Key Management

Provider-independent cryptographic key management for AgentGuard: secure key creation,
identification and versioning, signing, verification material, rotation, lifecycle/status,
revocation metadata, provider health checks and controlled retirement.

> **Scope.** This document covers Step 5 only. It reuses — and does not rebuild — the
> Step 1–4 identity, credential, SPIFFE/SPIRE, PostgreSQL and Redis components.

---

## 1. Reused existing components (not rebuilt)

| Component | Where | How Step 5 reuses it |
|---|---|---|
| `KeyStore` ABC (sign-only, no private bytes) | `storage/interfaces.py` | `KeyManager` **extends** it; `DefaultKeyManager` is a drop-in |
| Ed25519 + domain separation | `crypto/keys.py` | the local provider signs through it; domains & fingerprints unchanged |
| `IdentityService` | `api/service.py` | takes a `keystore=` — now the KMS-backed manager |
| `Verifier` / trust chain | `verification/verifier.py` | unchanged; issuer keys resolve through the new trust bridge |
| `TrustStore` ABC | `storage/interfaces.py` | composed, not replaced (`TrustStoreComposition`) |
| PostgreSQL storage + `Database.run` | `storage/postgres/*` | new KMS metadata/audit tables ride on the same pool & migrations |
| Migration framework | `storage/postgres/migrate.py` | migration `0002_kms_keys.sql` (checksummed, advisory-locked) |
| `SecurityLogger`, `Clock`, `errors` | `observability/`, `core/` | reused for audit + lifecycle timing |
| SPIFFE/SPIRE providers | `spiffe/provider.py` | get their signing key from the same manager |

**No Step 1–4 component was replaced. The existing test suite is the regression guard.**

## 2. Files changed / created

Created (new package `src/agent_identity/kms/`):

```
kms/__init__.py          public surface
kms/models.py            KeyAlgorithm, KeyStatus, KeyMetadata, ProviderHealth, policy predicates
kms/interfaces.py        KeyManager (extends KeyStore) + CryptoBackend
kms/errors.py            provider/key error hierarchy (no secrets in messages)
kms/manager.py           DefaultKeyManager: lifecycle, rotation, retries, audit
kms/metadata.py          KeyMetadataStore (memory + PostgreSQL), KeyAuditSink
kms/config.py            KmsConfig (env, dev-vs-prod enforcement, redaction)
kms/factory.py           build_key_manager / build_managed_service
kms/trust_bridge.py      TrustStoreComposition + managed_storage_kwargs
kms/providers/local_provider.py    software Ed25519 (DEV/TEST ONLY)
kms/providers/vault_provider.py    HashiCorp Vault Transit (Ed25519, non-exportable)
kms/providers/pkcs11_provider.py   PKCS#11 HSM (CKM_EDDSA)
```

Changed:

* `storage/postgres/migrations/0002_kms_keys.sql` — **new** (schema v2)
* `pyproject.toml` — `kms = ["python-pkcs11>=0.9"]` extra
* `tests/test_pg_integration.py`, `tests/test_pg_unit.py` — updated for schema v2 + new
  `KmsMetadata` class (these were assertions about "the only migration", not functionality)

Untouched: `crypto/`, `credentials/`, `api/`, `verification/`, `spiffe/`, Redis state,
migration `0001_initial.sql`, `keystore_keys` table.

## 3. Key-management interfaces and providers

**`KeyManager`** (extends `KeyStore`): `create_key`, `get_key_status`, `get_public_key`,
`list_keys`, `rotate_key`, `retire_key`, `revoke_key`, `destroy_key`, `health_check`,
`verification_material` — plus the legacy `generate_key / public_key / sign / has_key /
delete_key` it inherits.

**`CryptoBackend`** — the provider-specific half (generate / public / sign / destroy /
health); no lifecycle logic leaks into it.

| Provider | Technology | Key custody | Status |
|---|---|---|---|
| `local` | software Ed25519, Fernet-encrypted at rest | exportable (software) | **DEV/TEST ONLY** |
| `vault` | HashiCorp Vault Transit `ed25519` | **non-exportable** (`exportable=false`) | validated against a real Vault |
| `pkcs11` | PKCS#11 `CKM_EDDSA` on a token | **non-exportable** (`SENSITIVE`, `EXTRACTABLE=false`) | validated against SoftHSM2 |

Algorithms: **Ed25519 only** (`KeyAlgorithm` is a deliberately closed enum — adding one is a
security decision because it changes the token format's implicit algorithm).

## 4. Provider integrations actually tested

| Integration | Real / mocked | Evidence |
|---|---|---|
| Vault Transit | **REAL** (dev server, `transit` engine) | keygen → server-side sign → verifies as standard Ed25519; `export/private-key` refused; wrong token → provider error |
| PKCS#11 | **REAL** (SoftHSM2 token) | keypair generated **on token**; `CKM_EDDSA` signature verifies as standard Ed25519; tampered message rejected |
| AWS KMS | **not implemented** | one cloud provider was chosen (Vault); the abstraction leaves room for a later adapter |
| Hardware HSM | **not tested** | EdDSA availability is vendor/version dependent — see Limitations |
| All of the above | **MOCKED** coverage too | transport/session doubles exercise error mapping, malformed responses, absent keys |

Both real integrations were run in the sandbox: `docker run hashicorp/vault:1.15` +
`softhsm2-util --init-token`. **No cloud account or hardware HSM was available**, so no live
cloud/HSM claim is made.

## 5. Rotation and revocation behaviour

```
PENDING ──► ACTIVE ◄──┐
              │        │
        rotate│        │
              ▼        │
          ROTATING ────┘ (successor created; both keys sign & verify)
              │ overlap (not_after) closes
              ▼
          RETIRING  (verify-only, until not_after)
              ▼
          RETIRED   (no signing; still verifies until not_after; now destroyable)
              ▼
        destroy_key()

   any state ──► REVOKED  (terminal; never signs, never verifies)
```

* **Overlap.** `rotate_key(old, new, grace_seconds)` creates the successor **first**, then
  CAS-moves the old key to `ROTATING`. During the window **both** keys verify, so a
  credential signed just before the change still validates.
* **Concurrency.** The old→ROTATING move is a compare-and-swap on `(key_id, status=ACTIVE)`
  in one guarded `UPDATE`. Exactly one of N concurrent rotations wins; the losers roll back
  their successor (provider key **and** metadata row).
* **Crash safety.** Because the successor is created before the old key changes state, an
  interrupt leaves the old key fully usable — never a broken signing path.
* **Revocation** is terminal and enforced twice: in `KeyManager` and by a PostgreSQL trigger
  that refuses any `revoked → non-revoked` update.
* **Never delete a key still needed.** `destroy_key` refuses unless the key is
  `RETIRED`/`REVOKED`. A key is retired with a `not_after` chosen past the longest validity
  of credentials that reference it, and only destroyed after that.
* **Recovery from an interrupted rotation.** (a) successor created, CAS not yet applied →
  old key still ACTIVE, successor unused: re-run rotation (or destroy the orphan).
  (b) CAS applied, links half-written → both keys verify; `rotate_key(old, …)` is refused
  with `KeyStateError` because the old key is no longer ACTIVE, so no second successor is
  created. Inspect with `list_keys(status=ROTATING)` and continue by retiring the old key
  once the successor is confirmed live.

## 6. Access control and audit

* **Least privilege per operation.** Signing is refused on any non-signing state; destroying
  is refused while a key may still verify; metadata-only updates cannot change custody.
* **Audit** (`kms_key_audit`, append-only): key creation, every signing operation, denied
  signing, verification-material refusals, rotation, retirement, revocation, destruction and
  provider errors — with `event, key_id, provider, result, reason, actor, correlation_id`.
* **No secrets, no chain-of-thought.** No key bytes, tokens, PINs or provider secrets are
  ever recorded. `KeyMetadata.public_dict()` and `KmsConfig.safe_dict()` are the
  loggable/serialisable forms, and `repr()` of every backend redacts credentials.

## 7. Configuration

Environment-based (`AGENTGUARD_KMS_*`); secrets by value **or** file reference.

| Setting | Default | Notes |
|---|---|---|
| `AGENTGUARD_ENV` | `production` | can only **tighten** the config's environment |
| `PROVIDER` | `local` | `local` \| `vault` \| `pkcs11` |
| `ALLOW_LOCAL_IN_PRODUCTION` | `false` | explicit, auditable override |
| `ALLOW_EXPORTABLE_KEYS` | `false` | refused outside development |
| `KEY_ID_PREFIX` | `agentguard` | provider-side name prefix |
| `VAULT_ADDR` / `VAULT_TOKEN` / `VAULT_TOKEN_FILE` / `VAULT_NAMESPACE` / `VAULT_MOUNT` / `VAULT_CA_CERT` | — | **https + TLS verify required outside development** |
| `PKCS11_LIBRARY` / `PKCS11_TOKEN_LABEL` / `PKCS11_SLOT` / `PKCS11_PIN` / `PKCS11_PIN_FILE` | — | module path + token selector |
| `TIMEOUT_SECONDS` | `5` | 0 < t ≤ 120 |
| `RETRY_MAX_ATTEMPTS` | `3` | bounded; only *transient* failures |
| `ROTATE_GRACE_SECONDS` | `7200` | default rotation overlap |

**No silent fallback.** In `staging`/`production` a `local` provider raises unless
`ALLOW_LOCAL_IN_PRODUCTION=true`; an unknown provider raises; a provider that cannot be
configured raises at startup. The master key for the local provider comes from
`AGENT_IDENTITY_MASTER_KEY`.

### Local development

```bash
export AGENTGUARD_ENV=development AGENTGUARD_KMS_PROVIDER=local
export AGENT_IDENTITY_MASTER_KEY="$(python3 -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')"
```

### Production (Vault)

```bash
export AGENTGUARD_ENV=production AGENTGUARD_KMS_PROVIDER=vault
export AGENTGUARD_KMS_VAULT_ADDR=https://vault.internal:8200
export AGENTGUARD_KMS_VAULT_TOKEN_FILE=/var/run/secrets/vault-token
export AGENTGUARD_KMS_VAULT_MOUNT=transit
```

The token needs `create/read/update/delete` on `transit/keys/*` and `update` on
`transit/sign/*`. Keys are created `exportable=false`, so even a leaked token cannot export
private key material.

### Production (HSM)

```bash
export AGENTGUARD_ENV=production AGENTGUARD_KMS_PROVIDER=pkcs11
export AGENTGUARD_KMS_PKCS11_LIBRARY=/usr/lib/libpkcs11.so
export AGENTGUARD_KMS_PKCS11_TOKEN_LABEL=agentguard-prod
export AGENTGUARD_KMS_PKCS11_PIN_FILE=/var/run/secrets/hsm-pin
```

## 8. Threat model summary

Handled by this step:

* private keys extracted from the database or shared store (never stored there);
* signing without authorization (lifecycle gate + least privilege per state);
* a compromised key signing forever (terminal revocation, DB-enforced);
* losing credentials during rotation (overlap window);
* destroying a key that live credentials still need (destroy guard);
* provider outage/reject producing a *valid* verdict (fail closed, bounded retries);
* provider outage producing duplicate/inconsistent state (idempotent, CAS-based);
* secrets leaking into logs/audit/HTTP (`safe_dict`, redacted `repr`, no-secret audit).

Out of scope (later steps): production mTLS/trust infrastructure (Step 6), a full HSM
vendor-certification matrix, quorum/dual-control key ceremonies, cloud-KMS multi-region
disaster recovery.

## 9. Recovery procedures

| Situation | Procedure |
|---|---|
| Provider unreachable | operations fail closed with `ProviderUnavailableError` after bounded retries; no key state changes |
| Permission denied | single attempt, `ProviderPermissionError`; fix the policy, retry |
| Rotation interrupted before CAS | old key still ACTIVE → re-run `rotate_key`; optionally destroy the orphan successor |
| Rotation CAS applied, links partial | both keys verify; inspect `list_keys(status=ROTATING)`; retire the old key when the successor is live |
| Key compromised | `revoke_key(key_id, reason=…)` — immediate and irreversible |
| Credentials must outlive their key | retire with `not_after` past their validity, then destroy |
| Metadata DB lost | restore PostgreSQL; provider keys are unaffected (they live in Vault/HSM) |

## 10. Known limitations

1. **AWS KMS / Azure Key Vault / GCP KMS adapters are not implemented.** Vault Transit is the
   chosen real cloud KMS; the `CryptoBackend` seam is where another adapter would go.
2. **PKCS#11 was validated against SoftHSM2, not a hardware HSM.** EdDSA support is
   vendor- and version-dependent; confirm `CKM_EDDSA` on the target device.
3. **Vault was validated against a dev server**, not a managed/HA cluster — HA/DR, seal
   behaviour and performance under load are unverified.
4. **Ed25519 only.** No RSA/ECDSA; the enum is closed on purpose.
5. **Retirement is deadline-based, not credential-aware.** `destroy_key` cannot know every
   live credential; operators must choose `not_after` past the longest credential validity.
6. **Two stores, not one transaction.** Metadata (PostgreSQL) and key material (Vault/HSM)
   cannot share a transaction; compensations are used (cleanup on failure), not 2PC.
7. **Per-key scope only for `key_id`.** No tenant isolation beyond the `tenant_id` column and
   the `tenant_id` in provider naming.

## 11. Integration boundary for Step 6 (Production mTLS and Trust Infrastructure)

Step 6 should treat this as the stable contract:

* obtain the signing key **only** through `KeyManager`/`CryptoBackend` — never a private key;
* perform every trust decision through `TrustStoreComposition` (or an equivalent gate) so
  revocation/retirement are honoured;
* keep the guarantee that **no private key material is ever persisted, logged or exported**;
* use `verification_material(key_id)` for "is this key currently trustworthy?" and treat
  `None` as **untrusted**;
* for mTLS specifically: the key id ↔ certificate binding and rotation overlap map directly
  onto the overlap window defined here, so certificate re-issuance can reuse `rotate_key`.

Repository left **stable for Step 6**: full suite green, no API removed, migration 0001
untouched, backward compatibility preserved.
