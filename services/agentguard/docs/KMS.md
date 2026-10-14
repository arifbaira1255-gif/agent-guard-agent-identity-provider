# Enterprise KMS/HSM Key Management (Step 5)

Production-grade cryptographic key custody for AgentGuard, behind a provider-independent abstraction.
This document states honestly what is implemented, what is verified, and what external setup is still
required.

> **Verification status (read first).** The `local-dev` provider and the entire key-management layer
> (interface, metadata ledger, rotation/retirement, `KmsKeyStore` adapter, identity integration) are
> unit-tested offline and pass. The **AWS KMS** and **PKCS#11/HSM** adapters are code-complete and
> exercised against **injected fake clients/modules** only. **No live AWS KMS or HSM integration has
> been verified** - no cloud account or hardware was available in the build environment. Treat those
> two adapters as untested-against-a-real-service until the setup below is performed.

## 1. What was added

```
src/agent_identity/kms/
  interfaces.py       KeyManagementProvider (provider contract) + KeyMetadataStore (ledger contract)
  models.py           KmsAlgorithm/KmsKeyType/KmsKeyUsage/KmsKeyState, KeyVersion, KeyMetadata,
                      the legal state-transition table
  errors.py           typed, secret-free errors (all subclass IdentityError)
  config.py           KmsConfig (env-driven, production guards)
  local_dev.py        LocalDevProvider          (development/test only, refuses staging/production)
  aws_kms.py          AwsKmsProvider            (real cloud KMS, Ed25519, non-exportable)
  pkcs11_provider.py  Pkcs11Provider            (HSM / PKCS#11, non-exportable)
  stores.py           InMemoryKeyMetadataStore + KeyManagementManager (rotation/retirement/recovery)
  keystore.py         KmsKeyStore -> drop-in for storage.interfaces.KeyStore
  factory.py          build_kms() provider selection + fail-closed guards
  integration.py      build_identity_service() composition helper
src/agent_identity/storage/postgres/
  migrations/0002_kms_key_metadata.sql   metadata-only ledger tables (no key material)
  kms_repos.py                           PgKeyMetadataStore (production ledger)
tests/test_kms.py                      62 offline tests (see §9)
```

Nothing in the existing identity engine was rewritten: `IdentityService` still calls the same
sign-only `KeyStore` contract. Key custody is swapped by passing `KmsKeyStore` as `keystore=`.

## 2. Interfaces

**`KeyManagementProvider`** (the HSM/KMS boundary): `capabilities`, `health_check`, `create_key`,
`describe`, `get_version`, `public_key`, `sign`, `verify`, `rotate`, `set_state`, `revoke`,
`delete_key`, plus a development-only `export_private_key` that real providers do not implement.

**`KeyMetadataStore`** (AgentGuard's own, non-secret ledger): `put_key`, `get_key`, `list_keys`,
`put_version`, `transition` (compare-and-swap), `delete`. It stores **no key material** - only ids,
versions, states and deadlines - and is what makes rotation recoverable and concurrency-safe.

## 3. Supported algorithms and key types

AgentGuard is deliberately **Ed25519-only** for signing (fixed algorithm, no `alg` header, no
algorithm-confusion surface; domain-separated signatures preserved end to end). `KmsAlgorithm` is an
enum so the surface stays extensible, but every provider here implements Ed25519. Keys are
asymmetric signature keys (`KmsKeyType.ASYMMETRIC_SIGNATURE`).

**Key usage** is explicit and enforced: `issuer_cert_signing` (root \(\to\) issuer certs),
`passport_signing` (org issuer key \(\to\) passports), `identity_signing` (agent key \(\to\) instance
bindings), `proof_signing`, `data_key`. `KmsKeyStore` infers usage from the existing key-id
convention (`root_*`, `iss_*`, `key_*`), so the unchanged engine automatically tags each key.

## 4. Key lifecycle

```
PENDING -> ENABLED -> (DISABLED) -> RETIRING -> RETIRED -> REVOKED/DESTROYED
```

* **Only `ENABLED` versions sign.** Exactly one version per logical key is enabled at a time.
* **`RETIRING` versions still verify** - this is the rotation overlap window. `KeyVersion.can_verify()`
  covers `ENABLED` + `RETIRING`; `can_sign()` covers only `ENABLED`.
* **`RETIRED`/`REVOKED`/`DESTROYED` are terminal.** A revoked key can never return to service. The
  transition table is enforced in the model, in every provider, and (for PostgreSQL) by a DB trigger.

## 5. Rotation and retirement

`KeyManagementManager.rotate(key_id, overlap_seconds=…)`:
1. creates the next version `ENABLED`;
2. moves every previously-enabled version to `RETIRING` via a **compare-and-swap** that only fires
   while the version is still `ENABLED`.

Consequently two concurrent rotations cannot both retire the same version or leave two signers
enabled (see §9). The retire deadline is the ledger's job, not a process's.

**Retirement never breaks live credentials.** `retire()` refuses early retirement while the overlap
has not elapsed, and `destroy()` refuses to remove any non-terminal version: a key that a valid
credential still depends on cannot be deleted. `reap()` advances every `RETIRING` version whose
overlap has elapsed to `RETIRED`; it is idempotent and safe to run from any replica.

**Recovery from an interrupted rotation.** State lives in the ledger, so a crash mid-rotation leaves
a consistent, readable state: a new `ENABLED` version (if the provider call committed) and old
versions still `RETIRING`. Run `reap()` (or wait for the scheduled sweep) to finish retirement; no
manual repair is required. If the provider call committed but the ledger write did not, the key is
re-detected by `describe/list_keys` on the next reconciliation - **run `reap()` after any rotation
failure** and reconcile `list_keys()` against the provider.

## 6. Private-key protection (how each requirement is met)

| Requirement | Implementation |
|---|---|
| Never store private keys in PostgreSQL | `kms_key_versions` stores public keys + metadata only; the existing Fernet-encrypted `keystore_keys` is unchanged and independent. Tests scan the SQL for key-material columns. |
| Never store private keys in Redis | The KMS layer does not touch Redis. Nothing here writes key material to the Redis state backend. |
| Never log keys/credentials/secret material | The audit logger's allow-list was extended only with non-secret fields (`provider`, `algorithm`, `key_id_version`, `key_state`); the redaction regex is unchanged. `test_kms.py` scans emitted events for raw/encoded key material. |
| Prefer non-exportable keys | AWS KMS and PKCS#11 generate keys in place with **no export** (`export_private_key` raises). Only `local-dev` is exportable, and only in development. |
| Restrict key usage and access | Usage sets are enforced per key and per operation; provider errors map to `KmsAccessDeniedError` and are never retried (`test_kms.py`). |
| Validate provider responses and key metadata | Signatures must be 64 bytes, public keys must parse to 32 raw bytes, algorithms/specs are checked; anything else raises `KmsProviderError` (fail closed). |
| Use established crypto libraries | Ed25519 via `cryptography`; AWS via `boto3`; PKCS#11 via `python-pkcs11`. No primitives are hand-rolled. |
| Migrate without losing identities | `KmsKeyStore` is a drop-in `KeyStore`: existing agent/instance/credential records and any Fernet-encrypted keys remain valid. Migration is additive (§8). |

## 7. Providers

### local-dev (development/test only)
Fernet-encrypted private keys in-process (same protection as the pre-existing
`EncryptedMemoryKeyStore`) but behind the full lifecycle. **Refuses twice** to run outside
development: at construction and again on every signing call, so a process that starts in dev and
re-enters production mode fails closed instead of signing with a development key.

### aws-kms (real cloud KMS - adapter complete, live integration NOT verified)
Ed25519 (`ECC_NIST_EDWARDS25519`, `ED25519_SHA_512`) non-exportable keys. KMS has no native versions,
so AgentGuard carries key id/version/state/usages as KMS **tags** and treats its own ledger as
authoritative. `sign` calls KMS `Sign` over `domain + data` (KMS signs raw bytes, so domain separation
is preserved); verification uses the existing Ed25519 primitives.

**Missing external setup to verify live:**
* an AWS account with KMS enabled, and credentials (env/`AWS_PROFILE`/instance role) permitted to
  `CreateKey`, `GetPublicKey`, `Sign`, `ListKeys`, `ListResourceTags`, `TagResource`, `DisableKey`,
  `EnableKey`, `ScheduleKeyDeletion`;
* `AGENTGUARD_KMS_REGION` (+ optional `AGENTGUARD_KMS_ENDPOINT_URL` / `AGENTGUARD_KMS_AWS_PROFILE`);
* `pip install 'agentguard-agent-identity[aws]'` (installs `boto3`).

### pkcs11 (HSM - adapter complete, live integration NOT verified)
Keys generated **inside the token**, non-exportable (`CKA_EXTRACTABLE=False`, `CKA_SENSITIVE=True`).
PKCS#11 has no versions or lifecycle, so the AgentGuard ledger is authoritative; token objects are
labelled `"<key_id>#v<version>"`.

**Missing external setup to verify live:** a PKCS#11 library and token with Ed25519 support
(SoftHSM2 \(\ge\) 2.6 for CI, or a vendor HSM), `AGENTGUARD_KMS_PKCS11_MODULE` pointing at the `.so`,
a token label/slot, and the PIN via `AGENTGUARD_KMS_PKCS11_PIN_FILE` (preferred) or
`AGENTGUARD_KMS_PKCS11_PIN`; `pip install 'agentguard-agent-identity[pkcs11]'`.

## 8. Configuration

All via `AGENTGUARD_KMS_*` (never commit production secrets). `KmsConfig.validate()` enforces that the
process environment can only make things **stricter**, and that a **development provider is never
selected outside development** - the same fail-closed pattern as `PgConfig`/`RedisConfig`.

| Variable | Purpose |
|---|---|
| `AGENTGUARD_KMS_PROVIDER` | `local-dev` \| `aws-kms` \| `pkcs11` |
| `AGENTGUARD_KMS_REGION` / `_ENDPOINT_URL` / `_AWS_PROFILE` | AWS KMS location/credentials |
| `AGENTGUARD_KMS_PKCS11_MODULE` / `_TOKEN_LABEL` / `_SLOT` / `_PIN_FILE` | HSM selection |
| `AGENTGUARD_KMS_ROTATION_INTERVAL_SECONDS` | default 30 days |
| `AGENTGUARD_KMS_RETIRE_OVERLAP_SECONDS` | verification overlap (default 2 h) |
| `AGENTGUARD_KMS_PENDING_DELETION_DAYS` | AWS deletion window (7..365) |
| `AGENTGUARD_KMS_CONNECT_TIMEOUT_S` / `_COMMAND_TIMEOUT_S` / `_RETRY_MAX_ATTEMPTS` | timeouts/retries |
| `AGENTGUARD_KMS_REQUIRE_HEALTH_CHECK` / `_REQUIRE_TLS` | strictness toggles |

Wiring (production) - PostgreSQL is required for the metadata ledger outside development:

```python
from agent_identity.kms import KmsConfig, build_kms
kms = build_kms(KmsConfig.from_env(), pg_db=pg_storage.db)   # aws-kms or pkcs11
svc = IdentityService(cfg, root_key_id=ROOT_ID, **pg_storage.service_kwargs(), keystore=kms.keystore)
# or, brevity form:
from agent_identity.kms.integration import build_identity_service
svc, kms = build_identity_service(cfg, KmsConfig.from_env(), root_key_id=ROOT_ID,
                                  kms_kwargs={"pg_db": pg_storage.db},
                                  service_kwargs=pg_storage.service_kwargs())
```

`build_key_metadata_store` refuses to build an in-memory ledger in staging/production.

## 9. Testing

`tests/test_kms.py` (62 tests, all offline) covers: config + production guards; the local-dev
lifecycle (create/sign/verify/rotate/retire/revoke/export); `KeyMetadataStore` compare-and-swap; the
`KmsKeyStore` adapter against the existing `KeyStore` contract; failure injection (provider outage
\(\Rightarrow\) `KmsUnavailableError`, never a bogus signature); usage/state enforcement; **concurrent
rotation keeping exactly one enabled signer**; verification continuing during rotation; the AWS
adapter against a fake client (including denied/throttled/not-found/invalid-response mapping); the
PKCS#11 adapter against a fake module, with a metadata store and without one; the identity end-to-end
flow over a KMS-backed store; and a log scan proving no key material is emitted.

Run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -t .        # full suite
PYTHONPATH=src python3 -m unittest tests.test_kms                # Step 5 only
```

**Mocked vs real.** Every AWS/PKCS#11 test uses fakes. There is **no** automated live-integration test
in this repo yet: add one gated on `AGENTGUARD_KMS_REGION` (AWS) / a token path (PKCS#11) once the
external setup above exists, mirroring how `tests/test_pg_integration.py` is gated.

## 10. Migration notes

* `0002_kms_key_metadata.sql` adds **additive, metadata-only** tables (`kms_keys`,
  `kms_key_versions`) plus a terminal-state trigger. It changes no existing table and migrates no
  data.
* Existing deployments keep working: the previous Fernet-encrypted `keystore_keys` path is untouched,
  and existing identities/credentials remain valid. Moving an existing deployment onto a KMS provider
  is a controlled operation - new signatures go through the provider while previously stored keys
  remain available for verification until their credentials expire; retire them with `reap()` once no
  live credential depends on them. **Do not delete stored keys before their credentials expire.**
* Run migrations as a separate deploy step (`python -m agent_identity.storage.postgres migrate`);
  `verify_schema` will fail closed if the schema does not match this build.

## 11. Known limitations

* **Live AWS KMS and HSM integration is UNVERIFIED** (fake clients/modules only).
* AWS KMS has no native key versions; versioning rides on tags + our ledger. An out-of-band tag edit
  is detectable drift, but the provider cannot enforce it cryptographically.
* PKCS#11 exposes no versions or state machine; the ledger is fully authoritative, so `describe()`
  requires a `KeyMetadataStore`.
* SoftHSM2 needs Ed25519 enabled; some older tokens do not support `CKM_EDDSA` at all.
* `AwsKmsProvider.set_state` best-effort mirrors DISABLED/RETIRED to the key; the logical state is the
  authority for signing/verification even if the mirror call fails.
* Rotation of the **root** key (`root_*`) still needs the existing `TrustStore` flow; the KMS layer
  versions it but cross-org root trust management remains Step 6 territory.

### Review findings (independent review of this build)
* AWS key spec `ECC_NIST_EDWARDS25519` and algorithm `ED25519_SHA_512` with `MessageType=RAW` match the AWS KMS documentation (checked online);
  nothing has been executed against a real AWS account.
* FIXED in this review: `IdentityService` did not include the key store in the staging/production durable-storage guard, so production
  could start with the in-memory development keystore. It now refuses (`tests/test_kms.py::ProductionKeystoreGuard`).
* `PgKeyMetadataStore` and migration `0002_kms_key_metadata.sql` have only been checked by offline/SQL-text tests; run them against real
  PostgreSQL (the schema version expected by `readiness()` is now 2).
* No AgentGuard-level authorization for key operations (who may rotate/revoke/sign): least privilege currently relies on provider IAM/HSM
  policy plus per-key usage enforcement. An application-level caller/role check is still missing.
* Audit events are emitted by the manager; completeness for every signing/verification failure path should be reviewed before production.
* Rotation/ledger consistency when a provider call succeeds but the ledger write fails relies on a manual `reap()`/reconciliation.

## 12. Integration boundary for Step 6

Step 6 (production mTLS and trust infrastructure) builds on, and does not replace, this layer:

* **Boundary:** `KeyManagementProvider` / `KmsKeyStore` remain the only key-custody surface;
  `KeyMetadataStore` remains the lifecycle ledger. Step 6 should consume `kms.manager`/
  `kms.keystore` and never reach into provider internals.
* **Hand-off points:** (a) real-credential integration tests for AWS KMS / HSM gated on env, using the
  same fake-injection seams; (b) binding workload/instance identity to a provider-attested key
  (SPIRE attestation \(\to\) HSM-held key) - `spiffe/` already models the contract; (c) cross-org /
  federated root trust, which needs a root-key ceremony procedure on top of `rotate_issuer_key`.
