# AgentGuard — Cryptographic Agent Identity

Standalone subsystem that gives every AI agent a unique, verifiable identity: signed
**Agent Passports**, short-lived credentials, instance/session identity, sub-agent lineage,
revocation, key rotation and replay protection. No dependency on any other AgentGuard
component; only Python ≥3.10 and `cryptography`.

## Architecture

```
Root (offline in prod) ──signs──▶ Organization issuer key (IssuerCertificate)
                                        │ signs
                                        ▼
        Agent (identity key) ──binds──▶ Agent Instance ──▶ Credential / Passport (ephemeral key)
                                        │ spawn (authenticated parent, caps ⊆ parent)
                                        ▼
                                   Sub-Agent (own identity, lineage)
```

```
src/agent_identity/
  core/          models, config, validation, ids, errors, clock
  crypto/        Ed25519, fingerprints, canonical JSON, agent-side key helper
  credentials/   passport format (agp1.<payload>.<sig>)
  verification/  Verifier (chain, signature, expiry, registry, revocation, replay)
  storage/       interfaces (KeyStore, AgentRegistry, CredentialRegistry, RevocationRegistry,
                 TrustStore, ReplayCache) + in-memory reference impls
  observability/ allow-list structured security logger
  adapters/      SPIFFE ID helpers, Attestor/IdentityProvider contracts, SPIRE stub
  api/           IdentityService (core engine) + optional HTTP transport
tests/ examples/ benchmarks/ docs/ config/
```

The engine (`IdentityService`) is transport-agnostic; HTTP is a thin optional wrapper.

## Security model (summary)
* Ed25519 everywhere; fixed algorithm (no `alg` header → no algorithm confusion);
  domain-separated signatures (passport / issuer-cert / instance-binding / proof / CSR).
* Private keys live only in a `KeyStore` that can **sign but never export**. The local store
  Fernet-encrypts keys at rest (master key via `AGENT_IDENTITY_MASTER_KEY`). Keys never appear
  in API responses, repr, or logs (logger is allow-list based and redacts token-like values).
* Trust is explicit: verifier trusts root keys → issuer certificates → passports. Self-declared
  identity is never trusted; every claim is cross-checked against the registry
  (capabilities, lineage, org, key fingerprint, payload digest).
* Credentials are short-lived (default 15 min, hard max 1 h, configurable).
* Replay: possession proof `{credential_id, nonce, timestamp, request_id, audience}` signed by the
  credential key; nonce + request_id cached; stale/foreign-audience proofs rejected; cache fails closed.
* Fail closed: any unexpected verifier exception ⇒ `valid=false, reason=internal_error`.

## Install & test
```bash
pip install cryptography            # or: pip install -e .
PYTHONPATH=src python3 -m unittest discover -s tests -t .     # 45 tests
PYTHONPATH=src python3 examples/quickstart.py
PYTHONPATH=src python3 benchmarks/bench.py
```

## Quickstart
```python
from agent_identity import IdentityService, AgentSideKey, SPAWN_AUDIENCE
svc = IdentityService()                       # local dev: in-memory stores
svc.register_organization("acme", "Acme Corp")
agent = svc.register_agent("acme", "support-agent", "support", "ops@acme.com",
                           capabilities=["agent:spawn", "tickets:read"])
inst  = svc.create_agent_instance(agent["agent_id"])
key   = AgentSideKey()                         # agent keeps its private key
cred  = svc.issue_credential(agent["agent_id"], inst["instance_id"],
                             **key.csr(agent["agent_id"], inst["instance_id"]))
proof = key.make_proof(cred.credential_id, audience="tickets-api")
svc.verify_credential(cred.token, proof=proof, audience="tickets-api").to_dict()
```

## API (IdentityService)
| Method | Purpose |
|---|---|
| `register_organization / rotate_issuer_key / revoke_issuer_key` | trust hierarchy |
| `register_agent(...)` | create agent identity + identity key |
| `create_agent_instance(agent_id)` | new runtime instance/session (binding signed by agent key) |
| `issue_credential(agent_id, instance_id, ttl_seconds=...)` | short-lived passport |
| `verify_credential(token, proof=, audience=, expected_agent_id=, expected_instance_id=)` | structured result |
| `rotate_credential(credential_id, grace_seconds=)` | new key + credential, old revoked after grace |
| `revoke_credential / revoke_instance / revoke_agent` | reasons: compromise, suspicious_behavior, agent_terminated, credential_rotated, administrative_action, security_incident |
| `spawn_sub_agent(parent_token, parent_proof, ...)` | authenticated child creation |
| `get_agent_identity / get_credential_status / rotate_agent_key` | queries / rotation |

Verification result: `{"valid", "agent_id", "instance_id", "credential_id", "issuer", "expires_at", "reason", ...}`.
Failure reasons are fixed machine-readable codes (see `core/models.py: Reason`), e.g.
`invalid_signature, expired, revoked, unknown_issuer, replay_detected, proof_required, ancestor_not_active`.

HTTP: `make_server(svc, admin_token)` exposes `POST /v1/{organizations,agents,instances,credentials/issue|verify|revoke|rotate,agents/spawn}`,
`GET /v1/agents/{id}`, `GET /v1/credentials/{id}/status` (bearer token required).

## Lifecycle
register agent → create instance (per start/restart) → issue credential (TTL) → use with proof →
expire or rotate → new credential. Restart ⇒ new instance_id + new credential; policies can tell
*same agent / different instance / different session* apart.

## Key rotation
* Credential: `rotate_credential` issues a new ephemeral key + passport; old one stays valid for
  `grace_seconds`, then fails as `revoked` (reason `credential_rotated`).
* Issuer: `rotate_issuer_key` → old key `retiring` for an overlap window, then `issuer_key_retired`.
* Agent identity key: `rotate_agent_key`; instances bound to the retired key must be recreated after grace.

## Sub-agents
Parent authenticates with credential + proof bound to audience `agent-identity:spawn`, must hold
`agent:spawn`, child capabilities ⊆ parent's, depth ≤ `max_sub_agent_depth`. `register_agent`
refuses `parent_agent_id`, so a child can't be self-declared. Revoking an ancestor invalidates all descendants.

## Configuration
See `config/identity.example.json` (`IdentityConfig.from_file`). Docs: `docs/THREAT_MODEL.md`,
`docs/INTEGRATION_CONTRACT.md`, `docs/BENCHMARK_RESULTS.txt`.

## Production considerations (honest limits)
* Bundled stores are **in-memory** — implement the `storage/interfaces.py` ABCs for PostgreSQL
  (registries), Redis (`SET NX EX` replay cache, atomic), KMS/HSM (`KeyStore`: sign-only).
* Run the root key offline/HSM; only the root-signed issuer certs need to be online.
* Python cannot reliably zeroize memory; use KMS/HSM for strong key-at-rest/in-use guarantees.
* Control-plane methods (register/issue/revoke/rotate) assume the **transport authenticates and
  authorises callers**; the bundled HTTP server uses a single static bearer token and plain HTTP —
  put it behind mTLS/OIDC + RBAC.
* Service-held credential keys (`create_proof`) are a dev convenience; use agent-held keys (`AgentSideKey`).
* Revocation is checked at verification time against the shared registry; with multiple verifier
  replicas they must share the revocation store.
* Benchmarks in `docs/BENCHMARK_RESULTS.txt` are from one sandbox run (single thread, in-memory); re-run on target hardware.

## SPIFFE/SPIRE integration
Implemented in `src/agent_identity/spiffe/`; see `docs/SPIFFE.md`. The old stub was replaced by a real
Workload API client (X.509-SVID, JWT-SVID, trust bundles, rotation). Status: WIP, not production-ready:
the real-SPIRE integration test (`integration/spire/run.sh`) passed on a Docker test host; production node attestation and federation are unverified.

## Redis distributed security state
Implemented in `src/agent_identity/state/`; see `docs/REDIS.md`. WIP: unit-tested, real Redis tests not yet run.

## Enterprise KMS/HSM key management
Implemented in `src/agent_identity/kms/`; see `docs/KMS.md`. A provider-independent, sign-only
key-management layer (`KeyManagementProvider` + `KeyMetadataStore` + `KeyManagementManager`) with a
drop-in `KeyStore` adapter (`KmsKeyStore`) so `IdentityService` is unchanged. Providers:
**local-dev** (development/test only, refuses staging/production), **AWS KMS** (Ed25519,
non-exportable) and **PKCS#11/HSM** (non-exportable). Status: the whole layer + local-dev provider
are unit-tested offline; the AWS and PKCS#11 adapters are code-complete but **NOT verified against
live services** (no cloud account / HSM was available) - see `docs/KMS.md` for the required setup.
```python
from agent_identity.kms import KmsConfig, build_kms
kms = build_kms(KmsConfig(environment="development", provider="local-dev"))
svc = IdentityService(cfg, root_key_id="root_prod", **kms.service_kwargs())
```


## Step 6 - mTLS and service-to-service trust
`agent_identity.mtls` adds mutual TLS built on the SPIFFE/SPIRE adapter, a deny-by-default trust policy
(optionally KMS-signed), rotation, readiness and metrics. See `docs/MTLS.md`. Tests: `tests/test_mtls.py`
(mocked SPIRE, real TLS), `tests/test_mtls_spire_integration.py` (real SPIRE; requires Docker; not run in CI here).


## Phase 5 - Runtime Monitoring, Agent Behaviour Intelligence, Intent Graph & Agentic Drift Detection

Implemented in `src/agent_identity/runtime_monitoring/` (17 modules) plus migration
`0008_phase5_runtime_monitoring.sql` and the authoritative store
`storage/postgres/runtime_monitoring.py`. Eight consolidated capabilities:

1. **Runtime activity monitoring** - normalized event pipeline (`pipeline.py`): alias resolution,
   closed 22-type vocabulary, fail-closed validation (future-skew and retention-horizon rejection),
   redaction, optional sampling, dedup, append-only store.
2. **Agent behaviour analytics** - tenant-isolated, versioned profiles (`profiles.py`) with
   configurable learning window and a minimum-sample threshold; an immature profile *declines to
   reason* instead of treating sparse data as suspicious.
3. **Intent graph** - `graph.py` over the *existing* store (no second database): 10 node kinds,
   8 edge kinds, explicit provenance (`direct_observation` / `derived` / `repeated_pattern`) and
   confidence on every edge.
4. **Agentic drift detection** - `drift.py`, four structurally distinct evidence tiers:
   `confirmed_violation` (contradicts authoritative config), `statistical_anomaly` (mature baseline),
   `heuristic_suspicion` (pattern rule), `insufficient_evidence`.
5. **Anomaly & abuse detection** - denial bursts, access bursts, unseen sequences, unusual
   data access, destination novelty.
6. **Risk scoring & correlation** - `risk.py`, versioned rules (`p5-risk-1`), eight signal kinds,
   returns contributing signals + evidence; advisory only, never gates an operation.
7. **Policy-engine integration** - `policy_integration.py`; response actions *delegate* to the
   existing policy/JIT planes. Phase 5 has no enforcement path and cannot allow or deny anything.
8. **Real-time alerts & investigation** - `alerts.py`: severity, dedup, rate limiting that
   **records** suppressed alerts rather than dropping them, validated lifecycle, and a
   tenant-scoped investigation view.

API: `/v1/runtime/*` (read) and `/v1/admin/runtime/*` (manage), behind new `runtime:read` /
`runtime:admin` permissions. When the service is not wired the surface 404s and nothing else changes.

**Tests:** `tests/test_phase5_runtime_monitoring.py` (96 unit/adversarial) and
`tests/test_pg_phase5_integration.py` (20 real-PostgreSQL). Full suite: 935 tests, `OK (skipped=82)`,
81% coverage. Benchmarks: `scripts/bench_phase5.py`.

**Docs:** `docs/PHASE5_ARCHITECTURE.md`, `docs/PHASE5_FINAL_REPORT.md`,
`docs/PHASE5_SECURITY_LIMITATIONS.md`.

Status: integration-tested against real PostgreSQL 15. Detection coverage equals the telemetry
actually emitted by instrumented integrations - read the limitations doc before relying on it.
No alert transport (notification delivery) and no scheduler exist yet; see the limitations doc for
the full list of what is stubbed or unverified.

---

## Phase 6 — Autonomous Response (loop detection, approval, incidents, containment)

Phase 6 adds a **response plane** on top of Phases 1-5. It introduces **no second database, no second
event pipeline and no competing authorization path**: every enforcement action delegates to a mechanism
that already exists (policy engine, JIT grant service, identity/credential plane, egress gateway,
governance registry, budget boundary).

1. **Autonomous loop / runaway detection** - `loops.py`: 7 patterns (repeated action, circular
   invocation, excessive retry, repeated denial, egress repetition, cascade failure, resource burn)
   over a bounded per-agent window. `CONFIRMED_VIOLATION` is emitted **only** when the count
   contradicts an authoritative configured budget; heuristics cap at `SUSPICIOUS_REPETITION`; sparse
   telemetry yields `INSUFFICIENT_EVIDENCE`.
2. **Execution budgets + emergency stops** - `budgets.py`: `guard()` is the **server-side enforcement
   boundary** and raises rather than advising. Atomic conditional increment; fail-closed when the
   budget store is unreadable; an active emergency stop is checked first.
3. **Risk-based human approval** - `approvals.py`: every request is bound to an
   `operation_fingerprint` over `(org, agent, action, resource, params)`, so a modified request cannot
   reuse an approval. Separation of duties, expiry, delegation, bounded pending queue.
4. **Incident management** - `incidents.py`: 7-state lifecycle with validated transitions.
   Correlation is **key-based** (`agent|subject`), never time-based.
5. **Automated containment + revocation** - `containment.py`: 10 actions, each delegating to an
   existing mechanism and reporting `unavailable` rather than pretending success. Auto-containment is
   **OFF by default**; high-impact actions require an approved human decision.
6. **Cross-component orchestration** - `orchestrator.py`: idempotent (UNIQUE `(org, idempotency_key)`),
   per-agent serialized, evidence preserved and sealed before destructive steps, honest
   `PARTIAL`/`FAILED` outcomes, audited rollback.
7. **Evidence + audit integrity** - `evidence.py` (references + digests, sealing, retention) and
   `audit.py` (hash chain with `verify_chain()`). This is a **hash chain, not a notarization** - see
   the limitations doc.
8. **Safe failure handling** - fail-closed defaults, explicit emergency policies, and 60 adversarial
   unit tests covering forged approvals, duplicate delivery, concurrent stops, partial failures and
   malicious payloads.

API: `/v1/response/*` (read + approvals) and `/v1/admin/response/*` (budgets, stops, incidents,
containment, evidence), behind new `response:read` / `response:admin` / `response:approve`
permissions. When the service is not wired the surface 404s and nothing else changes.

**Tests:** `tests/test_phase6_response.py` (60 unit/adversarial) and
`tests/test_pg_phase6_integration.py` (14 real-PostgreSQL, none skipped). Full suite: **1009 tests,
`OK (skipped=82)`**, 80% coverage. Benchmarks: `benchmarks/phase6_bench.py`.

**Docs:** `docs/PHASE6_ARCHITECTURE.md`, `docs/PHASE6_FINAL_REPORT.md`,
`docs/PHASE6_SECURITY_LIMITATIONS.md`.

Status: integration-tested against real PostgreSQL 15. Containment is effective at the
**authorization boundary, not the process boundary** - an agent runtime that never calls `guard()` is
not constrained by it. Detection coverage equals the telemetry actually emitted by instrumented
integrations. No alert transport, no scheduler, no external audit anchoring, no SIEM export. Read the
limitations doc before relying on this plane.

## Phase 7 — Assurance Plane (self-healing policy intelligence, tamper-evident audit, compliance, SIEM)

Phase 7 adds an **assurance plane** on top of Phases 1-6. It introduces **no second database, no
second event pipeline and no competing authorization path**: it consumes the signals the existing
planes already produce and routes every policy change back through the **existing policy engine**.

**Capabilities**

1. **Self-healing policy intelligence** - analyzes trusted signals (authorization denials, confirmed
   violations, DLP detections, drift alerts, incidents, suspicious tool-use, admin feedback,
   false-positive investigations) into **explainable** recommendations that keep observed facts,
   heuristic conclusions and proposed changes strictly separate, with explicit confidence and
   uncertainty. It never claims to infer every attack or discover perfect policies.
2. **Safe policy lifecycle** - draft -> validated -> simulated -> pending_approval -> approved ->
   canary -> active -> rolled_back, with schema validation, static security checks, simulation,
   canary evaluation, approval gating, rollback and full provenance. **A policy never becomes active
   because a model recommended it.**
3. **Tamper-evident audit** - canonical serialization, SHA-256 hash chaining, Ed25519 signatures
   through the existing KMS/HSM interface, key-id/version rotation compatibility, integrity
   verification, and signed checkpoints. Tamper-**evident**, not tamper-proof.
4. **Compliance evidence** - configurable control mappings (SOC 2, ISO 27001, GDPR, EU AI Act) with
   honest verification statuses and exportable evidence reports. A report is **not** a certification.
5. **SIEM integration** - modular transports (syslog TLS/TCP, HTTP, Splunk HEC, Elastic bulk,
   webhook) with TLS verification, batching, bounded retries, rate limiting, backpressure, delivery
   status and secret redaction.
6. **Event correlation** - consistent event ids, correlation ids, severity normalization,
   deduplication, incident references and provenance (original evidence vs. derived analytics).
7. **Reliability** - health/readiness, bounded queues, backpressure, fail-closed audit, explicit
   behavior when the audit store or a SIEM endpoint is unavailable.

**API:** `/v1/assurance/*` (read) and `/v1/admin/assurance/*` (evidence, analysis, proposals,
compliance, SIEM, checkpoints), behind new `assurance:read` / `assurance:admin` / `assurance:approve`
permissions. When the service is not wired the surface 404s and nothing else changes.

**Tests:** `tests/test_assurance_unit.py` (61 unit/adversarial) and
`tests/test_pg_phase7_integration.py` (14 real-PostgreSQL, none skipped). Full suite: **1083 tests,
`OK (skipped=187)`**.

**Docs:** `docs/PHASE7_ARCHITECTURE.md`, `docs/PHASE7_POLICY_WORKFLOW.md`,
`docs/PHASE7_AUDIT_INTEGRITY.md`, `docs/PHASE7_COMPLIANCE.md`, `docs/PHASE7_SIEM.md`,
`docs/PHASE7_SECURITY_LIMITATIONS.md`, `docs/PHASE7_FINAL_REPORT.md`.

Status: integration-tested against real PostgreSQL 15. Audit integrity is tamper-**evident** (tail
truncation needs an externally anchored checkpoint). Live SIEM vendor endpoints are **unverified**.
Compliance reports are **not** certification. Read `docs/PHASE7_SECURITY_LIMITATIONS.md` before
relying on this plane.
