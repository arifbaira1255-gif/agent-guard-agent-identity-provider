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
Implemented in `src/agent_identity/state/`; see `docs/REDIS.md`. Unit-tested and covered by real
Redis integration tests (`AGENTGUARD_TEST_REDIS_HOST=...`) — currently passing.

## KMS/HSM key management (Step 5)
Implemented in `src/agent_identity/kms/`; see `docs/KMS_HSM.md`. Provider-independent key
management: `DefaultKeyManager` **implements the existing `KeyStore` ABC**, so it drops into
`IdentityService`/`Verifier` unchanged. Providers: `local` (development only, software Ed25519
encrypted at rest), `vault` (HashiCorp Vault Transit, **non-exportable** keys), `pkcs11`
(PKCS#11 `CKM_EDDSA` HSM). Lifecycle: pending → active → rotating → retiring → retired (+
terminal revoked); rotation keeps both keys verifying through an overlap window; keys are never
destroyed while a live credential may still depend on them; production refuses to fall back to
the development provider. Key material is **never** stored in PostgreSQL, Redis or logs.

```python
from agent_identity.kms import KmsConfig, build_key_manager
from agent_identity.kms.trust_bridge import managed_storage_kwargs

manager = build_key_manager(KmsConfig.from_env(), db=storage.db)
svc = IdentityService(cfg, **managed_storage_kwargs(storage, manager))   # keystore=KMS, trust=gated
```

Provider integrations are tested against **real** infrastructure: a Vault container with the
`transit` engine, and a SoftHSM2 PKCS#11 token (plus mocked transports for error paths). AWS KMS
and hardware HSMs are **not** implemented/verified — see the limitations section of `docs/KMS_HSM.md`.
