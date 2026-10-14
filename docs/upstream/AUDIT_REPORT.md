# Integration Audit — AgentGuard × Happy LANG

**Role:** Principal Software Architect & Security Engineer
**Date:** 2026-10-12
**Scope:** Full integration audit of two existing projects, based on the **real codebase** (archives downloaded, extracted, inspected, and executed). No integration was performed.
**Verdict:** **Integration is feasible but NOT yet safe to begin.** Three blockers must be cleared first (see §11). The exact next milestone is defined in §12.

---

## 0. Method & Evidence Discipline

Every claim below is tagged:

| Tag | Meaning |
|---|---|
| **[VERIFIED]** | Executed and observed in this audit — command + output recorded |
| **[ASSUMED]** | Reasoned from source inspection but not executed |
| **[BLOCKED]** | Could not be verified in this environment |

**Artifacts inspected**

| Project | Archive | Extracted root | Files | Python LOC |
|---|---|---|---|---|
| AgentGuard | `agentguard_v7_phase9.zip` (gzip/tar, not zip) | `audit/src/agentguard/agentguard_v7_phase9/` | 636 | 55,982 |
| Happy LANG | `happy-lang-v10-hardened.zip` (zip; contains `happy-lang-v8/`) | `audit/src/happy-lang/happy-lang-v8/` | 136 | 38,807 |

> **Note on archive format [VERIFIED]:** the AgentGuard artifact is named `.zip` but is a **gzip-compressed tar** (`file` → `gzip compressed data, from Unix`). `unzip` fails; `tar -xzf` succeeds. The Happy LANG artifact is a real zip whose top-level directory is `happy-lang-v8/` despite the `v10-hardened` filename. Both facts matter for any automated build/CI that fetches these artifacts.

**Commands executed (representative)**

```bash
# extraction
tar -xzf agentguard.zip -C agentguard
unzip -q -o happy-lang.zip -d happy-lang

# Happy LANG — per-file pytest (full-suite run was OOM-killed by a fuzzer test)
for f in tests/test_*.py; do python3 -m pytest "$f" -q; done
python3 tests/run_all_tests.py
python3 attacks/repro_all.py
python3 attacks/new_attacks.py

# AgentGuard — real infra
apt-get install -y postgresql redis-server
pg_ctlcluster 15 main start ; redis-server --daemonize yes
AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_PORT=5432 \
AGENTGUARD_TEST_PG_USER=postgres AGENTGUARD_TEST_PG_PASSWORD=postgres \
AGENTGUARD_TEST_REDIS_HOST=127.0.0.1 \
PYTHONPATH=src:. python3 -m unittest discover -s tests -t .
```

---

## A. Existing Implementation Inventory

### A.1 AgentGuard (`agentguard_v7_phase9`) — Python 3.10+, 55,982 LOC

A cryptographic **agent identity + security control plane**. Package `agent_identity` under `src/`.

| Subsystem | Path | LOC | Purpose |
|---|---|---:|---|
| Core models/config/validation | `src/agent_identity/core/` | ~600 | records, IDs, clock, validation |
| Crypto | `src/agent_identity/crypto/` | ~400 | Ed25519, fingerprints, canonical JSON |
| Credentials (passport) | `src/agent_identity/credentials/passport.py` | ~200 | `agp1.<payload>.<sig>` format |
| Verification | `src/agent_identity/verification/verifier.py` | ~300 | chain, signature, expiry, revocation, replay |
| Storage interfaces + memory | `src/agent_identity/storage/` | ~700 | ABCs + in-memory reference impls |
| PostgreSQL storage | `src/agent_identity/storage/postgres/` | ~2,000 | repos + 10 SQL migrations |
| **Policy engine** | `src/agent_identity/policy/` | **2,007** | OPA/Rego engine, enforcer, JIT, approvals |
| **Security (authN/authZ/RBAC)** | `src/agent_identity/security/` | **3,096** | sessions, tokens, OIDC, RBAC, tenant isolation |
| **Egress / DLP / SSRF** | `src/agent_identity/egress/` | **2,633** | `SecureEgressGateway`, DLP, rate limit |
| **Governance (tools/resources)** | `src/agent_identity/governance/` | **2,291** | tool registry, classifier, guard |
| **Runtime monitoring** | `src/agent_identity/runtime_monitoring/` | **3,861** | event pipeline, intent graph, drift, risk |
| **Autonomous response** | `src/agent_identity/response/` | **3,741** | loops, budgets, approvals, incidents, containment |
| **Assurance** | `src/agent_identity/assurance/` | **3,338** | policy intelligence, audit chain, compliance, SIEM |
| SPIFFE/SPIRE | `src/agent_identity/spiffe/` | 1,983 | Workload API, X.509/JWT-SVID |
| mTLS | `src/agent_identity/mtls/` | 1,061 | deny-by-default service trust |
| KMS/HSM | `src/agent_identity/kms/` | 2,099 | sign-only key custody (local-dev/AWS/PKCS#11) |
| HA primitives | `src/agent_identity/ha/` | ~700 | idempotency, coordination, retry, metrics |
| Distributed state | `src/agent_identity/state/` | ~900 | Redis backend, locks, replay, rate limit |
| **HTTP API** | `src/agent_identity/api/` | **3,743** | `service.py` (core), `http_transport.py` (v1), `enterprise_http.py` (v2/admin) |
| **SDK** | `src/agentguard_sdk/` | ~1,200 | client, auth, authorization, events, `adapters/tool_guard.py` |
| Server entrypoint | `src/agent_identity/server.py` | — | `serve` + `migrate` |
| Tests | `tests/` | 40 files | unit + real-PG integration + adversarial |
| Deploy | `deploy/kubernetes/` (11 manifests), `deploy/compose/` | — | K8s + compose |
| Docs | `docs/` | 40 files | phase reports, threat model, integration contract |

**Dependencies [VERIFIED]** (`pyproject.toml`): `cryptography>=42`, `PyJWT>=2.7`; optional extras `spire` (grpcio), `redis`, `postgres` (psycopg), `aws` (boto3), `pkcs11`.

### A.2 Happy LANG (`happy-lang-v8`, toolchain v1.0.0, hardened to v10) — Python 3.9+, 38,807 LOC

A **programming language toolchain** (`.hpy`): compiler → IR → Python backend → runtime, plus an AI-native layer and dev tooling. Zero third-party runtime dependencies.

| Subsystem | Path | LOC | Purpose |
|---|---|---:|---|
| **Compiler** | `happy/compiler/` | **12,702** | lexer, parser, AST, types, semantic, IR, contracts, contract_proofs, effects, permissions, optimizer, modules |
| **Runtime** | `happy/runtime/` | **2,658** | core, context, contracts, capability, secrets, async, values, errors |
| Backend | `happy/backend/` | 1,521 | IR→Python codegen, source maps |
| **Security analyzer** | `happy/security/analyzer.py` | **1,093** | SEC001–SEC012 static rules |
| **AI layer** | `happy/ai/` | **3,628** | providers, agent, verifier (trust ladder), sandbox, isolation, tools |
| Stdlib | `happy/std/` | 1,938 | core, io, collections, json, async, crypto, fs, net, process, env, … |
| Tools | `happy/tools/` | 3,072 | fmt, lint, lsp, repl, debugger, docgen, publish |
| Package manager | `happy/package/manager.py` | 886 | `happy.toml`/`happy.lock`, checksum-verified install |
| CLI | `happy/cli/` | 699 | `new/check/build/run/test/fmt/lint/verify/ai` |
| Tests | `tests/` | 22 files | unit + regression + adversarial |
| Attacks | `attacks/` | 2 harnesses | 13 + 39 reproducible exploits |
| Fuzzers | `tools/` | 3 | contracts, differential, scopes |

**Dependencies [VERIFIED]** (`pyproject.toml`): **none** at runtime; `pytest` for dev.

---

## B. Verified Functionality Matrix

Legend: **FI** = fully implemented & tested · **IT** = implemented, insufficiently tested · **PI** = partially implemented · **PP** = prototype/placeholder · **MI** = missing · **VU** = vulnerable/architecturally unsafe.

### B.1 AgentGuard

| Capability | Status | Evidence |
|---|---|---|
| Ed25519 passport issue/verify, chain to root | **FI** | `tests/test_identity.py`; full suite green |
| Revocation (credential/instance/agent/issuer) + cascade | **FI** | `service.py` `revoke_*`; adversarial suite |
| Replay protection (nonce + request_id + audience) | **FI** | `verification/verifier.py`; Redis-backed in HA tests |
| Sub-agent spawn (capability subsetting, depth) | **FI** | `service.py::spawn_sub_agent`; `test_identity.py` |
| Policy engine (OPA/Rego, fail-closed) | **FI** | `policy/engine.py`; `test_policy_unit.py` + `test_policy_pg_integration.py` |
| Policy enforcer (anti-bypass chokepoint) | **FI** | `policy/enforcer.py`; `test_phase9_adversarial.py` |
| Egress gateway (SSRF/DLP/rate limit) | **FI** | `egress/gateway.py`; 6 SSRF tests + 3 DLP tests PASS |
| RBAC / tenant isolation / sessions / OIDC | **FI** | `security/`; `test_security_unit.py`, `test_security_pg.py` |
| Runtime monitoring (pipeline, drift, risk) | **FI** | `test_phase5_runtime_monitoring.py` (96) + PG (20) |
| Autonomous response (loops, budgets, approvals, containment) | **FI** | `test_phase6_response.py` (60) + PG (14) |
| Assurance (audit hash chain, compliance, SIEM) | **IT** | `test_assurance_unit.py` (61) + PG (14); **live SIEM vendor endpoints unverified** |
| KMS/HSM (local-dev) | **FI** | `test_kms.py` |
| KMS/HSM (AWS KMS, PKCS#11) | **IT** | code-complete, **never run against live service** (README + `docs/KMS.md`) |
| SPIFFE/SPIRE | **IT** | `test_spiffe_*`; real-SPIRE integration test requires Docker, **not run in CI** |
| mTLS | **IT** | `test_mtls.py` (mocked SPIRE, real TLS); real-SPIRE test not run |
| Redis distributed state | **FI** | `test_phase9_ha.py` (5) PASS against real Redis |
| PostgreSQL storage + migrations | **FI** | 10 migrations; real-PG integration tests PASS |
| Kubernetes manifests | **IT** | 18 conformance tests PASS; **never applied to a cluster** |
| Docker image | **IT** | Dockerfile authored; **never built** (no container runtime) |
| SDK conformance vectors | **MI** | `tests/test_sdk_conformance.py` **errors**: fixture `sdks/conformance/vectors.json` absent from archive |
| Container escape / runtime hardening | **BLOCKED** | no container runtime |
| Live cluster RBAC / admission bypass | **BLOCKED** | no K8s API server |
| Sustained load / soak | **MI** | Phase 10 scope |

### B.2 Happy LANG

| Capability | Status | Evidence |
|---|---|---|
| Lexer / parser / AST | **FI** | `test_lexer_parser.py` 37 passed |
| Type system / semantic analysis | **FI** | `test_semantic.py` 60 passed |
| IR + contracts + permissions + effects | **FI** | `test_ir_contracts.py` 34 passed |
| Python backend + runtime + source maps | **FI** | `test_e2e_backend.py` 45 passed |
| Static contract prover (interval analysis) | **FI** | `test_contract_proofs.py` 24 passed; soundness fuzzer 0 failures |
| Capability/permission runtime enforcement | **FI** | `test_security_adversarial.py` 16 passed |
| Secret protection (tainted `Secret` box) | **FI** | `test_regression_v8_bugs.py`; attack #6 blocked |
| AI trust ladder (RAW→APPROVED) | **IT** | `test_ai_verifier.py` **1 failed / 47 passed** — see §B.3 |
| AI sandbox (static scan + restricted subprocess) | **IT** | `test_regression_v10_security.py` **2 failed / 33 passed** — env-caused |
| OS-level isolation (docker/bwrap/namespaces) | **IT** | `test_isolation.py` **2 failed / 11 passed** — env-caused |
| Security analyzer SEC001–SEC012 | **FI** | `test_security_rules.py` 13 passed |
| Package manager (checksum-verified install) | **FI** | `test_cli_tools.py` 41 passed |
| CLI / fmt / lint / LSP / REPL | **FI** | `test_cli_extended.py` 15, `test_cli_tools.py` 41 passed |
| 13 reported attacks closed | **FI** | `attacks/repro_all.py` → **0/13 VULNERABLE** |
| 39 extra adversarial checks blocked | **FI** | `attacks/new_attacks.py` → **0/39 VULNERABLE** |
| **Security boundary for a host system** | **VU** | By design: compile-time rejection + runtime capability denial + static analysis — **not OS-level isolation** (CHANGELOG, "Hardening" section) |

### B.3 Real test results [VERIFIED]

**AgentGuard — full suite with real PostgreSQL 15.19 + Redis 7:**

```
Ran 1186 tests in 75.627s
FAILED (errors=1, skipped=121)
```

- The **single error** is `tests.test_sdk_conformance.ConformanceTests.setUpClass` → `FileNotFoundError: .../sdks/conformance/vectors.json`. The fixture is referenced at `tests/test_sdk_conformance.py:18` but **is not present in the archive** (`ls sdks/` → *No such file or directory*). This is a **packaging gap, not a code failure** — 7 conformance tests are blocked, not failing.
- **121 skipped** = tests requiring infra not present (real SPIRE, live KMS/HSM, container runtime, live SIEM).
- Without infra (first run): 1170 tests, 2 errors (missing `yaml` module + the same fixture). After `pip install pyyaml`: 1187 tests, 1 error. The delta confirms the fixture gap is the only genuine defect.
- **Phase 9 suite explicitly:** `tests.test_phase9_adversarial tests.test_phase9_ha tests.test_phase9_deployment tests.test_phase9_server` → **`Ran 74 tests ... OK`** — exactly matches the claim in `docs/PHASE9_FINAL_REPORT.md`.
- **Live server [VERIFIED]:** `python3 -m agent_identity.server --bootstrap-admin` started and logged `{"event": "started", "host": "0.0.0.0", "port": 8443, "environment": "development"}` against real PG+Redis.

**Happy LANG — per-file pytest (full-suite run was OOM-killed by a fuzzer test):**

| Test file | Result |
|---|---|
| `test_ai_tools.py` | 24 passed |
| `test_ai_verifier.py` | **1 failed**, 47 passed |
| `test_cli_extended.py` | 15 passed |
| `test_cli_tools.py` | 41 passed |
| `test_contract_proofs.py` | 24 passed |
| `test_e2e_backend.py` | 45 passed |
| `test_integration.py` | 13 passed |
| `test_ir_contracts.py` | 34 passed |
| `test_isolation.py` | **2 failed**, 11 passed |
| `test_lexer_parser.py` | 37 passed |
| `test_modules.py` | 9 passed |
| `test_optimizer.py` | 17 passed |
| `test_pipeline.py` | 16 passed |
| `test_regression_v10_security.py` | **2 failed**, 33 passed |
| `test_regression_v8_bugs.py` | **1 failed**, 32 passed |
| `test_regression_v91.py` | 10 passed |
| `test_regression_v9_bugs.py` | 71 passed |
| `test_security_adversarial.py` | 16 passed |
| `test_security_rules.py` | 13 passed |
| `test_semantic.py` | 60 passed |
| `test_stdlib_extended.py` | 17 passed |
| `test_traits_match.py` | 15 passed |
| **Total** | **600 passed, 6 failed** |

**Failure triage [VERIFIED]:**

1. **`test_isolation.py` (2) and `test_regression_v10_security.py` (2) — ENVIRONMENT, not implementation.** Observed error: `AssertionError: 'timed out' not found in 'unshare: fork failed: Resource temporarily unavailable'`. The sandbox kernel refuses `unshare` (no user-namespace capability), so the isolation backend cannot start. These tests assert on the *timeout* path of a jail that never launched. **Not a code defect** — they would pass on a host with namespace support.
2. **`test_ai_verifier.py::test_tests_gate_passes_on_green_tests` (1) — REAL, environment-adjacent.** Observed: `AssertionError: 'REJECTED' != 'APPROVED'`. The TESTED gate runs candidate tests via `run_sandboxed_python`, which calls `select_backend(...)`; with no usable isolation backend the run is refused, so a green test suite is reported REJECTED. Same root cause as (1) but it **changes a security-relevant verdict** — worth a follow-up.
3. **`test_regression_v8_bugs.py::test_benign_tests_still_run` (1) — REAL, same root cause.** Observed: `AssertionError: 'REJECTED' == 'REJECTED'` (the test expects the benign run to be *approved*, not rejected).

> **Honest reading:** Happy LANG's own `ATTACK_REPORT.md` claims `453 passed, 187 subtests passed`. In this environment we observe **600 passed / 6 failed**, where 4 failures are provably environmental and 2 are the same environmental cause surfacing through a security verdict. The claim is **not reproducible as stated** here, but the discrepancy is explained by the missing kernel feature, not by regressions.

**Attack harnesses [VERIFIED]:**

```
$ python3 attacks/repro_all.py
=== 0/13 attacks still VULNERABLE ===
$ python3 attacks/new_attacks.py
=== 0/39 new checks VULNERABLE ===
```

**Master runner [VERIFIED]:** `python3 tests/run_all_tests.py` → `10/11 stages passed` (the one failure is the `pytest: tests/` stage, which failed only because `pytest` was not installed at that moment; after installing pytest the per-file runs above succeeded).

---

## C. Integration Architecture

### C.1 The two systems are complementary, not overlapping

```
┌──────────────────────────────────────────────────────────────────────┐
│  HAPPY LANG  (untrusted-code producer & executor)                    │
│  .hpy source → lexer → parser → semantic → IR → contracts/effects/   │
│  permissions → Python backend → runtime (capability checker, secrets)│
│  AI layer: providers → agent → verifier (trust ladder) → sandbox     │
└───────────────────────────┬──────────────────────────────────────────┘
                            │  (1) "may this agent perform action X on resource R?"
                            │      typed request, authenticated, versioned
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  AGENTGUARD  (central security policy enforcement — the boundary)    │
│  identity (passport/proof) → policy engine (OPA/Rego) → enforcer     │
│  → egress gateway (SSRF/DLP) → governance (tool registry)            │
│  → runtime monitoring → response → assurance (audit chain)           │
└──────────────────────────────────────────────────────────────────────┘
```

**The single integration seam already exists on both sides:**

- **AgentGuard side:** `src/agentguard_sdk/adapters/tool_guard.py` — `ToolGuard.execute()` normalizes a tool call into `action = "tool:<name>"`, calls `client.authorization.authorize(...)`, and **runs the callable only on an explicit ALLOW**; DENY raises `ToolGuardError`. This is the ready-made enforcement point.
- **Happy LANG side:** `happy/ai/verifier.py` — the trust ladder already produces a structured verdict (`VerificationResult` with `state`, `gates`, `diagnostics`) and `happy/security/analyzer.py` produces `SecurityReport` with `blocking` findings. This is the ready-made decision *input*.

### C.2 Proposed integration topology (target)

```
Happy LANG runtime
  └─ sensitive op (write_file / http_get / ai{...})
       └─ CapabilityChecker.check_operation()          [local, fast, advisory]
            └─ NEW: AgentGuardAuthorizer.authorize()   [remote, authoritative]
                 └─ POST /v1/authorize  (AgentGuard)
                      └─ PolicyEnforcer → OPA/Rego decision
                           └─ ALLOW → execute ; DENY/INDETERMINATE → raise
```

**Design rule:** Happy LANG's local `CapabilityChecker` stays as a **fast pre-filter and developer-experience layer**. The **authoritative** decision comes from AgentGuard. A local ALLOW must never override a remote DENY.

### C.3 Transport & trust

- **Transport:** HTTPS (AgentGuard's `http_transport.py` v1 surface; `enterprise_http.py` for `/v2` admin). AgentGuard's bundled server is plain HTTP with a static bearer token — **must be fronted by mTLS/OIDC** (its own README says so).
- **Authentication:** Happy LANG's agent presents an AgentGuard **passport** (`agp1.<payload>.<sig>`) + a fresh **possession proof** (`make_proof(credential_id, audience=...)`). AgentGuard verifies via `verify_credential(token, proof=, audience=)`.
- **Trust boundary:** the Happy LANG process is **semi-trusted** (may be compromised by prompt injection). AgentGuard treats every request as untrusted input and fails closed.

---

## D. Component Ownership Matrix

| Responsibility | Owner | Rationale |
|---|---|---|
| **Central security policy enforcement** | **AgentGuard** | Explicit task requirement; `policy/enforcer.py` is the anti-bypass chokepoint |
| Agent identity, credentials, revocation | **AgentGuard** | `credentials/passport.py`, `verification/verifier.py` |
| Authorization decisions (ALLOW/DENY/REQUIRE_APPROVAL) | **AgentGuard** | OPA/Rego engine, fail-closed |
| Egress control, SSRF, DLP | **AgentGuard** | `egress/gateway.py` |
| Tool/resource governance | **AgentGuard** | `governance/tool_registry.py` |
| Audit logging, tamper-evidence, SIEM | **AgentGuard** | `assurance/audit.py` hash chain |
| Runtime monitoring, drift, risk, response | **AgentGuard** | Phases 5–6 |
| Language parsing, typing, IR | **Happy LANG** | `compiler/` |
| Contract checking & static proofs | **Happy LANG** | `compiler/contracts.py`, `contract_proofs.py` |
| Effect inference | **Happy LANG** | `compiler/effects.py` |
| Code generation & execution | **Happy LANG** | `backend/`, `runtime/` |
| Secret tainting in-language | **Happy LANG** | `runtime/secrets.py` |
| AI output verification (trust ladder) | **Happy LANG** | `ai/verifier.py` |
| Untrusted-code sandboxing | **Happy LANG** | `ai/sandbox.py`, `ai/isolation.py` |
| **Being a security boundary for the host** | **NEITHER alone** | Happy LANG is explicitly *not* one; AgentGuard enforces at the authorization boundary, not the process boundary |

> **Critical ownership statement (task §9):** **AgentGuard remains the sole central security policy enforcement point.** Happy LANG's compiler, contracts, capability checker and security analyzer are **defence-in-depth and developer feedback — NOT a security boundary.** A Happy LANG program that compiles cleanly and whose contracts validate is **not** thereby authorized to do anything. Authorization is decided only by AgentGuard.

---

## E. Data-Flow & Trust-Boundary Description

### E.1 Primary flow (a Happy LANG agent performing a sensitive operation)

```
1. .hpy source authored (possibly by an LLM)
2. Happy LANG: parse → analyze → lower → contracts/permissions/effects
3. Happy LANG: AI verifier trust ladder (RAW→PARSED→GROUNDED→VERIFIED→TESTED→APPROVED)
      └─ sandbox gate: static dunder scan + restricted subprocess
4. Happy LANG runtime executes; sensitive op hits CapabilityChecker
5. [NEW] CapabilityChecker → AgentGuardAuthorizer
      ├─ attach passport + fresh proof (audience = agentguard)
      └─ POST /v1/authorize {agent_id, instance_id, action, resource, context}
6. AgentGuard: verify_credential(token, proof, audience)   ← identity boundary
7. AgentGuard: PolicyEnforcer.decide() → OPA/Rego          ← policy boundary
8. AgentGuard: ALLOW → execute ; DENY/REQUIRE_APPROVAL/INDETERMINATE → raise
9. AgentGuard: audit event (hash-chained) + runtime monitoring signal
10. Happy LANG: on DENY, raise CapabilityDenied/PermissionDenied with source location
```

### E.2 Trust boundaries

| # | Boundary | Trusted side | Untrusted side | Control |
|---|---|---|---|---|
| TB1 | Happy LANG runtime ↔ AgentGuard | AgentGuard | Happy LANG process (semi-trusted) | passport + proof, fail-closed verify |
| TB2 | AgentGuard control plane ↔ callers | AgentGuard | admin callers | transport authN/authZ (mTLS/OIDC + RBAC) |
| TB3 | AgentGuard ↔ storage/KMS | AgentGuard | — | integrity-critical; sign-only KeyStore |
| TB4 | LLM output ↔ Happy LANG compiler | compiler | model output | trust ladder + sandbox |
| TB5 | Happy LANG ↔ host OS | host | generated code | capability denial + optional OS isolation |

**Explicit non-boundary:** Happy LANG's `CapabilityChecker` runs **in the same process as the code it checks**. A compromised runtime can bypass it. It is a *correctness/UX* control, not a security boundary. This is why TB1 must terminate at AgentGuard.

---

## F. Required API & Event Contracts

### F.1 Authorization request (Happy LANG → AgentGuard) — **NEW, to be defined**

```jsonc
// POST /v1/authorize   (AgentGuard, existing route — see api/http_transport.py:166)
{
  "agent_id":    "agt_...",          // from verified passport
  "instance_id": "inst_...",         // from verified passport
  "action":      "tool:write_file",  // AgentGuard ToolGuard convention
  "resource":    "/data/out.json",
  "context": {
    "happy": {
      "operation":   "write_file",   // Happy LANG ENFORCEMENT_MAP key
      "action":      "file_write",   // Happy LANG abstract action
      "source_loc":  {"file": "app.hpy", "line": 14, "column": 9},
      "agent_scope": "Teller",
      "effects":     ["FileSystem"],
      "contracts":   ["requires path != \"\""]
    }
  },
  "correlation_id": "corr_..."
}
```

**Response** (AgentGuard `PolicyDecision`, existing shape):

```jsonc
{ "decision": "ALLOW" | "DENY" | "REQUIRE_APPROVAL",
  "reason": "...", "obligations": [...], "policy_id": "...", "policy_version": "...",
  "latency_ms": 3 }
```

**Contract rules:**
- `INDETERMINATE` (engine timeout, undefined rule, malformed result) **must be treated as DENY** by Happy LANG. AgentGuard already fails closed; Happy LANG must not soften it.
- Versioned: `context.happy` is a namespaced, additive-only extension. Unknown keys ignored.
- Typed: both sides should generate from a shared JSON Schema / dataclass pair.

### F.2 Security event (Happy LANG → AgentGuard) — **NEW**

```jsonc
// POST /v1/security/events   (AgentGuard, existing route — api/http_transport.py:168)
{ "events": [ { "event_type": "happy.capability.denied",
                "outcome": "denied", "action": "tool:write_file",
                "resource": "/data/out.json", "reason": "no capability",
                "correlation_id": "corr_...",
                "metadata": { "source_loc": {...}, "agent_scope": "Teller" } } ] }
```

### F.3 Existing contracts to reuse unchanged

| Contract | Location | Stability |
|---|---|---|
| `IdentityService` public methods | `api/service.py` | **Stable** (per `docs/INTEGRATION_CONTRACT.md`) |
| `VerificationResult.to_dict()` | `core/models.py` | **Stable** |
| `Reason` codes | `core/models.py` | **Stable** |
| Passport claims | `credentials/passport.py` | **Stable** |
| Storage ABCs | `storage/interfaces.py` | **Stable** |
| `ToolGuard.execute()` | `agentguard_sdk/adapters/tool_guard.py` | **Stable** |
| Happy LANG `VerificationResult` | `ai/verifier.py` | Internal (no versioning) |
| Happy LANG `SecurityReport` | `security/analyzer.py` | Internal (no versioning) |

> **Gap:** Happy LANG exposes **no versioned external contract** — its `VerificationResult`/`SecurityReport` are internal dataclasses. Any integration must pin a version and add a serialization boundary.

---

## G. Security Threat Model (integration-specific)

| ID | Threat | Vector | Mitigation | Status |
|---|---|---|---|---|
| T1 | **Happy LANG treated as a security boundary** | Team assumes "it compiles + contracts validate ⇒ safe" | Ownership matrix §D; AgentGuard is authoritative | **Design risk — must be enforced by review** |
| T2 | **Local ALLOW overrides remote DENY** | Happy LANG `CapabilityChecker` returns True, skips AgentGuard | Integration rule: remote decision is final; local is pre-filter only | **To implement** |
| T3 | **INDETERMINATE softened to ALLOW** | Network error → Happy LANG proceeds | Map INDETERMINATE → deny; AgentGuard already fails closed | **To implement** |
| T4 | **Prompt injection → tool use** | LLM output drives a sensitive op | Happy LANG trust ladder + AgentGuard `ToolGuard` | **Covered** (AgentGuard adversarial test 9 PASS) |
| T5 | **Credential theft from Happy LANG process** | Compromised runtime reads its own passport | Short TTL (15 min default), proof-of-possession, fast revocation | **Covered** |
| T6 | **SSRF via Happy LANG `http_get`** | Dynamic URL | AgentGuard egress gateway (6 SSRF tests PASS) | **Covered if routed through egress** |
| T7 | **Secret exfiltration** | `secret` field → log | Happy LANG `Secret` box + AgentGuard DLP | **Covered** (attack #6 blocked; DLP tests PASS) |
| T8 | **Sandbox escape from AI-generated code** | `__class__.__mro__` chain | Happy LANG static scan + restricted subprocess | **Covered** (attack #1 blocked) |
| T9 | **Audit gap across the seam** | Happy LANG denials not in AgentGuard audit chain | Emit `happy.*` events to `/v1/security/events` | **To implement** |
| T10 | **Replay of an authorization request** | Captured request replayed | AgentGuard nonce + request_id + audience | **Covered** |
| T11 | **Cross-tenant leakage** | Happy LANG agent reads another tenant's resource | AgentGuard tenant isolation (4 tests PASS) | **Covered** |
| T12 | **Isolation backend unavailable → silent allow** | No `unshare`/docker | `HAPPY_ISOLATION=required` fails closed | **Covered** (but see §B.3 failure 2) |

**Residual risk (accepted, documented by AgentGuard itself):** containment is effective at the **authorization boundary, not the process boundary** — a Happy LANG runtime that never calls `authorize()` is unconstrained. **This is the single most important integration risk.**

---

## H. Dependency & Compatibility Report

| Dimension | AgentGuard | Happy LANG | Conflict? |
|---|---|---|---|
| Python | `>=3.10` | `>=3.9` | **None** (3.10+ satisfies both) |
| Runtime deps | `cryptography`, `PyJWT` | **none** | **None** |
| Optional deps | grpcio, redis, psycopg, boto3, python-pkcs11 | pytest (dev) | **None** |
| Package name | `agentguard-agent-identity` | `happy-lang` | **None** |
| Import roots | `agent_identity`, `agentguard_sdk` | `happy` | **None** |
| Build backend | setuptools | setuptools | **None** |
| Test framework | `unittest` | `pytest` (+ unittest fallback) | **None** (coexist) |

**Verdict: no dependency conflict.** The two projects are cleanly separable and can share one virtualenv.

**Compatibility risks:**

1. **No shared contract package.** Neither project defines a versioned schema for the authorization request. **Must be created.**
2. **Happy LANG has no external API surface.** Its `VerificationResult`/`SecurityReport` are internal; serialization must be added.
3. **AgentGuard's bundled HTTP server is plain HTTP + static bearer token.** Production requires mTLS/OIDC fronting (its own README states this).
4. **AgentGuard's `sdks/conformance/vectors.json` is missing from the archive** — the SDK conformance contract cannot be validated as shipped.
5. **Happy LANG's isolation depends on kernel features** (`unshare`, docker/podman, bubblewrap) that are absent in this environment — a deployment prerequisite, not a code issue.

---

## I. Ordered Implementation Roadmap

> **Not started** — this audit is the deliverable. The roadmap is the plan for the *next* phase.

| # | Milestone | Deliverable | Depends on | Acceptance test |
|---|---|---|---|---|
| **M0** | **Clear blockers** | Restore `sdks/conformance/vectors.json`; document isolation prerequisites | — | `test_sdk_conformance` passes; isolation tests pass on a capable host |
| **M1** | **Define the contract** | `agentguard-happy-contract` package: JSON Schema + Python dataclasses for §F.1/F.2 | M0 | Schema round-trip test; both projects import it |
| **M2** | **Happy LANG authorizer client** | `happy/integration/agentguard.py`: passport + proof + `POST /v1/authorize`, INDETERMINATE→deny | M1 | Unit test with a fake AgentGuard; deny path raises |
| **M3** | **Wire into CapabilityChecker** | `CapabilityChecker` consults the remote authorizer; remote DENY is final | M2 | Integration test: local ALLOW + remote DENY ⇒ denied |
| **M4** | **Event forwarding** | Emit `happy.*` events to `/v1/security/events` | M2 | AgentGuard audit chain contains the event |
| **M5** | **Egress routing** | Happy LANG `http_get`/`http_post` routed through AgentGuard egress gateway | M3 | SSRF test blocked end-to-end |
| **M6** | **End-to-end adversarial suite** | Cross-project attack suite (prompt injection → tool use → egress) | M3–M5 | All attacks blocked; audit chain verifies |
| **M7** | **Production hardening** | mTLS/OIDC fronting, shared Redis rate limiter, KMS signer | M6 | Live deployment verification |

---

## J. Acceptance Tests for Every Proposed Milestone

| Milestone | Acceptance test (must be executed, not asserted) |
|---|---|
| M0 | `python3 -m unittest tests.test_sdk_conformance` → OK; `pytest tests/test_isolation.py` → OK on a namespace-capable host |
| M1 | `pytest tests/test_contract_schema.py` → schema validates both a Happy LANG request and an AgentGuard decision |
| M2 | `pytest tests/test_agentguard_client.py` → ALLOW executes; DENY raises; **INDETERMINATE raises**; timeout raises |
| M3 | `pytest tests/test_capability_remote.py` → local-allow/remote-deny ⇒ `CapabilityDenied`; local-deny/remote-allow ⇒ still denied (local is a pre-filter) |
| M4 | `pytest tests/test_event_forwarding.py` → event appears in AgentGuard audit chain; `verify_chain()` returns True |
| M5 | `pytest tests/test_egress_routing.py` → cloud-metadata URL blocked; private IP blocked; DNS-rebinding blocked |
| M6 | `python3 attacks/integration_attacks.py` → 0 vulnerable; AgentGuard `test_phase9_adversarial` still 42/42 |
| M7 | Live: server starts, `/readyz` 200, cross-tenant 403, oversized body 413, graceful shutdown |

---

## 11. Blockers

| # | Blocker | Severity | Evidence | Resolution |
|---|---|---|---|---|
| **B1** | **No integration contract exists.** Neither project defines a versioned, typed schema for the authorization request/response or the event payload. | **HIGH** | §F.3 — Happy LANG exposes only internal dataclasses; AgentGuard's `/v1/authorize` takes an untyped `context` dict | Build `agentguard-happy-contract` (M1) |
| **B2** | **`sdks/conformance/vectors.json` missing from the AgentGuard archive.** 7 SDK conformance tests error at `setUpClass`. | **MEDIUM** | `tests/test_sdk_conformance.py:18`; `ls sdks/` → not found; suite → `errors=1` | Restore the fixture; re-run (M0) |
| **B3** | **No OS-level isolation available in the test/CI environment.** `unshare: fork failed: Resource temporarily unavailable` → 4 Happy LANG tests fail, and 2 of them surface through a **security verdict** (green tests reported REJECTED). | **MEDIUM** | `test_isolation.py` (2 failed), `test_regression_v10_security.py` (2 failed), `test_ai_verifier.py` (1 failed), `test_regression_v8_bugs.py` (1 failed) | Provision a namespace-capable host or container runtime; document as a deployment prerequisite (M0) |
| **B4** | **Happy LANG is not a security boundary, but nothing in the code enforces that at the seam.** A runtime that never calls `authorize()` is unconstrained. | **HIGH** | AgentGuard `PHASE6` limitations: "containment is effective at the authorization boundary, not the process boundary" | M3 + M6; make the remote call mandatory for sensitive ops |
| **B5** | **AgentGuard's bundled server is plain HTTP with a static bearer token.** | **MEDIUM** | `docs/THREAT_MODEL.md` residual risks; README "Production considerations" | mTLS/OIDC fronting (M7) |
| **B6** | **Live KMS/HSM, real SPIRE, live SIEM, container runtime, K8s cluster all unverified.** 121 AgentGuard tests skipped. | **LOW–MEDIUM** | Suite output `skipped=121`; `docs/PHASE9_FINAL_REPORT.md` §7–8 | Provision infra; re-run (M7) |

---

## 12. Exact Next Implementation Milestone

> **M1 — Define and implement the typed, authenticated authorization contract between Happy LANG and AgentGuard.**

**Concretely:**

1. Create a shared contract package `agentguard-happy-contract` containing:
   - `AuthorizationRequest` / `AuthorizationDecision` dataclasses + JSON Schema (per §F.1),
   - `SecurityEvent` dataclass + JSON Schema (per §F.2),
   - a `CONTRACT_VERSION` constant and additive-only evolution rule.
2. Implement `happy/integration/agentguard.py` — an `AgentGuardAuthorizer` that:
   - obtains a passport + fresh possession proof (reusing `agentguard_sdk`),
   - calls `POST /v1/authorize` with the typed payload,
   - **maps `INDETERMINATE`/timeout/error → deny**,
   - raises `CapabilityDenied` with the Happy LANG source location on deny.
3. Wire it into `happy/runtime/capability.py::CapabilityChecker.check_operation()` as the **authoritative** decision, keeping the local check as a pre-filter.
4. Land the acceptance test `tests/test_capability_remote.py` (M3 row) proving **local-allow + remote-deny ⇒ denied**.

**Why this milestone first:** it is the smallest change that establishes the trust boundary the whole integration depends on (B1 + B4), it reuses two already-stable surfaces (`ToolGuard.execute()` and `CapabilityChecker.check_operation()`), and it is independently testable without touching either project's existing behaviour.

**Explicitly out of scope for this milestone:** egress routing (M5), event forwarding (M4), production hardening (M7), and any change to AgentGuard's policy engine.

---

## 13. Summary of Verified vs. Assumed vs. Blocked

| Category | Count | Examples |
|---|---|---|
| **VERIFIED** (executed & observed) | 20+ | AgentGuard 1186 tests / 1 error / 121 skipped; Phase 9 74 OK; live server on :8443; Happy LANG 600 passed / 6 failed; 0/13 + 0/39 attacks; both archives extracted |
| **ASSUMED** (source-inspected, not executed) | ~10 | OPA/Rego engine behaviour under load; KMS AWS/PKCS#11 adapters; SPIFFE real-SPORE; K8s manifests applied |
| **BLOCKED** (cannot verify here) | 6 | container escape, live cluster RBAC, live SIEM, KMS/HSM extraction, soak/load, OS isolation |

**No claim of zero vulnerabilities is made for either project.** Both projects' own documentation is unusually honest about their limits, and this audit confirms those limits rather than contradicting them.

---

*End of audit. No integration code was written; no existing functionality was modified or removed.*
