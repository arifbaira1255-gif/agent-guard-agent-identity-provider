# AgentGuard Phase 9 — Adversarial Security Assessment

> **Scope & honesty.** This is a **controlled, isolated** adversarial suite run against the
> integrated platform with synthetic data and in-memory stores. **No production system was touched.**
> A passing suite means the tested controls held — it does **not** mean the system is
> vulnerability-free. Findings are ranked by severity and exploitability; confirmed high/critical
> issues were fixed and retested.

---

## 1. Method

`tests/test_phase9_adversarial.py` — **42 tests, all passing** (1 skipped where a shape differed,
now fixed). Each test asserts the platform **refuses** the attack. Coverage maps to the Phase 9
brief §7.

---

## 2. Coverage & results

| # | Attack class | Tests | Result |
|---|---|---:|---|
| 1 | Authentication / authorization bypass | 5 | **PASS** — deny-by-default; unknown permission denied; developer cannot revoke others; analyst cannot execute containment; operator cannot approve |
| 2 | Cross-tenant data access | 4 | **PASS** — tenant scope mismatch denied; tenant role cannot grant platform role; non-admin cannot grant platform role; platform admin may cross-tenant |
| 3 | Privilege escalation | 3 | **PASS** — explicit deny beats grant; tenant admin lacks platform admin; unknown role rejected |
| 4 | Credential leakage | 2 | **PASS** — password/api_key/refresh_token/token redacted; private-key material redacted |
| 5 | Replay & concurrency | 3 | **PASS** — replay rejected; exactly one idempotency winner across 8 threads; body mismatch → CONFLICT |
| 6 | Policy-enforcement bypass | 3 | **PASS** — unauthorized create/activate denied; invalid Rego rejected |
| 7 | Egress / SSRF bypass | 6 | **PASS** — cloud metadata, literal metadata IP, private/loopback, DNS rebinding (mixed answer), unregistered host, malformed URL all blocked |
| 8 | DLP evasion | 3 | **PASS** — plaintext secret detected; base64-encoded secret detected; credential-named key flagged |
| 9 | Prompt-injection → tool use | 2 | **PASS** — ungranted tool denied; capability escalation via claim denied |
| 10 | Resource exhaustion / DoS | 5 | **PASS** — rate limiter fails closed; pagination clamped; negative/zero rejected; time range bounded; oversized filter rejected |
| 11 | Audit tampering | 4 | **PASS** — clean chain verifies; **modified record detected**; **reordered records detected**; **missing record detected** |
| 12 | Unsafe rollback | 1 | **PASS** — rollback requires authority |
| 13 | Secret redaction in exports | 1 | **PASS** — a secret never appears in an exported SIEM event |

---

## 3. Findings

### 3.1 Confirmed & FIXED (this phase)

| ID | Severity | Finding | Fix | Retest |
|---|---|---|---|---|
| **P9-01** | **HIGH** | **Redis TLS was broken on modern redis-py.** `state/redis_backend.py` passed `ssl=True` to the connection pool. redis-py ≥ 6 removed that kwarg, so **every Redis operation raised `TypeError`** and the backend failed closed — meaning replay protection, permission caching, rate limiting and locks were **entirely unavailable** on any deployment with a current redis-py. | Select TLS via `connection_class=redis.SSLConnection` instead of the removed kwarg. | **PASS** — `tests/test_phase9_ha.py::SharedStateTests` now exercises real Redis successfully; full regression green. |

> P9-01 is the most important finding of this phase: a dependency-compatibility regression that
> silently disabled a security control. It was found by *running* the HA tests against real Redis,
> not by reading code.

### 3.2 Confirmed, accepted with documentation (not fixed)

| ID | Severity | Finding | Rationale |
|---|---|---|---|
| P9-02 | **MEDIUM** | The Phase 8 in-process `RateLimiter` is **per-replica**, so the effective limit is `replicas × limit`. | Documented in `PHASE9_HA.md` §6. A shared Redis limiter is the production path; deferred (out of this phase's scope). |
| P9-03 | **MEDIUM** | Audit chain verification is **O(n)** (~250 ms / 2,000 records). | Inherent to tamper-evidence; documented in `PHASE9_BENCHMARKS.md` §3.1. Mitigation: verify from signed checkpoints, off the request path. |
| P9-04 | **LOW** | `bandit` reports 44 LOW + 39 MEDIUM static-analysis findings. | Triaged: predominantly `assert` usage, `subprocess` in scripts, and `try/except/pass` in cleanup paths. No HIGH/CRITICAL. See `PHASE9_SUPPLY_CHAIN.md`. |
| P9-05 | **LOW** | Dependency CVEs reported by `pip-audit` are in the **sandbox's global environment** (pillow, pip, pypdf2, setuptools, starlette), not in AgentGuard's declared dependency closure. | Reported verbatim, not filtered. CI runs `pip-audit` in the project venv so the report covers exactly the project closure. |

### 3.3 Not tested (blocked / out of scope)

| Area | Status |
|---|---|
| Container escape / runtime hardening | **BLOCKED** — no container runtime in this environment |
| Live cluster RBAC / admission-controller bypass | **BLOCKED** — no Kubernetes API server |
| Live SIEM vendor endpoint attacks | **BLOCKED** — no vendor endpoint (unchanged from Phase 7) |
| Sustained load / soak DoS | **NOT RUN** — Phase 10 scope |
| KMS/HSM key-extraction attacks | **BLOCKED** — no KMS/HSM device |

---

## 4. What the suite proves (and does not)

**Proves:** the tested authorization, tenant-isolation, replay, policy, egress/SSRF, DLP,
prompt-injection, DoS-bound, audit-tamper and redaction controls **held** under the tested attacks.

**Does not prove:** that the system is vulnerability-free, that untested attack classes are safe, or
that the platform resists a determined adversary with infrastructure access. **No such claim is
made.**
