# AgentGuard Phase 9 — Performance & Capacity Engineering

> **Reproducibility.** Every figure below was measured in this environment by
> `benchmarks/phase9_bench.py`. The machine spec, dataset size and concurrency are printed with the
> results so a reader can judge transferability. **No figure is extrapolated or invented**, and no
> security control was disabled to improve a number.

---

## 1. Test configuration

| Parameter | Value |
|---|---|
| Machine | AMD EPYC 9254 24-Core (48 vCPU), Linux, Python 3.11.15 |
| Dataset | N = 2000 iterations per operation |
| Concurrency | single-threaded (component latency, not end-to-end SLA) |
| Stores | in-memory (component path); PostgreSQL path measured separately by the integration suite |
| Command | `BENCH_N=2000 PYTHONPATH=src:. python3 benchmarks/phase9_bench.py` |

---

## 2. Results (measured)

| Operation | n | p50 | p95 | p99 | mean |
|---|---:|---:|---:|---:|---:|
| credential issue (Ed25519) | 500 | 0.357 ms | 0.554 ms | 0.577 ms | 0.395 ms |
| **credential verify (hot path)** | 2000 | **0.237 ms** | 0.358 ms | 0.390 ms | 0.299 ms |
| policy authorize | 2000 | 0.017 ms | 0.025 ms | 0.028 ms | 0.018 ms |
| JIT grant issue | 500 | 0.006 ms | 0.006 ms | 0.010 ms | 0.006 ms |
| JIT grant lookup | 2000 | 0.089 ms | 0.142 ms | 0.151 ms | 0.111 ms |
| governance decide | 2000 | 0.013 ms | 0.015 ms | 0.017 ms | 0.013 ms |
| egress allow | 2000 | 0.019 ms | 0.035 ms | 0.052 ms | 0.030 ms |
| egress SSRF-blocked | 2000 | 0.018 ms | 0.032 ms | 0.038 ms | 0.021 ms |
| audit write (hash + sign) | 2000 | 0.042 ms | 0.066 ms | 0.078 ms | 0.055 ms |
| **audit chain verify** | 100 | **252.8 ms** | 279.2 ms | 287.3 ms | 252.6 ms |
| response evaluate | 500 | 0.001 ms | 0.001 ms | 0.001 ms | 0.001 ms |
| **HTTP `GET /livez`** (live server) | 500 | **0.481 ms** | 0.755 ms | 2.135 ms | 0.662 ms |

**Derived throughput (single-threaded, component path):**
* credential verify ≈ **3,300 ops/s** (1 / 0.299 ms);
* policy authorize ≈ **55,000 ops/s**;
* audit write ≈ **18,000 ops/s**.

---

## 3. Bottlenecks found (measured, not guessed)

### 3.1 Audit chain verification is O(n) — the dominant cost
`audit chain verify` at **252 ms** for a 2,000-record chain is ~4,600× slower than a single audit
write. This is inherent: verification re-hashes and re-verifies every signature in the chain. It is
**not** a defect — it is the cost of tamper-evidence — but it has capacity consequences:

* **Do not** run full-chain verification on a request path. It is an operator/audit action.
* For large tenants, verify **incrementally from a signed checkpoint** rather than from genesis.
* The Phase 7 design already supports signed checkpoints; anchoring them externally (Phase 10) is
  the recommended next step to bound verification cost.

### 3.2 Policy evaluation is fast only with the null engine
`policy authorize` at 0.017 ms reflects `engine=NullEngine` (OPA not installed here). With a real
OPA/Rego engine the cost is dominated by the engine round trip and is **not** represented by this
figure. **Do not** use 0.017 ms for capacity planning with OPA enabled.

### 3.3 HTTP overhead is small
`GET /livez` p50 0.481 ms shows the server's own overhead (parsing, headers, thread handoff) is
sub-millisecond; the security work dominates end-to-end latency.

---

## 4. Optimization trade-offs (deliberately NOT taken)

| Tempting optimization | Why it was rejected |
|---|---|
| Cache credential verification results to skip signature checks | would let a revoked credential be accepted until cache expiry |
| Skip the replay check when Redis is slow | replay protection is a security control; the system fails closed instead |
| Verify the audit chain lazily / partially on the request path | would weaken tamper-evidence |
| Raise the rate limit to improve throughput numbers | would weaken DoS protection |

**No security control was disabled to improve any figure in this document.**

---

## 5. Capacity guidance (with caveats)

* **Per replica:** the control-plane components are sub-millisecond; a single replica can serve
  thousands of authorization decisions per second. The real ceiling is the **PostgreSQL primary**
  and the **KMS/HSM** signing rate, not the application.
* **Scale out:** add replicas (HPA, `maxReplicas: 12`); the service is stateless.
* **Scale up the database:** size `max_connections` ≥ `replicas × pool_max` + headroom.
* **Audit verification:** schedule it off the request path; expect ~250 ms per 2,000 records.

> ⚠️ **Not claimed:** enterprise-scale capacity, a specific SLA, or behaviour under sustained
> multi-hour load. This phase measured **component latency**, not a soak test. A soak/load test
> against a production-like PostgreSQL + KMS deployment is **Phase 10** work.

---

## 6. Reproducing

```bash
# component benchmarks
BENCH_N=2000 PYTHONPATH=src:. python3 benchmarks/phase9_bench.py

# include HTTP latency against a running server
python -m agent_identity.server --host 127.0.0.1 --port 8443 &
AGENTGUARD_BENCH_URL=http://127.0.0.1:8443 BENCH_N=2000 PYTHONPATH=src:. python3 benchmarks/phase9_bench.py
```
