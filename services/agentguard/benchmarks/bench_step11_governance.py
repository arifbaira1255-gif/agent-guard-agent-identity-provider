"""Step 11 governance-overhead benchmark (measured, not claimed).

Measures the ResourceGuard decision path end to end:
  * ALLOW  — registry resolution + tool checks + a real Rego evaluation through OPA,
  * DENY   — the short-circuit paths (unknown resource, operation not permitted), which never reach
             the policy engine,
  * throughput under concurrency.

Run:
  PYTHONPATH=src:. python -m benchmarks.bench_step11_governance                      # OPA CLI engine
  AGENTGUARD_BENCH_ENGINE=http AGENTGUARD_TEST_OPA_URL=http://127.0.0.1:8181 \
    PYTHONPATH=src:. python -m benchmarks.bench_step11_governance                    # OPA HTTP server

Prints p50/p95/p99 in milliseconds. Numbers are for THIS machine and container and are not a
capacity claim.

NOTE on caching: the Step 10 decision cache is Redis-backed (``policy/cache.py``) and is NOT wired in
this harness, so no cache-hit benefit is claimed here. What this measures is the *uncached* decision
cost. The cache's safety properties (ALLOW-only, policy-version scoping, tenant/identity scoping,
generation invalidation on policy/JIT/approval change, fail-closed on backend error) are covered by
the Step 10 policy tests. Governance adds no cache of its own: the registry record is read
authoritatively on every decision, so a registry change takes effect on the next request.
"""
from __future__ import annotations

import os
import shutil
import statistics
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_identity.governance import (GovernanceConfig, GovernanceService, GovernanceOutcome,
                                       MemoryGovernanceStore)
from agent_identity.policy import (MemoryPolicyStore, PolicyConfig, PolicyDecisionService,
                                   StoreApprovalProvider, build_engine)
from agent_identity.security.rbac import ROLE_TENANT_ADMIN, effective_access

REGO = """
package agentguard.authz

default decision := {"decision": "DENY", "reason": "default_deny"}

decision := {"decision": "ALLOW", "reason": "gov_allow"} {
    input.request_context.registry_status == "registered"
}
"""


def build(engine_mode: str):
    pcfg = PolicyConfig(environment="development", engine="opa", opa_mode=engine_mode,
                        eval_timeout_ms=5000, cache_enabled=False)
    if engine_mode == "http":
        pcfg = pcfg.with_overrides(opa_url=os.environ.get("AGENTGUARD_TEST_OPA_URL",
                                                          "http://127.0.0.1:8181"))
    pstore = MemoryPolicyStore()
    psvc = PolicyDecisionService(pstore, build_engine(pcfg), pcfg,
                                approvals=StoreApprovalProvider(pstore, pcfg))
    a = effective_access("usr_admin", "acme", tenant_roles=(ROLE_TENANT_ADMIN,))
    rec = psvc.create_policy(a, name="gov", org_id="acme", rego_source=REGO)
    psvc.activate(a, rec.policy_id, 1)
    gov = GovernanceService(MemoryGovernanceStore(), psvc,
                            config=GovernanceConfig(environment="development"))
    gov.resources.register_resource(a, resource_id="api:billing", org_id="acme",
                                    resource_type="http_api", name="billing",
                                    owner="team", permitted_operations=["read"])
    return gov


def pcts(samples, *qs):
    s = sorted(samples)
    return [s[min(len(s) - 1, int(q * len(s)))] for q in qs]


def bench(gov, n, **kwargs):
    lat = []
    for _ in range(n):
        t = time.perf_counter()
        d = gov.decide(agent_id="agt1", tenant="acme", **kwargs)
        lat.append((time.perf_counter() - t) * 1000)
    assert d.outcome is GovernanceOutcome.ALLOW or d.outcome is GovernanceOutcome.DENY
    return lat, d


def bench_throughput(gov, n, threads):
    per = n // threads
    errs = []

    def w():
        try:
            for _ in range(per):
                gov.decide(agent_id="agt1", tenant="acme", resource_id="api:billing",
                           operation="read")
        except Exception as e:                     # noqa: BLE001
            errs.append(e)

    ts = [threading.Thread(target=w) for _ in range(threads)]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return (threads * per) / (time.perf_counter() - t0), errs


def main():
    if not shutil.which("opa"):
        print("opa binary not found; install OPA first")
        return 1
    mode = os.environ.get("AGENTGUARD_BENCH_ENGINE", "cli")
    print(f"== AgentGuard Step 11 governance benchmark (OPA {mode} engine) ==")
    print("machine/container-specific; not a capacity claim. Cache NOT wired (uncached cost).\n")
    gov = build(mode)

    n = 300 if mode == "http" else 60
    lat, d = bench(gov, n, resource_id="api:billing", operation="read")
    assert d.outcome is GovernanceOutcome.ALLOW
    p50, p95, p99 = pcts(lat[1:], 0.50, 0.95, 0.99)
    print(f"ALLOW (registry+tool+Rego)  n={n:4d}  p50={p50:8.3f} ms  p95={p95:8.3f} ms  "
          f"p99={p99:8.3f} ms  mean={statistics.mean(lat[1:]):8.3f} ms")

    lat2, d2 = bench(gov, 200, resource_id="api:unknown", operation="read")
    assert d2.outcome is GovernanceOutcome.DENY
    p50, p95, p99 = pcts(lat2, 0.50, 0.95, 0.99)
    print(f"DENY  (unknown resource)    n= 200  p50={p50:8.3f} ms  p95={p95:8.3f} ms  "
          f"p99={p99:8.3f} ms  (short-circuit, no Rego eval)")

    lat3, d3 = bench(gov, 200, resource_id="api:billing", operation="delete")
    assert d3.outcome is GovernanceOutcome.DENY
    p50, p95, p99 = pcts(lat3, 0.50, 0.95, 0.99)
    print(f"DENY  (op not permitted)    n= 200  p50={p50:8.3f} ms  p95={p95:8.3f} ms  "
          f"p99={p99:8.3f} ms  (short-circuit, no Rego eval)")

    tps, errs = bench_throughput(gov, 600 if mode == "http" else 200, 8)
    print(f"\nThroughput (8 threads, ALLOW path): {tps:,.0f} decisions/s   errors={len(errs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
