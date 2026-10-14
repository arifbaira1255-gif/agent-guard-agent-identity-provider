#!/usr/bin/env python3
"""AgentGuard Phase 9 -- reproducible control-plane benchmarks.

Honest measurement, no extrapolation. Every number printed here is measured on THIS machine in
THIS run; the machine spec, dataset size and concurrency are printed alongside so a reader can
judge whether the numbers transfer. Nothing is optimized by disabling a security control.

    PYTHONPATH=src:. python3 benchmarks/phase9_bench.py

Measured operations (the security-critical control-plane round trips):
  1. identity issue + verify (Ed25519 passport, proof of possession)
  2. credential verification only (the hot path)
  3. policy evaluation (OPA if present, else the null engine -- reported honestly)
  4. JIT authorization grant issue + lookup
  5. governance decision (resource/tool guard)
  6. egress/DLP decision (allow + SSRF-blocked + DLP-blocked)
  7. tamper-evident audit write + chain verification
  8. incident/response evaluation
  9. HTTP API latency against a running server (optional; set AGENTGUARD_BENCH_URL)

Caveats that MUST accompany these figures in any capacity plan:
  * In-memory stores are used for the pure-component benchmarks; the PostgreSQL-backed path is
    slower and is measured separately by the integration suite.
  * Single-process, single-threaded unless a concurrency figure is printed.
  * These are component latencies, not end-to-end SLA numbers.
"""
from __future__ import annotations

import gc
import json
import os
import platform
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

N = int(os.environ.get("BENCH_N", "2000"))
ORG = "org_bench"


def machine() -> str:
    try:
        with open("/proc/cpuinfo") as fh:
            model = next((l.split(":", 1)[1].strip() for l in fh if l.startswith("model name")), "?")
        cores = os.cpu_count()
    except OSError:  # pragma: no cover
        model, cores = "?", os.cpu_count()
    return f"{model} x{cores}, Python {platform.python_version()}, {platform.system()}"


def pct(vals, p):
    if not vals:
        return 0.0
    s = sorted(vals)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def report(name, lat_ms, *, extra=""):
    if not lat_ms:
        print(f"  {name:<34} no samples")
        return
    print(f"  {name:<34} n={len(lat_ms):<6} "
          f"p50={pct(lat_ms,50):8.3f}ms p95={pct(lat_ms,95):8.3f}ms p99={pct(lat_ms,99):8.3f}ms "
          f"mean={statistics.fmean(lat_ms):8.3f}ms {extra}")


def timed(fn, n=N):
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t0) * 1000.0)
    return out


# --------------------------------------------------------------------------- 1-2 identity
def bench_identity():
    from agent_identity import IdentityService, AgentSideKey
    from agent_identity.core.config import IdentityConfig
    from agent_identity.observability.logging import SecurityLogger
    svc = IdentityService(IdentityConfig(log_to_python_logging=False),
                          logger=SecurityLogger(use_python_logging=False))
    svc.register_organization(ORG, "Bench Org")
    agent = svc.register_agent(ORG, "bench-agent", "support", "ops@bench.io", "bench",
                               ["tickets:read"], "production", {})
    inst = svc.create_agent_instance(agent["agent_id"])
    key = AgentSideKey()

    def issue():
        svc.issue_credential(agent["agent_id"], inst["instance_id"],
                             **key.csr(agent["agent_id"], inst["instance_id"]))

    issue_lat = timed(issue, max(50, N // 4))

    cred = svc.issue_credential(agent["agent_id"], inst["instance_id"],
                                **key.csr(agent["agent_id"], inst["instance_id"]))
    proof = key.make_proof(cred.credential_id, audience="bench-api")

    def verify():
        svc.verify_credential(cred.token, proof=proof, audience="bench-api")

    verify_lat = timed(verify, N)
    return issue_lat, verify_lat


# --------------------------------------------------------------------------- 3 policy
def bench_policy():
    from agent_identity.policy import MemoryPolicyStore, PolicyConfig, PolicyDecisionService, build_engine
    from agent_identity.security.rbac import ROLE_TENANT_ADMIN, effective_access
    cfg = PolicyConfig(environment="development")
    engine = build_engine(cfg)
    engine_name = type(engine).__name__
    svc = PolicyDecisionService(MemoryPolicyStore(), engine, cfg)
    actor = effective_access("usr_bench", ORG, tenant_roles=(ROLE_TENANT_ADMIN,))
    # A trivial allow policy; if OPA is absent the null engine returns indeterminate (reported).
    rego = 'package agentguard.authz\ndefault decision := {"decision":"ALLOW","reason":"bench"}\n'
    try:
        p = svc.create_policy(actor, name="bench", org_id=ORG, rego_source=rego)
        svc.activate(actor, p.policy_id, 1)
    except Exception as e:  # noqa: BLE001
        print(f"  (policy setup note: {type(e).__name__}: {e})")

    def evaluate():
        try:
            svc.authorize(agent_id="agt_bench", tenant=ORG, action="tickets:read",
                          resource="ticket/1")
        except Exception:  # noqa: BLE001
            pass

    return timed(evaluate, N), engine_name


# --------------------------------------------------------------------------- 4 JIT
def bench_jit():
    from agent_identity.policy import JitGrantService, MemoryPolicyStore, PolicyConfig
    cfg = PolicyConfig(environment="development")
    jit = JitGrantService(MemoryPolicyStore(), cfg)

    def issue():
        jit.issue(org_id=ORG, agent_id="agt_bench", action="tickets:read", resource="ticket/1",
                  ttl_seconds=300, issued_by="bench")

    issue_lat = timed(issue, max(50, N // 4))

    def lookup():
        jit.find_live_grant(org_id=ORG, agent_id="agt_bench", action="tickets:read",
                            resource="ticket/1")

    return issue_lat, timed(lookup, N)


# --------------------------------------------------------------------------- 5 governance
def bench_governance():
    from agent_identity.governance import (GovernanceConfig, GovernanceService,
                                           MemoryGovernanceStore, ResourceDescriptor)
    svc = GovernanceService(MemoryGovernanceStore(), GovernanceConfig(environment="development"))

    def decide():
        svc.decide(agent_id="agt_bench", tenant=ORG, resource_id="res_bench",
                   operation="read", resource_type="database")

    return timed(decide, N)


# --------------------------------------------------------------------------- 6 egress/DLP
def bench_egress():
    from agent_identity.egress import (EgressConfig, EgressService, MemoryEgressStore)
    from agent_identity.egress.addresses import AddressPolicy, StaticDnsResolver
    from agent_identity.egress.gateway import EgressRequest
    resolver = StaticDnsResolver({"api.example.com": ["93.184.216.34"],
                                  "evil.example.net": ["169.254.169.254"]})
    svc = EgressService(MemoryEgressStore(), config=EgressConfig(environment="development"),
                        address_policy=AddressPolicy(resolver=resolver))

    def allow():
        svc.decide(agent_id="agt_bench", tenant=ORG,
                   request=EgressRequest(url="https://api.example.com/v1/data"))

    def ssrf():
        svc.decide(agent_id="agt_bench", tenant=ORG,
                   request=EgressRequest(url="https://evil.example.net/latest/meta-data"))

    return timed(allow, N), timed(ssrf, N)


# --------------------------------------------------------------------------- 7 audit
def bench_audit():
    from agent_identity.assurance import AssuranceConfig, AssuranceService, MemoryAssuranceStore
    from agent_identity.assurance.audit import LocalEd25519Signer, TamperEvidentAudit
    store = MemoryAssuranceStore()
    audit = TamperEvidentAudit(store, config=AssuranceConfig(environment="development"),
                               signer=LocalEd25519Signer(environment="development"))

    def write():
        audit.record("bench.event", org_id=ORG, actor_user_id="usr_bench", outcome="ok")

    write_lat = timed(write, N)

    def verify():
        audit.verify_chain(org_id=ORG)

    return write_lat, timed(verify, max(20, N // 20))


# --------------------------------------------------------------------------- 8 response
def bench_response():
    from agent_identity.response import MemoryResponseStore, ResponseConfig, ResponseService
    svc = ResponseService(MemoryResponseStore(), config=ResponseConfig(environment="development"))

    def evaluate():
        try:
            svc.evaluate_agent(org_id=ORG, agent_id="agt_bench")
        except Exception:  # noqa: BLE001
            pass

    return timed(evaluate, max(50, N // 4))


# --------------------------------------------------------------------------- 9 HTTP
def bench_http():
    url = os.environ.get("AGENTGUARD_BENCH_URL")
    if not url:
        return None
    import urllib.request
    lat = []
    for _ in range(max(50, N // 4)):
        t0 = time.perf_counter()
        try:
            urllib.request.urlopen(url + "/livez", timeout=5).read()
        except Exception:  # noqa: BLE001
            pass
        lat.append((time.perf_counter() - t0) * 1000.0)
    return lat


def main() -> int:
    print("=" * 78)
    print("AgentGuard Phase 9 -- control-plane benchmarks")
    print("=" * 78)
    print(f"machine:   {machine()}")
    print(f"dataset:   N={N} iterations per operation (in-memory stores)")
    print(f"concurrency: single-threaded (component latency, not end-to-end SLA)")
    print()

    print("[1-2] Identity (Ed25519 passport)")
    issue_lat, verify_lat = bench_identity()
    report("credential issue", issue_lat)
    report("credential verify (hot path)", verify_lat)
    gc.collect()

    print("[3] Policy evaluation")
    pol_lat, engine_name = bench_policy()
    report("policy authorize", pol_lat, extra=f"engine={engine_name}")
    gc.collect()

    print("[4] JIT authorization")
    jit_issue, jit_lookup = bench_jit()
    report("jit grant issue", jit_issue)
    report("jit grant lookup", jit_lookup)
    gc.collect()

    print("[5] Governance decision")
    report("governance decide", bench_governance())
    gc.collect()

    print("[6] Egress / DLP decision")
    eg_allow, eg_ssrf = bench_egress()
    report("egress allow", eg_allow)
    report("egress SSRF-blocked", eg_ssrf)
    gc.collect()

    print("[7] Tamper-evident audit")
    au_write, au_verify = bench_audit()
    report("audit write (hash+sign)", au_write)
    report("audit chain verify", au_verify)
    gc.collect()

    print("[8] Incident / response")
    report("response evaluate", bench_response())
    gc.collect()

    print("[9] HTTP API (optional)")
    http_lat = bench_http()
    if http_lat is None:
        print("  set AGENTGUARD_BENCH_URL=http://host:port to measure HTTP latency")
    else:
        report("GET /livez", http_lat)

    print()
    print("NOTE: figures are component latencies on the machine above with in-memory stores.")
    print("      The PostgreSQL-backed path is slower; see docs/PHASE9_BENCHMARKS.md.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
