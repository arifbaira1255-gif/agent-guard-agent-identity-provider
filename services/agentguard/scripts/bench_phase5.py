#!/usr/bin/env python3
"""Phase 5 reproducible benchmarks.

Honest measurement, no extrapolation. Every number printed here is measured on THIS machine in
THIS run; the machine spec is printed alongside so a reader can judge whether the numbers transfer.

    PYTHONPATH=src:. python3 scripts/bench_phase5.py

Phases measured:
  1. ingestion throughput   -- normalize + redact + dedup + store
  2. correlation query      -- p50/p95/p99 over an N-event corpus
  3. intent-graph query     -- suspicious-chain traversal over an N-event graph
  4. profile build          -- folding an agent's history into a behavioural profile
  5. drift evaluation       -- full drift pass over an agent's event set
  6. risk assessment        -- scoring pass
  7. alert dedup/rate-limit -- raise N alerts through the dedup+ratelimit path

What is measured is the in-memory store plus, for one phase, the real PostgreSQL store. See
docs/PHASE5_FINAL_REPORT.md for the caveats that must accompany these figures in any capacity plan.
"""
from __future__ import annotations

import gc
import os
import platform
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_identity.runtime_monitoring import (  # noqa: E402
    AlertService, BehaviorProfileService, DriftDetector, IntentGraph, MonitoringConfig,
    RiskScorer, RuntimeEventPipeline)
from agent_identity.runtime_monitoring.memory_store import MemoryRuntimeMonitoringStore  # noqa: E402

ORG = "org_bench"
N = int(os.environ.get("BENCH_N", "20000"))
NOW = time.time() - 3600


def machine() -> str:
    try:
        with open("/proc/cpuinfo") as fh:
            model = next((l.split(":", 1)[1].strip() for l in fh if l.startswith("model name")), "?")
        cores = os.cpu_count()
    except OSError:                                                   # pragma: no cover
        model, cores = "?", os.cpu_count()
    return f"{model} x{cores}, Python {platform.python_version()}, {platform.system()}"


def fmt(n: float) -> str:
    return f"{n:,.0f}"


def pct(values, p):
    if not values:
        return 0.0
    return statistics.quantiles(values, n=100)[min(p, 99) - 1] if len(values) > 1 else values[0]


def event(i: int) -> dict:
    return {"org_id": ORG, "event_type": ("tool.invocation" if i % 7 else "dlp.blocked"),
            "ts": NOW + (i % 600), "agent_id": f"agent_{i % 25}",
            "action": "read" if i % 5 else "write", "resource": f"res://{i % 50}",
            "decision": "ALLOW" if i % 4 else "DENY", "correlation_id": f"corr_{i % 500}",
            "trace_id": f"trace_{i % 300}", "policy_id": "pol_1", "policy_version": "3",
            "destination": f"svc-{i % 20}.internal", "resource_type": "api",
            "data_classes": ["pii"] if i % 3 == 0 else [],
            "extra": {"tool_id": f"tool_{i % 12}", "method": "GET", "status_code": 200}}


def bench_ingest():
    store = MemoryRuntimeMonitoringStore()
    pipe = RuntimeEventPipeline(store, config=MonitoringConfig(default_min_samples=5))
    payloads = [event(i) for i in range(N)]
    gc.collect()
    t0 = time.perf_counter()
    stored = 0
    for p in payloads:
        if pipe.ingest(p).stored:
            stored += 1
    dt = time.perf_counter() - t0
    print(f"1. ingestion            : {fmt(stored)} stored / {dt:.3f}s "
          f"= {fmt(stored / dt)} events/s  ({fmt(dt / max(stored, 1) * 1e6)} us/event)")
    return store, pipe


def bench_correlation(store):
    lat = []
    gc.collect()
    for i in range(2000):
        t0 = time.perf_counter()
        store.list_events(org_id=ORG, correlation_id=f"corr_{i % 500}", limit=500)
        lat.append((time.perf_counter() - t0) * 1000)
    print(f"2. correlation query    : p50={pct(lat, 50):.3f}ms  p95={pct(lat, 95):.3f}ms  "
          f"p99={pct(lat, 99):.3f}ms  (n=2000)")


def bench_graph():
    store = MemoryRuntimeMonitoringStore()
    pipe = RuntimeEventPipeline(store, config=MonitoringConfig(default_min_samples=5))
    g = IntentGraph(store)
    for i in range(N):
        g.record_event(pipe.normalize(event(i)))
    lat = []
    gc.collect()
    for i in range(500):
        t0 = time.perf_counter()
        g.suspicious_chains(org_id=ORG, agent_id=f"agent_{i % 25}", max_depth=3, limit=50)
        lat.append((time.perf_counter() - t0) * 1000)
    print(f"3. graph query          : p50={pct(lat, 50):.3f}ms  p95={pct(lat, 95):.3f}ms  "
          f"(n=500, graph edges={len(store.list_edges(org_id=ORG, limit=10 ** 9))})")


def bench_analysis(store, pipe):
    events = store.list_events(org_id=ORG, agent_id="agent_0", limit=10 ** 9)[0]
    svc = BehaviorProfileService(store, config=MonitoringConfig(default_min_samples=5))
    t0 = time.perf_counter()
    profile = svc.build(org_id=ORG, agent_id="agent_0", events=events, now=NOW + 700)
    print(f"4. profile build        : {len(events)} events in window -> {time.perf_counter() - t0:.4f}s "
          f"(tools={len(profile.tools)}, resources={len(profile.resources)}, "
          f"destinations={len(profile.destinations)}, mature={profile.is_mature})")
    det = DriftDetector()
    t0 = time.perf_counter()
    findings = det.detect(org_id=ORG, agent_id="agent_0", events=events, profile=profile)
    print(f"5. drift evaluation     : {len(findings)} findings in {time.perf_counter() - t0:.4f}s")
    t0 = time.perf_counter()
    a = RiskScorer(config=MonitoringConfig(default_min_samples=5)).assess(
        org_id=ORG, agent_id="agent_0", events=events, findings=findings)
    print(f"6. risk assessment      : score={a.score} band={a.band} "
          f"in {time.perf_counter() - t0:.4f}s ({len(a.signals)} signals)")


def bench_alerts():
    store = MemoryRuntimeMonitoringStore()
    svc = AlertService(store, config=MonitoringConfig())
    rule = svc.register_rule(org_id=ORG, name="bench", dedup_window_s=60, rate_window_s=3600,
                             max_per_window=10 ** 9)
    gc.collect()
    t0 = time.perf_counter()
    for i in range(N):
        svc.raise_alert(org_id=ORG, rule=rule, severity="high", title=f"t{i % 1000}", agent_id="a",
                        event_ids=[f"e{i}"], ts=NOW + (i % 600))
    dt = time.perf_counter() - t0
    alerts = svc.list_alerts(org_id=ORG, limit=1)
    print(f"7. alert dedup/ratelimit: {fmt(N)} raises in {dt:.3f}s = {fmt(N / dt)} raises/s "
          f"({len(svc.list_alerts(org_id=ORG, limit=10 ** 9))} distinct alerts after dedup)")


def bench_pg():
    host = os.environ.get("AGENTGUARD_TEST_PG_HOST")
    if not host:
        print("8. postgres ingestion   : SKIPPED (set AGENTGUARD_TEST_PG_HOST to measure)")
        return
    import secrets                                                     # noqa: PLC0415
    import psycopg                                                     # noqa: PLC0415
    from agent_identity.storage.postgres import PgConfig, migrate       # noqa: PLC0415
    from agent_identity.storage.postgres.db import Database            # noqa: PLC0415
    from agent_identity.storage.postgres.runtime_monitoring import (    # noqa: PLC0415
        PgRuntimeMonitoringStore)
    user = os.environ["AGENTGUARD_TEST_PG_USER"]
    pw = os.environ["AGENTGUARD_TEST_PG_PASSWORD"]
    name = "bench_" + secrets.token_hex(5)
    with psycopg.connect(host=host, user=user, password=pw, dbname="postgres", autocommit=True) as a:
        a.execute(f'CREATE DATABASE "{name}"')                          # generated name
    cfg = PgConfig(environment="development", host=host,
                   port=int(os.environ.get("AGENTGUARD_TEST_PG_PORT", "5432")), dbname=name,
                   user=user, password=pw, sslmode="disable", retry_initial_backoff_seconds=0.01,
                   pool_min_size=1, pool_max_size=8).validate()
    db = Database(cfg)
    migrate.migrate(db)
    store = PgRuntimeMonitoringStore(db)
    pipe = RuntimeEventPipeline(store, config=MonitoringConfig(default_min_samples=5))
    with db.tenant_scope(None, platform_admin=True):
        db.run("seed", lambda c: c.execute(
            "INSERT INTO organizations (org_id,name,status,created_at,active_issuer_key_id)"
            " VALUES (%s,'b','active',%s,'k') ON CONFLICT DO NOTHING", (ORG, NOW)))
    m = max(1000, N // 5)
    gc.collect()
    t0 = time.perf_counter()
    with db.tenant_scope(ORG):
        for i in range(m):
            pipe.ingest(event(i))
    dt = time.perf_counter() - t0
    with db.tenant_scope(ORG):
        n = store.count_events(org_id=ORG)
    print(f"8. postgres ingestion   : {fmt(n)} stored / {dt:.3f}s = {fmt(n / dt)} events/s "
          f"(sync, single connection, per-event transaction)")
    db.close()
    with psycopg.connect(host=host, user=user, password=pw, dbname="postgres", autocommit=True) as a:
        a.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def main():
    print("=" * 92)
    print("AgentGuard Phase 5 benchmarks")
    print(f"machine : {machine()}")
    print(f"corpus  : N={fmt(N)} events per phase; timings are wall-clock, single process, no warmup")
    print("=" * 92)
    store, pipe = bench_ingest()
    bench_correlation(store)
    bench_graph()
    bench_analysis(store, pipe)
    bench_alerts()
    bench_pg()
    print("=" * 92)
    print("CAVEAT: single-process, in-memory (except phase 8), no concurrency, no warmup, one run.")
    print("These figures are indicative of the code path, NOT a capacity guarantee. Re-run in your")
    print("target topology before sizing production.")


if __name__ == "__main__":
    main()
