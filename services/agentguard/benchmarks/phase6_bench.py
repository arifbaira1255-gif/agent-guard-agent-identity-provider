"""Phase 6 micro-benchmarks (single-process, no warm-up, NOT a load test).

Measures the response plane's hot paths against the in-memory store so the numbers describe the
ALGORITHMS, not the database. The PostgreSQL figures elsewhere in the report are a floor, not a
ceiling: they are one transaction per operation on a single connection with no batching.

    PYTHONPATH=src:. python3 benchmarks/phase6_bench.py
"""
from __future__ import annotations

import os
import platform
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_identity.response import (ContainmentEngine, ContainmentIntegrations, EvidenceService,
                                     IncidentService, LoopDetector, MemoryResponseStore,
                                     ResponseConfig, ResponseLevel, ResponseOrchestrator,
                                     ResponseService)
from agent_identity.runtime_monitoring.models import RuntimeEvent

ORG = "org_bench"
AGENT = "agent_bench"


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def now(self):
        return self.t


def _events(n, *, action="read_file", resource="s3://b/x", etype="tool.invocation", ts=None):
    return [RuntimeEvent(event_id=f"e{i}", event_type=etype, ts=(ts if ts is not None else 1_700_000_000.0),
                         org_id=ORG, agent_id=AGENT, action=action, resource=resource)
            for i in range(n)]


def bench(label, fn, *, n=1, repeat=5):
    times = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) / n)
    p50 = statistics.median(times) * 1000
    print(f"{label:<46} p50={p50:9.3f} ms/op   ({n} op(s)/run, {repeat} runs)")
    return p50


def main():
    print("=" * 78)
    print("AgentGuard Phase 6 -- response plane micro-benchmarks")
    print(f"python {platform.python_version()} | {platform.platform()} | "
          f"{os.cpu_count()} cpu")
    print("single-process, no warm-up, in-memory store -- NOT a load test")
    print("=" * 78)

    cfg = ResponseConfig(containment_allow_auto=True, containment_high_impact_requires_approval=False)
    clock = Clock()

    # 1. loop detection over a full observation window
    det = LoopDetector(config=cfg, clock=clock)
    det.observe(_events(500))
    bench("1. loop detection (500-event window)", lambda: det.detect(org_id=ORG, agent_id=AGENT), n=1)

    # 2. observation ingestion
    det2 = LoopDetector(config=cfg, clock=clock)
    bench("2. observation ingestion (500 events)", lambda: det2.observe(_events(500)), n=500)

    # 3. budget guard (the enforcement boundary)
    store = MemoryResponseStore()
    svc = ResponseService(store, config=cfg, clock=clock)
    svc.budgets.set_budget(org_id=ORG, agent_id=AGENT, max_actions=10_000_000)
    bench("3. budget guard (consume+check)", lambda: svc.budgets.guard(org_id=ORG, agent_id=AGENT),
          n=1, repeat=3)

    # 4. approval request + decide + bound check
    def approval_cycle():
        a = svc.approvals.request(org_id=ORG, agent_id=AGENT, action="export", resource="users",
                                  requested_by="req", params={"fmt": "csv"})
        svc.approvals.decide(org_id=ORG, approval_id=a.approval_id, approved=True,
                             decided_by="appr", approver_org_id=ORG)
        svc.approvals.check(org_id=ORG, agent_id=AGENT, action="export", resource="users",
                            params={"fmt": "csv"}, approval_id=a.approval_id)
    bench("4. approval request+decide+bound check", approval_cycle, n=1, repeat=3)

    # 5. incident correlation (attach to an open incident)
    inc = svc.incidents.open_or_correlate(org_id=ORG, title="t", agent_id=AGENT, subject="s::r")
    bench("5. incident correlation (attach)", lambda: svc.incidents.attach(
        org_id=ORG, incident_id=inc.incident_id, alert_ids=("a1",)), n=1, repeat=3)

    # 6. containment execution (3 delegated actions)
    bench("6. containment execution (RESTRICT plan)", lambda: svc.orchestrator.execute(
        org_id=ORG, level=ResponseLevel.RESTRICT, agent_id=AGENT, authorized_by="admin",
        idempotency_key=f"k{time.perf_counter_ns()}"), n=1, repeat=3)

    # 7. evidence preservation + digest
    ev = EvidenceService(store, config=cfg, clock=clock)
    bench("7. evidence preserve (digest+seal)", lambda: ev.preserve(
        org_id=ORG, kind="k", summary="s", payload={"a": 1}, seal=True), n=1, repeat=3)

    # 8. audit record + chain verify
    for i in range(200):
        svc.audit.record(f"e{i}", org_id=ORG)
    bench("8. audit chain verify (200 records)", lambda: svc.audit.verify_chain(org_id=ORG),
          n=1, repeat=3)

    # 9. idempotent replay (duplicate delivery)
    key = "replay-key"
    svc.orchestrator.execute(org_id=ORG, level=ResponseLevel.RESTRICT, agent_id=AGENT,
                             authorized_by="admin", idempotency_key=key)
    bench("9. duplicate delivery (idempotent replay)", lambda: svc.orchestrator.execute(
        org_id=ORG, level=ResponseLevel.RESTRICT, agent_id=AGENT, authorized_by="admin",
        idempotency_key=key), n=1, repeat=3)

    print("=" * 78)
    print("NOTE: in-memory store. PostgreSQL adds a transaction per operation; the PG figures in the")
    print("report are a FLOOR (1 txn/op, 1 connection, no batching), not a ceiling.")


if __name__ == "__main__":
    main()
