"""Tests for the observability layer (`core/observability.py` + `/api/logs`).

Covers: trace building from both run shapes, the routing-savings maths, the
success/failure trend, filtering, the empty state and the HTTP contract.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from core.observability import (
    PREMIUM_MODEL,
    build_logs,
    build_traces,
    routing_savings,
    summarise,
    success_trend,
)
from core.router import PRICING, ModelRouter
from main import app

client = TestClient(app)


# ── Fixtures ────────────────────────────────────────────────────────────────

ORCH_RUN = {
    "run_id": "run-orch-1",
    "created_at": "2026-10-01T10:00:00+00:00",
    "prompt": "Research the AI agent market and write a long detailed strategy brief",
    "status": "completed",
    "iteration": 1,
    "max_iterations": 3,
    "duration_ms": 4000,
    "total_cost_usd": 0.02,
    "plan": [
        {
            "id": "t1",
            "description": "Search for recent market data",
            "tool": "web_search",
            "status": "approved",
            "attempts": 1,
            "feedback": "",
        },
        {
            "id": "t2",
            "description": "Compute the compound annual growth rate and analyze the trend",
            "tool": "python_exec",
            "status": "approved",
            "attempts": 1,
            "feedback": "",
        },
    ],
    "results": [
        {
            "task_id": "t1",
            "tool": "web_search",
            "output": "Found 12 sources on the agent market.",
            "ok": True,
            "error": None,
            "model": "claude-opus-4.6",
            "provider": "unorouter",
            "cost_usd": 0.018,
            "duration_ms": 1420,
        },
        {
            "task_id": "t2",
            "tool": "python_exec",
            "output": "CAGR = 41.7%",
            "ok": True,
            "error": None,
            "model": "gpt-4o-mini",
            "provider": "openai",
            "cost_usd": 0.002,
            "duration_ms": 1980,
        },
    ],
    "reviews": [
        {"task_id": "t1", "verdict": "approved", "feedback": "Good sources.", "score": 0.92},
        {"task_id": "t2", "verdict": "approved", "feedback": "Math checks out.", "score": 0.88},
    ],
    "final_output": "Launch brief ready.",
}

AGENT_RUN = {
    "run_id": "run-agent-1",
    "created_at": "2026-10-01T10:05:00+00:00",
    "task": "Say hello",
    "status": "completed",
    "answer": "Hello there!",
    "error": None,
    "duration_ms": 500,
    "route": {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "tier": "fast",
        "reason": "complexity=Low; tier=fast; provider=openai; signals=none",
    },
    "steps": [
        {
            "index": 0,
            "thought": "The user greeted me, I should respond.",
            "action": "echo",
            "action_input": {"text": "Hello there!"},
            "observation": "Hello there!",
        }
    ],
}


# ── Trace building ──────────────────────────────────────────────────────────


def test_build_traces_from_orchestration_run():
    traces = build_traces([ORCH_RUN])
    # planner + 2 executions + 2 reviews
    assert len(traces) == 5
    agents = {t.agent.split("·")[0] for t in traces}
    assert agents == {"PlannerAgent", "ExecutionAgent", "ReviewerAgent"}
    assert {t.run_id for t in traces} == {"run-orch-1"}


def test_build_traces_from_agent_run():
    traces = build_traces([AGENT_RUN])
    assert len(traces) == 1
    assert traces[0].agent == "ReActAgent"
    assert traces[0].tool == "echo"
    assert traces[0].total_tokens > 0


def test_traces_carry_every_required_column():
    for t in build_traces([ORCH_RUN, AGENT_RUN]):
        row = t.to_dict()
        for key in (
            "trace_id",
            "run_id",
            "timestamp",
            "agent",
            "tool",
            "status",
            "latency_ms",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "cost_usd",
            "complexity",
            "model",
            "provider",
        ):
            assert key in row, key


def test_traces_are_chronological():
    traces = build_traces([ORCH_RUN, AGENT_RUN])
    stamps = [t.timestamp for t in traces]
    assert stamps == sorted(stamps)


def test_trace_ids_are_unique():
    traces = build_traces([ORCH_RUN, AGENT_RUN])
    ids = [t.trace_id for t in traces]
    assert len(ids) == len(set(ids))


def test_failed_step_is_reported_as_failed():
    run = dict(ORCH_RUN)
    run["results"] = [
        {**ORCH_RUN["results"][0], "ok": False, "error": "boom"},
        ORCH_RUN["results"][1],
    ]
    traces = build_traces([run])
    exec_traces = [t for t in traces if t.tool == "web_search"]
    assert exec_traces and exec_traces[0].status == "failed"


def test_build_traces_tolerates_garbage_runs():
    # Must not raise — a single malformed payload never kills the page.
    traces = build_traces([{}, {"run_id": "x"}, ORCH_RUN])
    assert any(t.run_id == "run-orch-1" for t in traces)


def test_run_with_no_steps_still_yields_one_trace():
    run = {**AGENT_RUN, "steps": []}
    traces = build_traces([run])
    assert len(traces) == 1
    assert traces[0].tool == "run"


# ── Routing savings ─────────────────────────────────────────────────────────


def test_routing_savings_is_positive_and_consistent():
    traces = build_traces([ORCH_RUN, AGENT_RUN])
    block = routing_savings(traces)

    assert block["premium_model"] == PREMIUM_MODEL
    # Actual spend equals the sum of the trace costs.
    assert abs(block["actual_cost_usd"] - sum(t.cost_usd for t in traces)) < 1e-9
    # Routing must never look worse than never routing at all.
    assert block["baseline_cost_usd"] >= block["actual_cost_usd"]
    assert block["saved_usd"] == round(
        block["baseline_cost_usd"] - block["actual_cost_usd"], 8
    )
    assert 0.0 <= block["saved_pct"] <= 100.0


def test_routing_savings_breakdown_covers_all_three_tiers():
    traces = build_traces([ORCH_RUN, AGENT_RUN])
    block = routing_savings(traces)
    tiers = {t["tier"] for t in block["tiers"]}
    assert {"Low", "Medium", "High"} <= tiers
    for tier in block["tiers"]:
        assert tier["calls"] >= 0
        assert tier["baseline_cost_usd"] >= tier["cost_usd"]


def test_all_premium_workload_saves_nothing():
    """A 100%-premium workload is its own baseline — zero savings."""
    router = ModelRouter(use_llm_classifier=False)
    run = {
        "run_id": "premium-only",
        "created_at": "2026-10-01T10:00:00+00:00",
        "prompt": "x",
        "status": "completed",
        "duration_ms": 100,
        "plan": [{"id": "t1", "description": "d", "tool": "echo", "status": "approved"}],
        "results": [
            {
                "task_id": "t1",
                "tool": "echo",
                "output": "ok",
                "ok": True,
                "model": PREMIUM_MODEL,
                "provider": "unorouter",
                "cost_usd": 0.0,
                "duration_ms": 100,
            }
        ],
        "reviews": [],
    }
    # Price the run purely at premium rates; the stub cost is exactly premium.
    traces = build_traces([run], router=router)
    in_price, out_price = PRICING[PREMIUM_MODEL]
    assert in_price > 0 and out_price > 0
    block = routing_savings(traces)
    # Everything already ran on the premium model, so there is nothing to save.
    assert block["saved_usd"] == 0.0
    assert block["saved_pct"] == 0.0
    assert block["baseline_cost_usd"] == block["actual_cost_usd"]


def test_empty_traces_give_zero_savings():
    block = routing_savings([])
    assert block["actual_cost_usd"] == 0.0
    assert block["baseline_cost_usd"] == 0.0
    assert block["saved_pct"] == 0.0
    assert len(block["tiers"]) == 3


# ── Success trend ───────────────────────────────────────────────────────────


def test_success_trend_counts_and_rate():
    traces = build_traces([ORCH_RUN, AGENT_RUN])
    block = success_trend(traces)
    assert block["total"] == block["succeeded"] + block["failed"]
    assert 0.0 <= block["success_rate"] <= 1.0
    # Every trace in the fixtures succeeded, except reviews are also successes.
    assert block["failed"] == 0
    assert block["success_rate"] == 1.0


def test_success_trend_series_length_and_shape():
    traces = build_traces([ORCH_RUN, AGENT_RUN])
    block = success_trend(traces, buckets=8)
    assert len(block["series"]) == 8
    assert sum(b["success"] for b in block["series"]) == block["succeeded"]
    assert sum(b["failure"] for b in block["series"]) == block["failed"]


def test_success_trend_empty_state():
    block = success_trend([])
    assert block["total"] == 0
    assert block["success_rate"] == 0.0
    assert block["series"] == []


def test_success_trend_mixed():
    run = dict(ORCH_RUN)
    run["results"] = [
        {**ORCH_RUN["results"][0], "ok": False},
        ORCH_RUN["results"][1],
    ]
    block = success_trend(build_traces([run]))
    assert block["succeeded"] >= 1
    assert block["failed"] >= 1


# ── Summary ─────────────────────────────────────────────────────────────────


def test_summary_rolls_up_costs_and_tokens():
    traces = build_traces([ORCH_RUN, AGENT_RUN])
    summary = summarise(traces)
    assert summary.runs == 2
    assert summary.calls == len(traces)
    assert summary.total_tokens == sum(t.total_tokens for t in traces)
    assert abs(summary.total_cost_usd - sum(t.cost_usd for t in traces)) < 1e-9
    assert summary.avg_latency_ms >= 0


def test_summary_empty():
    summary = summarise([])
    assert summary.runs == 0
    assert summary.calls == 0
    assert summary.success_rate == 0.0
    assert summary.avg_cost_usd == 0.0


# ── Filters & payload ───────────────────────────────────────────────────────


def test_build_logs_payload_shape():
    payload = build_logs([ORCH_RUN, AGENT_RUN])
    for key in ("generated_at", "summary", "routing", "success", "traces", "count"):
        assert key in payload
    assert payload["count"] == len(payload["traces"])


def test_build_logs_traces_are_newest_first():
    payload = build_logs([ORCH_RUN, AGENT_RUN])
    stamps = [t["timestamp"] for t in payload["traces"]]
    assert stamps == sorted(stamps, reverse=True)


def test_build_logs_filter_by_run_id():
    payload = build_logs([ORCH_RUN, AGENT_RUN], run_id="run-agent-1")
    assert payload["count"] >= 1
    assert all(t["run_id"] == "run-agent-1" for t in payload["traces"])


def test_build_logs_filter_by_agent():
    payload = build_logs([ORCH_RUN], agent="reviewer")
    assert payload["count"] == 2
    assert all("ReviewerAgent" in t["agent"] for t in payload["traces"])


def test_build_logs_filter_by_status():
    payload = build_logs([ORCH_RUN], status="failed")
    assert payload["count"] == 0
    assert payload["traces"] == []


def test_build_logs_limit():
    payload = build_logs([ORCH_RUN, AGENT_RUN], limit=2)
    assert payload["count"] == 2


def test_build_logs_empty_and_never_raises():
    payload = build_logs([])
    assert payload["traces"] == []
    assert payload["summary"]["calls"] == 0
    assert payload["routing"]["saved_pct"] == 0.0
    assert payload["success"]["series"] == []
    assert build_logs(None)["count"] == 0


# ── HTTP contract ───────────────────────────────────────────────────────────


def test_api_logs_endpoint_shape():
    client.post("/orchestrate", json={"task": "Say hello to the team"})
    r = client.get("/api/logs")
    assert r.status_code == 200
    body = r.json()
    assert set(
        ["generated_at", "summary", "routing", "success", "traces", "count"]
    ) <= set(body)
    assert body["summary"]["calls"] >= 1
    assert body["routing"]["premium_model"] == PREMIUM_MODEL


def test_api_logs_returns_traces_with_required_fields():
    client.post("/agent/run", json={"task": "Say hello"})
    r = client.get("/api/logs")
    traces = r.json()["traces"]
    assert traces, "expected at least one trace after a run"
    first = traces[0]
    for key in (
        "timestamp",
        "run_id",
        "agent",
        "tool",
        "status",
        "latency_ms",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "cost_usd",
        "complexity",
        "model",
    ):
        assert key in first, key


def test_api_logs_filters():
    client.post("/orchestrate", json={"task": "Say hello to the team"})
    r = client.get("/api/logs", params={"agent": "PlannerAgent"})
    assert r.status_code == 200
    assert r.json()["count"] >= 1

    r2 = client.get("/api/logs", params={"status": "failed"})
    assert r2.status_code == 200
    # Whatever the shared state holds, the filter must be applied exactly.
    assert all(t["status"] == "failed" for t in r2.json()["traces"])


def test_api_logs_no_keys_fallback_still_works():
    """With no Supabase/OpenAI keys the endpoint must still answer cleanly."""
    r = client.get("/api/logs")
    assert r.status_code == 200
    body = r.json()
    assert body["routing"]["premium_model"] == PREMIUM_MODEL
    assert isinstance(body["traces"], list)


def test_sdk_logs_method_exists():
    from sdk.client import AQL1Client

    assert hasattr(AQL1Client, "logs")
    assert hasattr(AQL1Client, "traces")
    assert hasattr(AQL1Client, "savings")
