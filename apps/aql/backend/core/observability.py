"""Observability: execution traces + model-routing cost analytics.

This module turns the runs already persisted by :class:`memory.state.StateManager`
into the three things the Observability dashboard needs:

1. **Routing savings** -- what the :class:`core.router.ModelRouter` actually spent
   versus the counterfactual of sending *every* request to the most expensive
   model in the pricing table ("all-premium"), broken down per complexity tier.
2. **Success vs failure** -- an overall success rate plus a time-bucketed trend
   series (successes / failures / success-rate per bucket).
3. **Step-by-step traces** -- one flat, typed record per agent call: timestamp,
   run id, agent name, tool, status, latency, token usage and cost.

Everything degrades gracefully: no runs, no router and no API keys all still
produce a well-formed, empty-but-valid payload rather than raising.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

from core.router import (
    PRICING,
    Complexity,
    ModelRouter,
    estimate_cost,
    estimate_tokens,
)

# ── Typed errors ────────────────────────────────────────────────────────────


class ObservabilityError(Exception):
    """Base class for observability failures."""


class LogBuildError(ObservabilityError):
    """Raised when the log payload cannot be assembled."""


# ── Constants ───────────────────────────────────────────────────────────────

#: The single most expensive model in the pricing table. Every request priced
#: against this is the "what if we never routed" counterfactual.
PREMIUM_MODEL = max(
    PRICING.items(), key=lambda kv: kv[1][0] + kv[1][1]
)[0]

#: Ordered complexity tiers used by the breakdown (matches `Complexity`).
TIER_ORDER: tuple[str, ...] = ("Low", "Medium", "High")

#: Fallback output-token budget per tier, mirroring the router's estimate.
_TIER_OUTPUT_BUDGET: dict[str, int] = {"Low": 256, "Medium": 768, "High": 2048}

_DONE = {"completed", "complete", "ok", "success", "approved", "done"}
_FAILED = {"failed", "error", "rejected", "max_iterations", "needs-revision"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def _as_float(value: Any, default: float = 0.0) -> float:
    """Coerce ``value`` to float without ever raising."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _blended_price(model: str) -> float:
    """One comparable price for ``model``: 25% prompt / 75% output blended.

    Mirrors the router's own estimation shape so the counterfactual and the
    actual spend are measured on the same yardstick.
    """
    in_price, out_price = PRICING.get(model, (0.003, 0.015))
    return 0.25 * in_price + 0.75 * out_price


def _premium_ratio(model: str) -> float:
    """How many times more expensive ``model`` would be at premium rates.

    A model already priced at (or above) premium yields a ratio of 1.0, so an
    all-premium workload correctly saves nothing. Pricing the counterfactual as
    a *ratio of the recorded cost* keeps the maths robust even when the token
    counts are estimates rather than provider-reported usage.
    """
    price = _blended_price(model)
    if price <= 0:
        return 1.0
    return max(1.0, _blended_price(PREMIUM_MODEL) / price)


def _premium_cost(model: str, cost_usd: float) -> float:
    """The all-premium counterfactual cost of a call that actually cost ``cost_usd``."""
    return cost_usd * _premium_ratio(model)


# ── Data structures ─────────────────────────────────────────────────────────


@dataclass
class TraceRecord:
    """One agent call — the atomic unit of the trace table."""

    trace_id: str
    run_id: str
    timestamp: str
    agent: str
    tool: str
    status: str  # success | failed | skipped
    latency_ms: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    complexity: str = "Medium"
    model: str = ""
    provider: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "agent": self.agent,
            "tool": self.tool,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "cost_usd": round(self.cost_usd, 8),
            "complexity": self.complexity,
            "model": self.model,
            "provider": self.provider,
            "detail": self.detail,
        }


@dataclass
class TierBreakdown:
    """Routing spend for one complexity tier."""

    tier: str
    model: str = ""
    provider: str = ""
    calls: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    baseline_cost_usd: float = 0.0

    @property
    def saved_usd(self) -> float:
        return max(0.0, self.baseline_cost_usd - self.cost_usd)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "model": self.model,
            "provider": self.provider,
            "calls": self.calls,
            "tokens": self.tokens,
            "cost_usd": round(self.cost_usd, 8),
            "baseline_cost_usd": round(self.baseline_cost_usd, 8),
            "saved_usd": round(self.saved_usd, 8),
        }


@dataclass
class TrendBucket:
    """Success/failure counts for one time slice."""

    label: str
    start: str
    success: int = 0
    failure: int = 0

    @property
    def total(self) -> int:
        return self.success + self.failure

    @property
    def success_rate(self) -> float:
        return self.success / self.total if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "start": self.start,
            "success": self.success,
            "failure": self.failure,
            "total": self.total,
            "success_rate": round(self.success_rate, 4),
        }


@dataclass
class ObservabilitySummary:
    """Headline counters across every trace."""

    runs: int = 0
    calls: int = 0
    succeeded: int = 0
    failed: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    total_latency_ms: int = 0

    @property
    def success_rate(self) -> float:
        return self.succeeded / self.calls if self.calls else 0.0

    @property
    def avg_latency_ms(self) -> int:
        return round(self.total_latency_ms / self.calls) if self.calls else 0

    @property
    def avg_cost_usd(self) -> float:
        return self.total_cost_usd / self.calls if self.calls else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "runs": self.runs,
            "calls": self.calls,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "success_rate": round(self.success_rate, 4),
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost_usd, 8),
            "avg_cost_usd": round(self.avg_cost_usd, 8),
            "avg_latency_ms": self.avg_latency_ms,
            "total_latency_ms": self.total_latency_ms,
        }


# ── Run → traces ────────────────────────────────────────────────────────────


def _status_of(value: Any, ok: bool | None = None) -> str:
    """Normalise any run/step status into success | failed | skipped."""
    if ok is not None:
        return "success" if ok else "failed"
    text = str(value or "").strip().lower()
    if text in _FAILED:
        return "failed"
    if text in _DONE:
        return "success"
    if text in ("pending", "running", ""):
        return "skipped"
    return "success"


def _complexity_from_reason(reason: str) -> str:
    """Pull ``complexity=High`` out of a router reason string."""
    for tier in TIER_ORDER:
        if f"complexity={tier}" in reason:
            return tier
    return "Medium"


def _split_tokens(text: str, complexity: str) -> tuple[int, int]:
    """Deterministically split a call into (prompt, completion) tokens.

    The real providers report exact usage; the stub path does not, so we derive
    a stable estimate from the text and the tier's output budget.
    """
    completion = estimate_tokens(text or "  ") if text else 0
    completion = max(1, min(completion, _TIER_OUTPUT_BUDGET.get(complexity, 768)))
    prompt = max(1, completion // 3)
    return prompt, completion


def _orchestrator_traces(
    payload: dict[str, Any], created: datetime, router: ModelRouter
) -> list[TraceRecord]:
    """Flatten a multi-agent orchestration run into per-call traces."""
    run_id = str(payload.get("run_id") or "unknown")
    plan = payload.get("plan") or []
    results = payload.get("results") or []
    reviews = payload.get("reviews") or []
    status = _status_of(payload.get("status"))
    total_ms = _as_int(payload.get("duration_ms"))
    traces: list[TraceRecord] = []

    # 1) Planner call — one trace, priced at the run's tier.
    plan_text = "; ".join(str(t.get("description", "")) for t in plan)
    planner_tier = "Medium"
    try:
        planner_tier = router.classify(str(payload.get("prompt") or "")).value
    except Exception:  # noqa: BLE001 - classification is best-effort only
        planner_tier = "Medium"
    p_in, p_out = _split_tokens(plan_text, planner_tier)
    planner_ms = max(1, round(total_ms * 0.12)) if total_ms else 0
    traces.append(
        TraceRecord(
            trace_id=f"{run_id}-planner",
            run_id=run_id,
            timestamp=_iso(created),
            agent="PlannerAgent",
            tool="plan",
            status=status,
            latency_ms=planner_ms,
            prompt_tokens=p_in,
            completion_tokens=p_out,
            total_tokens=p_in + p_out,
            cost_usd=estimate_cost(PREMIUM_MODEL, p_in, p_out),
            complexity=planner_tier,
            model=PREMIUM_MODEL,
            provider="unorouter",
            detail=f"Decomposed the goal into {len(plan)} sub-task(s).",
        )
    )

    # 2) One execution trace per sub-task (+ its reviewer verdict).
    by_id = {str(r.get("task_id")): r for r in results}
    reviewed = {str(v.get("task_id")): v for v in reviews}
    remaining_ms = max(0, total_ms - planner_ms)
    per_step = round(remaining_ms / max(1, len(plan))) if plan else 0

    for index, task in enumerate(plan):
        task_id = str(task.get("id") or f"t{index + 1}")
        result = by_id.get(task_id, {})
        output = str(result.get("output") or "")
        ok = bool(result.get("ok", bool(result)))
        step_status = _status_of(result.get("status"), ok=ok if result else None)

        try:
            tier = router.classify(str(task.get("description") or "")).value
        except Exception:  # noqa: BLE001 - best-effort only
            tier = "Medium"

        in_tok, out_tok = _split_tokens(output, tier)
        cost = _as_float(result.get("cost_usd"))
        # If the provider reported no cost (local stub), estimate from pricing.
        if cost <= 0:
            cost = estimate_cost(
                str(result.get("model") or PREMIUM_MODEL), in_tok, out_tok
            )

        traces.append(
            TraceRecord(
                trace_id=f"{run_id}-{task_id}-exec",
                run_id=run_id,
                timestamp=_iso(created + timedelta(milliseconds=planner_ms + index * per_step)),
                agent=f"ExecutionAgent·{str(task.get('tool') or 'tool')}",
                tool=str(task.get("tool") or "unknown"),
                status=step_status,
                latency_ms=_as_int(result.get("duration_ms"), per_step),
                prompt_tokens=in_tok,
                completion_tokens=out_tok,
                total_tokens=in_tok + out_tok,
                cost_usd=cost,
                complexity=tier,
                model=str(result.get("model") or PREMIUM_MODEL),
                provider=str(result.get("provider") or "unorouter"),
                detail=output or str(task.get("description") or ""),
            )
        )

        verdict = reviewed.get(task_id)
        if verdict:
            feedback = str(verdict.get("feedback") or "")
            traces.append(
                TraceRecord(
                    trace_id=f"{run_id}-{task_id}-review",
                    run_id=run_id,
                    timestamp=_iso(
                        created
                        + timedelta(milliseconds=planner_ms + index * per_step + per_step // 2)
                    ),
                    agent="ReviewerAgent",
                    tool="review",
                    status=_status_of(verdict.get("verdict")),
                    latency_ms=max(0, per_step // 4),
                    prompt_tokens=max(1, len(feedback or " ") // 4),
                    completion_tokens=max(1, len(feedback or " ") // 8),
                    total_tokens=max(1, len(feedback or " ") // 4)
                    + max(1, len(feedback or " ") // 8),
                    cost_usd=0.0,
                    complexity=tier,
                    model=str(result.get("model") or PREMIUM_MODEL),
                    provider=str(result.get("provider") or "unorouter"),
                    detail=f"{verdict.get('verdict')} · score {verdict.get('score')}"
                    + (f" — {feedback}" if feedback else ""),
                )
            )

    return traces


def _agent_traces(
    payload: dict[str, Any], created: datetime
) -> list[TraceRecord]:
    """Flatten a single-agent ReAct run into per-step traces."""
    run_id = str(payload.get("run_id") or "unknown")
    route = payload.get("route") or {}
    model = str(route.get("model") or "")
    provider = str(route.get("provider") or "")
    complexity = _complexity_from_reason(str(route.get("reason") or ""))
    status = _status_of(payload.get("status"))
    steps = payload.get("steps") or []
    total_ms = _as_int(payload.get("duration_ms"))
    per_step = round(total_ms / max(1, len(steps))) if steps else total_ms

    traces: list[TraceRecord] = []
    for index, step in enumerate(steps):
        obs = str(step.get("observation") or "")
        action = str(step.get("action") or "think")
        in_tok = max(1, len(str(step.get("thought") or " ")) // 4)
        out_tok = max(0, len(obs) // 4)
        cost = estimate_cost(model or PREMIUM_MODEL, in_tok, out_tok)
        traces.append(
            TraceRecord(
                trace_id=f"{run_id}-step-{_as_int(step.get('index'), index)}",
                run_id=run_id,
                timestamp=_iso(created + timedelta(milliseconds=index * per_step)),
                agent="ReActAgent",
                tool=action,
                status="success" if obs else "skipped",
                latency_ms=per_step,
                prompt_tokens=in_tok,
                completion_tokens=out_tok,
                total_tokens=in_tok + out_tok,
                cost_usd=cost,
                complexity=complexity,
                model=model,
                provider=provider,
                detail=obs or str(step.get("thought") or ""),
            )
        )

    # A run that never produced a step still deserves one trace row.
    if not traces:
        answer = str(payload.get("answer") or "")
        in_tok = max(1, len(str(payload.get("task") or " ")) // 4)
        out_tok = max(0, len(answer) // 4)
        traces.append(
            TraceRecord(
                trace_id=f"{run_id}-run",
                run_id=run_id,
                timestamp=_iso(created),
                agent="ReActAgent",
                tool="run",
                status=status,
                latency_ms=total_ms,
                prompt_tokens=in_tok,
                completion_tokens=out_tok,
                total_tokens=in_tok + out_tok,
                cost_usd=estimate_cost(model or PREMIUM_MODEL, in_tok, out_tok),
                complexity=complexity,
                model=model,
                provider=provider,
                detail=answer or str(payload.get("error") or ""),
            )
        )
    return traces


def _parse_created(payload: dict[str, Any], fallback: datetime) -> datetime:
    """Read the run's ``created_at`` (set by StateManager) as an aware datetime."""
    raw = payload.get("created_at")
    if isinstance(raw, str) and raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return fallback


def build_traces(
    runs: Sequence[dict[str, Any]], router: ModelRouter | None = None
) -> list[TraceRecord]:
    """Convert persisted run payloads into a flat, ordered list of traces."""
    router = router or ModelRouter(use_llm_classifier=False)
    now = _utcnow()
    traces: list[TraceRecord] = []

    for offset, (run_id, payload) in enumerate(_iter_runs(runs)):
        if not isinstance(payload, dict):
            continue
        created = _parse_created(payload, now - timedelta(minutes=offset))
        try:
            if "plan" in payload:
                traces.extend(_orchestrator_traces(payload, created, router))
            else:
                traces.extend(_agent_traces(payload, created))
        except Exception as exc:  # noqa: BLE001 - one bad run never kills the page
            raise LogBuildError(f"Could not build traces for run {run_id}: {exc}") from exc

    traces.sort(key=lambda t: t.timestamp)
    return traces


def _iter_runs(runs: Sequence[Any]) -> Iterable[tuple[str, Any]]:
    """Accept either ``{run_id: payload}`` dicts or bare payloads."""
    for item in runs:
        if isinstance(item, dict) and "payload" in item and "run_id" in item:
            yield str(item["run_id"]), item["payload"]
        elif isinstance(item, dict):
            yield str(item.get("run_id") or "unknown"), item
        else:
            yield "unknown", item


# ── Aggregation ─────────────────────────────────────────────────────────────


def summarise(traces: Sequence[TraceRecord]) -> ObservabilitySummary:
    """Roll every trace up into the headline counters."""
    summary = ObservabilitySummary(runs=len({t.run_id for t in traces}))
    for t in traces:
        summary.calls += 1
        summary.total_tokens += t.total_tokens
        summary.total_cost_usd += t.cost_usd
        summary.total_latency_ms += t.latency_ms
        if t.status == "success":
            summary.succeeded += 1
        elif t.status == "failed":
            summary.failed += 1
    return summary


def routing_savings(traces: Sequence[TraceRecord]) -> dict[str, Any]:
    """Actual spend vs. the all-premium counterfactual, broken down per tier."""
    tiers: dict[str, TierBreakdown] = {
        name: TierBreakdown(tier=name) for name in TIER_ORDER
    }
    actual = 0.0
    baseline = 0.0

    for t in traces:
        tier = tiers.setdefault(t.complexity, TierBreakdown(tier=t.complexity))
        # The counterfactual is the *same call* priced at premium rates, so the
        # two sides are always directly comparable.
        counterfactual = _premium_cost(t.model, t.cost_usd)
        tier.calls += 1
        tier.tokens += t.total_tokens
        tier.cost_usd += t.cost_usd
        tier.baseline_cost_usd += counterfactual
        if not tier.model and t.model:
            tier.model = t.model
            tier.provider = t.provider
        actual += t.cost_usd
        baseline += counterfactual

    saved = max(0.0, baseline - actual)
    saved_pct = (saved / baseline * 100.0) if baseline > 0 else 0.0

    return {
        "premium_model": PREMIUM_MODEL,
        "actual_cost_usd": round(actual, 8),
        "baseline_cost_usd": round(baseline, 8),
        "saved_usd": round(saved, 8),
        "saved_pct": round(saved_pct, 2),
        "tiers": [tiers[name].to_dict() for name in TIER_ORDER if name in tiers]
        + [t.to_dict() for k, t in tiers.items() if k not in TIER_ORDER],
    }


def success_trend(
    traces: Sequence[TraceRecord], buckets: int = 8
) -> dict[str, Any]:
    """Overall success rate plus a time-bucketed trend series.

    Buckets span the window covered by the traces; with no traces we return an
    empty series so the chart can render its empty state.
    """
    considered = [t for t in traces if t.status in ("success", "failed")]
    succeeded = sum(1 for t in considered if t.status == "success")
    failed = len(considered) - succeeded
    rate = (succeeded / len(considered)) if considered else 0.0

    series: list[TrendBucket] = []
    if considered:
        stamps = []
        for t in considered:
            try:
                stamps.append(datetime.fromisoformat(t.timestamp))
            except ValueError:
                continue
        if stamps:
            start, end = min(stamps), max(stamps)
            span = max(end - start, timedelta(seconds=1))
            step = span / buckets
            for i in range(buckets):
                b_start = start + step * i
                label = b_start.strftime("%H:%M:%S")
                series.append(TrendBucket(label=label, start=_iso(b_start)))
            for t in considered:
                try:
                    at = datetime.fromisoformat(t.timestamp)
                except ValueError:
                    continue
                idx = min(buckets - 1, max(0, int((at - start) / step)))
                if t.status == "success":
                    series[idx].success += 1
                else:
                    series[idx].failure += 1

    return {
        "total": len(considered),
        "succeeded": succeeded,
        "failed": failed,
        "success_rate": round(rate, 4),
        "series": [b.to_dict() for b in series],
    }


# ── Public entry point ──────────────────────────────────────────────────────


def build_logs(
    runs: Sequence[Any] | None = None,
    *,
    router: ModelRouter | None = None,
    run_id: str | None = None,
    status: str | None = None,
    agent: str | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """Assemble the full ``/api/logs`` payload.

    ``runs`` is whatever the state layer exposes (a list of payloads, or
    ``{run_id, payload}`` dicts). Filtering happens server-side too so a client
    can narrow to one run, one status or one agent.
    """
    try:
        traces = build_traces(list(runs or []), router=router)
    except LogBuildError:
        raise
    except Exception as exc:  # noqa: BLE001 - never 500 the dashboard
        raise LogBuildError(str(exc)) from exc

    if run_id:
        traces = [t for t in traces if t.run_id == run_id]
    if status and status != "all":
        traces = [t for t in traces if t.status == status]
    if agent:
        needle = agent.lower()
        traces = [t for t in traces if needle in t.agent.lower()]

    # Newest first for the table, capped so one huge workspace can't blow up
    # the response payload.
    ordered = list(reversed(traces))[: max(1, limit)]

    return {
        "generated_at": _iso(_utcnow()),
        "summary": summarise(traces).to_dict(),
        "routing": routing_savings(traces),
        "success": success_trend(traces),
        "traces": [t.to_dict() for t in ordered],
        "count": len(ordered),
    }
