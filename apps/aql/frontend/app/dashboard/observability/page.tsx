"use client";

/**
 * AQL-1 — Observability.
 *
 * Three panels over the backend's `GET /api/logs` payload:
 *
 *  1. **Cost saved by model routing** — actual spend vs. the all-premium
 *     counterfactual, plus a per-complexity-tier breakdown.
 *  2. **Success vs failure** — a donut for the overall rate, a stacked
 *     success/failure bar chart with a success-rate trend line, a legend and
 *     hover tooltips. Inline SVG only — no chart dependency.
 *  3. **Step-by-step traces** — an expandable, filterable, searchable table of
 *     every agent call with per-run cost subtotals.
 *
 * If the API is unreachable the page degrades to the deterministic demo
 * dataset, exactly like the main dashboard.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Coins,
  Layers,
  RefreshCw,
  Search,
  Sparkles,
  XCircle,
} from "lucide-react";

import api, {
  ApiError,
  type ComplexityTier,
  type LogRecord,
  type LogsResponse,
  type TraceStatus,
} from "@/lib/api";

import Sidebar, { type NavKey } from "@/components/dashboard/Sidebar";
import {
  Badge,
  Card,
  EmptyState,
  Skeleton,
  StatusDot,
  ThemeToggle,
  useTheme,
  formatDuration,
  formatTokens,
  formatUsd,
  type Tone,
} from "@/components/dashboard/ui";
import { DEMO_LOGS } from "@/components/dashboard/observability-demo";

/* ── Local formatters ────────────────────────────────────────────────────── */

function formatPct(value: number, digits = 1): string {
  if (!Number.isFinite(value)) return "0%";
  return `${value.toFixed(digits)}%`;
}

/** `14:03:22` — the trace table is dense, so time-of-day is enough. */
function formatClock(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

/**
 * Short axis label, sized to the bucket width.
 *
 * Two failure modes to avoid: a 5-minute window makes every `hh:mm:ss` label
 * identical (so we drop the seconds), while a 1-second window makes every
 * `hh:mm` label identical (so we keep them). Choosing the resolution from the
 * bucket spacing handles both.
 */
function formatAxisTime(iso: string, bucketMs: number): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  if (bucketMs < 60_000) {
    return d.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  }
  return d.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

/**
 * Evenly spaced count ticks for a small integer maximum.
 *
 * Returns the axis maximum plus a *uniform* step so the labels read
 * `0, 3, 6, 9, 12` rather than the ragged `0, 2, 4, 5, 7` that naive rounding
 * of a 5-way split produces.
 */
function countAxis(maxTotal: number): { max: number; ticks: number[] } {
  const top = Math.max(1, Math.ceil(maxTotal));
  // A "nice" step: 1, 2 or 5 (×10ⁿ) that yields 3–5 intervals.
  const rough = top / 4;
  const pow = Math.pow(10, Math.floor(Math.log10(Math.max(1, rough))));
  const step =
    rough <= pow ? pow : rough <= 2 * pow ? 2 * pow : rough <= 5 * pow ? 5 * pow : 10 * pow;
  const max = Math.max(step, Math.ceil(top / step) * step);
  const ticks: number[] = [];
  for (let v = 0; v <= max + 1e-9; v += step) ticks.push(Math.round(v));
  return { max, ticks };
}

function statusTone(status: TraceStatus): Tone {
  if (status === "success") return "success";
  if (status === "failed") return "danger";
  return "neutral";
}

function tierTone(tier: ComplexityTier | string): Tone {
  if (tier === "High") return "danger";
  if (tier === "Medium") return "warning";
  return "success";
}

/* ── KPI strip ───────────────────────────────────────────────────────────── */

function Kpi({
  icon,
  label,
  value,
  sub,
  accent = false,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
  accent?: boolean;
}) {
  return (
    <Card className="p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-subtle)]">
            {label}
          </p>
          <p
            className={`mt-1 truncate text-xl font-semibold ${
              accent ? "text-[var(--accent)]" : "text-[var(--text)]"
            }`}
          >
            {value}
          </p>
          {sub && (
            <p className="mt-0.5 truncate text-[11px] text-[var(--text-muted)]">
              {sub}
            </p>
          )}
        </div>
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-[var(--border)] bg-[var(--panel-2)] text-[var(--text-muted)]">
          {icon}
        </span>
      </div>
    </Card>
  );
}

/* ── 1. Routing cost savings ─────────────────────────────────────────────── */

function RoutingSavingsCard({
  routing,
  loading,
}: {
  routing: LogsResponse["routing"] | null;
  loading: boolean;
}) {
  if (loading || !routing) {
    return (
      <Card className="p-5">
        <Skeleton className="h-5 w-52" />
        <Skeleton className="mt-4 h-9 w-40" />
        <Skeleton className="mt-4 h-24 w-full" />
      </Card>
    );
  }

  const hasData = routing.actual_cost_usd > 0 || routing.baseline_cost_usd > 0;

  return (
    <Card className="overflow-hidden">
      {/* Headline */}
      <div className="flex flex-col gap-4 border-b border-[var(--border)] p-5 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="grid h-8 w-8 place-items-center rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
              <Sparkles size={16} />
            </span>
            <div>
              <h2 className="text-sm font-semibold text-[var(--text)]">
                Total cost saved via Model Routing
              </h2>
              <p className="text-[11px] text-[var(--text-muted)]">
                Complexity-based routing vs. sending every call to{" "}
                <code className="rounded bg-[var(--panel-2)] px-1 py-0.5 text-[10px]">
                  {routing.premium_model}
                </code>
              </p>
            </div>
          </div>

          <div className="mt-4 flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="text-3xl font-semibold tracking-tight text-emerald-600 dark:text-emerald-400">
              {formatUsd(routing.saved_usd)}
            </span>
            <Badge tone="success">
              <ArrowDownRight size={12} />
              {formatPct(routing.saved_pct, 2)} saved
            </Badge>
          </div>
        </div>

        {/* Actual vs counterfactual */}
        <div className="grid shrink-0 grid-cols-2 gap-3 sm:gap-4">
          <div className="rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3.5 py-2.5">
            <p className="text-[10px] font-medium uppercase tracking-wide text-[var(--text-subtle)]">
              Actual spend
            </p>
            <p className="mt-0.5 text-base font-semibold text-[var(--text)]">
              {formatUsd(routing.actual_cost_usd)}
            </p>
          </div>
          <div className="rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3.5 py-2.5">
            <p className="text-[10px] font-medium uppercase tracking-wide text-[var(--text-subtle)]">
              All-premium spend
            </p>
            <p className="mt-0.5 text-base font-semibold text-[var(--text-muted)] line-through">
              {formatUsd(routing.baseline_cost_usd)}
            </p>
          </div>
        </div>
      </div>

      {/* Per-tier breakdown */}
      <div className="p-5">
        <p className="mb-3 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-[var(--text-subtle)]">
          <Layers size={12} />
          Breakdown by complexity tier
        </p>

        {!hasData ? (
          <EmptyState
            icon={<Coins size={18} />}
            title="No routing data yet"
            hint="Run an agent or an orchestration and per-tier routing costs will appear here."
          />
        ) : (
          <div className="space-y-2">
            {/* Column header */}
            <div className="hidden grid-cols-12 gap-2 px-1 text-[10px] font-medium uppercase tracking-wide text-[var(--text-subtle)] sm:grid">
              <span className="col-span-3">Tier / model</span>
              <span className="col-span-2 text-right">Calls</span>
              <span className="col-span-2 text-right">Tokens</span>
              <span className="col-span-2 text-right">Cost</span>
              <span className="col-span-3 text-right">Saved vs premium</span>
            </div>

            {routing.tiers.map((tier) => {
              const share =
                routing.baseline_cost_usd > 0
                  ? tier.baseline_cost_usd / routing.baseline_cost_usd
                  : 0;
              return (
                <div
                  key={tier.tier}
                  className="grid grid-cols-2 gap-y-2 rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2.5 transition hover:border-[var(--border-strong)] sm:grid-cols-12 sm:items-center sm:gap-2"
                >
                  <div className="col-span-2 min-w-0 sm:col-span-3">
                    <div className="flex items-center gap-1.5">
                      <Badge tone={tierTone(tier.tier)}>{tier.tier}</Badge>
                      {tier.saved_usd > 0 && (
                        <span className="text-[10px] text-[var(--text-subtle)]">
                          {formatPct(share * 100, 0)} of baseline
                        </span>
                      )}
                    </div>
                    <p className="mt-1 truncate text-[11px] text-[var(--text-muted)]">
                      {tier.model || "—"}
                      {tier.provider ? (
                        <span className="text-[var(--text-subtle)]">
                          {" "}
                          · {tier.provider}
                        </span>
                      ) : null}
                    </p>
                  </div>

                  <div className="text-right text-xs text-[var(--text-muted)] sm:col-span-2">
                    <span className="sm:hidden text-[10px] uppercase text-[var(--text-subtle)]">
                      calls{" "}
                    </span>
                    {tier.calls}
                  </div>
                  <div className="text-right text-xs text-[var(--text-muted)] sm:col-span-2">
                    <span className="sm:hidden text-[10px] uppercase text-[var(--text-subtle)]">
                      tokens{" "}
                    </span>
                    {formatTokens(tier.tokens)}
                  </div>
                  <div className="text-right text-xs font-medium text-[var(--text)] sm:col-span-2">
                    {formatUsd(tier.cost_usd)}
                  </div>
                  <div className="text-right text-xs sm:col-span-3">
                    {tier.saved_usd > 0 ? (
                      <span className="font-medium text-emerald-600 dark:text-emerald-400">
                        +{formatUsd(tier.saved_usd)}
                      </span>
                    ) : (
                      <span className="text-[var(--text-subtle)]">
                        already premium
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </Card>
  );
}

/* ── 2. Success vs failure ───────────────────────────────────────────────── */

const CHART_W = 760;
const CHART_H = 240;
const PAD_L = 40;
const PAD_R = 16;
const PAD_T = 16;
const PAD_B = 34;

function SuccessChart({
  success,
  loading,
}: {
  success: LogsResponse["success"] | null;
  loading: boolean;
}) {
  const [hover, setHover] = useState<number | null>(null);

  if (loading || !success) {
    return (
      <Card className="p-5">
        <Skeleton className="h-5 w-44" />
        <Skeleton className="mt-4 h-56 w-full" />
      </Card>
    );
  }

  const series = success.series;
  const counts = series.map((b) => b.total);
  const maxTotal = Math.max(1, ...counts);
  const plotW = CHART_W - PAD_L - PAD_R;
  const plotH = CHART_H - PAD_T - PAD_B;
  const slot = plotW / Math.max(1, series.length);
  const barW = Math.min(46, slot * 0.55);

  // Window span, used to decide how much of the timestamp to show.
  const spanMs = series.length > 1
    ? new Date(series[series.length - 1].start).getTime() -
      new Date(series[0].start).getTime()
    : 0;
  const bucketMs = series.length > 1 ? spanMs / (series.length - 1) : spanMs;

  /** BARS domain — the lower 55% of the plot. */
  const axis = countAxis(maxTotal);
  const BAR_H = plotH * 0.55;
  const barBase = PAD_T + plotH;

  /** y for a stacked-bar height in the 0..axis.max domain (lower band). */
  const yForCount = (n: number) => barBase - (n / axis.max) * BAR_H;
  /**
   * LINE domain — the upper panel, clearly separated from the bars. A 100% rate
   * therefore sits well above the tallest bar instead of on top of it.
   */
  const yForRate = (r: number) => PAD_T + (1 - r) * (plotH - BAR_H - 14);

  // The trend line joins only the buckets that actually had calls — a bucket
  // with no calls has no rate, and plotting 0% would read as total failure.
  // A single continuous stroke keeps the "trend line" the legend promises.
  const ratePoints = series
    .map((b, i) =>
      b.total === 0
        ? null
        : `${(PAD_L + slot * i + slot / 2).toFixed(1)},${yForRate(b.success_rate).toFixed(1)}`,
    )
    .filter((p): p is string => p !== null)
    .join(" ");

  const hasAny = series.some((b) => b.total > 0);
  const hovered = hover !== null ? series[hover] : null;

  // Donut geometry for the overall success rate.
  const R = 34;
  const CIRC = 2 * Math.PI * R;
  const rate = success.success_rate;

  return (
    <Card>
      <div className="flex flex-col gap-4 border-b border-[var(--border)] p-5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
            <BarChart3 size={16} />
          </span>
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">
              Success vs Failure rate
            </h2>
            <p className="text-[11px] text-[var(--text-muted)]">
              {success.total} graded call{success.total === 1 ? "" : "s"} across
              the selected window
            </p>
          </div>
        </div>

        {/* Overall success-rate donut */}
        <div className="flex items-center gap-3">
          <svg width="84" height="84" viewBox="0 0 84 84" role="img" aria-label={`Overall success rate ${formatPct(rate * 100)}`}>
            <circle
              cx="42"
              cy="42"
              r={R}
              fill="none"
              stroke="var(--border-strong)"
              strokeWidth="8"
            />
            <circle
              cx="42"
              cy="42"
              r={R}
              fill="none"
              stroke="currentColor"
              className="text-emerald-500 transition-[stroke-dashoffset] duration-700"
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={`${(rate * CIRC).toFixed(2)} ${CIRC.toFixed(2)}`}
              transform="rotate(-90 42 42)"
            />
            <text
              x="42"
              y="47"
              textAnchor="middle"
              className="fill-[var(--text)]"
              style={{ fontSize: 16, fontWeight: 600 }}
            >
              {formatPct(rate * 100, 0)}
            </text>
          </svg>
          <div className="text-xs">
            <p className="flex items-center gap-1.5 text-[var(--text-muted)]">
              <StatusDot tone="success" />
              {success.succeeded} succeeded
            </p>
            <p className="mt-1 flex items-center gap-1.5 text-[var(--text-muted)]">
              <StatusDot tone="danger" />
              {success.failed} failed
            </p>
          </div>
        </div>
      </div>

      <div className="p-5">
        {!hasAny ? (
          <EmptyState
            icon={<Activity size={18} />}
            title="No runs in this window"
            hint="Once agents execute, their success and failure counts appear here over time."
          />
        ) : (
          <>
            {/* Legend */}
            <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[11px] text-[var(--text-muted)]">
              <span className="flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded-sm bg-emerald-500" />
                Successful calls
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded-sm bg-red-500" />
                Failed calls
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-0.5 w-4 rounded bg-[var(--accent)]" />
                Success rate
              </span>
            </div>

            <div className="relative">
              <svg
                viewBox={`0 0 ${CHART_W} ${CHART_H}`}
                className="h-56 w-full"
                role="img"
                aria-label="Stacked success and failure counts per time bucket with a success-rate trend line"
              >
                {/* Chart furniture: bar-band baseline + top of the line panel */}
                <line
                  x1={PAD_L}
                  x2={CHART_W - PAD_R}
                  y1={barBase}
                  y2={barBase}
                  stroke="var(--border-strong)"
                  strokeWidth="1"
                />
                <line
                  x1={PAD_L}
                  x2={CHART_W - PAD_R}
                  y1={yForRate(0)}
                  y2={yForRate(0)}
                  stroke="var(--border)"
                  strokeWidth="1"
                  strokeDasharray="3 5"
                />

                {/* Left axis: uniform integer count ticks */}
                {axis.ticks.map((tick) => {
                  const y = yForCount(tick);
                  return (
                    <g key={`ct-${tick}`}>
                      <line
                        x1={PAD_L}
                        x2={CHART_W - PAD_R}
                        y1={y}
                        y2={y}
                        stroke="var(--border)"
                        strokeWidth="1"
                        strokeDasharray={tick === 0 ? "0" : "3 5"}
                      />
                      <text
                        x={PAD_L - 8}
                        y={y}
                        textAnchor="end"
                        dominantBaseline="central"
                        className="fill-[var(--text-subtle)]"
                        style={{ fontSize: 9 }}
                      >
                        {tick}
                      </text>
                    </g>
                  );
                })}

                {/* Right axis: success-rate scale for the trend line */}
                {[0, 0.5, 1].map((r) => {
                  const y = yForRate(r);
                  return (
                    <g key={`rt-${r}`}>
                      <line
                        x1={PAD_L}
                        x2={CHART_W - PAD_R}
                        y1={y}
                        y2={y}
                        stroke="var(--accent)"
                        strokeWidth="1"
                        strokeDasharray="2 6"
                        opacity="0.28"
                      />
                      <text
                        x={CHART_W - PAD_R + 5}
                        y={y}
                        textAnchor="start"
                        dominantBaseline="central"
                        className="fill-[var(--accent)]"
                        style={{ fontSize: 9, opacity: 0.8 }}
                      >
                        {Math.round(r * 100)}%
                      </text>
                    </g>
                  );
                })}

                {/* Stacked bars: success at the bottom, failure stacked on top */}
                {series.map((bucket, i) => {
                  const x = PAD_L + slot * i + (slot - barW) / 2;
                  const ySuccess = yForCount(bucket.success);
                  const yTotal = yForCount(bucket.total);
                  const hSuccess = Math.max(0, PAD_T + plotH - ySuccess);
                  const hFailure = Math.max(0, ySuccess - yTotal);
                  const isHover = hover === i;
                  return (
                    <g
                      key={`${bucket.label}-${i}`}
                      opacity={hover === null || isHover ? 1 : 0.55}
                      className="transition-opacity"
                    >
                      {/* Failure (top segment) */}
                      {hFailure > 0 && (
                        <rect
                          x={x}
                          y={yTotal}
                          width={barW}
                          height={hFailure}
                          rx="2"
                          className="fill-red-500"
                        />
                      )}
                      {/* Success (bottom segment) */}
                      {hSuccess > 0 && (
                        <rect
                          x={x}
                          y={ySuccess}
                          width={barW}
                          height={hSuccess}
                          rx="2"
                          className="fill-emerald-500"
                        />
                      )}
                      {/* Zero-total bucket: a faint "no data" tick, not a bar */}
                      {bucket.total === 0 && (
                        <line
                          x1={x}
                          x2={x + barW}
                          y1={barBase}
                          y2={barBase}
                          stroke="var(--border-strong)"
                          strokeWidth="1"
                          strokeDasharray="2 3"
                          opacity="0.7"
                        />
                      )}
                      {/* X label — seconds only when the window is short */}
                      <text
                        x={x + barW / 2}
                        y={CHART_H - PAD_B + 16}
                        textAnchor="middle"
                        className={
                          isHover
                            ? "fill-[var(--text)]"
                            : "fill-[var(--text-subtle)]"
                        }
                        style={{ fontSize: 9 }}
                      >
                        {formatAxisTime(bucket.start, bucketMs)}
                      </text>                    </g>
                  );
                })}

                {/* Success-rate trend line (upper panel; empty buckets omitted) */}
                {ratePoints.includes(",") && (
                  <polyline
                    points={ratePoints}
                    fill="none"
                    stroke="var(--accent)"
                    strokeWidth="2"
                    strokeLinejoin="round"
                    strokeLinecap="round"
                  />
                )}
                {series.map((bucket, i) =>
                  bucket.total === 0 ? null : (
                    <circle
                      key={`dot-${i}`}
                      cx={PAD_L + slot * i + slot / 2}
                      cy={yForRate(bucket.success_rate)}
                      r={hover === i ? 4 : 2.5}
                      className="fill-[var(--accent)] transition-all"
                    />
                  ),
                )}

                {/* Invisible hover targets — one per bucket */}
                {series.map((bucket, i) => (
                  <rect
                    key={`hit-${i}`}
                    x={PAD_L + slot * i}
                    y={PAD_T}
                    width={slot}
                    height={plotH}
                    fill="transparent"
                    onMouseEnter={() => setHover(i)}
                    onMouseLeave={() => setHover(null)}
                  />
                ))}
              </svg>

              {/* Tooltip */}
              {hovered && (
                <div
                  className="pointer-events-none absolute top-0 z-10 min-w-[132px] rounded-lg border border-[var(--border-strong)] bg-[var(--bg-elevated)] px-3 py-2 text-[11px] shadow-soft"
                  style={{
                    left: `calc(${(((hover ?? 0) + 0.5) / series.length) * 100}% - 66px)`,
                  }}
                >
                  <p className="font-medium text-[var(--text)]">
                    {formatAxisTime(hovered.start, bucketMs)}
                  </p>
                  <p className="mt-1 flex items-center justify-between gap-3 text-[var(--text-muted)]">
                    <span className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-sm bg-emerald-500" />
                      Success
                    </span>
                    <span className="font-medium text-[var(--text)]">
                      {hovered.success}
                    </span>
                  </p>
                  <p className="flex items-center justify-between gap-3 text-[var(--text-muted)]">
                    <span className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-sm bg-red-500" />
                      Failed
                    </span>
                    <span className="font-medium text-[var(--text)]">
                      {hovered.failure}
                    </span>
                  </p>
                  <p className="flex items-center justify-between gap-3 border-t border-[var(--border)] pt-1 text-[var(--text-muted)]">
                    <span>Rate</span>
                    <span className="font-medium text-[var(--accent)]">
                      {formatPct(hovered.success_rate * 100)}
                    </span>
                  </p>
                </div>
              )}
            </div>

            <p className="mt-2 text-right text-[10px] text-[var(--text-subtle)]">
              Blue right axis: success rate (0–100%) for buckets with calls.
              Bars share the left count axis.
            </p>
          </>
        )}
      </div>
    </Card>
  );
}

/* ── 3. Step-by-step trace table ─────────────────────────────────────────── */

interface RunGroup {
  runId: string;
  rows: LogRecord[];
  cost: number;
  failed: number;
}

function TracesTable({
  traces,
  loading,
}: {
  traces: LogRecord[];
  loading: boolean;
}) {
  const [statusFilter, setStatusFilter] = useState<TraceStatus | "all">("all");
  const [agentFilter, setAgentFilter] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const agents = useMemo(() => {
    const set = new Set(traces.map((t) => t.agent));
    return Array.from(set).sort();
  }, [traces]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return traces.filter((t) => {
      if (statusFilter !== "all" && t.status !== statusFilter) return false;
      if (agentFilter !== "all" && t.agent !== agentFilter) return false;
      if (!needle) return true;
      return (
        t.run_id.toLowerCase().includes(needle) ||
        t.agent.toLowerCase().includes(needle) ||
        t.tool.toLowerCase().includes(needle) ||
        t.model.toLowerCase().includes(needle) ||
        t.detail.toLowerCase().includes(needle)
      );
    });
  }, [traces, statusFilter, agentFilter, query]);

  /** Group by run so each run shows a per-run cost subtotal. */
  const groups = useMemo<RunGroup[]>(() => {
    const map = new Map<string, RunGroup>();
    for (const t of filtered) {
      const g =
        map.get(t.run_id) ??
        ({ runId: t.run_id, rows: [], cost: 0, failed: 0 } as RunGroup);
      g.rows.push(t);
      g.cost += t.cost_usd;
      if (t.status === "failed") g.failed += 1;
      map.set(t.run_id, g);
    }
    return Array.from(map.values());
  }, [filtered]);

  const toggle = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const totalCost = filtered.reduce((sum, t) => sum + t.cost_usd, 0);

  if (loading) {
    return (
      <Card className="p-5">
        <Skeleton className="h-5 w-48" />
        <Skeleton className="mt-4 h-10 w-full" />
        <Skeleton className="mt-2 h-10 w-full" />
        <Skeleton className="mt-2 h-10 w-full" />
      </Card>
    );
  }

  return (
    <Card>
      {/* Header + filters */}
      <div className="border-b border-[var(--border)] p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <span className="grid h-8 w-8 place-items-center rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
              <Layers size={16} />
            </span>
            <div>
              <h2 className="text-sm font-semibold text-[var(--text)]">
                Step-by-step trace logs
              </h2>
              <p className="text-[11px] text-[var(--text-muted)]">
                {filtered.length} call{filtered.length === 1 ? "" : "s"} ·{" "}
                {groups.length} run{groups.length === 1 ? "" : "s"} ·{" "}
                {formatUsd(totalCost)} total
              </p>
            </div>
          </div>

          {/* Search */}
          <div className="relative w-full sm:w-64">
            <Search
              size={14}
              className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-subtle)]"
            />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search run, agent, tool, model…"
              aria-label="Search traces"
              className="w-full rounded-lg border border-[var(--border)] bg-[var(--panel-2)] py-1.5 pl-8 pr-3 text-xs text-[var(--text)] outline-none transition placeholder:text-[var(--text-subtle)] focus:border-[var(--accent)]"
            />
          </div>
        </div>

        {/* Filter chips */}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <div
            className="flex items-center gap-1 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] p-0.5"
            role="group"
            aria-label="Filter by status"
          >
            {(["all", "success", "failed", "skipped"] as const).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setStatusFilter(s)}
                aria-pressed={statusFilter === s}
                className={`rounded-md px-2.5 py-1 text-[11px] font-medium capitalize transition ${
                  statusFilter === s
                    ? "bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "text-[var(--text-muted)] hover:text-[var(--text)]"
                }`}
              >
                {s}
              </button>
            ))}
          </div>

          <select
            value={agentFilter}
            onChange={(e) => setAgentFilter(e.target.value)}
            aria-label="Filter by agent"
            className="rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2.5 py-1.5 text-[11px] text-[var(--text)] outline-none transition focus:border-[var(--accent)]"
          >
            <option value="all">All agents</option>
            {agents.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>

          {(statusFilter !== "all" ||
            agentFilter !== "all" ||
            query.trim() !== "") && (
            <button
              type="button"
              onClick={() => {
                setStatusFilter("all");
                setAgentFilter("all");
                setQuery("");
              }}
              className="rounded-lg border border-[var(--border)] px-2.5 py-1.5 text-[11px] text-[var(--text-muted)] transition hover:text-[var(--text)]"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Body */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={<Search size={18} />}
          title="No matching agent calls"
          hint="Adjust the status filter or clear the search to see more traces."
        />
      ) : (
        <div className="divide-y divide-[var(--border)]">
          {groups.map((group) => (
            <div key={group.runId}>
              {/* Per-run subtotal header */}
              <div className="flex flex-wrap items-center justify-between gap-2 bg-[var(--panel-2)] px-4 py-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px] text-[var(--text)]">
                    {group.runId}
                  </span>
                  <Badge tone="neutral">
                    {group.rows.length} call
                    {group.rows.length === 1 ? "" : "s"}
                  </Badge>
                  {group.failed > 0 && (
                    <Badge tone="danger">
                      <AlertTriangle size={11} />
                      {group.failed} failed
                    </Badge>
                  )}
                </div>
                <div className="flex items-center gap-3 text-[11px]">
                  <span className="text-[var(--text-subtle)]">run total</span>
                  <span className="font-medium text-[var(--text)]">
                    {formatUsd(group.cost)}
                  </span>
                </div>
              </div>

              {/* Rows */}
              {group.rows.map((row) => {
                const isOpen = expanded.has(row.trace_id);
                return (
                  <div key={row.trace_id} className="group">
                    <button
                      type="button"
                      onClick={() => toggle(row.trace_id)}
                      aria-expanded={isOpen}
                      className="grid w-full grid-cols-2 items-center gap-2 px-4 py-2.5 text-left transition hover:bg-[var(--panel-2)] sm:grid-cols-12"
                    >
                      {/* Expand chevron + timestamp */}
                      <div className="col-span-2 flex items-center gap-2 sm:col-span-3">
                        {isOpen ? (
                          <ChevronDown
                            size={13}
                            className="shrink-0 text-[var(--text-subtle)]"
                          />
                        ) : (
                          <ChevronRight
                            size={13}
                            className="shrink-0 text-[var(--text-subtle)]"
                          />
                        )}
                        <span
                          className="font-mono text-[11px] text-[var(--text-muted)]"
                          title={row.timestamp}
                        >
                          {formatClock(row.timestamp)}
                        </span>
                        <StatusDot tone={statusTone(row.status)} />
                      </div>

                      {/* Agent */}
                      <div className="col-span-2 min-w-0 sm:col-span-3">
                        <p className="truncate text-xs font-medium text-[var(--text)]">
                          {row.agent}
                        </p>
                        <p className="truncate text-[10px] text-[var(--text-subtle)]">
                          {row.model}
                          {row.provider ? ` · ${row.provider}` : ""}
                        </p>
                      </div>

                      {/* Tool + tier */}
                      <div className="sm:col-span-2">
                        <Badge tone="accent">{row.tool}</Badge>
                      </div>
                      <div className="hidden sm:col-span-1 sm:block">
                        <Badge tone={tierTone(row.complexity)}>
                          {row.complexity}
                        </Badge>
                      </div>

                      {/* Latency */}
                      <div className="text-right text-[11px] text-[var(--text-muted)] sm:col-span-1">
                        <span className="text-[10px] uppercase text-[var(--text-subtle)] sm:hidden">
                          lat{" "}
                        </span>
                        {formatDuration(row.latency_ms)}
                      </div>

                      {/* Tokens */}
                      <div
                        className="text-right text-[11px] text-[var(--text-muted)] sm:col-span-1"
                        title={`prompt ${row.prompt_tokens} / completion ${row.completion_tokens} / total ${row.total_tokens}`}
                      >
                        <span className="text-[10px] uppercase text-[var(--text-subtle)] sm:hidden">
                          tok{" "}
                        </span>
                        {formatTokens(row.total_tokens)}
                      </div>

                      {/* Cost */}
                      <div className="text-right text-[11px] font-medium text-[var(--text)] sm:col-span-1">
                        {formatUsd(row.cost_usd)}
                      </div>
                    </button>

                    {/* Expanded detail */}
                    {isOpen && (
                      <div className="border-t border-[var(--border)] bg-[var(--panel-2)] px-4 py-3">
                        <dl className="grid grid-cols-2 gap-3 text-[11px] sm:grid-cols-4">
                          <div>
                            <dt className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
                              Prompt tokens
                            </dt>
                            <dd className="mt-0.5 font-medium text-[var(--text)]">
                              {formatTokens(row.prompt_tokens)}
                            </dd>
                          </div>
                          <div>
                            <dt className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
                              Completion tokens
                            </dt>
                            <dd className="mt-0.5 font-medium text-[var(--text)]">
                              {formatTokens(row.completion_tokens)}
                            </dd>
                          </div>
                          <div>
                            <dt className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
                              Total tokens
                            </dt>
                            <dd className="mt-0.5 font-medium text-[var(--text)]">
                              {formatTokens(row.total_tokens)}
                            </dd>
                          </div>
                          <div>
                            <dt className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
                              Cost this task
                            </dt>
                            <dd className="mt-0.5 font-medium text-[var(--text)]">
                              {formatUsd(row.cost_usd)}
                            </dd>
                          </div>
                          <div>
                            <dt className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
                              Trace id
                            </dt>
                            <dd className="mt-0.5 break-all font-mono text-[10px] text-[var(--text-muted)]">
                              {row.trace_id}
                            </dd>
                          </div>
                          <div>
                            <dt className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
                              Timestamp
                            </dt>
                            <dd className="mt-0.5 font-mono text-[10px] text-[var(--text-muted)]">
                              {row.timestamp}
                            </dd>
                          </div>
                          <div className="sm:col-span-2">
                            <dt className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
                              Status
                            </dt>
                            <dd className="mt-0.5">
                              <Badge tone={statusTone(row.status)}>
                                {row.status}
                              </Badge>
                            </dd>
                          </div>
                        </dl>
                        {row.detail && (
                          <div className="mt-3">
                            <p className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
                              Step detail
                            </p>
                            <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-[var(--border)] bg-[var(--panel)] p-2.5 font-mono text-[11px] text-[var(--text-muted)]">
                              {row.detail}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

/* ── Page ────────────────────────────────────────────────────────────────── */

export default function ObservabilityPage() {
  const { mode, mounted, setMode } = useTheme();
  const [active] = useState<NavKey>("observability");
  const [collapsed, setCollapsed] = useState(false);
  const [data, setData] = useState<LogsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [demoMode, setDemoMode] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    try {
      const res = await api.getLogs({ limit: 500 });
      setData(res);
      setDemoMode(false);
    } catch (err) {
      // Any API failure (unreachable, 500, timeout) falls back to the demo set
      // so the page is never blank. Surface which mode we're in via the badge.
      if (err instanceof ApiError) {
        setData(DEMO_LOGS);
        setDemoMode(true);
      } else {
        setData(DEMO_LOGS);
        setDemoMode(true);
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const summary = data?.summary;

  return (
    <div className="flex h-screen overflow-hidden bg-[var(--bg)] text-[var(--text)]">
      <Sidebar
        active={active}
        onSelect={() => {
          /* this page is its own route; nav items without an href switch views */
        }}
        collapsed={collapsed}
        onToggleCollapsed={() => setCollapsed((c) => !c)}
        pendingCount={0}
        onOpenApprovals={() => {
          /* approvals live on the main dashboard */
        }}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        {/* Header */}
        <header className="flex h-16 shrink-0 items-center justify-between gap-3 border-b border-[var(--border)] bg-[var(--bg-elevated)] px-5">
          <div className="min-w-0">
            <h1 className="truncate text-sm font-semibold text-[var(--text)]">
              Observability
            </h1>
            <p className="truncate text-[11px] text-[var(--text-muted)]">
              Model routing savings, success rates and step traces
            </p>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            {demoMode ? (
              <Badge tone="warning">
                <AlertTriangle size={11} />
                demo data — backend unreachable
              </Badge>
            ) : (
              <Badge tone="success">
                <StatusDot tone="success" pulse />
                live
              </Badge>
            )}

            <Link
              href="/dashboard"
              className="hidden rounded-lg border border-[var(--border)] px-2.5 py-1.5 text-[11px] text-[var(--text-muted)] transition hover:text-[var(--text)] sm:block"
            >
              ← Dashboard
            </Link>

            <button
              type="button"
              onClick={() => void load(true)}
              title="Refresh logs"
              aria-label="Refresh logs"
              className="grid h-8 w-8 place-items-center rounded-lg border border-[var(--border)] text-[var(--text-muted)] transition hover:text-[var(--text)]"
            >
              <RefreshCw
                size={14}
                className={refreshing ? "animate-spin" : ""}
              />
            </button>

            <ThemeToggle mode={mode} mounted={mounted} onSelect={setMode} />
          </div>
        </header>

        {/* Body */}
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1180px] space-y-4 p-5">
            {/* KPIs */}
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <Kpi
                icon={<Coins size={15} />}
                label="Saved by routing"
                value={
                  loading ? "—" : formatUsd(data?.routing.saved_usd ?? 0)
                }
                sub={
                  loading
                    ? undefined
                    : `${formatPct(data?.routing.saved_pct ?? 0, 2)} vs all-premium`
                }
                accent
              />
              <Kpi
                icon={<CheckCircle2 size={15} />}
                label="Success rate"
                value={
                  loading
                    ? "—"
                    : formatPct((summary?.success_rate ?? 0) * 100)
                }
                sub={
                  loading
                    ? undefined
                    : `${summary?.succeeded ?? 0} ok · ${summary?.failed ?? 0} failed`
                }
              />
              <Kpi
                icon={<Activity size={15} />}
                label="Agent calls"
                value={loading ? "—" : String(summary?.calls ?? 0)}
                sub={
                  loading ? undefined : `${summary?.runs ?? 0} runs traced`
                }
              />
              <Kpi
                icon={<Clock size={15} />}
                label="Avg latency"
                value={
                  loading
                    ? "—"
                    : formatDuration(summary?.avg_latency_ms ?? 0)
                }
                sub={
                  loading
                    ? undefined
                    : `${formatTokens(summary?.total_tokens ?? 0)} tokens`
                }
              />
            </div>

            <RoutingSavingsCard
              routing={data?.routing ?? null}
              loading={loading}
            />

            <SuccessChart success={data?.success ?? null} loading={loading} />

            <TracesTable traces={data?.traces ?? []} loading={loading} />

            <p className="pb-2 text-center text-[10px] text-[var(--text-subtle)]">
              {data
                ? `Source: GET /api/logs · generated ${formatClock(data.generated_at)}`
                : "Loading execution logs…"}
            </p>
          </div>
        </main>
      </div>
    </div>
  );
}
