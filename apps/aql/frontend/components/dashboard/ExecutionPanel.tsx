"use client";

/**
 * Execution panel — a live run timeline for the multi-agent orchestrator.
 *
 * Renders the planner → executor → reviewer loop as a streaming list of
 * timeline entries (agent, tool, status, duration, cost), keeps a running cost
 * total, and auto-scrolls as new entries arrive. When the backend is
 * unreachable it replays `DEMO_ORCHESTRATION` so the panel is never empty.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  CircleDashed,
  Coins,
  FileText,
  Loader2,
  Play,
  RefreshCw,
  Search,
  Sparkles,
  Terminal,
  XCircle,
  type LucideIcon,
} from "lucide-react";

import type { OrchestrationState } from "@/lib/api";
import {
  Badge,
  Card,
  EmptyState,
  Skeleton,
  StatusDot,
  formatDuration,
  formatUsd,
  type Tone,
} from "./ui";

/* ── Timeline model ─────────────────────────────────────────────────────── */

type EntryStatus = "done" | "running" | "failed" | "pending";

interface TimelineEntry {
  key: string;
  agent: string;
  tool: string;
  detail: string;
  status: EntryStatus;
  durationMs: number;
  costUsd: number;
  tokens: number;
  Icon: LucideIcon;
}

const TOOL_ICONS: Record<string, LucideIcon> = {
  web_search: Search,
  python_exec: Terminal,
  file_generator: FileText,
  echo: Sparkles,
};

/** Maps a tool to the sub-agent that runs it. */
function agentForTool(tool: string): string {
  if (tool === "web_search") return "ExecutionAgent · Researcher";
  if (tool === "python_exec") return "ExecutionAgent · Analyst";
  if (tool === "file_generator") return "ExecutionAgent · Builder";
  return "ExecutionAgent";
}

/** Rough token estimate from output length — the API reports cost, not tokens. */
function estimateTokens(text: string): number {
  return Math.max(0, Math.round(text.length / 4));
}

function statusTone(status: EntryStatus): Tone {
  if (status === "done") return "success";
  if (status === "running") return "accent";
  if (status === "failed") return "danger";
  return "neutral";
}

/** Flattens an orchestration state into the ordered timeline the UI renders. */
function buildTimeline(state: OrchestrationState): TimelineEntry[] {
  const entries: TimelineEntry[] = [];

  // 1. Planner — always the first entry.
  entries.push({
    key: "planner",
    agent: "PlannerAgent",
    tool: "plan",
    detail: `Decomposed the goal into ${state.plan.length} sequential sub-task${
      state.plan.length === 1 ? "" : "s"
    }`,
    status: state.plan.length > 0 ? "done" : "running",
    durationMs: 0,
    costUsd: 0,
    tokens: 0,
    Icon: Sparkles,
  });

  // 2. Per sub-task: the execution entry, then its review entry.
  for (const task of state.plan) {
    const result = state.results.find((r) => r.task_id === task.id);
    const review = state.reviews.find((v) => v.task_id === task.id);
    const Icon = TOOL_ICONS[task.tool] ?? CircleDashed;

    const execStatus: EntryStatus = !result
      ? "pending"
      : result.ok
        ? "done"
        : "failed";

    entries.push({
      key: `${task.id}-exec`,
      agent: agentForTool(task.tool),
      tool: task.tool,
      detail: result?.output || task.description,
      status: execStatus,
      durationMs: result?.duration_ms ?? 0,
      costUsd: result?.cost_usd ?? 0,
      tokens: estimateTokens(result?.output ?? ""),
      Icon,
    });

    if (review) {
      const approved = review.verdict === "approved";
      entries.push({
        key: `${task.id}-review`,
        agent: "ReviewerAgent",
        tool: "review",
        detail: `${approved ? "Approved" : "Needs revision"} · score ${review.score.toFixed(
          2,
        )}${review.feedback ? ` — ${review.feedback}` : ""}`,
        status: approved ? "done" : "failed",
        durationMs: 0,
        costUsd: 0,
        tokens: 0,
        Icon: approved ? CheckCircle2 : AlertTriangle,
      });
    }
  }

  // 3. Final synthesis entry.
  if (state.final_output) {
    entries.push({
      key: "final",
      agent: "Orchestrator",
      tool: "finalize",
      detail: state.final_output,
      status: "done",
      durationMs: state.duration_ms,
      costUsd: 0,
      tokens: estimateTokens(state.final_output),
      Icon: CheckCircle2,
    });
  }

  return entries;
}

/* ── Sub-components ─────────────────────────────────────────────────────── */

function TimelineRow({ entry }: { entry: TimelineEntry }) {
  const { Icon } = entry;
  const tone = statusTone(entry.status);
  return (
    <li className="relative flex gap-3 pb-4 last:pb-0 animate-fade-in">
      {/* Connector rail */}
      <span className="absolute left-[15px] top-8 h-[calc(100%-1.5rem)] w-px bg-[var(--border)] last:hidden" />

      <span
        className={`relative z-10 grid h-8 w-8 shrink-0 place-items-center rounded-lg border ${
          entry.status === "failed"
            ? "border-red-500/30 bg-red-500/10 text-red-500"
            : entry.status === "pending"
              ? "border-[var(--border)] bg-[var(--panel-2)] text-[var(--text-subtle)]"
              : "border-[var(--border)] bg-[var(--panel-2)] text-[var(--accent)]"
        }`}
      >
        {entry.status === "running" ? (
          <Loader2 size={15} className="animate-spin" />
        ) : (
          <Icon size={15} strokeWidth={2} />
        )}
      </span>

      <div className="min-w-0 flex-1 rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2.5">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="text-[13px] font-semibold text-[var(--text)]">
            {entry.agent}
          </span>
          <code className="rounded bg-[var(--panel)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--text-muted)]">
            {entry.tool}
          </code>
          <Badge tone={tone} className="ml-auto">
            <StatusDot tone={tone} pulse={entry.status === "running"} />
            {entry.status}
          </Badge>
        </div>

        <p className="mt-1.5 line-clamp-3 text-xs leading-relaxed text-[var(--text-muted)]">
          {entry.detail}
        </p>

        {(entry.durationMs > 0 || entry.costUsd > 0 || entry.tokens > 0) && (
          <div className="mt-2 flex flex-wrap items-center gap-3 text-[11px] text-[var(--text-subtle)]">
            {entry.durationMs > 0 && <span>{formatDuration(entry.durationMs)}</span>}
            {entry.tokens > 0 && <span>~{entry.tokens} tok</span>}
            {entry.costUsd > 0 && (
              <span className="font-medium text-[var(--text-muted)]">
                {formatUsd(entry.costUsd)}
              </span>
            )}
          </div>
        )}
      </div>
    </li>
  );
}

function CostMeter({
  total,
  steps,
  running,
}: {
  total: number;
  steps: number;
  running: boolean;
}) {
  return (
    <div className="flex items-center gap-4 rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-4 py-3">
      <div className="grid h-9 w-9 place-items-center rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
        <Coins size={17} strokeWidth={2} />
      </div>
      <div>
        <p className="text-[11px] uppercase tracking-wide text-[var(--text-subtle)]">
          Cost incurred
        </p>
        <p className="font-mono text-lg font-semibold text-[var(--text)]">
          {formatUsd(total)}
        </p>
      </div>
      <div className="ml-auto text-right">
        <p className="text-[11px] uppercase tracking-wide text-[var(--text-subtle)]">
          Steps
        </p>
        <p className="font-mono text-lg font-semibold text-[var(--text)]">
          {steps}
        </p>
      </div>
      {running && (
        <Badge tone="accent">
          <Loader2 size={11} className="animate-spin" />
          live
        </Badge>
      )}
    </div>
  );
}

/* ── Panel ──────────────────────────────────────────────────────────────── */

export default function ExecutionPanel({
  state,
  loading,
  running,
  error,
  isDemo,
  onRun,
  onRefresh,
}: {
  state: OrchestrationState | null;
  loading: boolean;
  running: boolean;
  error: string | null;
  isDemo: boolean;
  onRun: (task: string) => void;
  onRefresh: () => void;
}) {
  const [task, setTask] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  const timeline = useMemo(() => (state ? buildTimeline(state) : []), [state]);

  // Auto-scroll to the newest entry — the "streaming" feel.
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }, [timeline.length, running]);

  const totalCost = state?.total_cost_usd ?? 0;
  const stepCount = state?.results.length ?? 0;

  return (
    <div className="flex h-full flex-col gap-4">
      {/* Run launcher */}
      <Card className="p-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const value = task.trim();
            if (value && !running) onRun(value);
          }}
          className="flex flex-col gap-3 sm:flex-row sm:items-center"
        >
          <div className="relative flex-1">
            <Sparkles
              size={15}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-subtle)]"
            />
            <input
              value={task}
              onChange={(e) => setTask(e.target.value)}
              placeholder="Describe a goal for the agent team…"
              aria-label="Task for the agent team"
              className="w-full rounded-xl border border-[var(--border)] bg-[var(--panel-2)] py-2.5 pl-9 pr-3 text-sm text-[var(--text)] outline-none transition placeholder:text-[var(--text-subtle)] focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent)]/20"
            />
          </div>
          <div className="flex items-center gap-2">
            <button
              type="submit"
              disabled={running || task.trim().length === 0}
              className="inline-flex items-center gap-2 rounded-xl bg-brand-500 px-4 py-2.5 text-sm font-semibold text-white shadow-soft transition hover:bg-brand-600 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {running ? (
                <Loader2 size={15} className="animate-spin" />
              ) : (
                <Play size={15} strokeWidth={2.5} />
              )}
              {running ? "Running" : "Run"}
            </button>
            <button
              type="button"
              onClick={onRefresh}
              title="Refresh run"
              aria-label="Refresh run"
              className="grid h-10 w-10 place-items-center rounded-xl border border-[var(--border)] bg-[var(--panel-2)] text-[var(--text-muted)] transition hover:text-[var(--text)]"
            >
              <RefreshCw size={15} strokeWidth={2} />
            </button>
          </div>
        </form>

        {isDemo && (
          <p className="mt-3 flex items-center gap-1.5 text-[11px] text-amber-600 dark:text-amber-300">
            <AlertTriangle size={12} />
            Backend unreachable — showing a demo run. Start the API to go live.
          </p>
        )}
        {error && !isDemo && (
          <p className="mt-3 flex items-center gap-1.5 text-[11px] text-red-500">
            <XCircle size={12} />
            {error}
          </p>
        )}
      </Card>

      {/* Cost + status strip */}
      <CostMeter total={totalCost} steps={stepCount} running={running} />

      {/* Timeline */}
      <Card className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="flex items-center gap-2 border-b border-[var(--border)] px-4 py-3">
          <StatusDot
            tone={running ? "accent" : state ? "success" : "neutral"}
            pulse={running}
          />
          <h2 className="text-sm font-semibold text-[var(--text)]">
            Live run timeline
          </h2>
          {state && (
            <span className="ml-auto font-mono text-[11px] text-[var(--text-subtle)]">
              {state.run_id}
            </span>
          )}
        </div>

        <div ref={scrollRef} className="scroll-thin min-h-0 flex-1 overflow-y-auto p-4">
          {loading && !state ? (
            <div className="space-y-3">
              {[0, 1, 2].map((i) => (
                <div key={i} className="flex gap-3">
                  <Skeleton className="h-8 w-8 rounded-lg" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-3 w-40" />
                    <Skeleton className="h-3 w-full" />
                  </div>
                </div>
              ))}
            </div>
          ) : timeline.length === 0 ? (
            <EmptyState
              icon={<CircleDashed size={18} />}
              title="No run yet"
              hint="Describe a goal above and hit Run to watch the planner, executor and reviewer work through it."
            />
          ) : (
            <ol className="relative">
              {timeline.map((entry) => (
                <TimelineRow key={entry.key} entry={entry} />
              ))}
            </ol>
          )}
        </div>

        {/* Final output footer */}
        {state?.final_output && (
          <div className="border-t border-[var(--border)] bg-[var(--panel-2)] px-4 py-3">
            <p className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-[var(--text-subtle)]">
              <ArrowRight size={11} />
              Final output
            </p>
            <p className="text-xs leading-relaxed text-[var(--text-muted)]">
              {state.final_output}
            </p>
          </div>
        )}
      </Card>
    </div>
  );
}
