"use client";

/**
 * AQL-1 dashboard — the control plane for the agent operating layer.
 *
 * Layout: a collapsible sidebar (Agents / Runs / Observability / Billing /
 * Settings) beside a main column. The Agents view hosts the live execution
 * panel; a header action opens the Pending Approvals modal, which is wired to
 * the real `/agent/approvals` + `/agent/approve` endpoints.
 *
 * Every fetch degrades to demo data when the backend is unreachable, so the UI
 * is always explorable.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  RefreshCw,
  Server,
  ShieldAlert,
  Wifi,
  WifiOff,
} from "lucide-react";

import {
  api,
  ApiError,
  type OrchestrationState,
  type PendingApproval,
  type ToolSchema,
} from "@/lib/api";
import Sidebar, { NAV_ITEMS, type NavKey } from "@/components/dashboard/Sidebar";
import ExecutionPanel from "@/components/dashboard/ExecutionPanel";
import ApprovalsModal from "@/components/dashboard/ApprovalsModal";
import { DEMO_APPROVALS, DEMO_ORCHESTRATION } from "@/components/dashboard/demo";
import {
  Badge,
  Card,
  EmptyState,
  StatusDot,
  ThemeToggle,
  formatUsd,
  useTheme,
} from "@/components/dashboard/ui";

type Connection = "checking" | "online" | "offline";

/* ── Secondary views ────────────────────────────────────────────────────── */

function RunsView({ state }: { state: OrchestrationState | null }) {
  if (!state) {
    return (
      <Card>
        <EmptyState
          icon={<Activity size={18} />}
          title="No runs yet"
          hint="Run a goal from the Agents view and it will show up here."
        />
      </Card>
    );
  }
  return (
    <Card className="overflow-hidden">
      <div className="border-b border-[var(--border)] px-4 py-3">
        <h2 className="text-sm font-semibold text-[var(--text)]">Run history</h2>
      </div>
      <table className="w-full text-left text-xs">
        <thead className="text-[var(--text-subtle)]">
          <tr className="border-b border-[var(--border)]">
            <th className="px-4 py-2 font-medium">Run</th>
            <th className="px-4 py-2 font-medium">Status</th>
            <th className="px-4 py-2 font-medium">Iterations</th>
            <th className="px-4 py-2 font-medium">Cost</th>
          </tr>
        </thead>
        <tbody>
          <tr className="text-[var(--text-muted)]">
            <td className="px-4 py-2.5 font-mono">{state.run_id}</td>
            <td className="px-4 py-2.5">
              <Badge tone={state.status === "completed" ? "success" : "warning"}>
                {state.status}
              </Badge>
            </td>
            <td className="px-4 py-2.5">
              {state.iteration}/{state.max_iterations}
            </td>
            <td className="px-4 py-2.5 font-mono">
              {formatUsd(state.total_cost_usd)}
            </td>
          </tr>
        </tbody>
      </table>
    </Card>
  );
}

function ObservabilityView({ state }: { state: OrchestrationState | null }) {
  const steps = state?.results.length ?? 0;
  const approved = state?.approved_count ?? 0;
  const cost = state?.total_cost_usd ?? 0;
  const avg = steps > 0 ? cost / steps : 0;

  const metrics = [
    { label: "Steps executed", value: String(steps) },
    { label: "Approved", value: `${approved}/${steps}` },
    { label: "Total cost", value: formatUsd(cost) },
    { label: "Avg cost / step", value: formatUsd(avg) },
  ];

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {metrics.map((m) => (
        <Card key={m.label} className="p-4">
          <p className="text-[11px] uppercase tracking-wide text-[var(--text-subtle)]">
            {m.label}
          </p>
          <p className="mt-1 font-mono text-xl font-semibold text-[var(--text)]">
            {m.value}
          </p>
        </Card>
      ))}
    </div>
  );
}

function BillingView({ state }: { state: OrchestrationState | null }) {
  const cost = state?.total_cost_usd ?? 0;
  const budget = 5;
  const pct = Math.min(100, (cost / budget) * 100);
  return (
    <Card className="p-5">
      <h2 className="text-sm font-semibold text-[var(--text)]">Usage this session</h2>
      <p className="mt-1 text-xs text-[var(--text-muted)]">
        Estimated spend across all routed model calls.
      </p>
      <p className="mt-4 font-mono text-3xl font-semibold text-[var(--text)]">
        {formatUsd(cost)}
      </p>
      <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-[var(--panel-2)]">
        <div
          className="h-full rounded-full bg-brand-500 transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="mt-2 text-[11px] text-[var(--text-subtle)]">
        {pct.toFixed(1)}% of a {formatUsd(budget)} demo budget
      </p>
    </Card>
  );
}

function SettingsView({
  tools,
  connection,
}: {
  tools: ToolSchema[];
  connection: Connection;
}) {
  return (
    <div className="space-y-4">
      <Card className="p-5">
        <h2 className="text-sm font-semibold text-[var(--text)]">Backend</h2>
        <div className="mt-3 flex items-center gap-2 text-xs text-[var(--text-muted)]">
          <StatusDot
            tone={connection === "online" ? "success" : connection === "offline" ? "danger" : "neutral"}
            pulse={connection === "checking"}
          />
          <span className="font-mono">{api.baseUrl}</span>
          <Badge tone={connection === "online" ? "success" : "neutral"}>
            {connection}
          </Badge>
        </div>
      </Card>

      <Card className="overflow-hidden">
        <div className="border-b border-[var(--border)] px-4 py-3">
          <h2 className="text-sm font-semibold text-[var(--text)]">
            Registered tools ({tools.length})
          </h2>
        </div>
        {tools.length === 0 ? (
          <EmptyState
            icon={<Server size={18} />}
            title="No tools loaded"
            hint="Start the backend to load the tool registry."
          />
        ) : (
          <ul className="divide-y divide-[var(--border)]">
            {tools.map((t) => (
              <li key={t.function.name} className="px-4 py-3">
                <p className="font-mono text-xs text-[var(--accent)]">
                  {t.function.name}
                </p>
                <p className="mt-0.5 text-[11px] text-[var(--text-muted)]">
                  {t.function.description}
                </p>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

/* ── Page ───────────────────────────────────────────────────────────────── */

export default function DashboardPage() {
  const { mode, mounted, setMode } = useTheme();

  const [nav, setNav] = useState<NavKey>("agents");
  const [collapsed, setCollapsed] = useState(false);
  const [connection, setConnection] = useState<Connection>("checking");
  const [tools, setTools] = useState<ToolSchema[]>([]);

  const [state, setState] = useState<OrchestrationState | null>(null);
  const [runLoading, setRunLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [isDemo, setIsDemo] = useState(false);

  const [approvals, setApprovals] = useState<PendingApproval[]>([]);
  const [approvalsLoading, setApprovalsLoading] = useState(true);
  const [approvalsDemo, setApprovalsDemo] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);

  /** Loads pending approvals, falling back to demo data offline. */
  const loadApprovals = useCallback(async () => {
    setApprovalsLoading(true);
    try {
      const res = await api.approvals("pending");
      setApprovals(res.approvals);
      setApprovalsDemo(false);
    } catch {
      setApprovals(DEMO_APPROVALS);
      setApprovalsDemo(true);
    } finally {
      setApprovalsLoading(false);
    }
  }, []);

  /** Health + tools + approvals on mount. */
  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        await api.health();
        if (cancelled) return;
        setConnection("online");
        const t = await api.tools();
        if (!cancelled) setTools(t.tools);
      } catch {
        if (!cancelled) {
          setConnection("offline");
          setTools([]);
        }
      }
    })();

    (async () => {
      // Seed the timeline with the demo run so the panel is never empty.
      setRunLoading(true);
      try {
        await api.health();
        if (cancelled) return;
        setIsDemo(false);
        setState(null);
      } catch {
        if (cancelled) return;
        setIsDemo(true);
        setState(DEMO_ORCHESTRATION);
      } finally {
        if (!cancelled) setRunLoading(false);
      }
    })();

    void loadApprovals();

    return () => {
      cancelled = true;
    };
  }, [loadApprovals]);

  /** Runs a goal through the orchestrator (or simulates it in demo mode). */
  const handleRun = useCallback(async (task: string) => {
    setRunning(true);
    setRunError(null);
    try {
      if (isDemo) {
        await new Promise((r) => setTimeout(r, 900));
        setState({ ...DEMO_ORCHESTRATION, prompt: task, run_id: `demo-${Date.now()}` });
      } else {
        const result = await api.orchestrate(task);
        setState(result);
        // A paused run creates a new pending approval — refresh the badge.
        if (result.status === "pending_approval") void loadApprovals();
      }
    } catch (err) {
      setRunError(
        err instanceof ApiError ? err.message : "The run could not be started.",
      );
    } finally {
      setRunning(false);
    }
  }, [isDemo, loadApprovals]);

  const pendingCount = approvals.length;
  const activeNav = useMemo(
    () => NAV_ITEMS.find((n) => n.key === nav) ?? NAV_ITEMS[0],
    [nav],
  );

  return (
    <div className="flex h-screen overflow-hidden bg-[var(--bg)]">
      <Sidebar
        active={nav}
        onSelect={setNav}
        collapsed={collapsed}
        onToggleCollapsed={() => setCollapsed((c) => !c)}
        pendingCount={pendingCount}
        onOpenApprovals={() => setModalOpen(true)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        {/* Header */}
        <header className="flex h-16 shrink-0 items-center gap-3 border-b border-[var(--border)] bg-[var(--bg-elevated)] px-5">
          <div className="min-w-0">
            <h1 className="truncate text-sm font-semibold text-[var(--text)]">
              {activeNav.label}
            </h1>
            <p className="truncate text-[11px] text-[var(--text-subtle)]">
              {activeNav.hint}
            </p>
          </div>

          <div className="ml-auto flex items-center gap-2">
            <Badge tone={connection === "online" ? "success" : connection === "offline" ? "danger" : "neutral"}>
              {connection === "online" ? (
                <Wifi size={11} />
              ) : connection === "offline" ? (
                <WifiOff size={11} />
              ) : (
                <RefreshCw size={11} className="animate-spin" />
              )}
              {connection === "online"
                ? "live"
                : connection === "offline"
                  ? "demo"
                  : "checking"}
            </Badge>

            <button
              type="button"
              onClick={() => setModalOpen(true)}
              className="relative inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2 text-xs font-medium text-[var(--text-muted)] transition hover:text-[var(--text)]"
            >
              <ShieldAlert size={14} strokeWidth={2} />
              Approvals
              {pendingCount > 0 && (
                <span className="grid h-4 min-w-4 place-items-center rounded-full bg-amber-500 px-1 text-[10px] font-bold text-white">
                  {pendingCount > 9 ? "9+" : pendingCount}
                </span>
              )}
            </button>

            <ThemeToggle mode={mode} mounted={mounted} onSelect={setMode} />
          </div>
        </header>

        {/* Main content */}
        <main className="scroll-thin min-h-0 flex-1 overflow-y-auto p-5">
          {nav === "agents" && (
            <div className="mx-auto h-full max-w-4xl">
              <ExecutionPanel
                state={state}
                loading={runLoading}
                running={running}
                error={runError}
                isDemo={isDemo}
                onRun={handleRun}
                onRefresh={() => void loadApprovals()}
              />
            </div>
          )}

          {nav === "runs" && (
            <div className="mx-auto max-w-4xl">
              <RunsView state={state} />
            </div>
          )}

          {nav === "observability" && (
            <div className="mx-auto max-w-4xl">
              <ObservabilityView state={state} />
            </div>
          )}

          {nav === "billing" && (
            <div className="mx-auto max-w-4xl">
              <BillingView state={state} />
            </div>
          )}

          {nav === "settings" && (
            <div className="mx-auto max-w-4xl">
              <SettingsView tools={tools} connection={connection} />
            </div>
          )}
        </main>
      </div>

      <ApprovalsModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        approvals={approvals}
        loading={approvalsLoading}
        isDemo={approvalsDemo}
        onDecided={() => void loadApprovals()}
      />
    </div>
  );
}
