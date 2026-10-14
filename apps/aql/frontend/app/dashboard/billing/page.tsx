"use client";

/**
 * AQL-1 — Billing.
 *
 * Reached from the sidebar's **Billing** item (a real route, not an in-page
 * tab). It reads two payloads from the backend and renders five panels:
 *
 *  1. **Current plan** — tier, status badge, renewal date and a "Refresh
 *     status" button (payments are verified manually by an admin).
 *  2. **Token usage** — a progress bar of tokens used vs the tier's monthly
 *     limit, with a warning state as the allowance runs out.
 *  3. **Pricing tiers** — Free / Pro / Team cards with the current tier
 *     highlighted and a CTA that jumps to the manual Payoneer / bank payment form.
 *  4. **Feature comparison** — which capabilities each tier enables.
 *  5. **Billing history** — past invoices, with an empty state.
 *
 * If the API is unreachable the page degrades to the deterministic demo
 * dataset, exactly like the dashboard and the Observability page.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  CheckCircle2,
  CreditCard,
  ExternalLink,
  Info,
  Loader2,
  Minus,
  Receipt,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Users,
  Zap,
} from "lucide-react";

import api, {
  ApiError,
  type FeatureKey,
  type Plan,
  type PlansResponse,
  type SubscriptionResponse,
  type TierId,
  type UsageSummary,
} from "@/lib/api";

import ManualPayment from "@/components/dashboard/ManualPayment";
import Sidebar, { type NavKey } from "@/components/dashboard/Sidebar";
import {
  Badge,
  Card,
  EmptyState,
  Skeleton,
  StatusDot,
  ThemeToggle,
  useTheme,
  type Tone,
} from "@/components/dashboard/ui";
import {
  DEMO_INVOICES,
  DEMO_PLANS_RESPONSE,
  DEMO_SUBSCRIPTION,
  type Invoice,
} from "@/components/dashboard/billing-demo";

/* ── Formatters ──────────────────────────────────────────────────────────── */

/** `$29` / `$0` — prices are whole dollars, so no cents noise. */
function formatPrice(value: number): string {
  if (!Number.isFinite(value)) return "$0";
  return `$${value % 1 === 0 ? value.toFixed(0) : value.toFixed(2)}`;
}

/**
 * Compact token counts: `50k`, `2M`, `10M`.
 *
 * The shared `formatTokens` renders 2,000,000 as "2000.0k", which reads badly
 * on a pricing card, so limits get their own formatter.
 */
function formatTokenCount(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0";
  if (n >= 1_000_000) {
    const m = n / 1_000_000;
    return `${m % 1 === 0 ? m.toFixed(0) : m.toFixed(1)}M`;
  }
  if (n >= 1_000) {
    const k = n / 1_000;
    return `${k % 1 === 0 ? k.toFixed(0) : k.toFixed(1)}k`;
  }
  return `${Math.round(n)}`;
}

/** `1 Nov 2026` — a renewal date reads better than an ISO string. */
function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
}

function statusTone(status: string): Tone {
  if (status === "active" || status === "trialing") return "success";
  if (status === "past_due" || status === "unpaid") return "warning";
  if (status === "canceled" || status === "incomplete") return "danger";
  return "neutral";
}

function statusLabel(status: string): string {
  return status.replace(/_/g, " ");
}

/* ── Feature metadata ────────────────────────────────────────────────────── */

const FEATURE_ORDER: FeatureKey[] = [
  "api_access",
  "priority_routing",
  "observability_history",
  "team_management",
  "sso",
];

const FEATURE_LABELS: Record<FeatureKey, string> = {
  api_access: "REST API access",
  priority_routing: "Priority model routing",
  observability_history: "Observability history",
  team_management: "Team management",
  sso: "SSO-ready",
};

/* ── 1. Current plan ─────────────────────────────────────────────────────── */

function CurrentPlanCard({
  data,
  loading,
  onManage,
  managing,
  demoMode,
}: {
  data: SubscriptionResponse | null;
  loading: boolean;
  onManage: () => void;
  managing: boolean;
  demoMode: boolean;
}) {
  if (loading || !data) {
    return (
      <Card className="p-5">
        <Skeleton className="h-5 w-32" />
        <Skeleton className="mt-4 h-8 w-40" />
        <Skeleton className="mt-4 h-9 w-full" />
      </Card>
    );
  }

  const sub = data.subscription;

  return (
    <Card className="flex flex-col p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
            <CreditCard size={16} />
          </span>
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">
              Current plan
            </h2>
            <p className="text-[11px] text-[var(--text-muted)]">
              Your subscription and renewal
            </p>
          </div>
        </div>
        <Badge tone={statusTone(sub.status)}>
          <StatusDot tone={statusTone(sub.status)} />
          {statusLabel(sub.status)}
        </Badge>
      </div>

      <div className="mt-4 flex items-baseline gap-2">
        <span className="text-2xl font-semibold tracking-tight text-[var(--text)]">
          {sub.tier_name}
        </span>
        <span className="text-sm text-[var(--text-muted)]">
          {formatPrice(sub.price_usd)}
          <span className="text-[var(--text-subtle)]">/mo</span>
        </span>
      </div>

      <dl className="mt-4 grid grid-cols-2 gap-3 text-[11px]">
        <div className="rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2">
          <dt className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
            Renews
          </dt>
          <dd className="mt-0.5 font-medium text-[var(--text)]">
            {formatDate(data.renewal_date)}
          </dd>
        </div>
        <div className="rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2">
          <dt className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
            Seats
          </dt>
          <dd className="mt-0.5 font-medium text-[var(--text)]">
            {sub.seats}
          </dd>
        </div>
      </dl>

      {data.cancel_at_period_end && (
        <p className="mt-3 flex items-start gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/10 px-2.5 py-2 text-[11px] text-amber-600 dark:text-amber-300">
          <AlertTriangle size={12} className="mt-0.5 shrink-0" />
          Cancels at the end of the current period.
        </p>
      )}

      <div className="mt-auto pt-4">
        <button
          type="button"
          onClick={onManage}
          disabled={managing}
          className="flex w-full items-center justify-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2 text-xs font-medium text-[var(--text)] transition hover:border-[var(--border-strong)] disabled:opacity-60"
        >
          {managing ? (
            <Loader2 size={13} className="animate-spin" />
          ) : (
            <ExternalLink size={13} />
          )}
          Refresh status
        </button>
        {demoMode && (
          <p className="mt-2 text-center text-[10px] text-[var(--text-subtle)]">
            Demo mode — showing sample data
          </p>
        )}
      </div>
    </Card>
  );
}

/* ── 2. Token usage ──────────────────────────────────────────────────────── */

function TokenUsageCard({
  usage,
  loading,
}: {
  usage: UsageSummary | null;
  loading: boolean;
}) {
  if (loading || !usage) {
    return (
      <Card className="p-5">
        <Skeleton className="h-5 w-32" />
        <Skeleton className="mt-4 h-8 w-40" />
        <Skeleton className="mt-4 h-2 w-full" />
      </Card>
    );
  }

  const pct = Math.min(100, Math.max(0, usage.percent_used));
  const nearLimit = pct >= 80 && pct < 100;
  const overLimit = usage.is_exhausted || pct >= 100;

  const barColor = overLimit
    ? "bg-red-500"
    : nearLimit
      ? "bg-amber-500"
      : "bg-[var(--accent)]";

  return (
    <Card className="flex flex-col p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
            <Zap size={16} />
          </span>
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">
              Token usage
            </h2>
            <p className="text-[11px] text-[var(--text-muted)]">
              This billing period
            </p>
          </div>
        </div>
        <Badge tone={overLimit ? "danger" : nearLimit ? "warning" : "neutral"}>
          {pct.toFixed(1)}%
        </Badge>
      </div>

      <div className="mt-4 flex items-baseline gap-1.5">
        <span className="text-2xl font-semibold tracking-tight text-[var(--text)]">
          {formatTokenCount(usage.tokens_used)}
        </span>
        <span className="text-sm text-[var(--text-muted)]">
          / {formatTokenCount(usage.tokens_limit)} tokens
        </span>
      </div>

      {/* Progress bar */}
      <div
        className="mt-3 h-2 w-full overflow-hidden rounded-full bg-[var(--panel-2)]"
        role="progressbar"
        aria-valuenow={Math.round(pct)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Monthly token usage"
      >
        <div
          className={`h-full rounded-full transition-all duration-500 ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>

      <div className="mt-3 flex items-center justify-between text-[11px]">
        <span className="text-[var(--text-muted)]">
          {formatTokenCount(usage.tokens_remaining)} remaining
        </span>
        <span className="text-[var(--text-subtle)]">
          {usage.runs_used} run{usage.runs_used === 1 ? "" : "s"} this period
        </span>
      </div>

      {(nearLimit || overLimit) && (
        <p
          className={`mt-3 flex items-start gap-1.5 rounded-lg border px-2.5 py-2 text-[11px] ${
            overLimit
              ? "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-300"
              : "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-300"
          }`}
        >
          <AlertTriangle size={12} className="mt-0.5 shrink-0" />
          {overLimit
            ? "Monthly token limit reached — upgrade to keep running agents."
            : "You are close to your monthly token limit."}
        </p>
      )}
    </Card>
  );
}

/* ── 3. Pricing tier cards ───────────────────────────────────────────────── */

function PricingCard({
  plan,
  currentTier,
  onSelect,
  busy,
  demoMode,
}: {
  plan: Plan;
  currentTier: TierId;
  onSelect: (tier: TierId) => void;
  busy: boolean;
  demoMode: boolean;
}) {
  const isCurrent = plan.id === currentTier;
  const isFree = plan.price_usd === 0;
  // A paid tier below the current one is a downgrade — handled in the portal.
  const isDowngrade = !isFree && plan.price_usd < 0;

  return (
    <Card
      className={`relative flex flex-col p-5 transition ${
        isCurrent
          ? "border-[var(--accent)] ring-1 ring-[var(--accent)]"
          : "hover:border-[var(--border-strong)]"
      }`}
    >
      {isCurrent && (
        <span className="absolute -top-2.5 left-5">
          <Badge tone="accent">
            <Check size={11} />
            Current plan
          </Badge>
        </span>
      )}

      <div className="flex items-center gap-2">
        <h3 className="text-sm font-semibold text-[var(--text)]">
          {plan.name}
        </h3>
        {plan.id === "pro" && <Badge tone="info">Popular</Badge>}
      </div>

      <div className="mt-3 flex items-baseline gap-1">
        <span className="text-3xl font-semibold tracking-tight text-[var(--text)]">
          {formatPrice(plan.price_usd)}
        </span>
        <span className="text-xs text-[var(--text-muted)]">/month</span>
      </div>

      <p className="mt-2 text-[11px] leading-relaxed text-[var(--text-muted)]">
        {plan.description}
      </p>

      {/* Headline limits */}
      <dl className="mt-4 grid grid-cols-3 gap-2 text-center">
        <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1.5">
          <dt className="text-[9px] uppercase tracking-wide text-[var(--text-subtle)]">
            Tokens
          </dt>
          <dd className="mt-0.5 text-[11px] font-medium text-[var(--text)]">
            {formatTokenCount(plan.monthly_token_limit)}
          </dd>
        </div>
        <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1.5">
          <dt className="text-[9px] uppercase tracking-wide text-[var(--text-subtle)]">
            Runs
          </dt>
          <dd className="mt-0.5 text-[11px] font-medium text-[var(--text)]">
            {plan.max_concurrent_runs}
          </dd>
        </div>
        <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1.5">
          <dt className="text-[9px] uppercase tracking-wide text-[var(--text-subtle)]">
            Seats
          </dt>
          <dd className="mt-0.5 text-[11px] font-medium text-[var(--text)]">
            {plan.seats}
          </dd>
        </div>
      </dl>

      {/* Feature list */}
      <ul className="mt-4 space-y-1.5">
        {FEATURE_ORDER.map((key) => {
          const on = plan.features[key];
          return (
            <li
              key={key}
              className={`flex items-center gap-2 text-[11px] ${
                on ? "text-[var(--text)]" : "text-[var(--text-subtle)]"
              }`}
            >
              {on ? (
                <Check size={12} className="shrink-0 text-emerald-500" />
              ) : (
                <Minus size={12} className="shrink-0 opacity-50" />
              )}
              {FEATURE_LABELS[key]}
            </li>
          );
        })}
      </ul>

      <div className="mt-auto pt-5">
        {isCurrent ? (
          <button
            type="button"
            disabled
            className="w-full rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2 text-xs font-medium text-[var(--text-muted)]"
          >
            Your current plan
          </button>
        ) : isFree ? (
          <button
            type="button"
            disabled
            className="w-full rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2 text-xs font-medium text-[var(--text-muted)]"
          >
            Included by default
          </button>
        ) : (
          <button
            type="button"
            onClick={() => onSelect(plan.id)}
            disabled={busy}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-brand-500 px-3 py-2 text-xs font-semibold text-white shadow-soft transition hover:opacity-90 disabled:opacity-60"
          >
            {busy ? (
              <Loader2 size={13} className="animate-spin" />
            ) : (
              <ArrowUpRight size={13} />
            )}
            {isDowngrade ? `Switch to ${plan.name}` : `Upgrade to ${plan.name}`}
          </button>
        )}
        {demoMode && !isCurrent && !isFree && (
          <p className="mt-2 text-center text-[10px] text-[var(--text-subtle)]">
            Demo data — no real charge
          </p>
        )}
      </div>
    </Card>
  );
}

/* ── 4. Feature comparison ───────────────────────────────────────────────── */

function FeatureComparison({
  plans,
  currentTier,
  loading,
}: {
  plans: Plan[];
  currentTier: TierId;
  loading: boolean;
}) {
  if (loading || plans.length === 0) {
    return (
      <Card className="p-5">
        <Skeleton className="h-5 w-40" />
        <Skeleton className="mt-4 h-40 w-full" />
      </Card>
    );
  }

  const rows: { label: string; value: (p: Plan) => string }[] = [
    { label: "Monthly tokens", value: (p) => formatTokenCount(p.monthly_token_limit) },
    { label: "Concurrent runs", value: (p) => String(p.max_concurrent_runs) },
    { label: "Seats", value: (p) => String(p.seats) },
  ];

  return (
    <Card className="overflow-hidden">
      <div className="flex items-center gap-2 border-b border-[var(--border)] p-5">
        <span className="grid h-8 w-8 place-items-center rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
          <ShieldCheck size={16} />
        </span>
        <div>
          <h2 className="text-sm font-semibold text-[var(--text)]">
            Feature comparison
          </h2>
          <p className="text-[11px] text-[var(--text-muted)]">
            What each tier enables
          </p>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[520px] text-left text-xs">
          <thead>
            <tr className="border-b border-[var(--border)] text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
              <th className="px-5 py-2.5 font-medium">Capability</th>
              {plans.map((p) => (
                <th key={p.id} className="px-4 py-2.5 text-center font-medium">
                  <span
                    className={
                      p.id === currentTier
                        ? "text-[var(--accent)]"
                        : "text-[var(--text-subtle)]"
                    }
                  >
                    {p.name}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {rows.map((row) => (
              <tr key={row.label} className="transition hover:bg-[var(--panel-2)]">
                <td className="px-5 py-2.5 text-[var(--text-muted)]">
                  {row.label}
                </td>
                {plans.map((p) => (
                  <td
                    key={p.id}
                    className="px-4 py-2.5 text-center font-medium text-[var(--text)]"
                  >
                    {row.value(p)}
                  </td>
                ))}
              </tr>
            ))}
            {FEATURE_ORDER.map((key) => (
              <tr key={key} className="transition hover:bg-[var(--panel-2)]">
                <td className="px-5 py-2.5 text-[var(--text-muted)]">
                  {FEATURE_LABELS[key]}
                </td>
                {plans.map((p) => (
                  <td key={p.id} className="px-4 py-2.5 text-center">
                    {p.features[key] ? (
                      <Check
                        size={14}
                        className="mx-auto text-emerald-500"
                        aria-label="Included"
                      />
                    ) : (
                      <Minus
                        size={14}
                        className="mx-auto text-[var(--text-subtle)] opacity-50"
                        aria-label="Not included"
                      />
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

/* ── 5. Billing history ──────────────────────────────────────────────────── */

function InvoiceHistory({
  invoices,
  loading,
  demoMode,
}: {
  invoices: Invoice[];
  loading: boolean;
  demoMode: boolean;
}) {
  if (loading) {
    return (
      <Card className="p-5">
        <Skeleton className="h-5 w-36" />
        <Skeleton className="mt-4 h-10 w-full" />
        <Skeleton className="mt-2 h-10 w-full" />
      </Card>
    );
  }

  return (
    <Card className="overflow-hidden">
      <div className="flex items-center gap-2 border-b border-[var(--border)] p-5">
        <span className="grid h-8 w-8 place-items-center rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
          <Receipt size={16} />
        </span>
        <div>
          <h2 className="text-sm font-semibold text-[var(--text)]">
            Billing history
          </h2>
          <p className="text-[11px] text-[var(--text-muted)]">
            {demoMode
              ? "Sample invoices (demo mode)"
              : "Approved payments appear here after admin verification"}
          </p>
        </div>
      </div>

      {invoices.length === 0 ? (
        <EmptyState
          icon={<Receipt size={18} />}
          title="No invoices yet"
          hint="Once your payment is verified and your plan is active, it will appear here."
        />
      ) : (
        <ul className="divide-y divide-[var(--border)]">
          {invoices.map((inv) => (
            <li
              key={inv.id}
              className="flex items-center justify-between gap-3 px-5 py-3 transition hover:bg-[var(--panel-2)]"
            >
              <div className="min-w-0">
                <p className="truncate text-xs font-medium text-[var(--text)]">
                  {inv.description}
                </p>
                <p className="truncate font-mono text-[10px] text-[var(--text-subtle)]">
                  {inv.id} · {formatDate(inv.date)}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-3">
                <Badge
                  tone={
                    inv.status === "paid"
                      ? "success"
                      : inv.status === "open"
                        ? "warning"
                        : "danger"
                  }
                >
                  {inv.status}
                </Badge>
                <span className="text-xs font-medium text-[var(--text)]">
                  {formatPrice(inv.amount_usd)}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/* ── Page ────────────────────────────────────────────────────────────────── */

export default function BillingPage() {
  const { mode, mounted, setMode } = useTheme();
  const [active] = useState<NavKey>("billing");
  const [collapsed, setCollapsed] = useState(false);

  const [plans, setPlans] = useState<PlansResponse | null>(null);
  const [subscription, setSubscription] = useState<SubscriptionResponse | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [demoMode, setDemoMode] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const [payTier, setPayTier] = useState<TierId>("pro");
  const [busyTier, setBusyTier] = useState<TierId | null>(null);
  const [managing, setManaging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    try {
      // Both calls are independent, so fetch them together.
      const [plansRes, subRes] = await Promise.all([
        api.getPlans(),
        api.getSubscription(),
      ]);
      setPlans(plansRes);
      setSubscription(subRes);
      setDemoMode(false);
    } catch (err) {
      // Any API failure (unreachable, 500, timeout) falls back to the demo set
      // so the page is never blank. The badge tells the user which mode it is.
      if (err instanceof ApiError) {
        setPlans(DEMO_PLANS_RESPONSE);
        setSubscription(DEMO_SUBSCRIPTION);
        setDemoMode(true);
      } else {
        setPlans(DEMO_PLANS_RESPONSE);
        setSubscription(DEMO_SUBSCRIPTION);
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

  const currentTier: TierId = subscription?.subscription.tier ?? "free";

  const invoices = useMemo<Invoice[]>(
    () => (demoMode ? DEMO_INVOICES : []),
    [demoMode],
  );

  /** Pick a paid tier and jump to the manual payment form. */
  const handleUpgrade = useCallback(async (tier: TierId) => {
    setPayTier(tier);
    setError(null);
    setNotice(null);
    if (typeof document !== "undefined") {
      document.getElementById("pay")?.scrollIntoView({ behavior: "smooth" });
    }
  }, []);

  /** Re-read the plan after an admin may have approved a payment. */
  const handleManage = useCallback(async () => {
    setManaging(true);
    setError(null);
    try {
      await load();
      setNotice("Status refreshed.");
    } finally {
      setManaging(false);
    }
  }, [load]);

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
              Billing
            </h1>
            <p className="truncate text-[11px] text-[var(--text-muted)]">
              Plans, usage and invoices
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
              title="Refresh billing"
              aria-label="Refresh billing"
              className="grid h-8 w-8 place-items-center rounded-lg border border-[var(--border)] text-[var(--text-muted)] transition hover:text-[var(--text)]"
            >
              <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} />
            </button>

            <ThemeToggle mode={mode} mounted={mounted} onSelect={setMode} />
          </div>
        </header>

        {/* Body */}
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1180px] space-y-4 p-5">
            {/* Checkout outcome / errors */}
            {notice && (
              <div className="flex items-start gap-2 rounded-xl border border-[var(--border)] bg-[var(--panel)] px-3.5 py-2.5 text-xs text-[var(--text-muted)]">
                <Info size={14} className="mt-0.5 shrink-0 text-[var(--accent)]" />
                <span className="flex-1">{notice}</span>
                <button
                  type="button"
                  onClick={() => setNotice(null)}
                  className="text-[var(--text-subtle)] transition hover:text-[var(--text)]"
                  aria-label="Dismiss"
                >
                  ×
                </button>
              </div>
            )}

            {error && (
              <div className="flex items-start gap-2 rounded-xl border border-red-500/30 bg-red-500/10 px-3.5 py-2.5 text-xs text-red-600 dark:text-red-300">
                <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                <span className="flex-1">{error}</span>
                <button
                  type="button"
                  onClick={() => setError(null)}
                  className="opacity-70 transition hover:opacity-100"
                  aria-label="Dismiss"
                >
                  ×
                </button>
              </div>
            )}

            {!loading && plans && !plans.payoneer_configured && (
              <div className="flex items-start gap-2 rounded-xl border border-[var(--border)] bg-[var(--panel)] px-3.5 py-2.5 text-[11px] text-[var(--text-muted)]">
                <Info size={13} className="mt-0.5 shrink-0 text-[var(--accent)]" />
                Payoneer details are not configured on this deployment. Set{" "}
                <code className="rounded bg-[var(--panel-2)] px-1 py-0.5 text-[10px]">
                  PAYONEER_EMAIL
                </code>{" "}
                on the backend.
              </div>
            )}

            {/* Current plan + usage */}
            <div className="grid gap-4 lg:grid-cols-2">
              <CurrentPlanCard
                data={subscription}
                loading={loading}
                onManage={handleManage}
                managing={managing}
                demoMode={demoMode}
              />
              <TokenUsageCard
                usage={subscription?.usage ?? null}
                loading={loading}
              />
            </div>

            {/* Pricing tiers */}
            <div>
              <div className="mb-3 flex items-center gap-2">
                <Sparkles size={14} className="text-[var(--accent)]" />
                <h2 className="text-sm font-semibold text-[var(--text)]">
                  Plans
                </h2>
                <span className="text-[11px] text-[var(--text-muted)]">
                  Upgrade or switch at any time
                </span>
              </div>

              {loading || !plans ? (
                <div className="grid gap-4 md:grid-cols-3">
                  {[0, 1, 2].map((i) => (
                    <Card key={i} className="p-5">
                      <Skeleton className="h-5 w-20" />
                      <Skeleton className="mt-4 h-9 w-24" />
                      <Skeleton className="mt-4 h-16 w-full" />
                      <Skeleton className="mt-4 h-9 w-full" />
                    </Card>
                  ))}
                </div>
              ) : (
                <div className="grid gap-4 md:grid-cols-3">
                  {plans.plans.map((plan) => (
                    <PricingCard
                      key={plan.id}
                      plan={plan}
                      currentTier={currentTier}
                      onSelect={handleUpgrade}
                      busy={busyTier === plan.id}
                      demoMode={demoMode}
                    />
                  ))}
                </div>
              )}
            </div>

            <ManualPayment
              tier={payTier}
              onTierChange={setPayTier}
              onSubmitted={() => void load()}
            />

            <FeatureComparison
              plans={plans?.plans ?? []}
              currentTier={currentTier}
              loading={loading}
            />

            <InvoiceHistory
              invoices={invoices}
              loading={loading}
              demoMode={demoMode}
            />

            <p className="flex items-center justify-center gap-1.5 pb-2 text-center text-[10px] text-[var(--text-subtle)]">
              <Users size={11} />
              {subscription
                ? `Source: GET /v1/billing/plans + /v1/billing/subscription · ${subscription.subscription.tier_name} tier`
                : "Loading billing…"}
            </p>
          </div>
        </main>
      </div>
    </div>
  );
}
