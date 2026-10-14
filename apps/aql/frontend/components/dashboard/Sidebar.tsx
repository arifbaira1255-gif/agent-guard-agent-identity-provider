"use client";

/**
 * Collapsible dashboard sidebar.
 *
 * In compact mode only the icons remain; the labels collapse away and each
 * item keeps a tooltip so the nav stays usable.
 */

import {
  Activity,
  BarChart3,
  Bot,
  CreditCard,
  PanelLeft,
  PanelLeftClose,
  Settings,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react";
import Link from "next/link";

import { Badge } from "./ui";

export type NavKey =
  | "agents"
  | "runs"
  | "observability"
  | "billing"
  | "settings";

export interface NavItem {
  key: NavKey;
  label: string;
  hint: string;
  Icon: LucideIcon;
  /** When set, the item navigates to its own route instead of switching views. */
  href?: string;
}

export const NAV_ITEMS: NavItem[] = [
  { key: "agents", label: "Agents", hint: "Live execution", Icon: Bot },
  { key: "runs", label: "Runs", hint: "Run history", Icon: Activity },
  {
    key: "observability",
    label: "Observability",
    hint: "Traces & cost",
    Icon: BarChart3,
    href: "/dashboard/observability",
  },
  {
    key: "billing",
    label: "Billing",
    hint: "Usage & plans",
    Icon: CreditCard,
    href: "/dashboard/billing",
  },
  { key: "settings", label: "Settings", hint: "Providers & keys", Icon: Settings },
];

export default function Sidebar({
  active,
  onSelect,
  collapsed,
  onToggleCollapsed,
  pendingCount,
  onOpenApprovals,
}: {
  active: NavKey;
  onSelect: (key: NavKey) => void;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  pendingCount: number;
  onOpenApprovals: () => void;
}) {
  return (
    <aside
      className={`flex h-full shrink-0 flex-col border-r border-[var(--border)] bg-[var(--bg-elevated)] transition-[width] duration-200 ${
        collapsed ? "w-[68px]" : "w-[236px]"
      }`}
    >
      {/* Brand */}
      <div className="flex h-16 items-center gap-2.5 px-4">
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-brand-500 text-sm font-bold text-white shadow-soft">
          A1
        </span>
        {!collapsed && (
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-[var(--text)]">
              AQL-1
            </p>
            <p className="truncate text-[11px] text-[var(--text-subtle)]">
              Agent operating layer
            </p>
          </div>
        )}
      </div>

      {/* Primary navigation */}
      <nav className="flex flex-1 flex-col gap-1 px-2.5 py-2">
        {NAV_ITEMS.map(({ key, label, hint, Icon, href }) => {
          const isActive = active === key;

          // Shared inner markup so the Link and button variants stay identical.
          const inner = (
            <>
              <Icon size={18} strokeWidth={2} className="shrink-0" />
              {!collapsed && (
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">
                    {label}
                  </span>
                  <span className="block truncate text-[11px] text-[var(--text-subtle)]">
                    {hint}
                  </span>
                </span>
              )}
              {isActive && !collapsed && (
                <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--accent)]" />
              )}
            </>
          );

          const className = `group flex items-center gap-3 rounded-xl px-2.5 py-2 text-left transition ${
            isActive
              ? "bg-[var(--accent-soft)] text-[var(--accent)]"
              : "text-[var(--text-muted)] hover:bg-[var(--panel-2)] hover:text-[var(--text)]"
          } ${collapsed ? "justify-center" : ""}`;

          // Items with their own route become real links (Observability).
          if (href) {
            return (
              <Link
                key={key}
                href={href}
                title={collapsed ? label : undefined}
                aria-current={isActive ? "page" : undefined}
                className={className}
              >
                {inner}
              </Link>
            );
          }

          return (
            <button
              key={key}
              type="button"
              title={collapsed ? label : undefined}
              aria-current={isActive ? "page" : undefined}
              onClick={() => onSelect(key)}
              className={className}
            >
              {inner}
            </button>
          );
        })}
      </nav>

      {/* Human-in-the-loop approvals entry point */}
      <div className="px-2.5 pb-2">
        <button
          type="button"
          onClick={onOpenApprovals}
          title={collapsed ? "Pending approvals" : undefined}
          className={`flex w-full items-center gap-3 rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-2.5 py-2 text-left transition hover:border-[var(--border-strong)] ${
            collapsed ? "justify-center" : ""
          }`}
        >
          <span className="relative shrink-0">
            <ShieldAlert
              size={18}
              strokeWidth={2}
              className={
                pendingCount > 0
                  ? "text-amber-500"
                  : "text-[var(--text-subtle)]"
              }
            />
            {pendingCount > 0 && (
              <span className="absolute -right-1.5 -top-1.5 grid h-4 min-w-4 place-items-center rounded-full bg-amber-500 px-1 text-[10px] font-bold text-white">
                {pendingCount > 9 ? "9+" : pendingCount}
              </span>
            )}
          </span>
          {!collapsed && (
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm font-medium text-[var(--text)]">
                Approvals
              </span>
              <span className="block truncate text-[11px] text-[var(--text-subtle)]">
                {pendingCount > 0
                  ? `${pendingCount} awaiting review`
                  : "Nothing pending"}
              </span>
            </span>
          )}
          {!collapsed && pendingCount > 0 && (
            <Badge tone="warning">HITL</Badge>
          )}
        </button>
      </div>

      {/* Collapse toggle */}
      <div className="border-t border-[var(--border)] p-2.5">
        <button
          type="button"
          onClick={onToggleCollapsed}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className={`flex w-full items-center gap-3 rounded-xl px-2.5 py-2 text-[var(--text-muted)] transition hover:bg-[var(--panel-2)] hover:text-[var(--text)] ${
            collapsed ? "justify-center" : ""
          }`}
        >
          {collapsed ? (
            <PanelLeft size={18} strokeWidth={2} />
          ) : (
            <PanelLeftClose size={18} strokeWidth={2} />
          )}
          {!collapsed && <span className="text-sm font-medium">Collapse</span>}
        </button>
      </div>
    </aside>
  );
}