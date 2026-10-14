"use client";

/**
 * Small, reusable UI primitives for the AQL-1 dashboard.
 *
 * Everything reads the CSS custom properties defined in `globals.css`, so a
 * single `dark` class on <html> re-themes the whole app.
 */

import { useEffect, useState, type ReactNode } from "react";
import { Monitor, Moon, Sun } from "lucide-react";

/* ── Theme ──────────────────────────────────────────────────────────────── */

export type ThemeMode = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

const THEME_KEY = "aql1-theme";

function readStoredMode(): ThemeMode {
  if (typeof window === "undefined") return "system";
  const stored = window.localStorage.getItem(THEME_KEY);
  return stored === "light" || stored === "dark" || stored === "system"
    ? stored
    : "system";
}

/**
 * Theme state: persists the user's choice in localStorage and, in "system"
 * mode, follows the OS `prefers-color-scheme` setting live.
 */
export function useTheme() {
  const [mode, setMode] = useState<ThemeMode>(readStoredMode);
  const [resolved, setResolved] = useState<ResolvedTheme>("dark");
  const [mounted, setMounted] = useState(false);

  // `mounted` gates the toggle's active state so SSR and client markup match.
  useEffect(() => setMounted(true), []);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      const next: ResolvedTheme =
        mode === "system" ? (mq.matches ? "dark" : "light") : mode;
      setResolved(next);
      document.documentElement.classList.toggle("dark", next === "dark");
    };
    apply();
    window.localStorage.setItem(THEME_KEY, mode);
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, [mode]);

  return { mode, resolved, mounted, setMode };
}

const THEME_OPTIONS: { value: ThemeMode; label: string; Icon: typeof Sun }[] = [
  { value: "light", label: "Light", Icon: Sun },
  { value: "dark", label: "Dark", Icon: Moon },
  { value: "system", label: "System", Icon: Monitor },
];

/** Compact 3-way segmented control: Light / Dark / System. */
export function ThemeToggle({
  mode,
  mounted,
  onSelect,
}: {
  mode: ThemeMode;
  mounted: boolean;
  onSelect: (mode: ThemeMode) => void;
}) {
  return (
    <div
      role="group"
      aria-label="Color theme"
      className="flex items-center gap-0.5 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] p-0.5"
    >
      {THEME_OPTIONS.map(({ value, label, Icon }) => {
        const active = mounted && mode === value;
        return (
          <button
            key={value}
            type="button"
            title={label}
            aria-label={label}
            aria-pressed={active}
            onClick={() => onSelect(value)}
            className={`grid h-7 w-7 place-items-center rounded-md transition ${
              active
                ? "bg-[var(--panel)] text-[var(--accent)] shadow-soft"
                : "text-[var(--text-subtle)] hover:text-[var(--text)]"
            }`}
          >
            <Icon size={14} strokeWidth={2} />
          </button>
        );
      })}
    </div>
  );
}

/* ── Primitives ─────────────────────────────────────────────────────────── */

export function Card({
  className = "",
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  return (
    <div
      className={`rounded-2xl border border-[var(--border)] bg-[var(--panel)] shadow-soft ${className}`}
    >
      {children}
    </div>
  );
}

export type Tone =
  | "neutral"
  | "accent"
  | "success"
  | "warning"
  | "danger"
  | "info";

const TONE_CLASSES: Record<Tone, string> = {
  neutral:
    "bg-[var(--panel-2)] text-[var(--text-muted)] border-[var(--border)]",
  accent: "bg-[var(--accent-soft)] text-[var(--accent)] border-transparent",
  success:
    "bg-emerald-500/10 text-emerald-600 dark:text-emerald-300 border-transparent",
  warning:
    "bg-amber-500/10 text-amber-600 dark:text-amber-300 border-transparent",
  danger: "bg-red-500/10 text-red-600 dark:text-red-300 border-transparent",
  info: "bg-sky-500/10 text-sky-600 dark:text-sky-300 border-transparent",
};

export function Badge({
  tone = "neutral",
  className = "",
  children,
}: {
  tone?: Tone;
  className?: string;
  children: ReactNode;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium leading-5 ${TONE_CLASSES[tone]} ${className}`}
    >
      {children}
    </span>
  );
}

/** Maps a risk level to a badge tone. */
export function riskTone(level: string): Tone {
  if (level === "high") return "danger";
  if (level === "medium") return "warning";
  return "success";
}

export function StatusDot({
  tone = "neutral",
  pulse = false,
}: {
  tone?: Tone;
  pulse?: boolean;
}) {
  const color: Record<Tone, string> = {
    neutral: "bg-[var(--text-subtle)]",
    accent: "bg-[var(--accent)]",
    success: "bg-emerald-500",
    warning: "bg-amber-500",
    danger: "bg-red-500",
    info: "bg-sky-500",
  };
  return (
    <span
      className={`inline-block h-2 w-2 shrink-0 rounded-full ${color[tone]} ${
        pulse ? "animate-pulse-ring" : ""
      }`}
    />
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton rounded-md ${className}`} />;
}

export function EmptyState({
  icon,
  title,
  hint,
}: {
  icon: ReactNode;
  title: string;
  hint: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <div className="grid h-11 w-11 place-items-center rounded-xl border border-[var(--border)] bg-[var(--panel-2)] text-[var(--text-subtle)]">
        {icon}
      </div>
      <p className="text-sm font-medium text-[var(--text)]">{title}</p>
      <p className="max-w-xs text-xs text-[var(--text-muted)]">{hint}</p>
    </div>
  );
}

/** Formats a USD amount with enough precision for sub-cent agent costs. */
export function formatUsd(value: number): string {
  if (!Number.isFinite(value)) return "$0.00";
  if (value === 0) return "$0.00";
  if (value < 0.01) return `$${value.toFixed(6)}`;
  return `$${value.toFixed(4)}`;
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "0ms";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

export function formatTokens(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0";
  if (n < 1000) return `${Math.round(n)}`;
  return `${(n / 1000).toFixed(1)}k`;
}
