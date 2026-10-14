"use client";

import { useEffect, useState } from "react";
import { api, ToolSchema } from "@/lib/api";
import AgentConsole from "@/components/AgentConsole";

export default function Home() {
  const [online, setOnline] = useState<boolean | null>(null);
  const [tools, setTools] = useState<ToolSchema[]>([]);

  useEffect(() => {
    api
      .health()
      .then(() => setOnline(true))
      .catch(() => setOnline(false));
    api
      .tools()
      .then((r) => setTools(r.tools))
      .catch(() => setTools([]));
  }, []);

  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <header className="mb-10">
        <div className="mb-3 flex items-center gap-3">
          <span className="grid h-10 w-10 place-items-center rounded-xl bg-brand-500 font-bold">
            A1
          </span>
          <h1 className="text-2xl font-bold">AQL-1</h1>
          <span
            className={`ml-auto rounded-full px-3 py-1 text-xs ${
              online === null
                ? "bg-white/10"
                : online
                  ? "bg-emerald-500/20 text-emerald-200"
                  : "bg-red-500/20 text-red-200"
            }`}
          >
            {online === null
              ? "checking…"
              : online
                ? "backend online"
                : "backend offline"}
          </span>
        </div>
        <p className="text-[var(--muted)]">
          Autonomous AI agent operating layer — control plane for planning,
          memory, and tool use.
        </p>
        <a
          href="/dashboard"
          className="mt-4 inline-flex items-center gap-2 rounded-xl bg-brand-500 px-4 py-2 text-sm font-semibold text-white shadow-soft transition hover:bg-brand-600"
        >
          Open dashboard →
        </a>
      </header>

      <AgentConsole />

      <section className="mt-10">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
          Registered tools ({tools.length})
        </h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {tools.map((t) => (
            <div
              key={t.function.name}
              className="rounded-xl border border-white/10 bg-[var(--panel)] p-4"
            >
              <p className="font-mono text-sm text-brand-100">
                {t.function.name}
              </p>
              <p className="mt-1 text-xs text-[var(--muted)]">
                {t.function.description}
              </p>
            </div>
          ))}
          {tools.length === 0 && (
            <p className="text-sm text-[var(--muted)]">
              No tools loaded — is the backend running?
            </p>
          )}
        </div>
      </section>
    </main>
  );
}
