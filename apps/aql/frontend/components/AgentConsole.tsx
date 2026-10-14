"use client";

import { useState } from "react";
import { api, AgentRun } from "@/lib/api";

export default function AgentConsole() {
  const [task, setTask] = useState("Summarize the latest AI agent news");
  const [run, setRun] = useState<AgentRun | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleRun() {
    setLoading(true);
    setError(null);
    try {
      const result = await api.run(task);
      setRun(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-[var(--panel)] p-6 shadow-xl">
      <label className="mb-2 block text-sm font-medium text-[var(--muted)]">
        Task
      </label>
      <textarea
        value={task}
        onChange={(e) => setTask(e.target.value)}
        rows={3}
        className="w-full resize-none rounded-xl border border-white/10 bg-black/30 p-3 text-sm outline-none focus:border-brand-500"
      />

      <button
        onClick={handleRun}
        disabled={loading || !task.trim()}
        className="mt-4 w-full rounded-xl bg-brand-500 px-4 py-3 font-semibold text-white transition hover:bg-brand-600 disabled:opacity-50"
      >
        {loading ? "Running agent…" : "Run agent"}
      </button>

      {error && (
        <p className="mt-4 rounded-lg bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </p>
      )}

      {run && (
        <div className="mt-6 space-y-4">
          <div className="flex flex-wrap gap-2 text-xs">
            <span className="rounded-full bg-brand-500/20 px-3 py-1 text-brand-100">
              {run.route.provider} · {run.route.model}
            </span>
            <span className="rounded-full bg-white/10 px-3 py-1">
              tier: {run.route.tier}
            </span>
            <span className="rounded-full bg-white/10 px-3 py-1">
              {run.duration_ms} ms
            </span>
            <span className="rounded-full bg-emerald-500/20 px-3 py-1 text-emerald-200">
              {run.status}
            </span>
          </div>

          <div className="rounded-xl border border-white/10 bg-black/20 p-4">
            <p className="mb-1 text-xs uppercase tracking-wide text-[var(--muted)]">
              Answer
            </p>
            <p className="text-sm leading-relaxed">{run.answer}</p>
          </div>

          <div className="rounded-xl border border-white/10 bg-black/20 p-4">
            <p className="mb-2 text-xs uppercase tracking-wide text-[var(--muted)]">
              Steps ({run.steps.length})
            </p>
            <ol className="space-y-2 text-sm">
              {run.steps.map((s) => (
                <li key={s.index} className="text-[var(--muted)]">
                  <span className="text-white">#{s.index}</span> {s.thought}
                </li>
              ))}
            </ol>
          </div>
        </div>
      )}
    </div>
  );
}
