"use client";

/**
 * AQL-1 — Admin: verify manual payments.
 *
 * The admin pastes the ADMIN_TOKEN (kept only in sessionStorage for this tab),
 * reviews pending submissions with their screenshot, and approves or rejects.
 * Approving activates the user's plan on the backend.
 */

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";

import api, { ApiError, type PaymentRecord, type PaymentStatus } from "@/lib/api";

const TOKEN_KEY = "aql1_admin_token";
const FILTERS: PaymentStatus[] = ["pending", "approved", "rejected"];

export default function AdminPaymentsPage() {
  const [token, setToken] = useState("");
  const [authed, setAuthed] = useState(false);
  const [filter, setFilter] = useState<PaymentStatus>("pending");
  const [rows, setRows] = useState<PaymentRecord[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (t: string, f: PaymentStatus) => {
      setError(null);
      try {
        setRows((await api.adminListPayments(t, f)).payments);
        setAuthed(true);
        sessionStorage.setItem(TOKEN_KEY, t);
      } catch (err) {
        setAuthed(false);
        setError(
          err instanceof ApiError
            ? err.status === 403
              ? "Wrong admin token."
              : err.status === 503
                ? "ADMIN_TOKEN is not set on the backend."
                : err.message
            : "Could not load payments.",
        );
      }
    },
    [],
  );

  useEffect(() => {
    const saved = sessionStorage.getItem(TOKEN_KEY);
    if (saved) {
      setToken(saved);
      void load(saved, "pending");
    }
  }, [load]);

  async function decide(id: string, action: "approve" | "reject") {
    const note =
      action === "reject" ? window.prompt("Reason for rejection (optional)") ?? "" : "";
    setBusyId(id);
    setError(null);
    try {
      await api.adminDecidePayment(token, id, action, note);
      await load(token, filter);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Action failed.");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <main className="mx-auto max-w-5xl space-y-5 p-6 text-[var(--text)]">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Payment verifications</h1>
          <p className="text-xs text-[var(--text-muted)]">
            Confirm the money arrived in Payoneer / your bank, then approve.
          </p>
        </div>
        <Link href="/dashboard/billing" className="text-xs underline">
          Back to billing
        </Link>
      </header>

      {!authed && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void load(token, filter);
          }}
          className="flex gap-2"
        >
          <input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Admin token"
            className="flex-1 rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2 text-sm"
          />
          <button className="rounded-xl bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white">
            Unlock
          </button>
        </form>
      )}

      {error && <p className="text-sm text-red-600">{error}</p>}

      {authed && (
        <>
          <div className="flex gap-2">
            {FILTERS.map((f) => (
              <button
                key={f}
                onClick={() => {
                  setFilter(f);
                  void load(token, f);
                }}
                className={`rounded-full border px-3 py-1 text-xs ${
                  f === filter
                    ? "border-[var(--accent)] text-[var(--accent)]"
                    : "border-[var(--border)] text-[var(--text-muted)]"
                }`}
              >
                {f}
              </button>
            ))}
          </div>

          {rows.length === 0 ? (
            <p className="text-sm text-[var(--text-muted)]">Nothing {filter}.</p>
          ) : (
            <ul className="space-y-3">
              {rows.map((p) => (
                <li
                  key={p.id}
                  className="rounded-2xl border border-[var(--border)] bg-[var(--panel)] p-4 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="space-y-0.5">
                      <div className="text-sm font-medium">
                        {p.tier.toUpperCase()} · ${p.amount_usd} · {p.method}
                      </div>
                      <div>
                        Reference: <span className="select-all font-mono">{p.reference}</span>
                      </div>
                      <div className="text-[var(--text-muted)]">
                        {p.email || p.user_id}
                        {p.sender_name ? ` · from ${p.sender_name}` : ""} ·{" "}
                        {new Date(p.created_at).toLocaleString()}
                      </div>
                      {p.note && <div>Note: {p.note}</div>}
                    </div>
                    <div className="flex items-center gap-2">
                      {p.screenshot_url ? (
                        <a
                          href={p.screenshot_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="underline"
                        >
                          View screenshot
                        </a>
                      ) : (
                        <span className="text-[var(--text-subtle)]">no screenshot</span>
                      )}
                      {p.status === "pending" && (
                        <>
                          <button
                            disabled={busyId === p.id}
                            onClick={() => void decide(p.id, "approve")}
                            className="rounded-lg bg-emerald-600 px-3 py-1.5 font-medium text-white disabled:opacity-60"
                          >
                            Approve
                          </button>
                          <button
                            disabled={busyId === p.id}
                            onClick={() => void decide(p.id, "reject")}
                            className="rounded-lg bg-red-600 px-3 py-1.5 font-medium text-white disabled:opacity-60"
                          >
                            Reject
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </main>
  );
}
