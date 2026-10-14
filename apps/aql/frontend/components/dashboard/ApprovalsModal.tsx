"use client";

/**
 * Pending Approvals modal — the human-in-the-loop surface.
 *
 * Lists paused runs from `GET /agent/approvals`, shows the action type, risk
 * level, reasons and payload, and lets a human Approve or Reject via
 * `POST /agent/approve` with an optional note. Falls back to demo data when the
 * backend is unreachable so the flow stays demonstrable.
 */

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Check,
  ChevronRight,
  Loader2,
  ShieldAlert,
  X,
} from "lucide-react";

import { api, ApiError, type PendingApproval } from "@/lib/api";
import { Badge, EmptyState, Skeleton, StatusDot, riskTone } from "./ui";

/** Pretty-prints a payload object for the detail view. */
function PayloadView({ payload }: { payload: Record<string, unknown> }) {
  const entries = Object.entries(payload);
  if (entries.length === 0) {
    return (
      <p className="text-xs text-[var(--text-subtle)]">No payload provided.</p>
    );
  }
  return (
    <dl className="space-y-1.5">
      {entries.map(([key, value]) => (
        <div key={key} className="flex gap-3 text-xs">
          <dt className="w-24 shrink-0 font-mono text-[var(--text-subtle)]">
            {key}
          </dt>
          <dd className="min-w-0 flex-1 break-words text-[var(--text-muted)]">
            {typeof value === "string" ? value : JSON.stringify(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function ApprovalRow({
  approval,
  selected,
  onSelect,
}: {
  approval: PendingApproval;
  selected: boolean;
  onSelect: () => void;
}) {
  const tone = riskTone(approval.risk.risk_level);
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`flex w-full items-center gap-3 rounded-xl border px-3 py-2.5 text-left transition ${
        selected
          ? "border-[var(--accent)] bg-[var(--accent-soft)]"
          : "border-[var(--border)] bg-[var(--panel-2)] hover:border-[var(--border-strong)]"
      }`}
    >
      <StatusDot tone={tone} pulse={approval.status === "pending"} />
      <span className="min-w-0 flex-1">
        <span className="block truncate font-mono text-xs font-medium text-[var(--text)]">
          {approval.action_type}
        </span>
        <span className="block truncate text-[11px] text-[var(--text-subtle)]">
          {approval.kind} · {approval.run_id}
        </span>
      </span>
      <Badge tone={tone}>{approval.risk.risk_level}</Badge>
      <ChevronRight size={14} className="shrink-0 text-[var(--text-subtle)]" />
    </button>
  );
}

export default function ApprovalsModal({
  open,
  onClose,
  approvals,
  loading,
  isDemo,
  onDecided,
}: {
  open: boolean;
  onClose: () => void;
  approvals: PendingApproval[];
  loading: boolean;
  isDemo: boolean;
  onDecided: () => void;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [approver, setApprover] = useState("");
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  // Keep a valid selection as the list changes.
  useEffect(() => {
    if (approvals.length === 0) {
      setSelectedId(null);
      return;
    }
    if (!selectedId || !approvals.some((a) => a.approval_id === selectedId)) {
      setSelectedId(approvals[0].approval_id);
    }
  }, [approvals, selectedId]);

  // Reset transient state whenever the modal is reopened.
  useEffect(() => {
    if (open) {
      setNote("");
      setError(null);
      setDone(null);
    }
  }, [open]);

  // Close on Escape.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const selected = approvals.find((a) => a.approval_id === selectedId) ?? null;

  async function decide(decision: "approve" | "reject") {
    if (!selected) return;
    setBusy(decision);
    setError(null);
    try {
      if (isDemo) {
        // Demo mode: simulate the webhook round-trip.
        await new Promise((r) => setTimeout(r, 500));
      } else {
        await api.approve(selected.approval_id, decision, {
          approver: approver.trim() || undefined,
          note: note.trim(),
        });
      }
      setDone(
        decision === "approve"
          ? `Approved — run ${selected.run_id} resumed.`
          : `Rejected — run ${selected.run_id} marked rejected.`,
      );
      setNote("");
      onDecided();
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Could not submit the decision.",
      );
    } finally {
      setBusy(null);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Pending approvals"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm"
        onClick={onClose}
      />

      <div className="relative flex max-h-[86vh] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--panel)] shadow-card animate-fade-in">
        {/* Header */}
        <div className="flex items-center gap-3 border-b border-[var(--border)] px-5 py-4">
          <span className="grid h-9 w-9 place-items-center rounded-xl bg-amber-500/10 text-amber-500">
            <ShieldAlert size={18} strokeWidth={2} />
          </span>
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">
              Pending approvals
            </h2>
            <p className="text-[11px] text-[var(--text-subtle)]">
              High-risk actions paused for human review
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="ml-auto grid h-8 w-8 place-items-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--panel-2)] hover:text-[var(--text)]"
          >
            <X size={16} />
          </button>
        </div>

        <div className="grid min-h-0 flex-1 grid-cols-1 md:grid-cols-[minmax(0,260px)_1fr]">
          {/* List */}
          <div className="scroll-thin min-h-0 overflow-y-auto border-b border-[var(--border)] p-3 md:border-b-0 md:border-r">
            {loading && approvals.length === 0 ? (
              <div className="space-y-2">
                {[0, 1].map((i) => (
                  <Skeleton key={i} className="h-14 w-full rounded-xl" />
                ))}
              </div>
            ) : approvals.length === 0 ? (
              <EmptyState
                icon={<Check size={18} />}
                title="All clear"
                hint="No actions are waiting for approval right now."
              />
            ) : (
              <div className="space-y-2">
                {approvals.map((a) => (
                  <ApprovalRow
                    key={a.approval_id}
                    approval={a}
                    selected={a.approval_id === selectedId}
                    onSelect={() => {
                      setSelectedId(a.approval_id);
                      setDone(null);
                      setError(null);
                    }}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Detail */}
          <div className="scroll-thin min-h-0 overflow-y-auto p-5">
            {!selected ? (
              <EmptyState
                icon={<ShieldAlert size={18} />}
                title="Nothing selected"
                hint="Pick an approval on the left to review its risk and payload."
              />
            ) : (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-2">
                  <code className="rounded-lg bg-[var(--panel-2)] px-2 py-1 font-mono text-xs text-[var(--text)]">
                    {selected.action_type}
                  </code>
                  <Badge tone={riskTone(selected.risk.risk_level)}>
                    {selected.risk.risk_level} risk
                  </Badge>
                  <Badge tone="neutral">{selected.kind}</Badge>
                  {selected.risk.requires_approval && (
                    <Badge tone="warning">approval required</Badge>
                  )}
                </div>

                {/* Reasons */}
                <section>
                  <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-[var(--text-subtle)]">
                    Why it was flagged
                  </h3>
                  <ul className="space-y-1">
                    {selected.risk.reasons.map((reason) => (
                      <li
                        key={reason}
                        className="flex gap-2 text-xs text-[var(--text-muted)]"
                      >
                        <AlertTriangle
                          size={12}
                          className="mt-0.5 shrink-0 text-amber-500"
                        />
                        {reason}
                      </li>
                    ))}
                  </ul>
                  {selected.risk.matched_rules.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {selected.risk.matched_rules.map((rule) => (
                        <code
                          key={rule}
                          className="rounded bg-[var(--panel-2)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-subtle)]"
                        >
                          {rule}
                        </code>
                      ))}
                    </div>
                  )}
                </section>

                {/* Payload */}
                <section>
                  <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-[var(--text-subtle)]">
                    Payload
                  </h3>
                  <div className="rounded-xl border border-[var(--border)] bg-[var(--panel-2)] p-3">
                    <PayloadView payload={selected.payload} />
                  </div>
                </section>

                {/* Decision form */}
                <section className="space-y-2.5">
                  <h3 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-subtle)]">
                    Decision
                  </h3>
                  <input
                    value={approver}
                    onChange={(e) => setApprover(e.target.value)}
                    placeholder="Approver (optional)"
                    aria-label="Approver"
                    className="w-full rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2 text-sm text-[var(--text)] outline-none transition placeholder:text-[var(--text-subtle)] focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent)]/20"
                  />
                  <textarea
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    rows={2}
                    placeholder="Note (optional) — e.g. why you approved or rejected"
                    aria-label="Approver note"
                    className="w-full resize-none rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2 text-sm text-[var(--text)] outline-none transition placeholder:text-[var(--text-subtle)] focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent)]/20"
                  />

                  {error && (
                    <p className="flex items-center gap-1.5 text-xs text-red-500">
                      <AlertTriangle size={12} />
                      {error}
                    </p>
                  )}
                  {done && (
                    <p className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-300">
                      <Check size={12} />
                      {done}
                    </p>
                  )}

                  <div className="flex items-center gap-2 pt-1">
                    <button
                      type="button"
                      disabled={busy !== null}
                      onClick={() => decide("approve")}
                      className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-soft transition hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {busy === "approve" ? (
                        <Loader2 size={15} className="animate-spin" />
                      ) : (
                        <Check size={15} strokeWidth={2.5} />
                      )}
                      Approve &amp; resume
                    </button>
                    <button
                      type="button"
                      disabled={busy !== null}
                      onClick={() => decide("reject")}
                      className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-sm font-semibold text-red-600 transition hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-50 dark:text-red-300"
                    >
                      {busy === "reject" ? (
                        <Loader2 size={15} className="animate-spin" />
                      ) : (
                        <X size={15} strokeWidth={2.5} />
                      )}
                      Reject
                    </button>
                  </div>
                </section>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
