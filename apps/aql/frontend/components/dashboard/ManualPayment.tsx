"use client";

/**
 * Manual payment panel: shows the Payoneer email + bank-transfer details, then
 * lets the user submit a transaction ID and screenshot for admin verification.
 */

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { CheckCircle2, Clock, Loader2, Upload, XCircle } from "lucide-react";

import api, {
  ApiError,
  type PaymentInfo,
  type PaymentMethod,
  type PaymentRecord,
  type TierId,
} from "@/lib/api";
import { Badge, Card } from "@/components/dashboard/ui";

const PAYMENT_URL = process.env.NEXT_PUBLIC_PAYONEER_PAYMENT_URL ?? "";

export default function ManualPayment({
  tier,
  onTierChange,
  onSubmitted,
}: {
  tier: TierId;
  onTierChange: (t: TierId) => void;
  onSubmitted?: () => void;
}) {
  const [info, setInfo] = useState<PaymentInfo | null>(null);
  const [mine, setMine] = useState<PaymentRecord[]>([]);
  const [method, setMethod] = useState<PaymentMethod>("payoneer");
  const [reference, setReference] = useState("");
  const [senderName, setSenderName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    try {
      setInfo(await api.getPaymentInfo());
    } catch {
      /* shown as "unavailable" below */
    }
    try {
      setMine((await api.getMyPayments()).payments);
    } catch {
      setMine([]); // signed out or API down — history is optional
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const paid = info?.plans.filter((p) => p.id !== "free") ?? [];
  const price = paid.find((p) => p.id === tier)?.price_usd;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (tier === "free") {
      setMsg({ ok: false, text: "Choose Pro or Team first." });
      return;
    }
    if (!file) {
      setMsg({ ok: false, text: "Attach your payment screenshot." });
      return;
    }
    const form = new FormData();
    form.set("tier", tier);
    form.set("reference", reference.trim());
    form.set("method", method);
    form.set("sender_name", senderName.trim());
    form.set("screenshot", file);
    setBusy(true);
    setMsg(null);
    try {
      await api.submitPayment(form);
      setMsg({
        ok: true,
        text: "Submitted! An admin will verify your payment and activate your plan.",
      });
      setReference("");
      setSenderName("");
      setFile(null);
      await load();
      onSubmitted?.();
    } catch (err) {
      setMsg({
        ok: false,
        text:
          err instanceof ApiError && err.status === 401
            ? "Please sign in first (see the Sign in page)."
            : err instanceof ApiError
              ? err.message
              : "Could not submit. Try again.",
      });
    } finally {
      setBusy(false);
    }
  }

  const input =
    "w-full rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2 text-xs";

  return (
    <div id="pay">
    <Card className="p-5">
      <h2 className="text-sm font-semibold text-[var(--text)]">Pay &amp; upgrade</h2>
      <p className="mt-1 text-[11px] text-[var(--text-muted)]">
        {info?.instructions ?? "Payment details are unavailable right now."}
      </p>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <div className="space-y-3 text-xs">
          <div className="rounded-xl border border-[var(--border)] bg-[var(--panel-2)] p-3">
            <div className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
              Payoneer email
            </div>
            <div className="mt-1 select-all break-all font-medium text-[var(--text)]">
              {info?.payoneer_email || "Not configured yet"}
            </div>
            {PAYMENT_URL && (
              <a
                href={PAYMENT_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-2 inline-block text-[var(--accent)] underline"
              >
                Open Payoneer payment page
              </a>
            )}
          </div>
          <div className="rounded-xl border border-[var(--border)] bg-[var(--panel-2)] p-3">
            <div className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">
              Bank transfer
            </div>
            <pre className="mt-1 whitespace-pre-wrap break-words font-sans text-[var(--text)]">
              {info?.bank_transfer_details || "Bank details not configured yet."}
            </pre>
          </div>
        </div>

        <form onSubmit={onSubmit} className="space-y-2.5 text-xs">
          <select
            value={tier}
            onChange={(e) => onTierChange(e.target.value as TierId)}
            className={input}
            aria-label="Plan"
          >
            <option value="free" disabled>
              Select a plan…
            </option>
            {paid.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} — ${p.price_usd}/month
              </option>
            ))}
          </select>
          <select
            value={method}
            onChange={(e) => setMethod(e.target.value as PaymentMethod)}
            className={input}
            aria-label="Payment method"
          >
            <option value="payoneer">Paid via Payoneer</option>
            <option value="bank_transfer">Paid via bank transfer</option>
          </select>
          <input
            required
            minLength={4}
            maxLength={120}
            value={reference}
            onChange={(e) => setReference(e.target.value)}
            placeholder="Transaction ID / payment reference"
            className={input}
          />
          <input
            value={senderName}
            onChange={(e) => setSenderName(e.target.value)}
            placeholder="Name on the payment (optional)"
            className={input}
          />
          <label className="flex cursor-pointer items-center gap-2 rounded-xl border border-dashed border-[var(--border-strong)] px-3 py-2 text-[var(--text-muted)]">
            <Upload size={13} />
            <span className="truncate">{file ? file.name : "Upload payment screenshot (PNG, JPG, WebP, PDF · max 5 MB)"}</span>
            <input
              type="file"
              accept="image/png,image/jpeg,image/webp,application/pdf"
              className="hidden"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </label>
          <button
            type="submit"
            disabled={busy}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-[var(--accent)] px-3 py-2 font-medium text-white disabled:opacity-60"
          >
            {busy && <Loader2 size={13} className="animate-spin" />}
            Submit payment{price ? ` ($${price})` : ""}
          </button>
          {msg && (
            <p className={msg.ok ? "text-emerald-600" : "text-red-600"}>{msg.text}</p>
          )}
        </form>
      </div>

      {mine.length > 0 && (
        <ul className="mt-5 divide-y divide-[var(--border)] border-t border-[var(--border)] text-xs">
          {mine.map((p) => (
            <li key={p.id} className="flex items-center justify-between gap-3 py-2">
              <span className="truncate">
                {p.tier.toUpperCase()} · {p.reference} ·{" "}
                {new Date(p.created_at).toLocaleDateString()}
              </span>
              <Badge tone={p.status === "approved" ? "success" : p.status === "rejected" ? "danger" : "warning"}>
                {p.status === "approved" ? <CheckCircle2 size={11} /> : p.status === "rejected" ? <XCircle size={11} /> : <Clock size={11} />}
                {" "}{p.status}
              </Badge>
            </li>
          ))}
        </ul>
      )}
    </Card>
    </div>
  );
}
