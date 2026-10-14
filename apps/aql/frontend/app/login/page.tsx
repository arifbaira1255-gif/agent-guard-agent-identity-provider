"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";

import { getSupabase } from "@/lib/supabase";

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    const sb = getSupabase();
    if (!sb) {
      setMessage("Supabase is not configured on this deployment.");
      return;
    }
    setBusy(true);
    setMessage(null);
    const { error } =
      mode === "signin"
        ? await sb.auth.signInWithPassword({ email, password })
        : await sb.auth.signUp({ email, password });
    setBusy(false);
    if (error) {
      setMessage(error.message);
    } else if (mode === "signup") {
      setMessage("Account created. Check your email to confirm, then sign in.");
      setMode("signin");
    } else {
      router.push("/dashboard/billing");
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-[var(--bg)] p-6 text-[var(--text)]">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm space-y-4 rounded-2xl border border-[var(--border)] bg-[var(--panel)] p-6"
      >
        <h1 className="text-lg font-semibold">
          {mode === "signin" ? "Sign in to AQL-1" : "Create your AQL-1 account"}
        </h1>
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@example.com"
          className="w-full rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2 text-sm"
        />
        <input
          type="password"
          required
          minLength={8}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password (8+ characters)"
          className="w-full rounded-xl border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2 text-sm"
        />
        {message && <p className="text-xs text-[var(--text-muted)]">{message}</p>}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-xl bg-[var(--accent)] px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
        >
          {busy ? "Please wait…" : mode === "signin" ? "Sign in" : "Sign up"}
        </button>
        <button
          type="button"
          onClick={() => setMode(mode === "signin" ? "signup" : "signin")}
          className="w-full text-center text-xs text-[var(--text-muted)] underline"
        >
          {mode === "signin" ? "Need an account? Sign up" : "Have an account? Sign in"}
        </button>
      </form>
    </main>
  );
}
