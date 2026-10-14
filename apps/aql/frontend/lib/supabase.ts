/**
 * Supabase browser client (auth only). The anon key is public by design; row
 * access is enforced by RLS and by the FastAPI backend, which verifies the
 * session JWT on every billing call.
 */
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

const URL = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
const ANON = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "";

let client: SupabaseClient | null = null;

/** The shared client, or `null` when Supabase env vars are not set. */
export function getSupabase(): SupabaseClient | null {
  if (!URL || !ANON) return null;
  if (!client) client = createClient(URL, ANON);
  return client;
}

/** Current session access token ("" when signed out / unconfigured). */
export async function getAccessToken(): Promise<string> {
  const sb = getSupabase();
  if (!sb) return "";
  const { data } = await sb.auth.getSession();
  return data.session?.access_token ?? "";
}
