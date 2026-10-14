-- AQL-1 schema: extensions, core tables, manual-payment verification, RLS.
-- The FastAPI backend uses the service-role key (bypasses RLS). RLS below
-- protects direct access with the public anon / user keys.

create extension if not exists vector with schema extensions;
create extension if not exists pgcrypto with schema extensions;

-- ── Users (profile mirror of auth.users) ─────────────────────────────────────
create table if not exists public.users (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.users (id, email) values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ── Billing state (payload jsonb, matches StateManager) ──────────────────────
create table if not exists public.subscriptions (
  user_id text primary key, payload jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now());
create table if not exists public.usage (
  user_id text primary key, payload jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now());

-- ── Manual payments ──────────────────────────────────────────────────────────
create table if not exists public.payment_verifications (
  id text primary key,
  user_id text not null,
  email text not null default '',
  tier text not null check (tier in ('pro','team')),
  amount_usd numeric(10,2) not null default 0,
  method text not null check (method in ('payoneer','bank_transfer')),
  reference text not null,
  sender_name text not null default '',
  screenshot_path text not null default '',
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  note text not null default '',
  reviewer text not null default '',
  created_at timestamptz not null default now(),
  decided_at timestamptz
);
create unique index if not exists payment_verifications_live_ref
  on public.payment_verifications (lower(reference)) where status <> 'rejected';
create index if not exists payment_verifications_status_idx
  on public.payment_verifications (status, created_at desc);

-- ── Agents / tasks / logs / approvals / keys ─────────────────────────────────
create table if not exists public.agents (
  id uuid primary key default gen_random_uuid(),
  user_id text not null, name text not null, config jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now());
create table if not exists public.tasks (
  id uuid primary key default gen_random_uuid(),
  user_id text not null, agent_id uuid references public.agents(id) on delete set null,
  prompt text not null, status text not null default 'queued',
  result jsonb, created_at timestamptz not null default now());
create table if not exists public.logs (
  id uuid primary key default gen_random_uuid(),
  user_id text, task_id uuid, level text not null default 'info',
  message text not null, data jsonb, created_at timestamptz not null default now());
create table if not exists public.pending_approvals (
  approval_id text primary key, payload jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now());
create table if not exists public.api_keys (
  key_hash text primary key, payload jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now());
create table if not exists public.memory_audit (
  id text primary key, payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now());

-- ── pgvector memory (optional Supabase-native store) ─────────────────────────
create table if not exists public.memories (
  id uuid primary key default gen_random_uuid(),
  user_id text not null, content text not null,
  metadata jsonb not null default '{}'::jsonb,
  embedding extensions.vector(1024),
  created_at timestamptz not null default now());
create index if not exists memories_embedding_idx
  on public.memories using hnsw (embedding extensions.vector_cosine_ops);

-- ── Row Level Security ───────────────────────────────────────────────────────
alter table public.users enable row level security;
alter table public.subscriptions enable row level security;
alter table public.usage enable row level security;
alter table public.payment_verifications enable row level security;
alter table public.agents enable row level security;
alter table public.tasks enable row level security;
alter table public.logs enable row level security;
alter table public.pending_approvals enable row level security;
alter table public.api_keys enable row level security;
alter table public.memory_audit enable row level security;
alter table public.memories enable row level security;

create policy "users read own profile" on public.users
  for select to authenticated using (id = (select auth.uid()));
create policy "read own subscription" on public.subscriptions
  for select to authenticated using (user_id = (select auth.uid())::text);
create policy "read own usage" on public.usage
  for select to authenticated using (user_id = (select auth.uid())::text);
create policy "read own payments" on public.payment_verifications
  for select to authenticated using (user_id = (select auth.uid())::text);
create policy "own agents" on public.agents
  for all to authenticated using (user_id = (select auth.uid())::text)
  with check (user_id = (select auth.uid())::text);
create policy "own tasks" on public.tasks
  for all to authenticated using (user_id = (select auth.uid())::text)
  with check (user_id = (select auth.uid())::text);
create policy "read own logs" on public.logs
  for select to authenticated using (user_id = (select auth.uid())::text);
create policy "own memories" on public.memories
  for all to authenticated using (user_id = (select auth.uid())::text)
  with check (user_id = (select auth.uid())::text);
-- pending_approvals, api_keys, memory_audit: no policies → service-role only.
-- payment_verifications has NO insert/update policy: submissions and approvals
-- go through the backend, so users can never approve their own payment.

-- ── Private bucket for payment screenshots ───────────────────────────────────
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('payment-screenshots','payment-screenshots', false, 5242880,
        array['image/png','image/jpeg','image/webp','application/pdf'])
on conflict (id) do nothing;
