/**
 * Offline fallback data for the Billing page.
 *
 * Mirrors the exact shape of `GET /v1/billing/plans` and
 * `GET /v1/billing/subscription`, so the page renders identically whether the
 * backend is reachable or not — the same pattern the dashboard and the
 * Observability page use.
 */

import type {
  FeatureMap,
  Plan,
  PlansResponse,
  SubscriptionResponse,
} from "@/lib/api";

/** A complete feature map — every key present, matching the backend. */
const NO_FEATURES: FeatureMap = {
  api_access: false,
  priority_routing: false,
  observability_history: false,
  team_management: false,
  sso: false,
};

const PRO_FEATURES: FeatureMap = {
  ...NO_FEATURES,
  api_access: true,
  priority_routing: true,
  observability_history: true,
};

const TEAM_FEATURES: FeatureMap = {
  ...PRO_FEATURES,
  team_management: true,
  sso: true,
};

export const DEMO_PLANS: Plan[] = [
  {
    id: "free",
    name: "Free",
    price_usd: 0,
    monthly_token_limit: 50_000,
    max_concurrent_runs: 1,
    seats: 1,
    features: NO_FEATURES,
    description: "Kick the tyres: a single agent, a small monthly token budget.",
    highlights: [
      "50k tokens / month",
      "1 concurrent run",
      "1 seat",
      "Community support",
    ],
  },
  {
    id: "pro",
    name: "Pro",
    price_usd: 29,
    monthly_token_limit: 2_000_000,
    max_concurrent_runs: 5,
    seats: 1,
    features: PRO_FEATURES,
    description: "For builders shipping agents to production.",
    highlights: [
      "2M tokens / month",
      "5 concurrent runs",
      "REST API access",
      "Priority model routing",
      "Observability history",
    ],
  },
  {
    id: "team",
    name: "Team",
    price_usd: 99,
    monthly_token_limit: 10_000_000,
    max_concurrent_runs: 25,
    seats: 10,
    features: TEAM_FEATURES,
    description: "Shared workspaces, seats and SSO for whole teams.",
    highlights: [
      "10M tokens / month",
      "25 concurrent runs",
      "10 seats",
      "Team management",
      "SSO-ready",
    ],
  },
];

export const DEMO_PLANS_RESPONSE: PlansResponse = {
  plans: DEMO_PLANS,
  billing_enabled: true,
  payoneer_configured: false,
};

export const DEMO_SUBSCRIPTION: SubscriptionResponse = {
  subscription: {
    user_id: "demo-user",
    tier: "pro",
    tier_name: "Pro",
    status: "active",
    is_active: true,
    payoneer_reference: "DEMO-TXN-123",
    last_payment_id: "demo-payment",
    current_period_start: "2026-10-01T00:00:00+00:00",
    current_period_end: "2026-11-01T00:00:00+00:00",
    cancel_at_period_end: false,
    updated_at: "2026-10-01T00:00:00+00:00",
    price_usd: 29,
    monthly_token_limit: 2_000_000,
    max_concurrent_runs: 5,
    seats: 1,
    features: PRO_FEATURES,
  },
  usage: {
    user_id: "demo-user",
    period_start: "2026-10-01T00:00:00+00:00",
    tokens_used: 1_284_500,
    tokens_limit: 2_000_000,
    tokens_remaining: 715_500,
    percent_used: 64.23,
    runs_used: 148,
    is_exhausted: false,
  },
  features: PRO_FEATURES,
  renewal_date: "2026-11-01T00:00:00+00:00",
  cancel_at_period_end: false,
  billing_enabled: true,
  payoneer_configured: false,
};

/** A couple of past invoices so the history list is not always empty. */
export interface Invoice {
  id: string;
  date: string;
  amount_usd: number;
  status: "paid" | "open" | "failed";
  description: string;
}

export const DEMO_INVOICES: Invoice[] = [
  {
    id: "in_demo_003",
    date: "2026-10-01T00:00:00+00:00",
    amount_usd: 29,
    status: "paid",
    description: "Pro — monthly subscription",
  },
  {
    id: "in_demo_002",
    date: "2026-09-01T00:00:00+00:00",
    amount_usd: 29,
    status: "paid",
    description: "Pro — monthly subscription",
  },
  {
    id: "in_demo_001",
    date: "2026-08-01T00:00:00+00:00",
    amount_usd: 29,
    status: "paid",
    description: "Pro — monthly subscription",
  },
];
