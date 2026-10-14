/**
 * Typed client for the AQL-1 backend API.
 *
 * This is the SINGLE place in the frontend that performs HTTP calls. Every
 * method returns a typed promise and throws `ApiError` on failure, so callers
 * (e.g. the dashboard) can degrade gracefully to demo data instead of crashing.
 */

const API_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL ||
  process.env.NEXT_PUBLIC_API_URL ||
  "http://localhost:8000"
).replace(/\/+$/, "");

/** Supabase session token for the signed-in user ("" when signed out). */
async function authHeader(): Promise<Record<string, string>> {
  try {
    const { getAccessToken } = await import("@/lib/supabase");
    const token = await getAccessToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
  } catch {
    return {};
  }
}

/** Default request timeout (ms) — keeps the UI responsive when the API is down. */
const DEFAULT_TIMEOUT_MS = 8000;

/** Thrown for any non-2xx response, timeout, or network failure. */
export class ApiError extends Error {
  readonly status: number | null;

  constructor(message: string, status: number | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// ── Shared domain types ──────────────────────────────────────────────────────

export type RiskLevel = "low" | "medium" | "high";
export type ApprovalStatus = "pending" | "approved" | "rejected";
export type ApprovalKind = "agent" | "orchestrator";

/** Structured result of `check_action_risk` on the backend. */
export interface RiskAssessment {
  action_type: string;
  risk_level: RiskLevel;
  is_high_risk: boolean;
  reasons: string[];
  matched_rules: string[];
  requires_approval: boolean;
  categories: string[];
  checked_at: string;
}

/** A paused run waiting for a human decision. */
export interface PendingApproval {
  approval_id: string;
  run_id: string;
  action_type: string;
  payload: Record<string, unknown>;
  risk: RiskAssessment;
  kind: ApprovalKind;
  status: ApprovalStatus;
  user_id: string;
  session_id: string;
  resume_state: Record<string, unknown>;
  approver: string | null;
  note: string;
  created_at: string;
  decided_at: string | null;
}

/** One ReAct step from a single-agent run. */
export interface AgentStep {
  index: number;
  thought: string;
  action: string | null;
  action_input: Record<string, unknown> | null;
  observation: string | null;
}

export interface RouteInfo {
  provider: string;
  model: string;
  tier: string;
  reason: string;
}

export interface AgentRun {
  run_id: string;
  task: string;
  status: string;
  answer: string | null;
  error: string | null;
  approval_id: string | null;
  duration_ms: number;
  route: RouteInfo;
  steps: AgentStep[];
}

export interface OrchestrationSubTask {
  id: string;
  description: string;
  tool: string;
  status: string;
  attempts: number;
  feedback: string;
}

export interface OrchestrationResult {
  task_id: string;
  tool: string;
  output: string;
  ok: boolean;
  error: string | null;
  model: string;
  provider: string;
  cost_usd: number;
  duration_ms: number;
}

export interface OrchestrationReview {
  task_id: string;
  verdict: string;
  feedback: string;
  score: number;
}

export interface OrchestrationState {
  run_id: string;
  prompt: string;
  status: string;
  error: string | null;
  approval_id: string | null;
  iteration: number;
  max_iterations: number;
  duration_ms: number;
  total_cost_usd: number;
  approved_count: number;
  plan: OrchestrationSubTask[];
  results: OrchestrationResult[];
  reviews: OrchestrationReview[];
  final_output: string | null;
  memory_context: string;
}

export interface ApprovalDecisionResult {
  approval_id: string;
  decision: string;
  status: string;
  result: Record<string, unknown>;
}

export interface ToolSchema {
  type: string;
  function: { name: string; description: string };
}

// ── Observability ─────────────────────────────────────────────────────────────

export type TraceStatus = "success" | "failed" | "skipped";
export type ComplexityTier = "Low" | "Medium" | "High";

/** One agent call — a row in the step-by-step trace table. */
export interface LogRecord {
  trace_id: string;
  run_id: string;
  timestamp: string;
  agent: string;
  tool: string;
  status: TraceStatus;
  latency_ms: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cost_usd: number;
  complexity: ComplexityTier;
  model: string;
  provider: string;
  detail: string;
}

/** Routing spend for one complexity tier. */
export interface TierBreakdown {
  tier: string;
  model: string;
  provider: string;
  calls: number;
  tokens: number;
  cost_usd: number;
  baseline_cost_usd: number;
  saved_usd: number;
}

/** Cost saved by complexity-based model routing vs. an all-premium baseline. */
export interface RoutingSavingsSummary {
  premium_model: string;
  actual_cost_usd: number;
  baseline_cost_usd: number;
  saved_usd: number;
  saved_pct: number;
  tiers: TierBreakdown[];
}

/** One time slice of the success/failure trend. */
export interface TrendBucket {
  label: string;
  start: string;
  success: number;
  failure: number;
  total: number;
  success_rate: number;
}

/** Successful vs failed runs over time, plus the overall rate. */
export interface SuccessTrendSummary {
  total: number;
  succeeded: number;
  failed: number;
  success_rate: number;
  series: TrendBucket[];
}

/** Headline counters across every trace. */
export interface ObservabilitySummary {
  runs: number;
  calls: number;
  succeeded: number;
  failed: number;
  success_rate: number;
  total_tokens: number;
  total_cost_usd: number;
  avg_cost_usd: number;
  avg_latency_ms: number;
  total_latency_ms: number;
}

/** Full `GET /api/logs` response. */
export interface LogsResponse {
  generated_at: string;
  summary: ObservabilitySummary;
  routing: RoutingSavingsSummary;
  success: SuccessTrendSummary;
  traces: LogRecord[];
  count: number;
}

// ── Low-level request helper ─────────────────────────────────────────────────

// ── Billing ──────────────────────────────────────────────────────────────────

export type TierId = "free" | "pro" | "team";
export type SubscriptionStatus =
  | "active"
  | "trialing"
  | "past_due"
  | "unpaid"
  | "canceled"
  | "incomplete"
  | "paused";

/** Canonical feature keys — mirrors `FEATURE_KEYS` on the backend. */
export type FeatureKey =
  | "api_access"
  | "priority_routing"
  | "observability_history"
  | "team_management"
  | "sso";

/** A complete feature map: every key is always present. */
export type FeatureMap = Record<FeatureKey, boolean>;

/** One commercial tier from `GET /v1/billing/plans`. */
export interface Plan {
  id: TierId;
  name: string;
  price_usd: number;
  monthly_token_limit: number;
  max_concurrent_runs: number;
  seats: number;
  features: FeatureMap;
  description: string;
  highlights: string[];
}

export interface PlansResponse {
  plans: Plan[];
  billing_enabled: boolean;
  payoneer_configured: boolean;
}

/** The caller's billing state. */
export interface Subscription {
  user_id: string;
  tier: TierId;
  tier_name: string;
  status: SubscriptionStatus;
  is_active: boolean;
  payoneer_reference: string;
  last_payment_id: string;
  current_period_start: string;
  current_period_end: string;
  cancel_at_period_end: boolean;
  updated_at: string;
  price_usd: number;
  monthly_token_limit: number;
  max_concurrent_runs: number;
  seats: number;
  features: FeatureMap;
}

/** Monthly token/run consumption for the current period. */
export interface UsageSummary {
  user_id: string;
  period_start: string;
  tokens_used: number;
  tokens_limit: number;
  tokens_remaining: number;
  percent_used: number;
  runs_used: number;
  is_exhausted: boolean;
}

/** Full `GET /v1/billing/subscription` response. */
export interface SubscriptionResponse {
  subscription: Subscription;
  usage: UsageSummary;
  features: FeatureMap;
  renewal_date: string | null;
  cancel_at_period_end: boolean;
  billing_enabled: boolean;
  payoneer_configured: boolean;
}

export type PaymentMethod = "payoneer" | "bank_transfer";
export type PaymentStatus = "pending" | "approved" | "rejected";

/** Where to send money, from `GET /v1/billing/payment-info`. */
export interface PaymentInfo {
  payoneer_email: string;
  payoneer_payment_url: string;
  bank_transfer_details: string;
  currency: string;
  plans: { id: TierId; name: string; price_usd: number }[];
  instructions: string;
}

/** A submitted proof of payment. */
export interface PaymentRecord {
  id: string;
  user_id: string;
  email: string;
  tier: TierId;
  amount_usd: number;
  method: PaymentMethod;
  reference: string;
  sender_name: string;
  status: PaymentStatus;
  note: string;
  reviewer: string;
  created_at: string;
  decided_at: string | null;
  has_screenshot: boolean;
  screenshot_url: string;
}

async function request<T>(
  path: string,
  init?: RequestInit,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const isForm =
      typeof FormData !== "undefined" && init?.body instanceof FormData;
    const res = await fetch(`${API_URL}${path}`, {
      ...init,
      cache: "no-store",
      signal: controller.signal,
      headers: {
        // The browser must set the multipart boundary itself for FormData.
        ...(isForm ? {} : { "Content-Type": "application/json" }),
        ...(await authHeader()),
        ...(init?.headers ?? {}),
      },
    });

    if (!res.ok) {
      // FastAPI puts the human-readable message in `detail`.
      let detail = `API error ${res.status}`;
      try {
        const body = (await res.json()) as { detail?: string };
        if (body && typeof body.detail === "string") detail = body.detail;
      } catch {
        /* non-JSON error body — keep the generic message */
      }
      throw new ApiError(detail, res.status);
    }

    return (await res.json()) as T;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError("Request timed out", null);
    }
    throw new ApiError(err instanceof Error ? err.message : "Network error", null);
  } finally {
    clearTimeout(timer);
  }
}

const post = <T>(path: string, body: unknown): Promise<T> =>
  request<T>(path, { method: "POST", body: JSON.stringify(body) });

// ── Public API surface ───────────────────────────────────────────────────────

export const api = {
  /** Base URL the client is pointed at (useful for the Settings view). */
  baseUrl: API_URL,

  health: () => request<{ status: string; service: string }>("/health"),

  tools: () => request<{ tools: ToolSchema[] }>("/tools"),

  // ── Agent runs ──
  run: (task: string, provider?: string) =>
    post<AgentRun>("/agent/run", { task, provider }),

  runs: (limit = 50) =>
    request<{ runs: Record<string, unknown>[] }>(`/agent/runs?limit=${limit}`),

  runById: (runId: string) => request<AgentRun>(`/agent/runs/${runId}`),

  // ── Multi-agent orchestration ──
  orchestrate: (
    task: string,
    opts: { user_id?: string; session_id?: string; max_iterations?: number } = {},
  ) => post<OrchestrationState>("/orchestrate", { task, ...opts }),

  // ── Safety & human approval ──
  riskCheck: (actionType: string, payload: Record<string, unknown> = {}) =>
    post<RiskAssessment>("/agent/risk-check", {
      action_type: actionType,
      payload,
    }),

  approvals: (status: ApprovalStatus | "all" = "pending", limit = 50) =>
    request<{ approvals: PendingApproval[] }>(
      `/agent/approvals?status=${status}&limit=${limit}`,
    ),

  approval: (approvalId: string) =>
    request<PendingApproval>(`/agent/approvals/${approvalId}`),

  approve: (
    approvalId: string,
    decision: "approve" | "reject",
    opts: { approver?: string; note?: string } = {},
  ) =>
    post<ApprovalDecisionResult>("/agent/approve", {
      approval_id: approvalId,
      decision,
      approver: opts.approver,
      note: opts.note ?? "",
    }),

  // ── Memory ──
  remember: (text: string) =>
    post<{ id: string; text: string }>("/memory", { text, metadata: {} }),

  recall: (text: string, topK = 5) =>
    post<{ results: { id: string; text: string }[] }>("/memory/query", {
      text,
      top_k: topK,
    }),

  // ── Observability ──
  /**
   * Structured execution logs for the Observability page: cost saved by model
   * routing, the success/failure trend, and the step-by-step agent traces.
   */
  getLogs: (
    opts: { run_id?: string; status?: TraceStatus | "all"; agent?: string; limit?: number } = {},
  ) => {
    const params = new URLSearchParams();
    if (opts.run_id) params.set("run_id", opts.run_id);
    if (opts.status) params.set("status", opts.status);
    if (opts.agent) params.set("agent", opts.agent);
    params.set("limit", String(opts.limit ?? 500));
    return request<LogsResponse>(`/api/logs?${params.toString()}`);
  },

  // ── Billing ──
  /** The Free / Pro / Team catalogue (prices, limits, feature flags). */
  getPlans: () => request<PlansResponse>("/v1/billing/plans"),

  /** The caller's tier, status, usage vs limit, renewal date and features. */
  getSubscription: () =>
    request<SubscriptionResponse>("/v1/billing/subscription"),

  /** Payoneer email + bank-transfer details to show on the upgrade page. */
  getPaymentInfo: () => request<PaymentInfo>("/v1/billing/payment-info"),

  /** Submit a transaction ID + screenshot for admin verification. */
  submitPayment: (form: FormData) =>
    request<{ payment: PaymentRecord }>(
      "/v1/billing/payments",
      { method: "POST", body: form },
      30000,
    ),

  /** The signed-in user's own payment submissions. */
  getMyPayments: () =>
    request<{ payments: PaymentRecord[] }>("/v1/billing/payments"),

  // ── Admin (X-Admin-Token) ──
  adminListPayments: (adminToken: string, status?: PaymentStatus) =>
    request<{ payments: PaymentRecord[] }>(
      `/v1/billing/admin/payments${status ? `?status=${status}` : ""}`,
      { headers: { "X-Admin-Token": adminToken } },
    ),

  adminDecidePayment: (
    adminToken: string,
    id: string,
    action: "approve" | "reject",
    note = "",
  ) =>
    request<{ payment: PaymentRecord }>(
      `/v1/billing/admin/payments/${encodeURIComponent(id)}/${action}`,
      {
        method: "POST",
        body: JSON.stringify({ note }),
        headers: { "X-Admin-Token": adminToken },
      },
    ),
};

export default api;
