"use client";

/**
 * Demo data used when the backend is unreachable.
 *
 * The dashboard stays fully explorable offline: the execution panel replays a
 * realistic orchestration run and the approvals modal shows a sample HITL
 * request. Shapes mirror the real API responses in `lib/api.ts` exactly.
 */

import type { OrchestrationState, PendingApproval } from "@/lib/api";

export const DEMO_ORCHESTRATION: OrchestrationState = {
  run_id: "demo-run-7f3a91",
  prompt: "Research the AI agent market and draft a launch brief",
  status: "completed",
  error: null,
  approval_id: null,
  iteration: 2,
  max_iterations: 3,
  duration_ms: 4820,
  total_cost_usd: 0.0412,
  approved_count: 3,
  plan: [
    {
      id: "t1",
      description: "Search for recent AI agent market data and funding rounds",
      tool: "web_search",
      status: "approved",
      attempts: 1,
      feedback: "",
    },
    {
      id: "t2",
      description: "Compute market size growth and CAGR from the collected figures",
      tool: "python_exec",
      status: "approved",
      attempts: 2,
      feedback: "Recompute with the 2024 baseline included.",
    },
    {
      id: "t3",
      description: "Generate the launch brief document",
      tool: "file_generator",
      status: "approved",
      attempts: 1,
      feedback: "",
    },
  ],
  results: [
    {
      task_id: "t1",
      tool: "web_search",
      output:
        "Found 12 sources: agent-platform funding reached $4.1B in 2025, up 63% YoY.",
      ok: true,
      error: null,
      model: "claude-opus-4.6",
      provider: "unorouter",
      cost_usd: 0.0184,
      duration_ms: 1420,
    },
    {
      task_id: "t2",
      tool: "python_exec",
      output: "CAGR 2024-2028 = 41.7% (baseline $2.5B -> $10.1B)",
      ok: true,
      error: null,
      model: "claude-opus-4.6",
      provider: "unorouter",
      cost_usd: 0.0151,
      duration_ms: 1980,
    },
    {
      task_id: "t3",
      tool: "file_generator",
      output: "Wrote launch_brief.md (1,284 words, 6 sections)",
      ok: true,
      error: null,
      model: "gpt-4o-mini",
      provider: "openai",
      cost_usd: 0.0077,
      duration_ms: 1420,
    },
  ],
  reviews: [
    {
      task_id: "t1",
      verdict: "approved",
      feedback: "Sources are recent and directly relevant.",
      score: 0.92,
    },
    {
      task_id: "t2",
      verdict: "approved",
      feedback: "Baseline corrected; math checks out.",
      score: 0.88,
    },
    {
      task_id: "t3",
      verdict: "approved",
      feedback: "Brief covers all required sections.",
      score: 0.95,
    },
  ],
  final_output:
    "Launch brief ready: the agent-platform market is growing at ~41.7% CAGR, with funding up 63% YoY. Positioning should lead with production reliability rather than raw model quality.",
  memory_context: "",
};

export const DEMO_APPROVALS: PendingApproval[] = [
  {
    approval_id: "apr-demo-1",
    run_id: "demo-run-7f3a91",
    action_type: "email.send",
    payload: {
      to: "partners@acme.io",
      subject: "AQL-1 launch brief",
      body: "Sharing the launch brief ahead of Thursday's review.",
    },
    risk: {
      action_type: "email.send",
      risk_level: "high",
      is_high_risk: true,
      reasons: ["Sends an email or message to an external recipient."],
      matched_rules: ["external_communication.send"],
      requires_approval: true,
      categories: ["external_communication"],
      checked_at: "2026-10-01T06:20:00+00:00",
    },
    kind: "orchestrator",
    status: "pending",
    user_id: "arif",
    session_id: "default",
    resume_state: {},
    approver: null,
    note: "",
    created_at: "2026-10-01T06:20:00+00:00",
    decided_at: null,
  },
  {
    approval_id: "apr-demo-2",
    run_id: "demo-run-2b81c4",
    action_type: "db.delete",
    payload: { table: "stale_sessions", where: "created_at < '2026-01-01'", rows: 1842 },
    risk: {
      action_type: "db.delete",
      risk_level: "high",
      is_high_risk: true,
      reasons: ["Deletes database records."],
      matched_rules: ["data_deletion.records"],
      requires_approval: true,
      categories: ["data_deletion"],
      checked_at: "2026-10-01T06:12:00+00:00",
    },
    kind: "agent",
    status: "pending",
    user_id: "arif",
    session_id: "default",
    resume_state: {},
    approver: null,
    note: "",
    created_at: "2026-10-01T06:12:00+00:00",
    decided_at: null,
  },
];
