-- AgentGuard Phase 6: autonomous loop detection, human approval, incident response & automated
-- containment. Schema v9.
-- Additive only: Steps 1-11 and Phases 4-5 tables are untouched. Applied exactly once by migrate.py
-- (checksummed, advisory-locked, forward-only). Times are DOUBLE PRECISION epoch seconds.
--
-- SECRETS / PRIVACY: none of these tables hold secrets, prompts or payloads. An approval row stores a
-- SHA-256 FINGERPRINT of the operation it authorizes (never the parameters themselves beyond a
-- bounded primitive-only `params` bag); an evidence row stores a REFERENCE plus a digest, never the
-- referenced content; the audit row stores ids, an outcome and a bounded primitive-only extra.
--
-- RETENTION: evidence is purgeable by `ts` (the store's purge_evidence_before is the only delete path
-- and it skips sealed rows). Audit and loop-finding tables are append-only against UPDATE (a trigger
-- rejects it); DELETE is permitted only so the retention path can work. Tenant isolation is enforced
-- twice: every query is filtered by org_id AND Row-Level Security applies the same GUC contract as
-- 0004-0008 (`app.current_org`, `app.platform_admin`).

-- --------------------------------------------------------------------------- loop findings (append-only)
CREATE TABLE response_loop_findings (
  finding_id     TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  agent_id       TEXT,
  task_id        TEXT,
  ts             DOUBLE PRECISION NOT NULL,
  pattern        TEXT NOT NULL,
  classification TEXT NOT NULL,
  subject        TEXT NOT NULL,
  observed_count INTEGER NOT NULL,
  threshold      INTEGER NOT NULL,
  window_s       INTEGER NOT NULL,
  severity       TEXT NOT NULL DEFAULT 'medium',
  evidence       TEXT[] NOT NULL DEFAULT '{}',
  detail         TEXT NOT NULL DEFAULT '',
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (observed_count >= 0),
  CHECK (threshold >= 0),
  CHECK (window_s >= 1)
);
CREATE INDEX response_loop_findings_org_ts_idx       ON response_loop_findings (org_id, ts DESC, finding_id DESC);
CREATE INDEX response_loop_findings_org_agent_ts_idx ON response_loop_findings (org_id, agent_id, ts DESC, finding_id DESC);
CREATE INDEX response_loop_findings_org_pattern_idx  ON response_loop_findings (org_id, pattern, ts DESC);

CREATE OR REPLACE FUNCTION response_loop_findings_no_update() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'response_loop_findings is append-only' USING ERRCODE = 'check_violation';
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER response_loop_findings_no_update BEFORE UPDATE ON response_loop_findings
  FOR EACH ROW EXECUTE FUNCTION response_loop_findings_no_update();

-- --------------------------------------------------------------------------- execution budgets
CREATE TABLE response_budgets (
  budget_id       TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  scope           TEXT NOT NULL DEFAULT 'agent',
  agent_id        TEXT,
  task_id         TEXT,
  max_actions     INTEGER,
  max_retries     INTEGER,
  max_requests    INTEGER,
  max_concurrency INTEGER,
  max_tokens      BIGINT,
  max_cost        DOUBLE PRECISION,
  deadline_s      INTEGER,
  started_at      DOUBLE PRECISION NOT NULL,
  updated_at      DOUBLE PRECISION NOT NULL,
  actions_used     INTEGER NOT NULL DEFAULT 0,
  retries_used     INTEGER NOT NULL DEFAULT 0,
  requests_used    INTEGER NOT NULL DEFAULT 0,
  concurrency_used INTEGER NOT NULL DEFAULT 0,
  tokens_used      BIGINT  NOT NULL DEFAULT 0,
  cost_used        DOUBLE PRECISION NOT NULL DEFAULT 0,
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  row_created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (scope IN ('agent','task')),
  CHECK (agent_id IS NOT NULL OR task_id IS NOT NULL),
  CHECK (actions_used >= 0 AND retries_used >= 0 AND requests_used >= 0
         AND concurrency_used >= 0 AND tokens_used >= 0 AND cost_used >= 0)
);
-- One budget per (org, agent) when agent-scoped, one per (org, task) when task-scoped.
CREATE UNIQUE INDEX response_budgets_agent_uniq ON response_budgets (org_id, agent_id)
  WHERE task_id IS NULL AND agent_id IS NOT NULL;
CREATE UNIQUE INDEX response_budgets_task_uniq  ON response_budgets (org_id, task_id)
  WHERE task_id IS NOT NULL;
CREATE INDEX response_budgets_org_idx ON response_budgets (org_id, updated_at DESC);

-- --------------------------------------------------------------------------- emergency stops
CREATE TABLE response_emergency_stops (
  stop_id        TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  agent_id       TEXT,
  task_id        TEXT,
  requested_by   TEXT NOT NULL,
  reason         TEXT NOT NULL DEFAULT '',
  ts             DOUBLE PRECISION NOT NULL,
  active         BOOLEAN NOT NULL DEFAULT TRUE,
  released_by    TEXT,
  released_at    DOUBLE PRECISION,
  release_reason TEXT,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (agent_id IS NOT NULL OR task_id IS NOT NULL)
);
CREATE INDEX response_emergency_stops_org_ts_idx ON response_emergency_stops (org_id, ts DESC);
CREATE INDEX response_emergency_stops_active_idx ON response_emergency_stops (org_id, agent_id, task_id)
  WHERE active;

-- --------------------------------------------------------------------------- human approvals
CREATE TABLE response_approvals (
  approval_id     TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  agent_id        TEXT,
  action          TEXT NOT NULL,
  resource        TEXT NOT NULL,
  fingerprint     TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending',
  requested_at    DOUBLE PRECISION NOT NULL,
  expires_at      DOUBLE PRECISION NOT NULL,
  requested_by    TEXT NOT NULL,
  reason          TEXT NOT NULL DEFAULT '',
  risk_score      DOUBLE PRECISION,
  risk_band       TEXT,
  risk_evidence   TEXT[] NOT NULL DEFAULT '{}',
  policy_id       TEXT,
  policy_version  TEXT,
  incident_id     TEXT,
  decided_at      DOUBLE PRECISION,
  decided_by      TEXT,
  decision_reason TEXT NOT NULL DEFAULT '',
  delegated_to    TEXT,
  params          JSONB NOT NULL DEFAULT '{}'::jsonb,
  row_created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (status IN ('pending','approved','denied','expired','cancelled'))
);
CREATE INDEX response_approvals_org_ts_idx     ON response_approvals (org_id, requested_at DESC);
CREATE INDEX response_approvals_fingerprint_idx ON response_approvals (org_id, fingerprint, requested_at DESC);
CREATE INDEX response_approvals_pending_idx    ON response_approvals (org_id, agent_id)
  WHERE status = 'pending';

-- --------------------------------------------------------------------------- incidents
CREATE TABLE response_incidents (
  incident_id      TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  title            TEXT NOT NULL,
  severity         TEXT NOT NULL DEFAULT 'medium',
  status           TEXT NOT NULL DEFAULT 'detected',
  opened_at        DOUBLE PRECISION NOT NULL,
  updated_at       DOUBLE PRECISION NOT NULL,
  closed_at        DOUBLE PRECISION,
  owner            TEXT,
  agent_ids        TEXT[] NOT NULL DEFAULT '{}',
  resources        TEXT[] NOT NULL DEFAULT '{}',
  alert_ids        TEXT[] NOT NULL DEFAULT '{}',
  finding_ids      TEXT[] NOT NULL DEFAULT '{}',
  evidence_ids     TEXT[] NOT NULL DEFAULT '{}',
  response_ids     TEXT[] NOT NULL DEFAULT '{}',
  timeline         JSONB NOT NULL DEFAULT '[]'::jsonb,
  detection_source TEXT NOT NULL DEFAULT '',
  risk_score       DOUBLE PRECISION,
  risk_band        TEXT,
  resolution       TEXT NOT NULL DEFAULT '',
  post_review      TEXT NOT NULL DEFAULT '',
  correlation_key  TEXT NOT NULL DEFAULT '',
  row_created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (status IN ('detected','triage','investigating','containment','recovery','closed','post_review'))
);
CREATE INDEX response_incidents_org_ts_idx    ON response_incidents (org_id, opened_at DESC);
CREATE INDEX response_incidents_org_status_idx ON response_incidents (org_id, status, opened_at DESC);
CREATE INDEX response_incidents_correlation_idx ON response_incidents (org_id, correlation_key)
  WHERE status NOT IN ('closed','post_review');

-- --------------------------------------------------------------------------- containment executions
CREATE TABLE response_executions (
  response_id      TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  idempotency_key  TEXT NOT NULL,
  incident_id      TEXT,
  agent_id         TEXT,
  task_id          TEXT,
  state            TEXT NOT NULL DEFAULT 'planned',
  trigger          TEXT NOT NULL DEFAULT '',
  requested_by     TEXT NOT NULL,
  approved_by      TEXT,
  approval_id      TEXT,
  created_at       DOUBLE PRECISION NOT NULL,
  updated_at       DOUBLE PRECISION NOT NULL,
  steps            JSONB NOT NULL DEFAULT '[]'::jsonb,
  rollback_steps   JSONB NOT NULL DEFAULT '[]'::jsonb,
  partial_failures TEXT[] NOT NULL DEFAULT '{}',
  evidence_ids     TEXT[] NOT NULL DEFAULT '{}',
  note             TEXT NOT NULL DEFAULT '',
  row_created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (state IN ('planned','running','succeeded','partial','failed','rolled_back','rollback_failed'))
);
-- The idempotency guarantee: one execution per (tenant, key). A duplicate delivery cannot insert a
-- second row, so containment cannot run twice for the same trigger.
CREATE UNIQUE INDEX response_executions_idem_uniq ON response_executions (org_id, idempotency_key);
CREATE INDEX response_executions_org_ts_idx     ON response_executions (org_id, created_at DESC);
CREATE INDEX response_executions_incident_idx   ON response_executions (org_id, incident_id, created_at DESC);

-- --------------------------------------------------------------------------- evidence
CREATE TABLE response_evidence (
  evidence_id     TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  kind            TEXT NOT NULL,
  ts              DOUBLE PRECISION NOT NULL,
  summary         TEXT NOT NULL DEFAULT '',
  ref             TEXT,
  digest          TEXT,
  incident_id     TEXT,
  agent_id        TEXT,
  source          TEXT NOT NULL DEFAULT '',
  retention_until DOUBLE PRECISION,
  sealed          BOOLEAN NOT NULL DEFAULT FALSE,
  row_created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX response_evidence_org_ts_idx       ON response_evidence (org_id, ts DESC);
CREATE INDEX response_evidence_incident_idx     ON response_evidence (org_id, incident_id, ts DESC);
CREATE INDEX response_evidence_retention_idx    ON response_evidence (org_id, ts) WHERE NOT sealed;

-- --------------------------------------------------------------------------- response-plane audit (append-only)
CREATE TABLE response_audit (
  seq            BIGSERIAL NOT NULL,
  event_id       TEXT PRIMARY KEY,
  ts             DOUBLE PRECISION NOT NULL,
  event          TEXT NOT NULL,
  org_id         TEXT,
  agent_id       TEXT,
  outcome        TEXT NOT NULL DEFAULT 'ok',
  reason         TEXT,
  incident_id    TEXT,
  approval_id    TEXT,
  response_id    TEXT,
  evidence_id    TEXT,
  actor_user_id  TEXT,
  action         TEXT,
  correlation_id TEXT,
  prev_hash      TEXT,
  hash           TEXT,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX response_audit_org_ts_idx ON response_audit (org_id, ts DESC, event_id DESC);
CREATE INDEX response_audit_event_idx  ON response_audit (event, ts DESC);
-- The hash chain is built in INSERTION order, so verification must read it back in insertion order.
-- Ordering by (ts, event_id) is NOT insertion order: many records share a timestamp and event_id is
-- random, so a tie would reorder the chain and make a valid chain look broken (and, worse, make a
-- reordered chain look valid). ``seq`` is the monotonic insertion counter that fixes this.
CREATE INDEX response_audit_org_seq_idx ON response_audit (org_id, seq);

CREATE OR REPLACE FUNCTION response_audit_no_update() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'response_audit is append-only' USING ERRCODE = 'check_violation';
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER response_audit_no_update BEFORE UPDATE ON response_audit
  FOR EACH ROW EXECUTE FUNCTION response_audit_no_update();

-- --------------------------------------------------------------------------- tenant isolation (RLS)
-- Same GUC contract as migrations 0004/0005/0006/0007/0008: `app.current_org` (verified tenant) and
-- `app.platform_admin`. A tenant can never read or write another tenant's response-plane rows.
-- NOTE: PostgreSQL exempts SUPERUSER and BYPASSRLS roles from RLS, so the application MUST connect as
-- a non-superuser role for this to be effective (see docs/PHASE6_SECURITY_LIMITATIONS.md).
ALTER TABLE response_loop_findings   ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_budgets         ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_emergency_stops ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_approvals       ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_incidents       ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_executions      ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_evidence        ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_audit           ENABLE ROW LEVEL SECURITY;

CREATE POLICY response_loop_findings_tenant_isolation ON response_loop_findings
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY response_budgets_tenant_isolation ON response_budgets
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY response_emergency_stops_tenant_isolation ON response_emergency_stops
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY response_approvals_tenant_isolation ON response_approvals
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY response_incidents_tenant_isolation ON response_incidents
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY response_executions_tenant_isolation ON response_executions
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY response_evidence_tenant_isolation ON response_evidence
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY response_audit_tenant_isolation ON response_audit
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true)
         OR org_id IS NULL)
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true)
         OR org_id IS NULL);
