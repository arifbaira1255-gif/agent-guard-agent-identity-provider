-- AgentGuard Phase 5: runtime monitoring, agent behaviour intelligence, intent graph & agentic drift
-- detection. Schema v8.
-- Additive only: Steps 1-11 and Phase 4 tables are untouched. Applied exactly once by migrate.py
-- (checksummed, advisory-locked, forward-only). Times are DOUBLE PRECISION epoch seconds.
--
-- SECRETS / PRIVACY: none of these tables hold secrets, prompts or payloads. A runtime event row is
-- normalized METADATA (ids, event type, decision, reason code, resource/destination identifiers, a
-- correlation/trace context and a bounded primitive-only `extra`). Producers cannot store prompts,
-- request bodies or credentials here: the ingestion pipeline redacts at the boundary (see
-- runtime_monitoring/redaction.py), and this schema has no column for such content.
--
-- RETENTION: events/findings/assessments are purgeable by `ts` (the store's purge_before is the only
-- delete path). Audit tables and events are append-only against UPDATE (a trigger rejects it);
-- DELETE is permitted only so the retention path can work. Tenant isolation is enforced twice: every
-- query is filtered by org_id AND Row-Level Security applies the same GUC contract as 0004-0007
-- (`app.current_org`, `app.platform_admin`).

-- --------------------------------------------------------------------------- runtime events (append-only)
CREATE TABLE runtime_events (
  event_id       TEXT PRIMARY KEY,
  dedup_key      TEXT,
  event_type     TEXT NOT NULL,
  ts             DOUBLE PRECISION NOT NULL,
  ingested_at    DOUBLE PRECISION NOT NULL,
  org_id         TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  agent_id       TEXT,
  instance_id    TEXT,
  session_id     TEXT,
  action         TEXT,
  resource       TEXT,
  resource_type  TEXT,
  decision       TEXT,
  reason         TEXT,
  outcome        TEXT NOT NULL DEFAULT 'ok',
  policy_id      TEXT,
  policy_version TEXT,
  destination    TEXT,
  address_class  TEXT,
  data_classes   TEXT[] NOT NULL DEFAULT '{}',
  dlp_rule_ids   TEXT[] NOT NULL DEFAULT '{}',
  severity       TEXT,
  latency_ms     INTEGER,
  correlation_id TEXT,
  trace_id       TEXT,
  span_id        TEXT,
  parent_span_id TEXT,
  actor_user_id  TEXT,
  task_id        TEXT,
  late           BOOLEAN NOT NULL DEFAULT FALSE,
  redacted       BOOLEAN NOT NULL DEFAULT FALSE,
  sampled        BOOLEAN NOT NULL DEFAULT FALSE,
  extra          JSONB NOT NULL DEFAULT '{}'::jsonb,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (latency_ms IS NULL OR latency_ms >= 0)
);
-- Index strategy: the investigation queries are (org [,agent]) newest-first, by correlation/trace,
-- by type, and by dedup key. DESC on ts matches the pagination order so the cursor scan is an index
-- walk rather than a sort.
CREATE INDEX runtime_events_org_ts_idx      ON runtime_events (org_id, ts DESC, event_id DESC);
CREATE INDEX runtime_events_org_agent_ts_idx ON runtime_events (org_id, agent_id, ts DESC, event_id DESC);
CREATE INDEX runtime_events_org_type_ts_idx ON runtime_events (org_id, event_type, ts DESC);
CREATE INDEX runtime_events_corr_idx        ON runtime_events (org_id, correlation_id, ts);
CREATE INDEX runtime_events_trace_idx       ON runtime_events (org_id, trace_id, ts);
CREATE INDEX runtime_events_dedup_idx       ON runtime_events (org_id, dedup_key);
-- The cursor page boundary is (ts, event_id); this index makes the "strictly older than" scan cheap.
CREATE INDEX runtime_events_ts_id_idx       ON runtime_events (ts DESC, event_id DESC);

CREATE FUNCTION ag_runtime_events_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'runtime_events is append-only' USING ERRCODE = 'check_violation';
END $$;
CREATE TRIGGER runtime_events_no_update BEFORE UPDATE ON runtime_events
  FOR EACH ROW EXECUTE FUNCTION ag_runtime_events_immutable();

-- --------------------------------------------------------------------------- behaviour profiles
CREATE TABLE runtime_behavior_profiles (
  profile_id           TEXT PRIMARY KEY,
  org_id               TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  agent_id             TEXT NOT NULL,
  version              INTEGER NOT NULL DEFAULT 1,
  learning_window_s    INTEGER NOT NULL DEFAULT 604800,
  min_samples          INTEGER NOT NULL DEFAULT 50,
  total_events         INTEGER NOT NULL DEFAULT 0,
  tools                JSONB NOT NULL DEFAULT '{}'::jsonb,
  resources            JSONB NOT NULL DEFAULT '{}'::jsonb,
  destinations         JSONB NOT NULL DEFAULT '{}'::jsonb,
  actions              JSONB NOT NULL DEFAULT '{}'::jsonb,
  decisions            JSONB NOT NULL DEFAULT '{}'::jsonb,
  data_classes         JSONB NOT NULL DEFAULT '{}'::jsonb,
  hour_histogram       JSONB NOT NULL DEFAULT '{}'::jsonb,
  sequences            JSONB NOT NULL DEFAULT '{}'::jsonb,
  denials              INTEGER NOT NULL DEFAULT 0,
  failures             INTEGER NOT NULL DEFAULT 0,
  retries              INTEGER NOT NULL DEFAULT 0,
  privileged_actions   INTEGER NOT NULL DEFAULT 0,
  sensitive_reads      INTEGER NOT NULL DEFAULT 0,
  max_events_per_hour  INTEGER NOT NULL DEFAULT 0,
  window_start         DOUBLE PRECISION,
  window_end           DOUBLE PRECISION,
  created_at           DOUBLE PRECISION NOT NULL,
  updated_at           DOUBLE PRECISION NOT NULL,
  row_created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, agent_id),
  CHECK (min_samples >= 1)
);
CREATE INDEX runtime_profiles_org_idx ON runtime_behavior_profiles (org_id, agent_id);

CREATE FUNCTION ag_runtime_touch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.row_updated_at := now();
  RETURN NEW;
END $$;
CREATE TRIGGER runtime_profiles_touch BEFORE UPDATE ON runtime_behavior_profiles
  FOR EACH ROW EXECUTE FUNCTION ag_runtime_touch();

-- --------------------------------------------------------------------------- drift findings (append-only)
CREATE TABLE runtime_drift_findings (
  finding_id      TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  agent_id        TEXT,
  ts              DOUBLE PRECISION NOT NULL,
  classification  TEXT NOT NULL
                  CHECK (classification IN ('confirmed_violation','statistical_anomaly',
                                            'heuristic_suspicion','insufficient_evidence')),
  category        TEXT NOT NULL,
  observed        TEXT NOT NULL,
  expected        TEXT,
  corroboration   TEXT NOT NULL DEFAULT 'none'
                  CHECK (corroboration IN ('authoritative','baseline','heuristic','none')),
  evidence        TEXT[] NOT NULL DEFAULT '{}',
  confidence      DOUBLE PRECISION NOT NULL DEFAULT 0,
  severity        TEXT NOT NULL DEFAULT 'medium',
  detail          TEXT NOT NULL DEFAULT '',
  row_created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (confidence >= 0 AND confidence <= 1)
);
CREATE INDEX runtime_findings_org_ts_idx   ON runtime_drift_findings (org_id, ts DESC);
CREATE INDEX runtime_findings_org_agent_idx ON runtime_drift_findings (org_id, agent_id, ts DESC);
CREATE INDEX runtime_findings_class_idx    ON runtime_drift_findings (org_id, classification, ts DESC);

CREATE TRIGGER runtime_drift_findings_no_update BEFORE UPDATE ON runtime_drift_findings
  FOR EACH ROW EXECUTE FUNCTION ag_runtime_events_immutable();

-- --------------------------------------------------------------------------- intent graph
CREATE TABLE runtime_graph_nodes (
  org_id         TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  node_id        TEXT NOT NULL,
  kind           TEXT NOT NULL
                 CHECK (kind IN ('agent','identity','task','tool','resource','policy','permission',
                                 'event','data_class','destination')),
  label          TEXT NOT NULL,
  first_seen     DOUBLE PRECISION NOT NULL,
  last_seen      DOUBLE PRECISION NOT NULL,
  attributes     JSONB NOT NULL DEFAULT '{}'::jsonb,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, node_id)
);
CREATE INDEX runtime_nodes_org_kind_idx ON runtime_graph_nodes (org_id, kind);

CREATE TABLE runtime_graph_edges (
  org_id         TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  edge_id        TEXT NOT NULL,
  kind           TEXT NOT NULL
                 CHECK (kind IN ('agent_tool','agent_resource','agent_destination','agent_policy',
                                 'agent_task','task_resource','event_subject','resource_destination')),
  src            TEXT NOT NULL,
  dst            TEXT NOT NULL,
  first_seen     DOUBLE PRECISION NOT NULL,
  last_seen      DOUBLE PRECISION NOT NULL,
  count          INTEGER NOT NULL DEFAULT 1,
  confidence     DOUBLE PRECISION NOT NULL DEFAULT 1,
  provenance     TEXT NOT NULL DEFAULT '',
  last_event_id  TEXT,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, edge_id),
  CHECK (count >= 1)
);
CREATE INDEX runtime_edges_org_src_idx ON runtime_graph_edges (org_id, src);
CREATE INDEX runtime_edges_org_dst_idx ON runtime_graph_edges (org_id, dst);
CREATE INDEX runtime_edges_org_kind_idx ON runtime_graph_edges (org_id, kind);

-- --------------------------------------------------------------------------- risk assessments (append-only)
CREATE TABLE runtime_risk_assessments (
  assessment_id  TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  agent_id       TEXT,
  ts             DOUBLE PRECISION NOT NULL,
  score          DOUBLE PRECISION NOT NULL,
  band           TEXT NOT NULL CHECK (band IN ('low','medium','high','critical')),
  rule_version   TEXT NOT NULL,
  signals        JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence       TEXT[] NOT NULL DEFAULT '{}',
  window_s       INTEGER NOT NULL DEFAULT 3600,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (score >= 0)
);
CREATE INDEX runtime_risk_org_ts_idx   ON runtime_risk_assessments (org_id, ts DESC);
CREATE INDEX runtime_risk_org_agent_idx ON runtime_risk_assessments (org_id, agent_id, ts DESC);

CREATE TRIGGER runtime_risk_assessments_no_update BEFORE UPDATE ON runtime_risk_assessments
  FOR EACH ROW EXECUTE FUNCTION ag_runtime_events_immutable();

-- --------------------------------------------------------------------------- alert rules
CREATE TABLE runtime_alert_rules (
  rule_id         TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  min_severity    TEXT NOT NULL DEFAULT 'medium',
  event_types     TEXT[] NOT NULL DEFAULT '{}',
  drift_classes   TEXT[] NOT NULL DEFAULT '{}',
  risk_threshold  DOUBLE PRECISION,
  dedup_window_s  INTEGER NOT NULL DEFAULT 300,
  rate_window_s   INTEGER NOT NULL DEFAULT 3600,
  max_per_window  INTEGER NOT NULL DEFAULT 20,
  auto_actions    TEXT[] NOT NULL DEFAULT '{}',
  description     TEXT NOT NULL DEFAULT '',
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  created_at      DOUBLE PRECISION NOT NULL,
  row_created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (dedup_window_s >= 0 AND rate_window_s >= 1 AND max_per_window >= 1)
);
CREATE INDEX runtime_rules_org_idx ON runtime_alert_rules (org_id, enabled);

-- --------------------------------------------------------------------------- alerts
CREATE TABLE runtime_alerts (
  alert_id         TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  rule_id          TEXT NOT NULL,
  severity         TEXT NOT NULL,
  title            TEXT NOT NULL,
  ts               DOUBLE PRECISION NOT NULL,
  state            TEXT NOT NULL DEFAULT 'open'
                   CHECK (state IN ('open','acknowledged','investigating','resolved','suppressed')),
  dedup_key        TEXT NOT NULL DEFAULT '',
  first_seen       DOUBLE PRECISION NOT NULL,
  last_seen        DOUBLE PRECISION NOT NULL,
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  suppressed_count INTEGER NOT NULL DEFAULT 0,
  agent_id         TEXT,
  drift_class      TEXT,
  risk_score       DOUBLE PRECISION,
  event_ids        TEXT[] NOT NULL DEFAULT '{}',
  actions_taken    TEXT[] NOT NULL DEFAULT '{}',
  acknowledged_by  TEXT,
  resolved_by      TEXT,
  note             TEXT NOT NULL DEFAULT '',
  detail           TEXT NOT NULL DEFAULT '',
  row_created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (occurrence_count >= 1 AND suppressed_count >= 0)
);
CREATE INDEX runtime_alerts_org_ts_idx    ON runtime_alerts (org_id, ts DESC);
CREATE INDEX runtime_alerts_org_state_idx ON runtime_alerts (org_id, state, ts DESC);
CREATE INDEX runtime_alerts_dedup_idx     ON runtime_alerts (org_id, dedup_key, state);
CREATE INDEX runtime_alerts_rate_idx      ON runtime_alerts (org_id, rule_id, ts DESC);

CREATE TRIGGER runtime_alerts_touch BEFORE UPDATE ON runtime_alerts
  FOR EACH ROW EXECUTE FUNCTION ag_runtime_touch();

-- --------------------------------------------------------------------------- monitoring-plane audit (append-only)
CREATE TABLE runtime_monitoring_audit (
  event_id         TEXT PRIMARY KEY,
  ts               DOUBLE PRECISION NOT NULL,
  event            TEXT NOT NULL,
  org_id           TEXT,
  agent_id         TEXT,
  outcome          TEXT NOT NULL DEFAULT 'ok',
  reason           TEXT,
  alert_id         TEXT,
  rule_id          TEXT,
  finding_id       TEXT,
  assessment_id    TEXT,
  runtime_event_id TEXT,
  actor_user_id    TEXT,
  action           TEXT,
  correlation_id   TEXT,
  extra            JSONB NOT NULL DEFAULT '{}'::jsonb,
  row_created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX runtime_audit_org_ts_idx ON runtime_monitoring_audit (org_id, ts DESC);

CREATE TRIGGER runtime_monitoring_audit_no_update BEFORE UPDATE ON runtime_monitoring_audit
  FOR EACH ROW EXECUTE FUNCTION ag_runtime_events_immutable();

-- --------------------------------------------------------------------------- Row-Level Security (defence in depth)
-- Same GUC contract as migrations 0004/0005/0006/0007: `app.current_org` (verified tenant) and
-- `app.platform_admin`. A tenant can never read or write another tenant's runtime telemetry/graph/
-- alerts. `org_id IS NULL` rows exist only in the monitoring audit and are readable by all tenants
-- (they are platform-level operational records carrying no tenant content).
ALTER TABLE runtime_events              ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime_behavior_profiles   ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime_drift_findings      ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime_graph_nodes         ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime_graph_edges         ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime_risk_assessments    ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime_alert_rules         ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime_alerts              ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime_monitoring_audit    ENABLE ROW LEVEL SECURITY;

CREATE POLICY runtime_events_tenant_isolation ON runtime_events
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY runtime_profiles_tenant_isolation ON runtime_behavior_profiles
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY runtime_findings_tenant_isolation ON runtime_drift_findings
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY runtime_nodes_tenant_isolation ON runtime_graph_nodes
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY runtime_edges_tenant_isolation ON runtime_graph_edges
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY runtime_risk_tenant_isolation ON runtime_risk_assessments
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY runtime_rules_tenant_isolation ON runtime_alert_rules
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY runtime_alerts_tenant_isolation ON runtime_alerts
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY runtime_monitoring_audit_tenant_isolation ON runtime_monitoring_audit
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id IS NULL OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id IS NULL OR org_id = current_setting('app.current_org', true));
