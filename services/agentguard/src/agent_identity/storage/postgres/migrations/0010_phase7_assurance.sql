-- AgentGuard Phase 7: self-healing policy intelligence, tamper-evident audit, compliance evidence &
-- SIEM integration. Schema v10.
-- Additive only: Steps 1-11 and Phases 4-6 tables are untouched. Applied exactly once by migrate.py
-- (checksummed, advisory-locked, forward-only). Times are DOUBLE PRECISION epoch seconds.
--
-- SECRETS / PRIVACY: none of these tables hold secrets, prompts or payloads. An evidence row stores a
-- REFERENCE plus a SHA-256 digest, never the referenced content; a SIEM event row stores an already
-- REDACTED, classification-gated projection; the audit row stores ids, an outcome and a bounded
-- primitive-only detail bag; a proposal row stores Rego source (not secret) and a checksum.
--
-- RETENTION: the audit table is append-only against UPDATE (a trigger rejects it); DELETE is
-- permitted only so a retention path can work. Tenant isolation is enforced twice: every query is
-- filtered by org_id AND Row-Level Security applies the same GUC contract as 0004-0009
-- (`app.current_org`, `app.platform_admin`).

-- --------------------------------------------------------------------------- security evidence
CREATE TABLE assurance_evidence (
  evidence_id    TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  kind           TEXT NOT NULL,
  ts             DOUBLE PRECISION NOT NULL,
  summary        TEXT NOT NULL DEFAULT '',
  source         TEXT NOT NULL DEFAULT '',
  agent_id       TEXT,
  ref            TEXT,
  digest         TEXT,
  severity       TEXT NOT NULL DEFAULT 'medium',
  count          INTEGER NOT NULL DEFAULT 1,
  correlation_id TEXT,
  provenance     TEXT NOT NULL DEFAULT 'observed_fact',
  detail         JSONB NOT NULL DEFAULT '{}'::jsonb,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (count >= 1)
);
CREATE INDEX assurance_evidence_org_ts_idx   ON assurance_evidence (org_id, ts DESC, evidence_id DESC);
CREATE INDEX assurance_evidence_org_kind_idx ON assurance_evidence (org_id, kind, ts DESC);

-- --------------------------------------------------------------------------- recommendations
CREATE TABLE assurance_recommendations (
  recommendation_id TEXT PRIMARY KEY,
  org_id            TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  created_at        DOUBLE PRECISION NOT NULL,
  kind              TEXT NOT NULL,
  title             TEXT NOT NULL DEFAULT '',
  target_policy_id  TEXT,
  target_rule       TEXT,
  proposed_change   JSONB NOT NULL DEFAULT '{}'::jsonb,
  observed_facts    TEXT[] NOT NULL DEFAULT '{}',
  heuristic_conclusions TEXT[] NOT NULL DEFAULT '{}',
  evidence_ids      TEXT[] NOT NULL DEFAULT '{}',
  expected_benefit  TEXT NOT NULL DEFAULT '',
  operational_impact TEXT NOT NULL DEFAULT '',
  confidence        DOUBLE PRECISION NOT NULL DEFAULT 0,
  uncertainty       TEXT NOT NULL DEFAULT '',
  impact_level      TEXT NOT NULL DEFAULT 'medium',
  requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
  test_requirements TEXT[] NOT NULL DEFAULT '{}',
  rollback_plan     TEXT NOT NULL DEFAULT '',
  status            TEXT NOT NULL DEFAULT 'open',
  provenance        TEXT NOT NULL DEFAULT 'recommendation',
  row_created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (confidence >= 0 AND confidence <= 1),
  CHECK (status IN ('open','accepted','rejected','superseded'))
);
CREATE INDEX assurance_recommendations_org_ts_idx ON assurance_recommendations (org_id, created_at DESC);

-- --------------------------------------------------------------------------- policy proposals
CREATE TABLE assurance_proposals (
  proposal_id        TEXT PRIMARY KEY,
  org_id             TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  recommendation_id  TEXT,
  policy_id          TEXT,
  base_version       INTEGER,
  proposed_rego      TEXT NOT NULL,
  checksum           TEXT NOT NULL,
  status             TEXT NOT NULL DEFAULT 'draft',
  impact_level       TEXT NOT NULL DEFAULT 'medium',
  created_at         DOUBLE PRECISION NOT NULL,
  created_by         TEXT NOT NULL,
  updated_at         DOUBLE PRECISION NOT NULL,
  title              TEXT NOT NULL DEFAULT '',
  rationale          TEXT NOT NULL DEFAULT '',
  validated_at       DOUBLE PRECISION,
  validation_summary JSONB,
  simulation_summary JSONB,
  approvals          JSONB NOT NULL DEFAULT '[]'::jsonb,
  canary             JSONB,
  activated_at       DOUBLE PRECISION,
  activated_by       TEXT,
  activated_version  INTEGER,
  rolled_back_at     DOUBLE PRECISION,
  rolled_back_to     INTEGER,
  expires_at         DOUBLE PRECISION,
  emergency          BOOLEAN NOT NULL DEFAULT FALSE,
  provenance         JSONB NOT NULL DEFAULT '[]'::jsonb,
  row_created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (status IN ('draft','validated','simulated','pending_approval','approved','canary',
                    'active','rejected','rolled_back','expired'))
);
CREATE INDEX assurance_proposals_org_ts_idx     ON assurance_proposals (org_id, created_at DESC);
CREATE INDEX assurance_proposals_org_status_idx ON assurance_proposals (org_id, status, created_at DESC);

-- --------------------------------------------------------------------------- compliance mappings
-- Platform-wide catalogue (not tenant-scoped): a control mapping describes the platform's controls.
CREATE TABLE assurance_compliance_mappings (
  mapping_id          TEXT PRIMARY KEY,
  framework           TEXT NOT NULL,
  control_id          TEXT NOT NULL,
  control_title       TEXT NOT NULL DEFAULT '',
  description         TEXT NOT NULL DEFAULT '',
  scope               TEXT NOT NULL DEFAULT 'platform',
  evidence_source     TEXT NOT NULL DEFAULT '',
  owner_component     TEXT NOT NULL DEFAULT '',
  verification_status TEXT NOT NULL DEFAULT 'unverified',
  evidence_ts         DOUBLE PRECISION,
  provenance          TEXT NOT NULL DEFAULT 'observed_fact',
  known_gaps          TEXT[] NOT NULL DEFAULT '{}',
  last_review         DOUBLE PRECISION,
  next_review         DOUBLE PRECISION,
  evidence_refs       TEXT[] NOT NULL DEFAULT '{}',
  row_created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (verification_status IN ('implemented','evidence_collected','organizational','unverified',
                                 'incomplete'))
);
CREATE UNIQUE INDEX assurance_compliance_fw_control_uniq
  ON assurance_compliance_mappings (framework, control_id);

-- --------------------------------------------------------------------------- SIEM events
CREATE TABLE assurance_siem_events (
  event_id       TEXT PRIMARY KEY,
  ts             DOUBLE PRECISION NOT NULL,
  org_id         TEXT,
  severity       TEXT NOT NULL DEFAULT 'medium',
  category       TEXT NOT NULL DEFAULT '',
  action         TEXT NOT NULL DEFAULT '',
  outcome        TEXT NOT NULL DEFAULT '',
  source         TEXT NOT NULL DEFAULT '',
  dedup_key      TEXT NOT NULL DEFAULT '',
  correlation_id TEXT,
  agent_id       TEXT,
  classification TEXT NOT NULL DEFAULT 'internal',
  provenance     TEXT NOT NULL DEFAULT 'observed_fact',
  incident_id    TEXT,
  policy_id      TEXT,
  policy_version TEXT,
  fields         JSONB NOT NULL DEFAULT '{}'::jsonb,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX assurance_siem_events_org_ts_idx ON assurance_siem_events (org_id, ts DESC, event_id DESC);
CREATE INDEX assurance_siem_events_dedup_idx  ON assurance_siem_events (org_id, dedup_key, ts DESC);

-- --------------------------------------------------------------------------- SIEM deliveries
CREATE TABLE assurance_siem_deliveries (
  delivery_id    TEXT PRIMARY KEY,
  destination_id TEXT NOT NULL,
  event_id       TEXT NOT NULL,
  org_id         TEXT,
  status         TEXT NOT NULL DEFAULT 'pending',
  attempts       INTEGER NOT NULL DEFAULT 0,
  ts             DOUBLE PRECISION NOT NULL,
  last_error     TEXT,
  next_attempt_at DOUBLE PRECISION,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (attempts >= 0)
);
CREATE INDEX assurance_siem_deliveries_dest_idx ON assurance_siem_deliveries (destination_id, ts DESC);
CREATE INDEX assurance_siem_deliveries_status_idx ON assurance_siem_deliveries (status, ts DESC);

-- --------------------------------------------------------------------------- correlation findings
CREATE TABLE assurance_correlations (
  finding_id          TEXT PRIMARY KEY,
  org_id              TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  correlation_id      TEXT NOT NULL,
  ts                  DOUBLE PRECISION NOT NULL,
  severity            TEXT NOT NULL DEFAULT 'medium',
  summary             TEXT NOT NULL DEFAULT '',
  event_ids           TEXT[] NOT NULL DEFAULT '{}',
  dedup_key           TEXT NOT NULL DEFAULT '',
  related_incident_id TEXT,
  policy_id           TEXT,
  agent_id            TEXT,
  provenance          TEXT NOT NULL DEFAULT 'derived',
  detail              JSONB NOT NULL DEFAULT '{}'::jsonb,
  row_created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX assurance_correlations_org_ts_idx ON assurance_correlations (org_id, ts DESC);

-- --------------------------------------------------------------------------- tamper-evident audit (append-only)
-- ``insert_order`` is the GLOBAL monotonic insertion counter used ONLY for ordering (the hash chain
-- is built in insertion order). ``seq`` is the record's OWN per-tenant sequence number and is part of
-- the hashed content, so it must be stored verbatim -- it is NOT the global counter.
CREATE TABLE assurance_audit (
  insert_order   BIGSERIAL NOT NULL,
  seq            BIGINT NOT NULL,
  record_id      TEXT PRIMARY KEY,
  org_id         TEXT,
  ts             DOUBLE PRECISION NOT NULL,
  event          TEXT NOT NULL,
  actor_user_id  TEXT,
  outcome        TEXT NOT NULL DEFAULT 'ok',
  reason         TEXT,
  payload_digest TEXT,
  prev_hash      TEXT,
  hash           TEXT NOT NULL,
  signature      TEXT,
  key_id         TEXT,
  key_version    INTEGER,
  correlation_id TEXT,
  detail         JSONB,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX assurance_audit_org_ts_idx ON assurance_audit (org_id, ts DESC, record_id DESC);
CREATE INDEX assurance_audit_event_idx  ON assurance_audit (event, ts DESC);
-- The hash chain is built in INSERTION order, so verification must read it back in insertion order.
-- ``insert_order`` is the monotonic global insertion counter that makes that possible (ts/record_id
-- are not unique, and ``seq`` is the per-tenant sequence that is part of the hashed content).
CREATE INDEX assurance_audit_org_order_idx ON assurance_audit (org_id, insert_order);

CREATE OR REPLACE FUNCTION assurance_audit_no_update() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'assurance_audit is append-only' USING ERRCODE = 'check_violation';
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER assurance_audit_no_update BEFORE UPDATE ON assurance_audit
  FOR EACH ROW EXECUTE FUNCTION assurance_audit_no_update();

-- --------------------------------------------------------------------------- signed checkpoints
CREATE TABLE assurance_checkpoints (
  checkpoint_id TEXT PRIMARY KEY,
  org_id        TEXT,
  seq           BIGINT NOT NULL,
  head_hash     TEXT NOT NULL,
  record_count  INTEGER NOT NULL,
  ts            DOUBLE PRECISION NOT NULL,
  signature     TEXT,
  key_id        TEXT,
  key_version   INTEGER,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (record_count >= 0)
);
CREATE INDEX assurance_checkpoints_org_seq_idx ON assurance_checkpoints (org_id, seq DESC);

-- --------------------------------------------------------------------------- tenant isolation (RLS)
-- Same GUC contract as migrations 0004-0009. NOTE: PostgreSQL exempts SUPERUSER and BYPASSRLS roles
-- from RLS, so the application MUST connect as a non-superuser role for this to be effective (see
-- docs/PHASE7_SECURITY_LIMITATIONS.md).
ALTER TABLE assurance_evidence        ENABLE ROW LEVEL SECURITY;
ALTER TABLE assurance_recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE assurance_proposals       ENABLE ROW LEVEL SECURITY;
ALTER TABLE assurance_siem_events     ENABLE ROW LEVEL SECURITY;
ALTER TABLE assurance_siem_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE assurance_correlations    ENABLE ROW LEVEL SECURITY;
ALTER TABLE assurance_audit           ENABLE ROW LEVEL SECURITY;

CREATE POLICY assurance_evidence_tenant_isolation ON assurance_evidence
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY assurance_recommendations_tenant_isolation ON assurance_recommendations
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY assurance_proposals_tenant_isolation ON assurance_proposals
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY assurance_siem_events_tenant_isolation ON assurance_siem_events
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true)
         OR org_id IS NULL)
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true)
         OR org_id IS NULL);

CREATE POLICY assurance_siem_deliveries_tenant_isolation ON assurance_siem_deliveries
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true)
         OR org_id IS NULL)
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true)
         OR org_id IS NULL);

CREATE POLICY assurance_correlations_tenant_isolation ON assurance_correlations
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));

CREATE POLICY assurance_audit_tenant_isolation ON assurance_audit
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true)
         OR org_id IS NULL)
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true)
         OR org_id IS NULL);
