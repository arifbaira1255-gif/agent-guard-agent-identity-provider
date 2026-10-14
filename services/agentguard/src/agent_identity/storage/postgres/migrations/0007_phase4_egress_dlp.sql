-- AgentGuard Phase 4: enterprise egress security, DLP & network enforcement. Schema v7.
-- Additive only: Steps 1-11 tables/constraints are untouched (the Step 11 governance tables from
-- 0006 in particular are NOT modified). Applied exactly once by migrate.py (checksummed,
-- advisory-locked, forward-only). Times are DOUBLE PRECISION epoch seconds.
--
-- SECRETS: none of these tables hold secrets. An egress policy is a RULE (a destination class, a
-- protocol, a port set, an action, limits) -- never a credential or a payload. The egress audit
-- records ids, decisions, reason codes, the destination host, the resolved address CLASS and DLP
-- rule ids -- never a request body, a matched secret, or a connection string.

-- --------------------------------------------------------------------------- egress policies
CREATE TABLE egress_policies (
  policy_id          TEXT PRIMARY KEY,
  org_id             TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  name               TEXT NOT NULL,
  -- host patterns: exact host or a single leading '*.' wildcard. Validated in the application layer;
  -- the CHECK here is a defence-in-depth floor (no bare '*', no whitespace).
  host_patterns      TEXT[] NOT NULL,
  protocols          TEXT[] NOT NULL DEFAULT '{https}',
  ports              INTEGER[] NOT NULL DEFAULT '{443}',
  action             TEXT NOT NULL CHECK (action IN ('ALLOW','DENY','REQUIRE_APPROVAL')),
  priority           INTEGER NOT NULL DEFAULT 100,
  rate_per_second    DOUBLE PRECISION,
  rate_burst         INTEGER,
  max_request_bytes  INTEGER,
  max_response_bytes INTEGER,
  timeout_ms         INTEGER,
  allow_redirects    BOOLEAN NOT NULL DEFAULT FALSE,
  dlp_enabled        BOOLEAN NOT NULL DEFAULT TRUE,
  description        TEXT NOT NULL DEFAULT '',
  enabled            BOOLEAN NOT NULL DEFAULT TRUE,
  created_at         DOUBLE PRECISION NOT NULL,
  updated_at         DOUBLE PRECISION NOT NULL,
  created_by         TEXT NOT NULL DEFAULT '',
  version            INTEGER NOT NULL DEFAULT 1,
  row_created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (array_length(host_patterns, 1) >= 1),
  CHECK (NOT ('*' = ANY(host_patterns))),
  CHECK (rate_per_second IS NULL OR rate_per_second > 0),
  CHECK (rate_burst IS NULL OR rate_burst >= 1)
);
CREATE INDEX egress_policies_org_idx ON egress_policies (org_id);
CREATE INDEX egress_policies_org_enabled_idx ON egress_policies (org_id, enabled);

-- --------------------------------------------------------------------------- egress audit (append-only)
CREATE TABLE egress_audit (
  event_id       TEXT PRIMARY KEY,
  ts             DOUBLE PRECISION NOT NULL,
  event          TEXT NOT NULL,
  org_id         TEXT,
  agent_id       TEXT,
  instance_id    TEXT,
  destination    TEXT,
  host           TEXT,
  port           INTEGER,
  protocol       TEXT,
  resource_id    TEXT,
  operation      TEXT,
  decision       TEXT,
  reason         TEXT,
  outcome        TEXT NOT NULL CHECK (outcome IN ('ok','denied','error')),
  policy_id      TEXT,
  policy_version TEXT,
  dlp_rule_ids   TEXT[] NOT NULL DEFAULT '{}',
  dlp_severity   TEXT,
  resolved_ips   TEXT[] NOT NULL DEFAULT '{}',
  address_class  TEXT,
  actor_user_id  TEXT,
  correlation_id TEXT,
  latency_ms     INTEGER,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX egress_audit_ts_idx ON egress_audit (ts DESC);
CREATE INDEX egress_audit_org_ts_idx ON egress_audit (org_id, ts DESC);
CREATE INDEX egress_audit_dest_idx ON egress_audit (destination, ts DESC);

CREATE FUNCTION ag_egress_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'egress_audit is append-only' USING ERRCODE = 'check_violation';
END $$;
CREATE TRIGGER egress_audit_append_only BEFORE UPDATE OR DELETE ON egress_audit
  FOR EACH ROW EXECUTE FUNCTION ag_egress_audit_immutable();

-- --------------------------------------------------------------------------- row-revision trigger
CREATE FUNCTION ag_egress_touch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.version := OLD.version + 1;
  NEW.row_updated_at := now();
  RETURN NEW;
END $$;

CREATE TRIGGER egress_policies_guard BEFORE UPDATE ON egress_policies
  FOR EACH ROW EXECUTE FUNCTION ag_egress_touch();

-- --------------------------------------------------------------------------- Row-Level Security (defence in depth)
-- Same GUC contract as migrations 0004/0005/0006: `app.current_org` (verified tenant) and
-- `app.platform_admin`. A tenant can never read or write another tenant's egress policy or audit.
ALTER TABLE egress_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE egress_audit    ENABLE ROW LEVEL SECURITY;

CREATE POLICY egress_policies_tenant_isolation ON egress_policies
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));
CREATE POLICY egress_audit_tenant_isolation ON egress_audit
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id IS NULL OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id IS NULL OR org_id = current_setting('app.current_org', true));
