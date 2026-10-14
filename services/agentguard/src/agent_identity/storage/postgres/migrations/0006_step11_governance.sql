-- AgentGuard Step 11: enterprise tool & resource governance. Schema v6.
-- Additive only: Steps 1-10 tables/constraints are untouched (the policy tables from 0005 in
-- particular are NOT modified). Applied exactly once by migrate.py (checksummed, advisory-locked,
-- forward-only). Times are DOUBLE PRECISION epoch seconds.
--
-- SECRETS: none of these tables hold secrets. A resource record is a logical identifier, its class,
-- its owner, its sensitivity and the operations it permits — never a credential, connection string,
-- shell command or payload. Tool manifests are checksummed, and only NON-secret manifest fields are
-- persisted (a manifest can never grant a capability; only approved_capabilities can).

-- --------------------------------------------------------------------------- governed resources
CREATE TABLE resources (
  resource_id           TEXT PRIMARY KEY,
  org_id                TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  resource_type         TEXT NOT NULL CHECK (resource_type IN
                          ('tool','tool_server','http_api','database','filesystem','shell','cloud',
                           'internal_service','custom')),
  name                  TEXT NOT NULL,
  owner                 TEXT NOT NULL,
  sensitivity           TEXT NOT NULL CHECK (sensitivity IN
                          ('public','internal','confidential','restricted')),
  permitted_operations  TEXT[] NOT NULL DEFAULT '{}',
  policy_refs           TEXT[] NOT NULL DEFAULT '{}',
  enabled               BOOLEAN NOT NULL DEFAULT TRUE,
  description           TEXT NOT NULL DEFAULT '',
  metadata              JSONB,
  created_at            DOUBLE PRECISION NOT NULL,
  updated_at            DOUBLE PRECISION NOT NULL,
  created_by            TEXT NOT NULL,
  version               INTEGER NOT NULL DEFAULT 1,
  row_created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX resources_org_idx ON resources (org_id);
CREATE INDEX resources_type_idx ON resources (resource_type);
CREATE INDEX resources_enabled_idx ON resources (enabled);

-- --------------------------------------------------------------------------- approved tools
CREATE TABLE tools (
  tool_id                TEXT PRIMARY KEY,
  org_id                 TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  name                   TEXT NOT NULL,
  -- the tool's own semantic version (part of tool_id "name@version"); NOT the row revision
  tool_version           TEXT NOT NULL,
  owner                  TEXT NOT NULL,
  risk                   TEXT NOT NULL CHECK (risk IN ('low','medium','high','critical')),
  -- capabilities the tool ASKS FOR (from its manifest). INFORMATIONAL only: these never grant.
  requested_capabilities TEXT[] NOT NULL DEFAULT '{}',
  -- capabilities an ADMINISTRATOR granted. These are the ONLY ones that affect a decision.
  approved_capabilities  TEXT[] NOT NULL DEFAULT '{}',
  resource_id            TEXT REFERENCES resources(resource_id) ON DELETE SET NULL,
  policy_refs            TEXT[] NOT NULL DEFAULT '{}',
  enabled                BOOLEAN NOT NULL DEFAULT TRUE,
  approved               BOOLEAN NOT NULL DEFAULT FALSE,
  description            TEXT NOT NULL DEFAULT '',
  manifest_checksum      TEXT NOT NULL DEFAULT '',
  created_at             DOUBLE PRECISION NOT NULL,
  updated_at             DOUBLE PRECISION NOT NULL,
  created_by             TEXT NOT NULL,
  approved_by            TEXT,
  version                INTEGER NOT NULL DEFAULT 1,
  row_created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- a tool can never claim an approval it was not granted
  CHECK (NOT approved OR approved_by IS NOT NULL)
);
CREATE INDEX tools_org_name_idx ON tools (org_id, name);
CREATE INDEX tools_org_idx ON tools (org_id);
CREATE INDEX tools_approved_idx ON tools (approved, enabled);

-- --------------------------------------------------------------------------- governance audit (append-only)
CREATE TABLE governance_audit (
  event_id       TEXT PRIMARY KEY,
  ts             DOUBLE PRECISION NOT NULL,
  event          TEXT NOT NULL,
  org_id         TEXT,
  agent_id       TEXT,
  instance_id    TEXT,
  resource_id    TEXT,
  resource_type  TEXT,
  operation      TEXT,
  tool_id        TEXT,
  decision       TEXT,
  reason         TEXT,
  outcome        TEXT NOT NULL CHECK (outcome IN ('ok','denied','error')),
  policy_id      TEXT,
  policy_version TEXT,
  actor_user_id  TEXT,
  correlation_id TEXT,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX governance_audit_ts_idx ON governance_audit (ts DESC);
CREATE INDEX governance_audit_org_ts_idx ON governance_audit (org_id, ts DESC);
CREATE INDEX governance_audit_resource_idx ON governance_audit (resource_id, ts DESC);

CREATE FUNCTION ag_governance_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'governance_audit is append-only' USING ERRCODE = 'check_violation';
END $$;
CREATE TRIGGER governance_audit_append_only BEFORE UPDATE OR DELETE ON governance_audit
  FOR EACH ROW EXECUTE FUNCTION ag_governance_audit_immutable();

-- --------------------------------------------------------------------------- row-revision triggers
-- NOTE: ag_guard_status() (0001) is NOT reused here: it references OLD.status (a column neither
-- governance table has) and enforces agent/instance status transitions. Governance rows instead use
-- this small, purpose-built touch trigger, which only bumps the row revision and the row timestamp.
CREATE FUNCTION ag_governance_touch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.version := OLD.version + 1;
  NEW.row_updated_at := now();
  RETURN NEW;
END $$;

CREATE TRIGGER resources_guard BEFORE UPDATE ON resources
  FOR EACH ROW EXECUTE FUNCTION ag_governance_touch();
CREATE TRIGGER tools_guard BEFORE UPDATE ON tools
  FOR EACH ROW EXECUTE FUNCTION ag_governance_touch();

-- --------------------------------------------------------------------------- Row-Level Security (defence in depth)
-- Same GUC contract as migrations 0004/0005: `app.current_org` (verified tenant) and
-- `app.platform_admin`. A tenant can never read or write another tenant's resources or tools.
ALTER TABLE resources        ENABLE ROW LEVEL SECURITY;
ALTER TABLE tools            ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance_audit ENABLE ROW LEVEL SECURITY;

CREATE POLICY resources_tenant_isolation ON resources
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));
CREATE POLICY tools_tenant_isolation ON tools
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));
CREATE POLICY governance_audit_tenant_isolation ON governance_audit
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id IS NULL OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id IS NULL OR org_id = current_setting('app.current_org', true));
