-- AgentGuard Step 10: policy engine, policy lifecycle and Just-in-Time authorization. Schema v5.
-- Additive only: Steps 1-9 tables/constraints are untouched. Applied exactly once by migrate.py
-- (checksummed, advisory-locked, forward-only). Times are DOUBLE PRECISION epoch seconds.
--
-- SECRETS: none of these tables hold secrets. rego_source is policy logic (not secret); grants and
-- approvals carry only ids, scopes, timestamps and reason codes.

-- --------------------------------------------------------------------------- policies (metadata)
CREATE TABLE policies (
  policy_id      TEXT PRIMARY KEY,
  org_id         TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,   -- NULL = platform-wide
  name           TEXT NOT NULL,
  description    TEXT NOT NULL DEFAULT '',
  owner_user_id  TEXT NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('draft','active','disabled')),
  active_version INTEGER,
  created_at     DOUBLE PRECISION NOT NULL,
  updated_at     DOUBLE PRECISION NOT NULL,
  created_by     TEXT NOT NULL,
  version        INTEGER NOT NULL DEFAULT 1,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX policies_org_idx ON policies (org_id);
CREATE INDEX policies_status_idx ON policies (status);

-- --------------------------------------------------------------------------- policy versions (immutable)
CREATE TABLE policy_versions (
  policy_id      TEXT NOT NULL REFERENCES policies(policy_id) ON DELETE CASCADE,
  version        INTEGER NOT NULL,
  org_id         TEXT,                                   -- denormalised for RLS / tenant scoping
  rego_source    TEXT NOT NULL,
  checksum       TEXT NOT NULL,                          -- sha256 of the canonical source
  status         TEXT NOT NULL CHECK (status IN ('draft','active','retired')),
  created_at     DOUBLE PRECISION NOT NULL,
  created_by     TEXT NOT NULL,
  activated_at   DOUBLE PRECISION,
  test_summary   JSONB,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (policy_id, version)
);
CREATE INDEX policy_versions_org_idx ON policy_versions (org_id);
CREATE INDEX policy_versions_status_idx ON policy_versions (status);

-- --------------------------------------------------------------------------- JIT grants
CREATE TABLE jit_grants (
  grant_id       TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  agent_id       TEXT NOT NULL,
  instance_id    TEXT,
  action         TEXT NOT NULL,
  resource       TEXT NOT NULL,
  issued_at      DOUBLE PRECISION NOT NULL,
  expires_at     DOUBLE PRECISION NOT NULL,
  policy_version TEXT,
  status         TEXT NOT NULL CHECK (status IN ('active','revoked','expired')),
  issued_by      TEXT NOT NULL,
  reason         TEXT NOT NULL DEFAULT '',
  context        JSONB,
  revoked_at     DOUBLE PRECISION,
  revoked_reason TEXT,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- a grant MUST expire after it is issued (no zero/negative-lifetime grants)
  CHECK (expires_at > issued_at)
);
CREATE INDEX jit_grants_org_agent_idx ON jit_grants (org_id, agent_id);
CREATE INDEX jit_grants_scope_idx ON jit_grants (org_id, agent_id, action, resource);
CREATE INDEX jit_grants_expiry_idx ON jit_grants (status, expires_at);

-- --------------------------------------------------------------------------- approvals (minimal; Step 17 owns the full workflow)
CREATE TABLE approvals (
  approval_id  TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
  agent_id     TEXT NOT NULL,
  action       TEXT NOT NULL,
  resource     TEXT NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired')),
  requested_at DOUBLE PRECISION NOT NULL,
  expires_at   DOUBLE PRECISION NOT NULL,
  requested_by TEXT NOT NULL,
  decided_at   DOUBLE PRECISION,
  decided_by   TEXT,
  reason       TEXT NOT NULL DEFAULT '',
  context      JSONB,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (expires_at > requested_at)
);
CREATE INDEX approvals_scope_idx ON approvals (org_id, agent_id, action, resource, status);

-- --------------------------------------------------------------------------- policy audit (append-only)
CREATE TABLE policy_audit (
  event_id       TEXT PRIMARY KEY,
  ts             DOUBLE PRECISION NOT NULL,
  event          TEXT NOT NULL,
  actor_user_id  TEXT,
  org_id         TEXT,
  policy_id      TEXT,
  policy_version INTEGER,
  grant_id       TEXT,
  outcome        TEXT NOT NULL CHECK (outcome IN ('ok','denied','error')),
  reason         TEXT,
  correlation_id TEXT,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX policy_audit_ts_idx ON policy_audit (ts DESC);
CREATE INDEX policy_audit_org_ts_idx ON policy_audit (org_id, ts DESC);
CREATE INDEX policy_audit_policy_idx ON policy_audit (policy_id, ts DESC);

CREATE FUNCTION ag_policy_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'policy_audit is append-only' USING ERRCODE = 'check_violation';
END $$;
CREATE TRIGGER policy_audit_append_only BEFORE UPDATE OR DELETE ON policy_audit
  FOR EACH ROW EXECUTE FUNCTION ag_policy_audit_immutable();

-- --------------------------------------------------------------------------- status guards
-- ag_guard_status() (defined in 0001) bumps `version` and `row_updated_at` on UPDATE. It is applied
-- ONLY to `policies`, which carries a `version` column. It is deliberately NOT applied to
-- policy_versions (whose `version` is the immutable POLICY version number, not a row revision),
-- jit_grants or approvals (which have no `version` column at all) — reusing it there would either
-- corrupt the policy version number or fail with "record NEW has no field version".
CREATE TRIGGER policies_guard BEFORE UPDATE ON policies
  FOR EACH ROW EXECUTE FUNCTION ag_guard_status();

-- --------------------------------------------------------------------------- Row-Level Security (defence in depth)
-- Same GUC contract as migration 0004: `app.current_org` (verified tenant) and `app.platform_admin`.
-- Platform-wide policies (org_id IS NULL) are visible to every tenant (they apply globally) but a
-- tenant can never WRITE one (the WITH CHECK requires the platform flag or a matching org).
ALTER TABLE policies        ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE jit_grants      ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals       ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_audit    ENABLE ROW LEVEL SECURITY;

CREATE POLICY policies_tenant_isolation ON policies
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id IS NULL OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));
CREATE POLICY policy_versions_tenant_isolation ON policy_versions
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id IS NULL OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));
CREATE POLICY jit_grants_tenant_isolation ON jit_grants
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));
CREATE POLICY approvals_tenant_isolation ON approvals
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));
CREATE POLICY policy_audit_tenant_isolation ON policy_audit
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id IS NULL OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id IS NULL OR org_id = current_setting('app.current_org', true));
