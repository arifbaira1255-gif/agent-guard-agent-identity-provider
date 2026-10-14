-- AgentGuard Step 8: enterprise authentication, RBAC and multi-tenancy. Schema v4.
-- Additive only: Steps 1-7 tables/constraints are untouched. Applied exactly once by migrate.py
-- (checksummed, advisory-locked, forward-only). Times are DOUBLE PRECISION epoch seconds.
--
-- SECRETS: users.password_hash holds a PHC scrypt hash (never plaintext). refresh_tokens stores only
-- a SHA-256 digest. idp_configs.client_secret_ref is a secret NAME/reference, never the value.

-- --------------------------------------------------------------------------- users (human principals)
CREATE TABLE users (
  user_id              TEXT PRIMARY KEY,
  email                TEXT NOT NULL,
  display_name         TEXT NOT NULL,
  status               TEXT NOT NULL CHECK (status IN ('active','suspended','disabled')),
  is_platform_admin    BOOLEAN NOT NULL DEFAULT FALSE,
  global_roles         TEXT[] NOT NULL DEFAULT '{}',
  password_hash        TEXT,                                   -- PHC scrypt string; NULL for SSO-only
  password_changed_at  DOUBLE PRECISION,
  must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
  failed_login_count   INTEGER NOT NULL DEFAULT 0,
  locked_until         DOUBLE PRECISION,
  last_login_at        DOUBLE PRECISION,
  mfa_enrolled         BOOLEAN NOT NULL DEFAULT FALSE,         -- reserved (see docs limitations)
  created_at           DOUBLE PRECISION NOT NULL,
  created_by           TEXT NOT NULL,
  updated_at           DOUBLE PRECISION NOT NULL,
  version              INTEGER NOT NULL DEFAULT 1,
  row_created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- case-insensitive uniqueness of email (a user can never be duplicated by case)
CREATE UNIQUE INDEX users_email_lower_uq ON users (lower(email));
CREATE INDEX users_status_idx ON users (status);
-- a user flagged is_platform_admin MUST actually hold the platform role (kept consistent by the app)
CREATE INDEX users_platform_admin_idx ON users (is_platform_admin) WHERE is_platform_admin;

-- --------------------------------------------------------------------------- tenant memberships
CREATE TABLE tenant_memberships (
  org_id         TEXT NOT NULL REFERENCES organizations(org_id),      -- tenant boundary (FK)
  user_id        TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  roles          TEXT[] NOT NULL DEFAULT '{}',
  status         TEXT NOT NULL CHECK (status IN ('active','suspended')),
  created_at     DOUBLE PRECISION NOT NULL,
  created_by     TEXT NOT NULL,
  updated_at     DOUBLE PRECISION NOT NULL,
  version        INTEGER NOT NULL DEFAULT 1,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id),
  -- DEFENCE IN DEPTH against privilege self-escalation: a platform role can never be stored on a
  -- tenant membership, no matter what the application layer does.
  CONSTRAINT tenant_memberships_no_platform_role CHECK (NOT ('platform_administrator' = ANY(roles)))
);
CREATE INDEX tenant_memberships_user_idx ON tenant_memberships (user_id);

-- --------------------------------------------------------------------------- sessions
CREATE TABLE sessions (
  session_id          TEXT PRIMARY KEY,
  user_id             TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  org_id              TEXT REFERENCES organizations(org_id),         -- active tenant (NULL = platform)
  auth_method         TEXT NOT NULL CHECK (auth_method IN ('password','oidc')),
  idp_id              TEXT,
  amr                 TEXT[] NOT NULL DEFAULT '{}',
  created_at          DOUBLE PRECISION NOT NULL,
  last_seen_at        DOUBLE PRECISION NOT NULL,
  absolute_expires_at DOUBLE PRECISION NOT NULL,
  idle_expires_at     DOUBLE PRECISION NOT NULL,
  status              TEXT NOT NULL CHECK (status IN ('active','revoked','expired')),
  revoked_at          DOUBLE PRECISION,
  revoked_reason      TEXT,
  csrf_secret         TEXT NOT NULL,
  refresh_version     INTEGER NOT NULL DEFAULT 0,
  rotated_at          DOUBLE PRECISION,
  user_agent          TEXT,
  ip                  TEXT,
  version             INTEGER NOT NULL DEFAULT 1,
  row_created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (absolute_expires_at > created_at)
);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_org_idx ON sessions (org_id);
CREATE INDEX sessions_active_idx ON sessions (status, absolute_expires_at);

-- --------------------------------------------------------------------------- refresh tokens (rotating)
CREATE TABLE refresh_tokens (
  token_hash     TEXT PRIMARY KEY,                                    -- sha256(raw token); never the token
  session_id     TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  user_id        TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  org_id         TEXT,
  issued_at      DOUBLE PRECISION NOT NULL,
  expires_at     DOUBLE PRECISION NOT NULL,
  rotated_at     DOUBLE PRECISION,
  status         TEXT NOT NULL CHECK (status IN ('active','rotated','revoked')),
  parent_hash    TEXT,
  child_hash     TEXT,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (expires_at > issued_at)
);
CREATE INDEX refresh_tokens_session_idx ON refresh_tokens (session_id);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id);

-- --------------------------------------------------------------------------- identity providers (OIDC)
CREATE TABLE idp_configs (
  idp_id                 TEXT PRIMARY KEY,
  org_id                 TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,   -- NULL = platform
  idp_type               TEXT NOT NULL CHECK (idp_type IN ('oidc')),
  issuer                 TEXT NOT NULL,
  client_id              TEXT NOT NULL,
  client_secret_ref      TEXT NOT NULL,          -- ENV/SECRET NAME only, never the secret value
  scopes                 TEXT[] NOT NULL DEFAULT '{openid,profile,email}',
  redirect_uri           TEXT NOT NULL,
  jwks_uri               TEXT NOT NULL DEFAULT '',
  authorization_endpoint TEXT NOT NULL DEFAULT '',
  token_endpoint         TEXT NOT NULL DEFAULT '',
  allowed_email_domains  TEXT[],
  allowed_organizations  TEXT[],
  require_verified_email BOOLEAN NOT NULL DEFAULT TRUE,
  enabled                BOOLEAN NOT NULL DEFAULT TRUE,
  created_at             DOUBLE PRECISION NOT NULL,
  created_by             TEXT NOT NULL,
  updated_at             DOUBLE PRECISION NOT NULL,
  version                INTEGER NOT NULL DEFAULT 1,
  row_created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idp_configs_org_idx ON idp_configs (org_id);

-- --------------------------------------------------------------------------- durable audit log (append-only)
CREATE TABLE audit_events (
  event_id       TEXT PRIMARY KEY,
  ts             DOUBLE PRECISION NOT NULL,
  event          TEXT NOT NULL,
  actor_user_id  TEXT,
  actor_type     TEXT NOT NULL CHECK (actor_type IN ('user','system','agent')),
  org_id         TEXT,
  target_type    TEXT,
  target_id      TEXT,
  outcome        TEXT NOT NULL CHECK (outcome IN ('ok','denied','error')),
  reason         TEXT,
  correlation_id TEXT,
  ip             TEXT,
  user_agent     TEXT,
  idp_id         TEXT,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_ts_idx      ON audit_events (ts DESC);
CREATE INDEX audit_events_org_ts_idx  ON audit_events (org_id, ts DESC);
CREATE INDEX audit_events_actor_idx   ON audit_events (actor_user_id, ts DESC);
CREATE INDEX audit_events_event_idx   ON audit_events (event, ts DESC);

-- --------------------------------------------------------------------------- audit append-only guard
CREATE FUNCTION ag_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = 'check_violation';
END $$;
CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION ag_audit_immutable();

-- --------------------------------------------------------------------------- status guards (reuse ag_guard_status)
-- ag_guard_status() (defined in 0001) bumps version/row_updated_at and blocks an un-terminate.
-- Reused here for the new tables that carry a status column (no 'terminated' value, so the
-- un-terminate branch is inert; the version bump + row_updated_at maintenance still apply).
CREATE TRIGGER users_guard BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION ag_guard_status();
CREATE TRIGGER tenant_memberships_guard BEFORE UPDATE ON tenant_memberships
  FOR EACH ROW EXECUTE FUNCTION ag_guard_status();
CREATE TRIGGER sessions_guard BEFORE UPDATE ON sessions
  FOR EACH ROW EXECUTE FUNCTION ag_guard_status();
CREATE TRIGGER idp_configs_guard BEFORE UPDATE ON idp_configs
  FOR EACH ROW EXECUTE FUNCTION ag_guard_status();

-- --------------------------------------------------------------------------- Row-Level Security (defence in depth)
-- Tenant-scoped tables get an RLS policy keyed on the transaction-local GUCs `app.current_org`
-- (the verified tenant of the request) and `app.platform_admin` (set only for a platform
-- administrator performing a legitimate cross-tenant operation). The policy is enforced for any
-- NON-OWNER (the application role in production); the schema owner (migration role) still bypasses
-- RLS, so Steps 1-7 behaviour is preserved. When neither GUC is set, `org_id = NULL` is never true
-- and the platform flag is not 'on' => rows are NOT visible (fail closed / deny by default).
ALTER TABLE agents             ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_instances    ENABLE ROW LEVEL SECURITY;
ALTER TABLE credentials        ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions           ENABLE ROW LEVEL SECURITY;

CREATE POLICY agents_tenant_isolation ON agents
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));
CREATE POLICY agent_instances_tenant_isolation ON agent_instances
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));
CREATE POLICY credentials_tenant_isolation ON credentials
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));
CREATE POLICY tenant_memberships_tenant_isolation ON tenant_memberships
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true)
         OR user_id = current_setting('app.current_user', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id = current_setting('app.current_org', true));
-- sessions may be platform-scoped (org_id IS NULL, e.g. a platform administrator session), and a
-- user may always see/revoke their OWN sessions (app.current_user).
CREATE POLICY sessions_tenant_isolation ON sessions
  USING (current_setting('app.platform_admin', true) = 'on'
         OR org_id IS NULL OR org_id = current_setting('app.current_org', true)
         OR user_id = current_setting('app.current_user', true))
  WITH CHECK (current_setting('app.platform_admin', true) = 'on'
         OR org_id IS NULL OR org_id = current_setting('app.current_org', true));
