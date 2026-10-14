-- AgentGuard identity persistence, schema v1. Applied exactly once by migrate.py (checksummed).
-- Times are DOUBLE PRECISION epoch seconds (exact round-trip with the domain models);
-- row_created_at / row_updated_at are DB-side audit timestamps.
-- NO private key material except keystore_keys.encrypted_private (Fernet-encrypted, master key never in DB).

CREATE TABLE organizations (
  org_id                TEXT PRIMARY KEY,
  name                  TEXT NOT NULL,
  created_at            DOUBLE PRECISION NOT NULL,
  status                TEXT NOT NULL CHECK (status IN ('active','suspended','terminated')),
  active_issuer_key_id  TEXT NOT NULL,
  allowed_capabilities  TEXT[],
  version               INTEGER NOT NULL DEFAULT 1,
  row_created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE trust_roots (
  root_key_id     TEXT PRIMARY KEY,
  public_key      TEXT NOT NULL,
  row_created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE issuer_certificates (
  issuer_key_id   TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL REFERENCES organizations(org_id),
  public_key      TEXT NOT NULL,
  fingerprint     TEXT NOT NULL,
  root_key_id     TEXT NOT NULL,
  issued_at       DOUBLE PRECISION NOT NULL,
  signature       TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('active','retiring','revoked')),
  not_after       DOUBLE PRECISION,
  row_created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX issuer_certificates_org_idx ON issuer_certificates (org_id);

CREATE TABLE agents (
  agent_id         TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL REFERENCES organizations(org_id),
  agent_name       TEXT NOT NULL,
  agent_type       TEXT NOT NULL,
  owner            TEXT NOT NULL,
  description      TEXT NOT NULL,
  capabilities     TEXT[] NOT NULL,
  environment      TEXT NOT NULL,
  metadata         JSONB NOT NULL,
  parent_agent_id  TEXT REFERENCES agents(agent_id),
  lineage          TEXT[] NOT NULL,
  created_at       DOUBLE PRECISION NOT NULL,
  status           TEXT NOT NULL CHECK (status IN ('active','suspended','terminated')),
  key_id           TEXT NOT NULL,
  public_key       TEXT NOT NULL,
  fingerprint      TEXT NOT NULL,
  retired_keys     JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_by       TEXT NOT NULL,
  version          INTEGER NOT NULL DEFAULT 1,
  row_created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (agent_id, org_id)                  -- target of tenant-consistent composite FKs
);
CREATE INDEX agents_org_status_idx ON agents (org_id, status);
CREATE INDEX agents_parent_idx ON agents (parent_agent_id) WHERE parent_agent_id IS NOT NULL;

CREATE TABLE agent_instances (
  instance_id        TEXT PRIMARY KEY,
  agent_id           TEXT NOT NULL,
  org_id             TEXT NOT NULL,
  session_id         TEXT NOT NULL,
  created_at         DOUBLE PRECISION NOT NULL,
  status             TEXT NOT NULL CHECK (status IN ('active','suspended','terminated')),
  agent_key_id       TEXT NOT NULL,
  agent_public_key   TEXT NOT NULL,
  binding_signature  TEXT NOT NULL,
  version            INTEGER NOT NULL DEFAULT 1,
  row_created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  FOREIGN KEY (agent_id, org_id) REFERENCES agents (agent_id, org_id),   -- tenant boundary
  UNIQUE (instance_id, agent_id, org_id)
);
CREATE INDEX agent_instances_agent_idx ON agent_instances (agent_id);

CREATE TABLE agent_spawns (
  child_agent_id          TEXT PRIMARY KEY REFERENCES agents(agent_id),
  parent_agent_id         TEXT NOT NULL REFERENCES agents(agent_id),
  spawned_by_instance_id  TEXT NOT NULL REFERENCES agent_instances(instance_id),
  created_at              DOUBLE PRECISION NOT NULL,
  issuer                  TEXT NOT NULL,
  status                  TEXT NOT NULL CHECK (status IN ('active','suspended','terminated')),
  row_created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (child_agent_id <> parent_agent_id)
);
CREATE INDEX agent_spawns_parent_idx ON agent_spawns (parent_agent_id);

CREATE TABLE credentials (
  credential_id    TEXT PRIMARY KEY,
  agent_id         TEXT NOT NULL,
  instance_id      TEXT NOT NULL,
  org_id           TEXT NOT NULL,
  issuer_key_id    TEXT NOT NULL,
  issued_at        DOUBLE PRECISION NOT NULL,
  expires_at       DOUBLE PRECISION NOT NULL,
  key_id           TEXT,
  key_fingerprint  TEXT NOT NULL,
  payload_digest   TEXT NOT NULL,
  row_created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  FOREIGN KEY (instance_id, agent_id, org_id) REFERENCES agent_instances (instance_id, agent_id, org_id),
  CHECK (expires_at > issued_at)
);
CREATE INDEX credentials_instance_idx ON credentials (instance_id);
CREATE INDEX credentials_agent_idx ON credentials (agent_id);
CREATE INDEX credentials_expires_idx ON credentials (expires_at);

CREATE TABLE revocations (
  target_type   TEXT NOT NULL CHECK (target_type IN ('credential','instance','agent','issuer_key')),
  target_id     TEXT NOT NULL,
  reason        TEXT NOT NULL CHECK (reason IN ('compromise','suspicious_behavior','agent_terminated',
                  'credential_rotated','administrative_action','security_incident')),
  revoked_at    DOUBLE PRECISION NOT NULL,
  revoked_by    TEXT NOT NULL,
  effective_at  DOUBLE PRECISION NOT NULL,
  detail        TEXT,
  row_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (target_type, target_id)      -- one record per target; earliest effective_at wins
);

CREATE TABLE spiffe_bindings (
  spiffe_id              TEXT PRIMARY KEY,
  org_id                 TEXT NOT NULL,
  agent_id               TEXT NOT NULL,
  instance_id            TEXT,
  created_at             DOUBLE PRECISION NOT NULL,
  delegated_by_agent     TEXT REFERENCES agents(agent_id),
  delegated_by_instance  TEXT REFERENCES agent_instances(instance_id),
  status                 TEXT NOT NULL CHECK (status IN ('active','revoked')),
  row_created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  FOREIGN KEY (agent_id, org_id) REFERENCES agents (agent_id, org_id)
);
-- one SPIFFE ID per (agent, instance): an identity cannot be given two SPIFFE IDs
CREATE UNIQUE INDEX spiffe_bindings_identity_uq ON spiffe_bindings (agent_id, COALESCE(instance_id, ''));

CREATE TABLE keystore_keys (
  key_id             TEXT PRIMARY KEY,
  public_key         BYTEA NOT NULL,
  encrypted_private  BYTEA NOT NULL,          -- Fernet token; the master key lives outside the DB
  row_created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- defence in depth: terminal states and immutable columns are enforced by the database
CREATE FUNCTION ag_guard_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'terminated' AND NEW.status <> 'terminated' THEN
    RAISE EXCEPTION 'invalid status transition' USING ERRCODE = 'check_violation';
  END IF;
  NEW.version := OLD.version + 1;
  NEW.row_updated_at := now();
  RETURN NEW;
END $$;

CREATE FUNCTION ag_guard_agent_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.org_id <> OLD.org_id OR NEW.parent_agent_id IS DISTINCT FROM OLD.parent_agent_id
     OR NEW.lineage <> OLD.lineage OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'immutable agent column changed' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION ag_guard_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.org_id <> OLD.org_id OR NEW.agent_id <> OLD.agent_id
     OR NEW.instance_id IS DISTINCT FROM OLD.instance_id
     OR (OLD.status = 'revoked' AND NEW.status <> 'revoked') THEN
    RAISE EXCEPTION 'binding is immutable (only active -> revoked)' USING ERRCODE = 'check_violation';
  END IF;
  NEW.row_updated_at := now();
  RETURN NEW;
END $$;

CREATE TRIGGER organizations_guard BEFORE UPDATE ON organizations
  FOR EACH ROW EXECUTE FUNCTION ag_guard_status();
CREATE TRIGGER agents_guard BEFORE UPDATE ON agents
  FOR EACH ROW EXECUTE FUNCTION ag_guard_status();
CREATE TRIGGER agents_immutable BEFORE UPDATE ON agents
  FOR EACH ROW EXECUTE FUNCTION ag_guard_agent_immutable();
CREATE TRIGGER agent_instances_guard BEFORE UPDATE ON agent_instances
  FOR EACH ROW EXECUTE FUNCTION ag_guard_status();
CREATE TRIGGER spiffe_bindings_guard BEFORE UPDATE ON spiffe_bindings
  FOR EACH ROW EXECUTE FUNCTION ag_guard_binding();
