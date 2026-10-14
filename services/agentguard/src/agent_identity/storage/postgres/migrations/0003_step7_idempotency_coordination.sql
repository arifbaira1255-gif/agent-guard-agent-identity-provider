-- AgentGuard Step 7: distributed high-availability identity service, schema v3.
-- Adds (a) an idempotency ledger for identity registration / credential issuance and
-- (b) a coordination ledger for scheduled multi-instance jobs (cleanup / reconciliation).
--
-- No key material and no bearer credentials are stored in the clear:
--   * idempotency_records.response_enc is a Fernet token (master key lives outside the DB);
--   * coordination_jobs holds only job bookkeeping (names, timestamps, instance ids).

-- --------------------------------------------------------------------------- idempotency
-- Scope is tenant-aware: (scope, operation, idem_key). `scope` is the organization id (or
-- '_system' for control-plane operations that are not tenant-bound). The PRIMARY KEY makes the
-- reservation atomic: exactly one instance can INSERT a given key; every other instance sees the
-- existing row and must NOT re-execute the security-critical transition.
CREATE TABLE idempotency_records (
  scope           TEXT NOT NULL,
  operation       TEXT NOT NULL,
  idem_key        TEXT NOT NULL,
  request_digest  TEXT NOT NULL,                 -- sha256 of the canonical request body
  actor           TEXT NOT NULL,                 -- authenticated principal that owns this key
  status          TEXT NOT NULL CHECK (status IN ('in_progress','completed','failed')),
  result_ref      TEXT,                          -- resource id (agent_id / credential_id / ...)
  result_digest   TEXT,                          -- digest of the stored response (conflict detection)
  response_enc    BYTEA,                         -- Fernet-encrypted response body (may hold a token)
  owner_instance  TEXT NOT NULL,                 -- instance that reserved the key
  created_at      DOUBLE PRECISION NOT NULL,
  updated_at      DOUBLE PRECISION NOT NULL,
  expires_at      DOUBLE PRECISION NOT NULL,     -- bounded retention; purged by a coordination job
  PRIMARY KEY (scope, operation, idem_key)
);
CREATE INDEX idempotency_expires_idx ON idempotency_records (expires_at);
CREATE INDEX idempotency_status_idx ON idempotency_records (status);

-- --------------------------------------------------------------------------- coordination
-- One row per named scheduled job. The advisory lock (not this table) serialises execution; this
-- table records the outcome so operators can see which instance last ran a job and whether it
-- succeeded. `lease_owner`/`lease_until` are advisory bookkeeping only (never a correctness gate).
CREATE TABLE coordination_jobs (
  job_name         TEXT PRIMARY KEY,
  last_started_at  DOUBLE PRECISION,
  last_finished_at DOUBLE PRECISION,
  last_status      TEXT CHECK (last_status IN ('ok','failed','skipped')),
  last_instance    TEXT,
  last_detail      TEXT,
  run_count        BIGINT NOT NULL DEFAULT 0,
  lease_owner      TEXT,
  lease_until      DOUBLE PRECISION,
  row_created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- defence in depth: an idempotency record's identity is immutable, and a completed record can
-- never be silently reset to in_progress (that would allow a second execution of the operation).
CREATE FUNCTION ag_guard_idempotency() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.scope <> OLD.scope OR NEW.operation <> OLD.operation OR NEW.idem_key <> OLD.idem_key THEN
    RAISE EXCEPTION 'idempotency record identity is immutable' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status = 'completed' AND NEW.status <> 'completed' THEN
    RAISE EXCEPTION 'completed idempotency record is terminal' USING ERRCODE = 'check_violation';
  END IF;
  NEW.updated_at := GREATEST(NEW.updated_at, OLD.updated_at);
  RETURN NEW;
END $$;

CREATE TRIGGER idempotency_records_guard BEFORE UPDATE ON idempotency_records
  FOR EACH ROW EXECUTE FUNCTION ag_guard_idempotency();
